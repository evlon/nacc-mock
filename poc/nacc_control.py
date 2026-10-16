#!/usr/bin/env python3
# -*- coding: utf-8 -*-
r"""
NACC 自由关停补丁（安全评估）

用途：自由地关停 / 恢复 启明星辰天珣 NAC 客户端（NACC.exe / NACCService / ndisnac 驱动）。

核心机制（基于逆向 + 实测验证）：
    1. NACC 自保护守护链：
       - NACCService（LocalSystem 服务）→ NACC.exe（主进程）
       - CCMon.exe（守护进程，每 500ms 周期自愈 FUN_004014d1：
         检测 NACCService 的 start_type，!=AUTO 就 ChangeServiceConfigA 改回，
         STOPPED 就 StartServiceA 拉起；服务不存在则 CreateServiceA 重建）
       - StartCCMon.exe → 拉起 CCMon.exe（CCMon9x.exe 为 9x 变体）
       - 开机自启链：HKLM\...\Run\NACCControl → NACCControl.exe
         → 拉起 NACC.exe / StartCCMon.exe → CCMon.exe → 自愈拉起服务
         （NACC.exe 与 NACCControl.exe 都会用 RegSetValueExW 重建该 Run 键）
    2. 关停的正确顺序（关键，否则被守护拉起）：
       ① 清除服务失败恢复动作（防止 SCM 自动重启服务）
       ② 【先杀守护进程】NACC.exe / CCMon.exe / NACCControl.exe / StartCCMon.exe
          （CCMon 有 500ms 自愈，必须先斩断守护源，且循环确认死透）
       ③ 再禁用服务 sc config NACCService start= disabled
       ④ 解除 ndisnac 驱动对网卡的绑定（等效手动取消勾选，不断网）
       * 若「先禁服务再杀进程」，CCMon 会在被杀前的自愈周期内把服务改回
         AUTO 并拉起，导致服务又起来（这是早期 stop 失效的根因）。
    3. 【持久禁用】stop 只关停「这一次」，重启后 Run 键仍会拉起整条链：
       - disable 命令额外删除 Run 自启项 + 禁服务 + 清失败动作 + 解绑驱动，
         并备份到 nacc_autostart_backup.json，重启后 NACC 不再自启。
       - enable 命令从备份完整还原。
       * 删 Run 键必须在【杀光进程之后】，否则 NACC.exe 会立刻重建它。
    4. 【重要教训】不要 sc stop ndisnac/tdinac 驱动！
       - ndisnac 是 NDIS 过滤驱动，sc stop 会导致网卡网络栈异常断网
       - tdinac 会卡在 Stop Pending 僵尸状态，只能重启恢复
       - 正确做法是用 Disable-NetAdapterBinding 解除绑定（安全、不断网）

用法：
    python nacc_control.py disable   # 【持久禁用】杀进程+禁服务+删Run键+解绑驱动（重启也不自启）
    python nacc_control.py enable    # 还原所有自启动项（从备份恢复，重启后重新自启）
    python nacc_control.py stop      # 临时关停（进程+服务+解绑驱动，但重启仍会自启）
    python nacc_control.py start     # 恢复 NACC（服务 + 进程 + 恢复驱动绑定）
    python nacc_control.py status    # 查看当前状态
    python nacc_control.py kill      # 仅杀进程（不解除驱动绑定，最轻量）

stop 与 disable 的区别：
    stop    = 只关停「这一次」，开机自启入口（Run 键/服务自启）未清除，重启后会自启。
    disable = 额外清除全部开机自启入口并备份，重启后也不会自启；用 enable 还原。

注意：需要管理员权限。
"""

import subprocess
import sys
import os
import re
import time
import json
import winreg  # Windows 注册表操作（本工具仅 Windows）

# 修复 GBK 控制台无法输出 emoji 的问题
if sys.stdout.encoding and sys.stdout.encoding.lower() in ("gbk", "cp936"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

# 目标进程（守护链的全部成员）
TARGET_PROCESSES = ["NACC.exe", "CCMon.exe", "NACCControl.exe", "StartCCMon.exe"]
SERVICE_NAME = "NACCService"
# NDIS 过滤驱动组件 ID（网卡绑定里的显示名 "ndisnac Driver" 对应 ComponentID）
DRIVER_COMPONENT_ID = "ndisnac"

# ---------------------------------------------------------------------------
# 开机自启入口（持久禁用用）
#   来源：逆向 Setup.ini + NACC.exe/NACCControl.exe 逆向
#     ① 服务 NACCService（二进制 NACC.exe，AUTO_START）
#     ② HKLM\Software\Microsoft\Windows\CurrentVersion\Run\NACCControl = NACCControl.exe
#        （NACC.exe / NACCControl.exe 都会用 RegSetValueExW 重建此键）
#     ③ 计划任务 / 启动文件夹（如有）
#   注意：必须在【杀光进程之后】再删 Run 键，否则 NACC.exe 会立刻重建。
# ---------------------------------------------------------------------------
AUTOSTART_RE = r"(?i)(NACC|CCMon|StartCCMon)"
BACKUP_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                           "nacc_autostart_backup.json")

# 需要检查的 Run/RunOnce 注册表位置（含 32/64 位视图）
RUN_KEYS = [
    ("HKLM", r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
    ("HKLM", r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"),
    ("HKLM", r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"),
    ("HKLM", r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce"),
    ("HKCU", r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
    ("HKCU", r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"),
    ("HKCU", r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"),
    ("HKCU", r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce"),
]
_HIVES = {"HKLM": winreg.HKEY_LOCAL_MACHINE, "HKCU": winreg.HKEY_CURRENT_USER}

# NACCService 的注册表 Start 值语义：0=Boot 1=System 2=Auto 3=Manual 4=Disabled
SERVICE_START_DISABLED = 4
SERVICE_START_AUTO = 2


def is_admin() -> bool:
    """检查是否有管理员权限。"""
    if os.name != "nt":
        return True
    try:
        import ctypes
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def run_cmd(cmd, check=False):
    """执行命令，返回 (returncode, stdout, stderr)。"""
    r = subprocess.run(
        cmd, capture_output=True, text=True, timeout=60,
        errors="replace",  # 避免 GBK 解码崩溃
    )
    return r.returncode, r.stdout or "", r.stderr or ""


def get_running_processes():
    """获取当前运行的 NACC 相关进程（PID → 进程名）。"""
    procs = {}
    try:
        out = subprocess.run(
            ["tasklist", "/FO", "CSV", "/NH"],
            capture_output=True, text=True, timeout=30,
            errors="replace",
        ).stdout or ""
        for line in out.splitlines():
            parts = [p.strip('"') for p in line.split('","')]
            if len(parts) >= 2:
                name, pid = parts[0], parts[1]
                if name in TARGET_PROCESSES and pid.isdigit():
                    procs[int(pid)] = name
    except Exception as e:
        print(f"[!] 枚举进程失败: {e}")
    return procs


def get_service_state():
    """获取 NACCService 状态（Running/Stopped）+ 启动类型（Auto/Disabled）。"""
    # sc query 的状态码映射
    STATE_MAP = {
        "1": "STOPPED", "2": "START_PENDING", "3": "STOP_PENDING",
        "4": "RUNNING", "7": "PAUSED",
    }
    code, out, _ = run_cmd(["sc", "query", SERVICE_NAME])
    state = "Unknown"
    start_type = "Unknown"
    for line in out.splitlines():
        if "STATE" in line.upper():
            raw = line.split(":")[-1].strip()
            # raw 形如 "4  RUNNING"，取第一个 token 做映射
            first = raw.split()[0] if raw.split() else raw
            state = STATE_MAP.get(first, raw)
    code2, out2, _ = run_cmd(["sc", "qc", SERVICE_NAME])
    for line in out2.splitlines():
        if "START_TYPE" in line.upper():
            start_type = line.split(":")[-1].strip()
    return state, start_type


def get_driver_binding_state():
    """获取 ndisnac 驱动在各网卡上的绑定状态。"""
    try:
        import json
        code, out, _ = run_cmd([
            "powershell", "-NoProfile", "-Command",
            "Get-NetAdapterBinding -ComponentID %s | "
            "Select-Object Name,Enabled | ConvertTo-Json -Compress" % DRIVER_COMPONENT_ID,
        ])
        if code == 0 and out.strip():
            return json.loads(out.strip())
    except Exception:
        pass
    return []


def kill_processes(confirm_dead=True, max_rounds=5):
    """杀所有 NACC 相关进程。

    confirm_dead=True 时循环确认守护进程(CCMon/StartCCMon/NACCControl)确实
    死透（防止 StartCCMon 或残留机制在 taskkill 间隙重新拉起 CCMon）。
    """
    for _ in range(max_rounds):
        procs = get_running_processes()
        if not procs:
            return True
        for pid, name in procs.items():
            try:
                subprocess.run(["taskkill", "/F", "/PID", str(pid)],
                               capture_output=True, timeout=30)
                print(f"  已杀 {name} (PID {pid})")
            except Exception as e:
                print(f"  [!] 杀 {name} (PID {pid}) 失败: {e}")
        if not confirm_dead:
            return bool(get_running_processes()) is False
        # 确认是否还有守护进程残留（NACC.exe 可能被服务立刻拉起，但守护进程是关键）
        time.sleep(0.3)
        remaining = get_running_processes()
        guardians = [n for n in remaining.values() if n in ("CCMon.exe", "StartCCMon.exe", "NACCControl.exe")]
        if not guardians:
            return True
        print(f"  [守护进程仍残留: {', '.join(guardians)}]，继续杀 ...")
    # 多轮后仍有残留
    remaining = get_running_processes()
    if remaining:
        print(f"  [!] 警告：以下进程杀不死: {', '.join(remaining.values())}")
        return False
    return True


def disable_service():
    """禁用 NACCService（斩断守护链的关键）。"""
    code, out, err = run_cmd(["sc", "config", SERVICE_NAME, "start=", "disabled"])
    if code == 0:
        print("  已禁用 NACCService（CCMon 的 StartServiceA 将失败）")
        return True
    print(f"  [!] 禁用服务失败: {err.strip() or out.strip()}")
    return False


def enable_service():
    """恢复 NACCService 为自动启动。"""
    code, out, err = run_cmd(["sc", "config", SERVICE_NAME, "start=", "auto"])
    if code == 0:
        print("  已恢复 NACCService 为自动启动")
        return True
    print(f"  [!] 恢复服务失败: {err.strip() or out.strip()}")
    return False


def start_service():
    """启动 NACCService。"""
    code, out, err = run_cmd(["sc", "start", SERVICE_NAME])
    print(f"  {'✓' if code == 0 else '✗'} 启动 NACCService: {out.strip() or err.strip()}")
    return code == 0


def unbind_driver():
    """解除 ndisnac 驱动对网卡的绑定（等效手动取消勾选，不断网）。"""
    code, out, err = run_cmd([
        "powershell", "-NoProfile", "-Command",
        "Get-NetAdapterBinding -ComponentID %s | "
        "Where-Object { $_.Enabled } | "
        "Disable-NetAdapterBinding -Confirm:$false" % DRIVER_COMPONENT_ID,
    ])
    if code == 0:
        print("  已解除 ndisnac 驱动对所有网卡的绑定（拦截失效，网络不断）")
        return True
    print(f"  [!] 解除驱动绑定失败: {err.strip() or out.strip()}")
    return False


def bind_driver():
    """恢复 ndisnac 驱动对网卡的绑定。"""
    code, out, err = run_cmd([
        "powershell", "-NoProfile", "-Command",
        "Get-NetAdapterBinding -ComponentID %s | "
        "Where-Object { -not $_.Enabled } | "
        "Enable-NetAdapterBinding -Confirm:$false" % DRIVER_COMPONENT_ID,
    ])
    if code == 0:
        print("  已恢复 ndisnac 驱动绑定")
        return True
    print(f"  [!] 恢复驱动绑定失败: {err.strip() or out.strip()}")
    return False


# ===========================================================================
# 持久禁用：自启动项枚举 / 备份 / 移除 / 恢复
# ===========================================================================

def get_service_start_value():
    """读取 NACCService 的注册表 Start 值（0=Boot..2=Auto..4=Disabled）。"""
    try:
        with winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            r"SYSTEM\CurrentControlSet\Services\%s" % SERVICE_NAME,
            0, winreg.KEY_READ,
        ) as k:
            return winreg.QueryValueEx(k, "Start")[0]
    except OSError:
        return None


def enumerate_run_entries():
    """枚举 Run/RunOnce 中指向 NACC/CCMon 的项。"""
    found = []
    for hive, sub in RUN_KEYS:
        try:
            with winreg.OpenKey(_HIVES[hive], sub, 0, winreg.KEY_READ) as k:
                i = 0
                while True:
                    try:
                        name, val, _ = winreg.EnumValue(k, i)
                    except OSError:
                        break
                    i += 1
                    if isinstance(val, str) and re.search(AUTOSTART_RE, val):
                        found.append({"hive": hive, "subkey": sub,
                                      "name": name, "value": val})
        except OSError:
            continue
    return found


def remove_run_entry(entry):
    """从注册表删除一个 Run 项。"""
    try:
        with winreg.OpenKey(_HIVES[entry["hive"]], entry["subkey"], 0,
                            winreg.KEY_SET_VALUE) as k:
            winreg.DeleteValue(k, entry["name"])
        return True
    except OSError as e:
        print(f"      [!] 删除失败 {entry['name']}: {e}")
        return False


def restore_run_entry(entry):
    """恢复一个 Run 项到注册表。"""
    try:
        with winreg.CreateKeyEx(_HIVES[entry["hive"]], entry["subkey"], 0,
                                winreg.KEY_SET_VALUE) as k:
            winreg.SetValueEx(k, entry["name"], 0, winreg.REG_SZ, entry["value"])
        return True
    except OSError as e:
        print(f"      [!] 恢复失败 {entry['name']}: {e}")
        return False


def enumerate_scheduled_tasks():
    """枚举 Actions 指向 NACC/CCMon 的计划任务。"""
    ps = ("$ErrorActionPreference='SilentlyContinue';"
          "Get-ScheduledTask | Where-Object { "
          "($_.Actions | ForEach-Object { $_.Execute }) -match 'NACC|CCMon' } | "
          "ForEach-Object { $_.TaskPath + '|' + $_.TaskName + '|' + $_.State }")
    code, out, _ = run_cmd(["powershell", "-NoProfile", "-Command", ps])
    tasks = []
    for line in out.splitlines():
        parts = line.strip().split("|")
        if len(parts) >= 3 and parts[1]:
            tasks.append({"path": parts[0], "name": parts[1], "state": parts[2]})
    return tasks


def disable_task(task):
    """禁用计划任务。"""
    code, out, err = run_cmd([
        "powershell", "-NoProfile", "-Command",
        "Disable-ScheduledTask -TaskPath '%s' -TaskName '%s' | Out-Null"
        % (task["path"], task["name"]),
    ])
    return code == 0


def enable_task(task):
    """重新启用计划任务。"""
    code, out, err = run_cmd([
        "powershell", "-NoProfile", "-Command",
        "Enable-ScheduledTask -TaskPath '%s' -TaskName '%s' | Out-Null"
        % (task["path"], task["name"]),
    ])
    return code == 0


def get_startup_dirs():
    """返回(当前用户, 所有用户)两个启动文件夹路径。"""
    dirs = []
    appdata = os.environ.get("APPDATA", "")
    programdata = os.environ.get("ProgramData", "")
    if appdata:
        dirs.append(os.path.join(
            appdata, r"Microsoft\Windows\Start Menu\Programs\Startup"))
    if programdata:
        dirs.append(os.path.join(
            programdata, r"Microsoft\Windows\Start Menu\Programs\Startup"))
    return dirs


def enumerate_startup_shortcuts():
    """枚举启动文件夹里文件名匹配 NACC/CCMon 的项。"""
    found = []
    for d in get_startup_dirs():
        if os.path.isdir(d):
            try:
                for f in os.listdir(d):
                    if re.search(AUTOSTART_RE, f):
                        found.append({"dir": d, "file": f})
            except OSError:
                pass
    return found


def clear_service_recovery():
    """清除 NACCService 的失败恢复动作（防止杀进程后 SCM 自动重启服务）。"""
    code, out, err = run_cmd(["sc", "failure", SERVICE_NAME, "reset=", "0",
                              "actions=", '""'])
    if code == 0:
        print("  已清除 NACCService 的失败恢复动作（SCM 不再自动重启它）")
        return True
    print(f"  [i] 清除失败恢复动作返回: {err.strip() or out.strip()}")
    return False


def save_backup(data):
    """把自启动项备份写入 JSON 文件。"""
    try:
        with open(BACKUP_FILE, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        return True
    except OSError as e:
        print(f"  [!] 备份失败: {e}")
        return False


def load_backup():
    """读取自启动项备份。"""
    try:
        with open(BACKUP_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return None


def do_disable():
    """持久禁用 NACC：重启后也不再自启。

    与 stop 的区别：stop 只是「这次关停」，本命令额外清除所有开机自启入口，
    使得重启后 NACC 不会被拉起。可用 enable 完整还原。
    """
    print("=" * 60)
    print("NACC 持久禁用（禁用后重启也不再自启）")
    print("=" * 60)
    print("\n将清除以下开机自启入口（并备份以便还原）：")
    print("  ① 服务 NACCService：start=disabled + 清除失败恢复动作")
    print("  ② 注册表 Run/RunOnce 里的 NACCControl 等自启项")
    print("  ③ 计划任务 / 启动文件夹中的 NACC 相关项（如有）")
    print("  ④ 解除 ndisnac 驱动绑定（持久生效）")
    print(f"\n备份文件：{BACKUP_FILE}")
    print("还原命令：python nacc_control.py enable\n")

    backup = {"run_entries": [], "tasks": [], "startup": [],
              "service_start": None, "time": time.strftime("%Y-%m-%d %H:%M:%S")}

    # --- [1/6] 枚举并备份当前自启动项 ---
    print("[1/6] 枚举并备份当前自启动项 ...")
    run_entries = enumerate_run_entries()
    for e in run_entries:
        print(f"      Run: [{e['hive']}\\{e['subkey']}] {e['name']} = {e['value']}")
    if not run_entries:
        print("      (未发现 NACC 相关的 Run 项)")
    backup["run_entries"] = run_entries

    tasks = enumerate_scheduled_tasks()
    for t in tasks:
        print(f"      计划任务: {t['path']}{t['name']} ({t['state']})")
    backup["tasks"] = tasks

    startup = enumerate_startup_shortcuts()
    for s in startup:
        print(f"      启动文件夹: {s['file']}  ({s['dir']})")
    backup["startup"] = startup

    st = get_service_start_value()
    backup["service_start"] = st
    print(f"      NACCService 原 Start 值: {st} "
          f"({'Auto' if st == SERVICE_START_AUTO else st})")
    save_backup(backup)

    # --- [2/6] 清除服务失败恢复动作（先做，防止杀进程后被 SCM 拉起） ---
    print("\n[2/6] 清除 NACCService 失败恢复动作 ...")
    clear_service_recovery()

    # --- [3/6] 杀光所有进程（含守护），必须在删 Run 键之前 ---
    print("\n[3/6] 杀光 NACC 相关进程（含 CCMon/StartCCMon/NACCControl）...")
    kill_processes()

    # --- [4/6] 禁用服务 ---
    print("\n[4/6] 禁用 NACCService（start=disabled）...")
    disable_service()

    # --- [5/6] 移除自启动项（此时进程已死，NACC.exe 无法重建 Run 键） ---
    print("\n[5/6] 移除自启动项 ...")
    removed = 0
    for e in run_entries:
        if remove_run_entry(e):
            print(f"      已移除 Run: {e['name']}")
            removed += 1
    for t in tasks:
        if disable_task(t):
            print(f"      已禁用计划任务: {t['path']}{t['name']}")
    print(f"      共移除 {removed} 个 Run 项")

    # --- [6/6] 解除驱动绑定 + 校验 ---
    print("\n[6/6] 解除 ndisnac 驱动绑定 ...")
    unbind_driver()

    # 最终校验：再杀一次残留（防自愈窗口），并确认自启动项已清空
    print("\n" + "-" * 40)
    print("最终校验：")
    time.sleep(1)
    kill_processes(confirm_dead=True, max_rounds=3)
    left = enumerate_run_entries()
    sv = get_service_start_value()
    ok = True
    if left:
        print(f"  [!] 仍有 Run 项残留: {[x['name'] for x in left]}")
        ok = False
    else:
        print("  [OK] Run 自启动项已清空")
    if sv == SERVICE_START_DISABLED:
        print("  [OK] NACCService 已禁用（Start=4）")
    else:
        print(f"  [!] NACCService Start 值 = {sv}（期望 4）")
        ok = False
    procs = get_running_processes()
    if procs:
        print(f"  [!] 仍有进程: {list(procs.values())}")
        ok = False
    else:
        print("  [OK] 无 NACC 相关进程")

    print("\n" + "=" * 60)
    if ok:
        print("持久禁用完成：重启后 NACC 将不会自动启动。")
    else:
        print("持久禁用部分完成：上面有 [!] 项，建议再执行一次 disable。")
    print("可用 `python nacc_control.py enable` 还原所有自启动项。")
    print("=" * 60)


def do_enable():
    """从备份还原所有自启动项，恢复正常（重启后会自启）。"""
    print("=" * 60)
    print("NACC 还原自启动（恢复被 disable 清除的入口）")
    print("=" * 60)

    backup = load_backup()
    if not backup:
        print(f"\n[!] 未找到备份文件：{BACKUP_FILE}")
        print("    将按默认方式恢复：服务设为自动 + 启动 + 绑定驱动。")
        print("    （Run 键需由 NACC 自身重启后重建）")
        backup = {"run_entries": [], "tasks": [], "startup": [],
                  "service_start": SERVICE_START_AUTO}

    # --- [1/5] 还原 Run 项 ---
    print("\n[1/5] 还原注册表自启动项 ...")
    run_entries = backup.get("run_entries") or []
    if run_entries:
        for e in run_entries:
            if restore_run_entry(e):
                print(f"      已还原 Run: [{e['hive']}] {e['name']} = {e['value']}")
    else:
        print("      (备份中无 Run 项)")

    # --- [2/5] 还原计划任务 ---
    tasks = backup.get("tasks") or []
    if tasks:
        print("\n[2/5] 还原计划任务 ...")
        for t in tasks:
            if enable_task(t):
                print(f"      已启用计划任务: {t['path']}{t['name']}")
    else:
        print("\n[2/5] 无计划任务需还原")

    # --- [3/5] 恢复驱动绑定 ---
    print("\n[3/5] 恢复 ndisnac 驱动绑定 ...")
    bind_driver()

    # --- [4/5] 恢复服务为自动并启动 ---
    print("\n[4/5] 恢复并启动 NACCService ...")
    enable_service()
    start_service()

    # --- [5/5] 等待拉起 ---
    print("\n[5/5] 等待进程拉起 ...")
    time.sleep(3)
    show_status_inline()

    print("=" * 60)
    print("已还原。若 Run 项缺失，NACC 首次运行时会自行重建 NACCControl 自启键。")
    print("=" * 60)


def do_stop():
    """关停 NACC（完整：进程 + 服务 + 解除驱动绑定）。
    【关键顺序修正 2026-10-12】必须「先杀守护进程，再禁服务」！
    逆向 CCMon.exe 发现：CCMon 有每 500ms 周期的服务自愈（FUN_004014d1），
    会检测 NACCService 的 start_type，若 != AUTO(2) 就 ChangeServiceConfigA
    改回 AUTO，若 STOPPED 就 StartServiceA 拉起。因此若「先禁服务再杀 CCMon」，
    CCMon 会在被杀前的自愈周期内把服务改回 AUTO 并拉起，导致服务又起来。
    正确顺序：先杀掉所有守护进程（CCMon/StartCCMon/NACCControl）斩断自愈源，
    再杀 NACC.exe，最后禁服务（此时已无 CCMon 改回）。
    """
    print("=" * 60)
    print("NACC 自由关停（完整模式）")
    print("=" * 60)

    # 步骤 1：先杀所有守护进程（斩断 CCMon 的 500ms 服务自愈源）
    print("\n[1/3] 杀守护进程（CCMon/StartCCMon/NACCControl）+ NACC.exe ...")
    kill_processes()

    # 步骤 2：杀守护进程后再禁用服务（此时无 CCMon 改回 AUTO）
    print("\n[2/3] 禁用 NACCService ...")
    disable_service()

    # 步骤 3：解除驱动绑定（安全，不断网）
    print("\n[3/3] 解除 ndisnac 驱动绑定 ...")
    unbind_driver()

    # 验证
    print("\n" + "-" * 40)
    time.sleep(2)
    show_status_inline()


def check_driver_health():
    """检查驱动是否处于异常状态（Stop Pending 僵尸状态会引发断网）。

    返回 (ok, 异常驱动列表)。Stop Pending 只能靠重启恢复。
    """
    abnormal = []
    for d in ["ndisnac", "tdinac"]:
        code, out, _ = run_cmd(["sc", "query", d])
        for line in out.splitlines():
            if "STATE" in line.upper():
                state = line.split(":")[-1].strip()
                if "STOP_PENDING" in state.upper() or "STOPPED" in state.upper():
                    abnormal.append((d, state.strip()))
    return (len(abnormal) == 0, abnormal)


def do_start():
    """恢复 NACC（完整：服务 + 进程 + 恢复驱动绑定）。

    顺序说明（关键）：
      ① 先检查驱动健康（Stop Pending 僵尸状态需重启）
      ② 恢复驱动绑定（先让 ndisnac 重新绑定网卡）
      ③ 再启动服务（后启动，避免服务重启瞬间驱动异常断网）
    """
    print("=" * 60)
    print("NACC 恢复（完整模式）")
    print("=" * 60)

    # 步骤 0：检查驱动健康
    ok, abnormal = check_driver_health()
    if not ok:
        print("\n[!] 警告：以下驱动处于异常状态（Stop Pending/Stopped）：")
        for d, s in abnormal:
            print(f"    - {d}: {s}")
        print("    这种状态启动服务会导致断网，建议【重启计算机】恢复。")
        print("    是否仍要继续恢复？(y/n)")
        ans = input().strip().lower()
        if ans != "y":
            print("已取消恢复。请重启计算机后重试。")
            return

    # 步骤 1：恢复驱动绑定（先于服务，避免断网）
    print("\n[1/3] 恢复 ndisnac 驱动绑定 ...")
    bind_driver()

    # 步骤 2：恢复服务为自动 + 启动
    print("\n[2/3] 恢复并启动 NACCService ...")
    enable_service()
    start_service()

    # 步骤 3：等待进程拉起
    print("\n[3/3] 等待进程拉起 ...")
    time.sleep(3)
    show_status_inline()


def do_kill():
    """仅杀进程（最轻量，不碰服务/驱动）。"""
    print("=" * 60)
    print("NACC 关停（仅杀进程，不解除驱动绑定）")
    print("=" * 60)
    print("[!] 提示：仅杀进程会被 CCMon 守护拉起，建议用 stop 完整关停。")
    print()
    kill_processes()


def show_status_inline():
    """内联显示当前状态。"""
    state, start_type = get_service_state()
    procs = get_running_processes()
    bindings = get_driver_binding_state()

    print(f"\n[状态] NACCService: {state} (启动类型 {start_type})")
    if procs:
        print(f"[状态] 进程: {', '.join(f'{n}({p})' for p, n in procs.items())}")
    else:
        print("[状态] 进程: 无 NACC 相关进程")
    if isinstance(bindings, list):
        bound = [b for b in bindings if b.get("Enabled")]
        unbound = [b for b in bindings if not b.get("Enabled")]
        if bound:
            print(f"[状态] ndisnac 绑定中: {', '.join(b['Name'] for b in bound)}")
        if unbound:
            print(f"[状态] ndisnac 已解绑: {', '.join(b['Name'] for b in unbound)}")
    print()


def do_status():
    """查看状态。"""
    print("=" * 60)
    print("NACC 当前状态")
    print("=" * 60)
    show_status_inline()


def main():
    cmd = sys.argv[1] if len(sys.argv) > 1 else "status"

    # 帮助信息无需管理员
    if cmd not in ("stop", "start", "kill", "status", "disable", "enable"):
        print(__doc__)
        sys.exit(0)

    # status 无需管理员；其余命令需要
    if cmd != "status" and not is_admin():
        print("[!] 需要管理员权限（杀进程/改服务/改注册表/解除驱动绑定需提权）")
        print("    请用管理员身份运行。")
        sys.exit(1)

    if cmd == "stop":
        do_stop()
    elif cmd == "start":
        do_start()
    elif cmd == "kill":
        do_kill()
    elif cmd == "status":
        do_status()
    elif cmd == "disable":
        do_disable()
    elif cmd == "enable":
        do_enable()


if __name__ == "__main__":
    main()
