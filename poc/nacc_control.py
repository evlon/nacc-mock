#!/usr/bin/env python3
# -*- coding: utf-8 -*-
r"""
NACC 自由关停补丁（安全评估）

用途：自由地关停 / 恢复 启明星辰天珣 NAC 客户端（NACC.exe / NACCService / ndisnac 驱动）。

核心机制（基于逆向 + 实测验证）：
    1. NACC 自保护守护链：
       - NACCService（LocalSystem 服务）→ NACC.exe（主进程）
       - CCMon.exe（守护进程，定时轮询 Process32First/Next 枚举进程，
         发现 NACC.exe 不在就 StartServiceA(NACCService) 重新拉起）
       - 自启动：HKLM\...\Run\NACCControl = NACCControl.exe
    2. 关停的正确顺序（关键，否则被守护拉起）：
       ① 先禁用服务 sc config NACCService start= disabled
          （让 CCMon 的 StartServiceA 失败，斩断守护链）
       ② 同时杀 NACC.exe / CCMon.exe / NACCControl.exe
       ③ 解除 ndisnac 驱动对网卡的绑定（等效手动取消勾选，不断网）
    3. 【重要教训】不要 sc stop ndisnac/tdinac 驱动！
       - ndisnac 是 NDIS 过滤驱动，sc stop 会导致网卡网络栈异常断网
       - tdinac 会卡在 Stop Pending 僵尸状态，只能重启恢复
       - 正确做法是用 Disable-NetAdapterBinding 解除绑定（安全、不断网）

用法：
    python nacc_control.py stop      # 关停 NACC（进程 + 服务 + 解除驱动绑定）
    python nacc_control.py start     # 恢复 NACC（服务 + 进程 + 恢复驱动绑定）
    python nacc_control.py status    # 查看当前状态
    python nacc_control.py kill      # 仅杀进程（不解除驱动绑定，最轻量）

注意：需要管理员权限。
"""

import subprocess
import sys
import os
import time

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


def kill_processes():
    """杀所有 NACC 相关进程。"""
    procs = get_running_processes()
    if not procs:
        print("  无 NACC 相关进程在运行")
        return
    for pid, name in procs.items():
        try:
            subprocess.run(["taskkill", "/F", "/PID", str(pid)],
                           capture_output=True, timeout=30)
            print(f"  已杀 {name} (PID {pid})")
        except Exception as e:
            print(f"  [!] 杀 {name} (PID {pid}) 失败: {e}")


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


def do_stop():
    """关停 NACC（完整：进程 + 服务 + 解除驱动绑定）。"""
    print("=" * 60)
    print("NACC 自由关停（完整模式）")
    print("=" * 60)

    # 步骤 1：禁用服务（斩断守护链）
    print("\n[1/3] 禁用 NACCService ...")
    disable_service()

    # 步骤 2：杀进程（守护链全部成员）
    print("\n[2/3] 杀 NACC 相关进程 ...")
    kill_processes()

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
    if cmd not in ("stop", "start", "kill", "status"):
        print(__doc__)
        sys.exit(0)

    # status 无需管理员；stop/start/kill 需要
    if cmd != "status" and not is_admin():
        print("[!] 需要管理员权限（杀进程/改服务/解除驱动绑定需提权）")
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


if __name__ == "__main__":
    main()
