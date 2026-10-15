#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
NAC 阻断环境模拟工具（安全评估）

用途：在公司 NAC 尚未启用"网络阻断"时，用 Windows 防火墙模拟
     NAC 终端侧的白名单阻断机制，以便本地验证：
     「默认阻断所有出站 + 白名单放行」的行为，以及 MVP 上报后
     白名单是否会更新。

背景：
    ndisnac.sys 是 NDIS 过滤驱动，拦截所有网卡的收发包，
    规则由 NACC.exe 通过 IOCTL + 注册表下发（IP/域名白名单）。
    当公司启用阻断时，非白名单流量被拦；合规设备在白名单内则放行。

模拟方法：
    用 Windows 防火墙规则模拟「默认阻断出站，白名单放行」：
    - 创建"默认阻断"规则（Block 所有出站，除白名单）
    - 白名单 = NAC 服务器 IP + 合规放行目标

用法：
    python simulate_block.py start     # 启用模拟阻断
    python simulate_block.py stop      # 停止模拟阻断
    python simulate_block.py status    # 查看当前状态

注意：需要管理员权限（netsh advfirewall 需提权）。
"""

import subprocess
import sys
import os

# 修复 GBK 控制台无法输出 emoji 的问题
if sys.stdout.encoding and sys.stdout.encoding.lower() in ("gbk", "cp936"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass


RULE_BLOCK_ALL = "NAC_Sim_BlockAll_Outbound"
RULE_ALLOW_NAC = "NAC_Sim_AllowNAC_Server"
RULE_ALLOW_WHITELIST = "NAC_Sim_Allow_Whitelist"


def is_admin() -> bool:
    if os.name != "nt":
        return True
    try:
        import ctypes
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def run_netsh(args):
    return subprocess.run(["netsh", "advfirewall", "firewall"] + args,
                          capture_output=True, text=True, timeout=30)


def add_rule(name, action, direction="out", remoteip=None, protocol=None,
             remoteport=None, program=None, description=""):
    """添加防火墙规则。"""
    args = ["add", "rule",
            f"name={name}",
            f"dir={direction}",
            f"action={action}"]
    if remoteip:
        args.append(f"remoteip={remoteip}")
    if protocol:
        args.append(f"protocol={protocol}")
    if remoteport:
        args.append(f"remoteport={remoteport}")
    if program:
        args.append(f"program={program}")
    if description:
        args.append(f"description={description}")
    return run_netsh(args)


def delete_rule(name):
    return run_netsh(["delete", "rule", f"name={name}"])


def rule_exists(name):
    r = run_netsh(["show", "rule", f"name={name}"])
    return name in r.stdout


def start_block(nac_server="<NAC_SERVER_IP>"):
    """启用模拟阻断：默认阻断所有出站，白名单放行 NAC 服务器 + 常见目标。"""
    print("[simulate] 启用模拟阻断 ...")

    # 1. 删除旧规则（幂等）
    for r in [RULE_BLOCK_ALL, RULE_ALLOW_NAC, RULE_ALLOW_WHITELIST]:
        if rule_exists(r):
            delete_rule(r)

    # 2. 白名单放行 NAC 服务器（否则 MVP 无法上报）
    add_rule(RULE_ALLOW_NAC, "allow", direction="out",
             remoteip=nac_server,
             description="模拟 NAC 白名单：放行 NAC 服务器")

    # 3. 白名单放行常见目标（模拟合规设备的放行范围）
    #    实际 NAC 是按 fwdsa 策略放行，这里简化为固定白名单
    add_rule(RULE_ALLOW_WHITELIST, "allow", direction="out",
             remoteip="10.0.0.0/8,172.16.0.0/12,192.168.0.0/16",
             description="模拟 NAC 白名单：放行内网")

    # 4. 默认阻断所有其他出站（模拟 NAC 的默认拦截）
    add_rule(RULE_BLOCK_ALL, "block", direction="out",
             description="模拟 NAC 默认阻断：非白名单出站全拦")

    print("[simulate] ✅ 模拟阻断已启用：默认阻断出站，白名单放行内网+NAC服务器")
    print("[simulate] 提示：这是终端侧模拟，真实阻断在出口防火墙按 TTL/DSCP 水印执行")


def stop_block():
    """停止模拟阻断。"""
    print("[simulate] 停止模拟阻断 ...")
    for r in [RULE_BLOCK_ALL, RULE_ALLOW_NAC, RULE_ALLOW_WHITELIST]:
        if rule_exists(r):
            delete_rule(r)
    print("[simulate] ✅ 已停止模拟阻断，恢复默认防火墙")


def show_status():
    """显示当前模拟阻断状态。"""
    print("[simulate] 当前模拟阻断状态：")
    for r in [RULE_BLOCK_ALL, RULE_ALLOW_NAC, RULE_ALLOW_WHITELIST]:
        exists = rule_exists(r)
        print(f"  {'✅' if exists else '❌'} {r}")
    if rule_exists(RULE_BLOCK_ALL):
        print("\n  当前状态：阻断已启用（默认阻断出站）")
    else:
        print("\n  当前状态：阻断未启用（正常出站）")


def main():
    if not is_admin():
        print("[!] 需要管理员权限（netsh advfirewall 需提权）")
        print("    请用管理员身份运行。")
        sys.exit(1)

    cmd = sys.argv[1] if len(sys.argv) > 1 else "status"

    if cmd == "start":
        start_block()
    elif cmd == "stop":
        stop_block()
    elif cmd == "status":
        show_status()
    else:
        print(__doc__)
        sys.exit(1)


if __name__ == "__main__":
    main()
