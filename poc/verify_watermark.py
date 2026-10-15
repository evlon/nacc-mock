#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
NAC 水印验证工具（安全评估）

用途：验证「TTL + DSCP 水印」是否真正打上了。
     这是"阻断启用后，出口防火墙能否识别水印"的前置验证。

背景：
    服务器在合规（under_nat=1）时下发 nat_ip_ttl / nat_qos_dscp，
    客户端调用 SetIpTTL / SetDSCP 给出站 IP 包打水印。
    公司出口防火墙识别水印 → 放行 NAT 后面的合规设备。

验证方法（三种，按可靠性递增）：
    1. netsh 查询：确认 Windows 默认 TTL 已改（快速，但只反映"默认值"非实际包）
    2. QoS 注册表查询：确认 DSCP 策略已写入
    3. 抓包验证：ping 一个外部地址，抓包看实际出站包的 TTL/DSCP 字段（最可靠）

注意：打水印需要管理员权限。
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


def is_admin() -> bool:
    if os.name != "nt":
        return True
    try:
        import ctypes
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def check_ttl_setting() -> dict:
    """检查 Windows 默认 TTL（defaultcurhoplimit）设置。"""
    r = subprocess.run(["netsh", "int", "ipv4", "show", "glob"],
                       capture_output=True, text=True, timeout=30)
    out = r.stdout + r.stderr
    ttl = None
    for line in out.splitlines():
        if "hop" in line.lower() and "limit" in line.lower():
            # 提取数字
            digits = "".join(ch for ch in line if ch.isdigit())
            if digits:
                ttl = int(digits)
    return {"raw": out, "default_ttl": ttl}


def check_dscp_setting() -> dict:
    """检查 QoS DSCP 策略注册表。"""
    result = {"exists": False, "dscp": None}
    try:
        import winreg
        key = r"SOFTWARE\Policies\Microsoft\Windows\QoS\ChangeQos"
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key) as k:
            result["exists"] = True
            try:
                val, _ = winreg.QueryValueEx(k, "DSCP Value")
                result["dscp"] = val
            except FileNotFoundError:
                pass
    except FileNotFoundError:
        result["exists"] = False
    except Exception as e:
        result["error"] = str(e)
    return result


def check_actual_packet_ttl(target: str = "<NAC_SERVER_IP>") -> dict:
    """用 ping 检查实际出站包的 TTL（通过回显 TTL 反推）。

    注意：ping 回显的 TTL 是「目标回包经过的跳数」，不是本机出站 TTL。
    更可靠的方法是抓包，这里用 ping 做近似（对比打水印前后回显 TTL 的变化）。
    """
    r = subprocess.run(["ping", "-n", "1", "-w", "2000", target],
                       capture_output=True, text=True, timeout=10)
    ttl = None
    for line in (r.stdout + r.stderr).splitlines():
        if "TTL=" in line.upper():
            # 提取 TTL= 后的数字
            idx = line.upper().find("TTL=")
            digits = "".join(ch for ch in line[idx+4:] if ch.isdigit())
            if digits:
                ttl = int(digits)
    return {"raw": r.stdout + r.stderr, "reply_ttl": ttl}


def capture_packet_ttl_dscp(target: str = "<NAC_SERVER_IP>", port: int = 443) -> str:
    """用 tshark 抓包验证实际出站包的 TTL 和 DSCP（最可靠）。

    需要安装 Wireshark/tshark。返回抓到的包信息。
    """
    tshark = r"C:\Program Files\Wireshark\tshark.exe"
    if not os.path.exists(tshark):
        return "[!] 未找到 tshark，请安装 Wireshark（或用 netsh 方法近似验证）"

    # 抓 1 个去往 target 的包，显示 TTL 和 DSCP（ip.dsfield）
    filter_expr = f"ip.addr == {target}"
    r = subprocess.run(
        [tshark, "-i", "2", "-c", "3", "-Y", filter_expr,
         "-T", "fields", "-e", "ip.src", "-e", "ip.dst",
         "-e", "ip.ttl", "-e", "ip.dsfield"],
        capture_output=True, text=True, timeout=30,
    )
    return r.stdout if r.stdout else r.stderr


def main():
    print("=" * 60)
    print("NAC 水印验证工具（安全评估）")
    print("=" * 60)

    if not is_admin():
        print("[!] 警告：当前非管理员，TTL/DSCP 打标需要管理员权限。")
        print("    可继续查看「当前状态」，但无法重新打标。")
        print()

    # 1. 检查 TTL 设置
    print("[1/3] 检查 Windows 默认 TTL ...")
    ttl = check_ttl_setting()
    print(f"  默认 TTL（defaultcurhoplimit）= {ttl['default_ttl']}")
    if ttl['default_ttl'] == 175:
        print("  ✅ 已设置为 175（符合水印值）")
    else:
        print("  ❌ 未设置为 175（水印未打或未生效）")

    # 2. 检查 DSCP 设置
    print("\n[2/3] 检查 QoS DSCP 策略 ...")
    dscp = check_dscp_setting()
    if dscp.get("exists"):
        print(f"  QoS 策略存在，DSCP Value = {dscp['dscp']}")
        if str(dscp['dscp']) == "41":
            print("  ✅ DSCP=41（符合水印值）")
        else:
            print("  ❌ DSCP 不是 41")
    else:
        print("  ❌ QoS 策略不存在（DSCP 水印未打）")
        if dscp.get("error"):
            print(f"    错误: {dscp['error']}")

    # 3. 抓包验证（可选，需 tshark）
    print("\n[3/3] 抓包验证实际出站包 TTL/DSCP（需 tshark）...")
    cap = capture_packet_ttl_dscp()
    if cap.startswith("[!]"):
        print(f"  {cap}")
    elif cap.strip():
        print("  抓到出站包（ip.src, ip.dst, ip.ttl, ip.dsfield）：")
        for line in cap.strip().splitlines():
            print(f"    {line}")
    else:
        print("  （未抓到包，可能无流量）")

    print()
    print("结果判读：")
    print("  - 默认 TTL=175 且 QoS DSCP=41 → 水印已打上（阻断启用后出口防火墙可识别）")
    print("  - 否则需要以管理员身份运行 nac_client_mvp.py 重新打标")
    print("  - 抓包 ip.ttl 应=175，ip.dsfield 的 DSCP 字段应=41(0x29<<2=0xA4)")


if __name__ == "__main__":
    main()
