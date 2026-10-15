#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
802.1X EAPOL Supplicant 模拟（复现 NACC.exe 的 Simulate 802dot1x auth）

安全评估用途：验证「伪造终端能否完成交换机 802.1X 认证」。

逆向依据（NACC.exe）：
    - "Notice_Simulate802dot1xAuth" / "ready to simulate 802.1x authen"
    - "[802.CtrlServerEvent] Receive EAP_SUCCESS Packet"
    客户端在用户态自己收发 EAPOL 报文代答，收到 EAP_SUCCESS 即认证成功。

关键事实（决定本模块形态）：
    - 认证凭据是【账号体系】(Dot1x_Auth_Info)，非设备证书(EAP-TLS)，
      安装包无 .p12/.pfx/.pem。
    - 但「交换机具体用哪种 EAP 方法」(EAP-MD5 / PEAP / EAP-TLS) 以及
      「EAP 挑战的具体报文内容」必须抓包确认 —— 这是静态逆向拿不到的。

本模块提供 EAPOL 收发骨架 + 常见 EAP 方法实现，
真实环境的报文字段按《抓包手册.md》填充。
"""

import sys

try:
    from scapy.all import Ether, EAPOL, EAP, sendp, sniff
    from scapy.layers.l2 import Dot1Q
except ImportError:
    print("需要 scapy: pip install scapy", file=sys.stderr)
    raise


# ============================================================================
# EAP 方法常量（RFC 3748）
# ============================================================================
EAP_TYPE_IDENTITY = 1
EAP_TYPE_NOTIFICATION = 2
EAP_TYPE_NAK = 3
EAP_TYPE_MD5 = 4          # EAP-MD5：用户名 + 密码散列（弱，可离线爆破）
EAP_TYPE_OTP = 5
EAP_TYPE_GTC = 6
EAP_TYPE_TLS = 13         # EAP-TLS：需要设备证书（本系统无客户端证书，不太可能）
EAP_TYPE_PEAP = 25        # PEAP：TLS 隧道 + 内层 MSCHAPv2
EAP_TYPE_MSCHAPV2 = 26

# EAPOL 报文类型
EAPOL_START = 1
EAPOL_LOGOFF = 2
EAPOL_PACKET = 0


class EapolSupplicant:
    """802.1X 客户端（Supplicant）模拟。"""

    def __init__(self, iface: str, identity: str, password: str):
        self.iface = iface
        self.identity = identity          # 用户名（登录 NAC 的账号）
        self.password = password          # 密码
        self.dst_mac = "01:80:c2:00:00:03"  # 802.1X 组播地址

    # ---- 底层收发 ----
    def _send_eapol(self, pkt):
        sendp(pkt, iface=self.iface, verbose=False)

    def send_eapol_start(self):
        """EAPOL-Start：主动发起认证。"""
        pkt = Ether(dst=self.dst_mac) / EAPOL(type=EAPOL_START)
        self._send_eapol(pkt)
        print(f"[eapol] 发送 EAPOL-Start on {self.iface}")

    def send_identity_response(self, req_id: int):
        """EAP-Response/Identity：回应身份请求。"""
        pkt = (Ether(dst=self.dst_mac)
               / EAPOL(type=EAPOL_PACKET)
               / EAP(code=2, id=req_id, type=EAP_TYPE_IDENTITY,
                     identity=self.identity))
        self._send_eapol(pkt)
        print(f"[eapol] 发送 EAP-Response/Identity (id={req_id})")

    def send_md5_response(self, req_id: int, challenge: bytes):
        """
        EAP-Response/MD5：回应 MD5 挑战。
        EAP-MD5 的值 = MD5(id + password + challenge)。
        （此方法最弱，可离线爆破密码；本系统具体方法需抓包确认）
        """
        import hashlib
        inner = bytes([req_id]) + self.password.encode() + challenge
        digest = hashlib.md5(inner).digest()
        pkt = (Ether(dst=self.dst_mac)
               / EAPOL(type=EAPOL_PACKET)
               / EAP(code=2, id=req_id, type=EAP_TYPE_MD5) / digest)
        self._send_eapol(pkt)
        print(f"[eapol] 发送 EAP-Response/MD5 (id={req_id})")

    # ---- 被动收包 + 状态机（骨架，需抓包补全）----
    def run(self, timeout=30):
        """
        运行认证状态机：收 EAP-Request，按类型代答，直到 EAP-Success。
        真实环境的 EAP 方法/字段需抓包确认后在此补全分支。
        """
        self.send_eapol_start()
        print(f"[eapol] 监听 {self.iface} 上的 EAPOL 报文...")

        def handler(pkt):
            if not pkt.haslayer(EAPOL):
                return
            eapol = pkt[EAPOL]
            if eapol.type != EAPOL_PACKET:
                return
            if not pkt.haslayer(EAP):
                return
            eap = pkt[EAP]

            if eap.code == 1:  # EAP-Request
                print(f"[eapol] 收到 EAP-Request type={eap.type} id={eap.id}")
                if eap.type == EAP_TYPE_IDENTITY:
                    self.send_identity_response(eap.id)
                elif eap.type == EAP_TYPE_MD5:
                    # 挑战值在 EAP 载荷里，具体偏移需抓包确认
                    # self.send_md5_response(eap.id, challenge)
                    print("[eapol]  EAP-MD5 挑战：需抓包确认 challenge 字段偏移")
                elif eap.type == EAP_TYPE_PEAP:
                    print("[eapol]  PEAP：需实现 TLS 隧道 + 内层 MSCHAPv2（复杂）")
                else:
                    print(f"[eapol]  未处理的 EAP 方法 type={eap.type}，需抓包确认")
            elif eap.code == 3:  # EAP-Success
                print("[eapol] ★ 收到 EAP-Success —— 802.1X 认证成功！")
                return True
            elif eap.code == 4:  # EAP-Failure
                print("[eapol] ★ 收到 EAP-Failure —— 认证被拒")
                return False

        sniff(iface=self.iface, filter="ether proto 0x888e",
              prn=handler, timeout=timeout, store=False)
        print("[eapol] 超时，未捕获到 EAP-Success，请检查 EAP 方法是否匹配")
        return None


def main():
    if len(sys.argv) < 4:
        print("用法: python eapol_sim.py <网卡> <用户名> <密码>")
        print("示例: python eapol_sim.py eth0 zhangsan 'P@ssw0rd'")
        sys.exit(1)

    iface, identity, password = sys.argv[1], sys.argv[2], sys.argv[3]
    sup = EapolSupplicant(iface, identity, password)
    sup.run()


if __name__ == "__main__":
    main()
