#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""验证签名算法（AES-192-ECB）的 Python 参考实现，用于比对 shell 版逻辑。

目的：确认 nac_openwrt.sh 里 build_signature 的算法步骤正确：
  1. 明文 = sprintf("%d %s %d", ts+5, sessionid, flag) + 30空格
  2. 密钥 = base64_decode(pskey) → 24字节
  3. AES-192-ECB 加密（明文已 16 对齐，nopad）
  4. Base64 输出
"""
import base64
from Crypto.Cipher import AES

def build_signature(sessionid, pskey, flag, ts=None):
    import time
    if ts is None:
        ts = int(time.time()) + 5
    plaintext = "%d %s %d" % (ts, sessionid, flag)
    plaintext = plaintext + " " * 30
    key = base64.b64decode(pskey)
    assert len(key) == 24, "pskey 解码后应为 24 字节（AES-192）"
    # 零填充到 16 字节对齐（MVP 实测：\x00 填充，非 PKCS7）
    pad_len = (16 - len(plaintext) % 16) % 16
    plaintext_bytes = plaintext.encode("utf-8") + b"\x00" * pad_len
    cipher = AES.new(key, AES.MODE_ECB)
    ct = cipher.encrypt(plaintext_bytes)
    return base64.b64encode(ct).decode("ascii")

if __name__ == "__main__":
    sessionid = "<SESSIONID_PLACEHOLDER>"
    pskey = "<NAC_PSKEY>"
    flag = 5

    # 验证 pskey base64 解码长度
    key = base64.b64decode(pskey)
    print("pskey base64 解码长度 = %d 字节（应为 24 = AES-192）" % len(key))
    print("pskey base64 解码 hex = %s" % key.hex())

    # 用固定 ts 验证（可复现）
    ts = 1791604916  # 之前实测命中的 ts
    sig = build_signature(sessionid, pskey, flag, ts=ts)
    print()
    print("固定 ts=%d 的签名 = %s" % (ts, sig))

    # 关键：验证 openssl 等价性所需的 key hex（供 shell 脚本 -K 参数）
    print()
    print("=== 供 shell 脚本 openssl 使用的参数 ===")
    print("key_hex (base64_decode(pskey)) = %s" % key.hex())
    plaintext = "%d %s %d" % (ts, sessionid, flag) + " " * 30
    pad_len = (16 - len(plaintext) % 16) % 16
    plaintext_bytes = plaintext.encode() + b"\x00" * pad_len
    print("明文长度（填充前）= %d" % len(plaintext))
    print("填充后长度 = %d（16的倍数）" % len(plaintext_bytes))
    print("明文 hex（填充后）= %s" % plaintext_bytes.hex())
