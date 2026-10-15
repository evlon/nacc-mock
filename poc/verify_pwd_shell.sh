#!/bin/sh
# 验证登录密码"加密"方式
#
# 【重要修正 2026-10-12】登录密码是 base64(明文)，不是 AES-128-CBC！
# 抓包证据（前端 auth/password 请求体）：
#   password=<NAC_PASSWORD_B64>  == base64("<NAC_PASSWORD>")  →  即明文直接 base64
#
# 之前误以为 AES-128-CBC(key=1234567890abcdef, iv=abcdef1234567890)，
# 那是客户端解密服务器下发配置(FUN_005499c0/Ghidra)用的，与登录密码无关。
#
# 用法：sh verify_pwd_shell.sh

plain="<NAC_PASSWORD>"

# 正确方式：base64(明文)
enc=$(echo -n "$plain" | base64 2>/dev/null | tr -d '\n')

echo "明文密码   = $plain"
echo "base64(明文)= $enc"
echo ""
echo "验证：前端实际提交的 password 字段值就是 $enc"
echo "（抓包实测 password=<NAC_PASSWORD_B64>，解码后即明文 <NAC_PASSWORD>）"
echo ""
echo "结论：登录密码 = base64(明文)，无 AES 加密，HTTPS 下仍有明文泄露风险。"
