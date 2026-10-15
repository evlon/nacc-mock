#!/bin/sh
# 验证 shell 版签名算法 vs Python 参考实现
sessionid="<SESSIONID_PLACEHOLDER>"
pskey="<NAC_PSKEY>"
flag=5
ts=1791604916

plaintext=$(printf "%d %s %d" "$ts" "$sessionid" "$flag")
plaintext="${plaintext}                              "

key_hex=$(echo -n "$pskey" | base64 -d 2>/dev/null | xxd -p | tr -d '\n')

plaintext_hex=$(printf "%s" "$plaintext" | xxd -p | tr -d '\n')
pad_len=$(( (16 - ${#plaintext} % 16) % 16 ))
i=0
while [ $i -lt $pad_len ]; do
    plaintext_hex="${plaintext_hex}00"
    i=$((i+1))
done

sig=$(echo -n "$plaintext_hex" | xxd -r -p 2>/dev/null | openssl enc -aes-192-ecb -K "$key_hex" -nopad 2>/dev/null | base64 | tr -d '\n')

echo "shell 版签名 = $sig"
echo "Python 参考 = <SIG_CIPHERTEXT>"
echo ""
if [ "$sig" = "<SIG_CIPHERTEXT>" ]; then
    echo "OK: 签名算法一致"
else
    echo "FAIL: 不一致"
fi
