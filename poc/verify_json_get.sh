#!/bin/sh
# 验证 json_get 函数（从 nac_openwrt.sh 提取的核心逻辑）
json_get() {
    local json="$1" key="$2" val=""
    if command -v jq >/dev/null 2>&1; then
        val=$(echo "$json" | jq -r ".${key} // empty" 2>/dev/null)
    else
        val=$(echo "$json" | sed -n "s/.*\"${key}\"[[:space:]]*:[[:space:]]*\"\([^\"]*\)\".*/\1/p")
        [ -z "$val" ] && val=$(echo "$json" | sed -n "s/.*\"${key}\"[[:space:]]*:[[:space:]]*\([0-9][0-9]*\).*/\1/p")
    fi
    echo -n "$val"
}

# 模拟 access_policy.json（pskey=字符串, device_id=数字, autologin_flag=字符串"0"）
policy='{"pskey":"<NAC_PSKEY>","device_id":3519,"autologin_flag":"0"}'

# 模拟 check/result（水印参数=数字）
result='{"fwdsa":3,"under_nat":1,"nat_ip_ttl":175,"nat_qos_dscp":41}'

echo "--- access_policy.json 解析 ---"
echo "pskey        = $(json_get "$policy" pskey)"
echo "device_id    = $(json_get "$policy" device_id)"
echo "autologin_flag = $(json_get "$policy" autologin_flag)"

echo ""
echo "--- check/result 解析 ---"
echo "fwdsa        = $(json_get "$result" fwdsa)"
echo "under_nat    = $(json_get "$result" under_nat)"
echo "nat_ip_ttl   = $(json_get "$result" nat_ip_ttl)"
echo "nat_qos_dscp = $(json_get "$result" nat_qos_dscp)"
