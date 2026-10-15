#!/bin/sh
# ============================================================================
# nac_openwrt.sh — 启明星辰天珣 NAC 客户端（OpenWrt 版）
#
# 把 NAC 客户端完整功能搬到 OpenWrt 路由器上运行：
#   1. 登录（/nac/user/auth/password，密码 base64 明文，非 AES）
#   2. 获取 pskey（access_policy.json 的 client_policy_xml 内）
#   3. 签名（AES-192-ECB）+ 上报合规（check/helper + check/result）
#   4. 心跳保活（check/session 循环）
#   5. 设置出口 TTL+DSCP 水印（nftables/iptables POSTROUTING，仅 under_nat=1）
#
# 依赖（OpenWrt 默认自带，缺则 opkg install）：
#   openssl-util  (opkg install openssl-util)  —— AES 加解密
#   curl 或 wget  —— HTTPS 请求（wget 需 wget-ssl）
#   nftables 或 iptables —— 水印打标
#
# 用法：
#   sh nac_openwrt.sh config       # 交互式/编辑配置
#   sh nac_openwrt.sh login        # 仅登录，输出 sessionid + pskey
#   sh nac_openwrt.sh run          # 完整运行（登录→上报→心跳循环）
#   sh nac_openwrt.sh watermark-on # 只打水印
#   sh nac_openwrt.sh watermark-off # 清除水印
#   sh nac_openwrt.sh status       # 查看状态
#
# 配置：编辑本文件开头的 CONFIG 区，或写入 /etc/config/nac_openwrt
# ============================================================================

# ============================ 配置区 ============================
# 说明：只有「账号密码 + URL」是静态凭据，其余（pskey/device_id/autologin_flag/
#       水印 TTL/DSCP/GUID）全部在运行时从服务器动态获取，见下方 *_FILE 运行时文件。

# NAC 服务器地址（静态 URL）
NAC_SERVER="<NAC_SERVER_IP>"
NAC_PORT="443"
NAC_BASE="https://${NAC_SERVER}:${NAC_PORT}"

# NAC 账号（静态凭据，需真实密码）
NAC_USERNAME="<NAC_USERNAME>"
NAC_PASSWORD="<NAC_PASSWORD>"   # NAC 真实密码（已授权测试）

# 路由器出口网卡（可留空自动探测默认路由出口；上联到公司网络的口）
WAN_IF=""        # 空 = 自动探测（ip route get 8.8.8.8）

# TLS 校验（评估阶段跳过，正式应加载服务器 CA）
VERIFY_TLS="0"   # 0=跳过校验(-k)，1=校验

# 心跳间隔（秒）
HEARTBEAT_INTERVAL="10"
# 合规重报间隔（秒）
RECHECK_INTERVAL="120"

# ============================ 运行时文件（动态状态） ============================
# 这些参数不写死，运行时从服务器/本机动态获取后存这里：
TMP_DIR="/tmp/nac_openwrt"
SESSIONID_FILE="${TMP_DIR}/sessionid"       # 登录后从 cookie 获取（临时，服务器会重新下发）
PSKEY_FILE="${TMP_DIR}/pskey"               # access_policy.json 下发（临时）
DEVICEID_FILE="${TMP_DIR}/device_id"        # access_policy.json 下发（临时）
AUTOLOGIN_FILE="${TMP_DIR}/autologin_flag"  # access_policy.json 下发（临时）
TTL_FILE="${TMP_DIR}/watermark_ttl"         # check/result 响应下发（临时，under_nat=1）
DSCP_FILE="${TMP_DIR}/watermark_dscp"       # check/result 响应下发（临时）
COOKIE_FILE="${TMP_DIR}/cookies"

# GUID 是【唯一需要跨重启持久化】的设备标识：
# 首次运行生成一次 → 存非易失位置 → 之后每次复用（有则复用、无则生成）
# 不能放 /tmp（重启即失），否则每次重启换新 GUID，服务器会判"新设备"触发重新审核
GUID_FILE="/etc/config/nac_openwrt_guid"

# ============================ 工具函数 ============================

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*"
}

die() {
    log "错误: $*"
    exit 1
}

# HTTPS 请求封装（优先 curl，回退 wget）
http_req() {
    # $1 = method (GET/POST)，$2 = url，$3 = post data（POST 时）
    local method="$1" url="$2" data="$3"
    local curl_opts=""

    if [ "$VERIFY_TLS" = "0" ]; then
        curl_opts="-k"
    fi

    if command -v curl >/dev/null 2>&1; then
        if [ "$method" = "POST" ]; then
            curl -s $curl_opts -c "${COOKIE_FILE}" -b "${COOKIE_FILE}" \
                -X POST -d "$data" "$url"
        else
            curl -s $curl_opts -c "${COOKIE_FILE}" -b "${COOKIE_FILE}" "$url"
        fi
    else
        # wget 回退
        local wget_opts=""
        if [ "$VERIFY_TLS" = "0" ]; then
            wget_opts="--no-check-certificate"
        fi
        if [ "$method" = "POST" ]; then
            wget $wget_opts -qO- --save-cookies "${COOKIE_FILE}" \
                --load-cookies "${COOKIE_FILE}" --post-data="$data" "$url"
        else
            wget $wget_opts -qO- --save-cookies "${COOKIE_FILE}" \
                --load-cookies "${COOKIE_FILE}" "$url"
        fi
    fi
}

# 从 cookie 文件提取 VSG_SESSIONID
get_sessionid() {
    grep "VSG_SESSIONID" "${COOKIE_FILE}" 2>/dev/null | awk '{print $NF}'
}

# 从 JSON 提取字符串字段（优先 jq，回退 sed）
# 用法：json_get <json> <key>
json_get() {
    local json="$1" key="$2" val=""
    if command -v jq >/dev/null 2>&1; then
        val=$(echo "$json" | jq -r ".${key} // empty" 2>/dev/null)
    else
        # 兼容数字/字符串值：先匹配 "key":"str"，再匹配 "key":num
        val=$(echo "$json" | sed -n "s/.*\"${key}\"[[:space:]]*:[[:space:]]*\"\([^\"]*\)\".*/\1/p")
        [ -z "$val" ] && val=$(echo "$json" | sed -n "s/.*\"${key}\"[[:space:]]*:[[:space:]]*\([0-9][0-9]*\).*/\1/p")
    fi
    echo -n "$val"
}

# 生成随机 GUID（伪装设备标识，首次运行生成后持久化）
gen_guid() {
    # 用 /dev/urandom 生成 16 字节，格式化成 GUID
    local hex
    hex=$(head -c 16 /dev/urandom 2>/dev/null | xxd -p | tr -d '\n')
    # 置版本位 4 和变体位 8/9/a/b（标准 GUID）
    echo "${hex:0:8}-${hex:8:4}-${hex:12:4}-${hex:16:4}-${hex:20:12}" | tr '[:lower:]' '[:upper:]'
}

# 获取 GUID（有则复用、无则生成并持久化到非易失位置）
get_guid() {
    local guid=""
    [ -f "${GUID_FILE}" ] && guid=$(cat "${GUID_FILE}" 2>/dev/null)
    if [ -z "$guid" ]; then
        guid=$(gen_guid)
        echo -n "$guid" > "${GUID_FILE}"
        log "首次运行，生成并持久化新设备 GUID=$guid" >&2   # 日志走 stderr，避免污染返回值
    fi
    echo -n "$guid"
}

# ============================ 加密函数 ============================

# 密码"加密"：实测前端就是 base64(明文)，不是 AES！
# 抓包证据（前端 auth/password 请求体）：
#   password=<NAC_PASSWORD_B64>  == base64("<NAC_PASSWORD>")
# 之前误以为 AES-128-CBC(key=1234567890abcdef)，那是解密服务器下发配置(FUN_005499c0)用的，与登录密码无关。
encrypt_password() {
    local plain="$1"
    echo -n "$plain" | base64 2>/dev/null | tr -d '\n'
}

# base64 解码（busybox 兼容）
b64decode() {
    echo -n "$1" | base64 -d 2>/dev/null
}

# base64 编码（busybox 兼容）
b64encode() {
    echo -n "$1" | base64 2>/dev/null | tr -d '\n'
}

# 签名：AES-192-ECB(base64_decode(pskey), sprintf("%d %s %d", ts+5, sessionid, flag) + 30空格)
# 明文需零填充（\x00）到 16 字节对齐，再 ECB 加密，结果 base64
build_signature() {
    local sessionid="$1" pskey="$2" flag="$3"
    local ts plaintext key_hex pad_len plaintext_hex i

    ts=$(( $(date +%s) + 5 ))

    # 明文 = "ts sessionid flag" + 30 个空格
    plaintext=$(printf "%d %s %d" "$ts" "$sessionid" "$flag")
    plaintext="${plaintext}                              "   # 追加 30 空格

    # 密钥 = base64_decode(pskey) → 24 字节 → hex
    key_hex=$(echo -n "$pskey" | base64 -d 2>/dev/null | xxd -p | tr -d '\n')

    # 明文转 hex，零填充到 16 字节对齐（shell 变量不能存 NUL，用 hex 拼接）
    plaintext_hex=$(printf "%s" "$plaintext" | xxd -p | tr -d '\n')
    pad_len=$(( (16 - ${#plaintext} % 16) % 16 ))
    i=0
    while [ $i -lt $pad_len ]; do
        plaintext_hex="${plaintext_hex}00"
        i=$((i+1))
    done

    # AES-192-ECB（nopad，已手动对齐），hex→二进制→加密→base64
    echo -n "$plaintext_hex" | xxd -r -p 2>/dev/null | \
        openssl enc -aes-192-ecb -K "$key_hex" -nopad 2>/dev/null | \
        base64 | tr -d '\n'
}

# ============================ 设备信息 ============================

# 探测出口网卡（WAN_IF 未配置时，取默认路由出口）
resolve_wan_if() {
    if [ -n "$WAN_IF" ]; then
        echo -n "$WAN_IF"
        return
    fi
    # 通过默认路由探测出口网卡
    local iface=""
    if command -v ip >/dev/null 2>&1; then
        iface=$(ip route get 8.8.8.8 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1); exit}}')
    fi
    [ -z "$iface" ] && iface=$(route -n 2>/dev/null | awk '$1=="0.0.0.0"{print $8; exit}')
    [ -z "$iface" ] && iface="wan"
    echo -n "$iface"
}

# 获取本机出口 IP（路由器 WAN IP）
get_wan_ip() {
    local iface ip
    iface=$(resolve_wan_if)
    ip=""
    if command -v ip >/dev/null 2>&1; then
        ip=$(ip -4 addr show dev "$iface" 2>/dev/null | awk '/inet /{print $2}' | cut -d/ -f1 | head -1)
    fi
    [ -z "$ip" ] && ip=$(ip route get "$NAC_SERVER" 2>/dev/null | awk '{print $NF; exit}')
    echo -n "$ip"
}

# 获取 WAN MAC
get_wan_mac() {
    local iface mac
    iface=$(resolve_wan_if)
    mac=""
    if command -v ip >/dev/null 2>&1; then
        mac=$(ip link show dev "$iface" 2>/dev/null | awk '/link\/ether/{print $2}')
    fi
    echo -n "$mac" | tr '[:lower:]' '[:upper:]'
}

# 构造 onlineaddrs（格式 100% 破解）
# g{device_id}_h{GUID}~8xxxm{MAC}_8xxxi{IPv4}
build_onlineaddrs() {
    local device_id="$1" guid="$2" mac="$3" ipv4="$4"
    echo -n "g${device_id}_h${guid}~8xxxm${mac}_8xxxi${ipv4}"
}

# ============================ 协议流程 ============================

# 步骤1：登录
do_login() {
    log "登录 NAC ..."
    mkdir -p "${TMP_DIR}"
    rm -f "${COOKIE_FILE}"

    local enc_user enc_pwd wan_ip
    enc_user=$(b64encode "$NAC_USERNAME")     # username 也 base64
    enc_pwd=$(encrypt_password "$NAC_PASSWORD")  # password = base64(明文)
    wan_ip=$(get_wan_ip)

    # 完整参数（实测抓包 100% 还原）：
    #   username=<b64> & password=<b64> & verifycode= & challenge= & terminal= &
    #   rmbpwd_browser= & encode=1 & type= & auto_login= & realip=<WAN_IP> &
    #   access_net_flag=1 & terminal_type=windows & onlineaddrs=g~3xxxi<WAN_IP>
    local post_data
    post_data="username=${enc_user}&password=${enc_pwd}&verifycode=&challenge=&terminal=&rmbpwd_browser=&encode=1&type=&auto_login=&realip=${wan_ip}&access_net_flag=1&terminal_type=windows&onlineaddrs=g~3xxxi${wan_ip}"

    local resp code
    resp=$(http_req POST "${NAC_BASE}/nac/user/auth/password?t=$(date +%s%3N)" "$post_data")

    log "登录响应: $(echo "$resp" | head -c 300)"

    # 判定登录成败：直接看响应 body 的 code（0x00000000=成功）
    code=$(json_get "$resp" "code")
    if [ "$code" != "0x00000000" ] && [ -n "$code" ]; then
        log "登录失败: code=$code msg=$(json_get "$resp" "msg")"
        return 1
    fi

    # 登录成功 → 从 Set-Cookie 提取 sessionid
    local sid
    sid=$(get_sessionid)
    if [ -z "$sid" ] || [ "$sid" = "0" ] || [ "$sid" = "VSG_SESSIONID" ]; then
        log "登录失败（未获取到有效 sessionid）"
        return 1
    fi

    echo -n "$sid" > "${SESSIONID_FILE}"
    log "登录成功，sessionid=$sid"
    return 0
}

# 步骤2：获取 access_policy（动态解析 pskey + device_id + autologin_flag）
do_get_policy() {
    log "获取 access_policy ..."
    local resp pskey device_id autologin_flag
    resp=$(http_req GET "${NAC_BASE}/nac/user/check/access_policy.json")

    device_id=$(json_get "$resp" "device_id")
    autologin_flag=$(json_get "$resp" "autologin_flag")

    # pskey 在顶层 JSON 里没有单独字段，而是嵌在 client_policy_xml 的 POLICY 标签里：
    #   client_policy_xml="...<POLICY ... pskey=\"xxx\" .../>"
    # 所以要从 client_policy_xml 里 grep 提取
    pskey=$(echo "$resp" | grep -oE 'pskey=\\"[^\\"]*\\"' | head -1 | sed 's/pskey=\\"//; s/\\"//')

    if [ -z "$pskey" ]; then
        log "未获取到 pskey（响应: $(echo "$resp" | head -c 200)）"
        return 1
    fi

    echo -n "$pskey" > "${PSKEY_FILE}"
    [ -n "$device_id" ] && echo -n "$device_id" > "${DEVICEID_FILE}"
    [ -n "$autologin_flag" ] && echo -n "$autologin_flag" > "${AUTOLOGIN_FILE}"

    log "获取策略成功: pskey=(已存) device_id=${device_id:-未知} autologin_flag=${autologin_flag:-未知}"
    return 0
}

# 步骤3：签名 + 上报合规（动态读取 device_id/autologin_flag/guid，
#        并解析响应里的 under_nat + nat_ip_ttl + nat_qos_dscp 存为水印参数）
do_report() {
    local sid pskey autologin_flag device_id guid sig enc_username
    local onlineaddrs wan_ip wan_mac

    sid=$(cat "${SESSIONID_FILE}" 2>/dev/null)
    pskey=$(cat "${PSKEY_FILE}" 2>/dev/null)
    autologin_flag=$(cat "${AUTOLOGIN_FILE}" 2>/dev/null)
    device_id=$(cat "${DEVICEID_FILE}" 2>/dev/null)
    guid=$(get_guid)
    [ -z "$sid" ] && { log "无 sessionid"; return 1; }
    [ -z "$pskey" ] && { log "无 pskey"; return 1; }
    [ -z "$autologin_flag" ] && autologin_flag="0"

    sig=$(build_signature "$sid" "$pskey" "$autologin_flag")

    # username base64
    enc_username=$(b64encode "$NAC_USERNAME")

    # onlineaddrs（GUID 动态生成，MAC/IP 本机采集，device_id 服务器下发）
    wan_ip=$(get_wan_ip)
    wan_mac=$(get_wan_mac)
    onlineaddrs=$(build_onlineaddrs "$device_id" "$guid" "$wan_mac" "$wan_ip")

    log "上报合规 score=90 ..."
    log "  device_id=$device_id guid=$guid mac=$wan_mac ip=$wan_ip"
    log "  onlineaddrs=$onlineaddrs"
    log "  signature=$sig"

    # ① check/helper
    local helper_url helper_resp
    helper_url="${NAC_BASE}/nac/dev/check/helper?username=${enc_username}&value=${sig}"
    helper_resp=$(http_req GET "$helper_url")
    log "  helper 响应: $(echo "$helper_resp" | head -c 200)"

    # ② check/result
    local ts result_url result_body result_resp
    ts=$(date +%s%3N 2>/dev/null || echo $(( $(date +%s) * 1000 )))
    result_url="${NAC_BASE}/nac/dev/check/result?t=${ts}"
    result_body="score=90&onlineaddrs=${onlineaddrs}"
    result_resp=$(http_req POST "$result_url" "$result_body")

    log "  result 响应: $result_resp"

    # 动态解析放行字段，并持久化水印参数（服务器下发，不写死）
    local fwdsa under_nat nat_ip_ttl nat_qos_dscp
    fwdsa=$(json_get "$result_resp" "fwdsa")
    under_nat=$(json_get "$result_resp" "under_nat")
    nat_ip_ttl=$(json_get "$result_resp" "nat_ip_ttl")
    nat_qos_dscp=$(json_get "$result_resp" "nat_qos_dscp")

    log "  解析: fwdsa=${fwdsa} under_nat=${under_nat} nat_ip_ttl=${nat_ip_ttl} nat_qos_dscp=${nat_qos_dscp}"

    # under_nat=1 时，服务器下发 TTL/DSCP 水印参数 → 持久化供 watermark_on 使用
    if [ "$under_nat" = "1" ] && [ -n "$nat_ip_ttl" ] && [ "$nat_ip_ttl" != "0" ]; then
        echo -n "$nat_ip_ttl" > "${TTL_FILE}"
        echo -n "$nat_qos_dscp" > "${DSCP_FILE}"
        log "  已记录水印参数 TTL=${nat_ip_ttl} DSCP=${nat_qos_dscp}"
    fi

    return 0
}

# 步骤4：心跳（动态读取 device_id/guid）
do_heartbeat() {
    local sid onlineaddrs wan_ip wan_mac device_id guid
    sid=$(cat "${SESSIONID_FILE}" 2>/dev/null)
    [ -z "$sid" ] && return 1

    device_id=$(cat "${DEVICEID_FILE}" 2>/dev/null)
    guid=$(get_guid)
    wan_ip=$(get_wan_ip)
    wan_mac=$(get_wan_mac)
    onlineaddrs=$(build_onlineaddrs "$device_id" "$guid" "$wan_mac" "$wan_ip")

    local body
    body="key=dateGmt&onlineaddrs=${onlineaddrs}&addressupdate=0&terminal_type=0"
    http_req POST "${NAC_BASE}/nac/user/check/session" "$body" >/dev/null 2>&1
    return 0
}

# ============================ 水印 ============================

# 打 TTL+DSCP 水印（在 POSTROUTING 出口打，最后一跳，无需 +1）
# 参数从运行时文件读取（服务器 check/result 动态下发，不写死）
watermark_on() {
    local ttl dscp iface
    ttl=$(cat "${TTL_FILE}" 2>/dev/null)
    dscp=$(cat "${DSCP_FILE}" 2>/dev/null)
    iface=$(resolve_wan_if)

    # 无动态参数时，尝试手动传参（watermark-on 命令可带 TTL DSCP）
    [ -z "$ttl" ] && ttl="$1"
    [ -z "$dscp" ] && dscp="$2"
    [ -z "$ttl" ] && { log "无 TTL 水印参数（需先 do_report 拿到服务器下发值，或手动传参）"; return 1; }
    [ -z "$dscp" ] && dscp="0"

    log "打 TTL=${ttl} DSCP=${dscp} 水印到 ${iface} ..."

    if command -v nft >/dev/null 2>&1 && nft list tables 2>/dev/null | grep -q .; then
        # nftables
        nft add table inet nac_openwrt 2>/dev/null
        nft add chain inet nac_openwrt postrouting '{ type filter hook postrouting priority 0; }' 2>/dev/null
        nft flush chain inet nac_openwrt postrouting 2>/dev/null
        nft add rule inet nac_openwrt postrouting oifname "$iface" ip ttl set "$ttl"
        nft add rule inet nac_openwrt postrouting oifname "$iface" ip dscp set "$dscp"
        log "已用 nftables 打水印"
    else
        # iptables
        iptables -t mangle -F NAC_WATERMARK 2>/dev/null
        iptables -t mangle -X NAC_WATERMARK 2>/dev/null
        iptables -t mangle -N NAC_WATERMARK 2>/dev/null
        iptables -t mangle -A NAC_WATERMARK -j TTL --ttl-set "$ttl"
        iptables -t mangle -A NAC_WATERMARK -j DSCP --set-dscp "$dscp"
        iptables -t mangle -A POSTROUTING -o "$iface" -j NAC_WATERMARK
        log "已用 iptables 打水印"
    fi
}

watermark_off() {
    local iface
    iface=$(resolve_wan_if)
    log "清除水印 ..."
    if command -v nft >/dev/null 2>&1; then
        nft delete table inet nac_openwrt 2>/dev/null
    fi
    iptables -t mangle -D POSTROUTING -o "$iface" -j NAC_WATERMARK 2>/dev/null
    iptables -t mangle -F NAC_WATERMARK 2>/dev/null
    iptables -t mangle -X NAC_WATERMARK 2>/dev/null
    log "水印已清除"
}

# ============================ 主流程 ============================

do_run() {
    log "========== NAC OpenWrt 客户端启动 =========="

    # 1. 登录
    if ! do_login; then
        die "登录失败"
    fi

    # 2. 获取策略（pskey + device_id + autologin_flag）
    if ! do_get_policy; then
        die "获取策略失败"
    fi

    # 3. 上报合规（内部会动态解析并记录水印参数）
    do_report || log "首次上报失败"

    # 4. 打水印（仅当服务器 under_nat=1 下发了 TTL/DSCP 才生效）
    watermark_on

    # 5. 心跳循环
    log "进入心跳循环（每 ${HEARTBEAT_INTERVAL}s 心跳，每 ${RECHECK_INTERVAL}s 重报）"
    local last_recheck=0 now
    while true; do
        now=$(date +%s)
        do_heartbeat || log "心跳失败"

        if [ $((now - last_recheck)) -ge "$RECHECK_INTERVAL" ]; then
            log "周期重报合规 ..."
            do_report
            last_recheck=$now
        fi
        sleep "$HEARTBEAT_INTERVAL"
    done
}

do_status() {
    log "NAC OpenWrt 客户端状态："
    [ -f "${SESSIONID_FILE}" ] && log "  sessionid=$(cat ${SESSIONID_FILE})" || log "  sessionid=(无)"
    [ -f "${PSKEY_FILE}" ] && log "  pskey=$(cat ${PSKEY_FILE})" || log "  pskey=(无)"
    [ -f "${DEVICEID_FILE}" ] && log "  device_id=$(cat ${DEVICEID_FILE})" || log "  device_id=(服务器下发)"
    [ -f "${AUTOLOGIN_FILE}" ] && log "  autologin_flag=$(cat ${AUTOLOGIN_FILE})" || log "  autologin_flag=(服务器下发)"
    [ -f "${TTL_FILE}" ] && log "  水印 TTL=$(cat ${TTL_FILE})" || log "  水印 TTL=(未下发)"
    [ -f "${DSCP_FILE}" ] && log "  水印 DSCP=$(cat ${DSCP_FILE})" || log "  水印 DSCP=(未下发)"
    [ -f "${GUID_FILE}" ] && log "  GUID=$(cat ${GUID_FILE})" || log "  GUID=(未生成)"
    log "  WAN IF=$(resolve_wan_if)  WAN IP=$(get_wan_ip)  WAN MAC=$(get_wan_mac)"
}

# ============================ 入口 ============================

case "$1" in
    login)        do_login ;;
    run)          do_run ;;
    watermark-on) watermark_on "$2" "$3" ;;
    watermark-off) watermark_off ;;
    status)       do_status ;;
    report)       do_report ;;
    policy)       do_get_policy ;;
    *)
        echo "用法: $0 {login|run|policy|report|watermark-on [TTL DSCP]|watermark-off|status}"
        echo "  仅需配置 NAC_SERVER/NAC_USERNAME/NAC_PASSWORD 三个静态值，"
        echo "  其余参数（pskey/device_id/autologin_flag/TTL/DSCP/GUID）运行时自动获取。"
        exit 1
        ;;
esac
