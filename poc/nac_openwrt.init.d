#!/bin/sh /etc/rc.common
# ============================================================================
# OpenWrt init.d 脚本：NAC 客户端开机自启
# 放到 /etc/init.d/nac_openwrt，然后：
#   chmod +x /etc/init.d/nac_openwrt
#   /etc/init.d/nac_openwrt enable   # 开机自启
#   /etc/init.d/nac_openwrt start    # 手动启动
#   /etc/init.d/nac_openwrt stop     # 停止
#   /etc/init.d/nac_openwrt status   # 状态
# ============================================================================

START=99
STOP=10

# 主程序路径（部署时改）
NAC_SCRIPT="/root/nac_openwrt.sh"
PID_FILE="/var/run/nac_openwrt.pid"
LOG_FILE="/var/log/nac_openwrt.log"

start() {
    if [ ! -f "$NAC_SCRIPT" ]; then
        echo "主程序不存在: $NAC_SCRIPT"
        return 1
    fi
    echo "启动 NAC OpenWrt 客户端 ..."
    # 后台运行主程序，日志写入文件
    ( sh "$NAC_SCRIPT" run >> "$LOG_FILE" 2>&1 & echo $! > "$PID_FILE" )
    echo "已启动，PID=$(cat $PID_FILE)，日志: $LOG_FILE"
}

stop() {
    echo "停止 NAC OpenWrt 客户端 ..."
    if [ -f "$PID_FILE" ]; then
        kill "$(cat $PID_FILE)" 2>/dev/null
        rm -f "$PID_FILE"
    fi
    # 同时清水印（可选，注释掉则保留水印）
    # sh "$NAC_SCRIPT" watermark-off
}

status() {
    if [ -f "$PID_FILE" ] && kill -0 "$(cat $PID_FILE)" 2>/dev/null; then
        echo "运行中，PID=$(cat $PID_FILE)"
    else
        echo "未运行"
    fi
}
