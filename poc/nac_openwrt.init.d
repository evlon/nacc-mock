#!/bin/sh /etc/rc.common
# ============================================================================
# OpenWrt init.d 脚本：NAC 客户端开机自启（procd 规范版）
#
# 部署：
#   scp nac_openwrt.init.d root@<ROUTER_IP>:/etc/init.d/nac_openwrt
#   ssh root@<ROUTER_IP> "chmod +x /etc/init.d/nac_openwrt && /etc/init.d/nac_openwrt enable"
#
# 说明（K-WRT 25.12 / 新版 OpenWrt 用 procd 作为 init 系统）：
#   必须用 USE_PROCD=1 + start_service() + procd_open_instance 的写法。
#   旧式 rc.common 写法（自定义 start() + & 后台）在 procd 下会被清理孤儿进程，
#   表现为「软链存在、enabled 通过，但重启后不自启」。
# ============================================================================

START=99
STOP=10

USE_PROCD=1

NAC_SCRIPT="/root/nac_openwrt.sh"

start_service() {
	procd_open_instance
	procd_set_param command /bin/sh "$NAC_SCRIPT" run
	procd_set_param respawn          # 崩溃自动重启
	procd_set_param stdout 1         # stdout 进 syslog
	procd_set_param stderr 1         # stderr 进 syslog
	procd_close_instance
}

stop_service() {
	# procd 会按 instance 停止进程；这里额外做清理（可选）
	:
}
