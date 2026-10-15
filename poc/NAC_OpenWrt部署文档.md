# NAC OpenWrt 客户端部署文档

> 把启明星辰天珣 NAC 客户端完整功能搬到 OpenWrt 路由器上，
> 一台路由器统一解决后面所有设备的准入（登录 + 心跳 + 上报 + TTL/DSCP 水印）。

---

## 一、方案原理

```
┌─────────────────────────────────────────────┐
│  公司网络（NAC 服务器 <NAC_SERVER_IP> / 交换机）│
└──────────────────┬──────────────────────────┘
                   │ 上联口 IP <WAN_IP> / MAC <WAN_MAC>
        ┌──────────┴──────────┐
        │  OpenWrt 路由器       │  ← 在这里跑 NAC 客户端 + 打水印
        │  (CUDY TR3000)      │
        └──────────┬──────────┘
                   │ 下联（192.168.3.x）
        ┌──────────┴──────────┐
        │ 所有终端（3.4/3.8/手机）│  ← 无需装客户端，路由器代劳
        └─────────────────────┘
```

**核心优势**：

1. **水印在路由器出口（POSTROUTING）打**，是「最后一跳」，打完即出网，
   **不存在「终端打完又被路由器 -1」的问题**，精确匹配服务器期望值；
2. 路由器后面**所有设备**统一被打水印，一台路由器解决全部终端；
3. 终端无感知、无客户端，隐蔽性好。

---

## 二、前置条件

| 项 | 说明 |
|----|------|
| 设备 | CUDY TR3000（AX3000，MTK 方案，256MB 闪存，2.5G 网口） |
| 系统 | OpenWrt（需刷入，TR3000 需确认 OpenWrt 支持情况） |
| 依赖 | `openssl-util`、`curl`（或 `wget-ssl`）、`nftables`（或 `iptables`）、`xxd` |
| 凭据 | **NAC 真实账号密码**（`<NAC_USERNAME>` 的 NAC 密码，非域密码） |
| 设备标识 | `device_id` 由服务器登录后下发；`GUID` 本机首次运行自动生成并持久化（存 `/etc/config/nac_openwrt_guid`，有则复用、无则生成） |

---

## 三、安装步骤

### 3.1 刷 OpenWrt

```bash
# 1. 确认 TR3000 是否在 OpenWrt 官方支持列表（或找第三方固件）
#    https://openwrt.org/toh/ 搜索 CUDY / TR3000
# 2. 刷机（TFTP / Breed / 官方后台升级，视设备而定）
# 3. 刷入后首次登录
ssh root@192.168.1.1
```

### 3.2 安装依赖

```bash
opkg update
opkg install openssl-util curl xxd nftables
# 如果 nftables 不可用，用 iptables：
# opkg install iptables-mod-ttl iptables-mod-ipopt
```

> 注意：`iptables` 打 TTL 需要 `iptables-mod-ttl` 内核模块；
> 打 DSCP 需要 `iptables-mod-ipopt`。nftables 则原生支持，推荐 nftables。

### 3.3 部署主程序

```bash
# 上传脚本（从开发机 scp）
scp nac_openwrt.sh root@192.168.1.1:/root/
ssh root@192.168.1.1 "chmod +x /root/nac_openwrt.sh"

# 上传 init.d 自启脚本
scp nac_openwrt.init.d root@192.168.1.1:/etc/init.d/nac_openwrt
ssh root@192.168.1.1 "chmod +x /etc/init.d/nac_openwrt"
```

### 3.35 开机自启（procd 规范，重要）

```bash
# 部署 init.d 脚本 + 启用自启
scp nac_openwrt.init.d root@<ROUTER_IP>:/etc/init.d/nac_openwrt
ssh root@<ROUTER_IP> "chmod +x /etc/init.d/nac_openwrt && /etc/init.d/nac_openwrt enable"

# 验证自启（应看到 S99nac_openwrt 软链）
ssh root@<ROUTER_IP> "ls -la /etc/rc.d/ | grep nac"
```

> ⚠️ **关键坑（实测踩过）**：K-WRT 25.12 / 新版 OpenWrt 用 **procd** 作为 init 系统。
> init.d 脚本**必须用 procd 规范写法**：
> ```sh
> #!/bin/sh /etc/rc.common
> START=99
> USE_PROCD=1
> start_service() {
>     procd_open_instance
>     procd_set_param command /bin/sh /root/nac_openwrt.sh run
>     procd_set_param respawn
>     procd_set_param stdout 1
>     procd_set_param stderr 1
>     procd_close_instance
> }
> ```
> **不能用旧式写法**（自定义 `start()` + `( ... & )` 后台）——那样软链虽然
> 存在、`enabled` 检查也通过，但开机时 procd 会清理孤儿进程，导致
> **「重启后不自启」**（实测：旧写法重启后 `ps` 无进程、`/var/run/*.pid` 不存在）。
>
> procd 版还自带 `respawn`（崩溃自动重启），比旧写法更健壮。

**验证自启是否真的生效**（必须真实重启验证）：

```bash
ssh root@<ROUTER_IP> "reboot"          # 等待 ~60-105 秒
# 重启后检查：
ssh root@<ROUTER_IP> "ps w | grep nac_openwrt.sh"
# 期望：/bin/sh /root/nac_openwrt.sh run  （有输出即自启成功）

ssh root@<ROUTER_IP> "logread | grep nac_openwrt"
# 期望：procd: /etc/rc.d/S99nac_openwrt: ========== NAC OpenWrt 客户端启动 ==========
```

> 注：procd 接管后，脚本 stdout/stderr 进 **syslog**（`logread` 查看），
> 不再写 `/var/log/nac_openwrt.log`（且 `/var/log` 是 tmpfs，重启清空）。

### 3.4 配置

编辑 `/root/nac_openwrt.sh` 的 CONFIG 区：

```bash
vi /root/nac_openwrt.sh
```

必改项（**只有这 3 个静态值**，其余全部运行时自动获取）：

| 变量 | 值 | 说明 |
|------|-----|------|
| `NAC_USERNAME` | `<NAC_USERNAME>` | NAC 账号（静态凭据） |
| `NAC_PASSWORD` | `<真实NAC密码>` | **关键，必须填对**（静态凭据） |
| `NAC_SERVER` | `<NAC_SERVER_IP>` | NAC 服务器 URL（静态地址） |

**自动获取（无需配置）**：

| 参数 | 来源 | 触发时机 |
|------|------|---------|
| `sessionid` | 登录响应 Set-Cookie | 登录后 |
| `pskey` | `access_policy.json`（嵌在 `client_policy_xml` 内） | 登录后 |
| `device_id` | `access_policy.json`（顶层字段） | 登录后 |
| `autologin_flag` | 服务器不下发，脚本默认 flag=5 | — |
| `under_nat` | `check/result` 响应 | 上报合规后 |
| `nat_ip_ttl`（水印 TTL） | `check/result` 响应 | 上报合规后 |
| `nat_qos_dscp`（水印 DSCP） | `check/result` 响应 | 上报合规后 |
| `GUID` | 本机首次运行生成 | 运行时 |
| `WAN_IF`/IP/MAC | 本机默认路由自动探测 | 运行时（也可手动指定 `WAN_IF`） |

> 这就是关键设计：**只有账号密码 + URL 是写死的静态凭据，
> 其余参数（pskey/device_id/水印 TTL/DSCP/GUID）全部动态获取**，
> 服务器改配置时无需改动脚本。

---

## 四、运行与测试

### 4.1 单独测试登录

```bash
sh /root/nac_openwrt.sh login
# 期望输出：登录成功，sessionid=xxx
# 失败则看返回的 code（0x80000058 密码错 / 0x8000005D 被锁定）
```

### 4.2 完整运行

```bash
sh /root/nac_openwrt.sh run
# 或后台 + 日志：
sh /root/nac_openwrt.sh run >> /var/log/nac_openwrt.log 2>&1 &
```

### 4.3 验证水印

```bash
# 在路由器上抓出口包，确认 TTL=175
tcpdump -i wan -n -v 'icmp' -c 5
# 或从内网终端 ping 服务器，抓路由器 WAN 口
```

### 4.4 验证合规上报

```bash
sh /root/nac_openwrt.sh status
# 看 sessionid/pskey 是否正常
```

---

## 五、关键算法（已逆向 100% 破解，代码已实现）

### 5.1 登录密码"加密"

```
password = base64( 明文密码 )    # 就是明文 base64，不是 AES！
username = base64( 账号 )

例：<NAC_PASSWORD>  →  <NAC_PASSWORD_B64>
```

> **重要修正（2026-10-12 抓包实证）**：登录密码是 `base64(明文)`，**不是** AES-128-CBC。
> 之前误判的 AES-128-CBC（key=1234567890abcdef）是客户端用于**解密服务器下发配置
> （如 VSG_PWD cookie）**的函数（Ghidra `FUN_00549af0`/`FUN_005499c0`），与登录密码无关。
>
> 完整登录请求（前端 auth/password 抓包还原）：
> ```
> POST /nac/user/auth/password?t=<毫秒时间戳>
> username=<b64(账号)>&password=<b64(密码)>&verifycode=&challenge=&terminal=
> &rmbpwd_browser=&encode=1&type=&auto_login=&realip=<WAN_IP>
> &access_net_flag=1&terminal_type=windows&onlineaddrs=g~3xxxi<WAN_IP>
> ```

### 5.2 合规签名

```
明文 = sprintf("%d %s %d", time()+5, sessionid, flag) + 30空格
密钥 = base64_decode(pskey)  # 24 字节
加密 = AES-192-ECB(明文零填充到16对齐) + Base64
```

### 5.3 水印

```
nftables: ip ttl set 175 + ip dscp set 41（POSTROUTING 出口）
```

---

## 六、注意事项

1. **NAC 密码 ≠ 域密码**：`<NAC_USERNAME>` 的 NAC 密码（实测 `<NAC_PASSWORD>`）需要单独向管理员获取，
   不是 `<DOMAIN_PASSWORD>`（那是 Windows 域密码）；
2. **密码是明文 base64 传输**：登录 `password` 字段就是 `base64(明文密码)`，
   **无加密**（AES-128-CBC 只用于解密服务器下发的配置），HTTPS 下仍有传输泄露风险；
2. **防暴力破解**：连续错误密码会触发 IP/用户锁定（`0x8000005D`/`0x80000060`），
   不要反复试错，锁定后需等一段时间；
3. **sessionid 会过期**：登录态失效后需重新 `login`；
4. **水印参数自动获取**：`nat_ip_ttl`/`nat_qos_dscp` 由服务器在
   `check/result` 响应里动态下发，脚本自动解析并应用，
   **服务器改配置无需改脚本**。
   > 注意：水印仅在 `under_nat=1`（NAT 穿透开启、设备在 NAT 后面）时下发。
   > 当前场景 A（路由器 WAN 直连公司，`under_nat=0`、`nat_traversal=0`）不下发水印，
   > 无需打 TTL/DSCP。只有把路由器放到另一个 NAT 后面（如 192.168.3.x 内网）时才触发。
5. **法律合规**：仅限授权环境安全评估，不得用于未授权网络。

---

## 七、文件清单

| 文件 | 作用 |
|------|------|
| `nac_openwrt.sh` | 主程序（登录+心跳+上报+签名+水印） |
| `nac_openwrt.init.d` | OpenWrt init.d 开机自启脚本 |
| `verify_signature.py` | 签名算法 Python 参考实现（用于比对验证） |
| `verify_sig_shell.sh` | 签名算法 shell 版验证脚本 |
| `verify_pwd_shell.sh` | 密码 base64 验证脚本（登录密码=base64 明文，非 AES） |
| 本文件 | 部署文档 |
