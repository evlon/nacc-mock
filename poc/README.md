# NAC 客户端协议复现 POC（安全评估）

> 目的：验证启明星辰天珣 NAC 系统在「伪造合规终端」场景下能否被绕过，
> 用于采购前红队/安全评估。**仅限授权环境使用。**

---

## 一、当前进展（2026-10 实测更新）

**核心结论：MVP 协议已 100% 复现并实测验证成功。**

在开发机 3.8 上复用目标机 3.4 的 sessionid + pskey + onlineaddrs，
上报 `score=90`，服务器返回 `code=0x00000000` + `fwdsa=3`（放行）+
`under_nat=1` + `nat_qos_dscp=41` + `nat_ip_ttl=175`（水印参数）。
**服务器完全信任客户端上报，不校验源 IP / 设备绑定。**

---

## 二、已破解的协议链路（逆向 + 实测 100% 确认）

### 2.1 登录通道（HTTPS 443）

- 登录接口：`POST /nac/user/auth/password?t={毫秒}`
- **登录密码 = base64(明文)**，无 AES 加密（2026-10-12 抓包实测纠正）
- 关键参数：`username=base64(账号)` + `password=base64(密码)` + `realip=<WAN_IP>`
  + `access_net_flag=1` + `terminal_type=windows` + `onlineaddrs=g~3xxxi<WAN_IP>`
- 登录成功服务器 `Set-Cookie: VSG_SESSIONID`，后续凭此会话鉴权

### 2.2 合规上报通道（HTTPS 443，非 7898）

```
① GET /nac/dev/check/helper?username={base64}&value={AES192签名}  → 302
② POST /nac/dev/check/result?t={毫秒} body="score=90&onlineaddrs=..."  → JSON
③ POST /nac/user/check/session（心跳，每 ~10s）
```

### 2.3 签名算法（100% 破解）

```
明文 = sprintf("%d %s %d", time()+5, sessionid, flag) + 30空格
flag = 7(autologin_flag=="1") 否则 5
密钥 = base64_decode(pskey)（24 字节）
加密 = AES-192-ECB（补零到 16 对齐）+ Base64
```
实测命中：ts=1791604916 flag=5 完整匹配抓包 value。

### 2.4 onlineaddrs 格式（100% 破解）

```
g{device_id}_h{GUID}~8xxxm{MAC}_8xxxi{IPv4}_8xxxj{IPv6}_8xxxj{IPv6}...
```
- `~8xxxm` = MAC（大写带连字符，如 <DEVICE_MAC>）
- `_8xxxi` = IPv4（inet_ntoa）
- `_8xxxj` = 网卡全局 IPv6 地址（非 fe80 链路本地，RouterAdvertisement 分配）

### 2.5 NAT 穿透水印（TTL + DSCP）

```
服务器 WebSocket 下发 under_nat=1 + nat_ip_ttl=175 + nat_qos_dscp=41
客户端 SetIpTTL(175) + SetDSCP(41) 给出站 IP 包打水印
公司出口防火墙识别水印 → 放行 NAT 后面的合规设备
```
- SetDSCP = 写 QoS 组策略注册表 + gpupdate（用户态可实现）
- SetIpTTL = IPHLPAPI.DLL → ndisnac.sys 驱动改写（用户态需降级 netsh）

> ⚠️ **水印触发条件**：仅在 `under_nat=1`（设备在 NAT 后面、且服务器开启
> NAT 穿透 `nat_traversal=1`）时才下发。若设备直连公司网络（`under_nat=0`）
> 则不下发水印，无需打 TTL/DSCP。详见 `证据与工具索引.md` 场景 A/B 区分。

---

## 三、文件清单

| 文件 | 作用 |
|------|------|
| `nac_client_mvp.py` | **主程序（Windows）**：登录 + 签名 + 上报合规 + 心跳 + 水印打标（13 项功能） |
| `nac_openwrt.sh` | **主程序（OpenWrt 路由器）**：登录 + 心跳 + 上报 + 签名 + 水印（本次实测打通） |
| `nac_openwrt.init.d` | OpenWrt 开机自启脚本 |
| `nacc_control.py` | **自由关停补丁**：关停/恢复 NACC 客户端（进程+服务+驱动解绑，破解自保护守护链） |
| `nac_compliance_bypass.ps1` | 合规绕过脚本（注册表伪造红名单软件，check/inject/verify/rollback） |
| `verify_watermark.py` | 水印验证工具：检查 TTL/DSCP 是否真正打上（阻断启用前的验证） |
| `verify_signature.py` / `verify_sig_shell.sh` | 签名算法验证（Python / shell 双版本，用于比对） |
| `verify_pwd_shell.sh` | 密码 base64 验证（登录密码=base64 明文，非 AES） |
| `verify_json_get.sh` | json_get 解析验证脚本 |
| `simulate_block.py` | 阻断模拟工具：用 Windows 防火墙模拟 NAC 白名单阻断（本地验证） |
| `eapol_sim.py` | EAPOL 认证模拟（802.1X 场景） |
| `test_login.py` / `test_login2.py` | 登录测试脚本（多账号格式/多密码候选） |
| `app.js` | 前端加密函数逆向证据（含 base64 明文密码逻辑） |
| `NAC_OpenWrt部署文档.md` | 路由器部署文档（刷机/依赖/配置/测试） |
| `阻断启用后作战手册.md` | 阻断启用后如何验证/应对的完整作战手册 |
| `抓包手册.md` | 获取运行时参数的完整操作步骤 |
| `证据与工具索引.md` | **关键证据链**：每个结论→证据→工具的可追溯索引 |
| `README.md` | 本文件 |

---

## 四、运行方法

### 4.1 完整登录模式（推荐，密码 base64 明文）

```bash
# 装依赖
pip install requests pycryptodome psutil

# 设置环境变量（真实 NAC 账号密码，密码会自动 base64）
$env:NAC_USERNAME = "<NAC_USERNAME>"
$env:NAC_PASSWORD = "<NAC_PASSWORD>"

# 跑 MVP（登录 → 上报 score=90 → 水印打标）
python nac_client_mvp.py
```

> 登录密码是 `base64(明文)`，脚本内部自动处理，无需手动加密。
> 打水印（TTL/DSCP）需要**管理员权限**，非管理员运行只能上报合规、无法打标。

### 4.2 复用会话模式（跳过登录，用于 sessionid 未过期时）

### 4.2 验证水印

```bash
python verify_watermark.py   # 检查 TTL/DSCP 是否打上
```

### 4.3 模拟阻断环境

```bash
python simulate_block.py start    # 启用模拟阻断（默认阻断出站，白名单放行）
python simulate_block.py status   # 查看状态
python simulate_block.py stop     # 停止模拟阻断
```

### 4.4 自由关停 / 恢复 NACC 客户端（nacc_control.py）

```powershell
# 管理员 PowerShell 运行
python nacc_control.py stop      # 关停 NACC（进程+服务+解除驱动绑定）
python nacc_control.py start     # 恢复 NACC（服务+进程+恢复驱动绑定）
python nacc_control.py status    # 查看状态（无需管理员）
python nacc_control.py kill      # 仅杀进程（最轻量，会被守护拉起）
```

**破解的自保护守护链**（逆向 + 实测）：

```
自启动 Run 键 → NACCControl.exe（界面）
NACCService（LocalSystem，Start=2）→ NACC.exe（主进程）
CCMon.exe（守护：定时轮询枚举进程，发现 NACC.exe 不在就 StartServiceA 拉起）
```

**关停要点**：先 `sc config NACCService start= disabled`（让守护的 `StartServiceA` 失败、斩断守护链）→ 杀进程 → 解绑驱动。

> ⚠️ **关键教训**：不要 `sc stop` 驱动！`ndisnac.sys` 是 NDIS 过滤驱动，
> `sc stop` 会导致断网 + `tdinac` 卡 Stop Pending 僵尸状态（只能重启恢复）。
> 正确做法是用 `Disable-NetAdapterBinding` 解除驱动对网卡的绑定
> （等效手动取消网卡属性里的勾选，安全、不断网、可逆）。

**实测结果**：`stop → start` 完整闭环验证通过，无断网（仅毫秒级网卡重连）。

---

## 五、关键事实提醒

1. **当前 NAC 未启用"网络阻断"**：外网本来就通，`fwdsa=12` 只是残留值，
   日志已变 `fwdsa=0`（不阻断）。故无法测试"水印是否让外网通"。

2. **已启用的管控**：客户端准入（`client_permit=true`，模式 4）、
   合规检查（`is_security_check=1`）、软件红名单检查（北信源/办公终端管控平台）。

3. **未启用的管控**：网络阻断、外联检测（`outreach_detection=0`）、
   网络切换管控（`access_net_change_enable=0`）、NAT 穿透（`nat_traversal=0`）。

4. **核心结论**：服务器不校验源 IP / 设备绑定，MVP 可在任意设备上
   复用他人 sessionid 上报 score=90 获得放行（fwdsa=3 + 水印参数）。

---

## 六、法律与合规声明

- 本 POC 仅用于**你拥有授权的单位 NAC 系统**的安全评估；
- 未经授权对第三方系统做此测试，可能违反《网络安全法》《刑法》相关条款；
- 请确保测试账号、测试环境均由你方合法获得与授权。
