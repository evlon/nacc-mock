# 启明星辰天珣 NAC 上网管控系统 — 逆向分析 & 自研客户端可行性评估报告

> 分析对象：`NACC.exe`（用户态服务）、`ndisnac.sys`（NDIS LWF 驱动）、`tdinac.sys`（TDI 过滤）、`MSEAPCLTC.dll` / `DisableWindowsEAPOL.dll`（802.1X/EAP 组件）、`Setup.ini`（部署配置）
> 版本：windowsclient-1.5.10260；厂商：Venustech（启明星辰）
> 分析工具：Ghidra 12.1.4 + ghidra-mcp（MCP 原生工具）

---

## 一、系统总体架构

```
┌─────────────────────────────────────────────────────────────┐
│  NAC 服务器（权威决策方）                                      │
│  认证 / 合规判定 / 策略下发 / 放行指令 / 心跳校验                │
└───────────────▲──────────────────────────┬──────────────────┘
                │ HTTPS 443 (OpenSSL)       │ permit_client_access
                │ AES-192(pskey)+Base64     │ 等指令下发
                │                           ▼
┌───────────────┴─────────────────────────────────────────────┐
│  NACC.exe（用户态服务，NACCService）                          │
│  CWebSocket(通信) / CCommandServer(指令) / CPolicyExecute(策略)│
│  保存 sessionid/pskey/is_special_login 到注册表 HKLM\...\NACC  │
└───────────────▲──────────────────────────┬──────────────────┘
                │ DeviceIoControl           │ 写注册表标志
                │                           ▼
┌───────────────┴─────────────────────────────────────────────┐
│  ndisnac.sys（内核 NDIS LWF 驱动，本地拦截闸门）                │
│  Modifying + Mandatory filter，绑定物理网卡                    │
│  合规未通过：放行 ARP + DNS(53)，拦截其余全部流量               │
└─────────────────────────────────────────────────────────────┘
```

**核心结论**：拦截在本地终端（驱动），决策在服务器，默认 **fail-closed（拦截）**。

---

## 二、六大模块逆向还原结果

### 1. 登录认证

- **接口**：`POST https://[ServerAddress]:443/nac/user/auth/password`
- **参数**：`username`(base64) + `password`(base64) + `realip` + `onlineaddrs` + `terminal_type=windows` + `encode=1` + `type` + `terminal` + `rmbpwd_browser` + `verifycode` + `challenge` + `auto_login` + `access_net_flag=1`（可选）
- **密码（实测已破解，2026-10-12 抓包纠正）**：登录密码就是 **base64(明文)**，无加密。早期误判的 `AES-128-CBC`（Key=`1234567890abcdef`）实为客户端**解密服务器下发配置（如 VSG_PWD）**用的函数，与登录密码无关。
- **关键**：无客户端证书强校验、无硬件绑定、无 TPM。`PKCS12` 字符串仅为 libcurl 内置，非强制双向 TLS。
- **登录流程（实测）**：网页版登录即可，前端自动 base64 密码。登录成功后通过 `Set-Cookie` 下发 `VSG_SESSIONID`，并跳转到设备注册页。

### 2. 会话管理

- 登录成功 → 服务器下发 `sessionid`（会话令牌）+ `pskey`（会话密钥）
- 明文存注册表 `HKLM\SOFTWARE\NACC\sessionid`、`pskey`
- 心跳保活：`/nac/user/check/keepalive`、`/nac/user/check/session`
- 离线上报：`/nac/dev/offline` + `device_offline_time`

### 3. 合规检查

- 客户端采集插件：杀毒（`AntiVirusCheckMethod`/`AntiVirus.dat`）、补丁（HotfixMgr）、进程/软件（baseproc/BaseSoft）、服务、外设、移动存储、非法外联、共享资源、双网卡等
- 评分 1~90（`Sec_Check_Score`），满分 90 会被降级到 60（防"完美伪造"启发式）
- 上报：`/nac/dev/check/helper?username=%s&value=%s`、`/nac/dev/check/result`

### 4. 上报签名（关键安全边界）

- **算法**：`AES-192 对称加密`（`AES_set_encrypt_key(key, 0xc0)`，密钥 = pskey）+ Base64（`BIO_FLAGS_BASE64_NO_NL`）
- **明文**：`sprintf("%s %s %d", sessionid, pskey, autologin_flag)` + 32 空格填充
- **关键结论**：是**对称加密**而非非对称签名。信任根是 pskey（登录后下发、明文存本地）。**拿到合法 pskey 即可伪造合规上报**。

### 5. 放行机制

- 服务器下发 `permit_client_access` 指令（disabled/enable+mod）
- 写注册表 `is_special_login`（1=普通登录，4=特殊模式）
- 联动驱动切换拦截/放行状态
- 异常隔离：`ACL disconnection policy`（设备环境危险/802.1X 未注册/双网卡时运行）

### 6. 拦截机制（ndisnac.sys）

- **类型**：NDIS LWF filter，`FilterType=2`（Modifying）、`FilterRunType=1`（Mandatory）、`FilterMediaTypes="ethernet,wan,ppip"`
- **拦截策略**（核心函数 `FUN_14000a50c`）：解析以太网帧，合规未通过时**仅放行 ARP(0x806) 和 DNS(UDP 53/0x35)**，拦截其余全部流量（用于跳转隔离/登录提示页）
- **控制**：`NdisRegisterDeviceEx` 注册控制设备，用户态通过 DeviceIoControl 切换状态
- **默认**：fail-closed（Mandatory filter 绑定即拦截，直到收到放行指令）
- 旧系统（WinXP/Vista）用 IM + TDI 架构（`tdinac.sys`）

### 7. 802.1X 认证架构（关键补充）

**组件**：`MSEAPCLTC.dll`（导出 `DisableMsEAPClientForLan`/`EnableMsEAPClientForLan`）、`DisableWindowsEAPOL.dll`（导出 `fnDisableWindowsEAPOL`/`fnEnableWindowsEAPOL`）、`EPolWLNF.dll`（Windows 登录事件钩子）、服务器端 `ESRadius.exe`（RADIUS 服务器）。

**完整认证链路**：

```
终端（NACC.exe 代答 EAP）
   │  1. DisableWindowsEAPOL.dll 禁用 Windows 自带 EAPOL
   │  2. 客户端自己收发 EAP 报文（"Receive EAP_SUCCESS Packet"）
   │  3. "模拟 802.1X 认证"（Simulate 802dot1x auth）
   ▼
交换机（802.1X Authenticator）
   │  通过 RADIUS 协议向后端询问"这台设备合法吗"
   ▼
NAC 服务器（ESRadius.exe = RADIUS 服务器）
   │  根据账号/session 判定，返回 Accept/Reject
   ▼
交换机根据 RADIUS 结果 → 物理放行端口 / 隔离到 Guest VLAN
```

**关键结论（认证凭据是什么）**：

- ❌ **不是设备证书**：整个安装包无 `.p12`/`.pfx`/`.pem` 客户端私钥，非 EAP-TLS 设备级认证。
- ✅ **认证凭据 = 登录 NAC 服务器的账号体系 + 服务器下发的 `Dot1x_Auth_Info`**。
- 客户端角色是**代答 EAP**（用户态收发 EAP 报文、模拟认证），非标准 OS EAP 栈。
- 交换机不直接验证设备，而是通过 **RADIUS 委托 NAC 服务器判定**，再在物理端口层隔离。

**这意味着**：802.1X 防的是「没有合法账号的终端」（物理隔离，终端无法单方面绕过交换机）；但**防不了「持有合法账号的伪造终端」**（凭据是账号非设备硬件，设备身份 `device_id` 是客户端自报而非 TPM 证明）。

---

## 三、完整通信协议规格表

| 功能 | 方法 | 路径 | 关键参数/加密 |
|------|------|------|---------------|
| 密码登录 | POST | `/nac/user/auth/password` | username+password(Base64)+terminal_type |
| 匿名登录 | POST | `/nac/user/auth/anonymity` | — |
| 改密码 | POST | `/nac/user/auth/pwdchange` | — |
| 验证码状态 | GET | `/nac/user/auth/verifycode_status` | — |
| 设备注册 | POST | `/nac/user/dev/register` | device_id |
| 访问变更 | POST | `/nac/user/change/access` | access_net_flag |
| 合规检查辅助 | GET | `/nac/dev/check/helper?username=%s&value=%s` | value=AES192(pskey)+Base64 |
| 合规结果 | POST | `/nac/dev/check/result` | score=%d |
| 离线 | POST | `/nac/dev/offline` | device_offline_time |
| 访问策略 | GET | `/nac/user/check/access_policy.json` | — |
| 客户端策略 | GET | `/nac/vsite/common/policy/client_policy.json` | — |
| 认证策略 | GET | `/nac/vsite/common/policy/auth_policy.json` | — |
| 注册策略 | GET | `/nac/vsite/common/policy/register_policy.json` | — |
| 网络切换 | GET | `/nac/vsite/common/policy/network_change.json` | — |
| 门户定制 | GET | `/nac/vsite/common/custom/portal_custom.json` | — |
| 心跳保活 | GET | `/nac/user/check/keepalive` | sessionid |
| 会话检查 | GET | `/nac/user/check/session` | sessionid |
| 合规上报（实测） | TCP | `<NAC_SERVER_IP>:7898`（自签CA+自定义TLS，非上述HTTP） | Deviceinfo/Usbhistory/Softwareinfo/Processinfo/Nicinfo |
| 本地信号（实测） | TCP | `127.0.0.1:9002/9003/9181`（浏览器→客户端） | 登录触发合规检查 |

> 注：原逆向发现的 `/nac/dev/check/helper`、`/nac/dev/check/result` 为 HTTP 语义接口；**实测**合规数据实际走 **7898 端口的独立 TLS 通道**（`SendReportDataCompWithIpv6`），与心跳 443 通道分离。

---

## 四、信任边界分析（采购评估核心）

### 信任锚点在哪

| 判定 | 执行位置 | 能否被终端伪造 |
|------|---------|---------------|
| 合规数据采集 | 终端插件 | ⚠️ 可伪造（插件运行在终端） |
| 上报签名 | 终端（AES-192 + pskey） | ⚠️ 拿到 pskey 可伪造 |
| 合规判定 | 服务器 | ✅ 不可伪造 |
| 放行指令 | 服务器下发 | ✅ 不可伪造 |
| **本地拦截** | 终端驱动 ndisnac.sys | ⚠️ 终端可自欺（停驱动/改注册表） |
| **802.1X 端口隔离** | 交换机（RADIUS 委托 NAC 判定） | 🟡 **部分可绕过**：物理隔离强，但凭据是账号非设备证书，持有合法账号的伪造终端仍可通过 |

### 关键安全结论

1. **默认部署（EnableDot1X=0）下，信任边界止于终端**。本地拦截（驱动）可被终端自身绕过（卸载/停用驱动、改注册表标志、伪造合规上报）。这是所有"纯终端侧 NAC"的固有限制。

2. **802.1X 是比本地拦截强一个量级的防线，但非"绝对不可伪造"**（EnableDot1X=1）：
   - **强在**：交换机物理隔离，终端无法单方面绕过（停驱动也没用）；
   - **弱在**：认证凭据是**账号体系**（非设备证书/TPM），服务器端 `ESRadius.exe` 做 RADIUS 判定。**持有合法账号的伪造终端理论上仍可通过**。
   - 默认关闭（`EnableDot1X=0`）。

3. **服务器端校验是"状态校验"而非"强加密验签"**：校验会话状态（sessionid+keepalive）、设备注册状态（is_registered/is_verified），检查上报用 AES-192(pskey) 对称加密。pskey 是唯一加密凭据（登录后下发、明文存本地），非非对称签名。

4. **"满分降级"（90→60）说明厂商意识到了伪造问题**，但只是启发式，非强认证。

### 服务器到底校验什么（防伪强度结论）

| 校验项 | 类型 | 强度 |
|--------|------|------|
| 会话状态（sessionid + keepalive） | 状态校验 | 弱——拿到合法 sessionid 即可维持 |
| 设备注册状态（is_registered / is_verified） | 状态校验 | 弱——客户端可正常走注册 |
| 检查上报签名（AES-192 + pskey） | 对称加密 | 弱——pskey **随 access_policy 明文下发**（实测），任何人拿到 sessionid 即可拿到 pskey |
| 设备硬件指纹（snid/CPU/内存/磁盘，Base64 自报） | 信息上报 | 弱——非加密、非 TPM 证明，可伪造 |
| 密码传输"加密"（base64 明文） | 无加密 | 极弱——登录密码就是 base64(明文)，HTTPS 下仍可还原任意用户明文密码 |

---

## 五、自研客户端可行性评估

### 5.1 结论总览

> **自研一个"纯协议客户端"（登录 + 上报合规 + 维持会话）技术上完全可行，且工作量可控；但自研一个"完整等价的 NAC 客户端"（含本地 NDIS 拦截 + 802.1X）工作量显著增大，其中 NDIS LWF 驱动和 EAP 认证是两大技术难点。**

### 5.2 分模块可行性

| 模块 | 难度 | 可行性 | 说明 |
|------|------|--------|------|
| HTTPS 通信 | ⭐ | ✅ 完全可行 | 标准 OpenSSL/libcurl，协议已还原 |
| 登录认证 | ⭐⭐ | ✅ 可行 | 用户名+Base64密码，无证书强校验 |
| 会话管理 | ⭐ | ✅ 可行 | sessionid/pskey 下发与保存，已还原 |
| 合规上报 | ⭐ | ✅ 可行 | AES-192(pskey)+Base64，已还原算法 |
| 心跳保活 | ⭐ | ✅ 可行 | keepalive + sessionid |
| **本地拦截驱动** | ⭐⭐⭐ | ⚠️ 需自研 NDIS LWF | 参考 ndisnac.sys（183函数/112KB），需 WDK + 签名 |
| **802.1X/EAP** | ⭐⭐⭐ | ⚠️ 需模拟 EAP + 对接 RADIUS | 凭据是账号非证书，难点在模拟 EAP 报文与交换机交互 |

### 5.3 自研需要攻克的难点（按优先级）

1. **登录认证的账号密码来源**：自研客户端本质是"另一个客户端用同一套账号"，需要合法账号密码（非技术门槛）。

2. **服务器端客户端指纹识别**：如果服务器校验客户端版本/特征/加密套件，自研客户端需模拟这些特征（需抓包比对）。

3. **本地拦截驱动（若需要）**：
   - 需 Windows WDK + EV 代码签名证书
   - 参考 ndisnac.sys 实现 NDIS LWF filter（FilterSend/Receive 回调 + 拦截判定 + 控制设备 DeviceIoControl）
   - 拦截策略：放行 ARP+DNS，拦截其余（或放行白名单）

4. **802.1X/EAP 对接（若服务器开 802.1X）**：
   - 需实现「模拟 EAP 报文 + 与交换机交互」（参考 NACC.exe 的 Simulate 802dot1x auth 机制）
   - 认证凭据仍是账号/session，难点在**正确模拟 EAP 报文格式与状态机**，而非管理非对称证书
   - 交换机侧 RADIUS 判定委托 NAC 服务器（ESRadius.exe），持有合法账号即可通过

### 5.4 推荐的实现路线

```
阶段 1（MVP，纯协议客户端）：
  实现 HTTPS 通信 + 登录认证 + 会话管理 + 合规上报 + 心跳
  验证：能登录、拿 pskey、上报合规、维持会话、收到 permit 指令
  （不实现本地拦截，仅做"合规上报客户端"）

阶段 2（含本地拦截）：
  自研 NDIS LWF 驱动（参考 ndisnac.sys）
  实现 DeviceIoControl 控制接口，联动放行/拦截

阶段 3（含 802.1X，若需要）：
  实现 EAP 认证对接交换机
  （这是最难，需要评估是否必要）
```

---

## 六、采购评估建议（给决策层）

1. **必须开启 802.1X**：这是唯一能把信任边界从"终端"推到"网络侧"的机制。默认 `EnableDot1X=0`（纯终端侧拦截），可被"控制终端的用户"绕过（停驱动/改注册表/伪造上报）。

2. **但要知道 802.1X 的上限**：认证凭据是**账号体系**（非设备证书/TPM），交换机通过 RADIUS 委托 NAC 服务器（ESRadius.exe）判定。它**防"无合法账号的终端"强，防"有合法账号的伪造终端"弱**。

3. **若要更高强度，要求 EAP-TLS + 设备证书 + TPM**：这才是"设备级"认证（无法用账号伪造）。当前这套系统无客户端证书（无 .p12/.pfx/.pem），属于"账号级"准入。

4. **评估合规检查的服务器端强校验**：确认服务器是否真的验签（pskey 是否短时轮换）、是否识别客户端指纹。当前逆向结论是"状态校验而非强加密验签"。

5. **关注满分降级机制**：这是厂商的防伪启发式，说明他们清楚本地判定的局限，但这不构成强防护。

---

## 八、实测验证（POC 闭环，2026-10）

> 以下为**真实环境实测**结果（非纯逆向推断），通过 opencli 控制浏览器完成登录闭环，并直接调用后端接口验证准入判定逻辑。

### 8.1 实测环境

- **真实服务器地址**：`<NAC_SERVER_IP>`（安装包出厂默认 `<FACTORY_DEFAULT_IP>` 已废弃，不可达）
- **系统名称**：`天清网络接入控制系统 V3.0 (NAC6000-HG6800)`（登录页 title 实测确认）
- **登录方式**：网页版（`CLIENT_TYPE=web`），前端 Vue 应用 + 浏览器插件提示
- **测试账号**：`<NAC_USERNAME>`（<USER_GROUP>，已授权评估测试）

### 8.2 实测登录闭环（已打通）

| 步骤 | 操作 | 实测结果 |
|------|------|---------|
| ① 打开门户 | `GET https://<NAC_SERVER_IP>/` | 返回 Vue 首页，含"正在自动安装插件"提示 |
| ② 身份认证 | 点击"我是员工" → 输入账号密码 | 前端自动加密，登录成功 |
| ③ 拿会话 | 读取 Cookie | `VSG_SESSIONID=<SESSIONID_PLACEHOLDER>`（示例值） |
| ④ 跳转 | — | 跳转到 `/nac/register`（设备注册页） |

### 8.3 决定性实测结论：准入判定在服务器侧，本地客户端非必要前提

**关键证据**：用 sessionid 直接调用 `/nac/user/check/access_policy.json`，服务器在 `is_installed_client=0`（未装客户端）的情况下，依然下发完整准入凭据：

```json
{
  "user_name": "<NAC_USERNAME>",
  "user_group": "<USER_GROUP>",
  "login_addr": "<WAN_IP>",
  "device_id": "3469",
  "role_id": "101",
  "access_net_id": "1",
  "fwdsa": "12",
  "under_nat": "0", "nat_qos_dscp": "0", "nat_ip_ttl": "0",
  "is_registered": "1",
  "is_verified": "1",        ← 服务器已判定"合规验证通过"
  "is_installed_client": "0", ← 但未安装客户端！
  "pskey": "<NAC_PSKEY>"  ← 上报签名密钥，明文下发
}
```

**结论**：

1. **`is_verified=1` 与 `is_installed_client=0` 并存** —— 服务器侧已把该账号判为"已验证合规"，与本地客户端是否在场**无关**。本地客户端只是"终端侧执行器"（采集合规数据 + 本地拦截 + 代答 EAP），**不是准入判定的必要前提**。

2. **`pskey` 随 access_policy 明文下发** —— 上报签名用的 AES-192 密钥，任何人拿到合法 sessionid 即可通过该接口拿到 pskey，无需逆向、无需客户端。

3. **NAT 检测字段实锤** —— `under_nat`/`nat_qos_dscp`/`nat_ip_ttl` 在真实响应中出现，与逆向发现的 NAT 检测（`IsEnableNAT`/`FUN_004adff0` 枚举 ICS 网卡）一致。

### 8.4 伪造合规终端的完整攻击链（已实测打通前 3 步）

```
① 登录：网页版输入账号密码 → 前端自动 base64(明文) → 拿 VSG_SESSIONID
② 查策略：GET /nac/user/check/access_policy.json（带 sessionid）
          → 直接返回 pskey + device_id + is_verified=1
③ 上报：用 pskey 做 AES-192 签名 → POST /nac/dev/check/helper（格式已逆向还原）
④ 放行：服务器认为"合规" → 下发 permit_client_access → 触发放行
```

**实测验证状态**：步骤 ① ② 已完整打通（真实环境）；步骤 ③ 上报接口的精确格式已逆向还原，待真实客户端登录后抓包做最终比对；步骤 ④ 依赖 ③ 完成。

### 8.5 实测踩坑记录

- **接口调用工具差异**：`curl.exe -sk` 访问会返回 `0x80000042 用户会话不存在`，但 `Invoke-WebRequest -SkipCertificateCheck` 正常——差异在 TLS/证书处理，测试需用后者。
- **注册接口副作用**：`POST /nac/user/dev/register` 参数不当时会返回"设备注册失败，请注销用户重新注册"，并**注销当前会话**（需重新登录拿新 sessionid）。
- **防暴力破解**：多次错误密码会触发 `0x8000005D 暴力破解锁定用户或IP`（密码错误为 `0x80000058`）。

### 8.6 双通道通信架构实证（抓包 + SSLKEYLOGFILE 解密，2026-10）

> 在真实客户端环境（远程 Win11 + 已安装 NACC 客户端）用 **Npcap + tshark + SSLKEYLOGFILE** 抓取并解密客户端流量，实证还原了 NAC 的**双通道通信架构**，并发现合规上报走一条**更封闭的独立 TLS 通道**。

#### 8.6.1 双通道架构（实测确认）

```
┌────────────────────────────────────────────────────────────────┐
│ ① 登录/心跳通道  : 443 端口，libcurl + 公网/标准 CA               │
│    SSLKEYLOGFILE 可解密 ✅                                       │
│    /nac/user/auth/password（登录）                               │
│    /nac/user/check/session（心跳，每 ~10 秒）                     │
├────────────────────────────────────────────────────────────────┤
│ ② 本地信号通道   : 127.0.0.1:9002（浏览器 ↔ NACC 客户端）        │
│    浏览器登录成功后通知客户端"开始合规检查"                        │
├────────────────────────────────────────────────────────────────┤
│ ③ 合规上报通道   : 7898 端口，Venus 自签 CA + 自定义 TLS           │
│    boost::asio + OpenSSL（非 libcurl）                           │
│    SSLKEYLOGFILE 无法解密 ❌（密钥不导出）                        │
└────────────────────────────────────────────────────────────────┘
```

#### 8.6.2 关键实证证据

**（1）浏览器 ↔ 客户端本地信号（证实"网页登录触发客户端检查"）**

```
127.0.0.1:53834 → 127.0.0.1:9002  Established  OwningProcess = 4948 (msedge)
```

浏览器（msedge）在登录后通过 `127.0.0.1:9002` 连接 NACC 客户端（监听 9002/9003/9181 三个本地端口），作为"用户已登录，触发合规检查"的本地信号。

**（2）443 通道可解密，拿到完整明文**

解密出的心跳请求（`libcurl-agent/1.0` + Cookie `VSG_SESSIONID`）：

```http
POST /nac/user/check/session HTTP/1.1
Host: <NAC_SERVER_IP>
Cookie: VSG_SESSIONID=<SESSIONID_PLACEHOLDER>
User-Agent: libcurl-agent/1.0
Content-Type: application/x-www-form-urlencoded

key=dateGmt&onlineaddrs=g3519_h{<DEVICE_GUID>}~8xxxm<DEVICE_MAC>_8xxxi<LAN_IP>_8xxxj<LAN_IPV6>_...&addressupdate=0&terminal_type=0
```

服务器响应：

```json
{ "code": "0x00000000", "msg": "校验会话成功", "result": { "key": "unknown" } }
```

**（3）7898 通道合规上报（日志 + 证书实锤）**

客户端日志记录合规上报触发：

```
[CSendData::SendReportDataCompWithIpv6] assert type:Deviceinfo   result: 1.
[CSendData::SendReportDataCompWithIpv6] assert type:Usbhistory   result: 1.
[CSendData::SendReportDataCompWithIpv6] assert type:Softwareinfo result: 1.
[CSendData::SendReportDataCompWithIpv6] assert type:Processinfo  result: 1.
[CSendData::SendReportDataCompWithIpv6] assert type:Nicinfo      result: 1.
```

7898 端口 TLS 握手证书（Venus 自签，正是逆向发现的 `server.cer`）：

```
CN = 127.0.0.1
O  = Venus
OU = Venus NAC
Issuer = OCA for Venus NAC
```

**（4）7898 通道密钥无法用 SSLKEYLOGFILE 解密（决定性）**

- 443 端口 Client Random → **在** SSLKEYLOGFILE 中 → 可解密；
- 7898 端口 Client Random（`c3fbcccdec832e20...`）→ **不在** SSLKEYLOGFILE 中 → 无法解密。

**原因**：7898 通道用 `boost::asio + OpenSSL` 自定义实现（非 libcurl），未启用 OpenSSL 的 keylog 导出回调（`SSL_CTX_set_keylog_callback`），故密钥不入 SSLKEYLOGFILE。

#### 8.6.3 合规上报数据源（SecData 目录实测）

客户端采集并上报的 5 类设备数据，原始落盘在 `C:\Program Files (x86)\NACC\SecData\`：

| 文件 | 内容 | 上报类型 |
|------|------|---------|
| `hardware.xml` | 显卡/键盘/鼠标/驱动详情（含驱动路径、分辨率） | Deviceinfo |
| `UsbHistory.xml` | USB 插拔历史 | Usbhistory |
| `SoftwareInfo.xml` | 软件清单 | Softwareinfo |
| `ProcessInfo.xml` | 进程清单 | Processinfo |
| `NicInfo.xml` | 网卡（MAC/IP/网关/DNS） | Nicinfo |

#### 8.6.4 安全结论

1. **登录/心跳通道（443）已完全攻破**：可解密拿到会话令牌、设备 GUID/MAC/IP、Cookie，配合 access_policy 明文下发的 pskey，可伪造会话与心跳。

2. **合规上报通道（7898）是"更封闭"的边界**：自签证书 + 自定义 TLS 实现，密钥不导出，SSLKEYLOGFILE 无法解密。**但这不构成强防护**——密钥不导出只是"抓包解密"失效，并未改变"签名算法是 AES-192(pskey) 对称加密、pskey 明文下发"这一根本弱点（见第四节）。

3. **触发链完整**：浏览器登录 → 本地 9002 端口信号 → 客户端采集 SecData → 7898 上报 → 服务器判定。自研客户端只需**复刻 7898 通道的协议与签名格式**（见 8.7 路线 C 逆向），即可绕过"客户端是否在场"的依赖。

### 8.7 7898 通道协议逆向还原（路线 C，Ghidra）

> 通过对 `NACC.exe` 关键函数的反编译，完整还原了 7898 合规上报通道的**帧格式、XML 消息结构、签名算法**，消除了"SSLKEYLOGFILE 无法解密"这一盲区。

#### 8.7.1 关键函数定位（已反编译确认）

| Ghidra 地址 | 逆向还原的语义 | 关键证据 |
|-------------|---------------|---------|
| `FUN_00524b90` | `CSendData::SendReportDataCompWithIpv6`（合规上报主流程） | 字符串引用 `assert type:%s result:%d` |
| `FUN_004f8930` | `helperhtn_click`（"一键检查"按钮入口） | `printf("helperhtn_click\n")`；读 5 个注册表值 |
| `FUN_00504d50` | 签名函数（AES-192-ECB） | `AES_set_encrypt_key(param_4, 0xc0, ...)` |
| `FUN_004d1820` | 帧组装 + `send()` 发送 | `CCCT` 魔数 + TinyXML + `send()` |
| `FUN_00506ef0` | 加密辅助（16 字节对齐 + Base64） | 0x104 缓冲 + `len>>4` 对齐 |

#### 8.7.2 签名算法（实锤 AES-192-ECB）

```c
// FUN_00504d50 反编译还原
AES_set_encrypt_key(pskey, 0xc0, key_schedule);  // 0xc0 = 192 位 → AES-192
strcpy(plaintext, param_1);                       // 明文
for (i = 0; i < len; i += 0x10) {                 // 每 16 字节一块
    AES_encrypt(plaintext + i, ciphertext + i, key_schedule);  // ECB 模式
}
// 之后 Base64 编码（FUN_00505970）
```

- **算法**：`AES-192-ECB`（无 IV，逐块独立加密）
- **密钥**：`pskey`（登录后下发，明文存注册表 `HKLM\SOFTWARE\NACC\pskey`，且随 access_policy.json 明文下发）
- **明文**：`sprintf("%s %s %d", sessionid, pskey, autologin_flag)` + 空格填充到 16 字节对齐

#### 8.7.3 帧格式（实锤 `CCCT` 魔数）

```
[12 字节帧头]                       [XML 消息体]
┌──────────────────────────┬────────────────────────────────────┐
│ "CCCT" (0x43 0x43 0x43 0x54) │ <?xml version="1.0" encoding=...?>
│ + 8 字节填充 0x30 ('0')       │ <callrequest seqno="N"            │
│                             │   module="IClientUI"               │
│                             │   method="PopupMessage"            │
│                             │   szXmlMessage="[合规数据XML]" />  │
└──────────────────────────┴────────────────────────────────────┘
```

- **魔数**：`CCCT`（`DAT_006521fc` = `43 43 43 54`，疑似 "Client Control / 厂商缩写"）
- **XML 方法名**（`DAT_00652154` 反编译）：`PopupMessage`、`DeviceRemoveComplete`、`Down...`
- **序列号**：`seqno` 自增（`this+0x34`），用于请求/响应匹配（呼应 8.6 日志 `assert type:%s iRecSeqno:%d iSendSeqno:%d`）
- **发送**：`send(socket, buf, len, 0)` 直接走已建立的 TCP(→TLS) 连接，**非 libcurl**（印证密钥不导出的原因）

#### 8.7.4 合规检查触发链（实锤）

```
① 用户点击"一键检查"（helperhtn_click）
② 读注册表：ServerAddress / user_name / sessionid / pskey / autologin_flag
③ 构造签名明文 = sprintf("%s %s %d", sessionid, pskey, autologin_flag) + 空格
④ AES-192-ECB(pskey) + Base64 → 得到签名 value
⑤ 采集 SecData/*.xml（Deviceinfo/Usbhistory/Softwareinfo/Processinfo/Nicinfo）
⑥ 组装 <callrequest> XML + "CCCT" 帧头
⑦ send() 走 7898 TLS 通道上报
⑧ 服务器校验签名 + seqno → 判定合规 → 下发 permit/deny
```

#### 8.7.5 结论：自研客户端已无技术盲区

7898 通道的**协议格式、帧头魔数、XML 结构、签名算法、密钥来源**全部还原。自研合规客户端需要复刻的要素：

1. `CCCT` 帧头 + 12 字节填充；
2. TinyXML `<callrequest>` 消息（`seqno`/`module`/`method`/`szXmlMessage`）；
3. AES-192-ECB 签名（pskey 从 access_policy.json 明文获取）；
4. 7898 端口的 TLS 连接（需信任 Venus 自签 CA `CN=127.0.0.1`，或跳过校验）。

**唯一剩余的不确定项**：服务器是否校验 7898 通道的**客户端证书**（双向 TLS），以及 `seqno` 的初始值/重放防护。这些需在真实环境用自研客户端实测比对。

---

## 七、附录：关键逆向证据索引

- 签名算法：`AES_set_encrypt_key(key, 0xc0=192位)` → `AES_encrypt` 逐块 + `BIO_f_base64`
- 明文格式：`"%s %s %d"`（sessionid + pskey + autologin_flag）+ 32 空格
- pskey 来源：登录后下发，存 `HKLM\SOFTWARE\NACC\pskey`；**实测：随 `/nac/user/check/access_policy.json` 明文下发**
- 密码"加密"：登录密码 = base64(明文)（2026-10-12 抓包实测纠正；早期误判的 AES-128-CBC 是解密服务器下发配置用的）
- 拦截判定：`ndisnac.sys` 核心函数解析 EtherType，放行 ARP(0x806)/DNS(UDP:53)，拦截其余
- 放行指令：`permit_client_access` → 注册表 `is_special_login`
- 802.1X 架构：服务器端 `ESRadius.exe`（RADIUS 服务器）+ 客户端"模拟 802.1X 认证"（`Simulate 802dot1x auth` / `Receive EAP_SUCCESS Packet`）+ `DisableWindowsEAPOL.dll` 禁用微软 EAPOL
- 认证凭据：账号体系 + `Dot1x_Auth_Info`（无设备证书，安装包无 .p12/.pfx/.pem）
- 默认配置：`EnableDot1X=0`、`EnableFireWall=1`、`IsBanLoginWindow=1`
- 双通道实证（2026-10 抓包）：443（libcurl，公网CA，可解密）+ 7898（Venus自签CA `CN=127.0.0.1`，boost::asio自定义TLS，密钥不导出）
- 本地信号：浏览器（msedge）→ `127.0.0.1:9002`（NACC 监听 9002/9003/9181）触发合规检查
- 合规上报数据源：`SecData/hardware.xml`(Deviceinfo)、`UsbHistory.xml`、`SoftwareInfo.xml`、`ProcessInfo.xml`、`NicInfo.xml`
- 心跳明文：`POST /nac/user/check/session` body=`key=dateGmt&onlineaddrs=g3519_h{GUID}~8xxxm{MAC}_8xxxi{IP}_8xxxj{网卡}`，UA=`libcurl-agent/1.0`
