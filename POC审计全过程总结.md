# 启明星辰天珣 NAC 上网管控系统 — POC 审计全过程总结报告

> 项目代号：`windowsclient-1.5.10260-ip_0.0.0.0_st`
> 审计对象：Venustech（启明星辰）天清网络接入控制系统 V3.0（NAC6000-HG6800）
> 版本：NACC 客户端 1.5.10260

---

## 一、背景

单位计划采购启明星辰天珣 NAC（网络准入控制）系统，用于终端上网管控。采购前需要回答一个核心安全命题：

> **这套 NAC 的「准入 + 合规 + 阻断」机制，能否被「自研客户端 / 伪造合规终端」绕过？其信任边界到底在哪？**

这决定了：是否值得采购、是否需要加购 802.1X 等更强准入、以及现有终端侧部署方案的固有风险。

---

## 二、目标

1. **逆向还原** NACC 客户端（用户态服务 + 内核驱动 + 802.1X 组件）的完整机制；
2. **评估**「自研客户端」的可行性（哪些模块容易、哪些难）；
3. **实测验证**核心结论（不依赖纯逆向推断）；
4. **产出可复用的工具**：MVP 协议客户端、关停补丁、水印验证、阻断模拟、OpenWrt 一体化客户端等。

---

## 三、环境

| 项 | 值 |
|----|-----|
| 真实服务器 | `<NAC_SERVER_IP>`（443 登录/心跳 + 7898 合规上报） |
| 系统名称 | 天清网络接入控制系统 V3.0（NAC6000-HG6800） |
| 测试账号 | `<NAC_USERNAME>`（<USER_GROUP>，已授权） |
| 测试设备 | 3.8（开发机，Win）+ 3.4（<HOSTNAME_3.4> Win11 Pro，装了 NACC 客户端） |
| 网络拓扑 | 公司侧上联 IP <WAN_IP> / MAC <WAN_MAC>；终端在路由器 NAT 后（192.168.3.x） |
| 目标二进制 | `NACC.exe`、`ndisnac.sys`（NDIS LWF）、`tdinac.sys`（TDI）、`CCMon.exe`/`StartCCMon.exe`（守护）、`MSEAPCLTC.dll`/`DisableWindowsEAPOL.dll`（802.1X） |

---

## 四、工具

| 工具 | 用途 |
|------|------|
| **Ghidra 12.1.4 + ghidra-mcp** | 静态逆向（反编译、字符串、xref、函数分析） |
| **Npcap + tshark** | 抓包（终端 + 远程 3.4） |
| **SSLKEYLOGFILE** | 解密 443 通道 TLS 流量 |
| **Wireshark** | 包分析 |
| **Python 3.14 + pycryptodome** | MVP 协议复现、加密算法验证 |
| **WinRM（Invoke-Command）** | 远程控制 3.4（部署 + 提权测试） |
| **WSL（bash/openssl/xxd）** | OpenWrt 版 shell 脚本的加密算法验证 |
| **注册表 + 服务 + 网卡绑定** | 终端侧行为观测（驱动、自保护、水印） |

---

## 五、过程（按时间线）

### 阶段 1：静态逆向（Ghidra）

逆向还原六大模块：
1. **登录认证**：`POST /nac/user/auth/password`，密码 **base64(明文)**（2026-10-12 抓包实测纠正；早期误判为 AES-128-CBC，那实为解密服务器下发配置用的）；
2. **会话管理**：`sessionid` + `pskey` 明文存注册表、心跳 `keepalive`/`session`；
3. **合规检查**：评分 1~90（满分 90 降级 60 的防伪启发式）；
4. **上报签名**：`AES-192-ECB(pskey)` + Base64（**对称加密，非非对称签名**）；
5. **放行机制**：`permit_client_access` → 注册表 `is_special_login`；
6. **拦截机制**：`ndisnac.sys`（NDIS LWF）未放行时只放行 ARP+DNS，拦截其余；
7. **802.1X**：客户端"代答 EAP"、服务器端 `ESRadius.exe`（RADIUS）判定。

**核心结论**：默认部署（`EnableDot1X=0`）下，**信任边界止于终端**，本地驱动拦截可被终端自欺。

### 阶段 2：实测登录闭环 + 决定性发现

用 sessionid 直接调 `access_policy.json`，发现 `is_verified=1`（已合规）与 `is_installed_client=0`（未装客户端）**并存**——即**准入判定在服务器侧，本地客户端非必要前提**。且 `pskey` 随接口**明文下发**。

### 阶段 3：双通道架构实证（抓包 + SSLKEYLOGFILE）

还原三通道：
- **443**（libcurl，公网 CA，可解密）→ 登录 + 心跳；
- **127.0.0.1:9002**（浏览器↔客户端本地信号）→ 触发合规检查；
- **7898**（Venus 自签 CA + boost::asio 自定义 TLS，**密钥不导出、SSLKEYLOGFILE 解不了**）→ 合规上报。

### 阶段 4：7898 通道协议逆向（Ghidra 反编译）

还原 `CCCT` 帧头 + TinyXML `<callrequest>` + `AES-192-ECB` 签名，消除 7898 加密盲区。

### 阶段 5：MVP 协议客户端（Python）

`nac_client_mvp.py`：登录复用 + 签名 + 上报合规 + 心跳 + 水印，实测上报 `score=90` → 服务器返回 `fwdsa=3`（放行）+ 水印参数。

### 阶段 6：NACC 自保护守护链破解

发现 `NACCService → NACC.exe` + `CCMon.exe`（守护，轮询发现进程不在就 `StartServiceA` 拉起）+ `StartCCMon.exe` + Run 键自启。破解：先 `sc config start= disabled` 斩断守护链，再杀进程。

### 阶段 7：驱动关停踩坑 + 安全方案

发现 `sc stop ndisnac` 会断网 + `tdinac` 卡 Stop Pending（只能重启），正确做法是 `Disable-NetAdapterBinding`（解绑，安全不断网）。

### 阶段 8：OpenWrt 一体化客户端

把登录/心跳/上报/签名/水印全部搬到 OpenWrt 路由器，实现"一台路由器解决所有终端"。

---

## 六、遇到的问题与解决办法

| # | 问题 | 根因 | 解决办法 |
|---|------|------|---------|
| 1 | `curl -sk` 返回 `0x80000042 会话不存在` | TLS/证书处理差异 | 改用 `Invoke-WebRequest -SkipCertificateCheck` |
| 2 | 注册接口误触发注销会话 | `dev/register` 参数不当 | 记录副作用，避免误调 |
| 3 | 多次试密码触发 IP/用户锁定 | 防暴力破解（`0x8000005D/60`） | 停止硬试，改为复用 sessionid |
| 4 | 7898 通道 SSLKEYLOGFILE 解不了密 | boost::asio 未导出密钥 | 转 Ghidra 静态逆向帧格式 + 签名 |
| 5 | 上报签名 ECB 报"未对齐" | 明文 63 字节非 16 倍数 | 零填充（`\x00`）到 16 对齐（非 PKCS7） |
| 6 | 杀进程被 CCMon 守护立即拉起 | 自保护守护链 | 先 `sc config start= disabled` 再杀 |
| 7 | `sc stop ndisnac` 导致断网 + tdinac 卡 Stop Pending | 驱动是 NDIS LWF，不能 sc stop | 改用 `Disable-NetAdapterBinding` 解绑 |
| 8 | `start` 恢复命令触发断网 | 服务重启+驱动重绑顺序错 | 先恢复驱动绑定，再启动服务 |
| 9 | 登录态丢失（sessionid=0） | 重启 + 折腾后 AD 自动登录未触发 | 明确 AD 登录本质，需真实 NAC 密码 |
| 10 | shell 变量不能存 NUL 字节 | 签名需零填充 | 明文转 hex → 拼接 `00` → `xxd -r` 回二进制 |
| 11 | NAC 密码 ≠ 域密码 | NAC 独立账号体系 | 需单独获取 `<NAC_USERNAME>` 的 NAC 密码 |
| 12 | 写死参数过多（TTL/DSCP/device_id 等） | 早期脚本偷懒 | 重构为运行时动态获取（仅账号密码+URL 写死） |

---

## 七、最终输出物清单

### 7.1 文档类

| 文件 | 解决的问题 | 使用的方法 |
|------|-----------|-----------|
| `NAC自研客户端可行性评估报告.md` | 回答"能否绕过、信任边界在哪、自研可行性" | Ghidra 逆向 + 实测 + 信任边界分析 |
| `poc/README.md` | 全局导航、进展、运行方法 | 汇总各工具用法 |
| `poc/阻断启用后作战手册.md` | 阻断启用后如何验证/应对 | 方案分级（上报/水印/红名单/关停） |
| `poc/抓包手册.md` | 如何获取运行时参数 | 抓包 + SSLKEYLOGFILE 步骤 |
| `poc/NAC_OpenWrt部署文档.md` | OpenWrt 客户端刷机/安装/配置/测试 | 部署全流程 |

### 7.2 工具/代码类

| 文件 | 解决的问题 | 使用的方法 |
|------|-----------|-----------|
| `poc/nac_client_mvp.py` | **核心 MVP**：登录 + 签名 + 上报合规 + 心跳 + 水印（13 项功能） | base64 明文密码 + AES-192-ECB 签名 + requests |
| `poc/nacc_control.py` | 自由关停/恢复 NACC（进程+服务+驱动解绑） | 斩断守护链 + Disable-NetAdapterBinding |
| `poc/nac_openwrt.sh` | OpenWrt 一体化客户端（登录+心跳+上报+签名+水印） | shell + openssl + nftables/iptables |
| `poc/nac_openwrt.init.d` | OpenWrt 开机自启 | rc.common init 脚本 |
| `poc/verify_watermark.py` | 验证 TTL/DSCP 水印是否打上 | 检查注册表/netsh |
| `poc/simulate_block.py` | 本地模拟 NAC 白名单阻断 | Windows 防火墙规则 |
| `poc/nac_compliance_bypass.ps1` | **写注册表绕过软件红名单检测**：在 `Uninstall` 键伪造红名单软件条目，使服务器判定合规 | 注册表注入（check/inject/verify/rollback/full/auto-redlist） |
| `poc/app.js` | 前端 JS（逆向证据）：登录密码 base64 明文逻辑来源 | 静态提取 |
| `poc/eapol_sim.py` | 802.1X EAP 模拟（探索） | EAPOL 报文构造 |
| `poc/nac_client_poc.py` | 早期协议 POC | — |
| `poc/verify_signature.py` | 签名算法 Python 参考实现（比对用） | AES-192-ECB |
| `poc/verify_sig_shell.sh` | shell 签名算法验证 | WSL + openssl |
| `poc/verify_pwd_shell.sh` | shell 密码 base64 验证 | base64 |
| `poc/verify_json_get.sh` | json_get 函数验证 | jq/sed |
| `poc/test_login.py` / `test_login2.py` | 登录账号/密码格式测试 | requests 登录 |

---

## 八、核心结论（一句话版）

> 启明星辰天珣 NAC 的准入判定在服务器侧、信任边界止于终端，登录密码用硬编码密钥加密、上报签名用明文下发的 pskey 做对称加密、本地拦截靠可被自欺的 NDIS 驱动。**默认部署下，持有合法账号即可伪造合规终端；要提升强度，必须开 802.1X（但仍只到"账号级"准入），要"设备级"则需 EAP-TLS + 设备证书 + TPM。**

---

## 九、未完成的审计线（后续待办）

### 9.1 USB / 外设 / 移动存储检测的绕过（未深入验证）

**已逆向到的现状**：

- 合规检查共有 **13 个采集维度**（非此前报告的 5 个），逆向自 `FUN_005257f0`（`CSendData` 类型→`SecData\*.xml` 映射器）：
  `Deviceinfo`、`Winservices`、`Useraccount`、`Usergroup`、**`Usbhistory`**、`Softwareinfo`、`IEPlugininfo`、`Grouppolicy`、`Antivirusinfo`、`Internetsecurity`、`Shareresource`、`Hotfixinfo`、`Nicinfo`
- USB 相关模块已定位：
  - `Usbhistory` → `SecData\UsbHistory.xml`（USB 插拔历史，采集上报）
  - `StorageMgr` + `Storage_AuthStatus_Change`（移动存储/U 盘管控）
  - `HidUsb` + `HidUsb_AuthStatus_Change`（USB HID 设备管控）
  - `storage_tip45/50/51/52/53`（存储设备接入提示/拦截文案）

**尚未验证的关键问题**：

1. USB/存储检测是**本地拦截**（插 U 盘即禁）还是**仅上报让服务器判定**？
2. 外设管控的执行器是哪个（`DeviceControl.exe`？还是内核驱动？）——未逆向；
3. **绕过可能**（核心待办）：
   - 能否像软件红名单那样，直接改 `SecData\UsbHistory.xml` 伪造"无 USB 记录"？
   - 能否停用/绕过 USB 管控进程或驱动？
   - USB HID 与移动存储的管控是否走同一链路、能否分别绕过？

> 结论：USB/外设检测是**唯一尚未走完绕过验证的合规维度**，需后续用真实 U 盘插入 + 抓包/观察驱动行为 + 尝试伪造 SecData 来闭环。

### 9.2 其他待办

- 拿到 NAC 真实密码后，端到端验证 OpenWrt 客户端的完整登录→上报→水印闭环；
- 确认 7898 通道是否校验客户端证书（双向 TLS）及 `seqno` 重放防护；
- 阻断实际启用后，验证 TTL/DSCP 水印是否被出口防火墙精确识别。

---

## 十、法律与合规声明

- 本 POC 仅用于**已授权单位 NAC 系统**的安全评估；
- 所有测试账号、环境均由委托方合法授权；
- 未经授权对第三方系统做此类测试，可能违反《网络安全法》《刑法》相关条款。
