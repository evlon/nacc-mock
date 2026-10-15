# NAC 客户端协议复现 POC（安全评估）

> 启明星辰天珣（Venustech）NAC 网络准入控制系统的协议逆向与伪造终端可行性验证。
> 用于**采购前红队 / 安全评估**，验证「伪造合规终端」场景能否绕过准入。
>
> ⚠️ **仅限授权环境使用**，详见文末法律声明。

---

## 项目背景

针对 NAC6000-HG6800（天清网络接入控制系统 V3.0）的客户端（NACC.exe）
进行逆向分析，完整还原其认证与合规上报协议，并验证两个核心结论：

1. **准入判定在服务器侧**：本地客户端只是"终端执行器"，非准入判定的必要前提；
2. **协议可被自研客户端复现**：无需官方客户端，任意设备（含 OpenWrt 路由器）
   即可登录、上报合规、获得放行。

## 核心成果

| 项 | 结论 |
|----|------|
| 登录密码 | `base64(明文)`，无 AES 加密 |
| 合规签名 | AES-192-ECB（key=base64_decode(pskey)） |
| pskey | 账号级，明文下发 |
| 准入判定 | 服务器侧（is_verified=1 与 is_installed_client=0 并存） |
| 源 IP / 设备绑定校验 | ❌ 极弱，可任意设备复用 sessionid 放行 |
| OpenWrt 路由器自主登录闭环 | ✅ 实测打通（fwdsa=3 放行） |

## 目录结构

```
nac-poc-publish/
├── poc/                        # 全部 POC 代码与文档
│   ├── nac_client_mvp.py       # 主程序（Windows）
│   ├── nac_openwrt.sh          # 主程序（OpenWrt 路由器）
│   ├── nac_openwrt.init.d      # 路由器开机自启
│   ├── nacc_control.py         # NACC 客户端自由关停补丁
│   ├── nac_compliance_bypass.ps1  # 合规绕过（注册表伪造红名单软件）
│   ├── simulate_block.py       # 阻断模拟
│   ├── eapol_sim.py            # EAPOL 认证模拟
│   ├── verify_*.py / *.sh      # 各类算法验证工具
│   ├── test_login*.py          # 登录测试
│   ├── app.js                  # 前端加密函数逆向证据
│   ├── README.md               # 协议总览 + 运行方法
│   ├── 证据与工具索引.md        # 关键证据链（结论→证据→工具）
│   ├── NAC_OpenWrt部署文档.md   # 路由器部署
│   ├── 抓包手册.md              # 抓包方法
│   └── 阻断启用后作战手册.md     # 阻断应对
├── NAC自研客户端可行性评估报告.md  # 完整逆向评估报告
├── POC审计全过程总结.md           # POC 全过程审计总结
└── .gitignore
```

## 快速上手

### Windows 版（开发机）

```bash
pip install requests pycryptodome psutil

# 设置账号密码（密码自动 base64）
$env:NAC_USERNAME = "<NAC_USERNAME>"
$env:NAC_PASSWORD = "<NAC_PASSWORD>"

python poc/nac_client_mvp.py
```

### OpenWrt 路由器版

```bash
# 详见 poc/NAC_OpenWrt部署文档.md
scp poc/nac_openwrt.sh root@<ROUTER_IP>:/root/
ssh root@<ROUTER_IP> "sh /root/nac_openwrt.sh run"
```

## 阅读顺序建议

1. `NAC自研客户端可行性评估报告.md` —— 先了解整体逆向结论；
2. `poc/README.md` —— 协议细节与运行方法；
3. `poc/证据与工具索引.md` —— 关键结论的证据链（核实查证用）；
4. `POC审计全过程总结.md` —— 完整过程回顾。

## 法律与合规声明

- 本项目仅用于**你拥有授权的单位 NAC 系统**的安全评估；
- 未经授权对第三方系统做此类测试，可能违反《网络安全法》《刑法》相关条款；
- 请确保测试账号、测试环境均由你方合法获得与授权；
- 本仓库已对真实账号、密码、IP、MAC、pskey 等敏感信息做脱敏处理
  （统一替换为 `<占位符>`），如需本地复现请自行回填。
