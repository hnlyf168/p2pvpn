# P2P VPN / Edge VPN

一个独立的虚拟组网项目，包含公众网站、用户控制台、Windows/Linux 客户端、备用打洞节点和独立中继。

**[体验网站](https://vpn.hngs.pub) · [安装包与源码下载](https://github.com/hnlyf168/p2pvpn/releases) · [使用指南](https://vpn.hngs.pub/guide) · [公众号图文稿](docs/wechat/公众号文章.md)**

![P2P VPN](docs/wechat/images/01-cover.png)

## 使用流程

1. 注册并完成邮箱验证，登录控制台。
2. 跟随引导创建网络，选择私有网段和设备分组。
3. 为每台设备选择系统，生成专属安装命令，复制到该设备执行。
4. 等待设备显示在线，再添加第二台同组设备验证互通。

安装命令当前有效期为 30 分钟；同机重试沿用领取标识。设备配置和凭据不应提交到仓库或贴到公开 Issue。

Linux 在线安装脚本使用 POSIX `sh`，不依赖 Python、jq 或预装 .NET。它使用 curl、unzip（可用 BusyBox 替代）、sha256sum 和基础命令；完整安装需要管理员权限、systemd、iproute2 与 `/dev/net/tun`。Windows 使用管理员 PowerShell。

## 能力与架构

- 每个用户管理自己的网络、分组、密钥与设备，支持自定义私有网段。
- 主控制服务负责账号、认证、配置与打洞协调，**不转发用户业务数据**。
- 客户端优先直连；高级会员可使用已部署并在线的独立 WSS 中继。
- 备用 punch 节点与 relay 节点分开部署；平台管理员管理节点及会员到期时间。
- 注册强制邮箱验证，后台配置 SMTP 与通知收件人；未配置发信服务时不开放新注册。
- 管理后台可查看用户、网络和在线设备，停用账号、撤销设备、轮换网络密钥。
- [访问与下载统计](docs/TRAFFIC.md)：按北京时间显示每日访问、安装包下载、脚本获取和近 7/30/90 天趋势，仅管理员可见。
- 下载校验、安装空间检查、安装目录互斥、同机重试及已有设备配置保护。

![网络架构](docs/wechat/images/03-architecture.png)

分组是通信隔离域，一个客户端实例一次加入一个网络分组。该项目不兼容 ZeroTier 客户端；实际打洞效果受 NAT、防火墙及运营商网络影响。

## 平台与版本

| 组件 | 当前发布状态 |
|---|---|
| 公众控制服务 | 0.3.5，包含每日访问与下载统计、纯 Shell 在线安装器 |
| Linux x64 / ARM64 / ARMv7 32 位客户端 | 0.3.3，已验证的静态 musl NativeAOT 包 |
| Windows x64 客户端 | 官网提供 0.3.0 包，源码保留 Windows 支持 |
| 独立 punch / relay 节点 | 官网提供 Linux x64 0.3.0 包 |
| Linux x86 32 位 / ARMv6 / Android | 当前独立项目未提供可用发布包 |

Linux 发布检查要求 ELF 没有 `PT_INTERP` 和 `DT_NEEDED`，不能用带运行时的自包含包冒充静态 AOT。组件版本独立记录；当前官网部署版本不等于每个下载包都使用同一版本号。

GitHub Releases 同时提供已验证的安装包、源码 ZIP、组件版本清单和 SHA-256 校验文件。后续可在 Actions 中运行 **Publish verified release**，按版本清单发布已有成品；详细步骤见 [Release 发布说明](docs/github-releases.md)。该流程包含源码构建和集成测试，各架构 NativeAOT 成品仍由原生构建机生成。

## 项目结构

| 路径 | 内容 |
|---|---|
| `src/ControlPlane` | ASP.NET Core 网站、账号与设备 API、主协调 |
| `src/Client` | Windows/Linux 客户端、虚拟网卡与安装工具 |
| `src/Node` | 独立 punch / relay 节点入口 |
| `src/Shared` | 服务端模型、套餐及协调运行器 |
| `src/Transport` | P2P 与 QUIC 传输库 |
| `tests/Integration` | 真进程、真实套接字的隔离/直连/中继测试 |
| `deploy` | 环境变量、systemd、容器和反向代理模板 |
| `docs/wechat` | 可发布的公众号 Markdown、封面、插图与预览 |

## 构建与测试

需要 .NET 10 SDK，版本选择见 `global.json`。源码构建不需要原 MyEdgeManager 项目目录。

```powershell
dotnet build EdgeVpn.sln -c Release
dotnet run --project tests/Integration -c Release
```

集成测试在本机启动临时控制服务及节点，使用临时账号和邮件投递目录，不安装系统服务、不创建虚拟网卡、不修改路由。构建、测试数据与下载包均放在忽略的目录中。

浏览器测试需要 Node.js、Playwright 和浏览器。设置 `PLAYWRIGHT_MODULE` 后可运行 `tools/browser-check.cjs`；安装包相关测试需要事先准备对应发布包。Linux Shell 测试见 `tools/architecture-check.py` 和 `tools/storage-check.py`。开发和打包工具可能使用 Python，**不影响目标设备的纯 Shell 在线安装**。

本地开发可运行 `powershell -File tools/dev.ps1`；默认监听本机。开发环境验证码投递到 `artifacts/dev/mail`，生产环境必须配置 SMTP。停止开发进程使用 `tools/stop-dev.ps1`。

静态 NativeAOT 发布需要具备 musl、静态原生依赖及对应架构 SDK 的 Linux 工具链。`tools/build-native-clients.sh` 记录已验证的构建流程，依赖预先准备的构建镜像，不是自动配置任意主机的脚本。先构建并验证 Linux 二进制，再使用打包工具；服务器部署详见文档。

## 部署与使用边界

- 控制服务使用单实例 JSON 存储，不支持多实例共同写同一数据目录。
- 备用协调节点之间没有实时跨节点发现；当前是主备架构，不是活跃多主。
- 高级会员中继能力以实际在线节点为前提；没有上线中继时不能提供数据兜底。
- 会员由管理员开通，目前没有支付、订单、退款和自动对账系统。
- 平台保存受保护的网络密钥材料，同组设备属于当前信任边界；不应将其描述成平台不可接触密钥的零信任系统。
- 生产负载、跨运营商 NAT 和目标设备的虚拟网卡互通仍需按实际部署验收。

**[部署说明](docs/DEPLOYMENT.md) · [架构边界](docs/ARCHITECTURE.md) · [API](docs/API.md) · [验证记录](docs/VALIDATION.md) · [源码来源](docs/ORIGIN.md) · [第三方组件](THIRD_PARTY_NOTICES.md)**

安装包从官网获取；仓库不包含生产配置、管理员密码、SMTP 授权码、设备身份文件或部署备份。
