# 验证记录

验证环境：Windows，本机 .NET SDK 10.0.401。源码目标 net10.0。

## 已通过

- 独立解决方案 Release 编译。
- 真实控制服务、独立 punch 节点与独立 relay 节点进程启动。
- 用户注册、持久化、跨租户列表／修改隔离和管理员接口保护。
- 加入密钥次数限制、独立设备凭据与设备冒用拦截。
- 相同分组客户端直接连接并传输 16000 字节随机数据；不同分组不发现彼此。
- 首个协调地址不可达后自动重试到备用 punch 节点，直接传输成功。
- 客户端强行请求旧中转协议时，控制服务不转发，中转统计为零。
- 普通会员即使自行填入中转地址也无法建立 WSS 中转连接。
- 开通 pro 后，协调端口完全不可达时仍能获得地址并通过独立 WSS 中转传输加密数据。
- 仅使用 WSS 中转时，设备重启后双向业务传输恢复。
- 中转节点分组隔离，设备吊销中断已有连接，会员降级中断已有连接。
- pro 到期后配置不再下发中转地址，独立中转也拒绝连接。
- 网络密钥轮换后，已授权设备配置中的握手密钥及组数据密钥更新。
- 无头 Edge 浏览器完成注册、创建网络／分组、生成密钥、下载 client.json、刷新恢复登录和退出。
- 手机宽度 390px 没有页面横向溢出，页面运行无 JavaScript 异常。
- Windows x64 和 Linux x64 自带运行时客户端发布；Windows 包保留独立 wintun.dll。
- 实际 ZIP 解压后 Windows 客户端独立执行配置检查，Wintun 库及必需导出加载成功。
- 原项目 git status 仍为空，未修改 原 MyEdgeManager 项目。

执行命令：

```powershell
dotnet build EdgeVpn.sln -c Release
dotnet run --project tests/Integration -c Release
# 浏览器验证需要已安装 Playwright 或 PLAYWRIGHT_MODULE 指向 playwright-core
node tools/browser-check.cjs
powershell -NoProfile -ExecutionPolicy Bypass -File tools/publish.ps1
```

测试启动的服务在测试退出时关闭；不创建系统 VPN 网卡，不安装系统服务，不修改路由。
日志与测试数据放在 artifacts/tests；浏览器截图放在 artifacts/browser。

## 尚未验证

真实 Wintun/TUN 数据收发、跨运营商和对称 NAT、Linux 服务实际安装、ARM/x86 运行、
公网 TLS 域名与防火墙、容器实际运行、多用户负载及持续在线稳定性。
当前提供的是本机协议验证，不代表已经完成公网端到端验收。


## v0.2.0 官网升级验证（2026-09-27）

- 真实浏览器完成公开首页 → 注册 → 一次性恢复密钥 → 私有控制台。
- 完成创建网络、创建分组、生成加入密钥、加入设备、读取独立配置；手机 390px 布局无横向溢出。
- Cookie 为 HttpOnly，浏览器 localStorage / sessionStorage 不保存令牌；匿名无法获取受保护 HTML。
- 缺少 CSRF 和非同源写入返回 403；普通用户无法读取运营接口。
- 独立节点角色凭据隔离、心跳进入下发清单、撤销后同步拒绝；旧设备配置在凭据重置后失效。
- 撤销其他会话、恢复密钥轮换、旧恢复码拒绝、恢复后会话失效、修改密码后全部会话失效。
- 五类实际 ZIP 安装包 HTTP Range 返回正确 ZIP 文件头；非法文件名不可下载。
- Windows ZIP 自包含运行成功，Wintun 动态库及导出加载通过，未改动本机路由或建立虚拟网卡。
- Release 编译无警告无错误。协议集成测试全部通过，涵盖备用打洞、直连、普通会员禁中继、高级会员加密 WSS 兜底、重启恢复、撤销和到期。
- 本地页面截图见 artifacts/browser/1790487640426。部署后的公网验收与截图见 artifacts/deployment。

尚未验证：跨运营商实际 NAT 组合、真实 TUN/Wintun 网卡与系统路由收发、高并发长期负载。公网协调验收使用同一测试主机的两客户端，不能代替这些验证。

## v0.3.0 验证（2026-09-27）

- 强制邮箱验证、邮箱与验证码绑定、60 秒重发间隔、消费后拒绝重放、10 分钟过期、跨 IP 的五次错误锁定均通过。
- 生产环境忽略开发邮件投递目录，未配置 SMTP 时不会绕过验证注册。
- SMTP 授权码不会出现在管理查询响应或持久化文件明文中；管理员的测试邮件接口通过开发投递器验证，真实 SMTP 投递需运营方填写配置后测试。
- 管理员用户详情、会员等级、通知设置、全平台设备与网络查询、节点真实在线上报与撤销均通过。
- 停用账号后已有会话、设备配置获取、新设备加入和再次登录均被拒绝。
- 自定义 /28 网段的实际直连和仅中继连接均获取正确前缀并传输数据；备用打洞、分组隔离、撤销和到期回归通过。
- /30 地址池只能分配两个主机地址；第三台设备加入拒绝。公网网段、重叠网段和已有设备时变更网段均被拒绝。
- Windows 一键安装脚本在 DownloadOnly 模式下实际下载、SHA-256 校验、解压成功；解压后的客户端和 Wintun 导出检查通过。没有创建本机网卡或安装系统服务。
- 修正 Linux 安装脚本的 CRLF 换行；发布工具统一将所有 .sh 以无 BOM、LF 形式写入 ZIP。
- 管理员邮件配置页桌面/390px 手机布局通过，浏览器无脚本异常。截图见 artifacts/browser/1790489737441。

新增检查：node tools/security-check-v03.cjs。源码发布脚本除 .NET 10 SDK / PowerShell 外需要 Python 3；已发布自包含二进制无需 .NET SDK。

## Android 1.1.0 / 控制服务 0.3.6

2026-09-27 的安卓移植验证单独在 GitHub Actions 完成，未在本机、模拟器或手机运行客户端。上文 Windows 记录属于此前的桌面与服务端版本。

- [构建与发布记录](https://github.com/hnlyf168/p2pvpn/actions/runs/36310968497)，构建提交 4b80fb103044285e8c327cffa7a4886ba54837dc。
- Android Release APK 编译成功，包含 armeabi-v7a、arm64-v8a、x86_64；包名 pub.hngs.vpn，versionCode 14，最低 API 26。
- SDK apksigner 正式签名及证书指纹检查通过；zipalign 16 KB 对齐检查通过；不是调试签名。
- 签名证书 SHA-256：3fb59a8442bd9263812eb9854d145c4f6b3f268b6caf0a02773073387379165c。
- APK SHA-256：15ea5274d0abd9100a794fafc6a5d3e87ed059b0baea4af4028c364ba6272c46。
- CI 服务端回归覆盖：安卓专属链接和二维码、设备系统不匹配拒绝、同设备重试、跨设备复用拒绝、撤销后拒绝，以及 APK MIME、目录白名单和历史下载。
- 原有统计、租户隔离、分组隔离、直连、独立中继、会员过期、设备撤销与密钥轮换等回归通过。
- [预发布附件](https://github.com/hnlyf168/p2pvpn/releases/tag/android-v1.1.0)包括 APK、源码 ZIP、SHA256SUMS 和构建验证说明。

尚未验证安卓系统授权交互、真机 TUN 数据收发、扫码摄像头、蜂窝/Wi-Fi 切换和长时间后台运行。CI 协议测试不能代替这些真机验证。
