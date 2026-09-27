# Edge VPN 部署说明（控制服务 0.3.4）

公共主服务、备用打洞和中继为三个独立角色。主服务永不承担用户数据中转。普通会员只认证/打洞；高级会员可使用实际在线的独立中继。尚未接入在线支付，管理员在 /ops 开通方案并设置到期时间。

## 主服务自包含安装包

Linux x64 包含运行时，适用于 Ubuntu 22.04/24.04、Debian 12 等 glibc / OpenSSL 3 / libicu 环境。公网域名需已指向主机并有 TLS 证书。

1. 解压 edge-vpn-control-linux-x64-0.3.4.zip，将 bin 内容安装到 /opt/edge-vpn/releases/0.3.4，并让 /opt/edge-vpn/current 指向该目录；对 EdgeVpn.ControlPlane 执行 chmod 755。
2. 创建系统用户 edgevpn（无登录 shell）。建立 /var/lib/edge-vpn-control，属主 edgevpn，权限 700。
3. 将 deploy/control.env.example 复制到 /etc/edge-vpn/control.env，设置三个不同随机密钥、PublicUrl、Coordinator__Hosts__0 和首次管理员。配置文件权限 600，仅 root 可读。不要使用示例占位值。
4. 将 deploy/edge-vpn-control.service 安装到 /etc/systemd/system/，执行 systemctl daemon-reload 和 systemctl enable --now edge-vpn-control。
5. 检查本地 http://127.0.0.1:5080/health。将 deploy/nginx.conf 的代理位置配置合并到现有 TLS 站点，保留证书/ACME设置；nginx -t 成功后再 reload。仅信任环回反向代理，公网不可直接访问 5080。
6. 开放 TCP/UDP 49000–49099（默认协调端口段），保留 SSH 与现有防火墙规则。实际网络按需绑定端口。
7. 访问 /login 使用首次管理员登录，/ops 管理会员、节点。首次成功初始化后移除配置中的 BootstrapAdmin 三项并重启服务。管理员不会再次创建。
8. 将客户端下载包和节点包放到主服务 downloads 目录，再重启服务建立下载清单。发布脚本已替官网部署产物完成此步骤；独立主服务包不递归包含自身及全部下载包。

## 独立节点

管理员 /ops → 基础设施节点 → 注册，下载只显示一次的 node.env。在另一台 Linux 主机解压相应 relay 或 punch 包，放入 node.env 后执行 sudo sh install-node.sh。完整 TLS、端口和升级说明见包内 README.md。

| 角色 | 公网端口 | 职责 |
|---|---|---|
| control | 443、TCP/UDP 49000–49099 | 官网、账号、设备认证、主协调 |
| punch | TCP/UDP 49000–49099 | 备用协调，不中转数据 |
| relay | HTTPS/WSS 443 | 高级会员数据中转 |

健康心跳每 15 秒发送，超过 60 秒不再分配节点；实际连接授权周期复核。备用打洞按主备连接顺序使用，尚无跨协调节点联邦发现。域名入口需可解析到节点，TLS 证书需覆盖对应域名。注册节点不等于已安装节点。

## 安全与恢复

- HTTPS、HttpOnly/Secure/SameSite Cookie、CSRF、同源校验、请求大小与频率限制、登录失败锁定。
- 密码为加盐 PBKDF2 派生值；加入密钥、节点凭据、设备凭据及恢复密钥以哈希存储。网络加密密钥由服务器生成并受文件权限保护，平台运营方属于信任边界。
- 用户只可管理自己的网络，设备凭据绑定身份与分组；敏感配置只显示一次。恢复密钥可重置密码，务必离线保存。
- 注册强制验证邮箱；管理员在 /ops 的通知与注册邮箱页面设置 SMTP、通知收件人并发送测试邮件。未启用发信时暂停新注册。验证码 10 分钟有效、每邮箱每小时最多 5 次、60 秒重发间隔、最多 5 次猜测，消费后失效。恢复密钥找回仍保留。SMTP 授权码以 AdminKey 派生密钥进行 AES-GCM 加密，变更 AdminKey 后需重新填写 SMTP 授权码。
- 单实例 JSON 原子持久化，默认平台最多 100 个网络、10000 个账号；不是无限扩容系统。程序持有进程锁，禁止多实例共同写同一数据目录。
- 备份 state.json 和受保护的 control.env，按敏感凭据管理；应停服备份或使用文件系统一致性快照。回滚时保留同版本数据副本，禁止用旧空文件覆盖生产状态。
- 本轮官网升级已在服务器保留原静态站点、Nginx 配置及回滚脚本；详见本地 artifacts/deployment/DEPLOYED.md。

## 从源码发布与检查

在安装 .NET 10 SDK 的 Windows 上：

```
powershell -File tools/publish.ps1
dotnet run --project tests/Integration -c Release
powershell -File tools/check-package.ps1
```

浏览器验证：设置 PLAYWRIGHT_MODULE 指向 playwright 或 playwright-core 模块，再执行 node tools/browser-check.cjs。安装包下载提供 SHA-256 校验值。Windows 客户端包含 Wintun 驱动库，尚未进行发行者代码签名；客户端需要管理员权限创建虚拟网卡。

## v0.3.0 功能

控制台的“一键添加设备”默认生成一次、24 小时有效的加入码，Windows 下载 /install.cmd 后双击，Linux 从下载中心复制安装命令。脚本从 HTTPS 下载对应客户端并校验 SHA-256，交互输入加入码，自动领取配置和安装服务。重复安装保留同平台的已有设备身份与配置。

用户创建网络时可填写 RFC1918 私有 IPv4 CIDR，支持 /8–/30；同账号网络不得重叠，已有有效设备时不能直接改网段。地址分配、主备协调握手和中继目录均携带正确前缀。使用自定义网段前请将客户端和所有独立节点更新到 v0.3.0。

管理员可查看所有用户的邮箱验证、会员、网络、分组、设备与审计信息，以及全平台真实在线连接；密码、加入码原文和 SMTP 授权码不在查询接口中显示。历史账号保留登录能力并标记为未验证，不会自动伪装成已验证。在线依据主协调连接和节点上报，配置同步不计为在线。

## v0.3.1 引导式安装

新账号登录后进入「创建网络 → 添加设备 → 复制安装命令」引导。已有网络可从设备页直接继续添加设备；下载中心也提供引导入口。设备名称、分组和系统在网页中确定，安装时不再输入加入码。

每条命令有效 30 分钟，绑定一个网络、分组、设备名称和系统。平台只保存安装凭据哈希；下载脚本不会创建设备，脚本完成下载校验后才通过 POST 自动加网。Windows 安装在管理员 PowerShell 执行，Linux 使用 sudo、systemd、unzip（或 BusyBox unzip）、curl、iproute2 和 TUN。

脚本为当前机器保留受限权限的重试标识，同机重试返回同一设备，不重复建档；换机器无法复用已经执行过的命令。凭据撤销、设备撤销、配置轮换、账号禁用或分组删除后不能通过重试恢复旧权限。已有另一设备配置时，专属安装脚本拒绝覆盖；使用通用脚本可保留已有配置升级。

页面根据实际协调连接或节点心跳显示上线状态，自动领取配置不等同于已上线。需要连接第二台同组设备才能测试互通。命令原文不写入浏览器持久化存储；刷新后可在引导中撤销待安装命令并生成新命令。

本次仅更新控制端为 0.3.1；客户端及独立节点继续使用兼容的 0.3.0 包。

验证：`node tools/setup-check.cjs` 检查实际 Windows 下载、哈希及自动配置（不安装服务）、Linux 领取配置代码、重试/重放/撤销/过期、引导与移动端；`node tools/live-setup-check.cjs` 验证已授权部署站点及临时设备公网双向传输。真实 TUN 网卡与系统服务安装需要在目标设备执行安装命令。

## v0.3.3 Linux 静态 NativeAOT

Linux 客户端必须在指定构建机上使用现有 musl AOT 镜像编译：ARM 构建机负责 ARM32/ARM64，x64 构建机负责 x64。`tools/build-native-clients.sh` 包含实际构建及 ELF 检查流程，使用独立 `/root/edge-vpn-native-0.3.3` 目录，不覆盖原项目或已有 VPN 服务。

项目开启 `PublishAot`、`IsAotCompatible`、`StaticExecutable`、`StaticOpenSslLinking`，使用 `DirectPInvoke Include="libc"` 在链接阶段绑定 ioctl/open/read/write/poll 等系统接口；新增加网 JSON 使用源生成上下文。发布脚本对 Linux 包强制运行 `tools/verify-native-elf.py`，要求无 PT_INTERP、无 DT_NEEDED，并验证 CPU Machine。不能把带运行时的自包含包当作 AOT 包发布。

客户端下载提供 linux-x64、linux-arm64、linux-arm（ARMv7 hard-float 32 位）；安装命令自动判断内核架构与用户空间位数。静态 musl 客户端不依赖宿主 glibc 或 .NET；一键脚本仍需要 unzip（或 BusyBox unzip）、curl、iproute2、systemd 和 TUN。无 systemd 的机器可以使用包内安装脚本或自行管理服务。

Linux x86 32 位不同于 ARM32；当前 .NET 工具链构建 linux-x86 报 NETSDK1084，没有可发布版本。v0.3.2 自包含候选包未部署，已由此次远程静态 AOT 构建取代。

验证：三架构 ELF/包结构检查、各架构实际启动、官网 HTTPS 加网与配置读取；x64 在独立 Docker 网络命名空间创建真实 TUN 并注册上线。当时的 ARM 构建机没有 TUN，ARM 使用隔离容器的 proxy 模式验证联网，不将其称为 ARM TUN 实机验证。所有测试使用专用临时网络，完成后撤销并清理。

## 安装空间预检查修复（2026-09-27）

在线 Linux 安装脚本在创建工作目录、下载或领取设备身份前，检查安装缓存、`/opt/edge-vpn`、`/var/lib/edge-vpn` 和 systemd 配置所在文件系统的可用容量、inode 与只读状态。同一分区合并计算预算，当前全部位于根分区时要求至少 121 MiB 可用；独立 `/tmp` 有空间不代表根分区可安装。

安装成功后删除本次缓存中的 ZIP 和客户端二进制，仅保留小体积配置及领取标识，以便同一命令安全重试。脚本不会自动删除业务文件或搬迁系统目录。空间不足时按提示检查 `df -h` 和 `df -i`，先释放对应分区空间，再执行命令；安装命令过期则在控制台重新生成。

验证：`python tools/storage-check.py` 覆盖磁盘满、inode 耗尽、只读、同分区合并预算、独立分区、缓存清理保留领取标识和配置；已在实际满盘 ARM64 机器验证领取凭据前中止。本修复更新官网在线脚本及源模板，客户端 NativeAOT 二进制保持 0.3.3。


## v0.3.4 纯 POSIX Shell 在线安装

Linux 一键安装不再调用 Python 或 jq。控制端生成脚本时直接填入下载路径及 SHA-256，脚本使用 curl、unzip（可用 BusyBox 替代）、sha256sum 和基础系统命令。架构通过当前 Shell 的 ELF 位数及 uname 判断；配置由 curl 领取并由 NativeAOT 客户端解析、验证，无需 Shell 解析或执行 JSON。

领取标识兼容旧脚本的格式，使用 /dev/urandom 生成并保存在受限目录。curl 从标准输入读取认证头，不把安装凭据写入请求文件或 curl 参数。固定成员解压避免 ZIP 路径穿越；安装锁避免并发操作同一凭据目录。通用升级保留已有配置及其控制服务器，专属命令会比较已有设备 ID，拒绝覆盖另一设备。

`--download-only` 校验下载并试运行原生客户端，不领取身份；`--configure-only` 用于运维验证，只领取和校验配置，不安装系统服务。两者不等于设备已上线。测试工具可在开发机使用 Python，目标设备执行在线脚本不依赖 Python。
