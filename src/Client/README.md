# 推荐：一键安装

前往 https://vpn.hngs.pub/console#setup，按引导创建网络、添加设备，复制专属命令执行。无需再次输入加入码；脚本自动下载、校验、领取配置并安装服务。
Linux 脚本自动选择 x64、ARM64 或 ARM32（ARMv7 hard-float）包。发布包为静态 musl NativeAOT，不依赖目标系统的 glibc 或 .NET 运行时。一键安装脚本需要 systemd、unzip（或 BusyBox unzip）、curl 和 iproute2；无 systemd 的系统可使用包内安装脚本或自行配置服务。Linux x86（Intel/AMD 32 位）和 ARMv6 暂不支持，不能与 ARM32 混淆。
专属命令不会覆盖已有其他设备身份。升级已有设备请使用下载中心的通用脚本。

以下为手动安装与诊断说明。

# Edge VPN 客户端

此客户端从 MyEdgeManager 提取，连接独立的 Edge VPN 公众控制服务。

1. 在网站注册，创建网络和分组，并生成加入密钥。
2. 每台设备在“加入网络”中分别生成一个 client.json。
3. 下载对应平台 ZIP 并解压，将 client.json 放在 P2PVpnClient 可执行文件旁。
4. Windows：以管理员身份运行“安装客户端.cmd”。Linux：执行 sudo sh install-linux.sh。

也可在尚未配置的目录运行：
```text
P2PVpnClient join https://vpn.example.com
```
按提示输入加入密钥与设备名称，再安装或执行 run。

普通会员只使用认证和 UDP/TCP 打洞；高级会员由网络所有者的套餐决定是否允许独立 WSS 中转。
客户端先尝试直连，12 秒后才建立中转后备路径。健康直连存在时不使用中转承载业务包。
中转采用标准 AES-GCM 加密负载，中转节点不持有负载密钥。组内成员共享组数据密钥。

每 15 秒刷新设备配置，自动接收套餐、节点地址和通信密钥更新。
吊销设备后客户端停止连接；已有中转连接在节点复查权限后关闭。

Windows 服务：EdgeVpnClient，安装目录：C:\Program Files\Edge VPN。
Linux 服务：edge-vpn，安装目录：/opt/edge-vpn，状态目录：/var/lib/edge-vpn。
Windows 保留 Wintun 驱动文件；Linux 需要 /dev/net/tun 和 ip 命令。
解压目录所有运行时文件都必须保留，不要只复制 exe。

诊断：run、check、id、upnp-test。运行 VPN 和安装服务需要管理员/root权限。
不支持用旧版客户端连接此公众服务；旧版缺少独立设备认证。
