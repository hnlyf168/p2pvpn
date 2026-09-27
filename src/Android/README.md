# Android 1.1.0 · 独立新版

从原项目移植 Android 客户端，使用独立包名 `pub.hngs.vpn` 和新的正式签名，可与旧版并存。请在平台重新添加安卓设备。

- 支持 Android 8.0+；一个 APK 包含 ARMv7、ARM64、x64。
- 登录平台 → 添加设备 → 选择 Android → 安装 APK → 扫码或粘贴专属加入链接 → 允许系统 VPN 连接。
- 平台为手机分配独立身份，支持自定义网段、分组、备用协调节点。
- 普通会员认证与打洞；高级会员获取独立加密中继配置。主控制服务不转发业务流量。
- Android Keystore 加密保存设备密钥；HTTPS 认证请求禁止重定向。
- 保留原客户端的远端子网映射、扫码和 VPN 前台通知。

GitHub Actions 编译并检查正式签名、包名、版本及三种 ABI。按要求没有进行本机、模拟器或手机实测，首次移植作为预发布；不能据此认定真机组网已验证。

安装包为 .NET Android Release APK；Linux 静态 musl NativeAOT 要求不适用于 Android。

官网：https://vpn.hngs.pub/downloads  
首次连接：https://vpn.hngs.pub/console#setup

## 构建与签名

本项目单独构建，不加入服务端解决方案。在 GitHub Actions 运行 **Build and publish Android**，默认生成已签名的构建产物；勾选 publish 后，服务端回归也必须通过才能发布 APK、源码及 SHA256SUMS。

Actions secrets 为 ANDROID_KEYSTORE_BASE64（PKCS#12 的 Base64）、ANDROID_KEYSTORE_PASSWORD、ANDROID_KEY_ALIAS。签名指纹在 signing-certificate.sha256；后续版本必须沿用此密钥，递增 ApplicationVersion。请离线备份私钥和密码，不得提交仓库。

## 运行边界

使用 VpnService，仅路由平台网段和用户设置的远端子网，不设置互联网默认路由。应用本身排除于隧道，避免认证、打洞、中继产生循环。每 15 秒刷新设备配置；分组、密钥、中继变化后重连，401/403 停止连接。

edgevpn 加入链接的短期凭据位于 fragment。应用会显示平台 HTTPS 地址并要求确认，收到深链不会直接兑换。不要分享加入链接或二维码。旧版 p2pvpn://configure 明文共享密钥链接不再接收。
