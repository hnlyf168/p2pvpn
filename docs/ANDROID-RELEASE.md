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
