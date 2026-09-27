# 源码来源

源项目：MyEdgeManager
源提交：6dd05f0f84196567b8aed03b6107efde5f0c57c6

复制：
- P2PVpnClient → src/Client
- EdgeDdnsClient/ThirdParty/Qcxt.Net.P2P → src/Transport/Qcxt.Net.P2P
- EdgeDdnsClient/ThirdParty/Qcxt.Net.QUIC → src/Transport/Qcxt.Net.QUIC

没有复制 DDNS、摄像头、文件管理、原管理后台、原部署凭据或原客户端下载 APK。
客户端仍沿用原项目的类库命名和可执行文件名，安装服务及状态目录使用 Edge VPN 独立名称。
控制服务和独立节点入口、公众管理页面、套餐／设备认证、新中转通道为此次新增。
提取过程的临时迁移脚本不属于公开仓库的构建入口。

构建无需访问 MyEdgeManager 目录。浏览器验证脚本使用 Playwright；
本次验证复用了本机已有工具，运行自己的验证环境时自行指定 PLAYWRIGHT_MODULE。
