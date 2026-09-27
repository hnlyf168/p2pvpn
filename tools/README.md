# 开发与验证工具

- import-traffic-history.py：首次启用统计时，离线导入旧 Nginx JSON 日志，仅保留按天汇总，拒绝覆盖现有统计。
- traffic-browser-check.cjs：使用隔离测试数据验证运营统计界面、日期筛选和手机适配。
- dev.ps1 / stop-dev.ps1：Windows 本地开发进程；验证码仅在 Development 环境写入本地邮件目录。
- build-native-clients.sh：已验证的 Linux 静态 musl NativeAOT 构建流程，需要自行准备对应 Docker 工具链镜像。默认客户端版本 0.3.3；不是自动安装编译环境的脚本。
- pack-native-source.py / package-native-clients.py / verify-native-elf.py：源码打包、远程构建产物整理和静态 ELF 检查。
- publish.ps1 / zip-package.py / package-setup-update.py：发布打包工具。客户端、服务端版本可能不同，请显式选择要发布的组件和版本；升级包工具需要已存在的前后两版产物。
- browser-check.cjs / setup-check.cjs：浏览器与安装流程回归；需要 Playwright、浏览器及相关下载包。可通过 PLAYWRIGHT_MODULE 和 BROWSER_EXECUTABLE 指定本机路径。
- architecture-check.py：Shell 架构识别及已有发布包结构检查，需要可执行的 sh；Windows 可使用 Git for Windows。
- storage-check.py：在 Linux 上测试安装前容量、inode、只读、分区预算和互斥保护。
- check-package.ps1 / check-shell-encoding.py：安装包和脚本编码检查，需要对应构建产物。
- render-wechat.cjs：生成公众号流程/架构 PNG，并从 Markdown 生成 HTML 预览；封面图片单独提供。

这些工具写入 artifacts/，不应把产物、临时凭据或测试状态提交到 Git。生产服务器操作及一次性代码迁移脚本不作为公开项目的构建入口。
