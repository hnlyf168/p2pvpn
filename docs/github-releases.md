# GitHub Releases 发布

下载地址：<https://github.com/hnlyf168/p2pvpn/releases>

本仓库提供 `Publish verified release` 流水线，把已经编译好的多平台成品和当前提交的源码发布到 Releases。Linux 客户端继续在指定的原生构建机上编译；此流水线负责来源、SHA-256、大小、ZIP 内容和静态 ELF 架构校验，不负责重新编译各架构的 NativeAOT 成品。源码构建及集成测试通过后才进入发布步骤。

## 发布一次新版本

1. 在构建机完成编译、运行测试，将成品上传官网 `/downloads/`。Linux 客户端必须通过 `tools/verify-native-elf.py`；ARM 32 位指 ARMv7，不是 x86 32 位。
2. 复制 `releases/manifests/0.3.4.json` 为新版本清单，填写实际组件版本、文件名、下载地址、SHA-256、字节数、运行方式。整体 Release 版本可以与组件版本不同，不能把旧二进制改名冒充新版本。
3. 提交并推送到 `main`。打开 GitHub → Actions → **Publish verified release** → **Run workflow**，选择 `main`，填写清单版本，例如 `0.3.4`，不要带 `v`。
4. 流水线测试源码，验证所有成品，生成源码 ZIP、`release-manifest.json`、`SHA256SUMS` 和发布说明，创建草稿并上传。GitHub 返回的每个附件 SHA-256 全部匹配后才公开 Release，标签绑定该次运行的提交。

不需要配置 SSH 密码或个人 GitHub Token。工作流仅在发布任务使用短期 `GITHUB_TOKEN` 的 `contents: write` 权限。动作固定到提交 SHA；输入不会直接拼接为 shell 代码；仅接受官网 HTTPS 下载地址，拒绝跨域重定向。

如果中途上传失败，草稿会保留，修复网络等问题后可以重跑**同一次工作流**。已经上传且摘要一致的附件会跳过；不覆盖摘要不一致的附件，不移动已有标签，不改写已公开 Release。若有 `starter` 或错误附件，请先人工检查草稿并删除该失败附件再重跑。源码提交变更后应使用新版本清单；已有标签对应的版本不能指向另一份源码。

## 本地发布

要求 Python 3.11+、Git、干净且已提交的工作区。已有安装包可作为缓存，缓存也会校验；没有缓存则从官网获取。

```powershell
python -m unittest discover -s tests/Release -v
python tools/github-release.py prepare --version 0.3.4 --cache artifacts/downloads --output artifacts/github-release-0.3.4
# 用安全的运行环境提供 GITHUB_TOKEN，或使用已登录的 Git Credential Manager：
python tools/github-release.py publish --output artifacts/github-release-0.3.4 --git-credential
```

输出目录必须为空。只归档 Git 已跟踪源码，不复制工作区里的部署口令、真实客户端配置、数据库、安装票据或构建缓存。GitHub 发布副本为旧 Windows 包补入 `Wintun-LICENSE.txt`，程序保持不变；`release-manifest.json` 同时记录输入包和最终发布包的摘要。

## 0.3.4 发布范围

| 组件 | 平台 | 组件版本 | 运行方式 |
| --- | --- | --- | --- |
| 客户端 | Linux x64 / ARM64 / ARMv7 | 0.3.3 | 静态 musl NativeAOT |
| 客户端 | Windows x64 | 0.3.0 | 自包含 .NET |
| 控制服务 | Linux x64 | 0.3.4 | 自包含 .NET |
| 独立打洞节点 / 中继节点 | Linux x64 | 0.3.0 | 自包含 .NET |

没有已验证的 Linux x86 32 位、ARMv6、Android 或 Windows ARM 安装包，不提供占位包。源码包对应发布标签；历史成品的编译提交没有统一记录，不能把发布标签当作所有二进制的可复现构建证明。后续要全自动编译，应先把原生构建镜像、构建提交和运行验证记录纳入独立构建流水线。
