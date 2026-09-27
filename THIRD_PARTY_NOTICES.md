# 第三方组件说明

## Wintun 0.14.1

Windows 客户端使用 Wintun。仓库内以下签名预编译文件与官方 0.14.1 下载包中的对应文件进行了 SHA-256 一致性比对：

- `src/Client/wintun.dll`：AMD64。
- `src/Client/runtimes/win-x86/native/wintun.dll`：X86。

来源：[Wintun 官方网站](https://www.wintun.net/)；[官方 0.14.1 ZIP](https://www.wintun.net/builds/wintun-0.14.1.zip)。官方 ZIP 的 SHA-256 为 `07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51`。

预编译 DLL 的许可文本随官方 ZIP 提供，保存在 [Wintun-LICENSE.txt](docs/third-party/Wintun-LICENSE.txt)。该许可仅适用于相应第三方组件，不代表整个项目的授权条款。

## NuGet 依赖与来源

NuGet 依赖及版本由各项目的 `.csproj` 定义，分别遵循其上游许可。P2P/QUIC 代码的提取来源见 [源码来源](docs/ORIGIN.md)。仓库未额外指定整个项目的开源许可证，第三方许可及权利声明保留。
