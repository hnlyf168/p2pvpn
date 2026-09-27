using System.Runtime.InteropServices;

namespace P2PVpnClient;

/// <summary>
/// 表示 Client Runtime Info，并提供相关数据或行为。
/// </summary>
internal static class ClientRuntimeInfo
{
    internal const string Version = "0.3.3";

    /// <summary>
    /// 获取或设置Platform。
    /// </summary>
    /// <returns>Platform。</returns>
    internal static string Platform =>
        OperatingSystem.IsWindows() && RuntimeInformation.ProcessArchitecture == Architecture.X64 ? "win-x64" :
        OperatingSystem.IsWindows() && RuntimeInformation.ProcessArchitecture == Architecture.X86 ? "win-x86" :
        OperatingSystem.IsLinux() && RuntimeInformation.ProcessArchitecture == Architecture.X64 ? "linux-x64" :
        OperatingSystem.IsLinux() && RuntimeInformation.ProcessArchitecture == Architecture.Arm ? "linux-arm" :
        OperatingSystem.IsLinux() && RuntimeInformation.ProcessArchitecture == Architecture.Arm64 ? "linux-arm64" :
        $"{(OperatingSystem.IsWindows() ? "win" : "linux")}-{RuntimeInformation.ProcessArchitecture.ToString().ToLowerInvariant()}";
}
