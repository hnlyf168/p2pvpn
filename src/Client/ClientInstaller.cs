using System.Diagnostics;
using System.Security.Principal;

namespace P2PVpnClient;

/// <summary>完成客户端文件复制、配置保存和 Windows 服务注册。</summary>
internal static class ClientInstaller
{
    private const string FirewallRuleUdp = "Edge VPN UDP";
    private const string FirewallRuleTcp = "Edge VPN TCP";
    private static readonly string InstallDirectory = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "Edge VPN");

    /// <summary>交互式收集配置并安装自动启动服务。</summary>
    /// <returns>安装成功返回 0。</returns>
    [System.Runtime.Versioning.SupportedOSPlatform("windows")]
    internal static int Install()
    {
        EnsureAdministrator();
        Console.OutputEncoding = System.Text.Encoding.UTF8;
        Console.WriteLine("Edge VPN 客户端安装程序");
        string packageConfig = ClientConfigStore.ConfigPath;
        if (!File.Exists(packageConfig))
            throw new FileNotFoundException("安装目录缺少 client.json，请把配置文件复制到客户端 EXE 同一目录。",
                packageConfig);
        ClientConfig config = ClientConfigStore.Load(packageConfig);
        string id = config.DeviceId;

        StopAndDeleteExistingService();
        CopyApplication(ClientConfigStore.ExecutableDirectory, InstallDirectory);
        string executable = Path.Combine(InstallDirectory, "P2PVpnClient.exe");
        var permissions = new ProcessStartInfo(Path.Combine(Environment.SystemDirectory, "icacls.exe")) { UseShellExecute = false, CreateNoWindow = true };
        foreach (var argument in new[] { InstallDirectory, "/inheritance:r", "/grant:r", "*S-1-5-18:(OI)(CI)F", "*S-1-5-32-544:(OI)(CI)F", "/T" }) permissions.ArgumentList.Add(argument);
        using (var process = Process.Start(permissions)!) { process.WaitForExit(); if (process.ExitCode != 0) throw new IOException("无法保护客户端凭据文件权限。"); }
        ConfigureFirewall(executable);
        RunSc(true, "create", WindowsServiceHost.ServiceName, "binPath=", executable,
            "start=", "auto", "DisplayName=", "Edge VPN 客户端");
        RunSc(true, "description", WindowsServiceHost.ServiceName,
            "Edge VPN 虚拟网卡客户端；自动打洞并在失败时通过服务器中继。");
        RunSc(true, "failure", WindowsServiceHost.ServiceName,
            "reset=", "86400", "actions=", "restart/5000/restart/15000/restart/30000");
        RunSc(true, "failureflag", WindowsServiceHost.ServiceName, "1");
        RunSc(true, "start", WindowsServiceHost.ServiceName);
        Console.WriteLine($"安装完成。固定客户端 ID：{id}");
        Console.WriteLine($"服务器：{config.Server}，分组：{config.Group}");
        Console.WriteLine($"客户端配置：{Path.Combine(InstallDirectory, "client.json")}");
        Console.WriteLine($"固定 ID 和日志目录：{ClientConfigStore.DirectoryPath}");
        return 0;
    }

    /// <summary>停止并删除服务，保留客户端 ID 和配置以便重装后继续使用原 IP。</summary>
    /// <returns>卸载成功返回 0。</returns>
    [System.Runtime.Versioning.SupportedOSPlatform("windows")]
    internal static int Uninstall()
    {
        EnsureAdministrator();
        StopAndDeleteExistingService();
        RemoveFirewallRules();
        Console.WriteLine("服务已删除；客户端 ID 和配置已保留，重装后仍会申请原虚拟 IP。");
        return 0;
    }

    /// <summary>检查当前进程是否具有本机管理员权限。</summary>
    [System.Runtime.Versioning.SupportedOSPlatform("windows")]
    private static void EnsureAdministrator()
    {
        using WindowsIdentity identity = WindowsIdentity.GetCurrent();
        if (!new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator))
            throw new UnauthorizedAccessException("请双击安装脚本自动以管理员权限运行。");
    }

    /// <summary>请求旧服务停止，并等待旧进程释放可执行文件后删除服务注册。</summary>
    private static void StopAndDeleteExistingService()
    {
        RunSc(false, "stop", WindowsServiceHost.ServiceName);
        long deadline = Environment.TickCount64 + 30_000;
        while (HasOtherClientProcess() && Environment.TickCount64 < deadline) Thread.Sleep(250);
        if (HasOtherClientProcess())
            throw new TimeoutException("旧 VPN 客户端服务未能在 30 秒内停止，请稍后重试安装。");
        RunSc(false, "delete", WindowsServiceHost.ServiceName);
    }

    /// <summary>检查除当前安装程序外是否仍有客户端服务或诊断进程。</summary>
    /// <returns>仍有进程占用客户端文件时返回 true。</returns>
    private static bool HasOtherClientProcess()
    {
        Process[] processes = Process.GetProcessesByName("P2PVpnClient");
        try { return processes.Any(process => process.Id != Environment.ProcessId &&
            string.Equals(process.MainModule?.FileName, Path.Combine(InstallDirectory, "P2PVpnClient.exe"), StringComparison.OrdinalIgnoreCase)); }
        finally { foreach (Process process in processes) process.Dispose(); }
    }

    /// <summary>复制当前发布目录中的全部文件到固定安装目录。</summary>
    /// <param name="source">Native AOT 发布目录。</param>
    /// <param name="destination">固定程序安装目录。</param>
    private static void CopyApplication(string source, string destination)
    {
        string sourceFull = Path.GetFullPath(source).TrimEnd(Path.DirectorySeparatorChar);
        string destinationFull = Path.GetFullPath(destination).TrimEnd(Path.DirectorySeparatorChar);
        if (sourceFull.Equals(destinationFull, StringComparison.OrdinalIgnoreCase)) return;
        Directory.CreateDirectory(destinationFull);
        foreach (string file in Directory.EnumerateFiles(sourceFull))
        {
            File.Copy(file, Path.Combine(destinationFull, Path.GetFileName(file)), true);
        }
    }

    /// <summary>Allows authenticated direct UDP/TCP traffic to reach the client process after UPnP opens the router.</summary>
    private static void ConfigureFirewall(string executable)
    {
        RemoveFirewallRules();
        RunNetsh("advfirewall", "firewall", "add", "rule", $"name={FirewallRuleUdp}",
            "dir=in", "action=allow", $"program={executable}", "protocol=UDP", "profile=any");
        RunNetsh("advfirewall", "firewall", "add", "rule", $"name={FirewallRuleTcp}",
            "dir=in", "action=allow", $"program={executable}", "protocol=TCP", "profile=any");
    }

    /// <summary>
    /// 移除Firewall Rules。
    /// </summary>
    private static void RemoveFirewallRules()
    {
        RunNetsh("advfirewall", "firewall", "delete", "rule", $"name={FirewallRuleUdp}");
        RunNetsh("advfirewall", "firewall", "delete", "rule", $"name={FirewallRuleTcp}");
    }

    /// <summary>
    /// 执行Run Netsh操作。
    /// </summary>
    /// <param name="arguments">arguments参数。</param>
    private static void RunNetsh(params string[] arguments)
    {
        var start = new ProcessStartInfo(Path.Combine(Environment.SystemDirectory, "netsh.exe"))
        { UseShellExecute = false, CreateNoWindow = true };
        foreach (string argument in arguments) start.ArgumentList.Add(argument);
        using Process process = Process.Start(start) ?? throw new InvalidOperationException("无法启动 netsh.exe。");
        process.WaitForExit();
        if (process.ExitCode != 0 && arguments.Contains("add", StringComparer.OrdinalIgnoreCase))
            throw new InvalidOperationException($"创建 Windows 防火墙规则失败，退出码 {process.ExitCode}。");
    }

    /// <summary>以独立参数调用系统 sc.exe，避免拼接命令造成路径或注入问题。</summary>
    /// <param name="required">失败时是否需要抛出异常。</param>
    /// <param name="arguments">传给 sc.exe 的独立参数。</param>
    private static void RunSc(bool required, params string[] arguments)
    {
        var start = new ProcessStartInfo(Path.Combine(Environment.SystemDirectory, "sc.exe")) { UseShellExecute = false };
        foreach (string argument in arguments) start.ArgumentList.Add(argument);
        using Process process = Process.Start(start) ?? throw new InvalidOperationException("无法启动 sc.exe。");
        process.WaitForExit();
        if (required && process.ExitCode != 0)
            throw new InvalidOperationException($"sc.exe {arguments[0]} 执行失败，退出码 {process.ExitCode}。");
    }
}
