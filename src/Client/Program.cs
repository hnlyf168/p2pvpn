namespace P2PVpnClient;

/// <summary>Edge VPN 客户端服务入口。</summary>
internal static class Program
{
    /// <summary>处理服务、安装、卸载和前台诊断命令。</summary>
    /// <param name="args">命令行参数。</param>
    /// <returns>进程退出码。</returns>
    private static int Main(string[] args)
    {
        try
        {
            if (args.Length == 0)
            {
                if (OperatingSystem.IsWindows() && WindowsServiceHost.TryRun()) return 0;
                if (OperatingSystem.IsLinux()) return RunInteractive();
                Console.WriteLine("请双击“安装客户端.cmd”，或使用 P2PVpnClient.exe run 前台诊断。");
                return 0;
            }
            return args[0].ToLowerInvariant() switch
            {
                "install" when OperatingSystem.IsWindows() => ClientInstaller.Install(),
                "uninstall" when OperatingSystem.IsWindows() => ClientInstaller.Uninstall(),
                "join" when args.Length == 2 => PublicControlAgent.JoinAsync(args[1]).GetAwaiter().GetResult(),
                "id" => PrintId(),
                "version" => PrintVersion(),
                "check" => CheckConfig(),
                "network-mode" when args.Length == 2 => SetNetworkMode(args[1]),
                "upnp-test" => TestUpnp(),
                "run" => RunInteractive(),
                _ => PrintUsage()
            };
        }
        catch (Exception exception)
        {
            Console.Error.WriteLine($"操作失败：{exception.Message}");
            ClientLog.Write($"程序入口异常：{exception}");
            return 1;
        }
    }

    /// <summary>打印持久客户端 ID。</summary>
    private static int PrintVersion() { Console.WriteLine($"Edge VPN {ClientRuntimeInfo.Version} ({ClientRuntimeInfo.Platform})"); return 0; }
    private static int PrintId() { Console.WriteLine(ClientConfigStore.Load().DeviceId); return 0; }
    private static int SetNetworkMode(string mode)
    {
        var config = ClientConfigStore.Load(); config.NetworkMode = mode;
        if (mode == "proxy" && config.GatewayMode == "route") config.GatewayMode = "nat";
        ClientConfigStore.Save(config); Console.WriteLine("网卡模式已保存：" + mode); return 0;
    }

    /// <summary>验证 EXE 同目录的 client.json，但不启动服务或虚拟网卡。</summary>
    /// <returns>配置有效时返回零。</returns>
    private static int CheckConfig()
    {
        ClientConfig config = ClientConfigStore.Load();
        Console.WriteLine($"配置有效：服务器={config.Server}，分组={config.Group}，网卡={config.AdapterName}");
        return 0;
    }

    /// <summary>以前台模式运行 VPN，便于观察日志和排错。</summary>
    private static int RunInteractive()
    {
        using var stop = new CancellationTokenSource();
        Console.CancelKeyPress += (_, value) => { value.Cancel = true; stop.Cancel(); };
        Console.WriteLine("正在以前台诊断模式运行；按 Ctrl+C 停止。");
        VpnClientWorker.RunAsync(stop.Token).GetAwaiter().GetResult();
        return 0;
    }

    /// <summary>
    /// 执行Test Upnp操作。
    /// </summary>
    /// <returns>操作结果。</returns>
    private static int TestUpnp()
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        VpnClientWorker.TestUpnpAsync(timeout.Token).GetAwaiter().GetResult();
        return 0;
    }

    /// <summary>打印命令帮助。</summary>
    private static int PrintUsage()
    {
        Console.WriteLine("用法：P2PVpnClient.exe [install|uninstall|run|id|check|upnp-test]");
        return 2;
    }
}
