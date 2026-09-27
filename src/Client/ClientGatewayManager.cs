using System.Diagnostics;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;

namespace P2PVpnClient;

/// <summary>
/// 表示 Client Gateway Manager，并提供相关数据或行为。
/// </summary>
internal static class ClientGatewayManager
{
    private const string WindowsNatName = "P2P-VPN-Subnet-Gateway";
    private const string LinuxForwardChain = "P2P_VPN_GW_FORWARD";
    private const string LinuxNatChain = "P2P_VPN_GW_NAT";
    private static readonly SemaphoreSlim Gate = new(1, 1);
    private static string _linuxSignature = string.Empty;

    /// <summary>
    /// 尝试Apply。
    /// </summary>
    /// <param name="config">config参数。</param>
    /// <param name="vpnAddress">vpn Address参数。</param>
    /// <param name="vpnPrefixLength">vpn Prefix Length参数。</param>
    /// <param name="vpnInterfaceName">vpn Interface Name参数。</param>
    /// <param name="cancellationToken">用于取消异步操作的令牌。</param>
    /// <returns>操作是否成功。</returns>
    internal static async Task TryApplyAsync(ClientConfig config, IPAddress vpnAddress,
        int vpnPrefixLength, string vpnInterfaceName, CancellationToken cancellationToken)
    {
        try
        {
            if (OperatingSystem.IsLinux())
            {
                await ApplyLinuxAsync(config, vpnAddress, vpnPrefixLength, vpnInterfaceName,
                    cancellationToken).ConfigureAwait(false);
                return;
            }
            if (OperatingSystem.IsWindows())
                await ApplyWindowsAsync(config, vpnAddress, vpnPrefixLength, vpnInterfaceName,
                    cancellationToken).ConfigureAwait(false);
        }
        catch (Exception exception)
        {
            ClientLog.Write($"Unable to apply subnet gateway: {exception.Message}");
        }
    }

    /// <summary>
    /// 执行Apply Windows操作。
    /// </summary>
    /// <param name="config">config参数。</param>
    /// <param name="vpnAddress">vpn Address参数。</param>
    /// <param name="vpnPrefixLength">vpn Prefix Length参数。</param>
    /// <param name="vpnInterfaceName">vpn Interface Name参数。</param>
    /// <param name="cancellationToken">用于取消异步操作的令牌。</param>
    /// <returns>操作结果。</returns>
    private static async Task ApplyWindowsAsync(ClientConfig config, IPAddress vpnAddress,
        int vpnPrefixLength, string vpnInterfaceName, CancellationToken cancellationToken)
    {
        IReadOnlyList<ClientGatewayNetwork> networks = ClientConfigStore.GetGatewayNetworks(config);
        if (config.GatewayMode == "local")
        {
            await RunPowerShellAsync($"Get-NetNat -Name '{WindowsNatName}' -ErrorAction SilentlyContinue | Remove-NetNat -Confirm:$false",
                cancellationToken).ConfigureAwait(false);
            return;
        }

        NetworkInterface vpnInterface = FindInterface(vpnInterfaceName) ??
            throw new InvalidOperationException("The Edge VPN interface was not found.");
        int vpnIndex = vpnInterface.GetIPProperties().GetIPv4Properties()?.Index ?? 0;
        if (vpnIndex <= 0) throw new InvalidOperationException("Unable to resolve the VPN interface index.");

        var indexes = new HashSet<int>();
        bool automaticInterface = false;
        foreach (ClientGatewayNetwork network in networks)
        {
            if (!ClientConfigStore.TryParseIpv4Cidr(network.Subnet, out IPAddress lanNetwork, out int lanPrefix))
                throw new InvalidDataException($"Invalid gateway LAN subnet: {network.Subnet}");
            if (network.Interface.Length == 0)
            {
                automaticInterface = true;
                continue;
            }
            NetworkInterface lan = ResolveLanInterface(network.Interface, lanNetwork, lanPrefix, vpnInterface.Id) ??
                throw new InvalidOperationException($"LAN interface '{network.Interface}' was not found for {network.Subnet}.");
            int index = lan.GetIPProperties().GetIPv4Properties()?.Index ?? 0;
            if (index > 0) indexes.Add(index);
        }

        string vpnSubnet = ToNetworkCidr(vpnAddress, vpnPrefixLength);
        string forwarding = automaticInterface
            ? $"Get-NetIPInterface -AddressFamily IPv4 | Where-Object {{$_.InterfaceIndex -ne {vpnIndex} -and $_.ConnectionState -eq 'Connected'}} | Set-NetIPInterface -Forwarding Enabled;"
            : string.Concat(indexes.Select(index =>
                $"Set-NetIPInterface -InterfaceIndex {index} -AddressFamily IPv4 -Forwarding Enabled;"));
        string script = "$ErrorActionPreference='Stop';" +
            $"Set-NetIPInterface -InterfaceIndex {vpnIndex} -AddressFamily IPv4 -Forwarding Enabled;" + forwarding +
            $"$n=Get-NetNat -Name '{WindowsNatName}' -ErrorAction SilentlyContinue;" +
            (config.GatewayMode == "nat"
                ? $"if($n -and $n.InternalIPInterfaceAddressPrefix -ne '{vpnSubnet}'){{$n|Remove-NetNat -Confirm:$false;$n=$null}};if(-not $n){{New-NetNat -Name '{WindowsNatName}' -InternalIPInterfaceAddressPrefix '{vpnSubnet}'|Out-Null}}"
                : "if($n){$n|Remove-NetNat -Confirm:$false}");
        await RunPowerShellAsync(script, cancellationToken).ConfigureAwait(false);
        ClientLog.Write($"{config.GatewayMode} subnet gateway enabled for {networks.Count} network(s); blank interfaces use the system route table.");
    }

    /// <summary>
    /// 执行Apply Linux操作。
    /// </summary>
    /// <param name="config">config参数。</param>
    /// <param name="vpnAddress">vpn Address参数。</param>
    /// <param name="vpnPrefixLength">vpn Prefix Length参数。</param>
    /// <param name="vpnInterfaceName">vpn Interface Name参数。</param>
    /// <param name="cancellationToken">用于取消异步操作的令牌。</param>
    /// <returns>操作结果。</returns>
    private static async Task ApplyLinuxAsync(ClientConfig config, IPAddress vpnAddress,
        int vpnPrefixLength, string vpnInterfaceName, CancellationToken cancellationToken)
    {
        await Gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            IReadOnlyList<ClientGatewayNetwork> networks = ClientConfigStore.GetGatewayNetworks(config);
            if (config.GatewayMode == "local")
            {
                await CleanupLinuxChainsAsync(cancellationToken).ConfigureAwait(false);
                _linuxSignature = string.Empty;
                return;
            }

            string vpnSubnet = ToNetworkCidr(vpnAddress, vpnPrefixLength);
            var resolved = new List<(string Subnet, string Interface)>(networks.Count);
            foreach (ClientGatewayNetwork network in networks)
            {
                if (!ClientConfigStore.TryParseIpv4Cidr(network.Subnet, out IPAddress lanNetwork, out int lanPrefix))
                    throw new InvalidDataException($"Invalid gateway LAN subnet: {network.Subnet}");
                string interfaceName = network.Interface;
                if (interfaceName.Length > 0)
                {
                    NetworkInterface vpnInterface = FindInterface(vpnInterfaceName) ??
                        throw new InvalidOperationException("The Edge VPN interface was not found.");
                    NetworkInterface lan = ResolveLanInterface(interfaceName, lanNetwork, lanPrefix, vpnInterface.Id) ??
                        throw new InvalidOperationException($"LAN interface '{interfaceName}' was not found for {network.Subnet}.");
                    interfaceName = lan.Name;
                }
                resolved.Add((network.Subnet, interfaceName));
            }

            string signature = $"{config.GatewayMode}|{vpnInterfaceName}|{vpnSubnet}|" +
                string.Join('|', resolved.OrderBy(static item => item.Subnet, StringComparer.Ordinal)
                    .ThenBy(static item => item.Interface, StringComparer.Ordinal)
                    .Select(static item => $"{item.Subnet}@{item.Interface}"));
            bool rebuild = !string.Equals(_linuxSignature, signature, StringComparison.Ordinal) ||
                !await LinuxChainExistsAsync("filter", LinuxForwardChain, cancellationToken).ConfigureAwait(false);
            if (rebuild)
            {
                await CleanupLinuxChainsAsync(cancellationToken).ConfigureAwait(false);
                await RunCommandAsync("sysctl", ["-w", "net.ipv4.ip_forward=1"], cancellationToken)
                    .ConfigureAwait(false);
                await RequireIptablesAsync("filter", ["-N", LinuxForwardChain], cancellationToken).ConfigureAwait(false);
                if (config.GatewayMode == "nat")
                    await RequireIptablesAsync("nat", ["-N", LinuxNatChain], cancellationToken).ConfigureAwait(false);
                _linuxSignature = signature;
            }

            bool changed = rebuild;
            changed |= await EnsureIptablesRuleAsync("filter",
                ["FORWARD", "-j", LinuxForwardChain], cancellationToken, insert: true).ConfigureAwait(false);
            if (config.GatewayMode == "nat")
                changed |= await EnsureIptablesRuleAsync("nat",
                    ["POSTROUTING", "-j", LinuxNatChain], cancellationToken, insert: true).ConfigureAwait(false);

            foreach ((string subnet, string interfaceName) in resolved)
            {
                var outbound = new List<string> { LinuxForwardChain, "-i", vpnInterfaceName };
                if (interfaceName.Length > 0) { outbound.Add("-o"); outbound.Add(interfaceName); }
                outbound.AddRange(["-s", vpnSubnet, "-d", subnet, "-j", "ACCEPT"]);
                changed |= await EnsureIptablesRuleAsync("filter", outbound, cancellationToken).ConfigureAwait(false);

                var inbound = new List<string> { LinuxForwardChain };
                if (interfaceName.Length > 0) { inbound.Add("-i"); inbound.Add(interfaceName); }
                inbound.AddRange(["-o", vpnInterfaceName, "-s", subnet, "-d", vpnSubnet,
                    "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT"]);
                changed |= await EnsureIptablesRuleAsync("filter", inbound, cancellationToken).ConfigureAwait(false);

                if (config.GatewayMode == "nat")
                {
                    var nat = new List<string> { LinuxNatChain };
                    if (interfaceName.Length > 0) { nat.Add("-o"); nat.Add(interfaceName); }
                    nat.AddRange(["-s", vpnSubnet, "-d", subnet, "-j", "MASQUERADE"]);
                    changed |= await EnsureIptablesRuleAsync("nat", nat, cancellationToken).ConfigureAwait(false);
                }
            }
            if (changed)
                ClientLog.Write($"{config.GatewayMode} subnet gateway rules applied or repaired for {resolved.Count} network(s); blank interfaces use the system route table.");
        }
        finally { Gate.Release(); }
    }

    /// <summary>
    /// 执行Cleanup Linux Chains操作。
    /// </summary>
    /// <param name="cancellationToken">用于取消异步操作的令牌。</param>
    /// <returns>操作结果。</returns>
    private static async Task CleanupLinuxChainsAsync(CancellationToken cancellationToken)
    {
        while (await IptablesRuleExistsAsync("filter", ["FORWARD", "-j", LinuxForwardChain], cancellationToken).ConfigureAwait(false))
            await RunIptablesAsync("filter", ["-D", "FORWARD", "-j", LinuxForwardChain], cancellationToken).ConfigureAwait(false);
        while (await IptablesRuleExistsAsync("nat", ["POSTROUTING", "-j", LinuxNatChain], cancellationToken).ConfigureAwait(false))
            await RunIptablesAsync("nat", ["-D", "POSTROUTING", "-j", LinuxNatChain], cancellationToken).ConfigureAwait(false);
        foreach ((string table, string chain) in new[] { ("filter", LinuxForwardChain), ("nat", LinuxNatChain) })
        {
            if (!await LinuxChainExistsAsync(table, chain, cancellationToken).ConfigureAwait(false)) continue;
            await RunIptablesAsync(table, ["-F", chain], cancellationToken).ConfigureAwait(false);
            await RunIptablesAsync(table, ["-X", chain], cancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// 执行Linux Chain Exists操作。
    /// </summary>
    /// <param name="table">table参数。</param>
    /// <param name="chain">chain参数。</param>
    /// <param name="cancellationToken">用于取消异步操作的令牌。</param>
    /// <returns>操作结果。</returns>
    private static async Task<bool> LinuxChainExistsAsync(string table, string chain,
        CancellationToken cancellationToken) =>
        await RunIptablesAsync(table, ["-n", "-L", chain], cancellationToken).ConfigureAwait(false) == 0;

    /// <summary>
    /// 执行Ensure Iptables Rule操作。
    /// </summary>
    /// <param name="table">table参数。</param>
    /// <param name="rule">rule参数。</param>
    /// <param name="cancellationToken">用于取消异步操作的令牌。</param>
    /// <param name="insert">insert参数。</param>
    /// <returns>操作结果。</returns>
    private static async Task<bool> EnsureIptablesRuleAsync(string table, IReadOnlyList<string> rule,
        CancellationToken cancellationToken, bool insert = false)
    {
        if (await IptablesRuleExistsAsync(table, rule, cancellationToken).ConfigureAwait(false)) return false;
        var arguments = new List<string> { insert ? "-I" : "-A" };
        arguments.AddRange(rule);
        await RequireIptablesAsync(table, arguments, cancellationToken).ConfigureAwait(false);
        return true;
    }

    /// <summary>
    /// 执行Iptables Rule Exists操作。
    /// </summary>
    /// <param name="table">table参数。</param>
    /// <param name="rule">rule参数。</param>
    /// <param name="cancellationToken">用于取消异步操作的令牌。</param>
    /// <returns>操作结果。</returns>
    private static async Task<bool> IptablesRuleExistsAsync(string table, IReadOnlyList<string> rule,
        CancellationToken cancellationToken)
    {
        var arguments = new List<string> { "-C" };
        arguments.AddRange(rule);
        return await RunIptablesAsync(table, arguments, cancellationToken).ConfigureAwait(false) == 0;
    }

    /// <summary>
    /// 执行Require Iptables操作。
    /// </summary>
    /// <param name="table">table参数。</param>
    /// <param name="arguments">arguments参数。</param>
    /// <param name="cancellationToken">用于取消异步操作的令牌。</param>
    /// <returns>操作结果。</returns>
    private static async Task RequireIptablesAsync(string table, IReadOnlyList<string> arguments,
        CancellationToken cancellationToken)
    {
        int exitCode = await RunIptablesAsync(table, arguments, cancellationToken).ConfigureAwait(false);
        if (exitCode != 0) throw new InvalidOperationException($"iptables ({table}) exited with code {exitCode}.");
    }

    /// <summary>
    /// 执行Run Iptables操作。
    /// </summary>
    /// <param name="table">table参数。</param>
    /// <param name="arguments">arguments参数。</param>
    /// <param name="cancellationToken">用于取消异步操作的令牌。</param>
    /// <returns>操作结果。</returns>
    private static Task<int> RunIptablesAsync(string table, IReadOnlyList<string> arguments,
        CancellationToken cancellationToken)
    {
        var full = new List<string> { "-w", "5" };
        if (table != "filter") { full.Add("-t"); full.Add(table); }
        full.AddRange(arguments);
        return RunCommandAsync("iptables", [.. full], cancellationToken, throwOnError: false);
    }

    /// <summary>
    /// 执行Find Interface操作。
    /// </summary>
    /// <param name="nameOrId">name Or Id参数。</param>
    /// <returns>操作结果。</returns>
    private static NetworkInterface? FindInterface(string nameOrId) =>
        NetworkInterface.GetAllNetworkInterfaces().FirstOrDefault(item =>
            string.Equals(item.Name, nameOrId, StringComparison.OrdinalIgnoreCase) ||
            string.Equals(item.Id, nameOrId, StringComparison.OrdinalIgnoreCase) ||
            string.Equals(item.Description, nameOrId, StringComparison.OrdinalIgnoreCase));

    /// <summary>
    /// 执行Resolve Lan Interface操作。
    /// </summary>
    /// <param name="requested">requested参数。</param>
    /// <param name="network">network参数。</param>
    /// <param name="prefixLength">prefix Length参数。</param>
    /// <param name="excludedId">excluded Id参数。</param>
    /// <returns>操作结果。</returns>
    private static NetworkInterface? ResolveLanInterface(string requested, IPAddress network,
        int prefixLength, string excludedId)
    {
        IEnumerable<NetworkInterface> candidates = NetworkInterface.GetAllNetworkInterfaces().Where(item =>
            item.OperationalStatus == OperationalStatus.Up && item.NetworkInterfaceType != NetworkInterfaceType.Loopback &&
            !string.Equals(item.Id, excludedId, StringComparison.OrdinalIgnoreCase));
        if (requested.Length > 0)
            return candidates.FirstOrDefault(item => string.Equals(item.Name, requested, StringComparison.OrdinalIgnoreCase) ||
                string.Equals(item.Id, requested, StringComparison.OrdinalIgnoreCase) ||
                string.Equals(item.Description, requested, StringComparison.OrdinalIgnoreCase));
        uint mask = prefixLength == 32 ? uint.MaxValue : uint.MaxValue << (32 - prefixLength);
        uint expected = ToUInt32(network) & mask;
        return candidates.FirstOrDefault(item => item.GetIPProperties().UnicastAddresses.Any(address =>
            address.Address.AddressFamily == AddressFamily.InterNetwork &&
            (ToUInt32(address.Address) & mask) == expected));
    }

    /// <summary>
    /// 执行To Network Cidr操作。
    /// </summary>
    /// <param name="address">网络地址。</param>
    /// <param name="prefixLength">prefix Length参数。</param>
    /// <returns>操作结果。</returns>
    private static string ToNetworkCidr(IPAddress address, int prefixLength)
    {
        uint mask = prefixLength == 32 ? uint.MaxValue : uint.MaxValue << (32 - prefixLength);
        uint network = ToUInt32(address) & mask;
        return $"{(network >> 24) & 255}.{(network >> 16) & 255}.{(network >> 8) & 255}.{network & 255}/{prefixLength}";
    }

    /// <summary>
    /// 执行To U Int32操作。
    /// </summary>
    /// <param name="address">网络地址。</param>
    /// <returns>操作结果。</returns>
    private static uint ToUInt32(IPAddress address)
    {
        byte[] bytes = address.GetAddressBytes();
        return ((uint)bytes[0] << 24) | ((uint)bytes[1] << 16) | ((uint)bytes[2] << 8) | bytes[3];
    }

    /// <summary>
    /// 执行Run Power Shell操作。
    /// </summary>
    /// <param name="script">script参数。</param>
    /// <param name="cancellationToken">用于取消异步操作的令牌。</param>
    /// <returns>操作结果。</returns>
    private static async Task RunPowerShellAsync(string script, CancellationToken cancellationToken)
    {
        var start = new ProcessStartInfo("powershell.exe")
        {
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true
        };
        start.ArgumentList.Add("-NoProfile");
        start.ArgumentList.Add("-NonInteractive");
        start.ArgumentList.Add("-ExecutionPolicy");
        start.ArgumentList.Add("Bypass");
        start.ArgumentList.Add("-Command");
        start.ArgumentList.Add(script);
        using Process process = Process.Start(start) ?? throw new InvalidOperationException("Unable to start PowerShell.");
        Task<string> output = process.StandardOutput.ReadToEndAsync(cancellationToken);
        Task<string> error = process.StandardError.ReadToEndAsync(cancellationToken);
        await process.WaitForExitAsync(cancellationToken).ConfigureAwait(false);
        string errorText = (await error.ConfigureAwait(false)).Trim();
        _ = await output.ConfigureAwait(false);
        if (process.ExitCode != 0)
            throw new InvalidOperationException(errorText.Length > 0 ? errorText : $"PowerShell exited with code {process.ExitCode}.");
    }

    /// <summary>
    /// 执行Run Command操作。
    /// </summary>
    /// <param name="fileName">file Name参数。</param>
    /// <param name="arguments">arguments参数。</param>
    /// <param name="cancellationToken">用于取消异步操作的令牌。</param>
    /// <param name="throwOnError">throw On Error参数。</param>
    /// <returns>操作结果。</returns>
    private static async Task<int> RunCommandAsync(string fileName, string[] arguments,
        CancellationToken cancellationToken, bool throwOnError = true)
    {
        var start = new ProcessStartInfo(fileName)
        {
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true
        };
        foreach (string argument in arguments) start.ArgumentList.Add(argument);
        using Process process = Process.Start(start) ?? throw new InvalidOperationException($"Unable to start {fileName}.");
        Task<string> output = process.StandardOutput.ReadToEndAsync(cancellationToken);
        Task<string> error = process.StandardError.ReadToEndAsync(cancellationToken);
        await process.WaitForExitAsync(cancellationToken).ConfigureAwait(false);
        _ = await output.ConfigureAwait(false);
        string errorText = (await error.ConfigureAwait(false)).Trim();
        if (throwOnError && process.ExitCode != 0)
            throw new InvalidOperationException(errorText.Length > 0 ? errorText : $"{fileName} exited with code {process.ExitCode}.");
        return process.ExitCode;
    }
}
