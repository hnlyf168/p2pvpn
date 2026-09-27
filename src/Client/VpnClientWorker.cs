using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using P2PSample;
using Qcxt.Net.P2P;
using Qcxt.Net.P2P.Signaling;
using Qcxt.Net.P2P.Tunneling;
using Qcxt.Net.Quic.Security;
using QuicSample;

namespace P2PVpnClient;

/// <summary>运行可自动重连、自动恢复路由和地址的 Wintun Edge VPN 客户端。</summary>
internal static class VpnClientWorker
{
    /// <summary>
    /// 执行Test Upnp操作。
    /// </summary>
    /// <param name="cancellationToken">用于取消异步操作的令牌。</param>
    /// <returns>操作结果。</returns>
    internal static async Task TestUpnpAsync(CancellationToken cancellationToken)
    {
        ClientConfig config = ClientConfigStore.Load();
        IPEndPoint server = await ResolveAsync(config.Server, 49000, cancellationToken);
        IPAddress localAddress = ResolveLocalAddress(server);
        int localPort = config.LocalPort == 0 ? FindAvailableDualProtocolPort(localAddress) : config.LocalPort;
        Console.WriteLine($"正在从 {localAddress}:{localPort} 搜索 UPnP IGD 路由器……");
        await using ClientUpnpMapper.ClientUpnpLease? lease = await ClientUpnpMapper.TryCreateAsync(
            localAddress, localPort, config.UpnpLeaseSeconds, cancellationToken).ConfigureAwait(false);
        if (lease is null) throw new InvalidOperationException("没有创建成功的 UPnP UDP/TCP 映射。");
        Console.WriteLine($"UPnP UDP：{lease.UdpPublicEndPoint?.ToString() ?? "不支持"}");
        Console.WriteLine($"UPnP TCP：{lease.TcpPublicEndPoint?.ToString() ?? "不支持"}");
        Console.WriteLine("测试完成，测试映射正在删除。");
    }

    /// <summary>持续运行到 Windows 服务停止；启动失败时使用有上限的退避重试。</summary>
    /// <param name="cancellationToken">服务停止令牌。</param>
    /// <returns>服务停止后完成的任务。</returns>
    internal static async Task RunAsync(CancellationToken cancellationToken)
    {
        ClientConfig managementConfig = ClientConfigStore.Load();
        string managementClientId = managementConfig.DeviceId;
        await using var management = new ClientManagementAgent(managementConfig, managementClientId);
        Task managementTask = management.RunAsync(cancellationToken);
        TimeSpan delay = TimeSpan.FromSeconds(2);
        try
        {
            while (!cancellationToken.IsCancellationRequested)
            {
                using var generation = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
                try
                {
                    await RunGenerationAsync(management, generation.Token);
                    delay = TimeSpan.FromSeconds(2);
                }
                catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { return; }
                catch (Exception exception)
                {
                    management.PolicyError = exception.Message;
                    ClientRuntimeStateStore.Error(exception.Message);
                    ClientLog.Write($"VPN 运行异常：{exception}；{delay.TotalSeconds:F0} 秒后重试。");
                    await Task.Delay(delay, cancellationToken);
                    delay = TimeSpan.FromSeconds(Math.Min(30, delay.TotalSeconds * 2));
                }
                finally { generation.Cancel(); }
            }
        }
        finally
        {
            try { await managementTask.ConfigureAwait(false); }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { }
        }
    }

    /// <summary>创建一代节点、虚拟网卡和数据泵；节点内部负责普通断线重连。</summary>
    /// <param name="cancellationToken">服务停止令牌。</param>
    /// <returns>当前运行代停止后完成的任务。</returns>
    private static async Task RunGenerationAsync(ClientManagementAgent management,
        CancellationToken cancellationToken)
    {
        ClientConfig config = ClientConfigStore.Load();
        if (config.AccessRevoked) throw new UnauthorizedAccessException("设备已被管理员吊销。");
        string clientId = string.IsNullOrEmpty(config.DeviceId) ? PersistentDeviceIdentity.GetOrCreate() : config.DeviceId;
        string policyFingerprint = ClientNetworkPolicy.Fingerprint(config);
        var networkPolicy = ClientNetworkPolicy.FromConfig(config);
        if (OperatingSystem.IsLinux() && config.NetworkMode != "veth") await LinuxVethDevice.CleanupDefaultAsync();
        IPEndPoint server = await ResolveAsync(config.Server, 49000, cancellationToken);
        IPAddress localAddress = ResolveLocalAddress(server);
        int resolveAttempt = 0;
        IPEndPoint lastResolvedServer = server;
        /// <summary>
        /// 执行Resolve Server For Connection操作。
        /// </summary>
        /// <param name="token">token参数。</param>
        /// <returns>操作结果。</returns>
        async Task<IPEndPoint> ResolveServerForConnectionAsync(CancellationToken token)
        {
            var candidates = config.CoordinatorServers.Length == 0 ? [config.Server] : config.CoordinatorServers;
            string selected = candidates[resolveAttempt++ % candidates.Length];
            IPEndPoint resolved = await ResolveAsync(selected, 49000, token,
                localAddress.AddressFamily, resolveAttempt).ConfigureAwait(false);
            bool changed = !resolved.Equals(lastResolvedServer);
            ClientLog.Write($"协调服务器 DNS 解析：{config.Server} -> {resolved}" +
                (changed ? $"（原地址 {lastResolvedServer} 已更换）" : ""));
            lastResolvedServer = resolved;
            return resolved;
        }
        int localPort = config.LocalPort == 0 ? FindAvailableDualProtocolPort(localAddress) : config.LocalPort;
        // UPnP is only an optional direct-connect enhancement. Coordinator registration
        // and the relay fallback must never wait for LAN device discovery or SOAP calls.
        await using ClientUpnpMapper.ClientUpnpLease? upnp = config.EnableUpnp
            ? ClientUpnpMapper.ClientUpnpLease.CreateMonitor(
                localAddress, localPort, config.UpnpLeaseSeconds) : null;
        using var keys = new PreSharedKeyProvider(SHA256.HashData(Encoding.UTF8.GetBytes(config.SharedSecret)));
        await using var node = new P2PNode(new P2PConnectionOptions
        {
            SessionId = config.Group,
            RegistrationCredential = config.DeviceToken,
            EnableCoordinatorRelay = false,
            RelayUrls = config.RelayUrls,
            RelayCredential = config.DeviceToken,
            RelayEncryptionKey = string.IsNullOrEmpty(config.DataSecret) ? null : Convert.FromBase64String(config.DataSecret),
            PeerId = clientId,
            KeepAliveInterval = TimeSpan.FromSeconds(10),
            LinkIdleTimeout = TimeSpan.FromSeconds(45),
            ShutdownTimeout = TimeSpan.FromSeconds(8),
            MaxLinksPerPeer = 6,
            MaximumHolePunchRounds = 12,
            HolePunchRetryInterval = TimeSpan.FromSeconds(4),
            UdpPunchTimeout = TimeSpan.FromSeconds(10),
            TcpPunchTimeout = TimeSpan.FromSeconds(8),
            UdpPublicPortFanout = config.UdpPortFanout,
            TcpPublicPortFanout = config.TcpPortFanout,
            EagerHolePunching = true,
            DirectLinkIdleTimeout = TimeSpan.FromMinutes(config.DirectIdleMinutes),
            DirectCandidateFilter = (peerVirtualAddress, candidate) =>
                IsDirectCandidateAllowed(config.RemoteSubnetRoutes, peerVirtualAddress, candidate.Address),
            AdvertisedUdpEndPoint = upnp?.UdpPublicEndPoint,
            AdvertisedTcpEndPoint = upnp?.TcpPublicEndPoint,
            ClientVersion = ClientRuntimeInfo.Version,
            ClientPlatform = string.IsNullOrWhiteSpace(config.Platform) ? ClientRuntimeInfo.Platform : config.Platform
        });
        node.Connected += () => { ClientRuntimeStateStore.Event("协调服务器连接成功"); ClientLog.Write("协调服务器连接成功。"); };
        node.Reconnecting += error => { ClientRuntimeStateStore.Event("协调连接中断，后台重连中"); ClientLog.Write($"协调连接中断：{error?.Message ?? "连接关闭"}；后台重连中。"); };
        node.TraversalStateChanged += value =>
        {
            ClientRuntimeStateStore.Event($"{value.Kind}：{value.PeerId}");
            ClientLog.Write($"打洞状态={value.Kind} 对端={value.PeerId} 轮次={value.AttemptNumber} {value.Detail}");
            management.Report(value);
            if (value.Kind == P2PTraversalEventKind.AttemptsExhausted)
                upnp?.RequestRebuild($"对端 {value.PeerId} 的全部直连尝试失败");
        };
        if (upnp is not null) upnp.MappingChanged += (udp, tcp) =>
        {
            node.Options.AdvertisedUdpEndPoint = udp;
            node.Options.AdvertisedTcpEndPoint = tcp;
            ClientLog.Write($"UPnP 公网候选发生变化：UDP={udp?.ToString() ?? "不可用"}，" +
                $"TCP={tcp?.ToString() ?? "不可用"}；映射继续维护，当前 VPN 会话保持在线。");
        };

        await node.StartAsync(ResolveServerForConnectionAsync, keys,
            new IPEndPoint(localAddress, localPort), cancellationToken);
        if (config.CoordinatorServers.Length < 2) _ = MonitorServerAddressAsync(config.Server, 49000, localAddress.AddressFamily,
            () => lastResolvedServer, node, cancellationToken);
        upnp?.StartRenewal(cancellationToken);
        IPAddress address = node.VirtualAddress ?? throw new InvalidDataException("服务端没有分配虚拟 IP。");
        int prefixLength = node.VirtualPrefixLength;
        if (prefixLength is < 8 or > 30) throw new InvalidDataException("服务端没有返回有效地址前缀。");
        await using IClientTunDevice tunDevice = config.NetworkMode == "proxy"
            ? new ProxyGatewayDevice(networkPolicy)
            : config.NetworkMode == "veth" ? await LinuxVethDevice.CreateAsync(address, prefixLength, P2PTunMultipathTunnel.RecommendedMtu, cancellationToken)
            : await ClientTunDevice.CreateAsync(config.AdapterName, address, prefixLength, P2PTunMultipathTunnel.RecommendedMtu, cancellationToken);
        if (config.NetworkMode != "proxy")
            await ClientGatewayManager.TryApplyAsync(config, address, prefixLength, tunDevice.Name, cancellationToken).ConfigureAwait(false);
        else if (OperatingSystem.IsLinux())
            await ClientGatewayManager.TryApplyAsync(new ClientConfig { GatewayMode = "local" }, address, prefixLength, tunDevice.Name, cancellationToken).ConfigureAwait(false);
        var router = new P2PIpv4PacketRouter();
        var knownRoutes = new Dictionary<ulong, IPAddress>();
        var knownSubnetRoutes = new Dictionary<string, InstalledSubnetRoute>(StringComparer.Ordinal);
        var subnetTranslator = new ClientSubnetPacketTranslator();
        await using P2PTunMultipathTunnel tunnel = node.CreateTunTunnel(tunDevice, router);
        tunnel.LocalIpv4Address = address;
        tunnel.RespondToIpv4EchoRequests = true;
        var ingress = new P2PVpn.Policy.VpnIngressGuard(subnetTranslator);
        tunnel.PacketTranslator = ingress;
        tunnel.InboundFilter = (packet, peerId) =>
        {
            var policy = Volatile.Read(ref networkPolicy);
            var peer = node.Peers.FirstOrDefault(p => p.NumericPeerId == peerId);
            return ingress.Allows(packet, peerId, peer?.VirtualAddress, address, policy);
        };
        tunnel.Start(cancellationToken);
        management.MarkPolicyApplied(config.NetworkPolicyRevision);
        ClientLog.Write($"客户端 ID={clientId}，服务器={server}，本地候选={localAddress}:{localPort}，" +
            $"虚拟地址={address}/{prefixLength}，UPnP={(upnp is null ? "未使用" : "已启用")}。");

        using var timer = new PeriodicTimer(TimeSpan.FromMilliseconds(500));
        int ticks = 0;
        while (await timer.WaitForNextTickAsync(cancellationToken))
        {
            if (ticks % 4 == 0)
            {
                var latest = ClientConfigStore.Load();
                if (PublicControlAgent.Fingerprint(latest) != PublicControlAgent.Fingerprint(config)) return;
                var fingerprint = ClientNetworkPolicy.Fingerprint(latest);
                if (latest.NetworkPolicyRevision != config.NetworkPolicyRevision || fingerprint != policyFingerprint)
                {
                    var nextPolicy = ClientNetworkPolicy.FromConfig(latest);
                    if (!networkPolicy.HasSameTopology(nextPolicy)) return;
                    nextPolicy.Validate();
                    Volatile.Write(ref networkPolicy, nextPolicy);
                    if (tunDevice is ProxyGatewayDevice proxy) proxy.UpdatePolicy(nextPolicy);
                    ClientNetworkPolicy.Apply(config, nextPolicy, latest.NetworkPolicyRevision);
                    policyFingerprint = fingerprint;
                    management.MarkPolicyApplied(latest.NetworkPolicyRevision);
                    ClientLog.Write($"网络配置版本 {latest.NetworkPolicyRevision} 已热更新，无需重连或重建网卡。");
                }
            }
            SynchronizeRoutes(router, knownRoutes, node.Peers);
            string[] activeSubnetCidrs = SynchronizeSubnetRoutes(router, subnetTranslator, knownSubnetRoutes,
                config.RemoteSubnetRoutes, node.Peers);
            await tunDevice.SynchronizePeerAddressesAsync(knownRoutes.Values.ToArray(), cancellationToken);
            await tunDevice.SynchronizeRemoteRoutesAsync(activeSubnetCidrs, cancellationToken);
            IPAddress? current = node.VirtualAddress;
            int currentPrefix = node.VirtualPrefixLength;
            if (current is not null && currentPrefix is >= 8 and <= 30 &&
                (!current.Equals(address) || currentPrefix != prefixLength))
            {
                await tunDevice.ReconfigureAsync(current, currentPrefix, cancellationToken);
                address = current;
                prefixLength = currentPrefix;
                tunnel.LocalIpv4Address = current;
                ClientLog.Write($"虚拟地址已经恢复为 {address}/{prefixLength}。");
            }
            if (++ticks % 60 == 0)
            {
                if (OperatingSystem.IsLinux() && config.NetworkMode != "proxy")
                    await ClientGatewayManager.TryApplyAsync(config, address, prefixLength, tunDevice.Name,
                        cancellationToken).ConfigureAwait(false);
                string transports = string.Join(',', node.Peers.Select(static peer =>
                    $"{peer.PeerId}:{(peer.DirectConnected ? peer.DirectTransport : "中继")}"));
                ClientLog.Write($"运行正常：在线={node.IsConnected}，虚拟IP={address}，" +
                    $"对端={node.Peers.Count}，链路={node.Session.LinkCount}，丢弃={tunnel.DroppedPackets}，路径=[{transports}]。");
            }
            if (ticks % 4 == 0)
                ClientRuntimeStateStore.Publish(node.IsConnected, clientId, config.Server,
                    address.ToString(), prefixLength, $"{localAddress}:{localPort}",
                    node.ServerLocalEndPoint?.ToString() ?? $"{localAddress}:{localPort}",
                    node.ServerRemoteEndPoint?.ToString() ?? lastResolvedServer.ToString(), node.Peers);
        }
    }

    /// <summary>
    /// 执行Resolve Local Address操作。
    /// </summary>
    /// <param name="server">server参数。</param>
    /// <returns>操作结果。</returns>
    private static IPAddress ResolveLocalAddress(IPEndPoint server)
    {
        using var socket = new Socket(server.AddressFamily, SocketType.Dgram, ProtocolType.Udp);
        socket.Connect(server);
        return ((IPEndPoint)socket.LocalEndPoint!).Address;
    }

    /// <summary>
    /// 执行Find Available Dual Protocol Port操作。
    /// </summary>
    /// <param name="localAddress">local Address参数。</param>
    /// <returns>操作结果。</returns>
    private static int FindAvailableDualProtocolPort(IPAddress localAddress)
    {
        for (int attempt = 0; attempt < 64; attempt++)
        {
            int port = RandomNumberGenerator.GetInt32(20_000, 60_000);
            try
            {
                using var udp = new Socket(localAddress.AddressFamily, SocketType.Dgram, ProtocolType.Udp);
                using var tcp = new Socket(localAddress.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
                udp.ExclusiveAddressUse = true;
                tcp.ExclusiveAddressUse = true;
                udp.Bind(new IPEndPoint(localAddress, port));
                tcp.Bind(new IPEndPoint(localAddress, port));
                return port;
            }
            catch (SocketException) { }
        }
        throw new IOException("无法找到可同时用于 UDP 和 TCP 的本地端口。");
    }

    /// <summary>把服务端发现的所有在线节点同步为虚拟 IPv4 主机路由。</summary>
    /// <param name="router">隧道 IPv4 路由器。</param>
    /// <param name="knownRoutes">当前已经安装的路由。</param>
    /// <param name="peers">服务端公布的在线对端。</param>
    private static void SynchronizeRoutes(P2PIpv4PacketRouter router,
        Dictionary<ulong, IPAddress> knownRoutes, IReadOnlyList<DiscoveredPeer> peers)
    {
        var online = new HashSet<ulong>();
        foreach (DiscoveredPeer peer in peers)
        {
            online.Add(peer.NumericPeerId);
            if (knownRoutes.TryGetValue(peer.NumericPeerId, out IPAddress? existing) &&
                existing.Equals(peer.VirtualAddress)) continue;
            if (existing is not null) router.RemoveRoute(existing);
            router.SetRoute(peer.VirtualAddress, peer.NumericPeerId);
            knownRoutes[peer.NumericPeerId] = peer.VirtualAddress;
        }
        foreach (KeyValuePair<ulong, IPAddress> route in knownRoutes.ToArray())
        {
            if (online.Contains(route.Key)) continue;
            router.RemoveRoute(route.Value);
            knownRoutes.Remove(route.Key);
        }
    }

    /// <summary>解析域名、IPv4、带端口主机名或方括号 IPv6 地址。</summary>
    /// <param name="value">用户配置的服务器地址。</param>
    /// <param name="defaultPort">地址没有端口时使用的默认端口。</param>
    /// <param name="cancellationToken">DNS 解析取消令牌。</param>
    /// <returns>优先使用可用 IPv6 的服务器终结点。</returns>
    private static async Task<IPEndPoint> ResolveAsync(string value, int defaultPort,
        CancellationToken cancellationToken, AddressFamily? preferredFamily = null, int addressOffset = 0)
    {
        (string host, int port) = ParseServerAddress(value, defaultPort);
        if (IPAddress.TryParse(host, out IPAddress? parsedAddress))
        {
            if (preferredFamily is not null && parsedAddress.AddressFamily != preferredFamily)
                throw new SocketException((int)SocketError.AddressFamilyNotSupported);
            return new IPEndPoint(parsedAddress, port);
        }
        IPAddress[] addresses = await Dns.GetHostAddressesAsync(host, cancellationToken);
        return ServerAddressSelector.Select(addresses, port, preferredFamily, addressOffset);
    }

    /// <summary>
    /// 执行Synchronize Subnet Routes操作。
    /// </summary>
    /// <param name="router">router参数。</param>
    /// <param name="translator">translator参数。</param>
    /// <param name="installed">installed参数。</param>
    /// <param name="configured">configured参数。</param>
    /// <param name="peers">peers参数。</param>
    /// <returns>操作结果。</returns>
    private static string[] SynchronizeSubnetRoutes(P2PIpv4PacketRouter router,
        ClientSubnetPacketTranslator translator,
        Dictionary<string, InstalledSubnetRoute> installed, IReadOnlyList<ClientSubnetRoute> configured,
        IReadOnlyList<DiscoveredPeer> peers)
    {
        var desired = new Dictionary<string, InstalledSubnetRoute>(StringComparer.Ordinal);
        foreach (ClientSubnetRoute route in configured.Where(static route => route.Enabled))
        {
            if (!ClientConfigStore.TryParseIpv4Cidr(route.Subnet, out IPAddress exposedNetwork, out int prefixLength) ||
                !IPAddress.TryParse(route.GatewayVirtualIp, out IPAddress? gateway)) continue;
            IPAddress destinationNetwork = exposedNetwork;
            if (!string.IsNullOrWhiteSpace(route.DestinationSubnet) &&
                !ClientConfigStore.TryParseIpv4Cidr(route.DestinationSubnet, out destinationNetwork, out _)) continue;
            DiscoveredPeer? peer = peers.FirstOrDefault(item => item.VirtualAddress.Equals(gateway));
            if (peer is null) continue;
            string cidr = $"{exposedNetwork}/{prefixLength}";
            desired[cidr] = new InstalledSubnetRoute(exposedNetwork, destinationNetwork,
                prefixLength, peer.NumericPeerId);
        }
        foreach ((string cidr, InstalledSubnetRoute existing) in installed.ToArray())
        {
            if (desired.TryGetValue(cidr, out InstalledSubnetRoute? replacement) && replacement == existing) continue;
            router.RemoveSubnetRoute(existing.ExposedNetwork, existing.PrefixLength);
            installed.Remove(cidr);
        }
        foreach ((string cidr, InstalledSubnetRoute route) in desired)
        {
            if (installed.ContainsKey(cidr)) continue;
            router.SetSubnetRoute(route.ExposedNetwork, route.PrefixLength, route.PeerId);
            installed[cidr] = route;
            ClientLog.Write($"Remote subnet route activated: {cidr} -> VPN peer {route.PeerId}.");
        }
        translator.ReplaceRules(desired.Values.Select(static route => new ClientSubnetTranslationRule(
            route.ExposedNetwork, route.DestinationNetwork, route.PrefixLength, route.PeerId)));
        return desired.Keys.ToArray();
    }

    /// <summary>
    /// 执行Is Direct Candidate Allowed操作。
    /// </summary>
    /// <param name="routes">routes参数。</param>
    /// <param name="peerVirtualAddress">peer Virtual Address参数。</param>
    /// <param name="candidateAddress">candidate Address参数。</param>
    /// <returns>操作结果。</returns>
    private static bool IsDirectCandidateAllowed(IReadOnlyList<ClientSubnetRoute> routes,
        IPAddress peerVirtualAddress, IPAddress candidateAddress)
    {
        if (peerVirtualAddress.AddressFamily != AddressFamily.InterNetwork ||
            candidateAddress.AddressFamily != AddressFamily.InterNetwork) return true;
        foreach (ClientSubnetRoute route in routes)
        {
            if (!route.Enabled || !IPAddress.TryParse(route.GatewayVirtualIp, out IPAddress? gateway) ||
                !gateway.Equals(peerVirtualAddress)) continue;
            if (IsInIpv4Cidr(candidateAddress, route.Subnet) ||
                (!string.IsNullOrWhiteSpace(route.DestinationSubnet) &&
                 IsInIpv4Cidr(candidateAddress, route.DestinationSubnet))) return false;
        }
        return true;
    }

    /// <summary>
    /// 执行Is In Ipv4 Cidr操作。
    /// </summary>
    /// <param name="address">网络地址。</param>
    /// <param name="cidr">cidr参数。</param>
    /// <returns>操作结果。</returns>
    private static bool IsInIpv4Cidr(IPAddress address, string cidr)
    {
        if (!ClientConfigStore.TryParseIpv4Cidr(cidr, out IPAddress network, out int prefixLength)) return false;
        byte[] addressBytes = address.GetAddressBytes();
        byte[] networkBytes = network.GetAddressBytes();
        int wholeBytes = prefixLength / 8;
        int remainingBits = prefixLength % 8;
        for (int index = 0; index < wholeBytes; index++)
            if (addressBytes[index] != networkBytes[index]) return false;
        if (remainingBits == 0) return true;
        int mask = 0xff << (8 - remainingBits);
        return (addressBytes[wholeBytes] & mask) == (networkBytes[wholeBytes] & mask);
    }

    /// <summary>
    /// 表示 Installed Subnet Route，并提供相关数据或行为。
    /// </summary>
    /// <param name="ExposedNetwork">Exposed Network参数。</param>
    /// <param name="DestinationNetwork">Destination Network参数。</param>
    /// <param name="PrefixLength">Prefix Length参数。</param>
    /// <param name="PeerId">Peer Id参数。</param>
    private sealed record InstalledSubnetRoute(IPAddress ExposedNetwork, IPAddress DestinationNetwork,
        int PrefixLength, ulong PeerId);

    /// <summary>
    /// 执行Parse Server Address操作。
    /// </summary>
    /// <param name="value">待处理的值。</param>
    /// <param name="defaultPort">default Port参数。</param>
    /// <returns>操作结果。</returns>
    private static (string Host, int Port) ParseServerAddress(string value, int defaultPort)
    {
        string host = value.Trim();
        int port = defaultPort;
        if (host.StartsWith('['))
        {
            int closing = host.IndexOf(']');
            if (closing < 2) throw new FormatException("IPv6 服务器地址格式无效。");
            string portText = closing + 1 < host.Length && host[closing + 1] == ':' ? host[(closing + 2)..] : "";
            if (portText.Length > 0) port = ParsePort(portText);
            host = host[1..closing];
        }
        else if (host.Count(static character => character == ':') == 1)
        {
            int separator = host.LastIndexOf(':');
            if (int.TryParse(host[(separator + 1)..], out int parsed))
            {
                port = ParsePort(parsed.ToString());
                host = host[..separator];
            }
        }
        if (host.Length == 0) throw new FormatException("服务器地址不能为空。");
        return (host, port);
    }

    /// <summary>
    /// 执行Monitor Server Address操作。
    /// </summary>
    /// <param name="value">待处理的值。</param>
    /// <param name="defaultPort">default Port参数。</param>
    /// <param name="family">family参数。</param>
    /// <param name="currentEndPoint">current End Point参数。</param>
    /// <param name="node">node参数。</param>
    /// <param name="cancellationToken">用于取消异步操作的令牌。</param>
    /// <returns>操作结果。</returns>
    private static async Task MonitorServerAddressAsync(string value, int defaultPort, AddressFamily family,
        Func<IPEndPoint> currentEndPoint, P2PNode node, CancellationToken cancellationToken)
    {
        (string host, int port) = ParseServerAddress(value, defaultPort);
        if (IPAddress.TryParse(host, out _)) return;
        using var timer = new PeriodicTimer(TimeSpan.FromMinutes(1));
        try
        {
            while (await timer.WaitForNextTickAsync(cancellationToken).ConfigureAwait(false))
            {
                try
                {
                    IPAddress[] addresses = await Dns.GetHostAddressesAsync(host, cancellationToken)
                        .ConfigureAwait(false);
                    IPEndPoint current = currentEndPoint();
                    bool stillPublished = current.Port == port && addresses.Any(address =>
                        address.AddressFamily == family && address.Equals(current.Address));
                    if (stillPublished) continue;
                    string published = string.Join(',', addresses.Where(address => address.AddressFamily == family));
                    ClientLog.Write($"DDNS 地址变化：当前协调服务器={current}，域名最新地址=[{published}]；主动重连。");
                    node.RequestReconnect("DDNS 记录已不再包含当前协调服务器地址。");
                }
                catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { break; }
                catch (Exception exception) { ClientLog.Write("DDNS 周期检查失败：" + exception.Message); }
            }
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { }
    }

    /// <summary>校验并解析 TCP/UDP 端口。</summary>
    /// <param name="value">十进制端口文本。</param>
    /// <returns>1 到 65535 的端口。</returns>
    private static int ParsePort(string value) => int.TryParse(value, out int port) && port is >= 1 and <= 65535
        ? port : throw new FormatException("服务器端口必须介于 1 到 65535。");
}
