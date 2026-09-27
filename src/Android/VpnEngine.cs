using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using Qcxt.Net.P2P;
using Qcxt.Net.P2P.Signaling;
using Qcxt.Net.P2P.Tunneling;
using Qcxt.Net.Quic.Security;

namespace P2PVpnAndroid;

internal sealed class VpnEngine(VpnTunnelService service)
{
    public async Task RunAsync(CancellationToken cancellationToken)
    {
        TimeSpan delay = TimeSpan.FromSeconds(2);
        while (!cancellationToken.IsCancellationRequested)
        {
            try
            {
                var profile = ProfileStore.Load(service);
                ProfileStore.Validate(profile);
                if (profile.AccessRevoked) throw new AccessRevokedException();
                var fresh = await ControlApi.RefreshAsync(profile, cancellationToken).ConfigureAwait(false);
                if (!ProfileStore.ReplaceIfCurrent(service, ControlApi.Fingerprint(profile), fresh)) continue;
                using var generation = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
                var sync = MonitorAsync(fresh, generation, cancellationToken);
                try { await RunGenerationAsync(fresh, generation.Token).ConfigureAwait(false); }
                catch (OperationCanceledException) when (generation.IsCancellationRequested && !cancellationToken.IsCancellationRequested) { }
                finally { generation.Cancel(); await sync.ConfigureAwait(false); }
                delay = TimeSpan.FromSeconds(2);
            }
            catch (AccessRevokedException)
            {
                var profile = ProfileStore.Load(service);
                if (profile.DeviceId.Length > 0) { profile.AccessRevoked = true; ProfileStore.Save(service, profile); }
                throw;
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { return; }
            catch (Exception ex)
            {
                VpnRuntimeState.Publish(new(true, false, "正在重连", "--", 0, ex.Message));
                service.UpdateNotification($"连接中断，{delay.TotalSeconds:F0} 秒后重试");
                await Task.Delay(delay, cancellationToken).ConfigureAwait(false);
                delay = TimeSpan.FromSeconds(Math.Min(30, delay.TotalSeconds * 2));
            }
        }
    }

    private async Task MonitorAsync(VpnProfile profile, CancellationTokenSource generation, CancellationToken stop)
    {
        var fingerprint = ControlApi.Fingerprint(profile);
        try
        {
            while (!generation.IsCancellationRequested)
            {
                await Task.Delay(TimeSpan.FromSeconds(15), generation.Token).ConfigureAwait(false);
                if (ControlApi.Fingerprint(ProfileStore.Load(service)) != fingerprint) { generation.Cancel(); return; }
                try
                {
                    var next = await ControlApi.RefreshAsync(profile, generation.Token).ConfigureAwait(false);
                    if (ControlApi.Fingerprint(next) == fingerprint) continue;
                    ProfileStore.ReplaceIfCurrent(service, fingerprint, next);
                    generation.Cancel(); return;
                }
                catch (AccessRevokedException)
                {
                    profile.AccessRevoked = true;
                    ProfileStore.ReplaceIfCurrent(service, fingerprint, profile);
                    generation.Cancel(); return;
                }
                catch (HttpRequestException) { /* Transport also re-authenticates; retry transient API outages. */ }
                catch (OperationCanceledException) when (!generation.IsCancellationRequested && !stop.IsCancellationRequested) { }
            }
        }
        catch (OperationCanceledException) when (generation.IsCancellationRequested) { }
        catch { generation.Cancel(); }
    }

    private async Task RunGenerationAsync(VpnProfile profile, CancellationToken cancellationToken)
    {
        var servers = profile.CoordinatorServers.Length > 0 ? profile.CoordinatorServers : [profile.Server];
        int serverOffset = 0;
        async Task<IPEndPoint> ResolveNext(CancellationToken ct, AddressFamily? family = null)
        {
            Exception? last = null;
            for (int i = 0; i < servers.Length; i++)
            {
                int offset = Interlocked.Increment(ref serverOffset) - 1;
                try { return await ResolveAsync(servers[offset % servers.Length], ct, family, offset / servers.Length).ConfigureAwait(false); }
                catch (SocketException ex) { last = ex; }
            }
            throw new IOException("无法解析协调节点地址。", last);
        }
        IPEndPoint firstServer = await ResolveNext(cancellationToken).ConfigureAwait(false);
        IPAddress localAddress = ResolveLocalAddress(firstServer);
        serverOffset = 0;
        int localPort = profile.LocalPort == 0 ? FindPort(localAddress) : profile.LocalPort;
        string clientId = profile.DeviceId;
        using var keys = new PreSharedKeyProvider(SHA256.HashData(Encoding.UTF8.GetBytes(profile.SharedSecret)));
        await using var node = new P2PNode(new P2PConnectionOptions
        {
            SessionId = profile.Group, PeerId = clientId,
            RegistrationCredential = profile.DeviceToken, EnableCoordinatorRelay = false,
            RelayUrls = profile.RelayUrls, RelayCredential = profile.DeviceToken,
            RelayEncryptionKey = Convert.FromBase64String(profile.DataSecret), KeepAliveInterval = TimeSpan.FromSeconds(10),
            LinkIdleTimeout = TimeSpan.FromSeconds(45), ShutdownTimeout = TimeSpan.FromSeconds(8), MaxLinksPerPeer = 6,
            MaximumHolePunchRounds = 12, HolePunchRetryInterval = TimeSpan.FromSeconds(4), UdpPunchTimeout = TimeSpan.FromSeconds(10),
            TcpPunchTimeout = TimeSpan.FromSeconds(8), UdpPublicPortFanout = 16, TcpPublicPortFanout = 16,
            EagerHolePunching = true, DirectLinkIdleTimeout = TimeSpan.FromMinutes(profile.DirectIdleMinutes),
            DirectCandidateFilter = (peer, candidate) => IsCandidateAllowed(profile.Routes, peer, candidate.Address),
            ClientVersion = "1.1.0", ClientPlatform = "android"
        });
        node.Connected += () => VpnRuntimeState.Publish(new(true, true, "已连接", node.VirtualAddress?.ToString() ?? "--", node.Peers.Count, profile.RelayUrls.Length > 0 ? "直连优先 · 独立中继备用" : "直连模式 · 当前未分配中继"));
        node.Reconnecting += ex => VpnRuntimeState.Publish(new(true, false, "协调服务器重连中", node.VirtualAddress?.ToString() ?? "--", node.Peers.Count, ex?.Message ?? "网络已变化"));
        node.TraversalStateChanged += value =>
        {
            string text = $"{value.PeerId}: {value.Kind}";
            VpnSnapshot old = VpnRuntimeState.Current;
            VpnRuntimeState.Publish(old with { Paths = text });
        };
        await node.StartAsync(ct => ResolveNext(ct, localAddress.AddressFamily), keys, new IPEndPoint(localAddress, localPort), cancellationToken).ConfigureAwait(false);
        IPAddress virtualIp = node.VirtualAddress ?? throw new InvalidDataException("服务端没有分配虚拟 IPv4 地址");
        int prefix = node.VirtualPrefixLength;
        if (prefix is < 8 or > 30) throw new InvalidDataException("服务端返回的虚拟网络前缀无效");
        using Android.OS.ParcelFileDescriptor descriptor = service.EstablishTunnel(virtualIp, prefix, profile.Routes);
        await using var tun = new AndroidTunDevice(descriptor);
        var router = new P2PIpv4PacketRouter();
        var translator = new SubnetPacketTranslator();
        var hostRoutes = new Dictionary<ulong, IPAddress>();
        var subnetRoutes = new Dictionary<string, InstalledRoute>(StringComparer.Ordinal);
        await using P2PTunMultipathTunnel tunnel = node.CreateTunTunnel(tun, router);
        var ingress = new P2PVpn.Policy.VpnIngressGuard(translator);
        var inboundPolicy = new P2PVpn.Policy.NetworkPolicy { GatewayMode = "local" };
        tunnel.InboundFilter = (packet, peerId) => ingress.Allows(packet, peerId,
            node.Peers.FirstOrDefault(p => p.NumericPeerId == peerId)?.VirtualAddress, virtualIp, inboundPolicy);
        tunnel.LocalIpv4Address = virtualIp; tunnel.RespondToIpv4EchoRequests = true; tunnel.PacketTranslator = ingress; tunnel.Start(cancellationToken);
        VpnRuntimeState.Publish(new(true, true, "已连接", $"{virtualIp}/{prefix}", node.Peers.Count, profile.RelayUrls.Length > 0 ? "直连优先 · 独立中继备用" : "直连模式 · 当前未分配中继"));
        service.UpdateNotification($"已连接 · {virtualIp}/{prefix}");
        using var timer = new PeriodicTimer(TimeSpan.FromMilliseconds(500)); int ticks = 0; int activeSubnetRoutes = 0;
        while (await timer.WaitForNextTickAsync(cancellationToken).ConfigureAwait(false))
        {
            SyncHosts(router, hostRoutes, node.Peers);
            activeSubnetRoutes = SyncSubnets(router, translator, subnetRoutes, profile.Routes, node.Peers);
            if (++ticks % 4 == 0)
            {
                string paths = string.Join(" · ", node.Peers.Select(x => $"{x.VirtualAddress}:{(x.DirectConnected ? x.DirectTransport : profile.RelayUrls.Length > 0 ? "独立中继/协商中" : "打洞中")}"));
                string routeState = profile.Routes.Count == 0 ? "" : $" · 子网出口 {activeSubnetRoutes}/{profile.Routes.Count} 已生效";
                VpnRuntimeState.Publish(new(true, node.IsConnected, node.IsConnected ? "已连接" : "正在重连", $"{virtualIp}/{prefix}", node.Peers.Count, (paths.Length == 0 ? "等待对端" : paths) + routeState));
            }
            if (ticks % 20 == 0)
            {
                IPEndPoint currentServer = await ResolveNext(cancellationToken).ConfigureAwait(false);
                IPAddress currentLocal = ResolveLocalAddress(currentServer);
                if (!currentLocal.Equals(localAddress)) throw new IOException("手机网络已切换，正在重新建立隧道");
            }
        }
    }

    private static void SyncHosts(P2PIpv4PacketRouter router, Dictionary<ulong, IPAddress> installed, IReadOnlyList<DiscoveredPeer> peers)
    {
        var online = new HashSet<ulong>();
        foreach (DiscoveredPeer peer in peers) { online.Add(peer.NumericPeerId); if (installed.TryGetValue(peer.NumericPeerId, out IPAddress? old) && old.Equals(peer.VirtualAddress)) continue; if (old is not null) router.RemoveRoute(old); router.SetRoute(peer.VirtualAddress, peer.NumericPeerId); installed[peer.NumericPeerId] = peer.VirtualAddress; }
        foreach ((ulong id, IPAddress address) in installed.Where(x => !online.Contains(x.Key)).ToArray()) { router.RemoveRoute(address); installed.Remove(id); }
    }

    private static int SyncSubnets(P2PIpv4PacketRouter router, SubnetPacketTranslator translator, Dictionary<string, InstalledRoute> installed, IReadOnlyList<SubnetRoute> configured, IReadOnlyList<DiscoveredPeer> peers)
    {
        var desired = new Dictionary<string, InstalledRoute>(StringComparer.Ordinal);
        foreach (SubnetRoute route in configured.Where(x => x.Enabled))
        {
            if (!ProfileStore.TryParseCidr(route.Subnet, out IPAddress exposed, out int prefix) || !ProfileStore.TryParseCidr(route.DestinationSubnet, out IPAddress destination, out _) || !IPAddress.TryParse(route.GatewayVirtualIp, out IPAddress? gateway)) continue;
            DiscoveredPeer? peer = peers.FirstOrDefault(x => x.VirtualAddress.Equals(gateway)); if (peer is null) continue;
            desired[$"{exposed}/{prefix}"] = new(exposed, destination, prefix, peer.NumericPeerId);
        }
        foreach ((string key, InstalledRoute old) in installed.ToArray()) if (!desired.TryGetValue(key, out InstalledRoute? next) || next != old) { router.RemoveSubnetRoute(old.Exposed, old.Prefix); installed.Remove(key); }
        foreach ((string key, InstalledRoute route) in desired) if (!installed.ContainsKey(key)) { router.SetSubnetRoute(route.Exposed, route.Prefix, route.PeerId); installed[key] = route; }
        translator.ReplaceRules(desired.Values.Select(x => new TranslationRule(x.Exposed, x.Destination, x.Prefix, x.PeerId)));
        return desired.Count;
    }

    private static bool IsCandidateAllowed(IReadOnlyList<SubnetRoute> routes, IPAddress peerVirtualIp, IPAddress candidate)
    {
        foreach (SubnetRoute route in routes.Where(x => x.Enabled && IPAddress.TryParse(x.GatewayVirtualIp, out IPAddress? gateway) && gateway.Equals(peerVirtualIp)))
            if (InCidr(candidate, route.Subnet) || InCidr(candidate, route.DestinationSubnet)) return false;
        return true;
    }
    private static bool InCidr(IPAddress address, string cidr)
    {
        if (address.AddressFamily != AddressFamily.InterNetwork || !ProfileStore.TryParseCidr(cidr, out IPAddress network, out int prefix)) return false;
        byte[] a = address.GetAddressBytes(), n = network.GetAddressBytes(); int whole = prefix / 8, bits = prefix % 8;
        for (int i = 0; i < whole; i++) if (a[i] != n[i]) return false; return bits == 0 || (a[whole] & (0xff << (8 - bits))) == (n[whole] & (0xff << (8 - bits)));
    }

    private static async Task<IPEndPoint> ResolveAsync(string value, CancellationToken ct, AddressFamily? family = null, int offset = 0)
    {
        (string host, int port) = ParseServer(value, 49000); IPAddress[] addresses = await Dns.GetHostAddressesAsync(host, ct).ConfigureAwait(false);
        return P2PVpnClient.ServerAddressSelector.Select(addresses, port, family, offset);
    }
    private static (string Host, int Port) ParseServer(string value, int defaultPort)
    {
        string text = value.Trim(); if (Uri.TryCreate("vpn://" + text, UriKind.Absolute, out Uri? uri) && !string.IsNullOrWhiteSpace(uri.Host)) return (uri.Host, uri.IsDefaultPort ? defaultPort : uri.Port);
        throw new FormatException("服务器地址格式无效");
    }
    private static IPAddress ResolveLocalAddress(IPEndPoint server) { using var socket = new Socket(server.AddressFamily, SocketType.Dgram, ProtocolType.Udp); socket.Connect(server); return ((IPEndPoint)socket.LocalEndPoint!).Address; }
    private static int FindPort(IPAddress local)
    {
        for (int i = 0; i < 64; i++) { int port = RandomNumberGenerator.GetInt32(20000, 60000); try { using var udp = new Socket(local.AddressFamily, SocketType.Dgram, ProtocolType.Udp); using var tcp = new Socket(local.AddressFamily, SocketType.Stream, ProtocolType.Tcp); udp.Bind(new IPEndPoint(local, port)); tcp.Bind(new IPEndPoint(local, port)); return port; } catch (SocketException) { } }
        throw new IOException("无法找到可用的本地端口");
    }
    private sealed record InstalledRoute(IPAddress Exposed, IPAddress Destination, int Prefix, ulong PeerId);
}
