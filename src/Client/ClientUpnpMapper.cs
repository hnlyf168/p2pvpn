using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Xml.Linq;

namespace P2PVpnClient;

/// <summary>Creates renewable IGD IPv4 mappings for the exact UDP/TCP port used by the P2P node.</summary>
internal static class ClientUpnpMapper
{
    /// <summary>
    /// 表示 Service Control，并提供相关数据或行为。
    /// </summary>
    /// <param name="ControlUri">Control Uri参数。</param>
    /// <param name="ServiceType">Service Type参数。</param>
    internal sealed record ServiceControl(Uri ControlUri, string ServiceType);
    /// <summary>
    /// 表示 Gateway，并提供相关数据或行为。
    /// </summary>
    /// <param name="Control">Control参数。</param>
    /// <param name="ExternalAddress">External Address参数。</param>
    /// <param name="Name">名称。</param>
    private sealed record Gateway(ServiceControl Control, IPAddress ExternalAddress, string Name);
    private static readonly HttpClient Http = new(new SocketsHttpHandler
    {
        ConnectTimeout = TimeSpan.FromSeconds(3),
        AllowAutoRedirect = false
    }) { Timeout = TimeSpan.FromSeconds(6) };

    /// <summary>
    /// 尝试Create。
    /// </summary>
    /// <param name="localAddress">local Address参数。</param>
    /// <param name="internalPort">internal Port参数。</param>
    /// <param name="leaseSeconds">lease Seconds参数。</param>
    /// <param name="cancellationToken">用于取消异步操作的令牌。</param>
    /// <returns>操作是否成功。</returns>
    internal static async Task<ClientUpnpLease?> TryCreateAsync(IPAddress localAddress, int internalPort,
        int leaseSeconds, CancellationToken cancellationToken)
    {
        if (localAddress.AddressFamily != AddressFamily.InterNetwork) return null;
        try
        {
            string[] locations = await DiscoverAsync(localAddress, cancellationToken).ConfigureAwait(false);
            Log($"UPnP SSDP 在网卡 {localAddress} 收到 {locations.Length} 个设备描述地址。");
            foreach (string location in locations)
            {
                Log($"检查 UPnP 设备：{location}");
                Gateway? gateway;
                try { gateway = await LoadGatewayAsync(location, cancellationToken).ConfigureAwait(false); }
                catch (Exception exception) { Log($"读取 UPnP 设备 {location} 失败：{exception.Message}"); continue; }
                if (gateway is null) { Log("该设备没有可用的 WANIPConnection/WANPPPConnection 控制地址。"); continue; }

                int? udpPort = await AddAvailableMappingAsync(gateway.Control, localAddress, internalPort,
                    "UDP", leaseSeconds, cancellationToken).ConfigureAwait(false);
                int? tcpPort = await AddAvailableMappingAsync(gateway.Control, localAddress, internalPort,
                    "TCP", leaseSeconds, cancellationToken).ConfigureAwait(false);
                if (udpPort is null && tcpPort is null) continue;

                var lease = new ClientUpnpLease(gateway.Control, gateway.ExternalAddress, localAddress,
                    internalPort, udpPort, tcpPort, leaseSeconds);
                Log($"UPnP 映射成功：路由器={gateway.Name}，UDP={lease.UdpPublicEndPoint?.ToString() ?? "不可用"}，" +
                    $"TCP={lease.TcpPublicEndPoint?.ToString() ?? "不可用"}，内网={localAddress}:{internalPort}。");
                return lease;
            }
            Log("UPnP 未发现可用 IGD 路由器或路由器拒绝创建映射，继续使用 STUN/服务器观察端点打洞。");
        }
        catch (Exception exception) when (exception is not OperationCanceledException)
        {
            Log($"UPnP 探测失败：{exception.Message}；继续使用普通打洞。");
        }
        return null;
    }

    /// <summary>
    /// 添加Available Mapping。
    /// </summary>
    /// <param name="control">control参数。</param>
    /// <param name="localAddress">local Address参数。</param>
    /// <param name="internalPort">internal Port参数。</param>
    /// <param name="protocol">protocol参数。</param>
    /// <param name="leaseSeconds">lease Seconds参数。</param>
    /// <param name="cancellationToken">用于取消异步操作的令牌。</param>
    /// <returns>操作结果。</returns>
    private static async Task<int?> AddAvailableMappingAsync(ServiceControl control, IPAddress localAddress,
        int internalPort, string protocol, int leaseSeconds, CancellationToken cancellationToken)
    {
        foreach (int externalPort in CandidatePorts(internalPort))
        {
            try
            {
                await AddMappingAsync(control, localAddress, internalPort, externalPort, protocol,
                    leaseSeconds, cancellationToken).ConfigureAwait(false);
                return externalPort;
            }
            catch (InvalidOperationException exception) when (IsConflict(exception)) { }
            catch (InvalidOperationException exception)
            {
                Log($"UPnP {protocol} {externalPort} 映射失败：{exception.Message}");
                return null;
            }
        }
        return null;
    }

    /// <summary>
    /// 执行Candidate Ports操作。
    /// </summary>
    /// <param name="preferred">preferred参数。</param>
    /// <returns>操作结果。</returns>
    private static IEnumerable<int> CandidatePorts(int preferred)
    {
        yield return preferred;
        for (int index = 0; index < 12; index++)
        {
            int candidate = RandomNumberGenerator.GetInt32(20_000, 65_000);
            if (candidate != preferred) yield return candidate;
        }
    }

    /// <summary>
    /// 添加Mapping。
    /// </summary>
    /// <param name="control">control参数。</param>
    /// <param name="localAddress">local Address参数。</param>
    /// <param name="internalPort">internal Port参数。</param>
    /// <param name="externalPort">external Port参数。</param>
    /// <param name="protocol">protocol参数。</param>
    /// <param name="leaseSeconds">lease Seconds参数。</param>
    /// <param name="cancellationToken">用于取消异步操作的令牌。</param>
    /// <returns>操作结果。</returns>
    internal static async Task AddMappingAsync(ServiceControl control, IPAddress localAddress,
        int internalPort, int externalPort, string protocol, int leaseSeconds,
        CancellationToken cancellationToken)
    {
        var arguments = new Dictionary<string, string>
        {
            ["NewRemoteHost"] = "",
            ["NewExternalPort"] = externalPort.ToString(),
            ["NewProtocol"] = protocol,
            ["NewInternalPort"] = internalPort.ToString(),
            ["NewInternalClient"] = localAddress.ToString(),
            ["NewEnabled"] = "1",
            ["NewPortMappingDescription"] = "Edge VPN",
            ["NewLeaseDuration"] = leaseSeconds.ToString()
        };
        try { await SoapAsync(control, "AddPortMapping", arguments, cancellationToken).ConfigureAwait(false); }
        catch (InvalidOperationException exception) when (leaseSeconds > 0 && IsError(exception, 725))
        {
            arguments["NewLeaseDuration"] = "0";
            await SoapAsync(control, "AddPortMapping", arguments, cancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// 执行Delete Mapping操作。
    /// </summary>
    /// <param name="control">control参数。</param>
    /// <param name="externalPort">external Port参数。</param>
    /// <param name="protocol">protocol参数。</param>
    /// <param name="cancellationToken">用于取消异步操作的令牌。</param>
    /// <returns>操作结果。</returns>
    internal static async Task DeleteMappingAsync(ServiceControl control, int externalPort, string protocol,
        CancellationToken cancellationToken)
    {
        try
        {
            await SoapAsync(control, "DeletePortMapping", new()
            {
                ["NewRemoteHost"] = "",
                ["NewExternalPort"] = externalPort.ToString(),
                ["NewProtocol"] = protocol
            }, cancellationToken).ConfigureAwait(false);
        }
        catch (InvalidOperationException exception) when (IsError(exception, 714)) { }
    }

    /// <summary>
    /// 执行Discover操作。
    /// </summary>
    /// <param name="localAddress">local Address参数。</param>
    /// <param name="cancellationToken">用于取消异步操作的令牌。</param>
    /// <returns>操作结果。</returns>
    private static async Task<string[]> DiscoverAsync(IPAddress localAddress, CancellationToken cancellationToken)
    {
        var locations = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        using var udp = new UdpClient(new IPEndPoint(localAddress, 0));
        udp.Client.SetSocketOption(SocketOptionLevel.IP, SocketOptionName.MulticastTimeToLive, 4);
        var destinations = new List<IPEndPoint> { new(IPAddress.Parse("239.255.255.250"), 1900) };
        IPAddress? gatewayAddress = FindGateway(localAddress);
        if (gatewayAddress is not null) destinations.Add(new IPEndPoint(gatewayAddress, 1900));
        foreach (string target in new[]
        {
            "urn:schemas-upnp-org:device:InternetGatewayDevice:2",
            "urn:schemas-upnp-org:device:InternetGatewayDevice:1",
            "upnp:rootdevice"
        })
        {
            byte[] request = Encoding.ASCII.GetBytes("M-SEARCH * HTTP/1.1\r\n" +
                "HOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 2\r\n" +
                $"ST: {target}\r\n\r\n");
            foreach (IPEndPoint destination in destinations)
                await udp.SendAsync(request, destination, cancellationToken).ConfigureAwait(false);
        }
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(TimeSpan.FromSeconds(3));
        while (!timeout.IsCancellationRequested)
        {
            try
            {
                UdpReceiveResult response = await udp.ReceiveAsync(timeout.Token).ConfigureAwait(false);
                string? location = Encoding.UTF8.GetString(response.Buffer).Split("\r\n")
                    .FirstOrDefault(static line => line.StartsWith("LOCATION:", StringComparison.OrdinalIgnoreCase))?
                    .Split(':', 2)[1].Trim();
                if (!string.IsNullOrWhiteSpace(location)) locations.Add(location);
            }
            catch (OperationCanceledException) { break; }
            catch (SocketException) { break; }
        }
        return locations.ToArray();
    }

    /// <summary>
    /// 执行Load Gateway操作。
    /// </summary>
    /// <param name="discoveryLocation">discovery Location参数。</param>
    /// <param name="cancellationToken">用于取消异步操作的令牌。</param>
    /// <returns>操作结果。</returns>
    private static async Task<Gateway?> LoadGatewayAsync(string discoveryLocation,
        CancellationToken cancellationToken)
    {
        if (!Uri.TryCreate(discoveryLocation, UriKind.Absolute, out Uri? location) ||
            location.Scheme is not ("http" or "https") || !IPAddress.TryParse(location.Host, out IPAddress? host) ||
            !IsPrivateOrLinkLocal(host)) return null;
        using HttpResponseMessage response = await Http.GetAsync(location, cancellationToken).ConfigureAwait(false);
        response.EnsureSuccessStatusCode();
        XDocument document = XDocument.Parse(await response.Content.ReadAsStringAsync(cancellationToken)
            .ConfigureAwait(false));
        var service = document.Descendants().Where(static element => element.Name.LocalName == "service")
            .Select(static element => new { Node = element, Type = ChildValue(element, "serviceType") })
            .Where(static item => item.Type.StartsWith("urn:schemas-upnp-org:service:WANIPConnection:", StringComparison.Ordinal) ||
                                  item.Type == "urn:schemas-upnp-org:service:WANPPPConnection:1")
            .OrderByDescending(static item => item.Type.Contains("WANIPConnection:2", StringComparison.Ordinal))
            .FirstOrDefault();
        if (service is null || !Uri.TryCreate(location, ChildValue(service.Node, "controlURL"), out Uri? controlUri) ||
            !string.Equals(controlUri.Host, location.Host, StringComparison.OrdinalIgnoreCase)) return null;
        var control = new ServiceControl(controlUri, service.Type);
        XDocument addressResult = await SoapAsync(control, "GetExternalIPAddress", [], cancellationToken)
            .ConfigureAwait(false);
        if (!IPAddress.TryParse(Value(addressResult, "NewExternalIPAddress"), out IPAddress? external) ||
            external.AddressFamily != AddressFamily.InterNetwork) return null;
        string name = Value(document, "friendlyName");
        return new Gateway(control, external, string.IsNullOrWhiteSpace(name) ? location.Host : name);
    }

    /// <summary>
    /// 执行Soap操作。
    /// </summary>
    /// <param name="control">control参数。</param>
    /// <param name="action">action参数。</param>
    /// <param name="arguments">arguments参数。</param>
    /// <param name="cancellationToken">用于取消异步操作的令牌。</param>
    /// <returns>操作结果。</returns>
    private static async Task<XDocument> SoapAsync(ServiceControl control, string action,
        Dictionary<string, string> arguments, CancellationToken cancellationToken)
    {
        XNamespace soap = "http://schemas.xmlsoap.org/soap/envelope/";
        XNamespace service = control.ServiceType;
        var envelope = new XDocument(new XElement(soap + "Envelope",
            new XAttribute(XNamespace.Xmlns + "s", soap.NamespaceName),
            new XAttribute(soap + "encodingStyle", "http://schemas.xmlsoap.org/soap/encoding/"),
            new XElement(soap + "Body", new XElement(service + action,
                arguments.Select(static item => new XElement(item.Key, item.Value))))));
        using var request = new HttpRequestMessage(HttpMethod.Post, control.ControlUri);
        request.Headers.TryAddWithoutValidation("SOAPAction", $"\"{control.ServiceType}#{action}\"");
        request.Content = new StringContent(envelope.ToString(SaveOptions.DisableFormatting), Encoding.UTF8, "text/xml");
        using HttpResponseMessage response = await Http.SendAsync(request, cancellationToken).ConfigureAwait(false);
        string xml = await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
        XDocument result;
        try { result = XDocument.Parse(xml); }
        catch { throw new InvalidOperationException($"UPnP 返回了无效响应（HTTP {(int)response.StatusCode}）。"); }
        if (!response.IsSuccessStatusCode)
        {
            string code = Value(result, "errorCode");
            string description = Value(result, "errorDescription");
            throw new InvalidOperationException($"UPnP 操作失败{(code.Length > 0 ? $"（{code}）" : "")}：" +
                (description.Length > 0 ? description : response.ReasonPhrase));
        }
        return result;
    }

    /// <summary>
    /// 执行Is Conflict操作。
    /// </summary>
    /// <param name="exception">发生的异常。</param>
    /// <returns>操作结果。</returns>
    private static bool IsConflict(Exception exception) => IsError(exception, 718);
    /// <summary>
    /// 执行Log操作。
    /// </summary>
    /// <param name="message">消息内容。</param>
    private static void Log(string message)
    {
        ClientLog.Write(message);
        if (Environment.UserInteractive) Console.WriteLine(message);
    }
    /// <summary>
    /// 执行Is Error操作。
    /// </summary>
    /// <param name="exception">发生的异常。</param>
    /// <param name="code">code参数。</param>
    /// <returns>操作结果。</returns>
    private static bool IsError(Exception exception, int code) =>
        exception.Message.Contains(code.ToString(), StringComparison.Ordinal);
    /// <summary>
    /// 执行Child Value操作。
    /// </summary>
    /// <param name="parent">parent参数。</param>
    /// <param name="name">名称。</param>
    /// <returns>操作结果。</returns>
    private static string ChildValue(XElement parent, string name) =>
        parent.Elements().FirstOrDefault(element => element.Name.LocalName == name)?.Value.Trim() ?? "";
    /// <summary>
    /// 执行Value操作。
    /// </summary>
    /// <param name="document">document参数。</param>
    /// <param name="name">名称。</param>
    /// <returns>操作结果。</returns>
    private static string Value(XContainer document, string name) =>
        document.Descendants().FirstOrDefault(element => element.Name.LocalName == name)?.Value.Trim() ?? "";
    /// <summary>
    /// 执行Is Private Or Link Local操作。
    /// </summary>
    /// <param name="address">网络地址。</param>
    /// <returns>操作结果。</returns>
    private static bool IsPrivateOrLinkLocal(IPAddress address)
    {
        if (IPAddress.IsLoopback(address)) return true;
        byte[] bytes = address.GetAddressBytes();
        return address.AddressFamily == AddressFamily.InterNetwork &&
            (bytes[0] == 10 || bytes[0] == 127 || bytes[0] == 192 && bytes[1] == 168 ||
             bytes[0] == 172 && bytes[1] is >= 16 and <= 31 || bytes[0] == 169 && bytes[1] == 254);
    }

    /// <summary>
    /// 执行Find Gateway操作。
    /// </summary>
    /// <param name="localAddress">local Address参数。</param>
    /// <returns>操作结果。</returns>
    private static IPAddress? FindGateway(IPAddress localAddress) => NetworkInterface.GetAllNetworkInterfaces()
        .Where(static adapter => adapter.OperationalStatus == OperationalStatus.Up)
        .Where(adapter => adapter.GetIPProperties().UnicastAddresses.Any(item => item.Address.Equals(localAddress)))
        .SelectMany(static adapter => adapter.GetIPProperties().GatewayAddresses)
        .Select(static item => item.Address)
        .FirstOrDefault(static address => address.AddressFamily == AddressFamily.InterNetwork);

    /// <summary>
/// 表示 Client Upnp Lease，并提供相关数据或行为。
/// </summary>
internal sealed class ClientUpnpLease : IAsyncDisposable
    {
        private ServiceControl? _control;
        private readonly IPAddress _localAddress;
        private readonly int _internalPort;
        private readonly int _leaseSeconds;
        private IPEndPoint? _udpPublicEndPoint;
        private IPEndPoint? _tcpPublicEndPoint;
        private int _forceRebuild;
        private long _lastRebuildRequestTicks;
        private CancellationTokenSource? _renewalLifetime;
        private Task? _renewalTask;

        /// <summary>
        /// 初始化 <see cref="ClientUpnpLease"/> 类的新实例。
        /// </summary>
        /// <param name="control">control参数。</param>
        /// <param name="externalAddress">external Address参数。</param>
        /// <param name="localAddress">local Address参数。</param>
        /// <param name="internalPort">internal Port参数。</param>
        /// <param name="udpPort">udp Port参数。</param>
        /// <param name="tcpPort">tcp Port参数。</param>
        /// <param name="leaseSeconds">lease Seconds参数。</param>
        internal ClientUpnpLease(ServiceControl control, IPAddress externalAddress, IPAddress localAddress,
            int internalPort, int? udpPort, int? tcpPort, int leaseSeconds)
        {
            _control = control;
            _localAddress = localAddress;
            _internalPort = internalPort;
            _leaseSeconds = leaseSeconds;
            _udpPublicEndPoint = udpPort is null ? null : new IPEndPoint(externalAddress, udpPort.Value);
            _tcpPublicEndPoint = tcpPort is null ? null : new IPEndPoint(externalAddress, tcpPort.Value);
        }

        /// <summary>
        /// 初始化 <see cref="ClientUpnpLease"/> 类的新实例。
        /// </summary>
        /// <param name="localAddress">local Address参数。</param>
        /// <param name="internalPort">internal Port参数。</param>
        /// <param name="leaseSeconds">lease Seconds参数。</param>
        private ClientUpnpLease(IPAddress localAddress, int internalPort, int leaseSeconds)
        {
            _localAddress = localAddress;
            _internalPort = internalPort;
            _leaseSeconds = leaseSeconds;
        }

        /// <summary>
        /// 创建Monitor。
        /// </summary>
        /// <param name="localAddress">local Address参数。</param>
        /// <param name="internalPort">internal Port参数。</param>
        /// <param name="leaseSeconds">lease Seconds参数。</param>
        /// <returns>操作结果。</returns>
        internal static ClientUpnpLease CreateMonitor(IPAddress localAddress, int internalPort, int leaseSeconds) =>
            new(localAddress, internalPort, leaseSeconds);

        /// <summary>
        /// 获取或设置Udp Public End Point。
        /// </summary>
        /// <returns>Udp Public End Point。</returns>
        internal IPEndPoint? UdpPublicEndPoint => Volatile.Read(ref _udpPublicEndPoint);
        /// <summary>
        /// 获取或设置Tcp Public End Point。
        /// </summary>
        /// <returns>Tcp Public End Point。</returns>
        internal IPEndPoint? TcpPublicEndPoint => Volatile.Read(ref _tcpPublicEndPoint);
        internal event Action<IPEndPoint?, IPEndPoint?>? MappingChanged;

        /// <summary>
        /// 执行Request Rebuild操作。
        /// </summary>
        /// <param name="reason">reason参数。</param>
        internal void RequestRebuild(string reason)
        {
            long now = Environment.TickCount64;
            long previous = Interlocked.Read(ref _lastRebuildRequestTicks);
            if (previous != 0 && now - previous < TimeSpan.FromMinutes(5).TotalMilliseconds) return;
            Interlocked.Exchange(ref _lastRebuildRequestTicks, now);
            Interlocked.Exchange(ref _forceRebuild, 1);
            Log($"检测到 UPnP 公网候选可能不可达：{reason}；将在本轮巡检中强制重新映射。");
        }

        /// <summary>
        /// 执行Start Renewal操作。
        /// </summary>
        /// <param name="cancellationToken">用于取消异步操作的令牌。</param>
        internal void StartRenewal(CancellationToken cancellationToken)
        {
            _renewalLifetime = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            _renewalTask = RenewLoopAsync(_renewalLifetime.Token);
        }

        /// <summary>
        /// 执行Renew Loop操作。
        /// </summary>
        /// <param name="cancellationToken">用于取消异步操作的令牌。</param>
        /// <returns>操作结果。</returns>
        private async Task RenewLoopAsync(CancellationToken cancellationToken)
        {
            try
            {
                while (!cancellationToken.IsCancellationRequested)
                {
                    await Task.Delay(TimeSpan.FromSeconds(_control is null ? 15 : Math.Max(120, _leaseSeconds / 2)),
                        cancellationToken).ConfigureAwait(false);
                    try
                    {
                        if (Interlocked.Exchange(ref _forceRebuild, 0) != 0)
                        {
                            _control = null;
                            ClearMappingCandidates();
                            await RecoverAsync(cancellationToken).ConfigureAwait(false);
                        }
                        else await RefreshAsync(cancellationToken).ConfigureAwait(false);
                    }
                    catch (Exception exception) when (exception is not OperationCanceledException)
                    {
                        Log($"UPnP 映射检查或续租失败：{exception.Message}；正在重新发现路由器并创建映射。");
                        _control = null;
                        ClearMappingCandidates();
                        try { await RecoverAsync(cancellationToken).ConfigureAwait(false); }
                        catch (Exception recoveryException) when (recoveryException is not OperationCanceledException)
                        { Log($"UPnP 映射重建失败：{recoveryException.Message}；稍后自动重试。"); }
                    }
                }
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { }
        }

        /// <summary>
        /// 执行Refresh操作。
        /// </summary>
        /// <param name="cancellationToken">用于取消异步操作的令牌。</param>
        /// <returns>操作结果。</returns>
        private async Task RefreshAsync(CancellationToken cancellationToken)
        {
            ServiceControl control = _control ?? throw new InvalidOperationException("需要重新发现 UPnP 路由器。");
            IPEndPoint? udp = UdpPublicEndPoint;
            IPEndPoint? tcp = TcpPublicEndPoint;
            if (udp is not null)
                await AddMappingAsync(control, _localAddress, _internalPort, udp.Port,
                    "UDP", _leaseSeconds, cancellationToken).ConfigureAwait(false);
            if (tcp is not null)
                await AddMappingAsync(control, _localAddress, _internalPort, tcp.Port,
                    "TCP", _leaseSeconds, cancellationToken).ConfigureAwait(false);
            XDocument addressResult = await SoapAsync(control, "GetExternalIPAddress", [], cancellationToken)
                .ConfigureAwait(false);
            if (!IPAddress.TryParse(Value(addressResult, "NewExternalIPAddress"), out IPAddress? external) ||
                !IsUsableExternalAddress(external))
                throw new InvalidOperationException("UPnP 路由器没有返回有效公网 IPv4 地址。");
            ApplyMapping(control, external, udp?.Port, tcp?.Port);
            Log("UPnP VPN 映射与公网地址检查完成，租约已续期。");
        }

        /// <summary>
        /// 执行Recover操作。
        /// </summary>
        /// <param name="cancellationToken">用于取消异步操作的令牌。</param>
        /// <returns>操作结果。</returns>
        private async Task RecoverAsync(CancellationToken cancellationToken)
        {
            string[] locations = await DiscoverAsync(_localAddress, cancellationToken).ConfigureAwait(false);
            foreach (string location in locations)
            {
                Gateway? gateway;
                try { gateway = await LoadGatewayAsync(location, cancellationToken).ConfigureAwait(false); }
                catch { continue; }
                if (gateway is null) continue;
                int? udpPort = await AddAvailableMappingAsync(gateway.Control, _localAddress, _internalPort,
                    "UDP", _leaseSeconds, cancellationToken).ConfigureAwait(false);
                int? tcpPort = await AddAvailableMappingAsync(gateway.Control, _localAddress, _internalPort,
                    "TCP", _leaseSeconds, cancellationToken).ConfigureAwait(false);
                if (udpPort is null && tcpPort is null) continue;
                ApplyMapping(gateway.Control, gateway.ExternalAddress, udpPort, tcpPort);
                Log($"UPnP 映射已自动重建：路由器={gateway.Name}，UDP={UdpPublicEndPoint?.ToString() ?? "不可用"}，" +
                    $"TCP={TcpPublicEndPoint?.ToString() ?? "不可用"}。");
                return;
            }
            throw new InvalidOperationException("没有发现可重新创建端口映射的 UPnP IGD 路由器。");
        }

        /// <summary>
        /// 执行Apply Mapping操作。
        /// </summary>
        /// <param name="control">control参数。</param>
        /// <param name="externalAddress">external Address参数。</param>
        /// <param name="udpPort">udp Port参数。</param>
        /// <param name="tcpPort">tcp Port参数。</param>
        private void ApplyMapping(ServiceControl control, IPAddress externalAddress, int? udpPort, int? tcpPort)
        {
            if (!IsUsableExternalAddress(externalAddress))
                throw new InvalidOperationException("UPnP returned an unusable external IPv4 address.");
            IPEndPoint? oldUdp = UdpPublicEndPoint;
            IPEndPoint? oldTcp = TcpPublicEndPoint;
            IPEndPoint? newUdp = udpPort is null ? null : new IPEndPoint(externalAddress, udpPort.Value);
            IPEndPoint? newTcp = tcpPort is null ? null : new IPEndPoint(externalAddress, tcpPort.Value);
            _control = control;
            Volatile.Write(ref _udpPublicEndPoint, newUdp);
            Volatile.Write(ref _tcpPublicEndPoint, newTcp);
            if (!Equals(oldUdp, newUdp) || !Equals(oldTcp, newTcp)) MappingChanged?.Invoke(newUdp, newTcp);
        }

        /// <summary>
        /// 执行Clear Mapping Candidates操作。
        /// </summary>
        private void ClearMappingCandidates()
        {
            IPEndPoint? oldUdp = UdpPublicEndPoint;
            IPEndPoint? oldTcp = TcpPublicEndPoint;
            Volatile.Write(ref _udpPublicEndPoint, null);
            Volatile.Write(ref _tcpPublicEndPoint, null);
            if (oldUdp is not null || oldTcp is not null) MappingChanged?.Invoke(null, null);
        }

        /// <summary>
        /// 执行Is Usable External Address操作。
        /// </summary>
        /// <param name="address">网络地址。</param>
        /// <returns>操作结果。</returns>
        private static bool IsUsableExternalAddress(IPAddress address)
        {
            if (address.AddressFamily != AddressFamily.InterNetwork || address.Equals(IPAddress.Any) ||
                address.Equals(IPAddress.None) || IPAddress.IsLoopback(address)) return false;
            byte first = address.GetAddressBytes()[0];
            return first is not (0 or >= 224);
        }

        /// <summary>
        /// 执行Dispose操作。
        /// </summary>
        /// <returns>操作结果。</returns>
        public async ValueTask DisposeAsync()
        {
            if (_renewalLifetime is not null) await _renewalLifetime.CancelAsync().ConfigureAwait(false);
            if (_renewalTask is not null) try { await _renewalTask.ConfigureAwait(false); } catch { }
            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(3));
            ServiceControl? control = _control;
            if (control is not null && UdpPublicEndPoint is not null)
                try { await DeleteMappingAsync(control, UdpPublicEndPoint.Port, "UDP", timeout.Token).ConfigureAwait(false); } catch { }
            if (control is not null && TcpPublicEndPoint is not null)
                try { await DeleteMappingAsync(control, TcpPublicEndPoint.Port, "TCP", timeout.Token).ConfigureAwait(false); } catch { }
            _renewalLifetime?.Dispose();
        }
    }
}
