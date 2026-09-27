using Qcxt.Net.P2P.Protocol;

namespace Qcxt.Net.P2P.Signaling;

/// <summary>为协调服务器提供可持久化的虚拟 IPv4 租约。</summary>
public interface IP2PVirtualAddressLeaseProvider
{
    /// <summary>获取指定稳定客户端在逻辑会话中的固定虚拟地址。</summary>
    /// <param name="sessionId">客户端提交的逻辑会话名称。</param>
    /// <param name="peerId">客户端提交的稳定设备标识。</param>
    /// <param name="networkAddress">服务器配置的 IPv4 网络地址。</param>
    /// <param name="prefixLength">服务器配置的网络前缀长度。</param>
    /// <returns>位于配置网段内且不与其他客户端冲突的主机地址。</returns>
    IPAddress Acquire(string sessionId, string peerId, IPAddress networkAddress, int prefixLength);
}

/// <summary>描述管理程序可安全读取的一份在线 P2P 客户端快照。</summary>
/// <param name="SessionId">逻辑会话名称。</param>
/// <param name="PeerId">稳定设备标识。</param>
/// <param name="NumericPeerId">用于线路寻址的数字标识。</param>
/// <param name="VirtualAddress">服务器分配的虚拟 IPv4 地址。</param>
/// <param name="PublicEndPoint">服务器观察到的公网 UDP 端点。</param>
/// <param name="TcpPublicEndPoint">服务器观察到的公网 TCP 端点。</param>
/// <param name="ConnectedAt">本代连接建立时间。</param>
/// <param name="ClientVersion">客户端上报的软件版本。</param>
/// <param name="ClientPlatform">客户端上报的运行平台。</param>
public sealed record P2PConnectedClient(string SessionId, string PeerId, ulong NumericPeerId,
    IPAddress VirtualAddress, IPEndPoint PublicEndPoint, IPEndPoint? TcpPublicEndPoint,
    DateTimeOffset ConnectedAt, string ClientVersion, string ClientPlatform);

/// <summary>描述一对客户端实际经过服务器转发的中继兜底连接统计。</summary>
/// <param name="GroupId">隔离分组。</param>
/// <param name="FirstPeerId">第一个稳定客户端 ID。</param>
/// <param name="SecondPeerId">第二个稳定客户端 ID。</param>
/// <param name="FirstActivityAt">首次实际中继时间。</param>
/// <param name="LastActivityAt">最近一次实际中继时间。</param>
/// <param name="ReliablePackets">可靠中继包数。</param>
/// <param name="ReliableBytes">可靠中继有效负载字节数。</param>
/// <param name="DatagramPackets">数据报中继包数。</param>
/// <param name="DatagramBytes">数据报中继有效负载字节数。</param>
public sealed record P2PRelayConnection(string GroupId, string FirstPeerId, string SecondPeerId,
    DateTimeOffset FirstActivityAt, DateTimeOffset LastActivityAt, long ReliablePackets,
    long ReliableBytes, long DatagramPackets, long DatagramBytes);

/// <summary>配置已认证的会合、信令和中转服务器。</summary>
public sealed class P2PServerOptions
{
    /// <summary>Explicit opt-in for legacy data forwarding. Public coordinators always leave this false.</summary>
    public bool EnableRelay { get; init; }
    /// <summary>Authorizes a network/group, device ID and credential. Rechecked on every control message.</summary>
    public Func<string, string, string, bool>? AuthorizeRegistration { get; init; }

    /// <summary>获取或设置在所需全部接口上监听的 UDP 端点。</summary>
    public required IPEndPoint ListenEndPoint { get; init; }
    /// <summary>获取或设置与授权客户端共享的 QUIC 密钥提供程序。</summary>
    public required IQuicKeyProvider KeyProvider { get; init; }
    /// <summary>获取或设置最大已连接客户端数量。</summary>
    public int MaximumClients { get; init; } = 100_000;
    /// <summary>获取或设置单个会话中的最大客户端数量。</summary>
    public int MaximumPeersPerSession { get; init; } = 4096;
    /// <summary>获取或设置 QUIC UDP 载荷长度。</summary>
    public int MaximumUdpPayloadSize { get; init; } = 1400;
    /// <summary>获取或设置操作系统套接字缓冲区大小。</summary>
    public int SocketBufferSize { get; init; } = 16 * 1024 * 1024;
    /// <summary>获取或设置有界关闭超时时间。</summary>
    public TimeSpan ShutdownTimeout { get; init; } = TimeSpan.FromSeconds(10);
    /// <summary>获取或设置每个逻辑会话独立共享的 IPv4 网段。</summary>
    public IPAddress VirtualNetworkAddress { get; init; } = IPAddress.Parse("10.77.0.0");
    /// <summary>获取或设置客户端租约使用的 IPv4 前缀长度。</summary>
    public int VirtualNetworkPrefixLength { get; init; } = 16;
    /// <summary>获取或设置可选的持久租约提供器；为空时使用进程内临时租约池。</summary>
    public IP2PVirtualAddressLeaseProvider? VirtualAddressLeaseProvider { get; init; }
    /// <summary>获取或设置是否在与 QUIC 相同的端口上启用 TCP 公网映射登记。</summary>
    public bool EnableTcpRendezvous { get; init; } = true;
    /// <summary>获取或设置 TCP 会合监听的积压连接上限。</summary>
    public int TcpListenBacklog { get; init; } = 4096;
    /// <summary>获取或设置服务器等待客户端完成 TCP 公网映射登记的最长时间。</summary>
    public TimeSpan TcpObservationTimeout { get; init; } = TimeSpan.FromSeconds(3);
    /// <summary>获取或设置无活动中继统计的保留时间。</summary>
    public TimeSpan RelayStatisticsRetention { get; init; } = TimeSpan.FromHours(24);
    /// <summary>获取或设置内存中最多保留的中继连接统计数量。</summary>
    public int MaximumRelayStatistics { get; init; } = 100_000;

    /// <summary>校验所有公开服务器限制。</summary>
    public void Validate()
    {
        ArgumentNullException.ThrowIfNull(ListenEndPoint);
        ArgumentNullException.ThrowIfNull(KeyProvider);
        if (MaximumClients is < 1 or > 10_000_000) throw new ArgumentOutOfRangeException(nameof(MaximumClients));
        if (MaximumPeersPerSession is < 2 or > 1_000_000) throw new ArgumentOutOfRangeException(nameof(MaximumPeersPerSession));
        if (MaximumUdpPayloadSize is < 1200 or > 65_527) throw new ArgumentOutOfRangeException(nameof(MaximumUdpPayloadSize));
        if (SocketBufferSize < 64 * 1024) throw new ArgumentOutOfRangeException(nameof(SocketBufferSize));
        if (ShutdownTimeout <= TimeSpan.Zero) throw new ArgumentOutOfRangeException(nameof(ShutdownTimeout));
        if (TcpListenBacklog is < 16 or > 1_000_000) throw new ArgumentOutOfRangeException(nameof(TcpListenBacklog));
        if (TcpObservationTimeout < TimeSpan.FromMilliseconds(200) || TcpObservationTimeout > TimeSpan.FromMinutes(1))
            throw new ArgumentOutOfRangeException(nameof(TcpObservationTimeout));
        if (RelayStatisticsRetention < TimeSpan.FromMinutes(1) || RelayStatisticsRetention > TimeSpan.FromDays(30))
            throw new ArgumentOutOfRangeException(nameof(RelayStatisticsRetention));
        if (MaximumRelayStatistics is < 100 or > 10_000_000)
            throw new ArgumentOutOfRangeException(nameof(MaximumRelayStatistics));
        ArgumentNullException.ThrowIfNull(VirtualNetworkAddress);
        if (VirtualNetworkAddress.AddressFamily != AddressFamily.InterNetwork)
            throw new ArgumentException("虚拟网络必须使用 IPv4。", nameof(VirtualNetworkAddress));
        if (VirtualNetworkPrefixLength is < 8 or > 30)
            throw new ArgumentOutOfRangeException(nameof(VirtualNetworkPrefixLength));
        uint address = BinaryPrimitives.ReadUInt32BigEndian(VirtualNetworkAddress.GetAddressBytes());
        uint mask = uint.MaxValue << (32 - VirtualNetworkPrefixLength);
        if ((address & ~mask) != 0)
            throw new ArgumentException("虚拟网络地址必须与其前缀边界对齐。", nameof(VirtualNetworkAddress));
        long availableHosts = (1L << (32 - VirtualNetworkPrefixLength)) - 2;
        if (MaximumPeersPerSession > availableHosts)
            throw new ArgumentOutOfRangeException(nameof(MaximumPeersPerSession),
                "对端数量上限超过已配置虚拟 IPv4 网络的容量。");
    }
}

/// <summary>运行支持 IPv4/IPv6 的已认证对端发现、UDP/TCP 双向打洞协调和自动 QUIC 中转。</summary>
public sealed class P2PSignalingServer : IAsyncDisposable
{
    private readonly P2PServerOptions _options;
    private readonly ConcurrentDictionary<RegistrationKey, ClientRegistration> _clients = new();
    private readonly ConcurrentDictionary<PairKey, byte[]> _pairTokens = new();
    private readonly ConcurrentDictionary<ulong, SessionLeasePool> _leasePools = new();
    private readonly ConcurrentDictionary<long, Task> _clientTasks = new();
    private readonly ConcurrentDictionary<P2PTcpObservationKey, ClientRegistration> _tcpObservations = new();
    private readonly ConcurrentDictionary<RelayConnectionKey, RelayConnectionStatistics> _relayConnections = new();
    private readonly CancellationTokenSource _lifetime = new();
    private Socket? _socket;
    private QuicSharedUdpEndpoint? _endpoint;
    private Task? _acceptTask;
    private Socket? _tcpListener;
    private Task? _tcpAcceptTask;
    private CancellationTokenSource? _runLifetime;
    private long _taskId;
    private int _started;
    private int _disposed;
    private long _lastRelayPruneAt = Environment.TickCount64;

    /// <summary>创建具有显式认证及有界资源限制的服务器。</summary>
    /// <param name="options">服务器选项。</param>
    public P2PSignalingServer(P2PServerOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        options.Validate();
        _options = options;
    }

    /// <summary>获取当前已注册客户端数量。</summary>
    public int ClientCount => _clients.Count;
    /// <summary>获取当前在线客户端的不可变快照。</summary>
    public IReadOnlyList<P2PConnectedClient> Clients => _clients.Values
        .Select(static client => client.CreateSnapshot()).ToArray();
    /// <summary>客户端成功上线、被替换或离线后触发；订阅方不得执行阻塞操作。</summary>
    public event Action? ClientsChanged;
    /// <summary>发现新的实际中继兜底连接或清理旧统计后触发。</summary>
    public event Action? RelayConnectionsChanged;
    /// <summary>获取保留期内全部实际中继兜底连接的最近优先快照。</summary>
    public IReadOnlyList<P2PRelayConnection> RelayConnections
    {
        get
        {
            MaybePruneRelayStatistics();
            return _relayConnections.Values.Select(static value => value.CreateSnapshot())
                .OrderByDescending(static value => value.LastActivityAt).ToArray();
        }
    }
    /// <summary>获取最近一分钟内有实际转发流量的中继连接数。</summary>
    public int ActiveRelayConnectionCount
    {
        get
        {
            MaybePruneRelayStatistics();
            long threshold = DateTimeOffset.UtcNow.Subtract(TimeSpan.FromMinutes(1)).UtcTicks;
            return _relayConnections.Values.Count(value => value.LastActivityTicks >= threshold);
        }
    }
    /// <summary>获取保留期内的中继连接总数。</summary>
    public int RelayConnectionCount { get { MaybePruneRelayStatistics(); return _relayConnections.Count; } }
    /// <summary>获取启动后实际绑定的 UDP 端点。</summary>
    public IPEndPoint? LocalEndPoint => _endpoint?.LocalEndPoint;
    /// <summary>获取启动后实际绑定的 TCP 会合端点。</summary>
    public IPEndPoint? LocalTcpEndPoint => _tcpListener?.LocalEndPoint as IPEndPoint;

    /// <summary>绑定 UDP 套接字并开始接受 QUIC 客户端。</summary>
    /// <param name="cancellationToken">可选的外部服务器生命周期取消标记。</param>
    /// <returns>绑定成功后立即结束的异步操作。</returns>
    public Task StartAsync(CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) != 0, this);
        if (Interlocked.Exchange(ref _started, 1) != 0) throw new InvalidOperationException("P2P 服务器已经启动。");
        _runLifetime = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, _lifetime.Token);
        _socket = new Socket(_options.ListenEndPoint.AddressFamily, SocketType.Dgram, ProtocolType.Udp)
        {
            ReceiveBufferSize = _options.SocketBufferSize,
            SendBufferSize = _options.SocketBufferSize
        };
        if (_socket.AddressFamily == AddressFamily.InterNetworkV6) _socket.DualMode = true;
        DisableUdpConnectionReset(_socket);
        _socket.Bind(_options.ListenEndPoint);
        _endpoint = new QuicSharedUdpEndpoint(_socket, CreateQuicServerOptions(), ownsSocket: true);
        _acceptTask = AcceptLoopAsync(_runLifetime.Token);
        if (_options.EnableTcpRendezvous)
        {
            IPEndPoint udpBound = (IPEndPoint)_socket.LocalEndPoint!;
            _tcpListener = new Socket(udpBound.AddressFamily, SocketType.Stream, ProtocolType.Tcp)
            {
                NoDelay = true,
                ExclusiveAddressUse = true
            };
            if (_tcpListener.AddressFamily == AddressFamily.InterNetworkV6) _tcpListener.DualMode = true;
            _tcpListener.Bind(new IPEndPoint(_options.ListenEndPoint.Address, udpBound.Port));
            _tcpListener.Listen(_options.TcpListenBacklog);
            _tcpAcceptTask = TcpAcceptLoopAsync(_runLifetime.Token);
        }
        return Task.CompletedTask;
    }

    /// <summary>创建共享服务器套接字上所有客户端使用的 QUIC 限制。</summary>
    /// <returns>已校验的 QUIC 服务器选项。</returns>
    private QuicServerOptions CreateQuicServerOptions() => new()
    {
        ListenEndPoint = _options.ListenEndPoint,
        KeyProvider = _options.KeyProvider,
        MaxConnections = _options.MaximumClients,
        MaxPendingHandshakes = Math.Min(4096, _options.MaximumClients),
        MaxUdpPayloadSize = _options.MaximumUdpPayloadSize,
        ConnectionQueueCapacity = 4096,
        PacketReceiveQueueCapacity = 8192,
        DatagramQueueCapacity = 8192,
        StreamAcceptQueueCapacity = 8,
        IdleTimeout = TimeSpan.FromMinutes(2),
        KeepAliveInterval = TimeSpan.FromSeconds(15),
        ShutdownTimeout = _options.ShutdownTimeout,
        SocketReceiveBufferSize = _options.SocketBufferSize,
        SocketSendBufferSize = _options.SocketBufferSize
    };

    /// <summary>接受连接并跟踪每个客户端任务，以支持有界关闭。</summary>
    /// <param name="cancellationToken">服务器生命周期取消标记。</param>
    /// <returns>服务器停止时结束的任务。</returns>
    private async Task AcceptLoopAsync(CancellationToken cancellationToken)
    {
        try
        {
            while (!cancellationToken.IsCancellationRequested)
            {
                QuicConnection connection = await _endpoint!.AcceptConnectionAsync(cancellationToken).ConfigureAwait(false);
                long id = Interlocked.Increment(ref _taskId);
                Task task = HandleClientAsync(connection, cancellationToken);
                _clientTasks[id] = task;
                _ = task.ContinueWith((completedTask, state) =>
                {
                    var tuple = ((ConcurrentDictionary<long, Task>, long))state!;
                    tuple.Item1.TryRemove(tuple.Item2, out _);
                }, (_clientTasks, id), CancellationToken.None, TaskContinuationOptions.ExecuteSynchronously,
                    TaskScheduler.Default);
            }
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { }
        catch (ChannelClosedException) when (cancellationToken.IsCancellationRequested) { }
    }

    /// <summary>接受用于观察公网映射的短连接 TCP 客户端。</summary>
    /// <param name="cancellationToken">服务器生命周期取消标记。</param>
    /// <returns>服务器停止时结束的任务。</returns>
    private async Task TcpAcceptLoopAsync(CancellationToken cancellationToken)
    {
        try
        {
            while (!cancellationToken.IsCancellationRequested)
            {
                Socket socket = await _tcpListener!.AcceptAsync(cancellationToken).ConfigureAwait(false);
                long id = Interlocked.Increment(ref _taskId);
                Task task = HandleTcpObservationAsync(socket, cancellationToken);
                _clientTasks[id] = task;
                _ = task.ContinueWith((completed, state) =>
                {
                    var tuple = ((ConcurrentDictionary<long, Task>, long))state!;
                    tuple.Item1.TryRemove(tuple.Item2, out Task? removed);
                }, (_clientTasks, id), CancellationToken.None, TaskContinuationOptions.ExecuteSynchronously,
                    TaskScheduler.Default);
            }
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { }
        catch (ObjectDisposedException) when (cancellationToken.IsCancellationRequested) { }
        catch (SocketException) when (cancellationToken.IsCancellationRequested) { }
    }

    /// <summary>使用 QUIC 注册阶段的一次性令牌绑定服务器观察到的 TCP 公网端点。</summary>
    /// <param name="socket">已接受的短连接 TCP 套接字。</param>
    /// <param name="serverCancellation">服务器生命周期取消标记。</param>
    /// <returns>登记响应发送并关闭短连接后结束的任务。</returns>
    private async Task HandleTcpObservationAsync(Socket socket, CancellationToken serverCancellation)
    {
        byte[] request = ArrayPool<byte>.Shared.Rent(P2PTcpProtocol.ObservationRequestLength);
        byte[] response = ArrayPool<byte>.Shared.Rent(P2PTcpProtocol.ObservationResponseLength);
        try
        {
            socket.NoDelay = true;
            IPEndPoint? remote = socket.RemoteEndPoint as IPEndPoint;
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(serverCancellation);
            timeout.CancelAfter(_options.TcpObservationTimeout);
            using var stream = new NetworkStream(socket, ownsSocket: true);
            socket = null!;
            await P2PTcpProtocol.ReadExactlyAsync(stream,
                request.AsMemory(0, P2PTcpProtocol.ObservationRequestLength), timeout.Token).ConfigureAwait(false);
            if (!P2PTcpProtocol.TryReadObservationRequest(
                request.AsSpan(0, P2PTcpProtocol.ObservationRequestLength), out P2PTcpObservationKey key) ||
                !_tcpObservations.TryRemove(key, out ClientRegistration? registration) ||
                !_clients.TryGetValue(registration.Key, out ClientRegistration? current) ||
                !ReferenceEquals(current, registration) || remote is null)
                return;
            remote = NormalizeMappedAddress(remote, registration.TcpPrivateEndPoint?.AddressFamily);
            registration.CompleteTcpObservation(remote);
            P2PTcpProtocol.WriteObservationResponse(response, remote);
            await stream.WriteAsync(response.AsMemory(0, P2PTcpProtocol.ObservationResponseLength), timeout.Token)
                .ConfigureAwait(false);
            if (registration.OffersPublished)
                await NotifyAllPairsAsync(registration, serverCancellation).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (serverCancellation.IsCancellationRequested) { }
        catch { }
        finally
        {
            socket?.Dispose();
            CryptographicOperations.ZeroMemory(request.AsSpan(0, P2PTcpProtocol.ObservationRequestLength));
            ArrayPool<byte>.Shared.Return(request);
            ArrayPool<byte>.Shared.Return(response);
        }
    }

    /// <summary>注册并服务一条已认证的 QUIC 连接。</summary>
    /// <param name="connection">共享端点接受的已认证连接。</param>
    /// <param name="serverCancellation">服务器生命周期取消标记。</param>
    /// <returns>精确移除对应代次注册后结束的任务。</returns>
    private async Task HandleClientAsync(QuicConnection connection, CancellationToken serverCancellation)
    {
        ClientRegistration? registration = null;
        P2PControlChannel? control = null;
        using var clientLifetime = CancellationTokenSource.CreateLinkedTokenSource(serverCancellation);
        try
        {
            clientLifetime.CancelAfter(TimeSpan.FromSeconds(15));
            QuicStream stream = await connection.AcceptStreamAsync(clientLifetime.Token).ConfigureAwait(false);
            control = new P2PControlChannel(stream);
            P2PControlMessage? first = await control.ReceiveAsync(clientLifetime.Token).ConfigureAwait(false);
            if (first is null || first.Type != P2PControlType.Register ||
                string.IsNullOrWhiteSpace(first.SessionId) || string.IsNullOrWhiteSpace(first.PeerId))
                throw new InvalidDataException("发送给协调服务器的第一条消息必须注册对端。");
            string credential = Encoding.UTF8.GetString(first.Payload.Span).Split('\n').ElementAtOrDefault(2) ?? "";
            if (_options.AuthorizeRegistration is not null && !_options.AuthorizeRegistration(first.SessionId, first.PeerId, credential))
                throw new UnauthorizedAccessException("Device is not authorized.");
            ulong sessionId = P2PFrameCodec.HashIdentifier(first.SessionId);
            ulong peerId = P2PFrameCodec.HashIdentifier(first.PeerId);
            var key = new RegistrationKey(sessionId, peerId);
            int peersInSession = _clients.Keys.Count(item => item.SessionId == sessionId);
            if (peersInSession >= _options.MaximumPeersPerSession && !_clients.ContainsKey(key))
                throw new InvalidOperationException("已经达到会话对端数量上限。");
            uint virtualAddress = AcquireLease(first.SessionId, first.PeerId, sessionId, peerId);
            IPEndPoint observedPublicEndPoint = NormalizeMappedAddress(connection.RemoteEndPoint,
                first.PrivateEndPoint?.AddressFamily);
            IPEndPoint publicEndPoint = SelectAdvertisedEndPoint(first.PublicEndPoint, observedPublicEndPoint)
                ?? observedPublicEndPoint;
            IPEndPoint? advertisedTcpEndPoint = SelectAdvertisedEndPoint(
                first.TcpPublicEndPoint, observedPublicEndPoint);
            (string clientVersion, string clientPlatform) = ParseClientMetadata(first.Payload.Span);
            registration = new ClientRegistration(key, first.SessionId, first.PeerId, virtualAddress,
                publicEndPoint, first.PrivateEndPoint, advertisedTcpEndPoint,
                first.TcpPrivateEndPoint, clientVersion, clientPlatform, connection, control);
            if (_options.EnableTcpRendezvous && first.TcpPrivateEndPoint is not null &&
                first.Token is { Length: 32 } && P2PTcpObservationKey.TryCreate(first.Token, out P2PTcpObservationKey tcpKey))
            {
                registration.ObservationKey = tcpKey;
                _tcpObservations[tcpKey] = registration;
            }
            if (_clients.TryGetValue(key, out ClientRegistration? existing))
            {
                if (!string.Equals(existing.SessionName, first.SessionId, StringComparison.Ordinal) ||
                    !string.Equals(existing.PeerName, first.PeerId, StringComparison.Ordinal))
                    throw new InvalidOperationException("检测到会话或对端标识哈希冲突。");
                _clients[key] = registration;
                RemovePairTokens(existing.Key);
                existing.Connection.Abort(0x210);
            }
            else if (!_clients.TryAdd(key, registration)) throw new IOException("无法注册对端。");

            await control.SendAsync(new P2PControlMessage(P2PControlType.Registered,
                SourcePeerId: peerId, PublicEndPoint: publicEndPoint,
                VirtualAddress: registration.VirtualAddress,
                VirtualPrefixLength: checked((byte)_options.VirtualNetworkPrefixLength)), clientLifetime.Token)
                .ConfigureAwait(false);
            RaiseClientsChanged();
            await registration.WaitForTcpObservationAsync(_options.TcpObservationTimeout, clientLifetime.Token)
                .ConfigureAwait(false);
            RaiseClientsChanged();
            registration.MarkOffersPublished();
            await NotifyAllPairsAsync(registration, clientLifetime.Token).ConfigureAwait(false);

            clientLifetime.CancelAfter(Timeout.InfiniteTimeSpan);
            Task controlLoop = ControlLoopAsync(registration, credential, clientLifetime.Token);
            Task datagramLoop = DatagramLoopAsync(registration, clientLifetime.Token);
            Task authorizationLoop = RevalidateAsync(first.SessionId, first.PeerId, credential, clientLifetime.Token);
            await Task.WhenAny(connection.Closed, controlLoop, datagramLoop, authorizationLoop).ConfigureAwait(false);
            clientLifetime.Cancel();
            await IgnoreTasksAsync(controlLoop, datagramLoop, authorizationLoop).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (serverCancellation.IsCancellationRequested) { }
        catch (Exception exception)
        {
            if (control is not null)
            {
                try { await control.SendAsync(new P2PControlMessage(P2PControlType.Error,
                    Error: exception.Message), CancellationToken.None).ConfigureAwait(false); } catch { }
            }
        }
        finally
        {
            if (registration?.ObservationKey is P2PTcpObservationKey observationKey)
                _tcpObservations.TryRemove(new KeyValuePair<P2PTcpObservationKey, ClientRegistration>(
                    observationKey, registration));
            if (registration is not null && _clients.TryRemove(
                new KeyValuePair<RegistrationKey, ClientRegistration>(registration.Key, registration)))
            {
                await NotifyPeerGoneAsync(registration, CancellationToken.None).ConfigureAwait(false);
                RemovePairTokens(registration.Key);
                if (_options.VirtualAddressLeaseProvider is null) ReleaseLease(registration.Key);
                RaiseClientsChanged();
            }
            if (control is not null) await control.DisposeAsync().ConfigureAwait(false);
            await connection.DisposeAsync().ConfigureAwait(false);
        }
    }

    /// <summary>Only accepts a client-advertised mapping when its address is the same public address observed by the server.</summary>
    private async Task RevalidateAsync(string session, string peer, string credential, CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            await Task.Delay(TimeSpan.FromSeconds(5), ct);
            if (_options.AuthorizeRegistration is not null && !_options.AuthorizeRegistration(session, peer, credential)) return;
        }
    }

    private static IPEndPoint? SelectAdvertisedEndPoint(IPEndPoint? advertised, IPEndPoint observed)
    {
        if (advertised is null || advertised.Port is < 1 or > 65535) return null;
        IPAddress candidate = advertised.Address.IsIPv4MappedToIPv6
            ? advertised.Address.MapToIPv4() : advertised.Address;
        IPAddress actual = observed.Address.IsIPv4MappedToIPv6
            ? observed.Address.MapToIPv4() : observed.Address;
        return candidate.Equals(actual) ? new IPEndPoint(actual, advertised.Port) : null;
    }

    /// <summary>
    /// 执行Parse Client Metadata操作。
    /// </summary>
    /// <param name="payload">payload参数。</param>
    /// <returns>操作结果。</returns>
    private static (string Version, string Platform) ParseClientMetadata(ReadOnlySpan<byte> payload)
    {
        if (payload.IsEmpty || payload.Length > 256) return ("", "");
        string value;
        try { value = Encoding.UTF8.GetString(payload); }
        catch { return ("", ""); }
        int separator = value.IndexOf('\n');
        if (separator < 0) return (value.Length <= 64 ? value : "", "");
        string version = value[..separator].Trim();
        string platform = value[(separator + 1)..].Trim();
        return (version.Length <= 64 ? version : "", platform.Length <= 64 ? platform : "");
    }

    /// <summary>处理来自一个已注册对端的可靠控制和中转消息。</summary>
    /// <param name="client">已绑定的注册信息。</param>
    /// <param name="cancellationToken">客户端生命周期取消标记。</param>
    /// <returns>控制流关闭时结束的任务。</returns>
    /// <param name="credential">Device registration credential.</param>
    private async Task ControlLoopAsync(ClientRegistration client, string credential, CancellationToken cancellationToken)
    {
        while (!cancellationToken.IsCancellationRequested)
        {
            P2PControlMessage? message = await client.Control.ReceiveAsync(cancellationToken).ConfigureAwait(false);
            if (message is null) return;
            if (_options.AuthorizeRegistration is not null && !_options.AuthorizeRegistration(client.SessionName, client.PeerName, credential))
                throw new UnauthorizedAccessException("Device access revoked.");
            switch (message.Type)
            {
                case P2PControlType.Ping:
                    await client.Control.SendAsync(new P2PControlMessage(P2PControlType.Ping),
                        cancellationToken).ConfigureAwait(false);
                    break;
                case P2PControlType.PunchRequest:
                    // Old clients used to request a new pair offer for every IP packet.
                    // Bound this control amplification without throttling relay data.
                    if (!client.PunchRequests.TryAcquire(message.TargetPeerId, Environment.TickCount64, 3000)) break;
                    if (_clients.TryGetValue(new RegistrationKey(client.Key.SessionId, message.TargetPeerId),
                        out ClientRegistration? punchTarget))
                        await NotifyPairAsync(client, punchTarget, cancellationToken, initiate: true)
                            .ConfigureAwait(false);
                    break;
                case P2PControlType.RelayReliable:
                    if (!_options.EnableRelay || message.Payload.IsEmpty) break;
                    if (_clients.TryGetValue(new RegistrationKey(client.Key.SessionId, message.TargetPeerId),
                        out ClientRegistration? relayTarget))
                    {
                        await relayTarget.Control.SendAsync(new P2PControlMessage(P2PControlType.RelayReliable,
                            SourcePeerId: client.Key.PeerId, TargetPeerId: relayTarget.Key.PeerId,
                            Payload: message.Payload, TrafficClass: message.TrafficClass), cancellationToken)
                            .ConfigureAwait(false);
                        RecordRelay(client, relayTarget, message.Payload.Length, reliable: true);
                    }
                    break;
            }
        }
    }

    /// <summary>校验并转发低延迟不透明中转数据报。</summary>
    /// <param name="client">已绑定的来源注册信息。</param>
    /// <param name="cancellationToken">客户端生命周期取消标记。</param>
    /// <returns>对应 QUIC 连接关闭时结束的任务。</returns>
    private async Task DatagramLoopAsync(ClientRegistration client, CancellationToken cancellationToken)
    {
        while (!cancellationToken.IsCancellationRequested)
        {
            using QuicDatagram datagram = await client.Connection.ReceiveDatagramAsync(cancellationToken)
                .ConfigureAwait(false);
            if (!_options.EnableRelay) continue;
            ulong session, source, target;
            P2PTrafficClass trafficClass;
            bool valid;
            {
                valid = P2PRelayDatagramCodec.TryRead(datagram.Memory.Span, out session, out source,
                    out target, out trafficClass, out _);
            }
            if (!valid || session != client.Key.SessionId || source != client.Key.PeerId || target == source) continue;
            if (_clients.TryGetValue(new RegistrationKey(session, target), out ClientRegistration? destination))
            {
                await Links.QuicDatagramP2PLink.SendPrioritizedAsync(destination.Connection, datagram.Memory,
                    trafficClass, cancellationToken).ConfigureAwait(false);
                RecordRelay(client, destination,
                    Math.Max(0, datagram.Memory.Length - P2PRelayDatagramCodec.HeaderLength), reliable: false);
            }
        }
    }

    /// <summary>在新注册客户端与会话内每个现有对端之间发送配对提议。</summary>
    /// <param name="client">新注册的客户端。</param>
    /// <param name="cancellationToken">客户端生命周期取消标记。</param>
    /// <returns>提议交付后结束的异步操作。</returns>
    private async Task NotifyAllPairsAsync(ClientRegistration client, CancellationToken cancellationToken)
    {
        ClientRegistration[] peers = _clients.Values.Where(peer => peer.Key.SessionId == client.Key.SessionId &&
            peer.Key.PeerId != client.Key.PeerId).ToArray();
        foreach (ClientRegistration peer in peers)
            await NotifyPairAsync(client, peer, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>向双方对端发送相同的随机配对令牌及双方候选端点。</summary>
    /// <param name="first">第一个对端。</param>
    /// <param name="second">第二个对端。</param>
    /// <param name="cancellationToken">用于取消发送的标记。</param>
    /// <param name="initiate">是否要求双方立即发起直连尝试。</param>
    /// <returns>双方提议发送完成后结束的异步操作。</returns>
    private async Task NotifyPairAsync(ClientRegistration first, ClientRegistration second,
        CancellationToken cancellationToken, bool initiate = false)
    {
        if (first.Key.SessionId != second.Key.SessionId || first.Key.PeerId == second.Key.PeerId) return;
        byte[] token = _pairTokens.GetOrAdd(PairKey.Create(first.Key, second.Key),
            static _ => RandomNumberGenerator.GetBytes(32));
        await first.Control.SendAsync(CreateOffer(second, token, initiate), cancellationToken).ConfigureAwait(false);
        await second.Control.SendAsync(CreateOffer(first, token, initiate), cancellationToken).ConfigureAwait(false);
    }

    /// <summary>创建一条对端提议，且不暴露可变服务器状态。</summary>
    /// <param name="peer">提议中的对端。</param>
    /// <param name="token">配对专用密钥。</param>
    /// <param name="initiate">是否在提议中携带立即打洞标记。</param>
    /// <returns>包含公网及局域网候选端点的控制消息。</returns>
    private P2PControlMessage CreateOffer(ClientRegistration peer, byte[] token, bool initiate) =>
        new(P2PControlType.PeerOffer, PeerId: peer.PeerName, SourcePeerId: peer.Key.PeerId,
            PublicEndPoint: peer.PublicEndPoint, PrivateEndPoint: peer.PrivateEndPoint,
            TcpPublicEndPoint: peer.TcpPublicEndPoint, TcpPrivateEndPoint: peer.TcpPrivateEndPoint,
            Token: token.ToArray(), Payload: initiate ? new byte[] { 1 } : ReadOnlyMemory<byte>.Empty,
            VirtualAddress: peer.VirtualAddress,
            VirtualPrefixLength: checked((byte)_options.VirtualNetworkPrefixLength));

    /// <summary>通知房间内剩余成员某一精确注册已经离开。</summary>
    /// <param name="client">已移除的注册信息。</param>
    /// <param name="cancellationToken">用于取消通知的标记。</param>
    /// <returns>尽力发送完成后结束的异步操作。</returns>
    private async Task NotifyPeerGoneAsync(ClientRegistration client, CancellationToken cancellationToken)
    {
        P2PControlMessage message = new(P2PControlType.PeerGone, SourcePeerId: client.Key.PeerId);
        foreach (ClientRegistration peer in _clients.Values.Where(peer => peer.Key.SessionId == client.Key.SessionId))
        {
            try { await peer.Control.SendAsync(message, cancellationToken).ConfigureAwait(false); } catch { }
        }
    }

    /// <summary>移除涉及一个已离开对端的配对密钥。</summary>
    /// <param name="key">已离开的注册键。</param>
    private void RemovePairTokens(RegistrationKey key)
    {
        foreach (PairKey pair in _pairTokens.Keys)
            if (pair.SessionId == key.SessionId && (pair.First == key.PeerId || pair.Second == key.PeerId))
                if (_pairTokens.TryRemove(pair, out byte[]? token)) CryptographicOperations.ZeroMemory(token);
    }

    /// <summary>归还一个精确的对端租约，并移除空的会话地址池。</summary>
    /// <param name="key">已离开的注册键。</param>
    private void ReleaseLease(RegistrationKey key)
    {
        if (!_leasePools.TryGetValue(key.SessionId, out SessionLeasePool? pool)) return;
        pool.Release(key.PeerId);
        if (pool.IsEmpty) _leasePools.TryRemove(new KeyValuePair<ulong, SessionLeasePool>(key.SessionId, pool));
    }

    /// <summary>隔离管理订阅方异常，避免网页通知破坏网络连接生命周期。</summary>
    private void RaiseClientsChanged()
    {
        Delegate[] subscribers = ClientsChanged?.GetInvocationList() ?? [];
        foreach (Delegate subscriber in subscribers)
            try { ((Action)subscriber)(); } catch { }
    }

    /// <summary>以无方向的客户端对为键记录一次成功的服务器中继转发。</summary>
    /// <param name="source">来源客户端。</param>
    /// <param name="destination">目标客户端。</param>
    /// <param name="bytes">有效负载字节数。</param>
    /// <param name="reliable">是否为可靠中继。</param>
    private void RecordRelay(ClientRegistration source, ClientRegistration destination, int bytes, bool reliable)
    {
        RelayConnectionKey key = RelayConnectionKey.Create(source.Key, destination.Key);
        ClientRegistration first = source.Key.PeerId <= destination.Key.PeerId ? source : destination;
        ClientRegistration second = ReferenceEquals(first, source) ? destination : source;
        var candidate = new RelayConnectionStatistics(first.SessionName, first.PeerName, second.PeerName);
        RelayConnectionStatistics statistics = _relayConnections.GetOrAdd(key, candidate);
        bool created = ReferenceEquals(statistics, candidate);
        statistics.Record(bytes, reliable);
        if (created) RaiseRelayConnectionsChanged();
        MaybePruneRelayStatistics();
    }

    /// <summary>每分钟或统计超过容量时执行一次单线程清理。</summary>
    private void MaybePruneRelayStatistics()
    {
        long now = Environment.TickCount64;
        long previous = Volatile.Read(ref _lastRelayPruneAt);
        if (_relayConnections.Count <= _options.MaximumRelayStatistics && now - previous < 60_000) return;
        if (Interlocked.CompareExchange(ref _lastRelayPruneAt, now, previous) != previous) return;
        PruneRelayStatistics();
    }

    /// <summary>清理过期和超出容量的中继统计，防止常驻服务内存无限增长。</summary>
    private void PruneRelayStatistics()
    {
        long threshold = DateTimeOffset.UtcNow.Subtract(_options.RelayStatisticsRetention).UtcTicks;
        bool changed = false;
        foreach (KeyValuePair<RelayConnectionKey, RelayConnectionStatistics> pair in _relayConnections)
            if (pair.Value.LastActivityTicks < threshold) changed |= _relayConnections.TryRemove(pair);
        int excess = _relayConnections.Count - _options.MaximumRelayStatistics;
        if (excess > 0)
            foreach (RelayConnectionKey key in _relayConnections.OrderBy(static pair => pair.Value.LastActivityTicks)
                .Take(excess).Select(static pair => pair.Key))
                changed |= _relayConnections.TryRemove(key, out _);
        if (changed) RaiseRelayConnectionsChanged();
    }

    /// <summary>隔离中继统计订阅方异常。</summary>
    private void RaiseRelayConnectionsChanged()
    {
        Delegate[] subscribers = RelayConnectionsChanged?.GetInvocationList() ?? [];
        foreach (Delegate subscriber in subscribers)
            try { ((Action)subscriber)(); } catch { }
    }

    /// <summary>从持久提供器或进程内地址池获取租约，并严格验证外部提供器结果。</summary>
    /// <param name="sessionName">逻辑会话文本名称。</param>
    /// <param name="peerName">稳定客户端文本标识。</param>
    /// <param name="sessionId">逻辑会话数字标识。</param>
    /// <param name="peerId">客户端数字标识。</param>
    /// <returns>网络字节序对应的无符号 IPv4 数值。</returns>
    private uint AcquireLease(string sessionName, string peerName, ulong sessionId, ulong peerId)
    {
        IP2PVirtualAddressLeaseProvider? provider = _options.VirtualAddressLeaseProvider;
        if (provider is null)
            return _leasePools.GetOrAdd(sessionId, _ => new SessionLeasePool(
                _options.VirtualNetworkAddress, _options.VirtualNetworkPrefixLength)).Acquire(peerId);

        IPAddress address = provider.Acquire(sessionName, peerName,
            _options.VirtualNetworkAddress, _options.VirtualNetworkPrefixLength);
        if (address.AddressFamily != AddressFamily.InterNetwork)
            throw new InvalidDataException("持久租约提供器返回的不是 IPv4 地址。");
        uint value = BinaryPrimitives.ReadUInt32BigEndian(address.GetAddressBytes());
        uint network = BinaryPrimitives.ReadUInt32BigEndian(_options.VirtualNetworkAddress.GetAddressBytes());
        uint mask = uint.MaxValue << (32 - _options.VirtualNetworkPrefixLength);
        uint host = value & ~mask;
        uint maximumHost = (1u << (32 - _options.VirtualNetworkPrefixLength)) - 2;
        if ((value & mask) != network || host is 0 || host > maximumHost)
            throw new InvalidDataException("持久租约提供器返回的地址不在配置网段的可用主机范围内。");
        return value;
    }

    /// <summary>等待任务完成，并忽略预期的连接关闭异常。</summary>
    /// <param name="tasks">要观察的任务集合。</param>
    /// <returns>所有任务结束后完成的异步操作。</returns>
    private static async Task IgnoreTasksAsync(params Task[] tasks)
    {
        try { await Task.WhenAll(tasks).ConfigureAwait(false); } catch { }
    }

    /// <summary>在长期运行的未连接套接字上禁用 Windows UDP ICMP 重置转换。</summary>
    /// <param name="socket">UDP 套接字。</param>
    private static void DisableUdpConnectionReset(Socket socket)
    {
        if (!OperatingSystem.IsWindows()) return;
        try { socket.IOControl(-1744830452, [0, 0, 0, 0], null); } catch { }
    }

    /// <summary>把双栈监听器观察到的 IPv4 映射 IPv6 地址恢复为客户端可用的 IPv4 地址。</summary>
    /// <param name="endpoint">监听套接字观察到的远程端点。</param>
    /// <param name="preferredFamily">客户端私网候选声明的地址族。</param>
    /// <returns>与客户端套接字地址族兼容的端点。</returns>
    private static IPEndPoint NormalizeMappedAddress(IPEndPoint endpoint, AddressFamily? preferredFamily)
    {
        if (preferredFamily == AddressFamily.InterNetwork && endpoint.Address.IsIPv4MappedToIPv6)
            return new IPEndPoint(endpoint.Address.MapToIPv4(), endpoint.Port);
        return endpoint;
    }

    /// <summary>把网络字节序数值转换为不依赖处理器端序的 IPv4 地址。</summary>
    /// <param name="value">IPv4 的三十二位网络序数值。</param>
    /// <returns>对应 IPv4 地址。</returns>
    private static IPAddress UInt32ToAddress(uint value)
    {
        Span<byte> bytes = stackalloc byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(bytes, value);
        return new IPAddress(bytes);
    }

    /// <summary>停止接受连接、关闭所有连接并等待已跟踪任务。</summary>
    /// <returns>有界关闭完成后结束的异步操作。</returns>
    public async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0) return;
        _lifetime.Cancel();
        foreach (ClientRegistration client in _clients.Values) client.Connection.Abort(0);
        try { _tcpListener?.Dispose(); } catch { }
        if (_endpoint is not null) await _endpoint.DisposeAsync().ConfigureAwait(false);
        if (_acceptTask is not null) { try { await _acceptTask.WaitAsync(_options.ShutdownTimeout).ConfigureAwait(false); } catch { } }
        if (_tcpAcceptTask is not null) { try { await _tcpAcceptTask.WaitAsync(_options.ShutdownTimeout).ConfigureAwait(false); } catch { } }
        Task[] tasks = _clientTasks.Values.ToArray();
        if (tasks.Length != 0) { try { await Task.WhenAll(tasks).WaitAsync(_options.ShutdownTimeout).ConfigureAwait(false); } catch { } }
        foreach (byte[] token in _pairTokens.Values) CryptographicOperations.ZeroMemory(token);
        _pairTokens.Clear();
        _tcpObservations.Clear();
        _clients.Clear();
        _relayConnections.Clear();
        _leasePools.Clear();
        _runLifetime?.Dispose();
        _lifetime.Dispose();
    }

    /// <summary>
    /// 表示 Registration Key，并提供相关数据或行为。
    /// </summary>
    /// <param name="SessionId">Session Id参数。</param>
    /// <param name="PeerId">Peer Id参数。</param>
    private readonly record struct RegistrationKey(ulong SessionId, ulong PeerId);
    /// <summary>
/// 表示 Pair Key，并提供相关数据或行为。
/// </summary>
/// <param name="SessionId">Session Id参数。</param>
/// <param name="First">First参数。</param>
/// <param name="Second">Second参数。</param>
private readonly record struct PairKey(ulong SessionId, ulong First, ulong Second)
    {
        /// <summary>
        /// 创建。
        /// </summary>
        /// <param name="first">first参数。</param>
        /// <param name="second">second参数。</param>
        /// <returns>操作结果。</returns>
        public static PairKey Create(RegistrationKey first, RegistrationKey second) =>
            first.PeerId < second.PeerId ? new(first.SessionId, first.PeerId, second.PeerId) :
                new(first.SessionId, second.PeerId, first.PeerId);
    }

    /// <summary>以分组和排序后的两个客户端数字 ID 唯一标识中继连接。</summary>
    private readonly record struct RelayConnectionKey(ulong GroupId, ulong First, ulong Second)
    {
        /// <summary>创建不区分数据方向的中继连接键。</summary>
        public static RelayConnectionKey Create(RegistrationKey first, RegistrationKey second) =>
            first.PeerId <= second.PeerId ? new(first.SessionId, first.PeerId, second.PeerId) :
                new(first.SessionId, second.PeerId, first.PeerId);
    }

    /// <summary>使用原子计数保存高频中继连接统计。</summary>
    private sealed class RelayConnectionStatistics
    {
        private readonly long _firstActivityTicks = DateTimeOffset.UtcNow.UtcTicks;
        private long _lastActivityTicks;
        private long _reliablePackets;
        private long _reliableBytes;
        private long _datagramPackets;
        private long _datagramBytes;

        /// <summary>创建一对客户端的中继统计。</summary>
        public RelayConnectionStatistics(string groupId, string firstPeerId, string secondPeerId)
        {
            GroupId = groupId;
            FirstPeerId = firstPeerId;
            SecondPeerId = secondPeerId;
            _lastActivityTicks = _firstActivityTicks;
        }

        /// <summary>
        /// 获取或设置Group Id。
        /// </summary>
        /// <returns>Group Id。</returns>
        public string GroupId { get; }
        /// <summary>
        /// 获取或设置First Peer Id。
        /// </summary>
        /// <returns>First Peer Id。</returns>
        public string FirstPeerId { get; }
        /// <summary>
        /// 获取或设置Second Peer Id。
        /// </summary>
        /// <returns>Second Peer Id。</returns>
        public string SecondPeerId { get; }
        /// <summary>
        /// 获取或设置Last Activity Ticks。
        /// </summary>
        /// <returns>Last Activity Ticks。</returns>
        public long LastActivityTicks => Volatile.Read(ref _lastActivityTicks);

        /// <summary>记录一个已经成功转发的中继有效负载。</summary>
        public void Record(int bytes, bool reliable)
        {
            Volatile.Write(ref _lastActivityTicks, DateTimeOffset.UtcNow.UtcTicks);
            if (reliable)
            {
                Interlocked.Increment(ref _reliablePackets);
                Interlocked.Add(ref _reliableBytes, bytes);
            }
            else
            {
                Interlocked.Increment(ref _datagramPackets);
                Interlocked.Add(ref _datagramBytes, bytes);
            }
        }

        /// <summary>创建无需锁定的统计快照。</summary>
        public P2PRelayConnection CreateSnapshot() => new(GroupId, FirstPeerId, SecondPeerId,
            new DateTimeOffset(_firstActivityTicks, TimeSpan.Zero),
            new DateTimeOffset(LastActivityTicks, TimeSpan.Zero),
            Volatile.Read(ref _reliablePackets), Volatile.Read(ref _reliableBytes),
            Volatile.Read(ref _datagramPackets), Volatile.Read(ref _datagramBytes));
    }

    /// <summary>保存一代已认证客户端注册及其可选 TCP 公网映射状态。</summary>
    private sealed class ClientRegistration
    {
        internal readonly PeerRequestLimiter PunchRequests = new();
        private readonly TaskCompletionSource _tcpObserved = new(TaskCreationOptions.RunContinuationsAsynchronously);
        private IPEndPoint? _tcpPublicEndPoint;
        private int _offersPublished;

        /// <summary>创建客户端注册状态。</summary>
        public ClientRegistration(RegistrationKey key, string sessionName, string peerName, uint virtualAddress,
            IPEndPoint publicEndPoint, IPEndPoint? privateEndPoint, IPEndPoint? tcpPublicEndPoint,
            IPEndPoint? tcpPrivateEndPoint, string clientVersion, string clientPlatform,
            QuicConnection connection, P2PControlChannel control)
        {
            Key = key;
            SessionName = sessionName;
            PeerName = peerName;
            VirtualAddress = virtualAddress;
            PublicEndPoint = publicEndPoint;
            PrivateEndPoint = privateEndPoint;
            _tcpPublicEndPoint = tcpPublicEndPoint;
            TcpPrivateEndPoint = tcpPrivateEndPoint;
            ClientVersion = clientVersion;
            ClientPlatform = clientPlatform;
            Connection = connection;
            Control = control;
        }

        /// <summary>
        /// 获取或设置Key。
        /// </summary>
        /// <returns>Key。</returns>
        public RegistrationKey Key { get; }
        /// <summary>
        /// 获取或设置Session Name。
        /// </summary>
        /// <returns>Session Name。</returns>
        public string SessionName { get; }
        /// <summary>
        /// 获取或设置Peer Name。
        /// </summary>
        /// <returns>Peer Name。</returns>
        public string PeerName { get; }
        /// <summary>
        /// 获取或设置Virtual Address。
        /// </summary>
        /// <returns>Virtual Address。</returns>
        public uint VirtualAddress { get; }
        /// <summary>
        /// 获取或设置Public End Point。
        /// </summary>
        /// <returns>Public End Point。</returns>
        public IPEndPoint PublicEndPoint { get; }
        /// <summary>
        /// 获取或设置Private End Point。
        /// </summary>
        /// <returns>Private End Point。</returns>
        public IPEndPoint? PrivateEndPoint { get; }
        /// <summary>
        /// 获取或设置Tcp Private End Point。
        /// </summary>
        /// <returns>Tcp Private End Point。</returns>
        public IPEndPoint? TcpPrivateEndPoint { get; }
        /// <summary>
        /// 获取或设置Tcp Public End Point。
        /// </summary>
        /// <returns>Tcp Public End Point。</returns>
        public IPEndPoint? TcpPublicEndPoint => Volatile.Read(ref _tcpPublicEndPoint);
        /// <summary>
        /// 获取或设置Client Version。
        /// </summary>
        /// <returns>Client Version。</returns>
        public string ClientVersion { get; }
        /// <summary>
        /// 获取或设置Client Platform。
        /// </summary>
        /// <returns>Client Platform。</returns>
        public string ClientPlatform { get; }
        /// <summary>
        /// 获取或设置Connection。
        /// </summary>
        /// <returns>Connection。</returns>
        public QuicConnection Connection { get; }
        /// <summary>
        /// 获取或设置Control。
        /// </summary>
        /// <returns>Control。</returns>
        public P2PControlChannel Control { get; }
        /// <summary>
        /// 获取或设置Observation Key。
        /// </summary>
        /// <returns>Observation Key。</returns>
        public P2PTcpObservationKey? ObservationKey { get; set; }
        /// <summary>
        /// 获取或设置Offers Published。
        /// </summary>
        /// <returns>Offers Published。</returns>
        public bool OffersPublished => Volatile.Read(ref _offersPublished) != 0;
        /// <summary>
        /// 获取或设置Connected At。
        /// </summary>
        /// <returns>Connected At。</returns>
        public DateTimeOffset ConnectedAt { get; } = DateTimeOffset.UtcNow;

        /// <summary>创建不暴露连接和控制流对象的管理快照。</summary>
        /// <returns>当前注册代次的只读客户端信息。</returns>
        public P2PConnectedClient CreateSnapshot() => new(SessionName, PeerName, Key.PeerId,
            UInt32ToAddress(VirtualAddress),
            PublicEndPoint, TcpPublicEndPoint, ConnectedAt, ClientVersion, ClientPlatform);

        /// <summary>仅接受首个服务器观察到的 TCP 公网端点。</summary>
        public void CompleteTcpObservation(IPEndPoint endpoint)
        {
            Interlocked.CompareExchange(ref _tcpPublicEndPoint, endpoint, null);
            _tcpObserved.TrySetResult();
        }

        /// <summary>有界等待 TCP 公网映射登记，失败时仍允许 UDP 和中转继续启动。</summary>
        public async Task WaitForTcpObservationAsync(TimeSpan timeout, CancellationToken cancellationToken)
        {
            if (ObservationKey is null) return;
            try { await _tcpObserved.Task.WaitAsync(timeout, cancellationToken).ConfigureAwait(false); }
            catch (TimeoutException) { }
        }

        /// <summary>标记初始对端提议已经发布。</summary>
        public void MarkOffersPublished() => Volatile.Write(ref _offersPublished, 1);
    }

    /// <summary>
/// 表示 Session Lease Pool，并提供相关数据或行为。
/// </summary>
private sealed class SessionLeasePool
    {
        private readonly object _sync = new();
        private readonly Dictionary<ulong, uint> _leases = new();
        private readonly HashSet<uint> _used = new();
        private readonly uint _network;
        private readonly uint _maximumHost;
        private uint _nextHost = 1;

        /// <summary>
        /// 初始化 <see cref="SessionLeasePool"/> 类的新实例。
        /// </summary>
        /// <param name="network">network参数。</param>
        /// <param name="prefixLength">prefix Length参数。</param>
        public SessionLeasePool(IPAddress network, int prefixLength)
        {
            _network = BinaryPrimitives.ReadUInt32BigEndian(network.GetAddressBytes());
            _maximumHost = (1u << (32 - prefixLength)) - 2;
        }

        /// <summary>
        /// 获取或设置Is Empty。
        /// </summary>
        /// <returns>Is Empty。</returns>
        public bool IsEmpty { get { lock (_sync) return _leases.Count == 0; } }

        /// <summary>
        /// 执行Acquire操作。
        /// </summary>
        /// <param name="peerId">peer Id参数。</param>
        /// <returns>操作结果。</returns>
        public uint Acquire(ulong peerId)
        {
            lock (_sync)
            {
                if (_leases.TryGetValue(peerId, out uint existing)) return existing;
                for (uint attempts = 0; attempts < _maximumHost; attempts++)
                {
                    uint host = _nextHost++;
                    if (_nextHost > _maximumHost) _nextHost = 1;
                    uint address = _network | host;
                    if (!_used.Add(address)) continue;
                    _leases.Add(peerId, address);
                    return address;
                }
                throw new InvalidOperationException("虚拟 IPv4 租约池已经耗尽。");
            }
        }

        /// <summary>
        /// 执行Release操作。
        /// </summary>
        /// <param name="peerId">peer Id参数。</param>
        public void Release(ulong peerId)
        {
            lock (_sync)
            {
                if (_leases.Remove(peerId, out uint address)) _used.Remove(address);
            }
        }
    }
}
