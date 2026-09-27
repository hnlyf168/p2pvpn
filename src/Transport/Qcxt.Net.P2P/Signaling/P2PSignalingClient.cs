using Qcxt.Net.P2P.Links;
using Qcxt.Net.P2P.Protocol;
using Qcxt.Net.P2P.Punching;
using Qcxt.Net.P2P.Relay;

namespace Qcxt.Net.P2P.Signaling;

/// <summary>包含协调服务器发现的一个对端及其当前候选状态。</summary>
/// <param name="PeerId">稳定的文本对端名称。</param>
/// <param name="NumericPeerId">稳定的数字线路标识。</param>
/// <param name="PublicEndPoint">服务器观察到的公网 UDP 端点。</param>
/// <param name="PrivateEndPoint">可选的同局域网候选端点。</param>
/// <param name="TcpPublicEndPoint">服务器观察到的公网 TCP 候选端点。</param>
/// <param name="TcpPrivateEndPoint">可选的同局域网 TCP 候选端点。</param>
/// <param name="DirectConnected">当前是否存在活动的已认证 QUIC 或 TCP 直连路径。</param>
/// <param name="DirectTransport">当前首选直连传输类型。</param>
/// <param name="VirtualAddress">协调服务器在逻辑会话内分配的 IPv4 地址。</param>
/// <param name="DirectLocalEndPoint">实际直连链路在本机使用的端点。</param>
/// <param name="DirectRemoteEndPoint">实际直连链路连接到的对端端点。</param>
public sealed record DiscoveredPeer(string PeerId, ulong NumericPeerId, IPEndPoint PublicEndPoint,
    IPEndPoint? PrivateEndPoint, IPEndPoint? TcpPublicEndPoint, IPEndPoint? TcpPrivateEndPoint,
    bool DirectConnected, P2PTransportKind DirectTransport, IPAddress VirtualAddress,
    IPEndPoint? DirectLocalEndPoint, IPEndPoint? DirectRemoteEndPoint);

/// <summary>维护一条已认证的协调服务器连接、中转回退路径及 QUIC/TCP 直连升级。</summary>
public sealed class P2PSignalingClient : IAsyncDisposable
{
    private const uint DirectHelloMagic = 0x51584432;
    private const int DirectHelloLength = 32;
    private readonly P2PConnectionOptions _options;
    private readonly IQuicKeyProvider _keyProvider;
    private readonly ulong _sessionId;
    private readonly ulong _localPeerId;
    private readonly ConcurrentDictionary<ulong, PeerState> _peers = new();
    private readonly PeerRequestLimiter _punchRequests = new();
    private readonly ConcurrentDictionary<long, Task> _backgroundTasks = new();
    private readonly CancellationTokenSource _lifetime = new();
    private Socket? _socket;
    private QuicSharedUdpEndpoint? _endpoint;
    private QuicConnection? _serverConnection;
    private P2PControlChannel? _control;
    private P2PHolePuncher? _puncher;
    private readonly TcpHolePunchClient _tcpPuncher = new();
    private Socket? _tcpListener;
    private IPEndPoint? _tcpLocalEndPoint;
    private IPEndPoint? _tcpPublicEndPoint;
    private Task? _controlTask;
    private Task? _relayDatagramTask;
    private Task? _directAcceptTask;
    private Task? _tcpAcceptTask;
    private Task? _maintenanceTask;
    private IPEndPoint? _publicEndPoint;
    private uint _virtualAddress;
    private int _virtualPrefixLength;
    private int _connected;
    private int _disposed;
    private long _backgroundTaskId;

    /// <summary>创建已认证的信令客户端。</summary>
    /// <param name="options">本地会话身份和资源限制。</param>
    /// <param name="keyProvider">由授权网状网络成员共享的 QUIC 密钥提供程序。</param>
    public P2PSignalingClient(P2PConnectionOptions options, IQuicKeyProvider keyProvider)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(keyProvider);
        options.Validate();
        _options = options;
        _keyProvider = keyProvider;
        _sessionId = P2PFrameCodec.HashIdentifier(options.SessionId);
        _localPeerId = P2PFrameCodec.HashIdentifier(options.PeerId);
    }

    /// <summary>发现对端或其候选端点发生变化时触发。</summary>
    public event Action<DiscoveredPeer>? PeerChanged;
    /// <summary>打洞开始、失败、成功、断开或安排重试时触发。</summary>
    public event Action<P2PTraversalEvent>? TraversalStateChanged;
    /// <summary>每条就绪的中转或直连路径都会触发；客户端仍保留生命周期所有权。</summary>
    public event Action<ulong, IP2PLink>? LinkEstablished;
    /// <summary>发现同一对端的新进程代际时触发，并且一定早于该代际的首条链路发布。</summary>
    public event Action<ulong>? PeerGenerationStarted;
    /// <summary>协调服务器连接意外停止后触发。</summary>
    public event Action<Exception?>? Disconnected;
    /// <summary>获取已知对端的线程安全快照。</summary>
    public IReadOnlyList<DiscoveredPeer> DiscoveredPeers => _peers.Values.Select(static peer => peer.Snapshot()).ToArray();
    /// <summary>获取协调服务器观察到的公网端点。</summary>
    public IPEndPoint? PublicEndPoint => _publicEndPoint;
    /// <summary>获取协调服务器分配的本地虚拟 IPv4 地址。</summary>
    public IPAddress? VirtualAddress => _virtualAddress == 0 ? null : UInt32ToAddress(_virtualAddress);
    /// <summary>获取协调服务器分配的虚拟 IPv4 网络前缀长度。</summary>
    public int VirtualPrefixLength => Volatile.Read(ref _virtualPrefixLength);
    /// <summary>获取由中转控制、打洞和 QUIC 直连共享的已绑定本地 UDP 端点。</summary>
    public IPEndPoint? LocalEndPoint => _endpoint?.LocalEndPoint;
    /// <summary>获取用于 TCP 打洞和入站直连的固定本地端点。</summary>
    public IPEndPoint? LocalTcpEndPoint => _tcpLocalEndPoint;
    /// <summary>获取协调服务器观察到的公网 TCP 端点。</summary>
    public IPEndPoint? PublicTcpEndPoint => _tcpPublicEndPoint;
    /// <summary>获取本机连接协调/中转服务器时实际使用的端点。</summary>
    public IPEndPoint? ServerLocalEndPoint => _serverConnection?.LocalEndPoint;
    /// <summary>获取当前协调/中转服务器的实际远程端点。</summary>
    public IPEndPoint? ServerRemoteEndPoint => _serverConnection?.RemoteEndPoint;
    /// <summary>获取已认证的协调服务器连接是否处于活动状态。</summary>
    public bool IsConnected => Volatile.Read(ref _connected) != 0 && _serverConnection?.IsConnected == true;

    /// <summary>从一个持久 UDP 端口连接协调服务器，并启动所有数据泵。</summary>
    /// <param name="serverEndPoint">协调服务器 UDP 端点。</param>
    /// <param name="localEndPoint">可选的真实本地接口和端口。</param>
    /// <param name="cancellationToken">仅用于取消初始连接建立的标记。</param>
    /// <returns>收到注册确认后结束的异步操作。</returns>
    public async Task ConnectAsync(IPEndPoint serverEndPoint, IPEndPoint? localEndPoint = null,
        CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) != 0, this);
        if (Interlocked.CompareExchange(ref _connected, 1, 0) != 0) throw new InvalidOperationException("客户端已经连接。");
        try
        {
            _socket = new Socket(serverEndPoint.AddressFamily, SocketType.Dgram, ProtocolType.Udp)
            {
                ReceiveBufferSize = 8 * 1024 * 1024,
                SendBufferSize = 8 * 1024 * 1024
            };
            DisableUdpConnectionReset(_socket);
            _socket.Bind(localEndPoint ?? (serverEndPoint.AddressFamily == AddressFamily.InterNetwork
                ? new IPEndPoint(IPAddress.Any, 0) : new IPEndPoint(IPAddress.IPv6Any, 0)));
            IPEndPoint privateCandidate = ResolvePrivateCandidate(serverEndPoint, (IPEndPoint)_socket.LocalEndPoint!);
            byte[]? tcpObservationToken = null;
            IPEndPoint? tcpPrivateCandidate = null;
            if (_options.EnableTcpHolePunching)
            {
                tcpObservationToken = RandomNumberGenerator.GetBytes(32);
                tcpPrivateCandidate = new IPEndPoint(privateCandidate.Address,
                    ((IPEndPoint)_socket.LocalEndPoint!).Port);
                _tcpLocalEndPoint = tcpPrivateCandidate;
            }
            _endpoint = new QuicSharedUdpEndpoint(_socket, CreateInboundOptions(), ownsSocket: true);
            _serverConnection = await _endpoint.ConnectAsync(CreateClientOptions(serverEndPoint, "p2p-coordinator"),
                cancellationToken).ConfigureAwait(false);
            _control = new P2PControlChannel(_serverConnection.OpenBidirectionalStream());
            await _control.SendAsync(new P2PControlMessage(P2PControlType.Register,
                SessionId: _options.SessionId, PeerId: _options.PeerId,
                PublicEndPoint: _options.AdvertisedUdpEndPoint,
                PrivateEndPoint: privateCandidate, TcpPrivateEndPoint: tcpPrivateCandidate,
                TcpPublicEndPoint: _options.AdvertisedTcpEndPoint,
                Token: tcpObservationToken,
                Payload: Encoding.UTF8.GetBytes(_options.ClientVersion + "\n" + _options.ClientPlatform + "\n" + _options.RegistrationCredential)),
                cancellationToken).ConfigureAwait(false);
            P2PControlMessage? registered = await _control.ReceiveAsync(cancellationToken).ConfigureAwait(false);
            if (registered is null || registered.Type != P2PControlType.Registered ||
                registered.SourcePeerId != _localPeerId || registered.PublicEndPoint is null ||
                registered.VirtualAddress == 0 || registered.VirtualPrefixLength is < 8 or > 30)
                throw new InvalidDataException("协调服务器返回了无效的注册确认。");
            _publicEndPoint = registered.PublicEndPoint;
            _virtualAddress = registered.VirtualAddress;
            Volatile.Write(ref _virtualPrefixLength, registered.VirtualPrefixLength);
            if (_options.EnableTcpHolePunching && tcpPrivateCandidate is not null && tcpObservationToken is not null)
            {
                try
                {
                    _tcpPublicEndPoint = await ObserveTcpMappingAsync(serverEndPoint, tcpPrivateCandidate,
                        tcpObservationToken, cancellationToken).ConfigureAwait(false);
                }
                catch when (!cancellationToken.IsCancellationRequested) { }
                finally { CryptographicOperations.ZeroMemory(tcpObservationToken); }
                TryStartTcpListener(tcpPrivateCandidate);
            }
            if (_options.EnableUdpHolePunching)
                _puncher = new P2PHolePuncher(_endpoint, _localPeerId, new P2PHolePunchOptions
                {
                    Timeout = _options.UdpPunchTimeout,
                    PublicPortFanout = _options.UdpPublicPortFanout
                });
            _controlTask = ObserveBackgroundAsync(ControlLoopAsync(_lifetime.Token));
            _relayDatagramTask = ObserveBackgroundAsync(RelayDatagramLoopAsync(_lifetime.Token));
            if (_options.EnableUdpHolePunching)
                _directAcceptTask = ObserveBackgroundAsync(DirectAcceptLoopAsync(_lifetime.Token));
            if (_tcpListener is not null)
                _tcpAcceptTask = ObserveBackgroundAsync(TcpAcceptLoopAsync(_lifetime.Token));
            _maintenanceTask = ObserveBackgroundAsync(MaintenanceLoopAsync(_lifetime.Token));
        }
        catch
        {
            Volatile.Write(ref _connected, 0);
            await CleanupNetworkAsync().ConfigureAwait(false);
            throw;
        }
    }

    /// <summary>通过与 QUIC 相同编号的 TCP 端口向协调服务器登记公网映射。</summary>
    /// <param name="serverEndPoint">协调服务器 UDP 端点；TCP 会合服务使用相同端口。</param>
    /// <param name="localEndPoint">准备供后续打洞复用的固定本地 TCP 端点。</param>
    /// <param name="token">已通过 QUIC 注册消息发送的一次性随机令牌。</param>
    /// <param name="cancellationToken">用于取消登记的标记。</param>
    /// <returns>协调服务器观察到的公网 TCP 端点。</returns>
    private async Task<IPEndPoint?> ObserveTcpMappingAsync(IPEndPoint serverEndPoint, IPEndPoint localEndPoint,
        byte[] token, CancellationToken cancellationToken)
    {
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, _lifetime.Token);
        timeout.CancelAfter(TimeSpan.FromMilliseconds(Math.Min(2500, _options.TcpPunchTimeout.TotalMilliseconds)));
        using var socket = new Socket(serverEndPoint.AddressFamily, SocketType.Stream, ProtocolType.Tcp)
        { NoDelay = true };
        TcpHolePunchClient.ConfigureReusablePort(socket);
        socket.Bind(localEndPoint);
        await socket.ConnectAsync(serverEndPoint, timeout.Token).ConfigureAwait(false);
        using var stream = new NetworkStream(socket, ownsSocket: false);
        byte[] request = ArrayPool<byte>.Shared.Rent(P2PTcpProtocol.ObservationRequestLength);
        byte[] response = ArrayPool<byte>.Shared.Rent(P2PTcpProtocol.ObservationResponseLength);
        try
        {
            P2PTcpProtocol.WriteObservationRequest(request, token);
            await stream.WriteAsync(request.AsMemory(0, P2PTcpProtocol.ObservationRequestLength), timeout.Token)
                .ConfigureAwait(false);
            await P2PTcpProtocol.ReadExactlyAsync(stream,
                response.AsMemory(0, P2PTcpProtocol.ObservationResponseLength), timeout.Token).ConfigureAwait(false);
            return P2PTcpProtocol.TryReadObservationResponse(
                response.AsSpan(0, P2PTcpProtocol.ObservationResponseLength), out IPEndPoint? observed)
                ? observed : null;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(request.AsSpan(0, P2PTcpProtocol.ObservationRequestLength));
            ArrayPool<byte>.Shared.Return(request);
            ArrayPool<byte>.Shared.Return(response);
        }
    }

    /// <summary>启动可与出站打洞套接字共享固定端口的 TCP 入站监听。</summary>
    /// <param name="localEndPoint">真实本地接口及固定端口。</param>
    private void TryStartTcpListener(IPEndPoint localEndPoint)
    {
        Socket? listener = null;
        try
        {
            listener = new Socket(localEndPoint.AddressFamily, SocketType.Stream, ProtocolType.Tcp)
            { NoDelay = true };
            TcpHolePunchClient.ConfigureReusablePort(listener);
            listener.Bind(localEndPoint);
            listener.Listen(256);
            _tcpListener = listener;
        }
        catch
        {
            listener?.Dispose();
            _tcpListener = null;
        }
    }

    /// <summary>为一个已知对端请求新的双向同时打洞提议。</summary>
    /// <param name="targetPeerId">数字形式的目标对端标识。</param>
    /// <param name="cancellationToken">用于取消控制消息排队的标记。</param>
    /// <returns>请求提交后结束的异步操作。</returns>
    public ValueTask RequestPunchAsync(ulong targetPeerId, CancellationToken cancellationToken = default)
    {
        if (_control is null) throw new InvalidOperationException("客户端尚未连接。");
        if (!_peers.TryGetValue(targetPeerId, out var peer) ||
            !peer.CanAttemptDirect(_options.MaximumHolePunchRounds) ||
            !_punchRequests.TryAcquire(targetPeerId, Environment.TickCount64,
                (long)_options.HolePunchRetryInterval.TotalMilliseconds)) return ValueTask.CompletedTask;
        return _control.SendAsync(new P2PControlMessage(P2PControlType.PunchRequest,
            TargetPeerId: targetPeerId), cancellationToken);
    }

    /// <summary>处理对端提议、离开通知、可靠中转、心跳回复和错误。</summary>
    /// <param name="cancellationToken">客户端生命周期取消标记。</param>
    /// <returns>可靠控制流关闭时结束的任务。</returns>
    private async Task ControlLoopAsync(CancellationToken cancellationToken)
    {
        while (!cancellationToken.IsCancellationRequested)
        {
            P2PControlMessage? message = await _control!.ReceiveAsync(cancellationToken).ConfigureAwait(false);
            if (message is null) throw new EndOfStreamException("协调服务器控制流已关闭。");
            switch (message.Type)
            {
                case P2PControlType.PeerOffer:
                    if (message.SourcePeerId != 0 && message.SourcePeerId != _localPeerId &&
                        message.PublicEndPoint is not null && message.Token is { Length: 32 } &&
                        message.VirtualAddress != 0)
                        HandlePeerOffer(message);
                    break;
                case P2PControlType.PeerGone:
                    await RemovePeerAsync(message.SourcePeerId).ConfigureAwait(false);
                    break;
                case P2PControlType.RelayReliable:
                    if (!message.Payload.IsEmpty && _peers.TryGetValue(message.SourcePeerId, out PeerState? source))
                        await source.ReliableRelay.DeliverAsync(message.Payload, cancellationToken).ConfigureAwait(false);
                    break;
                case P2PControlType.Error:
                    throw new IOException($"协调服务器拒绝了客户端：{message.Error}");
            }
        }
    }

    /// <summary>立即创建中转回退路径，并启动一个去重后的直连尝试。</summary>
    /// <param name="message">已校验的对端提议。</param>
    private void HandlePeerOffer(P2PControlMessage message)
    {
        bool generationStarted = false;
        PeerState peer = _peers.GetOrAdd(message.SourcePeerId, id =>
        {
            generationStarted = true;
            return CreatePeerState(id, message.PeerId, message.PublicEndPoint!, message.PrivateEndPoint,
                message.TcpPublicEndPoint, message.TcpPrivateEndPoint, message.Token!, message.VirtualAddress);
        });
        generationStarted |= peer.Update(message.PeerId, message.PublicEndPoint!, message.PrivateEndPoint,
            message.TcpPublicEndPoint, message.TcpPrivateEndPoint, message.Token!, message.VirtualAddress);
        if (generationStarted) RaisePeerGenerationStarted(peer.PeerId);
        if (_options.EnableCoordinatorRelay && peer.TryPublishRelays())
        {
            PublishLink(peer.PeerId, peer.ReliableRelay);
            PublishLink(peer.PeerId, peer.DatagramRelay);
        }
        RaisePeerChanged(peer.Snapshot());
        bool requested = !message.Payload.IsEmpty && message.Payload.Span[0] == 1;
        if (_options.EagerHolePunching || requested)
        {
            peer.MarkApplicationTraffic();
            StartDirectAttempt(peer);
        }
    }

    /// <summary>通知订阅者开始新的对端进程代际，并隔离订阅者异常。</summary>
    /// <param name="peerId">开始新代际的数字对端标识。</param>
    private void RaisePeerGenerationStarted(ulong peerId)
    {
        Action<ulong>? handlers = PeerGenerationStarted;
        if (handlers is null) return;
        foreach (Action<ulong> handler in handlers.GetInvocationList())
        {
            try { handler(peerId); } catch { }
        }
    }

    /// <summary>为一个对端同时构造可靠和低延迟中转路径。</summary>
    /// <param name="peerId">数字形式的对端标识。</param>
    /// <param name="peerName">文本形式的对端名称。</param>
    /// <param name="publicEndPoint">服务器观察到的候选端点。</param>
    /// <param name="privateEndPoint">局域网候选端点。</param>
    /// <param name="tcpPublicEndPoint">服务器观察到的 TCP 公网候选端点。</param>
    /// <param name="tcpPrivateEndPoint">对端声明的 TCP 局域网候选端点。</param>
    /// <param name="token">配对专用令牌。</param>
    /// <param name="virtualAddress">协调服务器分配的对端 IPv4 地址。</param>
    /// <returns>已初始化的对端状态。</returns>
    private PeerState CreatePeerState(ulong peerId, string peerName, IPEndPoint publicEndPoint,
        IPEndPoint? privateEndPoint, IPEndPoint? tcpPublicEndPoint, IPEndPoint? tcpPrivateEndPoint,
        byte[] token, uint virtualAddress)
    {
        int datagramMaximum = Math.Max(64, (_serverConnection?.MaximumDatagramPayloadSize ?? 1200) -
            P2PRelayDatagramCodec.HeaderLength);
        var reliable = new P2PRelayLink($"relay-stream-{peerId:x16}", P2PTransportKind.QuicRelay,
            _options.MaximumFrameSize, _options.ReceiveQueueCapacity,
            (packet, traffic, ct) => SendReliableRelayAsync(peerId, packet, traffic, ct));
        var datagram = new P2PRelayLink($"relay-dgram-{peerId:x16}", P2PTransportKind.QuicDatagramRelay,
            datagramMaximum, _options.ReceiveQueueCapacity,
            (packet, traffic, ct) => SendDatagramRelayAsync(peerId, packet, traffic, ct));
        return new PeerState(peerId, peerName, publicEndPoint, privateEndPoint, tcpPublicEndPoint,
            tcpPrivateEndPoint, token, virtualAddress, reliable, datagram);
    }

    /// <summary>通过可靠协调服务器流发送一个不透明数据帧。</summary>
    /// <param name="target">目标对端。</param>
    /// <param name="packet">已编码的 P2P 帧。</param>
    /// <param name="trafficClass">流量等级。</param>
    /// <param name="cancellationToken">用于取消排队的标记。</param>
    /// <returns>控制队列接纳消息后结束的异步操作。</returns>
    private ValueTask SendReliableRelayAsync(ulong target, ReadOnlyMemory<byte> packet,
        P2PTrafficClass trafficClass, CancellationToken cancellationToken) =>
        _control!.SendAsync(new P2PControlMessage(P2PControlType.RelayReliable,
            SourcePeerId: _localPeerId, TargetPeerId: target, Payload: packet,
            TrafficClass: trafficClass), cancellationToken);

    /// <summary>通过低延迟 QUIC DATAGRAM 中转发送一个不透明数据帧。</summary>
    /// <param name="target">目标对端。</param>
    /// <param name="packet">已编码的 P2P 帧。</param>
    /// <param name="trafficClass">流量等级。</param>
    /// <param name="cancellationToken">用于取消排队的标记。</param>
    /// <returns>QUIC 队列接纳消息后结束的异步操作。</returns>
    private async ValueTask SendDatagramRelayAsync(ulong target, ReadOnlyMemory<byte> packet,
        P2PTrafficClass trafficClass, CancellationToken cancellationToken)
    {
        int total = P2PRelayDatagramCodec.HeaderLength + packet.Length;
        if (_serverConnection is null || total > _serverConnection.MaximumDatagramPayloadSize)
            throw new ArgumentOutOfRangeException(nameof(packet));
        P2POwnedBuffer owner = P2POwnedBuffer.Rent(total);
        try
        {
            P2PRelayDatagramCodec.Write(owner.Memory.Span, _sessionId, _localPeerId, target,
                trafficClass, packet.Span);
            await QuicDatagramP2PLink.SendPrioritizedAsync(_serverConnection, owner.Memory,
                trafficClass, cancellationToken).ConfigureAwait(false);
        }
        finally { owner.Dispose(); }
    }

    /// <summary>根据已认证来源接收并路由低延迟中转 DATAGRAM 数据包。</summary>
    /// <param name="cancellationToken">客户端生命周期取消标记。</param>
    /// <returns>协调服务器连接关闭时结束的任务。</returns>
    private async Task RelayDatagramLoopAsync(CancellationToken cancellationToken)
    {
        while (!cancellationToken.IsCancellationRequested)
        {
            using QuicDatagram datagram = await _serverConnection!.ReceiveDatagramAsync(cancellationToken)
                .ConfigureAwait(false);
            ulong session, source, target;
            bool valid;
            {
                valid = P2PRelayDatagramCodec.TryRead(datagram.Memory.Span, out session, out source,
                    out target, out _, out _);
            }
            if (!valid || session != _sessionId || target != _localPeerId ||
                !_peers.TryGetValue(source, out PeerState? peer)) continue;
            await peer.DatagramRelay.DeliverAsync(datagram.Memory[P2PRelayDatagramCodec.HeaderLength..],
                cancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>当不存在等效活动任务时，为对端启动一个后台打洞和 QUIC 升级任务。</summary>
    /// <param name="peer">远程对端状态。</param>
    private void StartDirectAttempt(PeerState peer)
    {
        if (_puncher is null && (!_options.EnableTcpHolePunching || _tcpLocalEndPoint is null)) return;
        if (!peer.TryBeginDirectAttempt(_options.MaximumHolePunchRounds,
            (long)_options.HolePunchRetryInterval.TotalMilliseconds, out int attemptNumber)) return;
        TrackBackground(EstablishDirectAsync(peer, attemptNumber, _lifetime.Token));
    }

    /// <summary>同时打通双方候选端点，并按确定规则由一方发起 QUIC 直连。</summary>
    /// <param name="peer">远程对端状态。</param>
    /// <param name="attemptNumber">本地递增的尝试序号。</param>
    /// <param name="cancellationToken">客户端生命周期取消标记。</param>
    /// <returns>成功或有界失败后结束的任务。</returns>
    private async Task EstablishDirectAsync(PeerState peer, int attemptNumber,
        CancellationToken cancellationToken)
    {
        try
        {
            using var roundLifetime = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            Task quicAttempt = _puncher is not null && !peer.HasQuicDirect
                ? EstablishQuicDirectAsync(peer, attemptNumber, roundLifetime.Token)
                : Task.CompletedTask;
            Task tcpAttempt = !peer.HasTcpDirect && _options.EnableTcpHolePunching && _tcpLocalEndPoint is not null
                ? EstablishTcpDirectAsync(peer, attemptNumber, roundLifetime.Token)
                : Task.CompletedTask;
            var remaining = new HashSet<Task> { quicAttempt, tcpAttempt };
            while (remaining.Count != 0)
            {
                Task completed = await Task.WhenAny(remaining).ConfigureAwait(false);
                remaining.Remove(completed);
                await completed.ConfigureAwait(false);
                if (!peer.HasDirect) continue;
                roundLifetime.Cancel();
                break;
            }
            await Task.WhenAll(quicAttempt, tcpAttempt).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { }
        finally
        {
            bool directSucceeded = peer.HasDirect;
            int failedRounds = peer.EndDirectAttempt(directSucceeded);
            RaisePeerChanged(peer.Snapshot());
            if (!cancellationToken.IsCancellationRequested && !directSucceeded &&
                failedRounds >= _options.MaximumHolePunchRounds)
            {
                RaiseTraversal(peer, P2PTraversalEventKind.AttemptsExhausted, P2PTransportKind.Unknown,
                    attemptNumber, detail: $"UDP 和 TCP 已连续失败 {failedRounds} 轮，停止主动打洞并继续使用服务器中继。");
            }
            else if (!cancellationToken.IsCancellationRequested && !directSucceeded)
            {
                RaiseTraversal(peer, P2PTraversalEventKind.RetryScheduled,
                    P2PTransportKind.Unknown, attemptNumber, retryDelay: _options.HolePunchRetryInterval,
                    detail: $"UDP 和 TCP 均未成功，当前继续使用服务器中继；已失败 {failedRounds}/{_options.MaximumHolePunchRounds} 轮。");
            }
        }
    }

    /// <summary>执行一轮 UDP 双向打洞，并在确认端点后建立经过身份校验的 QUIC 直连。</summary>
    /// <param name="peer">远程对端状态。</param>
    /// <param name="attemptNumber">本地递增的尝试序号。</param>
    /// <param name="cancellationToken">客户端生命周期取消标记。</param>
    /// <returns>成功或有界失败后结束的任务。</returns>
    private async Task EstablishQuicDirectAsync(PeerState peer, int attemptNumber,
        CancellationToken cancellationToken)
    {
        P2PPunchCandidate candidate = peer.PunchCandidate();
        if (!IsDirectCandidateAllowed(peer, candidate.PublicEndPoint))
        {
            RaiseTraversal(peer, P2PTraversalEventKind.UdpAttemptFailed, P2PTransportKind.Quic,
                attemptNumber, candidate.PublicEndPoint,
                detail: "公网候选命中该对端的远端子网路由，已阻止递归 VPN 直连。");
            return;
        }
        if (candidate.PrivateEndPoint is not null &&
            !IsDirectCandidateAllowed(peer, candidate.PrivateEndPoint))
        {
            RaiseTraversal(peer, P2PTraversalEventKind.UdpAttemptFailed, P2PTransportKind.Quic,
                attemptNumber, candidate.PrivateEndPoint,
                detail: "局域网候选命中该对端的远端子网路由，已过滤此候选。");
            candidate = candidate with { PrivateEndPoint = null };
        }
        RaiseTraversal(peer, P2PTraversalEventKind.UdpAttemptStarted, P2PTransportKind.Quic,
            attemptNumber, candidate.PublicEndPoint,
            detail: $"双方同时探测公网和局域网 UDP 候选，公网端口上下各猜测 {_options.UdpPublicPortFanout} 个。");
        try
        {
            P2PPunchResult? result = await _puncher!.PunchAsync(candidate, cancellationToken).ConfigureAwait(false);
            if (result is null)
            {
                RaiseTraversal(peer, P2PTraversalEventKind.UdpAttemptFailed, P2PTransportKind.Quic,
                    attemptNumber, candidate.PublicEndPoint, detail: "UDP 打洞在限定时间内没有收到认证确认。");
                return;
            }
            if (!IsDirectCandidateAllowed(peer, result.Value.RemoteEndPoint))
            {
                RaiseTraversal(peer, P2PTraversalEventKind.UdpAttemptFailed, P2PTransportKind.Quic,
                    attemptNumber, result.Value.RemoteEndPoint,
                    detail: "打洞返回端点命中远端子网路由，已拒绝伪直连并保留中继。");
                return;
            }
            peer.SetConfirmedEndPoint(result.Value.RemoteEndPoint);
            if (_localPeerId > peer.PeerId)
            {
                QuicConnection connection = await _endpoint!.ConnectAsync(CreateClientOptions(
                    result.Value.RemoteEndPoint, $"p2p-peer-{peer.PeerId:x16}"), cancellationToken)
                    .ConfigureAwait(false);
                try
                {
                    QuicStream stream = connection.OpenBidirectionalStream();
                    await ExchangeDirectHelloAsync(stream, peer.PeerId, initiator: true, cancellationToken)
                        .ConfigureAwait(false);
                    PublishDirect(peer, connection, stream);
                    connection = null!;
                }
                finally
                {
                    if (connection is not null) await connection.DisposeAsync().ConfigureAwait(false);
                }
            }
            else
            {
                long deadline = Environment.TickCount64 + 2500;
                while (!peer.HasQuicDirect && Environment.TickCount64 < deadline)
                    await Task.Delay(25, cancellationToken).ConfigureAwait(false);
                if (!peer.HasQuicDirect)
                    RaiseTraversal(peer, P2PTraversalEventKind.UdpAttemptFailed, P2PTransportKind.Quic,
                        attemptNumber, result.Value.RemoteEndPoint,
                        detail: "UDP 打洞已确认，但没有在限定时间内收到对端 QUIC 连接。");
            }
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { }
        catch (Exception exception)
        {
            RaiseTraversal(peer, P2PTraversalEventKind.UdpAttemptFailed, P2PTransportKind.Quic,
                attemptNumber, candidate.PublicEndPoint, detail: $"UDP/QUIC 尝试异常：{exception.Message}");
        }
    }

    /// <summary>并发连接远程 TCP 候选端点，完成配对 HMAC 认证并发布后备直连。</summary>
    /// <param name="peer">远程对端状态。</param>
    /// <param name="attemptNumber">本地递增的尝试序号。</param>
    /// <param name="cancellationToken">客户端生命周期取消标记。</param>
    /// <returns>成功或有界失败后结束的任务。</returns>
    private async Task EstablishTcpDirectAsync(PeerState peer, int attemptNumber,
        CancellationToken cancellationToken)
    {
        IPEndPoint[] candidates = peer.TcpCandidates(_options.TcpPublicPortFanout,
            endpoint => IsDirectCandidateAllowed(peer, endpoint));
        IPEndPoint? primary = candidates.FirstOrDefault();
        RaiseTraversal(peer, P2PTraversalEventKind.TcpAttemptStarted, P2PTransportKind.TcpDirect,
            attemptNumber, primary,
            detail: $"双方使用固定本地端口同时连接 {candidates.Length} 个 TCP 候选，公网端口上下各猜测 {_options.TcpPublicPortFanout} 个。");
        if (candidates.Length == 0 || _tcpLocalEndPoint is null)
        {
            RaiseTraversal(peer, P2PTraversalEventKind.TcpAttemptFailed, P2PTransportKind.TcpDirect,
                attemptNumber, detail: "服务器尚未返回可用的 TCP 候选端点。");
            return;
        }
        Socket? socket = null;
        try
        {
            socket = await _tcpPuncher.ConnectAuthenticatedSocketAsync(candidates, _tcpLocalEndPoint,
                checked((int)_options.TcpPunchTimeout.TotalMilliseconds), async (connected, token) =>
                {
                    await ExchangeTcpHelloAsync(connected, peer, readFirst: false, token).ConfigureAwait(false);
                    return true;
                }, cancellationToken).ConfigureAwait(false);
            if (cancellationToken.IsCancellationRequested) return;
            if (socket is null)
            {
                RaiseTraversal(peer, P2PTraversalEventKind.TcpAttemptFailed, P2PTransportKind.TcpDirect,
                    attemptNumber, primary, detail: "TCP 同时打开在限定时间内没有建立连接。");
                return;
            }
            PublishTcpDirect(peer, socket);
            socket = null;
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { }
        catch (Exception exception)
        {
            RaiseTraversal(peer, P2PTraversalEventKind.TcpAttemptFailed, P2PTransportKind.TcpDirect,
                attemptNumber, primary, detail: $"TCP 打洞或身份认证异常：{exception.Message}");
        }
        finally { socket?.Dispose(); }
    }

    /// <summary>接受入站 QUIC 直连并绑定其显式对端握手信息。</summary>
    /// <param name="cancellationToken">客户端生命周期取消标记。</param>
    /// <returns>在客户端释放期间结束的任务。</returns>
    private async Task DirectAcceptLoopAsync(CancellationToken cancellationToken)
    {
        while (!cancellationToken.IsCancellationRequested)
        {
            QuicConnection connection = await _endpoint!.AcceptConnectionAsync(cancellationToken).ConfigureAwait(false);
            TrackBackground(HandleInboundDirectAsync(connection, cancellationToken));
        }
    }

    /// <summary>持续接受来自任意已提议房间对端的 TCP 直连。</summary>
    /// <param name="cancellationToken">客户端生命周期取消标记。</param>
    /// <returns>客户端释放时结束的任务。</returns>
    private async Task TcpAcceptLoopAsync(CancellationToken cancellationToken)
    {
        try
        {
            while (!cancellationToken.IsCancellationRequested)
            {
                Socket socket = await _tcpListener!.AcceptAsync(cancellationToken).ConfigureAwait(false);
                TrackBackground(HandleInboundTcpAsync(socket, cancellationToken));
            }
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { }
        catch (ObjectDisposedException) when (cancellationToken.IsCancellationRequested) { }
        catch (SocketException) when (cancellationToken.IsCancellationRequested) { }
    }

    /// <summary>校验入站 TCP 身份消息并发布对应多对端后备路径。</summary>
    /// <param name="socket">已接受的 TCP 套接字。</param>
    /// <param name="cancellationToken">客户端生命周期取消标记。</param>
    /// <returns>认证成功发布或失败释放后结束的任务。</returns>
    private async Task HandleInboundTcpAsync(Socket socket, CancellationToken cancellationToken)
    {
        try
        {
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            timeout.CancelAfter(_options.TcpPunchTimeout);
            byte[] first = ArrayPool<byte>.Shared.Rent(P2PTcpProtocol.DirectHelloLength);
            try
            {
                using var stream = new NetworkStream(socket, ownsSocket: false);
                await P2PTcpProtocol.ReadExactlyAsync(stream,
                    first.AsMemory(0, P2PTcpProtocol.DirectHelloLength), timeout.Token).ConfigureAwait(false);
                if (!P2PTcpProtocol.TryReadDirectRoute(first.AsSpan(0, P2PTcpProtocol.DirectHelloLength),
                    out ulong source, out ulong target) || target != _localPeerId ||
                    !_peers.TryGetValue(source, out PeerState? peer)) return;
                if (socket.RemoteEndPoint is not IPEndPoint remote ||
                    !IsDirectCandidateAllowed(peer, remote)) return;
                await ExchangeTcpHelloAsync(socket, peer, readFirst: true, timeout.Token, first).ConfigureAwait(false);
                PublishTcpDirect(peer, socket);
                socket = null!;
            }
            finally
            {
                CryptographicOperations.ZeroMemory(first.AsSpan(0, P2PTcpProtocol.DirectHelloLength));
                ArrayPool<byte>.Shared.Return(first);
            }
        }
        catch { }
        finally { socket?.Dispose(); }
    }

    /// <summary>交换并校验配对专用的 TCP 直连身份消息。</summary>
    /// <param name="socket">已连接的 TCP 套接字。</param>
    /// <param name="peer">预期远程对端。</param>
    /// <param name="readFirst">是否已经由入站处理读取了远端消息。</param>
    /// <param name="cancellationToken">用于取消认证输入输出的标记。</param>
    /// <param name="preRead">入站处理预先读取的可选消息缓冲区。</param>
    /// <returns>双方身份均通过认证后结束的任务。</returns>
    private async Task ExchangeTcpHelloAsync(Socket socket, PeerState peer, bool readFirst,
        CancellationToken cancellationToken, byte[]? preRead = null)
    {
        byte[] local = ArrayPool<byte>.Shared.Rent(P2PTcpProtocol.DirectHelloLength);
        byte[]? remote = preRead is null ? ArrayPool<byte>.Shared.Rent(P2PTcpProtocol.DirectHelloLength) : null;
        byte[] token = peer.CopyToken();
        try
        {
            socket.NoDelay = true;
            using var stream = new NetworkStream(socket, ownsSocket: false);
            ReadOnlySpan<byte> received;
            if (readFirst)
            {
                received = preRead!.AsSpan(0, P2PTcpProtocol.DirectHelloLength);
                if (!P2PTcpProtocol.ValidateDirectHello(received, peer.PeerId, _localPeerId, token))
                    throw new InvalidDataException("TCP 直连身份认证失败。");
                P2PTcpProtocol.WriteDirectHello(local, _localPeerId, peer.PeerId, token);
                await stream.WriteAsync(local.AsMemory(0, P2PTcpProtocol.DirectHelloLength), cancellationToken)
                    .ConfigureAwait(false);
            }
            else
            {
                P2PTcpProtocol.WriteDirectHello(local, _localPeerId, peer.PeerId, token);
                await stream.WriteAsync(local.AsMemory(0, P2PTcpProtocol.DirectHelloLength), cancellationToken)
                    .ConfigureAwait(false);
                await P2PTcpProtocol.ReadExactlyAsync(stream,
                    remote!.AsMemory(0, P2PTcpProtocol.DirectHelloLength), cancellationToken).ConfigureAwait(false);
                received = remote.AsSpan(0, P2PTcpProtocol.DirectHelloLength);
                if (!P2PTcpProtocol.ValidateDirectHello(received, peer.PeerId, _localPeerId, token))
                    throw new InvalidDataException("TCP 直连身份认证失败。");
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(token);
            CryptographicOperations.ZeroMemory(local.AsSpan(0, P2PTcpProtocol.DirectHelloLength));
            ArrayPool<byte>.Shared.Return(local);
            if (remote is not null)
            {
                CryptographicOperations.ZeroMemory(remote.AsSpan(0, P2PTcpProtocol.DirectHelloLength));
                ArrayPool<byte>.Shared.Return(remote);
            }
        }
    }

    /// <summary>发布一条经过配对令牌认证的 TCP 直连，并替换旧的 TCP 代次。</summary>
    /// <param name="peer">远程对端状态。</param>
    /// <param name="socket">已经完成身份认证的连接套接字。</param>
    private void PublishTcpDirect(PeerState peer, Socket socket)
    {
        IPEndPoint? remote = socket.RemoteEndPoint as IPEndPoint;
        var link = new TcpP2PLink(socket, _options.MaximumFrameSize,
            $"direct-tcp-{peer.PeerId:x16}-{Guid.NewGuid():N}");
        IP2PLink? old = peer.SetTcpDirect(link);
        if (old is not null) TrackBackground(old.DisposeAsync().AsTask());
        PublishLink(peer.PeerId, link);
        RaisePeerChanged(peer.Snapshot());
        RaiseTraversal(peer, P2PTraversalEventKind.TcpDirectSucceeded, P2PTransportKind.TcpDirect,
            peer.CurrentAttemptNumber, remote, detail: "TCP 打洞和配对身份认证成功。");
        TrackBackground(ObserveTcpClosedAsync(peer, link));
    }

    /// <summary>
    /// 执行Is Direct Candidate Allowed操作。
    /// </summary>
    /// <param name="peer">peer参数。</param>
    /// <param name="endpoint">网络端点。</param>
    /// <returns>操作结果。</returns>
    private bool IsDirectCandidateAllowed(PeerState peer, IPEndPoint endpoint)
    {
        Func<IPAddress, IPEndPoint, bool>? filter = _options.DirectCandidateFilter;
        if (filter is null) return true;
        try { return filter(peer.VirtualAddress, endpoint); }
        catch { return false; }
    }

    /// <summary>仅清除实际关闭的那一代 TCP 直连。</summary>
    private async Task ObserveTcpClosedAsync(PeerState peer, IP2PLink link)
    {
        try { await link.Closed.ConfigureAwait(false); } catch { }
        if (!peer.ClearTcpDirect(link)) return;
        try { await link.DisposeAsync().ConfigureAwait(false); } catch { }
        RaisePeerChanged(peer.Snapshot());
        RaiseTraversal(peer, P2PTraversalEventKind.DirectDisconnected, P2PTransportKind.TcpDirect,
            peer.CurrentAttemptNumber, detail: "TCP 直连已经断开，将保留中继并自动重试。");
    }

    /// <summary>在发布路径前校验入站直连握手信息。</summary>
    /// <param name="connection">入站的已认证组连接。</param>
    /// <param name="cancellationToken">客户端生命周期取消标记。</param>
    /// <returns>路径发布或拒绝后结束的任务。</returns>
    private async Task HandleInboundDirectAsync(QuicConnection connection, CancellationToken cancellationToken)
    {
        try
        {
            QuicStream stream = await connection.AcceptStreamAsync(cancellationToken).ConfigureAwait(false);
            ulong remotePeer = await ExchangeDirectHelloAsync(stream, 0, initiator: false, cancellationToken)
                .ConfigureAwait(false);
            if (!_peers.TryGetValue(remotePeer, out PeerState? peer) ||
                !IsDirectCandidateAllowed(peer, connection.RemoteEndPoint) ||
                !peer.IsExpectedEndpoint(connection.RemoteEndPoint))
                throw new InvalidDataException("入站直连对端尚未完成打洞或信令提议。");
            PublishDirect(peer, connection, stream);
            connection = null!;
        }
        catch { }
        finally { if (connection is not null) await connection.DisposeAsync().ConfigureAwait(false); }
    }

    /// <summary>在数据流成为 P2P 数据链路前交换固定身份前导信息。</summary>
    /// <param name="stream">新建的直连双向流。</param>
    /// <param name="expectedPeer">出站连接预期的对端；入站连接时为零。</param>
    /// <param name="initiator">是否先执行写入。</param>
    /// <param name="cancellationToken">用于取消输入输出的标记。</param>
    /// <returns>已通过校验的远程对端标识。</returns>
    private async Task<ulong> ExchangeDirectHelloAsync(QuicStream stream, ulong expectedPeer, bool initiator,
        CancellationToken cancellationToken)
    {
        byte[] buffer = ArrayPool<byte>.Shared.Rent(DirectHelloLength);
        try
        {
            if (initiator)
            {
                WriteDirectHello(buffer, acknowledgement: false, _localPeerId, expectedPeer);
                await stream.WriteAsync(buffer.AsMemory(0, DirectHelloLength), cancellationToken).ConfigureAwait(false);
                await ReadExactlyAsync(stream, buffer.AsMemory(0, DirectHelloLength), cancellationToken).ConfigureAwait(false);
                if (!TryReadDirectHello(buffer, acknowledgement: true, out ulong source, out ulong target) ||
                    source != expectedPeer || target != _localPeerId) throw new InvalidDataException("直连接收确认无效。");
                return source;
            }
            await ReadExactlyAsync(stream, buffer.AsMemory(0, DirectHelloLength), cancellationToken).ConfigureAwait(false);
            if (!TryReadDirectHello(buffer, acknowledgement: false, out ulong inboundSource, out ulong inboundTarget) ||
                inboundTarget != _localPeerId) throw new InvalidDataException("直连握手信息无效。");
            WriteDirectHello(buffer, acknowledgement: true, _localPeerId, inboundSource);
            await stream.WriteAsync(buffer.AsMemory(0, DirectHelloLength), cancellationToken).ConfigureAwait(false);
            return inboundSource;
        }
        finally { ArrayPool<byte>.Shared.Return(buffer); }
    }

    /// <summary>发布一条直连链路并观察其关闭状态，以便后续重试。</summary>
    /// <param name="peer">远程对端状态。</param>
    /// <param name="connection">已认证的直连连接。</param>
    /// <param name="stream">已校验身份的可靠流。</param>
    private void PublishDirect(PeerState peer, QuicConnection connection, QuicStream stream)
    {
        var reliable = new QuicP2PLink(connection, stream, _options.MaximumFrameSize,
            $"direct-quic-stream-{peer.PeerId:x16}");
        var datagram = new QuicDatagramP2PLink(connection, P2PTransportKind.Quic, ownsConnection: false,
            $"direct-quic-dgram-{peer.PeerId:x16}");
        IP2PLink[] old = peer.SetDirect(reliable, datagram);
        foreach (IP2PLink oldLink in old) TrackBackground(oldLink.DisposeAsync().AsTask());
        PublishLink(peer.PeerId, reliable);
        PublishLink(peer.PeerId, datagram);
        RaisePeerChanged(peer.Snapshot());
        RaiseTraversal(peer, P2PTraversalEventKind.QuicDirectSucceeded, P2PTransportKind.Quic,
            peer.CurrentAttemptNumber, connection.RemoteEndPoint,
            detail: "UDP 打洞和 QUIC 身份握手成功。");
        TrackBackground(ObserveDirectClosedAsync(peer, reliable));
    }

    /// <summary>仅清除实际已经关闭的那一代精确直连链路。</summary>
    /// <param name="peer">拥有链路的对端。</param>
    /// <param name="link">已发布的直连链路。</param>
    /// <returns>观察到关闭后结束的任务。</returns>
    private async Task ObserveDirectClosedAsync(PeerState peer, IP2PLink link)
    {
        try { await link.Closed.ConfigureAwait(false); } catch { }
        IP2PLink[] closedGeneration = peer.ClearDirect(link);
        if (closedGeneration.Length == 0) return;
        foreach (IP2PLink closedLink in closedGeneration)
        {
            try { await closedLink.DisposeAsync().ConfigureAwait(false); } catch { }
        }
        RaisePeerChanged(peer.Snapshot());
        RaiseTraversal(peer, P2PTraversalEventKind.DirectDisconnected, P2PTransportKind.Quic,
            peer.CurrentAttemptNumber, detail: "QUIC 直连已经断开，将保留后备路径并自动重试。");
    }

    /// <summary>调用链路订阅者，并隔离回调异常以免停止网络循环。</summary>
    /// <param name="peerId">远程对端标识。</param>
    /// <param name="link">已就绪且具有所有权的路径。</param>
    private void PublishLink(ulong peerId, IP2PLink link)
    {
        Action<ulong, IP2PLink>? handlers = LinkEstablished;
        if (handlers is null) return;
        foreach (Action<ulong, IP2PLink> handler in handlers.GetInvocationList())
        {
            try { handler(peerId, link); } catch { }
        }
    }

    /// <summary>发送保活消息，并定期重试尚无直连路径的对端。</summary>
    /// <param name="cancellationToken">客户端生命周期取消标记。</param>
    /// <returns>在释放期间结束的任务。</returns>
    private async Task MaintenanceLoopAsync(CancellationToken cancellationToken)
    {
        using var timer = new PeriodicTimer(_options.HolePunchRetryInterval);
        int tick = 0;
        while (await timer.WaitForNextTickAsync(cancellationToken).ConfigureAwait(false))
        {
            if (++tick % 3 == 0)
                await _control!.SendAsync(new P2PControlMessage(P2PControlType.Ping), cancellationToken)
                    .ConfigureAwait(false);
            foreach (PeerState peer in _peers.Values)
            {
                bool wanted = _options.EagerHolePunching || peer.HasRecentApplicationTraffic(
                    _options.DirectLinkIdleTimeout);
                if (peer.HasDirect && !_options.EagerHolePunching && !wanted)
                {
                    foreach (IP2PLink link in peer.TakeDirectLinks())
                        try { await link.DisposeAsync().ConfigureAwait(false); } catch { }
                    RaisePeerChanged(peer.Snapshot());
                    continue;
                }
                if (wanted && !peer.HasDirect) StartDirectAttempt(peer);
                if (wanted && _puncher is not null && tick % 2 == 0 && !peer.HasDirect && peer.CanAttemptDirect(
                    _options.MaximumHolePunchRounds))
                    await RequestPunchAsync(peer.PeerId, cancellationToken).ConfigureAwait(false);
            }
        }
    }

    /// <summary>
    /// 执行Request Direct操作。
    /// </summary>
    /// <param name="peerId">peer Id参数。</param>
    internal void RequestDirect(ulong peerId)
    {
        if (!_peers.TryGetValue(peerId, out PeerState? peer)) return;
        peer.MarkApplicationTraffic();
        if (peer.CanAttemptDirect(_options.MaximumHolePunchRounds))
        {
            StartDirectAttempt(peer);
            var request = RequestPunchAsync(peerId, _lifetime.Token);
            if (!request.IsCompletedSuccessfully) TrackBackground(request.AsTask());
        }
    }

    /// <summary>移除对端路径并清除其秘密令牌。</summary>
    /// <param name="peerId">已离开的对端标识。</param>
    /// <returns>路径释放后结束的异步操作。</returns>
    private async ValueTask RemovePeerAsync(ulong peerId)
    {
        _punchRequests.Forget(peerId);
        if (!_peers.TryRemove(peerId, out PeerState? peer)) return;
        await peer.DisposeAsync().ConfigureAwait(false);
        RaisePeerChanged(peer.Snapshot());
    }

    /// <summary>跟踪后台任务，并在完成后从活动任务计数中移除。</summary>
    /// <param name="task">要跟踪的任务。</param>
    private void TrackBackground(Task task)
    {
        long id = Interlocked.Increment(ref _backgroundTaskId);
        Task observed = ObserveBackgroundAsync(task);
        _backgroundTasks[id] = observed;
        _ = observed.ContinueWith(static (_, state) =>
        {
            var item = (KeyValuePair<ConcurrentDictionary<long, Task>, long>)state!;
            item.Key.TryRemove(item.Value, out Task? _);
        }, new KeyValuePair<ConcurrentDictionary<long, Task>, long>(_backgroundTasks, id),
            CancellationToken.None, TaskContinuationOptions.ExecuteSynchronously, TaskScheduler.Default);
    }

    /// <summary>报告意外的致命数据泵故障，并停止同级任务。</summary>
    /// <param name="task">数据泵任务。</param>
    /// <returns>用于观察其异常的任务。</returns>
    private async Task ObserveBackgroundAsync(Task task)
    {
        try { await task.ConfigureAwait(false); }
        catch (OperationCanceledException) when (_lifetime.IsCancellationRequested) { }
        catch (Exception exception)
        {
            if (!_lifetime.IsCancellationRequested)
            {
                Volatile.Write(ref _connected, 0);
                _lifetime.Cancel();
                RaiseDisconnected(exception);
            }
        }
    }

    /// <summary>触发对端状态回调，并防止应用异常进入网络任务。</summary>
    /// <param name="peer">不可变的对端快照。</param>
    private void RaisePeerChanged(DiscoveredPeer peer)
    {
        Action<DiscoveredPeer>? handlers = PeerChanged;
        if (handlers is null) return;
        foreach (Action<DiscoveredPeer> handler in handlers.GetInvocationList())
        {
            try { handler(peer); } catch { }
        }
    }

    /// <summary>向所有诊断订阅者发布一条打洞状态，并隔离订阅者异常。</summary>
    /// <param name="peer">事件对应的远程对端。</param>
    /// <param name="kind">打洞事件类型。</param>
    /// <param name="transport">事件对应的传输类型。</param>
    /// <param name="attemptNumber">本地尝试序号。</param>
    /// <param name="remoteEndPoint">可选的远程候选或确认端点。</param>
    /// <param name="retryDelay">可选的下一轮重试等待时间。</param>
    /// <param name="detail">适合直接记录的中文说明。</param>
    private void RaiseTraversal(PeerState peer, P2PTraversalEventKind kind, P2PTransportKind transport,
        int attemptNumber, IPEndPoint? remoteEndPoint = null, TimeSpan? retryDelay = null,
        string? detail = null)
    {
        Action<P2PTraversalEvent>? handlers = TraversalStateChanged;
        if (handlers is null) return;
        var value = new P2PTraversalEvent(kind, peer.PeerName, peer.PeerId, transport,
            attemptNumber, remoteEndPoint, retryDelay, detail);
        foreach (Action<P2PTraversalEvent> handler in handlers.GetInvocationList())
        {
            try { handler(value); } catch { }
        }
    }

    /// <summary>在同级网络任务已取消后触发断开连接回调。</summary>
    /// <param name="exception">导致本代信令连接结束的异常。</param>
    private void RaiseDisconnected(Exception? exception)
    {
        Action<Exception?>? handlers = Disconnected;
        if (handlers is null) return;
        foreach (Action<Exception?> handler in handlers.GetInvocationList())
        {
            try { handler(exception); } catch { }
        }
    }

    /// <summary>由上层在网络候选变化时主动结束本代连接，以重新向协调器注册。</summary>
    /// <param name="reason">重新连接原因。</param>
    internal void RequestReconnect(string reason)
    {
        if (Interlocked.Exchange(ref _connected, 0) == 0) return;
        _lifetime.Cancel();
        RaiseDisconnected(new IOException(string.IsNullOrWhiteSpace(reason) ? "上层请求重新连接。" : reason));
    }

    /// <summary>创建入站共享端点 QUIC 限制。</summary>
    /// <returns>与出站直连及协调服务器连接兼容的服务器选项。</returns>
    private QuicServerOptions CreateInboundOptions() => new()
    {
        ListenEndPoint = (IPEndPoint)_socket!.LocalEndPoint!,
        KeyProvider = _keyProvider,
        MaxConnections = Math.Max(64, _options.MaxLinksPerPeer * 1024),
        MaxPendingHandshakes = 256,
        MaxUdpPayloadSize = 1400,
        ConnectionQueueCapacity = 2048,
        PacketReceiveQueueCapacity = 8192,
        DatagramQueueCapacity = 8192,
        StreamAcceptQueueCapacity = 64,
        IdleTimeout = TimeSpan.FromMinutes(2),
        KeepAliveInterval = TimeSpan.FromSeconds(15),
        ShutdownTimeout = _options.ShutdownTimeout
    };

    /// <summary>在已绑定的共享套接字上创建出站 QUIC 选项。</summary>
    /// <param name="remote">远程端点。</param>
    /// <param name="name">已认证的逻辑服务器或对端名称。</param>
    /// <returns>与共享端点兼容的客户端选项。</returns>
    private QuicClientOptions CreateClientOptions(IPEndPoint remote, string name) => new()
    {
        RemoteEndPoint = remote,
        ServerName = name,
        KeyProvider = _keyProvider,
        MaxUdpPayloadSize = 1400,
        ConnectionQueueCapacity = 2048,
        PacketReceiveQueueCapacity = 8192,
        DatagramQueueCapacity = 8192,
        StreamAcceptQueueCapacity = 64,
        IdleTimeout = TimeSpan.FromMinutes(2),
        KeepAliveInterval = TimeSpan.FromSeconds(15),
        ShutdownTimeout = _options.ShutdownTimeout
    };

    /// <summary>在保留已绑定打洞端口的同时查找路由选中的局域网地址。</summary>
    /// <param name="server">协调服务器端点。</param>
    /// <param name="bound">实际绑定的通配或接口端点。</param>
    /// <returns>带共享 UDP 端口的局域网候选端点。</returns>
    private static IPEndPoint ResolvePrivateCandidate(IPEndPoint server, IPEndPoint bound)
    {
        if (!bound.Address.Equals(IPAddress.Any) && !bound.Address.Equals(IPAddress.IPv6Any)) return bound;
        using var probe = new Socket(server.AddressFamily, SocketType.Dgram, ProtocolType.Udp);
        probe.Connect(server);
        IPAddress address = ((IPEndPoint)probe.LocalEndPoint!).Address;
        return new IPEndPoint(address, bound.Port);
    }

    /// <summary>写入一个直连身份前导信息。</summary>
    private void WriteDirectHello(Span<byte> buffer, bool acknowledgement, ulong source, ulong target)
    {
        buffer = buffer[..DirectHelloLength]; buffer.Clear();
        BinaryPrimitives.WriteUInt32BigEndian(buffer, DirectHelloMagic);
        buffer[4] = 2; buffer[5] = acknowledgement ? (byte)2 : (byte)1;
        BinaryPrimitives.WriteUInt64BigEndian(buffer[8..], _sessionId);
        BinaryPrimitives.WriteUInt64BigEndian(buffer[16..], source);
        BinaryPrimitives.WriteUInt64BigEndian(buffer[24..], target);
    }

    /// <summary>校验并读取一个直连身份前导信息。</summary>
    private bool TryReadDirectHello(ReadOnlySpan<byte> buffer, bool acknowledgement, out ulong source, out ulong target)
    {
        source = target = 0;
        if (buffer.Length < DirectHelloLength || BinaryPrimitives.ReadUInt32BigEndian(buffer) != DirectHelloMagic ||
            buffer[4] != 2 || buffer[5] != (acknowledgement ? (byte)2 : (byte)1) ||
            BinaryPrimitives.ReadUInt64BigEndian(buffer[8..]) != _sessionId) return false;
        source = BinaryPrimitives.ReadUInt64BigEndian(buffer[16..]);
        target = BinaryPrimitives.ReadUInt64BigEndian(buffer[24..]);
        return source != 0 && target != 0;
    }

    /// <summary>从 QUIC 流精确读取一条直连握手信息。</summary>
    private static async ValueTask ReadExactlyAsync(QuicStream stream, Memory<byte> destination,
        CancellationToken cancellationToken)
    {
        int offset = 0;
        while (offset < destination.Length)
        {
            int read = await stream.ReadAsync(destination[offset..], cancellationToken).ConfigureAwait(false);
            if (read == 0) throw new EndOfStreamException("直连对端在身份交换过程中关闭。");
            offset += read;
        }
    }

    /// <summary>禁用 Windows 将 UDP ICMP 错误转换为致命套接字重置的行为。</summary>
    private static void DisableUdpConnectionReset(Socket socket)
    {
        if (!OperatingSystem.IsWindows()) return;
        try { socket.IOControl(-1744830452, [0, 0, 0, 0], null); } catch { }
    }

    /// <summary>将网络字节序协议地址转换为 IPv4 对象。</summary>
    /// <param name="address">网络字节序的 32 位 IPv4 值。</param>
    /// <returns>等效的 IPv4 地址。</returns>
    private static IPAddress UInt32ToAddress(uint address)
    {
        Span<byte> bytes = stackalloc byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(bytes, address);
        return new IPAddress(bytes);
    }

    /// <summary>释放部分或全部初始化的网络资源。</summary>
    private async ValueTask CleanupNetworkAsync()
    {
        try { _tcpListener?.Dispose(); } catch { }
        _tcpListener = null;
        // A reconnect must not wait for the peer to acknowledge a graceful stream FIN.  In
        // particular, a late UPnP discovery requests a reconnect roughly 15 seconds after
        // startup; disposing the control stream before closing its QUIC connection could wait
        // forever and leave the process running while the coordinator already showed it
        // offline. Abort the old connection first so every stream/read loop is released, then
        // dispose the remaining resources independently.
        try { _serverConnection?.Abort(0x201); } catch { }
        if (_puncher is not null)
            try { await _puncher.DisposeAsync().ConfigureAwait(false); } catch { }
        if (_control is not null)
            try { await _control.DisposeAsync().ConfigureAwait(false); } catch { }
        if (_serverConnection is not null)
            try { await _serverConnection.DisposeAsync().ConfigureAwait(false); } catch { }
        if (_endpoint is not null)
            try { await _endpoint.DisposeAsync().ConfigureAwait(false); } catch { }
        else
            try { _socket?.Dispose(); } catch { }
        _puncher = null;
        _control = null;
        _serverConnection = null;
        _endpoint = null;
        _socket = null;
    }

    /// <summary>停止所有数据泵、关闭全部路径并释放共享 UDP 套接字。</summary>
    /// <returns>有界关闭完成后结束的异步操作。</returns>
    public async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0) return;
        _lifetime.Cancel();
        Volatile.Write(ref _connected, 0);
        // Abort sockets and shared QUIC connections before per-peer disposal so a late
        // UPnP mapping change cannot strand the node between generations.
        await CleanupNetworkAsync().ConfigureAwait(false);
        foreach (PeerState peer in _peers.Values) await peer.DisposeAsync().ConfigureAwait(false);
        _peers.Clear();
        Task[] fixedTasks = [_controlTask ?? Task.CompletedTask, _relayDatagramTask ?? Task.CompletedTask,
            _directAcceptTask ?? Task.CompletedTask, _tcpAcceptTask ?? Task.CompletedTask,
            _maintenanceTask ?? Task.CompletedTask];
        Task[] all = fixedTasks.Concat(_backgroundTasks.Values).ToArray();
        try { await Task.WhenAll(all).WaitAsync(_options.ShutdownTimeout).ConfigureAwait(false); } catch { }
        _lifetime.Dispose();
    }

    /// <summary>
/// 表示 Peer State，并提供相关数据或行为。
/// </summary>
private sealed class PeerState : IAsyncDisposable
    {
        private readonly object _sync = new();
        private byte[] _token;
        private IPEndPoint _publicEndPoint;
        private IPEndPoint? _privateEndPoint;
        private IPEndPoint? _tcpPublicEndPoint;
        private IPEndPoint? _tcpPrivateEndPoint;
        private IPEndPoint? _confirmedEndPoint;
        private uint _virtualAddress;
        private IP2PLink? _directReliable;
        private IP2PLink? _directDatagram;
        private IP2PLink? _tcpDirect;
        private int _attempting;
        private int _attemptNumber;
        private int _failedAttemptRounds;
        private int _relaysPublished;
        private long _lastApplicationTrafficTicks;
        /// <summary>
        /// 初始化 <see cref="PeerState"/> 类的新实例。
        /// </summary>
        /// <param name="peerId">peer Id参数。</param>
        /// <param name="peerName">peer Name参数。</param>
        /// <param name="publicEndPoint">public End Point参数。</param>
        /// <param name="privateEndPoint">private End Point参数。</param>
        /// <param name="tcpPublicEndPoint">tcp Public End Point参数。</param>
        /// <param name="tcpPrivateEndPoint">tcp Private End Point参数。</param>
        /// <param name="token">token参数。</param>
        /// <param name="virtualAddress">virtual Address参数。</param>
        /// <param name="reliableRelay">reliable Relay参数。</param>
        /// <param name="datagramRelay">datagram Relay参数。</param>
        public PeerState(ulong peerId, string peerName, IPEndPoint publicEndPoint,
            IPEndPoint? privateEndPoint, IPEndPoint? tcpPublicEndPoint, IPEndPoint? tcpPrivateEndPoint,
            byte[] token, uint virtualAddress, P2PRelayLink reliableRelay, P2PRelayLink datagramRelay)
        {
            PeerId = peerId; PeerName = peerName; _publicEndPoint = publicEndPoint;
            _privateEndPoint = privateEndPoint; _tcpPublicEndPoint = tcpPublicEndPoint;
            _tcpPrivateEndPoint = tcpPrivateEndPoint; _token = token.ToArray(); _virtualAddress = virtualAddress;
            ReliableRelay = reliableRelay; DatagramRelay = datagramRelay;
        }
        /// <summary>
        /// 获取或设置Peer Id。
        /// </summary>
        /// <returns>Peer Id。</returns>
        public ulong PeerId { get; }
        /// <summary>
        /// 获取或设置Peer Name。
        /// </summary>
        /// <returns>Peer Name。</returns>
        public string PeerName { get; private set; }
        /// <summary>
        /// 获取或设置Reliable Relay。
        /// </summary>
        /// <returns>Reliable Relay。</returns>
        public P2PRelayLink ReliableRelay { get; }
        /// <summary>
        /// 获取或设置Datagram Relay。
        /// </summary>
        /// <returns>Datagram Relay。</returns>
        public P2PRelayLink DatagramRelay { get; }
        /// <summary>
        /// 获取或设置Current Attempt Number。
        /// </summary>
        /// <returns>Current Attempt Number。</returns>
        public int CurrentAttemptNumber => Math.Max(1, Volatile.Read(ref _attemptNumber));
        /// <summary>
        /// 获取或设置Has Quic Direct。
        /// </summary>
        /// <returns>Has Quic Direct。</returns>
        public bool HasQuicDirect { get { lock (_sync) return _directReliable?.IsConnected == true; } }
        /// <summary>
        /// 获取或设置Has Tcp Direct。
        /// </summary>
        /// <returns>Has Tcp Direct。</returns>
        public bool HasTcpDirect { get { lock (_sync) return _tcpDirect?.IsConnected == true; } }
        /// <summary>
        /// 获取或设置Has Direct。
        /// </summary>
        /// <returns>Has Direct。</returns>
        public bool HasDirect { get { lock (_sync) return _directReliable?.IsConnected == true ||
            _tcpDirect?.IsConnected == true; } }
        /// <summary>
        /// 执行Mark Application Traffic操作。
        /// </summary>
        public void MarkApplicationTraffic() => Volatile.Write(ref _lastApplicationTrafficTicks,
            DateTimeOffset.UtcNow.UtcTicks);
        /// <summary>
        /// 执行Has Recent Application Traffic操作。
        /// </summary>
        /// <param name="timeout">操作超时时间。</param>
        /// <returns>操作结果。</returns>
        public bool HasRecentApplicationTraffic(TimeSpan timeout)
        {
            long value = Volatile.Read(ref _lastApplicationTrafficTicks);
            return value != 0 && DateTimeOffset.UtcNow.UtcTicks - value < timeout.Ticks;
        }
        /// <summary>
        /// 执行Take Direct Links操作。
        /// </summary>
        /// <returns>操作结果。</returns>
        public IP2PLink[] TakeDirectLinks()
        {
            lock (_sync)
            {
                IP2PLink[] links = new IP2PLink?[] { _tcpDirect, _directDatagram, _directReliable }
                    .Where(static link => link is not null).Cast<IP2PLink>().ToArray();
                _tcpDirect = _directDatagram = _directReliable = null;
                return links;
            }
        }
        /// <summary>
        /// 执行Update操作。
        /// </summary>
        /// <param name="name">名称。</param>
        /// <param name="publicEndPoint">public End Point参数。</param>
        /// <param name="privateEndPoint">private End Point参数。</param>
        /// <param name="tcpPublicEndPoint">tcp Public End Point参数。</param>
        /// <param name="tcpPrivateEndPoint">tcp Private End Point参数。</param>
        /// <param name="token">token参数。</param>
        /// <param name="virtualAddress">virtual Address参数。</param>
        /// <returns>操作结果。</returns>
        public bool Update(string name, IPEndPoint publicEndPoint, IPEndPoint? privateEndPoint,
            IPEndPoint? tcpPublicEndPoint, IPEndPoint? tcpPrivateEndPoint, byte[] token, uint virtualAddress)
        {
            lock (_sync)
            {
                bool tokenChanged = !CryptographicOperations.FixedTimeEquals(_token, token);
                bool generationChanged = !_publicEndPoint.Equals(publicEndPoint) ||
                    !Equals(_privateEndPoint, privateEndPoint) ||
                    !Equals(_tcpPublicEndPoint, tcpPublicEndPoint) ||
                    !Equals(_tcpPrivateEndPoint, tcpPrivateEndPoint) ||
                    tokenChanged;
                PeerName = name; _publicEndPoint = publicEndPoint; _privateEndPoint = privateEndPoint;
                _tcpPublicEndPoint = tcpPublicEndPoint; _tcpPrivateEndPoint = tcpPrivateEndPoint;
                _virtualAddress = virtualAddress;
                if (tokenChanged)
                { CryptographicOperations.ZeroMemory(_token); _token = token.ToArray(); _confirmedEndPoint = null; }
                if (generationChanged)
                {
                    Volatile.Write(ref _nextDirectAttempt, 0);
                    Volatile.Write(ref _failedAttemptRounds, 0);
                    Volatile.Write(ref _attemptNumber, 0);
                }
                return tokenChanged;
            }
        }
        /// <summary>
        /// 执行Snapshot操作。
        /// </summary>
        /// <returns>操作结果。</returns>
        public DiscoveredPeer Snapshot()
        {
            lock (_sync)
            {
                P2PTransportKind directTransport = _directReliable?.IsConnected == true
                    ? P2PTransportKind.Quic
                    : _tcpDirect?.IsConnected == true ? P2PTransportKind.TcpDirect : P2PTransportKind.Unknown;
                IP2PLink? directLink = directTransport == P2PTransportKind.Quic
                    ? _directReliable : directTransport == P2PTransportKind.TcpDirect ? _tcpDirect : null;
                return new(PeerName, PeerId, _publicEndPoint, _privateEndPoint, _tcpPublicEndPoint,
                    _tcpPrivateEndPoint, directTransport != P2PTransportKind.Unknown, directTransport,
                    UInt32ToAddress(_virtualAddress), directLink?.LocalEndPoint as IPEndPoint,
                    directLink?.RemoteEndPoint as IPEndPoint);
            }
        }
        /// <summary>
        /// 执行Punch Candidate操作。
        /// </summary>
        /// <returns>操作结果。</returns>
        public P2PPunchCandidate PunchCandidate() { lock (_sync) return new(PeerId, _publicEndPoint, _privateEndPoint, _token.ToArray()); }
        /// <summary>
        /// 执行Tcp Candidates操作。
        /// </summary>
        /// <param name="publicPortFanout">public Port Fanout参数。</param>
        /// <param name="filter">filter参数。</param>
        /// <returns>操作结果。</returns>
        public IPEndPoint[] TcpCandidates(int publicPortFanout, Func<IPEndPoint, bool>? filter = null)
        {
            lock (_sync)
            {
                var candidates = new HashSet<IPEndPoint>();
                if (_tcpPrivateEndPoint is not null && (filter?.Invoke(_tcpPrivateEndPoint) ?? true))
                    candidates.Add(_tcpPrivateEndPoint);
                if (_tcpPublicEndPoint is not null)
                {
                    if (filter?.Invoke(_tcpPublicEndPoint) ?? true) candidates.Add(_tcpPublicEndPoint);
                    for (int offset = 1; offset <= publicPortFanout; offset++)
                    {
                        int lower = _tcpPublicEndPoint.Port - offset;
                        int upper = _tcpPublicEndPoint.Port + offset;
                        if (lower >= 1)
                        {
                            var lowerCandidate = new IPEndPoint(_tcpPublicEndPoint.Address, lower);
                            if (filter?.Invoke(lowerCandidate) ?? true) candidates.Add(lowerCandidate);
                        }
                        if (upper <= 65_535)
                        {
                            var upperCandidate = new IPEndPoint(_tcpPublicEndPoint.Address, upper);
                            if (filter?.Invoke(upperCandidate) ?? true) candidates.Add(upperCandidate);
                        }
                    }
                }
                return candidates.ToArray();
            }
        }
        /// <summary>
        /// 获取或设置Virtual Address。
        /// </summary>
        /// <returns>Virtual Address。</returns>
        public IPAddress VirtualAddress { get { lock (_sync) return UInt32ToAddress(_virtualAddress); } }
        /// <summary>
        /// 执行Copy Token操作。
        /// </summary>
        /// <returns>操作结果。</returns>
        public byte[] CopyToken() { lock (_sync) return _token.ToArray(); }
        /// <summary>
        /// 尝试Publish Relays。
        /// </summary>
        /// <returns>操作是否成功。</returns>
        public bool TryPublishRelays() => Interlocked.Exchange(ref _relaysPublished, 1) == 0;
        /// <summary>
        /// 执行Can Attempt Direct操作。
        /// </summary>
        /// <param name="maximumRounds">maximum Rounds参数。</param>
        /// <returns>操作结果。</returns>
        public bool CanAttemptDirect(int maximumRounds) => !HasDirect &&
            Volatile.Read(ref _failedAttemptRounds) < maximumRounds;
        private long _nextDirectAttempt;
        /// <summary>
        /// 尝试Begin Direct Attempt。
        /// </summary>
        /// <param name="maximumRounds">maximum Rounds参数。</param>
        /// <param name="attemptNumber">attempt Number参数。</param>
        /// <returns>操作是否成功。</returns>
        /// <param name="retryMilliseconds">Minimum retry interval.</param>
        public bool TryBeginDirectAttempt(int maximumRounds, long retryMilliseconds, out int attemptNumber)
        {
            attemptNumber = 0;
            if (!CanAttemptDirect(maximumRounds) || Interlocked.CompareExchange(ref _attempting, 1, 0) != 0)
                return false;
            if (!CanAttemptDirect(maximumRounds))
            {
                Volatile.Write(ref _attempting, 0);
                return false;
            }
            long now = Environment.TickCount64;
            if (now < Volatile.Read(ref _nextDirectAttempt))
            {
                Volatile.Write(ref _attempting, 0);
                return false;
            }
            Volatile.Write(ref _nextDirectAttempt, now + Math.Max(1, retryMilliseconds));
            attemptNumber = Volatile.Read(ref _failedAttemptRounds) + 1;
            Volatile.Write(ref _attemptNumber, attemptNumber);
            return true;
        }
        /// <summary>
        /// 执行End Direct Attempt操作。
        /// </summary>
        /// <param name="directSucceeded">direct Succeeded参数。</param>
        /// <returns>操作结果。</returns>
        public int EndDirectAttempt(bool directSucceeded)
        {
            int failedRounds = directSucceeded ? 0 : Interlocked.Increment(ref _failedAttemptRounds);
            if (directSucceeded) Volatile.Write(ref _failedAttemptRounds, 0);
            Volatile.Write(ref _attempting, 0);
            return failedRounds;
        }
        /// <summary>
        /// 设置Confirmed End Point。
        /// </summary>
        /// <param name="endpoint">网络端点。</param>
        public void SetConfirmedEndPoint(IPEndPoint endpoint) { lock (_sync) _confirmedEndPoint = endpoint; }
        /// <summary>
        /// 执行Is Expected Endpoint操作。
        /// </summary>
        /// <param name="endpoint">网络端点。</param>
        /// <returns>操作结果。</returns>
        public bool IsExpectedEndpoint(IPEndPoint endpoint) { lock (_sync) return _confirmedEndPoint is not null &&
            _confirmedEndPoint.Address.Equals(endpoint.Address) && _confirmedEndPoint.Port == endpoint.Port; }
        /// <summary>
        /// 设置Direct。
        /// </summary>
        /// <param name="reliable">reliable参数。</param>
        /// <param name="datagram">datagram参数。</param>
        /// <returns>操作结果。</returns>
        public IP2PLink[] SetDirect(IP2PLink reliable, IP2PLink datagram)
        {
            lock (_sync)
            {
                IP2PLink[] old = new IP2PLink?[] { _directReliable, _directDatagram }
                    .Where(static link => link is not null).Cast<IP2PLink>().ToArray();
                _directReliable = reliable; _directDatagram = datagram;
                Volatile.Write(ref _failedAttemptRounds, 0);
                return old;
            }
        }
        /// <summary>
        /// 执行Clear Direct操作。
        /// </summary>
        /// <param name="link">link参数。</param>
        /// <returns>操作结果。</returns>
        public IP2PLink[] ClearDirect(IP2PLink link)
        {
            lock (_sync)
            {
                if (!ReferenceEquals(_directReliable, link)) return [];
                IP2PLink[] generation = new IP2PLink?[] { _directDatagram, _directReliable }
                    .Where(static candidate => candidate is not null).Cast<IP2PLink>().ToArray();
                _directReliable = null;
                _directDatagram = null;
                return generation;
            }
        }
        /// <summary>
        /// 设置Tcp Direct。
        /// </summary>
        /// <param name="link">link参数。</param>
        /// <returns>操作结果。</returns>
        public IP2PLink? SetTcpDirect(IP2PLink link)
        {
            lock (_sync)
            {
                IP2PLink? old = _tcpDirect;
                _tcpDirect = link;
                Volatile.Write(ref _failedAttemptRounds, 0);
                return old;
            }
        }
        /// <summary>
        /// 执行Clear Tcp Direct操作。
        /// </summary>
        /// <param name="link">link参数。</param>
        /// <returns>操作结果。</returns>
        public bool ClearTcpDirect(IP2PLink link)
        {
            lock (_sync)
            {
                if (!ReferenceEquals(_tcpDirect, link)) return false;
                _tcpDirect = null;
                return true;
            }
        }
        /// <summary>
        /// 执行Dispose操作。
        /// </summary>
        /// <returns>操作结果。</returns>
        public async ValueTask DisposeAsync()
        {
            IP2PLink? reliable; IP2PLink? datagram; IP2PLink? tcp;
            lock (_sync)
            {
                reliable = _directReliable; datagram = _directDatagram; tcp = _tcpDirect;
                _directReliable = _directDatagram = _tcpDirect = null;
                CryptographicOperations.ZeroMemory(_token);
            }
            if (tcp is not null) await tcp.DisposeAsync().ConfigureAwait(false);
            if (datagram is not null) await datagram.DisposeAsync().ConfigureAwait(false);
            if (reliable is not null) await reliable.DisposeAsync().ConfigureAwait(false);
            await ReliableRelay.DisposeAsync().ConfigureAwait(false);
            await DatagramRelay.DisposeAsync().ConfigureAwait(false);
        }
    }
}
