using Qcxt.Net.Quic.Configuration;
using Qcxt.Net.Quic.Memory;
using Qcxt.Net.Quic.Protocol;
using Qcxt.Net.Quic.Recovery;
using Qcxt.Net.Quic.Security;

namespace Qcxt.Net.Quic;

/// <summary>表示一条经过认证且支持多路复用的 QUIC 传输连接。</summary>
public sealed class QuicConnection : IAsyncDisposable
{
    private readonly QuicEndpointOptions _options;
    private readonly Socket _socket;
    private readonly bool _ownsSocket;
    private readonly bool _isServer;
    private readonly IQuicHandshake _handshake;
    private readonly AesGcmPacketProtector _protector;
    private readonly Channel<PooledDatagram> _incoming;
    private readonly Channel<SendCommand> _outgoing;
    private readonly Channel<SendCommand> _interactiveOutgoing;
    private readonly Channel<SendCommand> _controlOutgoing;
    private readonly Channel<byte> _sendWakeup;
    private readonly SemaphoreSlim _sendProgress = new(0, 1);
    private readonly Channel<QuicStream> _acceptedStreams;
    private readonly Channel<PooledSegment> _datagrams;
    private readonly ConcurrentDictionary<ulong, QuicStream> _streams = new();
    private readonly CancellationTokenSource _lifetime = new();
    private readonly TaskCompletionSource _connected = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private readonly TaskCompletionSource _closed = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private readonly CongestionController _congestion;
    private readonly SendFlowController _sendFlow = new(0, 0);
    private readonly AckRangeSet _receivedPackets = new();
    private readonly object _receivedLock = new();
    private readonly Dictionary<long, SentPacket> _sentPackets = new();
    private readonly object _sentLock = new();
    private Task? _receiveTask, _processTask, _sendTask, _recoveryTask;
    private IPEndPoint _remoteEndPoint;
    private QuicConnectionId _remoteConnectionId;
    private long _nextPacketNumber;
    private long _nextBidiStreamId;
    private long _nextUniStreamId;
    private long _lastActivity;
    private long _lastSendActivity;
    private long _receivedStreamBytes;
    private long _consumedStreamBytes;
    private long _advertisedConnectionLimit;
    private long _sentPacketCount;
    private long _largestAcknowledged = -1;
    private long _ackPendingSince;
    private long _lastPtoProbeAt;
    private ulong _peerMaxBidirectionalStreams;
    private ulong _peerMaxUnidirectionalStreams;
    private ulong _peerMaxDatagramFrameSize;
    private int _state;
    private int _disposed;
    private int _ackElicitingPending;
    private int _ackRequested;
    private long _droppedIncomingPackets;
    private Exception? _closeException;

    /// <summary>
    /// 初始化 <see cref="QuicConnection"/> 类的新实例。
    /// </summary>
    /// <param name="options">操作配置选项。</param>
    /// <param name="socket">socket参数。</param>
    /// <param name="ownsSocket">owns Socket参数。</param>
    /// <param name="isServer">is Server参数。</param>
    /// <param name="remoteEndPoint">网络端点。</param>
    /// <param name="localCid">local Cid参数。</param>
    /// <param name="remoteCid">remote Cid参数。</param>
    /// <param name="handshake">handshake参数。</param>
    private QuicConnection(QuicEndpointOptions options, Socket socket, bool ownsSocket, bool isServer,
        IPEndPoint remoteEndPoint, QuicConnectionId localCid, QuicConnectionId remoteCid, IQuicHandshake handshake)
    {
        _options = options; _socket = socket; _ownsSocket = ownsSocket; _isServer = isServer;
        _advertisedConnectionLimit = options.InitialConnectionWindow;
        _remoteEndPoint = remoteEndPoint; LocalConnectionId = localCid; _remoteConnectionId = remoteCid;
        _handshake = handshake;
        QuicKeySet baseKeys = handshake.ApplicationKeys ??
            throw new InvalidOperationException("The key provider did not produce application keys.");
        using (QuicKeySet connectionKeys = ConnectionKeyDerivation.Derive(baseKeys, localCid, remoteCid, isServer))
            _protector = new AesGcmPacketProtector(connectionKeys);
        _incoming = Channel.CreateBounded<PooledDatagram>(new BoundedChannelOptions(options.PacketReceiveQueueCapacity)
        { SingleReader = true, SingleWriter = false, FullMode = BoundedChannelFullMode.Wait });
        _outgoing = Channel.CreateBounded<SendCommand>(new BoundedChannelOptions(options.ConnectionQueueCapacity)
        { SingleReader = true, SingleWriter = false, FullMode = BoundedChannelFullMode.Wait });
        _interactiveOutgoing = Channel.CreateBounded<SendCommand>(new BoundedChannelOptions(
            Math.Clamp(options.ConnectionQueueCapacity / 4, 16, 256))
        {
            SingleReader = true,
            SingleWriter = false,
            FullMode = BoundedChannelFullMode.Wait
        });
        _controlOutgoing = Channel.CreateUnbounded<SendCommand>(new UnboundedChannelOptions
        { SingleReader = true, SingleWriter = false, AllowSynchronousContinuations = false });
        _sendWakeup = Channel.CreateBounded<byte>(new BoundedChannelOptions(1)
        { SingleReader = true, SingleWriter = false, FullMode = BoundedChannelFullMode.DropWrite });
        _acceptedStreams = Channel.CreateBounded<QuicStream>(new BoundedChannelOptions(options.StreamAcceptQueueCapacity)
        { SingleReader = false, SingleWriter = true, FullMode = BoundedChannelFullMode.Wait });
        _datagrams = Channel.CreateBounded<PooledSegment>(new BoundedChannelOptions(options.DatagramQueueCapacity)
        { SingleReader = false, SingleWriter = true, FullMode = BoundedChannelFullMode.Wait });
        _congestion = new CongestionController(options.MaxUdpPayloadSize);
        _nextBidiStreamId = isServer ? 1 : 0; _nextUniStreamId = isServer ? 3 : 2;
        _lastActivity = _lastSendActivity = Stopwatch.GetTimestamp();
    }

    /// <summary>获取用于将数据包路由到此端点的连接标识符。</summary>
    public QuicConnectionId LocalConnectionId { get; }
    /// <summary>获取此连接使用的本地 UDP 端点。</summary>
    public IPEndPoint? LocalEndPoint => _socket.LocalEndPoint as IPEndPoint;
    /// <summary>获取当前对端 UDP 端点。</summary>
    public IPEndPoint RemoteEndPoint => _remoteEndPoint;
    /// <summary>获取认证握手是否已经完成。</summary>
    public bool IsConnected => Volatile.Read(ref _state) == 1;
    /// <summary>获取从最后一个认证数据包到达到现在经过的单调时间。</summary>
    public TimeSpan TimeSinceLastReceive => Stopwatch.GetElapsedTime(Volatile.Read(ref _lastActivity));
    /// <summary>获取在连接关闭时完成的任务。</summary>
    public Task Closed => _closed.Task;
    /// <summary>获取导致连接终止的意外后台故障；没有故障时为空。</summary>
    public Exception? CloseException => Volatile.Read(ref _closeException);
    /// <summary>获取因连接的有界解码队列已满而丢弃的 UDP 数据包数量。</summary>
    public long DroppedIncomingPacketCount => Interlocked.Read(ref _droppedIncomingPackets);
    /// <summary>Number of successfully submitted UDP packets, including control frames.</summary>
    public long SentPacketCount => Interlocked.Read(ref _sentPacketCount);
    /// <summary>获取双方端点当前都能接受的最大不可靠应用数据报长度。</summary>
    public int MaximumDatagramPayloadSize => (int)Math.Min(
        (ulong)Math.Max(0, _options.MaxUdpPayloadSize - 64), Volatile.Read(ref _peerMaxDatagramFrameSize));
    /// <summary>
    /// 获取或设置Connected。
    /// </summary>
    /// <returns>Connected。</returns>
    internal Task Connected => _connected.Task;

    /// <summary>
    /// 创建Client。
    /// </summary>
    /// <param name="options">操作配置选项。</param>
    /// <param name="socket">socket参数。</param>
    /// <param name="localCid">local Cid参数。</param>
    /// <param name="remoteCid">remote Cid参数。</param>
    /// <param name="cancellationToken">用于取消异步操作的令牌。</param>
    /// <returns>操作结果。</returns>
    internal static async ValueTask<QuicConnection> CreateClientAsync(QuicClientOptions options, Socket socket,
        QuicConnectionId localCid, QuicConnectionId remoteCid, CancellationToken cancellationToken)
        => await CreateClientCoreAsync(options, socket, ownsSocket: true, startReceiveLoop: true,
            localCid, remoteCid, register: null, cancellationToken).ConfigureAwait(false);

    /// <summary>创建由共享套接字路由器接收数据包的客户端连接。</summary>
    /// <param name="options">已经校验的客户端传输选项。</param>
    /// <param name="socket">由多条连接和原始数据报共享的已绑定、未连接 UDP 套接字。</param>
    /// <param name="localCid">在共享路由器中注册的连接标识符。</param>
    /// <param name="remoteCid">初始目标连接标识符。</param>
    /// <param name="register">在发送第一个握手数据包前注册连接的回调。</param>
    /// <param name="cancellationToken">用于取消连接建立的标记。</param>
    /// <returns>不拥有套接字且不直接从套接字接收数据的认证连接。</returns>
    internal static ValueTask<QuicConnection> CreateAttachedClientAsync(QuicClientOptions options, Socket socket,
        QuicConnectionId localCid, QuicConnectionId remoteCid, Func<QuicConnection, bool> register,
        CancellationToken cancellationToken)
        => CreateClientCoreAsync(options, socket, ownsSocket: false, startReceiveLoop: false,
            localCid, remoteCid, register, cancellationToken);

    /// <summary>创建并握手拥有套接字或由外部路由的客户端连接。</summary>
    /// <param name="options">已经校验的客户端传输选项。</param>
    /// <param name="socket">每次发送数据包都使用的 UDP 套接字。</param>
    /// <param name="ownsSocket">释放连接时是否同时释放套接字。</param>
    /// <param name="startReceiveLoop">连接是否直接读取套接字，而不是接收路由后的数据包。</param>
    /// <param name="localCid">本地路由使用的连接标识符。</param>
    /// <param name="remoteCid">初始对端目标连接标识符。</param>
    /// <param name="register">首次发送前注册连接的可选回调。</param>
    /// <param name="cancellationToken">用于取消握手的标记。</param>
    /// <returns>经过认证的连接。</returns>
    private static async ValueTask<QuicConnection> CreateClientCoreAsync(QuicClientOptions options, Socket socket,
        bool ownsSocket, bool startReceiveLoop, QuicConnectionId localCid, QuicConnectionId remoteCid,
        Func<QuicConnection, bool>? register, CancellationToken cancellationToken)
    {
        var handshake = await options.KeyProvider.CreateClientAsync(options.ServerName, cancellationToken).ConfigureAwait(false);
        var connection = new QuicConnection(options, socket, ownsSocket, false, options.RemoteEndPoint,
            localCid, remoteCid, handshake);
        try
        {
            if (register is not null && !register(connection))
                throw new InvalidOperationException("The local connection identifier is already registered.");
            connection.Start(startReceiveLoop);
            await connection.QueueHandshakeAsync(client: true, cancellationToken).ConfigureAwait(false);
            await connection._connected.Task.WaitAsync(options.HandshakeTimeout, cancellationToken).ConfigureAwait(false);
            return connection;
        }
        catch
        {
            await connection.DisposeAsync().ConfigureAwait(false);
            throw;
        }
    }

    /// <summary>
    /// 创建Server。
    /// </summary>
    /// <param name="options">操作配置选项。</param>
    /// <param name="socket">socket参数。</param>
    /// <param name="remote">remote参数。</param>
    /// <param name="localCid">local Cid参数。</param>
    /// <param name="remoteCid">remote Cid参数。</param>
    /// <param name="cancellationToken">用于取消异步操作的令牌。</param>
    /// <returns>操作结果。</returns>
    internal static async ValueTask<QuicConnection> CreateServerAsync(QuicServerOptions options, Socket socket,
        IPEndPoint remote, QuicConnectionId localCid, QuicConnectionId remoteCid, CancellationToken cancellationToken)
    {
        var handshake = await options.KeyProvider.CreateServerAsync(cancellationToken).ConfigureAwait(false);
        var connection = new QuicConnection(options, socket, false, true, remote, localCid, remoteCid, handshake);
        connection.Start(startReceiveLoop: false);
        return connection;
    }

    /// <summary>
    /// 执行Start操作。
    /// </summary>
    /// <param name="startReceiveLoop">start Receive Loop参数。</param>
    private void Start(bool startReceiveLoop)
    {
        _processTask = ProcessLoopAsync(); _sendTask = SendLoopAsync();
        _recoveryTask = RecoveryLoopAsync();
        if (startReceiveLoop) _receiveTask = ReceiveLoopAsync();
    }

    /// <summary>打开一条由本地发起的双向流。</summary>
    /// <returns>可读写的流。</returns>
    public QuicStream OpenBidirectionalStream()
    {
        EnsureConnected();
        ulong id = (ulong)(Interlocked.Add(ref _nextBidiStreamId, 4) - 4);
        if (id / 4 >= Volatile.Read(ref _peerMaxBidirectionalStreams)) throw new InvalidOperationException("The peer's bidirectional stream limit was reached.");
        return _streams.GetOrAdd(id, CreateStream);
    }

    /// <summary>打开一条由本地发起且仅可写的单向流。</summary>
    /// <returns>可写的流。</returns>
    public QuicStream OpenUnidirectionalStream()
    {
        EnsureConnected();
        ulong id = (ulong)(Interlocked.Add(ref _nextUniStreamId, 4) - 4);
        if (id / 4 >= Volatile.Read(ref _peerMaxUnidirectionalStreams)) throw new InvalidOperationException("The peer's unidirectional stream limit was reached.");
        return _streams.GetOrAdd(id, CreateStream);
    }

    /// <summary>等待对端创建流。</summary>
    /// <param name="cancellationToken">用于取消等待的标记。</param>
    /// <returns>对端新创建的流。</returns>
    public ValueTask<QuicStream> AcceptStreamAsync(CancellationToken cancellationToken = default) =>
        _acceptedStreams.Reader.ReadAsync(cancellationToken);

    /// <summary>将一个不可靠、无序应用数据报加入队列。</summary>
    /// <param name="payload">数据报字节，将复制到池化传输内存。</param>
    /// <param name="cancellationToken">用于取消排队的标记。</param>
    /// <returns>数据报进入有界发送队列时完成的操作。</returns>
    public async ValueTask SendDatagramAsync(ReadOnlyMemory<byte> payload, CancellationToken cancellationToken = default)
    {
        EnsureConnected();
        if (payload.IsEmpty) throw new ArgumentException("A datagram cannot be empty.", nameof(payload));
        if (payload.Length > MaximumDatagramPayloadSize)
            throw new ArgumentOutOfRangeException(nameof(payload), "The datagram exceeds the peer's advertised limit.");
        var segment = PooledSegment.CopyFrom(payload.Span);
        try
        {
            await _outgoing.Writer.WriteAsync(new(0, 0, segment, false, false, false, Datagram: true), cancellationToken).ConfigureAwait(false);
            segment = null!;
            WakeSendLoop();
        }
        finally { segment?.Dispose(); }
    }

    /// <summary>尝试将一个不可靠数据报加入队列，不在已经饱和的应用队列后等待。</summary>
    /// <param name="payload">数据报字节；队列有容量时复制到池化传输内存。</param>
    /// <returns>成功排队时返回 <see langword="true"/>；有界队列已满时返回 <see langword="false"/>。</returns>
    public bool TrySendDatagram(ReadOnlySpan<byte> payload)
        => TrySendDatagram(payload, QuicDatagramPriority.Normal);

    /// <summary>尝试将一个不可靠数据报加入选定的有界服务队列。</summary>
    /// <param name="payload">数据报字节；队列有容量时复制到池化传输内存。</param>
    /// <param name="priority">本地调度优先级；交互流量必须保持低带宽。</param>
    /// <returns>成功排队时返回 <see langword="true"/>；对应有界队列已满时返回 <see langword="false"/>。</returns>
    public bool TrySendDatagram(ReadOnlySpan<byte> payload, QuicDatagramPriority priority)
    {
        EnsureConnected();
        if (payload.IsEmpty) throw new ArgumentException("A datagram cannot be empty.", nameof(payload));
        if (payload.Length > MaximumDatagramPayloadSize)
            throw new ArgumentOutOfRangeException(nameof(payload), "The datagram exceeds the peer's advertised limit.");
        if (priority is not QuicDatagramPriority.Normal and not QuicDatagramPriority.Interactive)
            throw new ArgumentOutOfRangeException(nameof(priority));
        var segment = PooledSegment.CopyFrom(payload);
        bool interactive = priority == QuicDatagramPriority.Interactive;
        ChannelWriter<SendCommand> writer = interactive
            ? _interactiveOutgoing.Writer
            : _outgoing.Writer;
        if (!writer.TryWrite(new(0, 0, segment, false, false, false,
            Datagram: true, Priority: interactive)))
        {
            segment.Dispose();
            return false;
        }
        WakeSendLoop();
        return true;
    }

    /// <summary>等待一个不可靠、无序应用数据报。</summary>
    /// <param name="cancellationToken">用于取消等待的标记。</param>
    /// <returns>池化数据报字节的可释放所有者。</returns>
    public async ValueTask<QuicDatagram> ReceiveDatagramAsync(CancellationToken cancellationToken = default) =>
        new(await _datagrams.Reader.ReadAsync(cancellationToken).ConfigureAwait(false));

    /// <summary>发送一个可触发确认的保活数据包。</summary>
    /// <param name="cancellationToken">用于取消排队或发送的标记。</param>
    /// <returns>数据包交给 UDP 后完成的操作。</returns>
    public async ValueTask PingAsync(CancellationToken cancellationToken = default)
    {
        EnsureConnected();
        var completion = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        await _controlOutgoing.Writer.WriteAsync(new(0, 0, null, false, false, false,
            Ping: true, Priority: true, Completion: completion), cancellationToken).ConfigureAwait(false);
        WakeSendLoop();
        await completion.Task.WaitAsync(cancellationToken).ConfigureAwait(false);
    }

    /// <summary>发送连接关闭帧并停止此连接。</summary>
    /// <param name="errorCode">应用定义的错误代码。</param>
    /// <param name="reason">简短的 UTF-8 诊断原因。</param>
    /// <param name="cancellationToken">用于取消优雅发送的标记。</param>
    /// <returns>关闭数据包交给 UDP 后完成的操作。</returns>
    public async ValueTask CloseAsync(ulong errorCode = 0, string reason = "", CancellationToken cancellationToken = default)
    {
        if (Volatile.Read(ref _state) == 2) return;
        byte[] reasonBytes = Encoding.UTF8.GetBytes(reason ?? string.Empty);
        if (reasonBytes.Length > 1024) throw new ArgumentOutOfRangeException(nameof(reason), "The UTF-8 reason must not exceed 1024 bytes.");
        var segment = PooledSegment.CopyFrom(reasonBytes);
        var completion = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        try
        {
            // 关闭帧必须排在此前已经提交的流和 DATAGRAM 数据之后，避免优雅关闭越过数据。
            await _outgoing.Writer.WriteAsync(new(0, 0, segment, false, false, false,
                Close: true, ErrorCode: errorCode, Completion: completion), cancellationToken)
                .ConfigureAwait(false);
            segment = null!;
            WakeSendLoop();
            await completion.Task.WaitAsync(cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            segment?.Dispose();
            CloseNow(errorCode);
        }
    }

    /// <summary>立即中止连接并释放全部待处理传输等待。</summary>
    /// <param name="errorCode">为本地关闭记录的应用定义错误代码。</param>
    public void Abort(ulong errorCode = 1) => CloseNow(errorCode);

    /// <summary>
    /// 尝试Enqueue。
    /// </summary>
    /// <param name="datagram">datagram参数。</param>
    /// <returns>操作是否成功。</returns>
    internal bool TryEnqueue(PooledDatagram datagram)
    {
        if (_incoming.Writer.TryWrite(datagram)) return true;
        Interlocked.Increment(ref _droppedIncomingPackets);
        datagram.Dispose(); return false;
    }

    /// <summary>
    /// 执行Receive Loop操作。
    /// </summary>
    /// <returns>操作结果。</returns>
    private async Task ReceiveLoopAsync()
    {
        try
        {
            while (!_lifetime.IsCancellationRequested)
            {
                var datagram = PooledDatagram.Rent(_options.MaxUdpPayloadSize);
                try
                {
                    int length = await _socket.ReceiveAsync(datagram.WritableMemory, SocketFlags.None, _lifetime.Token).ConfigureAwait(false);
                    datagram.Length = length; datagram.RemoteEndPoint = _remoteEndPoint;
                    await _incoming.Writer.WriteAsync(datagram, _lifetime.Token).ConfigureAwait(false);
                    datagram = null!;
                }
                finally { datagram?.Dispose(); }
            }
        }
        catch (OperationCanceledException) { }
        catch (ObjectDisposedException) { }
        catch (Exception exception) { FailConnection(exception); }
    }

    /// <summary>
    /// 执行Process Loop操作。
    /// </summary>
    /// <returns>操作结果。</returns>
    private async Task ProcessLoopAsync()
    {
        byte[] plaintext = ArrayPool<byte>.Shared.Rent(_options.MaxUdpPayloadSize);
        try
        {
            await foreach (var datagram in _incoming.Reader.ReadAllAsync(_lifetime.Token).ConfigureAwait(false))
            {
                using (datagram)
                {
                    long expectedPacketNumber;
                    lock (_receivedLock) expectedPacketNumber = _receivedPackets.Largest + 1;
                    if (!ProtectedPacketCodec.TryDecode(datagram.Memory.Span, _options.ConnectionIdLength, _protector,
                        expectedPacketNumber, plaintext, out var header, out long pn, out int length)) continue;
                    _lastActivity = Stopwatch.GetTimestamp();
                    if (datagram.RemoteEndPoint is IPEndPoint authenticatedRemote &&
                        !authenticatedRemote.Equals(_remoteEndPoint))
                        _remoteEndPoint = authenticatedRemote;
                    if (header.SourceConnectionId.Length != 0) _remoteConnectionId = header.SourceConnectionId;
                    lock (_receivedLock)
                    {
                        if (!_receivedPackets.Add(pn)) continue;
                    }
                    ProcessFrames(plaintext.AsSpan(0, length));
                }
            }
        }
        catch (OperationCanceledException) { }
        catch (Exception exception) { FailConnection(exception); }
        finally { ArrayPool<byte>.Shared.Return(plaintext); }
    }

    /// <summary>
    /// 执行Process Frames操作。
    /// </summary>
    /// <param name="payload">payload参数。</param>
    private void ProcessFrames(ReadOnlySpan<byte> payload)
    {
        var reader = new QuicFrameReader(payload);
        bool ackEliciting = false;
        while (reader.TryRead(out var frame))
        {
            switch (frame.Kind)
            {
                case QuicFrameKind.Padding: break;
                case QuicFrameKind.Ack: Acknowledge(frame.A, frame.C, frame.Data); break;
                case QuicFrameKind.Crypto: ProcessHandshakeFrame(frame.Data); ackEliciting = true; break;
                case QuicFrameKind.Stream: ProcessStreamFrame(frame.A, frame.B, frame.Data, frame.Flag); ackEliciting = true; break;
                case QuicFrameKind.MaxData: _sendFlow.UpdateConnectionLimit(frame.A); ackEliciting = true; break;
                case QuicFrameKind.MaxStreamData: _sendFlow.UpdateStreamLimit(frame.A, frame.B); ackEliciting = true; break;
                case QuicFrameKind.Datagram:
                    var datagram = PooledSegment.CopyFrom(frame.Data);
                    if (!_datagrams.Writer.TryWrite(datagram)) datagram.Dispose();
                    ackEliciting = true;
                    break;
                case QuicFrameKind.ConnectionClose: CloseNow(frame.A); break;
                default: ackEliciting = true; break;
            }
        }
        if (ackEliciting && IsConnected) ScheduleAck();
    }

    /// <summary>
    /// 执行Process Handshake Frame操作。
    /// </summary>
    /// <param name="data">待处理的数据。</param>
    private void ProcessHandshakeFrame(ReadOnlySpan<byte> data)
    {
        if (_isServer && TransportParameterCodec.TryDecode(data, server: false, out var peer))
        {
            ApplyPeerParameters(peer);
            MarkConnected();
            var segment = TransportParameterCodec.Encode(server: true, GetLocalParameters());
            if (!TryQueueControl(new(0, 0, segment, false, true, false, Priority: true))) segment.Dispose();
            return;
        }
        if (!_isServer && TransportParameterCodec.TryDecode(data, server: true, out peer))
        {
            ApplyPeerParameters(peer);
            MarkConnected();
        }
    }

    /// <summary>
    /// 执行Process Stream Frame操作。
    /// </summary>
    /// <param name="id">唯一标识。</param>
    /// <param name="offset">数据起始偏移量。</param>
    /// <param name="data">待处理的数据。</param>
    /// <param name="fin">fin参数。</param>
    private void ProcessStreamFrame(ulong id, ulong offset, ReadOnlySpan<byte> data, bool fin)
    {
        bool initiatedByServer = (id & 1) != 0;
        bool peerInitiated = initiatedByServer != _isServer;
        bool bidirectional = (id & 2) == 0;
        ulong ordinal = id / 4;
        if (peerInitiated && ordinal >= (ulong)(bidirectional ? _options.MaxBidirectionalStreams : _options.MaxUnidirectionalStreams))
        { CloseNow(0x04); return; }
        bool created = false;
        var stream = _streams.GetOrAdd(id, key => { created = true; return CreateStream(key); });
        if (!stream.CanRead || !stream.TryReceive(offset, data, fin, out int accepted)) { CloseNow(0x03); return; }
        if (accepted != 0 && Interlocked.Add(ref _receivedStreamBytes, accepted) >
            Interlocked.Read(ref _consumedStreamBytes) + _options.InitialConnectionWindow)
        { CloseNow(0x03); return; }
        if (created && !_acceptedStreams.Writer.TryWrite(stream)) CloseNow(0x03);
    }

    /// <summary>
    /// 创建Stream。
    /// </summary>
    /// <param name="id">唯一标识。</param>
    /// <returns>操作结果。</returns>
    private QuicStream CreateStream(ulong id)
    {
        bool initiatedByServer = (id & 1) != 0;
        bool localInitiated = initiatedByServer == _isServer;
        bool bidirectional = (id & 2) == 0;
        int receiveQueueCapacity = Math.Clamp(
            (int)Math.Ceiling((double)_options.InitialStreamWindow / Math.Max(1, _options.MaxUdpPayloadSize - 128)) + 8,
            16, 65_536);
        return new(id, canRead: bidirectional || !localInitiated, canWrite: bidirectional || localInitiated,
            receiveQueueCapacity, (ulong)_options.InitialStreamWindow, SendStreamAsync, OnStreamBytesConsumed);
    }

    /// <summary>
    /// 执行Send Stream操作。
    /// </summary>
    /// <param name="stream">用于读取或写入数据的流。</param>
    /// <param name="data">待处理的数据。</param>
    /// <param name="fin">fin参数。</param>
    /// <param name="cancellationToken">用于取消异步操作的令牌。</param>
    /// <returns>操作结果。</returns>
    private async ValueTask SendStreamAsync(QuicStream stream, ReadOnlyMemory<byte> data, bool fin, CancellationToken cancellationToken)
    {
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, _lifetime.Token);
        CancellationToken sendToken = linked.Token;
        try
        {
            int maximum = Math.Max(1, _options.MaxUdpPayloadSize - 128);
            if (data.IsEmpty)
            {
                await QueueOwnedAsync(new(stream.Id, (ulong)stream.WriteOffset,
                    PooledSegment.CopyFrom(ReadOnlySpan<byte>.Empty), fin, false, false), sendToken).ConfigureAwait(false);
                return;
            }
            int offset = 0;
            while (offset < data.Length)
            {
                int count = Math.Min(maximum, data.Length - offset);
                await _sendFlow.ReserveAsync(stream.Id, count, sendToken).AsTask()
                    .WaitAsync(_options.SendStallTimeout, sendToken).ConfigureAwait(false);
                bool segmentFin = fin && offset + count == data.Length;
                var command = new SendCommand(stream.Id, (ulong)(stream.WriteOffset + offset),
                    PooledSegment.CopyFrom(data.Span.Slice(offset, count)), segmentFin, false, false);
                await QueueOwnedAsync(command, sendToken).ConfigureAwait(false);
                offset += count;
            }
        }
        catch { CloseNow(0x01); throw; }
    }

    /// <summary>
    /// 执行Queue Owned操作。
    /// </summary>
    /// <param name="command">command参数。</param>
    /// <param name="cancellationToken">用于取消异步操作的令牌。</param>
    /// <returns>操作结果。</returns>
    private async ValueTask QueueOwnedAsync(SendCommand command, CancellationToken cancellationToken)
    {
        PooledSegment? owner = command.Payload;
        try
        {
            ChannelWriter<SendCommand> writer = command.Priority ? _controlOutgoing.Writer : _outgoing.Writer;
            await writer.WriteAsync(command, cancellationToken).AsTask()
                .WaitAsync(_options.SendStallTimeout, cancellationToken).ConfigureAwait(false);
            owner = null;
            WakeSendLoop();
        }
        finally { owner?.Dispose(); }
    }

    /// <summary>
    /// 执行Queue Handshake操作。
    /// </summary>
    /// <param name="client">client参数。</param>
    /// <param name="cancellationToken">用于取消异步操作的令牌。</param>
    /// <returns>操作结果。</returns>
    private async ValueTask QueueHandshakeAsync(bool client, CancellationToken cancellationToken)
    {
        var segment = TransportParameterCodec.Encode(server: !client, GetLocalParameters());
        await QueueOwnedAsync(new(0, 0, segment, false, true, false, Priority: true), cancellationToken).ConfigureAwait(false);
    }
    /// <summary>
    /// 执行Schedule Ack操作。
    /// </summary>
    private void ScheduleAck()
    {
        lock (_receivedLock)
        {
            if (_ackElicitingPending++ == 0) _ackPendingSince = Stopwatch.GetTimestamp();
            if (_ackElicitingPending >= 2) RequestAckUnsafe();
        }
    }

    /// <summary>
    /// 执行Request Ack Unsafe操作。
    /// </summary>
    private void RequestAckUnsafe()
    {
        if (Interlocked.Exchange(ref _ackRequested, 1) == 0) WakeSendLoop();
    }

    /// <summary>
    /// 执行Wake Send Loop操作。
    /// </summary>
    private void WakeSendLoop()
    {
        _sendWakeup.Writer.TryWrite(0);
        // ACK, loss recovery and pending control traffic can also unblock a sender
        // already holding a data command and waiting for congestion credit.
        if (_sendProgress.CurrentCount == 0)
            try { _sendProgress.Release(); } catch (SemaphoreFullException) { }
    }

    /// <summary>
    /// 尝试Queue Control。
    /// </summary>
    /// <param name="command">command参数。</param>
    /// <returns>操作是否成功。</returns>
    private bool TryQueueControl(SendCommand command)
    {
        if (!_controlOutgoing.Writer.TryWrite(command)) return false;
        WakeSendLoop();
        return true;
    }

    /// <summary>
    /// 获取Local Parameters。
    /// </summary>
    /// <returns>操作结果。</returns>
    private QuicTransportParameters GetLocalParameters() => new()
    {
        InitialConnectionWindow = (ulong)_options.InitialConnectionWindow,
        InitialStreamWindow = (ulong)_options.InitialStreamWindow,
        MaxBidirectionalStreams = (ulong)_options.MaxBidirectionalStreams,
        MaxUnidirectionalStreams = (ulong)_options.MaxUnidirectionalStreams,
        MaxDatagramFrameSize = (ulong)Math.Max(0, _options.MaxUdpPayloadSize - 64)
    };

    /// <summary>
    /// 执行Apply Peer Parameters操作。
    /// </summary>
    /// <param name="parameters">parameters参数。</param>
    private void ApplyPeerParameters(QuicTransportParameters parameters)
    {
        _sendFlow.UpdateConnectionLimit(parameters.InitialConnectionWindow);
        _sendFlow.UpdateDefaultStreamLimit(parameters.InitialStreamWindow);
        Volatile.Write(ref _peerMaxBidirectionalStreams, parameters.MaxBidirectionalStreams);
        Volatile.Write(ref _peerMaxUnidirectionalStreams, parameters.MaxUnidirectionalStreams);
        Volatile.Write(ref _peerMaxDatagramFrameSize, parameters.MaxDatagramFrameSize);
    }

    /// <summary>
    /// 执行On Stream Bytes Consumed操作。
    /// </summary>
    /// <param name="stream">用于读取或写入数据的流。</param>
    /// <param name="count">数据数量。</param>
    private void OnStreamBytesConsumed(QuicStream stream, int count)
    {
        ulong connectionLimit = (ulong)(Interlocked.Add(ref _consumedStreamBytes, count) + _options.InitialConnectionWindow);
        ulong streamLimit = stream.ExtendReceiveLimit(count);
        // Replenish after half a window, not twice for every (often 4-byte) read.
        // Limits remain monotonic and retransmittable; retained credit prevents stalls.
        long advertised = Volatile.Read(ref _advertisedConnectionLimit);
        while ((long)connectionLimit - advertised >= _options.InitialConnectionWindow / 2)
        {
            long previous = Interlocked.CompareExchange(ref _advertisedConnectionLimit, (long)connectionLimit, advertised);
            if (previous == advertised)
            {
                TryQueueControl(new(0, 0, null, false, false, false, connectionLimit, false, Priority: true));
                break;
            }
            advertised = previous;
        }
        if (stream.ShouldAdvertiseReceiveLimit(streamLimit))
            TryQueueControl(new(stream.Id, 0, null, false, false, false, streamLimit, true, Priority: true));
    }

    /// <summary>
    /// 执行Send Loop操作。
    /// </summary>
    /// <returns>操作结果。</returns>
    private async Task SendLoopAsync()
    {
        byte[] frames = ArrayPool<byte>.Shared.Rent(_options.MaxUdpPayloadSize);
        int interactiveBurst = 0;
        try
        {
            while (!_lifetime.IsCancellationRequested)
            {
                if (TryBuildAckPacket(frames, out PooledDatagram? pendingAck))
                {
                    using (pendingAck)
                    {
                        await SendPacketAsync(pendingAck!, _lifetime.Token).ConfigureAwait(false);
                        Volatile.Write(ref _lastSendActivity, Stopwatch.GetTimestamp());
                    }
                    continue;
                }

                SendCommand command;
                bool normalCanSend;
                lock (_sentLock)
                    normalCanSend = _congestion.CanSend(_options.MaxUdpPayloadSize);
                if (_controlOutgoing.Reader.TryRead(out command))
                {
                    // 传输控制始终优先，并且不消耗应用突发发送预算。
                }
                else if (interactiveBurst < 8 && _interactiveOutgoing.Reader.TryRead(out command))
                {
                    interactiveBurst++;
                }
                else if (normalCanSend && _outgoing.Reader.TryRead(out command))
                {
                    interactiveBurst = 0;
                }
                else if (_interactiveOutgoing.Reader.TryRead(out command))
                {
                    interactiveBurst = 1;
                }
                else
                {
                    await _sendWakeup.Reader.ReadAsync(_lifetime.Token).ConfigureAwait(false);
                    continue;
                }

                PooledSegment? payloadOwner = command.Payload;
                try
                {
                    var writer = new QuicFrameWriter(frames);
                    bool inFlight;
                    bool retransmit;
                    if (command.Handshake)
                    { writer.WriteHandshake(command.Payload!.Memory.Span); inFlight = true; retransmit = true; }
                    else if (command.Ack)
                    {
                        lock (_receivedLock)
                        {
                            long largest = _receivedPackets.Largest; if (largest < 0) continue;
                            if (!writer.WriteAck(_receivedPackets)) writer.WriteAck((ulong)largest, 0);
                        }
                        inFlight = false; retransmit = false;
                    }
                    else if (command.FlowLimit != 0)
                    {
                        if (command.StreamFlow) writer.WriteMaxStreamData(command.StreamId, command.FlowLimit);
                        else writer.WriteMaxData(command.FlowLimit);
                        inFlight = true; retransmit = true;
                    }
                    else if (command.Datagram)
                    {
                        writer.WriteDatagram(command.Payload!.Memory.Span);
                        inFlight = true; retransmit = false;
                    }
                    else if (command.Ping) { writer.WritePing(); inFlight = true; retransmit = false; }
                    else if (command.Close)
                    {
                        writer.WriteClose(command.ErrorCode, command.Payload!.Memory.Span);
                        inFlight = false; retransmit = false;
                    }
                    else
                    {
                        writer.WriteStream(command.StreamId, command.Offset, command.Payload!.Memory.Span, command.Fin);
                        inFlight = true; retransmit = true;
                    }
                    long pn = Interlocked.Increment(ref _nextPacketNumber) - 1;
                    PooledDatagram packet = command.Handshake
                        ? ProtectedPacketCodec.EncodeInitial(_remoteConnectionId, LocalConnectionId, pn, frames.AsSpan(0, writer.Written), _protector)
                        : ProtectedPacketCodec.EncodeOneRtt(_remoteConnectionId, pn, frames.AsSpan(0, writer.Written), _protector);
                    using (packet)
                    {
                        long congestionWaitStarted = Stopwatch.GetTimestamp();
                        while (inFlight && !command.Probe)
                        {
                            lock (_sentLock)
                            {
                                bool canSend = command.Priority
                                    ? _congestion.CanSendPriority(packet.Length)
                                    : _congestion.CanSend(packet.Length);
                                if (canSend) break;
                            }
                            if (TryBuildAckPacket(frames, out pendingAck))
                            {
                                using (pendingAck)
                                {
                                    await SendPacketAsync(pendingAck!, _lifetime.Token).ConfigureAwait(false);
                                    Volatile.Write(ref _lastSendActivity, Stopwatch.GetTimestamp());
                                }
                                continue;
                            }
                            if (Stopwatch.GetElapsedTime(congestionWaitStarted) >= _options.SendStallTimeout)
                                throw new TimeoutException("The congestion window made no progress before the send-stall timeout.");
                            await _sendProgress.WaitAsync(50, _lifetime.Token).ConfigureAwait(false);
                        }
                        // Publish in-flight ownership before submitting to the socket: a
                        // loopback/LAN ACK can otherwise arrive before registration.
                        if (inFlight)
                        {
                            long now = Stopwatch.GetTimestamp();
                            lock (_sentLock)
                            {
                                _congestion.OnPacketSent(packet.Length, true);
                                SendCommand retained = retransmit ? command : command with { Payload = null, Completion = null };
                                _sentPackets[pn] = new(packet.Length, now, retained, retransmit);
                            }
                            if (retransmit) payloadOwner = null;
                        }
                        await SendPacketAsync(packet, _lifetime.Token).ConfigureAwait(false);
                        Volatile.Write(ref _lastSendActivity, Stopwatch.GetTimestamp());
                        command.Completion?.TrySetResult();
                        if (command.Close) CloseNow(command.ErrorCode);
                    }
                }
                finally { payloadOwner?.Dispose(); }
            }
        }
        catch (OperationCanceledException) { }
        catch (Exception exception) { FailConnection(exception); }
        finally { ArrayPool<byte>.Shared.Return(frames); }
    }

    /// <summary>
    /// 尝试Build Ack Packet。
    /// </summary>
    /// <param name="frames">frames参数。</param>
    /// <param name="packet">packet参数。</param>
    /// <returns>操作是否成功。</returns>
    private bool TryBuildAckPacket(byte[] frames, out PooledDatagram? packet)
    {
        packet = null;
        if (Interlocked.Exchange(ref _ackRequested, 0) == 0) return false;
        int written;
        lock (_receivedLock)
        {
            if (_ackElicitingPending == 0 || _receivedPackets.Largest < 0) return false;
            var writer = new QuicFrameWriter(frames);
            if (!writer.WriteAck(_receivedPackets))
            {
                writer = new QuicFrameWriter(frames);
                if (!writer.WriteAck((ulong)_receivedPackets.Largest, 0)) return false;
            }
            written = writer.Written;
            _ackElicitingPending = 0;
            _ackPendingSince = 0;
        }
        long packetNumber = Interlocked.Increment(ref _nextPacketNumber) - 1;
        packet = ProtectedPacketCodec.EncodeOneRtt(
            _remoteConnectionId, packetNumber, frames.AsSpan(0, written), _protector);
        return true;
    }

    /// <summary>
    /// 执行Send Packet操作。
    /// </summary>
    /// <param name="packet">packet参数。</param>
    /// <param name="cancellationToken">用于取消异步操作的令牌。</param>
    /// <returns>操作结果。</returns>
    private async ValueTask SendPacketAsync(PooledDatagram packet, CancellationToken cancellationToken)
    {
        if (_socket.Connected)
            await _socket.SendAsync(packet.Memory, SocketFlags.None, cancellationToken).ConfigureAwait(false);
        else
            await _socket.SendToAsync(packet.Memory, SocketFlags.None, _remoteEndPoint, cancellationToken).ConfigureAwait(false);
        Interlocked.Increment(ref _sentPacketCount);
    }

    /// <summary>
    /// 执行Acknowledge操作。
    /// </summary>
    /// <param name="largest">largest参数。</param>
    /// <param name="firstRange">first Range参数。</param>
    /// <param name="encodedRanges">encoded Ranges参数。</param>
    private void Acknowledge(ulong largest, ulong firstRange, ReadOnlySpan<byte> encodedRanges)
    {
        if (largest > (ulong)QuicVarInt.MaxValue || firstRange > largest) return;
        UpdateLargestAcknowledged((long)largest);
        long rangeEnd = (long)largest;
        long rangeStart = (long)(largest - firstRange);
        AcknowledgeRange(rangeStart, rangeEnd, updateRtt: true);
        while (!encodedRanges.IsEmpty)
        {
            if (!QuicVarInt.TryRead(encodedRanges, out ulong gap, out int read)) return;
            encodedRanges = encodedRanges[read..];
            if (!QuicVarInt.TryRead(encodedRanges, out ulong length, out read)) return;
            encodedRanges = encodedRanges[read..];
            if (gap > (ulong)rangeStart || gap + 2 > (ulong)rangeStart) return;
            rangeEnd = rangeStart - (long)gap - 2;
            if (length > (ulong)rangeEnd) return;
            rangeStart = rangeEnd - (long)length;
            AcknowledgeRange(rangeStart, rangeEnd, updateRtt: false);
        }
    }

    /// <summary>
    /// 执行Acknowledge Range操作。
    /// </summary>
    /// <param name="start">start参数。</param>
    /// <param name="end">end参数。</param>
    /// <param name="updateRtt">update Rtt参数。</param>
    private void AcknowledgeRange(long start, long end, bool updateRtt)
    {
        long now = Stopwatch.GetTimestamp();
        bool releasedCongestionWindow = false;
        lock (_sentLock)
        {
            // .NET 8+ 的 Dictionary 允许在枚举期间 Remove；避免每个 ACK 都分配 Keys.ToArray。
            foreach (KeyValuePair<long, SentPacket> pair in _sentPackets)
            {
                if (pair.Key < start || pair.Key > end) continue;
                if (_sentPackets.Remove(pair.Key, out var sent))
                {
                    _congestion.OnPacketAcknowledged(sent.Bytes, sent.SentAt, now, 0,
                        updateRtt && pair.Key == end);
                    releasedCongestionWindow = true;
                    Volatile.Write(ref _lastPtoProbeAt, 0);
                    sent.Command.Payload?.Dispose();
                }
            }
        }
        if (releasedCongestionWindow) WakeSendLoop();
    }

    /// <summary>
    /// 执行Update Largest Acknowledged操作。
    /// </summary>
    /// <param name="candidate">candidate参数。</param>
    private void UpdateLargestAcknowledged(long candidate)
    {
        long current = Volatile.Read(ref _largestAcknowledged);
        while (candidate > current)
        {
            long observed = Interlocked.CompareExchange(ref _largestAcknowledged, candidate, current);
            if (observed == current) return;
            current = observed;
        }
    }

    /// <summary>
    /// 执行Recovery Loop操作。
    /// </summary>
    /// <returns>操作结果。</returns>
    private async Task RecoveryLoopAsync()
    {
        using var timer = new PeriodicTimer(TimeSpan.FromMilliseconds(10));
        try
        {
            while (await timer.WaitForNextTickAsync(_lifetime.Token).ConfigureAwait(false))
            {
                long now = Stopwatch.GetTimestamp();
                if (now - Volatile.Read(ref _lastActivity) > _options.IdleTimeout.TotalSeconds * Stopwatch.Frequency)
                { CloseNow(0); break; }
                if (now - Volatile.Read(ref _lastSendActivity) > _options.KeepAliveInterval.TotalSeconds * Stopwatch.Frequency)
                {
                    if (TryQueueControl(new(0, 0, null, false, false, false,
                        Ping: true, Priority: true)))
                        Volatile.Write(ref _lastSendActivity, now);
                }
                lock (_receivedLock)
                {
                    if (_ackElicitingPending != 0 && _ackPendingSince != 0 &&
                        now - _ackPendingSince >= Stopwatch.Frequency / 100)
                        RequestAckUnsafe();
                }
                List<SentPacket>? lost = null;
                bool sendProbe = false;
                lock (_sentLock)
                {
                    long largestAcknowledged = Volatile.Read(ref _largestAcknowledged);
                    long lossDelay = _congestion.LossDelayTicks;
                    // 恢复循环每 10ms 执行，直接枚举并删除可避免长期运行时的高频数组分配。
                    foreach (KeyValuePair<long, SentPacket> pair in _sentPackets)
                    {
                        bool packetThreshold = largestAcknowledged >= 0 && pair.Key + 3 <= largestAcknowledged;
                        bool timeThreshold = pair.Key < largestAcknowledged &&
                            now - pair.Value.SentAt >= lossDelay;
                        if (!packetThreshold && !timeThreshold) continue;
                        _sentPackets.Remove(pair.Key);
                        (lost ??= new()).Add(pair.Value);
                        _congestion.OnPacketsLost(pair.Value.Bytes, pair.Value.SentAt);
                    }
                    if (lost is null && _sentPackets.Count != 0)
                    {
                        KeyValuePair<long, SentPacket> oldest = default;
                        bool foundOldest = false;
                        foreach (KeyValuePair<long, SentPacket> pair in _sentPackets)
                        {
                            if (foundOldest && pair.Value.SentAt >= oldest.Value.SentAt) continue;
                            oldest = pair;
                            foundOldest = true;
                        }
                        if (!foundOldest) continue;
                        long oldestSentAt = oldest.Value.SentAt;
                        long lastProbeAt = Volatile.Read(ref _lastPtoProbeAt);
                        long reference = Math.Max(oldestSentAt, lastProbeAt);
                        if (now - reference >= _congestion.ProbeTimeoutTicks)
                        {
                            _congestion.OnProbeTimeout();
                            Volatile.Write(ref _lastPtoProbeAt, now);
                            _sentPackets.Remove(oldest.Key);
                            (lost ??= new()).Add(oldest.Value);
                            _congestion.OnPacketsLost(oldest.Value.Bytes, oldest.Value.SentAt);
                            sendProbe = !oldest.Value.Retransmit;
                        }
                    }
                }
                if (lost is not null)
                {
                    WakeSendLoop();
                    foreach (var packet in lost)
                    {
                        if (!packet.Retransmit) continue;
                        SendCommand retransmission = packet.Command with { Priority = true };
                        if (!TryQueueControl(retransmission)) retransmission.Payload?.Dispose();
                    }
                }
                if (sendProbe) TryQueueControl(new(0, 0, null, false, false, false,
                    Ping: true, Probe: true, Priority: true));
            }
        }
        catch (OperationCanceledException) { }
        catch (Exception exception) { FailConnection(exception); }
    }

    /// <summary>
    /// 执行Mark Connected操作。
    /// </summary>
    private void MarkConnected() { if (Interlocked.CompareExchange(ref _state, 1, 0) == 0) _connected.TrySetResult(); }
    /// <summary>
    /// 执行Ensure Connected操作。
    /// </summary>
    private void EnsureConnected() { if (!IsConnected) throw new InvalidOperationException("The connection is not established."); }

    /// <summary>
    /// 执行Close Internal操作。
    /// </summary>
    /// <param name="errorCode">error Code参数。</param>
    /// <returns>操作结果。</returns>
    private async Task CloseInternalAsync(ulong errorCode)
    {
        CloseNow(errorCode); await Task.CompletedTask;
    }

    /// <summary>
    /// 执行Fail Connection操作。
    /// </summary>
    /// <param name="exception">发生的异常。</param>
    private void FailConnection(Exception exception)
    {
        Interlocked.CompareExchange(ref _closeException, exception, null);
        CloseNow(0x01);
    }

    /// <summary>
    /// 执行Close Now操作。
    /// </summary>
    /// <param name="errorCode">error Code参数。</param>
    private void CloseNow(ulong errorCode)
    {
        if (Interlocked.Exchange(ref _state, 2) == 2) return;
        _lifetime.Cancel(); _incoming.Writer.TryComplete(); _outgoing.Writer.TryComplete();
        _interactiveOutgoing.Writer.TryComplete();
        _controlOutgoing.Writer.TryComplete(); _sendWakeup.Writer.TryComplete();
        _acceptedStreams.Writer.TryComplete(); _datagrams.Writer.TryComplete();
        foreach (QuicStream stream in _streams.Values) stream.Abort();
        _connected.TrySetException(new IOException($"Connection closed with QUIC error {errorCode}.")); _closed.TrySetResult();
    }

    /// <summary>优雅关闭连接并释放全部传输资源。</summary>
    /// <returns>后台循环停止后结束的操作。</returns>
    public async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0) return;
        if (IsConnected)
        {
            using var timeout = new CancellationTokenSource(_options.ShutdownTimeout);
            try { await CloseAsync(0, "Disposed", timeout.Token).ConfigureAwait(false); }
            catch { CloseNow(0); }
        }
        else await CloseInternalAsync(0).ConfigureAwait(false);
        var tasks = new[] { _receiveTask, _processTask, _sendTask, _recoveryTask }.Where(static t => t is not null).Cast<Task>().ToArray();
        try { await Task.WhenAll(tasks).WaitAsync(_options.ShutdownTimeout).ConfigureAwait(false); } catch { }
        while (_incoming.Reader.TryRead(out var queuedDatagram)) queuedDatagram.Dispose();
        while (_outgoing.Reader.TryRead(out var queuedCommand))
        {
            queuedCommand.Payload?.Dispose();
            queuedCommand.Completion?.TrySetCanceled();
        }
        while (_interactiveOutgoing.Reader.TryRead(out var queuedInteractive))
        {
            queuedInteractive.Payload?.Dispose();
            queuedInteractive.Completion?.TrySetCanceled();
        }
        while (_controlOutgoing.Reader.TryRead(out var queuedControl))
        {
            queuedControl.Payload?.Dispose();
            queuedControl.Completion?.TrySetCanceled();
        }
        foreach (var stream in _streams.Values) await stream.DisposeAsync().ConfigureAwait(false);
        while (_datagrams.Reader.TryRead(out var datagram)) datagram.Dispose();
        lock (_sentLock) { foreach (var packet in _sentPackets.Values) packet.Command.Payload?.Dispose(); _sentPackets.Clear(); }
        _protector.Dispose(); await _handshake.DisposeAsync().ConfigureAwait(false);
        _sendWakeup.Writer.TryComplete();
        _lifetime.Dispose(); if (_ownsSocket) _socket.Dispose();
    }

    /// <summary>
    /// 表示 Send Command，并提供相关数据或行为。
    /// </summary>
    /// <param name="StreamId">Stream Id参数。</param>
    /// <param name="Offset">数据起始偏移量。</param>
    /// <param name="Payload">Payload参数。</param>
    /// <param name="Fin">Fin参数。</param>
    /// <param name="Handshake">Handshake参数。</param>
    /// <param name="Ack">Ack参数。</param>
    /// <param name="FlowLimit">Flow Limit参数。</param>
    /// <param name="StreamFlow">Stream Flow参数。</param>
    /// <param name="Datagram">Datagram参数。</param>
    /// <param name="Ping">Ping参数。</param>
    /// <param name="Close">Close参数。</param>
    /// <param name="ErrorCode">Error Code参数。</param>
    /// <param name="Probe">Probe参数。</param>
    /// <param name="Priority">Priority参数。</param>
    /// <param name="Completion">Completion参数。</param>
    private readonly record struct SendCommand(ulong StreamId, ulong Offset, PooledSegment? Payload, bool Fin,
        bool Handshake, bool Ack, ulong FlowLimit = 0, bool StreamFlow = false, bool Datagram = false,
        bool Ping = false, bool Close = false, ulong ErrorCode = 0, bool Probe = false,
        bool Priority = false, TaskCompletionSource? Completion = null);
    /// <summary>
    /// 表示 Sent Packet，并提供相关数据或行为。
    /// </summary>
    /// <param name="Bytes">Bytes参数。</param>
    /// <param name="SentAt">Sent At参数。</param>
    /// <param name="Command">Command参数。</param>
    /// <param name="Retransmit">Retransmit参数。</param>
    private readonly record struct SentPacket(int Bytes, long SentAt, SendCommand Command,
        bool Retransmit);
}
