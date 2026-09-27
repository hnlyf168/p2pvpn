namespace Qcxt.Net.P2P.Relay;

/// <summary>表示经已认证协调服务器连接路由的有界虚拟对端路径。</summary>
internal sealed class P2PRelayLink : IP2PLink
{
    private readonly Channel<P2PReceiveResult> _received;
    private readonly Func<ReadOnlyMemory<byte>, P2PTrafficClass, CancellationToken, ValueTask> _sender;
    private readonly TaskCompletionSource _closed = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private readonly int _maximumPacketSize;
    private int _disposed;

    /// <summary>创建一条对端专用的中转路径。</summary>
    /// <param name="id">诊断路径标识。</param>
    /// <param name="kind">可靠流或 DATAGRAM 中转类型。</param>
    /// <param name="maximumPacketSize">允许的最大不透明 P2P 帧长度。</param>
    /// <param name="queueCapacity">有界接收队列容量。</param>
    /// <param name="sender">协调服务器发送委托。</param>
    public P2PRelayLink(string id, P2PTransportKind kind, int maximumPacketSize, int queueCapacity,
        Func<ReadOnlyMemory<byte>, P2PTrafficClass, CancellationToken, ValueTask> sender)
    {
        if (kind is not P2PTransportKind.QuicRelay and not P2PTransportKind.QuicDatagramRelay)
            throw new ArgumentOutOfRangeException(nameof(kind));
        Id = id;
        Kind = kind;
        _maximumPacketSize = maximumPacketSize;
        _sender = sender;
        _received = Channel.CreateBounded<P2PReceiveResult>(new BoundedChannelOptions(queueCapacity)
        {
            SingleReader = true,
            SingleWriter = false,
            FullMode = BoundedChannelFullMode.Wait
        });
    }

    /// <inheritdoc />
    public string Id { get; }
    /// <inheritdoc />
    public P2PTransportKind Kind { get; }
    /// <inheritdoc />
    public EndPoint? LocalEndPoint => null;
    /// <inheritdoc />
    public EndPoint? RemoteEndPoint => null;
    /// <inheritdoc />
    public bool IsReliable => Kind == P2PTransportKind.QuicRelay;
    /// <inheritdoc />
    public bool IsConnected => Volatile.Read(ref _disposed) == 0;
    /// <inheritdoc />
    public int MaximumPacketSize => _maximumPacketSize;
    /// <inheritdoc />
    public Task Closed => _closed.Task;

    /// <inheritdoc />
    public ValueTask SendAsync(ReadOnlyMemory<byte> packet,
        P2PTrafficClass trafficClass = P2PTrafficClass.Normal, CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) != 0, this);
        if (packet.Length > _maximumPacketSize) throw new ArgumentOutOfRangeException(nameof(packet));
        return _sender(packet, trafficClass, cancellationToken);
    }

    /// <inheritdoc />
    public ValueTask<P2PReceiveResult> ReceiveAsync(CancellationToken cancellationToken = default) =>
        _received.Reader.ReadAsync(cancellationToken);

    /// <summary>将协调服务器拥有的一份载荷复制到有界池化链路队列。</summary>
    /// <param name="packet">不透明的已编码 P2P 帧。</param>
    /// <param name="cancellationToken">客户端生命周期取消标记。</param>
    /// <returns>队列接纳数据后结束的异步操作。</returns>
    public async ValueTask DeliverAsync(ReadOnlyMemory<byte> packet, CancellationToken cancellationToken)
    {
        if (packet.Length > _maximumPacketSize || Volatile.Read(ref _disposed) != 0) return;
        P2POwnedBuffer owner = P2POwnedBuffer.CopyFrom(packet.Span);
        var result = new P2PReceiveResult(owner, owner.Length, Stopwatch.GetTimestamp());
        try { await _received.Writer.WriteAsync(result, cancellationToken).ConfigureAwait(false); }
        catch { result.Dispose(); throw; }
    }

    /// <summary>关闭虚拟路径并清空池化消息。</summary>
    /// <returns>已完成的清理操作。</returns>
    public ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0) return ValueTask.CompletedTask;
        _received.Writer.TryComplete();
        while (_received.Reader.TryRead(out P2PReceiveResult? result)) result.Dispose();
        _closed.TrySetResult();
        return ValueTask.CompletedTask;
    }
}
