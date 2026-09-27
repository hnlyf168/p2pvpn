namespace Qcxt.Net.P2P.Links;

/// <summary>通过已认证的 QUIC DATAGRAM 帧提供低延迟不可靠数据包传输。</summary>
public sealed class QuicDatagramP2PLink : IP2PLink, IP2PFastSendLink
{
    private readonly QuicConnection _connection;
    private readonly bool _ownsConnection;
    private int _disposed;

    /// <summary>创建 QUIC DATAGRAM 链路。</summary>
    /// <param name="connection">支持 DATAGRAM 的已认证 QUIC 连接。</param>
    /// <param name="kind">直连或中转诊断传输类型。</param>
    /// <param name="ownsConnection">该链路是否负责释放连接。</param>
    /// <param name="id">可选的诊断标识。</param>
    public QuicDatagramP2PLink(QuicConnection connection, P2PTransportKind kind = P2PTransportKind.Quic,
        bool ownsConnection = true, string? id = null)
    {
        ArgumentNullException.ThrowIfNull(connection);
        if (kind is not P2PTransportKind.Quic and not P2PTransportKind.QuicDatagramRelay)
            throw new ArgumentOutOfRangeException(nameof(kind));
        _connection = connection;
        _ownsConnection = ownsConnection;
        Kind = kind;
        Id = id ?? $"quic-dgram-{connection.LocalEndPoint}-{connection.RemoteEndPoint}";
    }

    /// <inheritdoc />
    public string Id { get; }
    /// <inheritdoc />
    public P2PTransportKind Kind { get; }
    /// <inheritdoc />
    public EndPoint? LocalEndPoint => _connection.LocalEndPoint;
    /// <inheritdoc />
    public EndPoint? RemoteEndPoint => _connection.RemoteEndPoint;
    /// <inheritdoc />
    public bool IsReliable => false;
    /// <inheritdoc />
    public bool IsConnected => Volatile.Read(ref _disposed) == 0 && _connection.IsConnected;
    /// <inheritdoc />
    public int MaximumPacketSize => _connection.MaximumDatagramPayloadSize;
    /// <inheritdoc />
    public Task Closed => _connection.Closed;

    /// <inheritdoc />
    public ValueTask SendAsync(ReadOnlyMemory<byte> packet,
        P2PTrafficClass trafficClass = P2PTrafficClass.Normal, CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) != 0, this);
        if (packet.Length > MaximumPacketSize) throw new ArgumentOutOfRangeException(nameof(packet));
        return SendPrioritizedAsync(_connection, packet, trafficClass, cancellationToken);
    }

    /// <inheritdoc />
    public bool TrySend(ReadOnlySpan<byte> packet, P2PTrafficClass trafficClass = P2PTrafficClass.Normal)
    {
        ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) != 0, this);
        if (packet.Length > MaximumPacketSize) throw new ArgumentOutOfRangeException(nameof(packet));
        QuicDatagramPriority priority = trafficClass == P2PTrafficClass.Interactive
            ? QuicDatagramPriority.Interactive
            : QuicDatagramPriority.Normal;
        return _connection.TrySendDatagram(packet, priority);
    }

    /// <summary>将交互式数据报放入 QUIC 的独立优先级队列。</summary>
    /// <param name="connection">已连接的 QUIC 传输对象。</param>
    /// <param name="packet">完整的数据报字节。</param>
    /// <param name="trafficClass">P2P 流量分类。</param>
    /// <param name="cancellationToken">用于取消有界队列等待的标记。</param>
    /// <returns>所选有界队列接纳数据报后结束的异步操作。</returns>
    internal static async ValueTask SendPrioritizedAsync(QuicConnection connection, ReadOnlyMemory<byte> packet,
        P2PTrafficClass trafficClass, CancellationToken cancellationToken)
    {
        if (trafficClass != P2PTrafficClass.Interactive)
        {
            await connection.SendDatagramAsync(packet, cancellationToken).ConfigureAwait(false);
            return;
        }
        while (!connection.TrySendDatagram(packet.Span, QuicDatagramPriority.Interactive))
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (!connection.IsConnected) throw new IOException("QUIC 数据报连接已关闭。");
            await Task.Delay(1, cancellationToken).ConfigureAwait(false);
        }
    }

    /// <inheritdoc />
    public async ValueTask<P2PReceiveResult> ReceiveAsync(CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) != 0, this);
        QuicDatagram datagram = await _connection.ReceiveDatagramAsync(cancellationToken).ConfigureAwait(false);
        return new P2PReceiveResult(datagram, datagram.Memory.Length, Stopwatch.GetTimestamp());
    }

    /// <summary>将链路标记为已关闭，并按需关闭共享连接。</summary>
    /// <returns>可选的 QUIC 释放完成后结束的异步操作。</returns>
    public async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0) return;
        if (_ownsConnection)
        {
            try { _connection.Abort(0x202); } catch { }
            await _connection.DisposeAsync().ConfigureAwait(false);
        }
    }
}
