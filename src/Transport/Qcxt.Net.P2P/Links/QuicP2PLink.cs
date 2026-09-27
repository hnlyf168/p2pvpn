namespace Qcxt.Net.P2P.Links;

/// <summary>通过一条已认证的 QUIC 流提供可靠的有界数据包传输。</summary>
public sealed class QuicP2PLink : IP2PLink
{
    private readonly QuicConnection _connection;
    private readonly QuicStream _stream;
    private readonly SemaphoreSlim _sendLock = new(1, 1);
    private readonly int _maximumPacketSize;
    private int _disposed;

    /// <summary>创建可靠 QUIC 流链路并接管连接和流的所有权。</summary>
    /// <param name="connection">已认证的 QUIC 连接。</param>
    /// <param name="stream">专用于带帧 P2P 流量的双向流。</param>
    /// <param name="maximumPacketSize">允许的最大数据包长度。</param>
    /// <param name="id">可选的诊断标识。</param>
    public QuicP2PLink(QuicConnection connection, QuicStream stream,
        int maximumPacketSize = 128 * 1024, string? id = null)
    {
        ArgumentNullException.ThrowIfNull(connection);
        ArgumentNullException.ThrowIfNull(stream);
        if (!stream.CanRead || !stream.CanWrite) throw new ArgumentException("必须提供双向流。", nameof(stream));
        if (maximumPacketSize is < 64 or > 32 * 1024 * 1024) throw new ArgumentOutOfRangeException(nameof(maximumPacketSize));
        _connection = connection;
        _stream = stream;
        _maximumPacketSize = maximumPacketSize;
        Id = id ?? $"quic-{connection.LocalEndPoint}-{connection.RemoteEndPoint}";
    }

    /// <inheritdoc />
    public string Id { get; }
    /// <inheritdoc />
    public P2PTransportKind Kind => P2PTransportKind.Quic;
    /// <inheritdoc />
    public EndPoint? LocalEndPoint => _connection.LocalEndPoint;
    /// <inheritdoc />
    public EndPoint? RemoteEndPoint => _connection.RemoteEndPoint;
    /// <inheritdoc />
    public bool IsReliable => true;
    /// <inheritdoc />
    public bool IsConnected => Volatile.Read(ref _disposed) == 0 && _connection.IsConnected;
    /// <inheritdoc />
    public int MaximumPacketSize => _maximumPacketSize;
    /// <inheritdoc />
    public Task Closed => _connection.Closed;

    /// <inheritdoc />
    public async ValueTask SendAsync(ReadOnlyMemory<byte> packet,
        P2PTrafficClass trafficClass = P2PTrafficClass.Normal, CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) != 0, this);
        if (packet.Length > _maximumPacketSize) throw new ArgumentOutOfRangeException(nameof(packet));
        await _sendLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            byte[] header = ArrayPool<byte>.Shared.Rent(4);
            try
            {
                BinaryPrimitives.WriteInt32BigEndian(header, packet.Length);
                await _stream.WriteAsync(header.AsMemory(0, 4), cancellationToken).ConfigureAwait(false);
                await _stream.WriteAsync(packet, cancellationToken).ConfigureAwait(false);
            }
            finally { ArrayPool<byte>.Shared.Return(header); }
        }
        finally { _sendLock.Release(); }
    }

    /// <inheritdoc />
    public async ValueTask<P2PReceiveResult> ReceiveAsync(CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) != 0, this);
        byte[] header = ArrayPool<byte>.Shared.Rent(4);
        try
        {
            await ReadExactlyAsync(header.AsMemory(0, 4), cancellationToken).ConfigureAwait(false);
            int length = BinaryPrimitives.ReadInt32BigEndian(header);
            if (length < 0 || length > _maximumPacketSize) throw new InvalidDataException("QUIC P2P 帧长度无效。");
            P2POwnedBuffer owner = P2POwnedBuffer.Rent(length);
            try
            {
                await ReadExactlyAsync(owner.Memory, cancellationToken).ConfigureAwait(false);
                return new P2PReceiveResult(owner, length, Stopwatch.GetTimestamp());
            }
            catch { owner.Dispose(); throw; }
        }
        finally { ArrayPool<byte>.Shared.Return(header); }
    }

    /// <summary>精确读取请求数量的 QUIC 流字节。</summary>
    /// <param name="destination">目标内存。</param>
    /// <param name="cancellationToken">用于取消读取的标记。</param>
    /// <returns>全部字节到达后结束的异步操作。</returns>
    private async ValueTask ReadExactlyAsync(Memory<byte> destination, CancellationToken cancellationToken)
    {
        int offset = 0;
        while (offset < destination.Length)
        {
            int read = await _stream.ReadAsync(destination[offset..], cancellationToken).ConfigureAwait(false);
            if (read == 0) throw new EndOfStreamException("QUIC P2P 流已关闭。");
            offset += read;
        }
    }

    /// <summary>以幂等方式关闭流及其所属的 QUIC 连接。</summary>
    /// <returns>QUIC 关闭后结束的异步操作。</returns>
    public async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0) return;
        // Retiring a direct path must not wait for an unreachable peer to acknowledge
        // a graceful close, otherwise coordinator re-registration can be blocked.
        try { _connection.Abort(0x202); } catch { }
        await _stream.DisposeAsync().ConfigureAwait(false);
        _sendLock.Dispose();
        await _connection.DisposeAsync().ConfigureAwait(false);
    }
}
