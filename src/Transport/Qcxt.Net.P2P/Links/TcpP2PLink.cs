namespace Qcxt.Net.P2P.Links;

/// <summary>通过一个已连接的 TCP 套接字提供带长度前缀的有界数据包传输。</summary>
public sealed class TcpP2PLink : IP2PLink
{
    private readonly Socket _socket;
    private readonly NetworkStream _stream;
    private readonly SemaphoreSlim _sendLock = new(1, 1);
    private readonly TaskCompletionSource _closed = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private readonly int _maximumPacketSize;
    private int _disposed;

    /// <summary>创建 TCP 链路并接管其套接字所有权。</summary>
    /// <param name="socket">已连接的 TCP 套接字。</param>
    /// <param name="maximumPacketSize">允许的最大数据包长度。</param>
    /// <param name="id">可选的诊断标识。</param>
    public TcpP2PLink(Socket socket, int maximumPacketSize = 128 * 1024, string? id = null)
    {
        ArgumentNullException.ThrowIfNull(socket);
        if (!socket.Connected) throw new ArgumentException("TCP 套接字必须处于已连接状态。", nameof(socket));
        if (maximumPacketSize is < 64 or > 32 * 1024 * 1024) throw new ArgumentOutOfRangeException(nameof(maximumPacketSize));
        _socket = socket;
        _socket.NoDelay = true;
        _stream = new NetworkStream(socket, ownsSocket: true);
        _maximumPacketSize = maximumPacketSize;
        Id = id ?? $"tcp-{socket.LocalEndPoint}-{socket.RemoteEndPoint}";
    }

    /// <inheritdoc />
    public string Id { get; }
    /// <inheritdoc />
    public P2PTransportKind Kind => P2PTransportKind.TcpDirect;
    /// <inheritdoc />
    public EndPoint? LocalEndPoint => _socket.LocalEndPoint;
    /// <inheritdoc />
    public EndPoint? RemoteEndPoint => _socket.RemoteEndPoint;
    /// <inheritdoc />
    public bool IsReliable => true;
    /// <inheritdoc />
    public bool IsConnected => Volatile.Read(ref _disposed) == 0 && _socket.Connected;
    /// <inheritdoc />
    public int MaximumPacketSize => _maximumPacketSize;
    /// <inheritdoc />
    public Task Closed => _closed.Task;

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
        catch
        {
            _closed.TrySetResult();
            throw;
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
            if (length < 0 || length > _maximumPacketSize) throw new InvalidDataException("TCP P2P 帧长度无效。");
            P2POwnedBuffer owner = P2POwnedBuffer.Rent(length);
            try
            {
                await ReadExactlyAsync(owner.Memory, cancellationToken).ConfigureAwait(false);
                return new P2PReceiveResult(owner, length, Stopwatch.GetTimestamp());
            }
            catch { owner.Dispose(); throw; }
        }
        catch
        {
            _closed.TrySetResult();
            throw;
        }
        finally { ArrayPool<byte>.Shared.Return(header); }
    }

    /// <summary>精确读取请求数量的流字节。</summary>
    /// <param name="destination">目标内存。</param>
    /// <param name="cancellationToken">用于取消读取的标记。</param>
    /// <returns>全部字节到达后结束的异步操作。</returns>
    private async ValueTask ReadExactlyAsync(Memory<byte> destination, CancellationToken cancellationToken)
    {
        int offset = 0;
        while (offset < destination.Length)
        {
            int read = await _stream.ReadAsync(destination[offset..], cancellationToken).ConfigureAwait(false);
            if (read == 0) throw new EndOfStreamException("TCP P2P 链路已关闭。");
            offset += read;
        }
    }

    /// <summary>以幂等方式关闭流、套接字及同步资源。</summary>
    /// <returns>本地清理后立即完成的异步操作。</returns>
    public ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0) return ValueTask.CompletedTask;
        _closed.TrySetResult();
        _stream.Dispose();
        _sendLock.Dispose();
        return ValueTask.CompletedTask;
    }
}
