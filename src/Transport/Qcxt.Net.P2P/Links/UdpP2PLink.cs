namespace Qcxt.Net.P2P.Links;

/// <summary>为测试或已完成认证的私有网络提供固定对端 UDP 路径。</summary>
/// <remarks>公网部署应优先使用 <see cref="QuicDatagramP2PLink"/>，因为原始 UDP 不提供身份保护。</remarks>
public sealed class UdpP2PLink : IP2PLink, IP2PFastSendLink
{
    private readonly Socket _socket;
    private readonly IPEndPoint _remoteEndPoint;
    private readonly TaskCompletionSource _closed = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private readonly int _maximumPacketSize;
    private int _disposed;

    /// <summary>创建固定对端 UDP 链路并接管套接字所有权。</summary>
    /// <param name="socket">已绑定、可连接或未连接的 UDP 套接字。</param>
    /// <param name="remoteEndPoint">唯一允许接收和发送的对端端点。</param>
    /// <param name="maximumPacketSize">允许的最大 UDP 载荷长度。</param>
    /// <param name="id">可选的诊断标识。</param>
    public UdpP2PLink(Socket socket, IPEndPoint remoteEndPoint, int maximumPacketSize = 65_507, string? id = null)
    {
        ArgumentNullException.ThrowIfNull(socket);
        ArgumentNullException.ThrowIfNull(remoteEndPoint);
        if (socket.SocketType != SocketType.Dgram) throw new ArgumentException("必须提供 UDP 套接字。", nameof(socket));
        if (maximumPacketSize is < 64 or > 65_507) throw new ArgumentOutOfRangeException(nameof(maximumPacketSize));
        _socket = socket;
        _remoteEndPoint = remoteEndPoint;
        _maximumPacketSize = maximumPacketSize;
        Id = id ?? $"udp-{socket.LocalEndPoint}-{remoteEndPoint}";
    }

    /// <inheritdoc />
    public string Id { get; }
    /// <inheritdoc />
    public P2PTransportKind Kind => P2PTransportKind.Unknown;
    /// <inheritdoc />
    public EndPoint? LocalEndPoint => _socket.LocalEndPoint;
    /// <inheritdoc />
    public EndPoint? RemoteEndPoint => _remoteEndPoint;
    /// <inheritdoc />
    public bool IsReliable => false;
    /// <inheritdoc />
    public bool IsConnected => Volatile.Read(ref _disposed) == 0;
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
        if (_socket.Connected) await _socket.SendAsync(packet, SocketFlags.None, cancellationToken).ConfigureAwait(false);
        else await _socket.SendToAsync(packet, SocketFlags.None, _remoteEndPoint, cancellationToken).ConfigureAwait(false);
    }

    /// <inheritdoc />
    public bool TrySend(ReadOnlySpan<byte> packet, P2PTrafficClass trafficClass = P2PTrafficClass.Normal)
    {
        ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) != 0, this);
        if (packet.Length > _maximumPacketSize) throw new ArgumentOutOfRangeException(nameof(packet));
        int sent = _socket.Connected
            ? _socket.Send(packet, SocketFlags.None)
            : _socket.SendTo(packet, SocketFlags.None, _remoteEndPoint);
        return sent == packet.Length;
    }

    /// <inheritdoc />
    public async ValueTask<P2PReceiveResult> ReceiveAsync(CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) != 0, this);
        while (true)
        {
            P2POwnedBuffer owner = P2POwnedBuffer.Rent(_maximumPacketSize);
            try
            {
                int length;
                if (_socket.Connected)
                    length = await _socket.ReceiveAsync(owner.Memory, SocketFlags.None, cancellationToken).ConfigureAwait(false);
                else
                {
                    EndPoint any = _remoteEndPoint.AddressFamily == AddressFamily.InterNetwork
                        ? new IPEndPoint(IPAddress.Any, 0) : new IPEndPoint(IPAddress.IPv6Any, 0);
                    SocketReceiveFromResult result = await _socket.ReceiveFromAsync(owner.Memory, SocketFlags.None, any,
                        cancellationToken).ConfigureAwait(false);
                    if (!result.RemoteEndPoint.Equals(_remoteEndPoint)) { owner.Dispose(); continue; }
                    length = result.ReceivedBytes;
                }
                return new P2PReceiveResult(owner, length, Stopwatch.GetTimestamp());
            }
            catch { owner.Dispose(); throw; }
        }
    }

    /// <summary>关闭 UDP 套接字并唤醒关闭状态观察者。</summary>
    /// <returns>已完成的清理操作。</returns>
    public ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0) return ValueTask.CompletedTask;
        _socket.Dispose();
        _closed.TrySetResult();
        return ValueTask.CompletedTask;
    }
}
