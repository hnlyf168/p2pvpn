using Qcxt.Net.Quic.Configuration;
using Qcxt.Net.Quic.Memory;
using Qcxt.Net.Quic.Protocol;

namespace Qcxt.Net.Quic;

/// <summary>
/// 在一个已绑定套接字上复用入站、出站 QUIC 连接和应用 UDP 数据报。
/// 这样可以保留 NAT 穿透所建立的 UDP 来源端口。
/// </summary>
public sealed class QuicSharedUdpEndpoint : IAsyncDisposable
{
    private readonly Socket _socket;
    private readonly QuicServerOptions _serverOptions;
    private readonly bool _ownsSocket;
    private readonly ConcurrentDictionary<QuicConnectionId, QuicConnection> _connections = new();
    private readonly ConcurrentBag<Task> _connectionTasks = new();
    private readonly Channel<QuicConnection> _accepted;
    private readonly Channel<PooledDatagram> _rawDatagrams;
    private readonly CancellationTokenSource _lifetime = new();
    private readonly SemaphoreSlim _pendingHandshakes;
    private readonly Task _receiveTask;
    private long _droppedRawDatagrams;
    private int _disposed;

    /// <summary>在已绑定且未连接的 UDP 套接字上初始化并启动共享接收路由器。</summary>
    /// <param name="socket">已绑定的 UDP 套接字；此端点活动期间其他代码不得从中接收数据。</param>
    /// <param name="serverOptions">入站对端连接使用的限制和密钥。</param>
    /// <param name="ownsSocket">释放此端点时是否同时释放 <paramref name="socket"/>。</param>
    public QuicSharedUdpEndpoint(Socket socket, QuicServerOptions serverOptions, bool ownsSocket = false)
    {
        ArgumentNullException.ThrowIfNull(socket);
        ArgumentNullException.ThrowIfNull(serverOptions);
        serverOptions.Validate();
        if (socket.SocketType != SocketType.Dgram || socket.ProtocolType != ProtocolType.Udp)
            throw new ArgumentException("A UDP datagram socket is required.", nameof(socket));
        if (socket.LocalEndPoint is not IPEndPoint local)
            throw new InvalidOperationException("The shared UDP socket must be bound before creating the endpoint.");
        if (socket.Connected)
            throw new InvalidOperationException("The shared UDP socket must remain unconnected so it can reach multiple peers.");
        if (local.AddressFamily != serverOptions.ListenEndPoint.AddressFamily)
            throw new ArgumentException("The socket and server options must use the same address family.", nameof(serverOptions));

        _socket = socket;
        _serverOptions = serverOptions;
        _ownsSocket = ownsSocket;
        _pendingHandshakes = new(serverOptions.MaxPendingHandshakes, serverOptions.MaxPendingHandshakes);
        _accepted = Channel.CreateBounded<QuicConnection>(new BoundedChannelOptions(serverOptions.ConnectionQueueCapacity)
        {
            SingleReader = false,
            SingleWriter = true,
            FullMode = BoundedChannelFullMode.Wait
        });
        _rawDatagrams = Channel.CreateBounded<PooledDatagram>(new BoundedChannelOptions(
            serverOptions.PacketReceiveQueueCapacity)
        {
            SingleReader = true,
            SingleWriter = true,
            FullMode = BoundedChannelFullMode.Wait
        });
        _receiveTask = ReceiveLoopAsync();
    }

    /// <summary>获取原始流量和全部附加 QUIC 连接共同使用的本地 UDP 端点。</summary>
    public IPEndPoint LocalEndPoint => (IPEndPoint)_socket.LocalEndPoint!;

    /// <summary>获取此端点路由的活动或握手中 QUIC 连接数量。</summary>
    public int ConnectionCount => _connections.Count;

    /// <summary>获取因有界应用队列已满而丢弃的原始数据报数量。</summary>
    public long DroppedRawDatagramCount => Interlocked.Read(ref _droppedRawDatagrams);

    /// <summary>在不改变共享套接字本地端口的情况下创建出站 QUIC 连接。</summary>
    /// <param name="options">对端端点、传输限制和认证密钥提供程序。</param>
    /// <param name="cancellationToken">用于取消握手的标记。</param>
    /// <returns>由此端点路由且通过认证的 QUIC 连接。</returns>
    public async ValueTask<QuicConnection> ConnectAsync(QuicClientOptions options,
        CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) != 0, this);
        ArgumentNullException.ThrowIfNull(options);
        options.Validate();
        ValidateCompatible(options);
        var localCid = QuicConnectionId.CreateRandom(options.ConnectionIdLength);
        var remoteCid = QuicConnectionId.CreateRandom(options.ConnectionIdLength);
        QuicConnection? connection = null;
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, _lifetime.Token);
        try
        {
            connection = await QuicConnection.CreateAttachedClientAsync(options, _socket, localCid, remoteCid,
                candidate => _connections.TryAdd(localCid, candidate), linked.Token).ConfigureAwait(false);
            Task lifecycle = TrackConnectionAsync(localCid, connection);
            _connectionTasks.Add(lifecycle);
            return connection;
        }
        catch
        {
            _connections.TryRemove(localCid, out _);
            if (connection is not null) await connection.DisposeAsync().ConfigureAwait(false);
            throw;
        }
    }

    /// <summary>在共享套接字上等待下一条通过认证的入站 QUIC 连接。</summary>
    /// <param name="cancellationToken">用于取消等待的标记。</param>
    /// <returns>下一条已接受的对端连接。</returns>
    public ValueTask<QuicConnection> AcceptConnectionAsync(CancellationToken cancellationToken = default) =>
        _accepted.Reader.ReadAsync(cancellationToken);

    /// <summary>等待一个不属于任何已注册 QUIC 连接的数据包。</summary>
    /// <param name="cancellationToken">用于取消等待的标记。</param>
    /// <returns>池化 UDP 接收缓冲区及其来源端点的可释放所有者。</returns>
    public async ValueTask<QuicUdpDatagram> ReceiveRawDatagramAsync(CancellationToken cancellationToken = default) =>
        new(await _rawDatagrams.Reader.ReadAsync(cancellationToken).ConfigureAwait(false));

    /// <summary>通过附加连接使用的同一本地端口发送非 QUIC UDP 数据报。</summary>
    /// <param name="payload">数据报字节；此操作完成前套接字接口会消费这些字节。</param>
    /// <param name="remoteEndPoint">目标 UDP 端点。</param>
    /// <param name="cancellationToken">用于取消发送的标记。</param>
    /// <returns>提交给套接字的载荷字节数。</returns>
    public ValueTask<int> SendRawDatagramAsync(ReadOnlyMemory<byte> payload, IPEndPoint remoteEndPoint,
        CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) != 0, this);
        ArgumentNullException.ThrowIfNull(remoteEndPoint);
        return _socket.SendToAsync(payload, SocketFlags.None, remoteEndPoint, cancellationToken);
    }

    /// <summary>仅接收每个 UDP 数据包一次，并将其路由到连接或有界原始队列。</summary>
    /// <returns>释放端点并停止套接字接收后完成的任务。</returns>
    private async Task ReceiveLoopAsync()
    {
        EndPoint any = LocalEndPoint.AddressFamily == AddressFamily.InterNetwork
            ? new IPEndPoint(IPAddress.Any, 0) : new IPEndPoint(IPAddress.IPv6Any, 0);
        try
        {
            while (!_lifetime.IsCancellationRequested)
            {
                var datagram = PooledDatagram.Rent(_serverOptions.MaxUdpPayloadSize);
                try
                {
                    SocketReceiveFromResult result = await _socket.ReceiveFromAsync(datagram.WritableMemory,
                        SocketFlags.None, any, _lifetime.Token).ConfigureAwait(false);
                    datagram.Length = result.ReceivedBytes;
                    datagram.RemoteEndPoint = result.RemoteEndPoint;
                    if (QuicPacketParser.TryReadDestinationConnectionId(datagram.Memory.Span,
                        _serverOptions.ConnectionIdLength, out QuicConnectionId dcid, out bool initial))
                    {
                        if (_connections.TryGetValue(dcid, out QuicConnection? existing))
                        {
                            existing.TryEnqueue(datagram);
                            datagram = null!;
                            continue;
                        }
                        if (initial && datagram.Length >= 1200 && result.RemoteEndPoint is IPEndPoint remote &&
                            _connections.Count < _serverOptions.MaxConnections &&
                            QuicPacketParser.TryParse(datagram.Memory.Span, _serverOptions.ConnectionIdLength,
                                out QuicPacketHeader header) && header.Type == QuicPacketType.Initial &&
                            _pendingHandshakes.Wait(0))
                        {
                            if (await TryAcceptInitialAsync(dcid, header.SourceConnectionId, remote, datagram)
                                .ConfigureAwait(false))
                                datagram = null!;
                            continue;
                        }
                    }
                    if (!_rawDatagrams.Writer.TryWrite(datagram))
                    {
                        Interlocked.Increment(ref _droppedRawDatagrams);
                        continue;
                    }
                    datagram = null!;
                }
                finally { datagram?.Dispose(); }
            }
        }
        catch (OperationCanceledException) { }
        catch (ObjectDisposedException) { }
        catch (SocketException) when (_lifetime.IsCancellationRequested) { }
        finally
        {
            _accepted.Writer.TryComplete();
            _rawDatagrams.Writer.TryComplete();
        }
    }

    /// <summary>为已校验的 Initial 数据包创建并注册入站连接。</summary>
    /// <param name="localCid">作为本地路由键的 Initial 目标标识符。</param>
    /// <param name="remoteCid">回复数据包使用的 Initial 来源标识符。</param>
    /// <param name="remote">观察到的 UDP 来源端点。</param>
    /// <param name="initial">成功时转交给连接的池化 Initial 数据包。</param>
    /// <returns><paramref name="initial"/> 的所有权已转移到连接时返回真。</returns>
    private async ValueTask<bool> TryAcceptInitialAsync(QuicConnectionId localCid,
        QuicConnectionId remoteCid, IPEndPoint remote, PooledDatagram initial)
    {
        QuicConnection? connection = null;
        bool registered = false;
        try
        {
            connection = await QuicConnection.CreateServerAsync(_serverOptions, _socket, remote,
                localCid, remoteCid, _lifetime.Token).ConfigureAwait(false);
            registered = _connections.TryAdd(localCid, connection);
            if (!registered)
            {
                await connection.DisposeAsync().ConfigureAwait(false);
                connection = null;
                _pendingHandshakes.Release();
                return false;
            }
            connection.TryEnqueue(initial);
            Task lifecycle = CompleteInboundHandshakeAsync(localCid, connection);
            _connectionTasks.Add(lifecycle);
            return true;
        }
        catch
        {
            if (registered) _connections.TryRemove(localCid, out _);
            if (connection is not null) await connection.DisposeAsync().ConfigureAwait(false);
            _pendingHandshakes.Release();
            return false;
        }
    }

    /// <summary>发布通过认证的入站连接，并在连接关闭后将其移除。</summary>
    /// <param name="id">在路由器中注册的本地连接标识符。</param>
    /// <param name="connection">正在认证的入站连接。</param>
    /// <returns>移除连接并释放握手槽位后结束的生命周期任务。</returns>
    private async Task CompleteInboundHandshakeAsync(QuicConnectionId id, QuicConnection connection)
    {
        try
        {
            await connection.Connected.WaitAsync(_serverOptions.HandshakeTimeout, _lifetime.Token).ConfigureAwait(false);
            await _accepted.Writer.WriteAsync(connection, _lifetime.Token).ConfigureAwait(false);
            await connection.Closed.ConfigureAwait(false);
        }
        catch { await connection.DisposeAsync().ConfigureAwait(false); }
        finally
        {
            _connections.TryRemove(id, out _);
            _pendingHandshakes.Release();
        }
    }

    /// <summary>出站连接关闭后立即将其从路由中移除。</summary>
    /// <param name="id">在路由器中注册的本地连接标识符。</param>
    /// <param name="connection">需要观察的出站连接。</param>
    /// <returns>连接关闭并移除后完成的任务。</returns>
    private async Task TrackConnectionAsync(QuicConnectionId id, QuicConnection connection)
    {
        try { await connection.Closed.ConfigureAwait(false); }
        finally { _connections.TryRemove(id, out _); }
    }

    /// <summary>校验共享同一接收循环的全部数据包必须保持一致的设置。</summary>
    /// <param name="options">需要与端点设置比较的出站连接选项。</param>
    private void ValidateCompatible(QuicClientOptions options)
    {
        if (options.ConnectionIdLength != _serverOptions.ConnectionIdLength)
            throw new ArgumentException("Every connection on a shared socket must use the same connection ID length.", nameof(options));
        if (options.RemoteEndPoint.AddressFamily != LocalEndPoint.AddressFamily)
            throw new ArgumentException("The peer and shared socket must use the same address family.", nameof(options));
        if (options.MaxUdpPayloadSize > _serverOptions.MaxUdpPayloadSize)
            throw new ArgumentException("A connection cannot receive packets larger than the shared endpoint buffer.", nameof(options));
    }

    /// <summary>停止路由、关闭附加连接，并按配置释放 UDP 套接字。</summary>
    /// <returns>接收和连接任务停止后结束的操作。</returns>
    public async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0) return;
        _lifetime.Cancel();
        if (_ownsSocket) _socket.Dispose();
        try { await _receiveTask.ConfigureAwait(false); } catch { }
        QuicConnection[] connections = _connections.Values.ToArray();
        foreach (QuicConnection connection in connections)
            try { connection.Abort(0x202); } catch { }
        foreach (QuicConnection connection in connections)
            await connection.DisposeAsync().ConfigureAwait(false);
        Task[] connectionTasks = _connectionTasks.ToArray();
        if (connectionTasks.Length != 0)
        {
            try { await Task.WhenAll(connectionTasks).WaitAsync(_serverOptions.ShutdownTimeout).ConfigureAwait(false); }
            catch { }
        }
        _connections.Clear();
        while (_rawDatagrams.Reader.TryRead(out PooledDatagram? datagram)) datagram.Dispose();
        while (_accepted.Reader.TryRead(out QuicConnection? connection))
            await connection.DisposeAsync().ConfigureAwait(false);
        _pendingHandshakes.Dispose();
        _lifetime.Dispose();
    }
}
