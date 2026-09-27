using Qcxt.Net.Quic.Configuration;
using Qcxt.Net.Quic.Memory;
using Qcxt.Net.Quic.Protocol;

namespace Qcxt.Net.Quic;

/// <summary>在一个共享 UDP 套接字上承载多条 QUIC 连接。</summary>
public sealed class QuicServer : IAsyncDisposable
{
    private readonly QuicServerOptions _options;
    private readonly ConcurrentDictionary<QuicConnectionId, QuicConnection> _connections = new();
    private readonly ConcurrentDictionary<QuicConnectionId, Task> _connectionTasks = new();
    private readonly Channel<QuicConnection> _accepted;
    private readonly CancellationTokenSource _lifetime = new();
    private readonly SemaphoreSlim _pendingHandshakes;
    private Socket? _socket;
    private Task? _receiveTask;
    private int _started;

    /// <summary>使用固定资源限制初始化服务端。</summary>
    /// <param name="options">服务端端点、传输限制和密钥提供程序选项。</param>
    public QuicServer(QuicServerOptions options)
    {
        ArgumentNullException.ThrowIfNull(options); options.Validate(); _options = options;
        _pendingHandshakes = new(options.MaxPendingHandshakes, options.MaxPendingHandshakes);
        _accepted = Channel.CreateBounded<QuicConnection>(new BoundedChannelOptions(options.ConnectionQueueCapacity)
        { SingleReader = false, SingleWriter = false, FullMode = BoundedChannelFullMode.Wait });
    }

    /// <summary>获取服务端启动后绑定的本地端点。</summary>
    public IPEndPoint? LocalEndPoint => _socket?.LocalEndPoint as IPEndPoint;
    /// <summary>获取活动连接和握手中连接的数量。</summary>
    public int ConnectionCount => _connections.Count;
    /// <summary>获取服务端保留的连接生命周期任务数量。</summary>
    internal int TrackedConnectionTaskCount => _connectionTasks.Count;

    /// <summary>启动共享 UDP 接收循环。</summary>
    /// <param name="cancellationToken">启动前检查的取消标记。</param>
    /// <returns>套接字绑定完成后结束的操作。</returns>
    public ValueTask StartAsync(CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (Interlocked.Exchange(ref _started, 1) != 0) throw new InvalidOperationException("The server is already started.");
        try
        {
            _socket = new Socket(_options.ListenEndPoint.AddressFamily, SocketType.Dgram, ProtocolType.Udp)
            { ReceiveBufferSize = _options.SocketReceiveBufferSize, SendBufferSize = _options.SocketSendBufferSize };
            if (_socket.AddressFamily == AddressFamily.InterNetworkV6) _socket.DualMode = true;
            _socket.Bind(_options.ListenEndPoint); _receiveTask = ReceiveLoopAsync();
            return ValueTask.CompletedTask;
        }
        catch
        {
            _socket?.Dispose(); _socket = null; Volatile.Write(ref _started, 0); throw;
        }
    }

    /// <summary>等待下一条通过认证的连接。</summary>
    /// <param name="cancellationToken">用于取消等待的标记。</param>
    /// <returns>下一条已经建立的连接。</returns>
    public ValueTask<QuicConnection> AcceptConnectionAsync(CancellationToken cancellationToken = default) =>
        _accepted.Reader.ReadAsync(cancellationToken);

    /// <summary>
    /// 执行Receive Loop操作。
    /// </summary>
    /// <returns>操作结果。</returns>
    private async Task ReceiveLoopAsync()
    {
        EndPoint any = _options.ListenEndPoint.AddressFamily == AddressFamily.InterNetwork
            ? new IPEndPoint(IPAddress.Any, 0) : new IPEndPoint(IPAddress.IPv6Any, 0);
        try
        {
            while (!_lifetime.IsCancellationRequested)
            {
                var datagram = PooledDatagram.Rent(_options.MaxUdpPayloadSize);
                try
                {
                    var result = await _socket!.ReceiveFromAsync(datagram.WritableMemory, SocketFlags.None, any, _lifetime.Token).ConfigureAwait(false);
                    datagram.Length = result.ReceivedBytes; datagram.RemoteEndPoint = result.RemoteEndPoint;
                    if (!QuicPacketParser.TryReadDestinationConnectionId(datagram.Memory.Span, _options.ConnectionIdLength,
                        out var dcid, out bool initial)) continue;
                    if (_connections.TryGetValue(dcid, out var existing))
                    { existing.TryEnqueue(datagram); datagram = null!; continue; }
                    if (!initial || datagram.Length < 1200 || _connections.Count >= _options.MaxConnections ||
                        !_pendingHandshakes.Wait(0)) continue;
                    if (!QuicPacketParser.TryParse(datagram.Memory.Span, _options.ConnectionIdLength, out var header) ||
                        header.Type != QuicPacketType.Initial || result.RemoteEndPoint is not IPEndPoint remote)
                    { _pendingHandshakes.Release(); continue; }
                    QuicConnection? connection = null;
                    try
                    {
                        connection = await QuicConnection.CreateServerAsync(_options, _socket!, remote, dcid,
                            header.SourceConnectionId, _lifetime.Token).ConfigureAwait(false);
                        if (!_connections.TryAdd(dcid, connection))
                        { await connection.DisposeAsync(); _pendingHandshakes.Release(); continue; }
                        connection.TryEnqueue(datagram); datagram = null!;
                        var lifecycle = new TaskCompletionSource(
                            TaskCreationOptions.RunContinuationsAsynchronously);
                        if (!_connectionTasks.TryAdd(dcid, lifecycle.Task))
                        {
                            _connections.TryRemove(dcid, out _);
                            await connection.DisposeAsync();
                            _pendingHandshakes.Release();
                            continue;
                        }
                        _ = CompleteHandshakeAsync(dcid, connection, lifecycle);
                    }
                    catch { if (connection is not null) await connection.DisposeAsync(); _pendingHandshakes.Release(); }
                }
                finally { datagram?.Dispose(); }
            }
        }
        catch (OperationCanceledException) { }
        catch (ObjectDisposedException) { }
    }

    /// <summary>
    /// 执行Complete Handshake操作。
    /// </summary>
    /// <param name="id">唯一标识。</param>
    /// <param name="connection">connection参数。</param>
    /// <param name="lifecycle">lifecycle参数。</param>
    /// <returns>操作结果。</returns>
    private async Task CompleteHandshakeAsync(QuicConnectionId id, QuicConnection connection,
        TaskCompletionSource lifecycle)
    {
        try
        {
            await connection.Connected.WaitAsync(_options.HandshakeTimeout, _lifetime.Token).ConfigureAwait(false);
            await _accepted.Writer.WriteAsync(connection, _lifetime.Token).ConfigureAwait(false);
            await connection.Closed.ConfigureAwait(false);
        }
        catch { await connection.DisposeAsync().ConfigureAwait(false); }
        finally
        {
            _connections.TryRemove(id, out _);
            _connectionTasks.TryRemove(id, out _);
            _pendingHandshakes.Release();
            lifecycle.TrySetResult();
        }
    }

    /// <summary>停止接受数据包并释放全部活动连接。</summary>
    /// <returns>全部连接和套接字释放后结束的操作。</returns>
    public async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref _started, 2) == 2) return;
        _lifetime.Cancel(); _socket?.Dispose(); _accepted.Writer.TryComplete();
        if (_receiveTask is not null) { try { await _receiveTask.ConfigureAwait(false); } catch { } }
        foreach (var connection in _connections.Values) await connection.DisposeAsync().ConfigureAwait(false);
        Task[] connectionTasks = _connectionTasks.Values.ToArray();
        if (connectionTasks.Length != 0)
        {
            try { await Task.WhenAll(connectionTasks).WaitAsync(_options.ShutdownTimeout).ConfigureAwait(false); } catch { }
        }
        while (_accepted.Reader.TryRead(out QuicConnection? queuedConnection))
            await queuedConnection.DisposeAsync().ConfigureAwait(false);
        _connections.Clear(); _pendingHandshakes.Dispose(); _lifetime.Dispose();
    }
}
