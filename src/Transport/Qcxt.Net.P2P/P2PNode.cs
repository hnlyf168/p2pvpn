using Qcxt.Net.P2P.Discovery;
using Qcxt.Net.P2P.Session;
using Qcxt.Net.P2P.Signaling;
using Qcxt.Net.P2P.Tunneling;

namespace Qcxt.Net.P2P;

/// <summary>提供支持 IPv4/IPv6 底层、QUIC/TCP 直连、自动中转回退及自动重连的高层 P2P 节点。</summary>
public sealed class P2PNode : IAsyncDisposable
{
    private readonly CancellationTokenSource _lifetime = new();
    private readonly object _resourceSync = new();
    private readonly List<IAsyncDisposable> _ownedResources = new();
    private Task? _reconnectTask;
    private Relay.ExternalRelayConnection? _externalRelay;
    private P2PSignalingClient? _signaling;
    private int _started;
    private int _disposed;

    /// <summary>创建节点及其持久化多路径会话。</summary>
    /// <param name="options">本地身份和有界资源设置。</param>
    public P2PNode(P2PConnectionOptions? options = null)
    {
        Options = options ?? new P2PConnectionOptions();
        Options.Validate();
        Session = new P2PMultipathSession(Options);
        Session.ApplicationTrafficObserved += peerId => Volatile.Read(ref _signaling)?.RequestDirect(peerId);
    }

    /// <summary>当一代协调服务器连接成功后触发。</summary>
    public event Action? Connected;
    /// <summary>当一代协调服务器连接失败并开始退避重连时触发。</summary>
    public event Action<Exception?>? Reconnecting;
    /// <summary>当 UDP/TCP 打洞开始、失败、成功、断开或安排重试时触发。</summary>
    public event Action<P2PTraversalEvent>? TraversalStateChanged;
    /// <summary>获取节点配置对象的只读访问入口。</summary>
    public P2PConnectionOptions Options { get; }
    /// <summary>获取持久化的对端级多路径会话。</summary>
    public P2PMultipathSession Session { get; }
    /// <summary>获取当前一代信令连接是否已连接。</summary>
    public bool IsConnected => Volatile.Read(ref _signaling)?.IsConnected == true || _externalRelay?.IsConnected == true;
    /// <summary>获取当前对端快照。</summary>
    public IReadOnlyList<DiscoveredPeer> Peers => (Volatile.Read(ref _signaling)?.DiscoveredPeers ?? [])
        .Concat(_externalRelay?.Peers ?? []).DistinctBy(p => p.PeerId).ToArray();
    /// <summary>获取协调服务器当前分配的虚拟 IPv4 租约。</summary>
    public IPAddress? VirtualAddress => Volatile.Read(ref _signaling)?.VirtualAddress ?? _externalRelay?.Address;
    /// <summary>获取协调服务器分配的虚拟 IPv4 网络前缀长度。</summary>
    public int VirtualPrefixLength => Volatile.Read(ref _signaling)?.VirtualPrefixLength ?? (_externalRelay?.Address is null ? 0 : _externalRelay.PrefixLength);
    /// <summary>获取本机到协调/中转服务器的实际连接端点。</summary>
    public IPEndPoint? ServerLocalEndPoint => Volatile.Read(ref _signaling)?.ServerLocalEndPoint;
    /// <summary>获取当前协调/中转服务器的实际远程端点。</summary>
    public IPEndPoint? ServerRemoteEndPoint => Volatile.Read(ref _signaling)?.ServerRemoteEndPoint;

    /// <summary>启动全天候重连循环，并等待首次注册成功。</summary>
    /// <param name="serverEndPoint">IPv4 或 IPv6 公网协调服务器 UDP 端点。</param>
    /// <param name="keyProvider">与协调服务器及授权对端共享的 QUIC 密钥提供程序。</param>
    /// <param name="localEndPoint">可选的本地接口和固定 UDP 端口。</param>
    /// <param name="cancellationToken">仅用于取消首次连接等待的标记。</param>
    /// <returns>首次连接成功后结束的异步操作。</returns>
    public Task StartAsync(IPEndPoint serverEndPoint, IQuicKeyProvider keyProvider,
        IPEndPoint? localEndPoint = null, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(serverEndPoint);
        return StartCoreAsync(_ => Task.FromResult(serverEndPoint), keyProvider, localEndPoint, cancellationToken);
    }

    /// <summary>使用每次重连都会执行的端点解析器启动全天候重连循环。</summary>
    /// <param name="serverEndPointResolver">返回当前协调服务器端点的解析器；适用于 DDNS 或多地址域名。</param>
    /// <param name="keyProvider">与协调服务器及授权对端共享的 QUIC 密钥提供程序。</param>
    /// <param name="localEndPoint">可选的本地接口和固定 UDP 端口。</param>
    /// <param name="cancellationToken">仅用于取消首次连接等待的标记。</param>
    /// <returns>首次连接成功后结束的异步操作。</returns>
    public Task StartAsync(Func<CancellationToken, Task<IPEndPoint>> serverEndPointResolver,
        IQuicKeyProvider keyProvider, IPEndPoint? localEndPoint = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(serverEndPointResolver);
        return StartCoreAsync(serverEndPointResolver, keyProvider, localEndPoint, cancellationToken);
    }

    /// <summary>
    /// 执行Start Core操作。
    /// </summary>
    /// <param name="serverEndPointResolver">server End Point Resolver参数。</param>
    /// <param name="keyProvider">key Provider参数。</param>
    /// <param name="localEndPoint">local End Point参数。</param>
    /// <param name="cancellationToken">用于取消异步操作的令牌。</param>
    /// <returns>操作结果。</returns>
    private async Task StartCoreAsync(Func<CancellationToken, Task<IPEndPoint>> serverEndPointResolver,
        IQuicKeyProvider keyProvider, IPEndPoint? localEndPoint, CancellationToken cancellationToken)
    {
        ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) != 0, this);
        ArgumentNullException.ThrowIfNull(keyProvider);
        if (Interlocked.Exchange(ref _started, 1) != 0) throw new InvalidOperationException("P2P 节点已经启动。");
        var firstConnection = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        if (Options.RelayUrls.Length > 0)
            _externalRelay = new Relay.ExternalRelayConnection(Options, Session, _lifetime.Token);
        _reconnectTask = ReconnectLoopAsync(serverEndPointResolver, keyProvider, localEndPoint,
            firstConnection, _lifetime.Token);
        if (_externalRelay is not null)
            await (await Task.WhenAny(firstConnection.Task, _externalRelay.Ready).WaitAsync(cancellationToken)).WaitAsync(cancellationToken);
        else await firstConnection.Task.WaitAsync(cancellationToken).ConfigureAwait(false);
    }

    /// <summary>通过带抖动的指数退避持续替换失败的信令连接。</summary>
    /// <param name="serverEndPointResolver">每轮连接前重新获取协调服务器端点的解析器。</param>
    /// <param name="keyProvider">共享的 QUIC 密钥提供程序。</param>
    /// <param name="localEndPoint">可选的本地绑定端点。</param>
    /// <param name="firstConnection">用于通知启动完成的任务源。</param>
    /// <param name="cancellationToken">节点生命周期取消标记。</param>
    /// <returns>仅在节点释放时结束的任务。</returns>
    private async Task ReconnectLoopAsync(Func<CancellationToken, Task<IPEndPoint>> serverEndPointResolver,
        IQuicKeyProvider keyProvider, IPEndPoint? localEndPoint, TaskCompletionSource firstConnection,
        CancellationToken cancellationToken)
    {
        TimeSpan delay = TimeSpan.FromSeconds(1);
        while (!cancellationToken.IsCancellationRequested)
        {
            P2PSignalingClient? client = null;
            var disconnected = new TaskCompletionSource<Exception?>(TaskCreationOptions.RunContinuationsAsynchronously);
            try
            {
                IPEndPoint serverEndPoint = await serverEndPointResolver(cancellationToken).ConfigureAwait(false);
                ArgumentNullException.ThrowIfNull(serverEndPoint);
                if (localEndPoint is not null && serverEndPoint.AddressFamily != localEndPoint.AddressFamily)
                    throw new SocketException((int)SocketError.AddressFamilyNotSupported);
                client = new P2PSignalingClient(Options, keyProvider);
                client.PeerGenerationStarted += Session.ResetPeerGeneration;
                client.LinkEstablished += AttachSignaledLink;
                client.TraversalStateChanged += RaiseTraversalStateChanged;
                client.Disconnected += error => disconnected.TrySetResult(error);
                using var attemptTimeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
                attemptTimeout.CancelAfter(TimeSpan.FromSeconds(15));
                await client.ConnectAsync(serverEndPoint, localEndPoint, attemptTimeout.Token).ConfigureAwait(false);
                Volatile.Write(ref _signaling, client);
                firstConnection.TrySetResult();
                delay = TimeSpan.FromSeconds(1);
                RaiseConnected();
                Exception? failure = await disconnected.Task.WaitAsync(cancellationToken).ConfigureAwait(false);
                RaiseReconnecting(failure);
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { break; }
            catch (Exception exception)
            {
                RaiseReconnecting(exception);
            }
            finally
            {
                if (ReferenceEquals(Volatile.Read(ref _signaling), client)) Volatile.Write(ref _signaling, null);
                if (client is not null) await client.DisposeAsync().ConfigureAwait(false);
            }
            try
            {
                double jitter = 0.8 + Random.Shared.NextDouble() * 0.4;
                await Task.Delay(TimeSpan.FromMilliseconds(delay.TotalMilliseconds * jitter), cancellationToken)
                    .ConfigureAwait(false);
            }
            catch (OperationCanceledException) { break; }
            delay = TimeSpan.FromSeconds(Math.Min(30, delay.TotalSeconds * 2));
        }
        firstConnection.TrySetCanceled(cancellationToken);
    }

    /// <summary>触发连接回调，并隔离应用回调异常以免中断重连。</summary>
    private void RaiseConnected()
    {
        Action? handlers = Connected;
        if (handlers is null) return;
        foreach (Action handler in handlers.GetInvocationList())
        {
            try { handler(); } catch { }
        }
    }

    /// <summary>触发重连回调，并隔离应用回调异常以免中断重连。</summary>
    /// <param name="exception">导致重连的异常；正常关闭时为 <see langword="null"/>。</param>
    private void RaiseReconnecting(Exception? exception)
    {
        Action<Exception?>? handlers = Reconnecting;
        if (handlers is null) return;
        foreach (Action<Exception?> handler in handlers.GetInvocationList())
        {
            try { handler(exception); } catch { }
        }
    }

    /// <summary>转发打洞诊断事件，并隔离应用日志回调异常。</summary>
    /// <param name="value">由当前信令连接产生的打洞状态。</param>
    private void RaiseTraversalStateChanged(P2PTraversalEvent value)
    {
        Action<P2PTraversalEvent>? handlers = TraversalStateChanged;
        if (handlers is null) return;
        foreach (Action<P2PTraversalEvent> handler in handlers.GetInvocationList())
        {
            try { handler(value); } catch { }
        }
    }

    /// <summary>将信令建立的链路转交给持久化会话。</summary>
    /// <param name="peerId">已认证的远程对端标识。</param>
    /// <param name="link">具有所有权的物理或中转链路。</param>
    private void AttachSignaledLink(ulong peerId, IP2PLink link)
    {
        try { Session.AddLink(peerId, link); }
        catch { _ = link.DisposeAsync(); }
    }

    /// <summary>将外部已认证路径附加到文本形式的对端。</summary>
    /// <param name="remotePeerId">远程对端名称。</param>
    /// <param name="link">具有所有权的路径。</param>
    public void AttachLink(string remotePeerId, IP2PLink link) => Session.AddLink(remotePeerId, link);

    /// <summary>发现临时套接字的公网映射，用于诊断。</summary>
    /// <param name="preferredStunHost">可选的 STUN 主机。</param>
    /// <param name="preferredStunPort">STUN UDP 端口。</param>
    /// <param name="timeoutMs">查询超时毫秒数。</param>
    /// <param name="cancellationToken">用于取消发现操作的标记。</param>
    /// <returns>观察到的映射；未发现时返回 <see langword="null"/>。</returns>
    public Task<P2PPublicEndPoint?> DiscoverPublicAddressAsync(string? preferredStunHost = null,
        int preferredStunPort = 3478, int timeoutMs = 3000, CancellationToken cancellationToken = default) =>
        P2PPublicAddressDiscovery.DiscoverAsync(preferredStunHost, preferredStunPort, timeoutMs, cancellationToken);

    /// <summary>使用指定 IPv4 或 IPv6 地址族发现临时套接字的公网映射。</summary>
    /// <param name="addressFamily">要查询的 IPv4 或 IPv6 地址族。</param>
    /// <param name="preferredStunHost">可选的 STUN 主机。</param>
    /// <param name="preferredStunPort">STUN UDP 端口。</param>
    /// <param name="timeoutMs">查询超时毫秒数。</param>
    /// <param name="cancellationToken">用于取消发现操作的标记。</param>
    /// <returns>观察到的映射；未发现时返回空。</returns>
    public Task<P2PPublicEndPoint?> DiscoverPublicAddressAsync(AddressFamily addressFamily,
        string? preferredStunHost = null, int preferredStunPort = 3478, int timeoutMs = 3000,
        CancellationToken cancellationToken = default) => P2PPublicAddressDiscovery.DiscoverAsync(
            addressFamily, preferredStunHost, preferredStunPort, timeoutMs, cancellationToken);

    /// <summary>在持久化会话上创建并持有一个 TUN 数据泵。</summary>
    /// <param name="tunDevice">已初始化的平台 TUN 设备。</param>
    /// <param name="router">将 IP 数据包映射到数字网状网络对端的路由器。</param>
    /// <returns>一个尚未启动、可由调用方启动的隧道。</returns>
    public P2PTunMultipathTunnel CreateTunTunnel(IP2PTunDevice tunDevice, IP2PPacketRouter router)
    {
        var tunnel = new P2PTunMultipathTunnel(tunDevice, Session, router);
        lock (_resourceSync) _ownedResources.Add(tunnel);
        return tunnel;
    }

    /// <summary>主动结束当前信令连接，使后台循环重新解析地址并重新注册。</summary>
    /// <param name="reason">用于诊断日志的重连原因。</param>
    public void RequestReconnect(string reason)
    {
        P2PSignalingClient? signaling = Volatile.Read(ref _signaling);
        signaling?.RequestReconnect(reason);
    }

    /// <summary>以幂等方式停止重连、隧道、信令和持久化会话。</summary>
    /// <returns>所有组件完成有界关闭后结束的异步操作。</returns>
    public async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0) return;
        _lifetime.Cancel();
        IAsyncDisposable[] resources;
        lock (_resourceSync) { resources = _ownedResources.ToArray(); _ownedResources.Clear(); }
        foreach (IAsyncDisposable resource in resources)
        {
            try { await resource.DisposeAsync().ConfigureAwait(false); } catch { }
        }
        P2PSignalingClient? signaling = Volatile.Read(ref _signaling);
        if (signaling is not null) await signaling.DisposeAsync().ConfigureAwait(false);
        if (_reconnectTask is not null)
        {
            try { await _reconnectTask.WaitAsync(Options.ShutdownTimeout).ConfigureAwait(false); } catch { }
        }
        if (_externalRelay is not null) await _externalRelay.DisposeAsync();
        await Session.DisposeAsync().ConfigureAwait(false);
        _lifetime.Dispose();
    }
}
