using Qcxt.Net.P2P.Protocol;

namespace Qcxt.Net.P2P.Session;

/// <summary>聚合有界物理链路，并为每个远程对端隔离排序与恢复状态。</summary>
public sealed class P2PMultipathSession : IAsyncDisposable
{
    private readonly P2PConnectionOptions _options;
    private readonly ulong _sessionId;
    private readonly ulong _localPeerId;
    private readonly ConcurrentDictionary<ulong, PeerState> _peers = new();
    private readonly Channel<P2PMessage> _received;
    private readonly CancellationTokenSource _lifetime = new();
    private readonly Task _maintenanceTask;
    private int _disposed;

    /// <summary>创建有界多路径会话。</summary>
    /// <param name="options">已校验的会话限制和本地身份。</param>
    public P2PMultipathSession(P2PConnectionOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        options.Validate();
        _options = options;
        _sessionId = P2PFrameCodec.HashIdentifier(options.SessionId);
        _localPeerId = P2PFrameCodec.HashIdentifier(options.PeerId);
        _received = Channel.CreateBounded<P2PMessage>(new BoundedChannelOptions(options.ReceiveQueueCapacity)
        {
            SingleReader = false,
            SingleWriter = false,
            FullMode = BoundedChannelFullMode.Wait
        });
        _maintenanceTask = MaintenanceLoopAsync(_lifetime.Token);
    }

    /// <summary>链路因关闭或故障被移除后触发。</summary>
    public event Action<ulong, string>? LinkClosed;
    /// <summary>可靠消息耗尽重试预算时触发。</summary>
    public event Action<ulong, ulong>? MessageDeliveryFailed;
    internal event Action<ulong>? ApplicationTrafficObserved;
    /// <summary>获取在线路协议中使用的数字本地对端标识。</summary>
    public ulong LocalPeerId => _localPeerId;
    /// <summary>获取当前已附加物理链路的数量。</summary>
    public int LinkCount => _peers.Values.Sum(static peer => peer.LinkCount);
    /// <summary>获取至少拥有一条路径或待处理接收状态的远程对端数量。</summary>
    public int PeerCount => _peers.Count;

    /// <summary>附加一条已经认证预期远程对端的路径。</summary>
    /// <param name="remotePeerId">数字形式的远程对端标识。</param>
    /// <param name="link">具有所有权的物理路径。</param>
    public void AddLink(ulong remotePeerId, IP2PLink link)
    {
        ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) != 0, this);
        if (remotePeerId == 0 || remotePeerId == _localPeerId) throw new ArgumentOutOfRangeException(nameof(remotePeerId));
        ArgumentNullException.ThrowIfNull(link);
        LinkState state = new(link);
        PeerState peer;
        while (true)
        {
            peer = _peers.GetOrAdd(remotePeerId,
                id => new PeerState(id, _options.MaxInFlightPackets));
            lock (peer.Sync)
            {
                if (!_peers.TryGetValue(remotePeerId, out PeerState? current) ||
                    !ReferenceEquals(current, peer)) continue;
                if (peer.Links.Any(existing => ReferenceEquals(existing.Link, link)))
                    throw new InvalidOperationException($"链路“{link.Id}”已经附加。");
                if (peer.Links.Count >= _options.MaxLinksPerPeer)
                    throw new InvalidOperationException("已经达到单个对端的链路数量上限。");
                peer.Links.Add(state);
                break;
            }
        }
        state.ReceiveTask = ReceiveLoopAsync(peer, state, _lifetime.Token);
    }

    /// <summary>使用稳定的文本对端标识附加路径。</summary>
    /// <param name="remotePeerId">远程对端名称。</param>
    /// <param name="link">具有所有权的物理路径。</param>
    public void AddLink(string remotePeerId, IP2PLink link) =>
        AddLink(P2PFrameCodec.HashIdentifier(remotePeerId), link);

    /// <summary>开始指定对端的新进程代际，立即淘汰旧链路并重置可靠传输序号。</summary>
    /// <param name="remotePeerId">重新上线的数字对端标识。</param>
    /// <remarks>
    /// 对端进程重启后会从序号一重新发送；如果保留上一代排序窗口，新包会被误判为重复包，
    /// 本地后续包也会令新对端永久等待并不存在的旧序号。
    /// </remarks>
    public void ResetPeerGeneration(ulong remotePeerId)
    {
        ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) != 0, this);
        if (remotePeerId == 0 || remotePeerId == _localPeerId)
            throw new ArgumentOutOfRangeException(nameof(remotePeerId));

        PeerState peer = _peers.GetOrAdd(remotePeerId,
            id => new PeerState(id, _options.MaxInFlightPackets));
        LinkState[] retiredLinks;
        lock (peer.Sync)
        {
            // A remote process generation invalidates authenticated direct paths and sequence
            // numbers, but the relay objects belong to the still-live signaling connection.
            // Removing them here leaves an online peer without its mandatory fallback path.
            retiredLinks = peer.Links.Where(static link =>
                link.Link.Kind is not (P2PTransportKind.QuicRelay or P2PTransportKind.QuicDatagramRelay) &&
                link.TryRetire()).ToArray();
            peer.Links.RemoveAll(static link =>
                link.Link.Kind is not (P2PTransportKind.QuicRelay or P2PTransportKind.QuicDatagramRelay));
            foreach (P2PMessage message in peer.Reorder.Values) message.Dispose();
            peer.Reorder.Clear();
            peer.NextExpectedSequence = 1;
            Interlocked.Exchange(ref peer.NextSendSequence, 0);
        }

        foreach (KeyValuePair<ulong, PendingFrame> pair in peer.Pending.ToArray())
        {
            if (!peer.Pending.TryRemove(pair)) continue;
            pair.Value.FailAndDispose();
            peer.InFlightSlots.Release();
            RaiseEvent(MessageDeliveryFailed, remotePeerId, pair.Key);
        }
        foreach (LinkState link in retiredLinks) _ = DisposeResetLinkAsync(peer, link);
    }

    /// <summary>异步释放被新代际替换的旧链路并发布关闭诊断事件。</summary>
    /// <param name="peer">旧链路所属的对端状态。</param>
    /// <param name="link">已经从活动集合移除的旧链路。</param>
    /// <returns>链路释放完成后结束的任务。</returns>
    private async Task DisposeResetLinkAsync(PeerState peer, LinkState link)
    {
        try { await link.Link.DisposeAsync().ConfigureAwait(false); } catch { }
        RaiseEvent(LinkClosed, peer.PeerId, link.Link.Id);
    }

    /// <summary>使用有界背压向指定对端发送一条消息。</summary>
    /// <param name="targetPeerId">数字形式的远程对端标识。</param>
    /// <param name="payload">应用载荷。</param>
    /// <param name="deliveryMode">可靠有序或不可靠交付模式。</param>
    /// <param name="trafficClass">延迟调度等级。</param>
    /// <param name="cancellationToken">用于取消背压等待的标记。</param>
    /// <returns>活动路径接受已编码帧后结束的异步操作。</returns>
    public async ValueTask SendAsync(ulong targetPeerId, ReadOnlyMemory<byte> payload,
        P2PDeliveryMode deliveryMode = P2PDeliveryMode.ReliableOrdered,
        P2PTrafficClass trafficClass = P2PTrafficClass.Normal,
        CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) != 0, this);
        if (payload.Length > _options.MaximumPayloadSize) throw new ArgumentOutOfRangeException(nameof(payload));
        if (!_peers.TryGetValue(targetPeerId, out PeerState? peer))
            throw new InvalidOperationException("目标对端没有已附加路径。");

        ApplicationTrafficObserved?.Invoke(targetPeerId);
        bool slotHeld = false;
        if (deliveryMode == P2PDeliveryMode.ReliableOrdered)
        {
            await peer.InFlightSlots.WaitAsync(cancellationToken).ConfigureAwait(false);
            slotHeld = true;
        }

        ulong sequence = deliveryMode == P2PDeliveryMode.ReliableOrdered
            ? unchecked((ulong)Interlocked.Increment(ref peer.NextSendSequence)) : 0;
        P2POwnedBuffer encoded;
        try
        {
            encoded = P2PFrameCodec.Encode(P2PFrameType.Data, deliveryMode, trafficClass,
                _sessionId, _localPeerId, targetPeerId, sequence, 0, payload.Span);
        }
        catch
        {
            if (slotHeld) peer.InFlightSlots.Release();
            throw;
        }
        PendingFrame? pending = null;
        try
        {
            if (deliveryMode == P2PDeliveryMode.ReliableOrdered)
            {
                pending = new PendingFrame(sequence, encoded, Stopwatch.GetTimestamp());
                if (!peer.Pending.TryAdd(sequence, pending)) throw new InvalidOperationException("发送序号重复。");
            }
            await SendOnBestPathAsync(peer, encoded.Memory, deliveryMode, trafficClass, cancellationToken)
                .ConfigureAwait(false);
            pending?.CompleteSend(success: true, _options.RetransmitTimeout);
            if (pending is null) encoded.Dispose();
        }
        catch
        {
            if (pending is not null)
            {
                if (peer.Pending.TryRemove(new KeyValuePair<ulong, PendingFrame>(sequence, pending)))
                {
                    pending.FailAndDispose();
                    if (slotHeld) peer.InFlightSlots.Release();
                }
                else pending.CompleteSend(false, _options.RetransmitTimeout);
            }
            else encoded.Dispose();
            throw;
        }
    }

    /// <summary>对文本目标对端标识执行哈希的兼容辅助方法。</summary>
    /// <param name="packet">应用载荷。</param>
    /// <param name="targetPeerId">目标对端名称；仅当只附加一个对端时可为空。</param>
    /// <param name="cancellationToken">用于取消背压等待的标记。</param>
    /// <returns>路径接受数据帧后结束的异步操作。</returns>
    public ValueTask SendPacketAsync(ReadOnlyMemory<byte> packet, string targetPeerId = "",
        CancellationToken cancellationToken = default)
    {
        ulong target = string.IsNullOrWhiteSpace(targetPeerId) ? GetOnlyPeerId() :
            P2PFrameCodec.HashIdentifier(targetPeerId);
        return SendAsync(target, packet, P2PDeliveryMode.ReliableOrdered, P2PTrafficClass.Normal,
            cancellationToken);
    }

    /// <summary>接收一条具有所有权的消息，且不复制其载荷。</summary>
    /// <param name="cancellationToken">用于取消等待的标记。</param>
    /// <returns>必须由调用方释放的消息。</returns>
    public ValueTask<P2PMessage> ReceiveAsync(CancellationToken cancellationToken = default) =>
        _received.Reader.ReadAsync(cancellationToken);

    /// <summary>返回已分配载荷数组的兼容辅助方法。</summary>
    /// <param name="cancellationToken">用于取消等待的标记。</param>
    /// <returns>包含下一条载荷的新数组。</returns>
    public async ValueTask<byte[]> ReceivePacketAsync(CancellationToken cancellationToken = default)
    {
        using P2PMessage message = await ReceiveAsync(cancellationToken).ConfigureAwait(false);
        return message.Payload.ToArray();
    }

    /// <summary>为兼容调用选择唯一的已知对端。</summary>
    /// <returns>唯一的对端标识。</returns>
    private ulong GetOnlyPeerId()
    {
        ulong[] peers = _peers.Where(static pair => pair.Value.LinkCount != 0).Select(static pair => pair.Key)
            .Take(2).ToArray();
        return peers.Length == 1 ? peers[0] : throw new InvalidOperationException(
            "未附加对端或附加多个对端时必须指定目标对端。");
    }

    /// <summary>通过当前最佳健康路径发送，并在失败时同步切换路径。</summary>
    /// <param name="peer">目标对端状态。</param>
    /// <param name="frame">完整的已编码帧。</param>
    /// <param name="deliveryMode">请求的交付行为。</param>
    /// <param name="trafficClass">流量等级。</param>
    /// <param name="cancellationToken">用于取消全部尝试的标记。</param>
    /// <returns>任一路径接受数据帧后结束的异步操作。</returns>
    private async ValueTask SendOnBestPathAsync(PeerState peer, ReadOnlyMemory<byte> frame,
        P2PDeliveryMode deliveryMode, P2PTrafficClass trafficClass, CancellationToken cancellationToken)
    {
        HashSet<string>? attempted = null;
        Exception? lastError = null;
        while (true)
        {
            LinkState? link = SelectBestLink(peer, frame.Length, deliveryMode, trafficClass, attempted);
            if (link is null) throw new IOException("没有能够承载该数据帧的健康 P2P 路径。", lastError);
            Interlocked.Add(ref link.ActiveSendBytes, frame.Length);
            try
            {
                if (deliveryMode == P2PDeliveryMode.Unreliable && link.Link is IP2PFastSendLink fastLink &&
                    fastLink.TrySend(frame.Span, trafficClass))
                {
                    link.LastSendTimestamp = Stopwatch.GetTimestamp();
                    Volatile.Write(ref link.ConsecutiveFailures, 0);
                    return;
                }
                using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, _lifetime.Token);
                timeout.CancelAfter(_options.SendStallTimeout);
                await link.Link.SendAsync(frame, trafficClass, timeout.Token).ConfigureAwait(false);
                link.LastSendTimestamp = Stopwatch.GetTimestamp();
                Volatile.Write(ref link.ConsecutiveFailures, 0);
                return;
            }
            catch (Exception exception) when (exception is not OperationCanceledException || !cancellationToken.IsCancellationRequested)
            {
                lastError = exception;
                (attempted ??= new(StringComparer.Ordinal)).Add(link.Link.Id);
                Interlocked.Increment(ref link.ConsecutiveFailures);
                if (!link.Link.IsConnected || Volatile.Read(ref link.ConsecutiveFailures) >= 3)
                    _ = RetireLinkAsync(peer, link);
            }
            finally { Interlocked.Add(ref link.ActiveSendBytes, -frame.Length); }
        }
    }

    /// <summary>根据可用性、交付适配度、当前负载和近期故障对路径排序。</summary>
    /// <param name="peer">目标对端状态。</param>
    /// <param name="frameLength">已编码帧长度。</param>
    /// <param name="deliveryMode">请求的交付行为。</param>
    /// <param name="trafficClass">流量等级。</param>
    /// <param name="excluded">已经尝试过的链路标识集合。</param>
    /// <returns>最佳路径；没有路径能够承载该帧时返回 <see langword="null"/>。</returns>
    private static LinkState? SelectBestLink(PeerState peer, int frameLength, P2PDeliveryMode deliveryMode,
        P2PTrafficClass trafficClass, HashSet<string>? excluded)
    {
        LinkState? best = null;
        long bestScore = long.MaxValue;
        lock (peer.Sync)
        {
            bool hasHealthyDirect = peer.Links.Any(link => !link.Retired && link.Link.IsConnected &&
                link.Link.MaximumPacketSize >= frameLength && Volatile.Read(ref link.ConsecutiveFailures) == 0 &&
                link.Link.Kind is P2PTransportKind.Quic or P2PTransportKind.TcpDirect &&
                excluded?.Contains(link.Link.Id) != true);
            foreach (LinkState candidate in peer.Links)
            {
                if (hasHealthyDirect && candidate.Link.Kind is P2PTransportKind.QuicRelay or P2PTransportKind.QuicDatagramRelay) continue;
                if (candidate.Retired || !candidate.Link.IsConnected || candidate.Link.MaximumPacketSize < frameLength ||
                    excluded?.Contains(candidate.Link.Id) == true) continue;
                long score = Math.Max(0, Volatile.Read(ref candidate.ActiveSendBytes)) +
                    1_000_000L * Math.Max(0, Volatile.Read(ref candidate.ConsecutiveFailures));
                if (candidate.Link.Kind is P2PTransportKind.QuicRelay or P2PTransportKind.QuicDatagramRelay)
                    score += 50_000;
                if (candidate.Link.Kind == P2PTransportKind.TcpDirect) score += 10_000;
                if (deliveryMode == P2PDeliveryMode.Unreliable && candidate.Link.IsReliable) score += 100_000;
                if (deliveryMode == P2PDeliveryMode.ReliableOrdered && !candidate.Link.IsReliable) score += 20_000;
                if (trafficClass == P2PTrafficClass.Interactive && candidate.Link.IsReliable) score += 2_000;
                if (score < bestScore) { best = candidate; bestScore = score; }
            }
        }
        return best;
    }

    /// <summary>接收、校验并分发来自一条已认证对端路径的数据帧。</summary>
    /// <param name="peer">预期的远程对端状态。</param>
    /// <param name="link">接收路径。</param>
    /// <param name="cancellationToken">会话生命周期取消标记。</param>
    /// <returns>路径关闭时结束的任务。</returns>
    private async Task ReceiveLoopAsync(PeerState peer, LinkState link, CancellationToken cancellationToken)
    {
        try
        {
            while (!cancellationToken.IsCancellationRequested)
            {
                using P2PReceiveResult result = await link.Link.ReceiveAsync(cancellationToken).ConfigureAwait(false);
                if (!TryExtractFrame(peer, result, out ReceivedFrame received)) continue;
                link.LastReceiveTimestamp = result.Timestamp;
                if (received.Type == P2PFrameType.Ack)
                {
                    Acknowledge(peer, received.Acknowledgement);
                    received.Message?.Dispose();
                    continue;
                }
                if (received.Type == P2PFrameType.KeepAlive) continue;
                if (received.Type == P2PFrameType.Close) break;
                ApplicationTrafficObserved?.Invoke(peer.PeerId);
                if (received.DeliveryMode == P2PDeliveryMode.ReliableOrdered)
                {
                    bool acknowledge = AcceptReliable(peer, received.Sequence, received.Message!, out List<P2PMessage>? ready);
                    if (acknowledge) await SendAckAsync(peer, link, received.Sequence, cancellationToken).ConfigureAwait(false);
                    if (ready is not null)
                        await EnqueueMessagesAsync(ready, cancellationToken).ConfigureAwait(false);
                }
                else
                    await EnqueueMessageAsync(received.Message!, cancellationToken).ConfigureAwait(false);
            }
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { }
        catch { Interlocked.Increment(ref link.ConsecutiveFailures); }
        finally { await RetireLinkAsync(peer, link).ConfigureAwait(false); }
    }

    /// <summary>将一条具有所有权的消息转交给有界应用队列。</summary>
    private async ValueTask EnqueueMessageAsync(P2PMessage message, CancellationToken cancellationToken)
    {
        try { await _received.Writer.WriteAsync(message, cancellationToken).ConfigureAwait(false); }
        catch { message.Dispose(); throw; }
    }

    /// <summary>转交一批连续有序消息，并在失败时释放所有未入队消息的所有者。</summary>
    private async ValueTask EnqueueMessagesAsync(List<P2PMessage> messages, CancellationToken cancellationToken)
    {
        int index = 0;
        try
        {
            for (; index < messages.Count; index++)
                await _received.Writer.WriteAsync(messages[index], cancellationToken).ConfigureAwait(false);
        }
        catch
        {
            for (; index < messages.Count; index++) messages[index].Dispose();
            throw;
        }
    }

    /// <summary>校验身份，并以零拷贝方式转交数据帧所有权。</summary>
    /// <param name="peer">预期的来源对端。</param>
    /// <param name="result">具有所有权的链路数据包。</param>
    /// <param name="received">提取出的标量字段及可选的具有所有权的消息。</param>
    /// <returns>数据帧属于当前会话和对端时返回 <see langword="true"/>。</returns>
    private bool TryExtractFrame(PeerState peer, P2PReceiveResult result, out ReceivedFrame received)
    {
        received = default;
        if (!P2PFrameCodec.TryDecode(result.Memory.Span, out P2PDecodedFrame frame) ||
            frame.SessionId != _sessionId || frame.SourcePeerId != peer.PeerId ||
            frame.TargetPeerId != _localPeerId) return false;
        P2PMessage? message = null;
        if (frame.Type == P2PFrameType.Data)
        {
            IMemoryOwner<byte> owner = result.DetachOwner();
            message = new P2PMessage(frame.SourcePeerId, frame.DeliveryMode, frame.TrafficClass,
                owner, P2PFrameCodec.HeaderLength, frame.Payload.Length);
        }
        received = new ReceivedFrame(frame.Type, frame.DeliveryMode, frame.Sequence,
            frame.Acknowledgement, message);
        return true;
    }

    /// <summary>将一个可靠序号接纳到对端独立的有界重排序窗口。</summary>
    /// <param name="peer">来源对端状态。</param>
    /// <param name="sequence">收到的对端级序号。</param>
    /// <param name="message">具有所有权的已接收载荷。</param>
    /// <param name="ready">可交付给应用的连续消息集合。</param>
    /// <returns>是否应向发送方发送确认。</returns>
    private bool AcceptReliable(PeerState peer, ulong sequence, P2PMessage message,
        out List<P2PMessage>? ready)
    {
        ready = null;
        lock (peer.Sync)
        {
            if (sequence < peer.NextExpectedSequence) { message.Dispose(); return true; }
            if (sequence - peer.NextExpectedSequence >= (ulong)_options.ReceiveWindowPackets ||
                peer.Reorder.Count >= _options.ReceiveWindowPackets)
            { message.Dispose(); return false; }
            if (!peer.Reorder.TryAdd(sequence, message)) { message.Dispose(); return true; }
            while (peer.Reorder.Remove(peer.NextExpectedSequence, out P2PMessage? next))
            {
                (ready ??= new()).Add(next);
                peer.NextExpectedSequence++;
            }
            return true;
        }
    }

    /// <summary>通过接收路径发送确认。</summary>
    /// <param name="peer">远程对端状态。</param>
    /// <param name="link">交付数据的路径。</param>
    /// <param name="sequence">要确认的序号。</param>
    /// <param name="cancellationToken">用于取消发送的标记。</param>
    /// <returns>确认帧进入队列后结束的异步操作。</returns>
    private async ValueTask SendAckAsync(PeerState peer, LinkState link, ulong sequence,
        CancellationToken cancellationToken)
    {
        using P2POwnedBuffer ack = P2PFrameCodec.Encode(P2PFrameType.Ack,
            P2PDeliveryMode.Unreliable, P2PTrafficClass.Interactive, _sessionId, _localPeerId,
            peer.PeerId, 0, sequence, ReadOnlySpan<byte>.Empty);
        await link.Link.SendAsync(ack.Memory, P2PTrafficClass.Interactive, cancellationToken).ConfigureAwait(false);
        link.LastSendTimestamp = Stopwatch.GetTimestamp();
    }

    /// <summary>收到有效对端确认后，仅完成一次对应的待处理帧。</summary>
    /// <param name="peer">发送确认的对端状态。</param>
    /// <param name="sequence">已确认的对端级序号。</param>
    private static void Acknowledge(PeerState peer, ulong sequence)
    {
        if (!peer.Pending.TryRemove(sequence, out PendingFrame? pending)) return;
        pending.Acknowledge();
        peer.InFlightSlots.Release();
    }

    /// <summary>重传到期帧、探测空闲链路并淘汰静默路径。</summary>
    /// <param name="cancellationToken">会话生命周期取消标记。</param>
    /// <returns>在会话释放期间结束的任务。</returns>
    private async Task MaintenanceLoopAsync(CancellationToken cancellationToken)
    {
        TimeSpan interval = TimeSpan.FromMilliseconds(Math.Max(20, _options.RetransmitTimeout.TotalMilliseconds / 2));
        using var timer = new PeriodicTimer(interval);
        while (await timer.WaitForNextTickAsync(cancellationToken).ConfigureAwait(false))
        {
            long now = Stopwatch.GetTimestamp();
            foreach (PeerState peer in _peers.Values)
            {
                foreach (KeyValuePair<ulong, PendingFrame> pair in peer.Pending)
                {
                    PendingFrame pending = pair.Value;
                    if (!pending.TryBeginRetry(now, _options.MaximumRetries, out bool exhausted)) continue;
                    if (exhausted)
                    {
                        if (peer.Pending.TryRemove(pair.Key, out _))
                        {
                            pending.FailAndDispose();
                            peer.InFlightSlots.Release();
                            RaiseEvent(MessageDeliveryFailed, peer.PeerId, pair.Key);
                        }
                        else pending.CompleteSend(false, _options.RetransmitTimeout);
                        continue;
                    }
                    try
                    {
                        await SendOnBestPathAsync(peer, pending.Memory, P2PDeliveryMode.ReliableOrdered,
                            P2PTrafficClass.Normal, cancellationToken).ConfigureAwait(false);
                        pending.CompleteSend(true, ComputeRetryDelay(pending.RetryCount));
                    }
                    catch { pending.CompleteSend(false, ComputeRetryDelay(pending.RetryCount)); }
                }
                LinkState[] links;
                lock (peer.Sync) links = peer.Links.ToArray();
                foreach (LinkState link in links)
                {
                    long lastActivity = Math.Max(Volatile.Read(ref link.LastReceiveTimestamp),
                        Volatile.Read(ref link.LastSendTimestamp));
                    TimeSpan silent = Stopwatch.GetElapsedTime(lastActivity, now);
                    if (silent >= _options.LinkIdleTimeout) { await RetireLinkAsync(peer, link).ConfigureAwait(false); continue; }
                    if (silent < _options.KeepAliveInterval || !link.TryBeginKeepAlive()) continue;
                    try
                    {
                        using P2POwnedBuffer keepAlive = P2PFrameCodec.Encode(P2PFrameType.KeepAlive,
                            P2PDeliveryMode.Unreliable, P2PTrafficClass.Interactive, _sessionId,
                            _localPeerId, peer.PeerId, 0, 0, ReadOnlySpan<byte>.Empty);
                        await link.Link.SendAsync(keepAlive.Memory, P2PTrafficClass.Interactive,
                            cancellationToken).ConfigureAwait(false);
                        link.LastSendTimestamp = Stopwatch.GetTimestamp();
                    }
                    catch { Interlocked.Increment(ref link.ConsecutiveFailures); }
                    finally { link.EndKeepAlive(); }
                }
            }
        }
    }

    /// <summary>计算有上限的指数重传延迟。</summary>
    /// <param name="retryCount">已完成的重试次数。</param>
    /// <returns>下一次重试延迟。</returns>
    private TimeSpan ComputeRetryDelay(int retryCount)
    {
        double multiplier = Math.Pow(2, Math.Min(retryCount, 8));
        return TimeSpan.FromMilliseconds(Math.Min(_options.MaximumRetransmitTimeout.TotalMilliseconds,
            _options.RetransmitTimeout.TotalMilliseconds * multiplier));
    }

    /// <summary>仅执行一次故障路径的移除和释放。</summary>
    /// <param name="peer">拥有该路径的对端状态。</param>
    /// <param name="link">要移除的路径。</param>
    /// <returns>传输对象释放后结束的异步操作。</returns>
    private async ValueTask RetireLinkAsync(PeerState peer, LinkState link)
    {
        if (!link.TryRetire()) return;
        lock (peer.Sync)
        {
            peer.Links.Remove(link);
            if (peer.Links.Count == 0 && peer.Pending.IsEmpty && peer.Reorder.Count == 0)
                _peers.TryRemove(new KeyValuePair<ulong, PeerState>(peer.PeerId, peer));
        }
        try { await link.Link.DisposeAsync().ConfigureAwait(false); } catch { }
        RaiseEvent(LinkClosed, peer.PeerId, link.Link.Id);
    }

    /// <summary>调用双参数诊断回调，并隔离应用异常以免停止会话任务。</summary>
    /// <typeparam name="TFirst">第一个参数的类型。</typeparam>
    /// <typeparam name="TSecond">第二个参数的类型。</typeparam>
    /// <param name="handlers">当前订阅者。</param>
    /// <param name="first">第一个事件参数。</param>
    /// <param name="second">第二个事件参数。</param>
    private static void RaiseEvent<TFirst, TSecond>(Action<TFirst, TSecond>? handlers,
        TFirst first, TSecond second)
    {
        if (handlers is null) return;
        foreach (Action<TFirst, TSecond> handler in handlers.GetInvocationList())
        {
            try { handler(first, second); } catch { }
        }
    }

    /// <summary>停止所有任务，并释放每条已缓冲消息、数据帧和路径。</summary>
    /// <returns>有界关闭完成后结束的异步操作。</returns>
    public async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0) return;
        _lifetime.Cancel();
        _received.Writer.TryComplete();
        try { await _maintenanceTask.WaitAsync(_options.ShutdownTimeout).ConfigureAwait(false); } catch { }
        LinkState[] links = _peers.Values.SelectMany(static peer => peer.SnapshotLinks()).ToArray();
        foreach (LinkState link in links)
        {
            try { await link.Link.DisposeAsync().ConfigureAwait(false); } catch { }
        }
        Task[] receives = links.Select(static link => link.ReceiveTask).Where(static task => task is not null)
            .Cast<Task>().ToArray();
        if (receives.Length != 0) { try { await Task.WhenAll(receives).WaitAsync(_options.ShutdownTimeout).ConfigureAwait(false); } catch { } }
        foreach (PeerState peer in _peers.Values) peer.Dispose();
        _peers.Clear();
        while (_received.Reader.TryRead(out P2PMessage? message)) message.Dispose();
        _lifetime.Dispose();
    }

    /// <summary>
    /// 表示 Received Frame，并提供相关数据或行为。
    /// </summary>
    /// <param name="Type">Type参数。</param>
    /// <param name="DeliveryMode">Delivery Mode参数。</param>
    /// <param name="Sequence">Sequence参数。</param>
    /// <param name="Acknowledgement">Acknowledgement参数。</param>
    /// <param name="Message">消息内容。</param>
    private readonly record struct ReceivedFrame(P2PFrameType Type, P2PDeliveryMode DeliveryMode,
        ulong Sequence, ulong Acknowledgement, P2PMessage? Message);

    /// <summary>
/// 表示 Peer State，并提供相关数据或行为。
/// </summary>
private sealed class PeerState : IDisposable
    {
        /// <summary>
        /// 初始化 <see cref="PeerState"/> 类的新实例。
        /// </summary>
        /// <param name="peerId">peer Id参数。</param>
        /// <param name="maximumInFlight">maximum In Flight参数。</param>
        public PeerState(ulong peerId, int maximumInFlight)
        {
            PeerId = peerId;
            InFlightSlots = new SemaphoreSlim(maximumInFlight, maximumInFlight);
        }
        /// <summary>
        /// 获取或设置Peer Id。
        /// </summary>
        /// <returns>Peer Id。</returns>
        public ulong PeerId { get; }
        /// <summary>
        /// 获取或设置Sync。
        /// </summary>
        /// <returns>Sync。</returns>
        public object Sync { get; } = new();
        /// <summary>
        /// 获取或设置Links。
        /// </summary>
        /// <returns>Links。</returns>
        public List<LinkState> Links { get; } = new();
        /// <summary>
        /// 获取或设置Pending。
        /// </summary>
        /// <returns>Pending。</returns>
        public ConcurrentDictionary<ulong, PendingFrame> Pending { get; } = new();
        /// <summary>
        /// 获取或设置Reorder。
        /// </summary>
        /// <returns>Reorder。</returns>
        public SortedDictionary<ulong, P2PMessage> Reorder { get; } = new();
        /// <summary>
        /// 获取或设置In Flight Slots。
        /// </summary>
        /// <returns>In Flight Slots。</returns>
        public SemaphoreSlim InFlightSlots { get; }
        public long NextSendSequence;
        public ulong NextExpectedSequence = 1;
        /// <summary>
        /// 获取或设置Link Count。
        /// </summary>
        /// <returns>Link Count。</returns>
        public int LinkCount { get { lock (Sync) return Links.Count; } }
        /// <summary>
        /// 执行Snapshot Links操作。
        /// </summary>
        /// <returns>操作结果。</returns>
        public LinkState[] SnapshotLinks() { lock (Sync) return Links.ToArray(); }
        /// <summary>
        /// 执行Dispose操作。
        /// </summary>
        public void Dispose()
        {
            foreach (PendingFrame pending in Pending.Values) pending.FailAndDispose();
            Pending.Clear();
            lock (Sync) { foreach (P2PMessage message in Reorder.Values) message.Dispose(); Reorder.Clear(); }
            InFlightSlots.Dispose();
        }
    }

    /// <summary>
/// 表示 Link State，并提供相关数据或行为。
/// </summary>
private sealed class LinkState
    {
        private int _retired;
        private int _keepAliveActive;
        /// <summary>
        /// 初始化 <see cref="LinkState"/> 类的新实例。
        /// </summary>
        /// <param name="link">link参数。</param>
        public LinkState(IP2PLink link)
        {
            Link = link;
            long now = Stopwatch.GetTimestamp();
            LastReceiveTimestamp = LastSendTimestamp = now;
        }
        /// <summary>
        /// 获取或设置Link。
        /// </summary>
        /// <returns>Link。</returns>
        public IP2PLink Link { get; }
        /// <summary>
        /// 获取或设置Receive Task。
        /// </summary>
        /// <returns>Receive Task。</returns>
        public Task? ReceiveTask { get; set; }
        public long ActiveSendBytes;
        public int ConsecutiveFailures;
        public long LastReceiveTimestamp;
        public long LastSendTimestamp;
        /// <summary>
        /// 获取或设置Retired。
        /// </summary>
        /// <returns>Retired。</returns>
        public bool Retired => Volatile.Read(ref _retired) != 0;
        /// <summary>
        /// 尝试Retire。
        /// </summary>
        /// <returns>操作是否成功。</returns>
        public bool TryRetire() => Interlocked.Exchange(ref _retired, 1) == 0;
        /// <summary>
        /// 尝试Begin Keep Alive。
        /// </summary>
        /// <returns>操作是否成功。</returns>
        public bool TryBeginKeepAlive() => Interlocked.CompareExchange(ref _keepAliveActive, 1, 0) == 0;
        /// <summary>
        /// 执行End Keep Alive操作。
        /// </summary>
        public void EndKeepAlive() => Volatile.Write(ref _keepAliveActive, 0);
    }

    /// <summary>
/// 表示 Pending Frame，并提供相关数据或行为。
/// </summary>
private sealed class PendingFrame
    {
        private readonly object _sync = new();
        private P2POwnedBuffer? _owner;
        private bool _sending = true;
        private bool _acknowledged;
        private bool _disposed;
        private long _nextRetry;
        /// <summary>
        /// 初始化 <see cref="PendingFrame"/> 类的新实例。
        /// </summary>
        /// <param name="sequence">sequence参数。</param>
        /// <param name="owner">owner参数。</param>
        /// <param name="now">now参数。</param>
        public PendingFrame(ulong sequence, P2POwnedBuffer owner, long now)
        { Sequence = sequence; _owner = owner; _nextRetry = now; }
        /// <summary>
        /// 获取或设置Sequence。
        /// </summary>
        /// <returns>Sequence。</returns>
        public ulong Sequence { get; }
        /// <summary>
        /// 获取或设置Retry Count。
        /// </summary>
        /// <returns>Retry Count。</returns>
        public int RetryCount { get; private set; }
        /// <summary>
        /// 获取或设置Memory。
        /// </summary>
        /// <returns>Memory。</returns>
        public ReadOnlyMemory<byte> Memory { get { lock (_sync) return (_owner ?? throw new ObjectDisposedException(nameof(PendingFrame))).Memory; } }
        /// <summary>
        /// 尝试Begin Retry。
        /// </summary>
        /// <param name="now">now参数。</param>
        /// <param name="maximumRetries">maximum Retries参数。</param>
        /// <param name="exhausted">exhausted参数。</param>
        /// <returns>操作是否成功。</returns>
        public bool TryBeginRetry(long now, int maximumRetries, out bool exhausted)
        {
            lock (_sync)
            {
                exhausted = false;
                if (_disposed || _acknowledged || _sending || now < _nextRetry) return false;
                if (RetryCount >= maximumRetries) { exhausted = true; _sending = true; return true; }
                RetryCount++;
                _sending = true;
                return true;
            }
        }
        /// <summary>
        /// 执行Complete Send操作。
        /// </summary>
        /// <param name="success">success参数。</param>
        /// <param name="delay">delay参数。</param>
        public void CompleteSend(bool success, TimeSpan delay)
        {
            P2POwnedBuffer? dispose = null;
            lock (_sync)
            {
                _sending = false;
                _nextRetry = Stopwatch.GetTimestamp() + (long)(delay.TotalSeconds * Stopwatch.Frequency);
                if (_acknowledged && !_disposed) { _disposed = true; dispose = _owner; _owner = null; }
            }
            dispose?.Dispose();
        }
        /// <summary>
        /// 执行Acknowledge操作。
        /// </summary>
        public void Acknowledge()
        {
            P2POwnedBuffer? dispose = null;
            lock (_sync)
            {
                _acknowledged = true;
                if (!_sending && !_disposed) { _disposed = true; dispose = _owner; _owner = null; }
            }
            dispose?.Dispose();
        }
        /// <summary>
        /// 执行Fail And Dispose操作。
        /// </summary>
        public void FailAndDispose()
        {
            P2POwnedBuffer? dispose;
            lock (_sync)
            {
                if (_disposed) return;
                _disposed = true;
                dispose = _owner;
                _owner = null;
            }
            dispose?.Dispose();
        }
    }
}
