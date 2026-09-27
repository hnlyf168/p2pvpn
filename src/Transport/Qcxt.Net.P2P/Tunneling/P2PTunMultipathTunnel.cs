using Qcxt.Net.P2P.Session;

namespace Qcxt.Net.P2P.Tunneling;

/// <summary>定义异步三层 TUN 设备。</summary>
public interface IP2PTunDevice : IAsyncDisposable
{
    /// <summary>读取一个完整 IP 数据包。</summary>
    /// <param name="buffer">目标数据包缓冲区。</param>
    /// <param name="cancellationToken">用于取消读取的标记。</param>
    /// <returns>数据包长度；没有产生数据包时返回零。</returns>
    ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default);
    /// <summary>写入一个完整 IP 数据包。</summary>
    /// <param name="buffer">原始数据包字节。</param>
    /// <param name="cancellationToken">用于取消写入的标记。</param>
    /// <returns>数据提交到设备后结束的异步操作。</returns>
    ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default);
}

/// <summary>
/// 表示 IP2P Packet Translator，并提供相关数据或行为。
/// </summary>
public interface IP2PPacketTranslator
{
    /// <summary>
    /// 执行Translate Outbound操作。
    /// </summary>
    /// <param name="packet">packet参数。</param>
    /// <param name="targetPeerId">target Peer Id参数。</param>
    /// <returns>操作结果。</returns>
    ReadOnlyMemory<byte> TranslateOutbound(ReadOnlyMemory<byte> packet, ulong targetPeerId);
    /// <summary>
    /// 执行Translate Inbound操作。
    /// </summary>
    /// <param name="packet">packet参数。</param>
    /// <param name="sourcePeerId">source Peer Id参数。</param>
    /// <returns>操作结果。</returns>
    ReadOnlyMemory<byte> TranslateInbound(ReadOnlyMemory<byte> packet, ulong sourcePeerId);
}

/// <summary>通过低延迟有界 P2P 消息桥接 TUN 数据包，并按需进行分片。</summary>
public sealed class P2PTunMultipathTunnel : IAsyncDisposable
{
    private const uint FragmentMagic = 0x51584632;
    private const int FragmentHeaderLength = 16;
    /// <summary>获取兼顾 IPv4、IPv6、直连及服务器中转封装的建议 TUN MTU。</summary>
    public const int RecommendedMtu = 1200;
    private const int FragmentPayloadSize = RecommendedMtu;
    private const int MaximumPacketSize = 65_535;
    private const int MaximumAssemblies = 4096;
    private readonly IP2PTunDevice _tunDevice;
    private readonly P2PMultipathSession _session;
    private readonly IP2PPacketRouter _router;
    private readonly ConcurrentDictionary<AssemblyKey, FragmentAssembly> _assemblies = new();
    private readonly CancellationTokenSource _lifetime = new();
    private CancellationTokenSource? _runLifetime;
    private Task? _tunReadTask;
    private Task? _sessionReadTask;
    private int _packetId;
    private int _started;
    private int _disposed;
    private long _droppedPackets;

    /// <summary>获取或设置客户端当前的本地 IPv4 地址；配置后可用于安全响应隧道内回显请求。</summary>
    public IPAddress? LocalIpv4Address { get; set; }

    /// <summary>获取或设置是否由隧道直接响应发给本机虚拟地址的 ICMPv4 Echo Request。</summary>
    public bool RespondToIpv4EchoRequests { get; set; }
    /// <summary>
    /// 获取或设置Packet Translator。
    /// </summary>
    /// <returns>Packet Translator。</returns>
    public IP2PPacketTranslator? PacketTranslator { get; set; }
    /// <summary>在转换、回显和写入前按已认证对端身份执行入站授权。</summary>
    public Func<ReadOnlyMemory<byte>, ulong, bool>? InboundFilter { get; set; }

    /// <summary>创建一个尚未启动的 TUN 网桥。</summary>
    /// <param name="tunDevice">具有所有权的 TUN 设备。</param>
    /// <param name="session">持久化多路径会话。</param>
    /// <param name="router">目标对端路由表。</param>
    public P2PTunMultipathTunnel(IP2PTunDevice tunDevice, P2PMultipathSession session, IP2PPacketRouter router)
    {
        _tunDevice = tunDevice ?? throw new ArgumentNullException(nameof(tunDevice));
        _session = session ?? throw new ArgumentNullException(nameof(session));
        _router = router ?? throw new ArgumentNullException(nameof(router));
    }

    /// <summary>在可选的零分配出站诊断中触发。</summary>
    public event Action<P2PNetworkPacketInfo>? PacketSending;
    /// <summary>在可选的零分配入站诊断中触发。</summary>
    public event Action<P2PNetworkPacketInfo>? PacketReceived;
    /// <summary>获取因解析、路由、队列或重组限制而被拒绝的数据包数量。</summary>
    public long DroppedPackets => Interlocked.Read(ref _droppedPackets);

    /// <summary>仅启动一组 TUN 与会话数据泵。</summary>
    /// <param name="cancellationToken">可选的外部隧道生命周期取消标记。</param>
    public void Start(CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) != 0, this);
        if (Interlocked.Exchange(ref _started, 1) != 0) throw new InvalidOperationException("TUN 隧道已经启动。");
        _runLifetime = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, _lifetime.Token);
        _tunReadTask = RunPumpAsync(PumpTunToSessionAsync(_runLifetime.Token), _runLifetime);
        _sessionReadTask = RunPumpAsync(PumpSessionToTunAsync(_runLifetime.Token), _runLifetime);
    }

    /// <summary>当任一方向结束或失败时取消另一个数据泵。</summary>
    /// <param name="pump">一个活动的隧道方向。</param>
    /// <param name="linked">共享的关联隧道生命周期。</param>
    /// <returns>保留原始数据泵结果的任务。</returns>
    private static async Task RunPumpAsync(Task pump, CancellationTokenSource linked)
    {
        try { await pump.ConfigureAwait(false); }
        finally
        {
            try { linked.Cancel(); } catch (ObjectDisposedException) { }
        }
    }

    /// <summary>读取 IP 数据包，应用路由与优先级，然后发送有界分片。</summary>
    /// <param name="cancellationToken">隧道生命周期取消标记。</param>
    /// <returns>隧道停止时结束的任务。</returns>
    private async Task PumpTunToSessionAsync(CancellationToken cancellationToken)
    {
        byte[] buffer = ArrayPool<byte>.Shared.Rent(MaximumPacketSize);
        try
        {
            while (!cancellationToken.IsCancellationRequested)
            {
                int length;
                try { length = await _tunDevice.ReadAsync(buffer, cancellationToken).ConfigureAwait(false); }
                catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { break; }
                catch
                {
                    Interlocked.Increment(ref _droppedPackets);
                    await Task.Delay(10, cancellationToken).ConfigureAwait(false);
                    continue;
                }
                if (length <= 0) continue;
                if (length > MaximumPacketSize ||
                    !P2PNetworkPacketParser.TryParse(buffer.AsSpan(0, length), out P2PNetworkPacketInfo info) ||
                    !_router.TryResolve(buffer.AsSpan(0, length), out ulong peerId))
                { Interlocked.Increment(ref _droppedPackets); continue; }
                try
                {
                ReadOnlyMemory<byte> outboundPacket = buffer.AsMemory(0, length);
                if (PacketTranslator is not null)
                    outboundPacket = PacketTranslator.TranslateOutbound(outboundPacket, peerId);
                outboundPacket = P2PTcpMss.Clamp(outboundPacket, RecommendedMtu);
                InvokePacketEvent(PacketSending, info);
                P2PTrafficClass traffic = P2PNetworkPacketParser.Classify(info);
                P2PDeliveryMode deliveryMode = P2PNetworkPacketParser.SelectDeliveryMode(info);
                // 常规 MTU 内的 IP 包直接进入 P2P 帧，避免分片缓冲区租用及一次整包复制。
                if (length <= FragmentPayloadSize)
                {
                    await SendWithTimeoutAsync(peerId, outboundPacket, deliveryMode, traffic,
                        cancellationToken).ConfigureAwait(false);
                    continue;
                }
                int fragmentCount = (length + FragmentPayloadSize - 1) / FragmentPayloadSize;
                uint packetId = NextPacketId();
                for (int index = 0, offset = 0; index < fragmentCount; index++)
                {
                    int payloadLength = Math.Min(FragmentPayloadSize, length - offset);
                    using P2POwnedBuffer fragment = P2POwnedBuffer.Rent(FragmentHeaderLength + payloadLength);
                    WriteFragmentHeader(fragment.Memory.Span, packetId, index, fragmentCount, length, payloadLength);
                    outboundPacket.Span.Slice(offset, payloadLength).CopyTo(fragment.Memory.Span[FragmentHeaderLength..]);
                    await SendWithTimeoutAsync(peerId, fragment.Memory, deliveryMode, traffic,
                        cancellationToken).ConfigureAwait(false);
                    offset += payloadLength;
                }
                }
                catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { break; }
                catch { Interlocked.Increment(ref _droppedPackets); }
            }
        }
        finally { ArrayPool<byte>.Shared.Return(buffer); }
    }

    /// <summary>返回适合长期运行隧道、可安全回绕的非零数据包标识。</summary>
    /// <returns>下一个非零 32 位标识。</returns>
    private uint NextPacketId()
    {
        uint value;
        do { value = unchecked((uint)Interlocked.Increment(ref _packetId)); }
        while (value == 0);
        return value;
    }

    /// <summary>限制单个数据包占用发送泵的时间，避免失效的可靠路径堵住后续全部流量。</summary>
    private async ValueTask SendWithTimeoutAsync(ulong peerId, ReadOnlyMemory<byte> payload,
        P2PDeliveryMode deliveryMode, P2PTrafficClass traffic, CancellationToken cancellationToken)
    {
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        byte[] ownedPayload = payload.ToArray();
        Task sendTask = _session.SendAsync(peerId, ownedPayload, deliveryMode, traffic, timeout.Token).AsTask();
        try
        {
            await sendTask.WaitAsync(TimeSpan.FromSeconds(3), cancellationToken).ConfigureAwait(false);
        }
        catch (TimeoutException)
        {
            timeout.Cancel();
            _ = ObserveAbandonedSendAsync(sendTask);
            throw;
        }
    }

    /// <summary>
    /// 执行Observe Abandoned Send操作。
    /// </summary>
    /// <param name="sendTask">send Task参数。</param>
    /// <returns>操作结果。</returns>
    private static async Task ObserveAbandonedSendAsync(Task sendTask)
    {
        try { await sendTask.ConfigureAwait(false); }
        catch { }
    }

    /// <summary>接收分片、写入完整 IP 数据包并淘汰不完整的重组项。</summary>
    /// <param name="cancellationToken">隧道生命周期取消标记。</param>
    /// <returns>隧道停止时结束的任务。</returns>
    private async Task PumpSessionToTunAsync(CancellationToken cancellationToken)
    {
        int cleanupCounter = 0;
        while (!cancellationToken.IsCancellationRequested)
        {
            P2PMessage message;
            try { message = await _session.ReceiveAsync(cancellationToken).ConfigureAwait(false); }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { break; }
            catch
            {
                Interlocked.Increment(ref _droppedPackets);
                await Task.Delay(10, cancellationToken).ConfigureAwait(false);
                continue;
            }
            using (message)
            try
            {
            // 新版发送端对 MTU 内的数据包不增加隧道头；同时继续接受真正的分片消息。
            if (P2PNetworkPacketParser.TryParse(message.Payload.Span, out P2PNetworkPacketInfo directInfo) &&
                directInfo.PacketLength == message.Payload.Length)
            {
                if (InboundFilter is not null && !InboundFilter(message.Payload, message.SourcePeerId))
                { Interlocked.Increment(ref _droppedPackets); continue; }
                ReadOnlyMemory<byte> inboundPacket = PacketTranslator is null ? message.Payload :
                    PacketTranslator.TranslateInbound(message.Payload, message.SourcePeerId);
                inboundPacket = P2PTcpMss.Clamp(inboundPacket, RecommendedMtu);
                if (TryCreateIpv4EchoReply(inboundPacket.Span, out byte[]? echoReply))
                {
                    await SendWithTimeoutAsync(message.SourcePeerId, echoReply,
                        P2PDeliveryMode.Unreliable, P2PTrafficClass.Interactive,
                        cancellationToken).ConfigureAwait(false);
                    InvokePacketEvent(PacketReceived, directInfo);
                    continue;
                }
                await _tunDevice.WriteAsync(inboundPacket, cancellationToken).ConfigureAwait(false);
                InvokePacketEvent(PacketReceived, directInfo);
                continue;
            }
            if (!TryReadFragmentHeader(message.Payload.Span, out uint packetId, out int index,
                out int count, out int totalLength, out int payloadLength))
            { Interlocked.Increment(ref _droppedPackets); continue; }
            ReadOnlyMemory<byte> payload = message.Payload.Slice(FragmentHeaderLength, payloadLength);
            if (count == 1)
            {
                await WritePacketAsync(payload, message.SourcePeerId, cancellationToken).ConfigureAwait(false);
            }
            else
            {
                var key = new AssemblyKey(message.SourcePeerId, packetId);
                if (_assemblies.Count >= MaximumAssemblies && !_assemblies.ContainsKey(key))
                { Interlocked.Increment(ref _droppedPackets); continue; }
                FragmentAssembly assembly = _assemblies.GetOrAdd(key, _ => new FragmentAssembly(count, totalLength));
                if (!assembly.Matches(count, totalLength) || !assembly.TryAdd(index, payload.Span))
                { Interlocked.Increment(ref _droppedPackets); continue; }
                if (assembly.IsComplete && _assemblies.TryRemove(new KeyValuePair<AssemblyKey, FragmentAssembly>(key, assembly)))
                {
                    try { await WritePacketAsync(assembly.Packet, message.SourcePeerId, cancellationToken).ConfigureAwait(false); }
                    finally { assembly.Dispose(); }
                }
            }
            if (++cleanupCounter % 1024 == 0) ExpireAssemblies();
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { break; }
            catch { Interlocked.Increment(ref _droppedPackets); }
        }
    }

    /// <summary>为发给当前虚拟 IPv4 地址的标准 ICMP Echo Request 构造 Echo Reply。</summary>
    private bool TryCreateIpv4EchoReply(ReadOnlySpan<byte> packet, out byte[]? reply)
    {
        reply = null;
        if (!RespondToIpv4EchoRequests || LocalIpv4Address is not IPAddress local ||
            local.AddressFamily != AddressFamily.InterNetwork || packet.Length < 28 ||
            packet[0] >> 4 != 4 || packet[9] != 1)
            return false;

        int headerLength = (packet[0] & 0x0f) * 4;
        int totalLength = BinaryPrimitives.ReadUInt16BigEndian(packet[2..]);
        ushort fragment = BinaryPrimitives.ReadUInt16BigEndian(packet[6..]);
        if (headerLength < 20 || totalLength < headerLength + 8 || totalLength > packet.Length ||
            (fragment & 0x3fff) != 0 || packet[headerLength] != 8 || packet[headerLength + 1] != 0)
            return false;

        Span<byte> localBytes = stackalloc byte[4];
        if (!local.TryWriteBytes(localBytes, out int written) || written != 4 ||
            !packet.Slice(16, 4).SequenceEqual(localBytes))
            return false;

        reply = packet[..totalLength].ToArray();
        Span<byte> result = reply;
        result.Slice(12, 4).CopyTo(result.Slice(16, 4));
        localBytes.CopyTo(result.Slice(12, 4));
        result[8] = 64;
        result[headerLength] = 0;
        result[headerLength + 2] = result[headerLength + 3] = 0;
        BinaryPrimitives.WriteUInt16BigEndian(result[(headerLength + 2)..],
            ComputeInternetChecksum(result[headerLength..totalLength]));
        result[10] = result[11] = 0;
        BinaryPrimitives.WriteUInt16BigEndian(result[10..], ComputeInternetChecksum(result[..headerLength]));
        return true;
    }

    /// <summary>
    /// 执行Compute Internet Checksum操作。
    /// </summary>
    /// <param name="value">待处理的值。</param>
    /// <returns>操作结果。</returns>
    private static ushort ComputeInternetChecksum(ReadOnlySpan<byte> value)
    {
        uint sum = 0;
        int index = 0;
        for (; index + 1 < value.Length; index += 2)
            sum += BinaryPrimitives.ReadUInt16BigEndian(value[index..]);
        if (index < value.Length) sum += (uint)value[index] << 8;
        while ((sum >> 16) != 0) sum = (sum & 0xffff) + (sum >> 16);
        return unchecked((ushort)~sum);
    }

    /// <summary>校验元数据、写入一个数据包并调用可选诊断。</summary>
    private async ValueTask WritePacketAsync(ReadOnlyMemory<byte> packet, ulong sourcePeerId,
        CancellationToken cancellationToken)
    {
        if (!P2PNetworkPacketParser.TryParse(packet.Span, out P2PNetworkPacketInfo info) ||
            info.PacketLength != packet.Length)
        { Interlocked.Increment(ref _droppedPackets); return; }
        if (InboundFilter is not null && !InboundFilter(packet, sourcePeerId))
        { Interlocked.Increment(ref _droppedPackets); return; }
        ReadOnlyMemory<byte> inboundPacket = PacketTranslator is null ? packet :
            PacketTranslator.TranslateInbound(packet, sourcePeerId);
        inboundPacket = P2PTcpMss.Clamp(inboundPacket, RecommendedMtu);
        await _tunDevice.WriteAsync(inboundPacket, cancellationToken).ConfigureAwait(false);
        InvokePacketEvent(PacketReceived, info);
    }

    /// <summary>调用诊断订阅者，并隔离应用回调异常以免停止数据包转发。</summary>
    /// <param name="handlers">当前诊断订阅者。</param>
    /// <param name="info">已解析的数据包元数据。</param>
    private static void InvokePacketEvent(Action<P2PNetworkPacketInfo>? handlers, P2PNetworkPacketInfo info)
    {
        if (handlers is null) return;
        foreach (Action<P2PNetworkPacketInfo> handler in handlers.GetInvocationList())
        {
            try { handler(info); } catch { }
        }
    }

    /// <summary>移除超过十秒仍未完整的分片组。</summary>
    private void ExpireAssemblies()
    {
        long now = Stopwatch.GetTimestamp();
        foreach (KeyValuePair<AssemblyKey, FragmentAssembly> pair in _assemblies)
        {
            if (Stopwatch.GetElapsedTime(pair.Value.CreatedTimestamp, now) < TimeSpan.FromSeconds(10)) continue;
            if (_assemblies.TryRemove(pair)) { pair.Value.Dispose(); Interlocked.Increment(ref _droppedPackets); }
        }
    }

    /// <summary>写入一个固定分片首部。</summary>
    private static void WriteFragmentHeader(Span<byte> destination, uint packetId, int index,
        int count, int totalLength, int payloadLength)
    {
        BinaryPrimitives.WriteUInt32BigEndian(destination, FragmentMagic);
        BinaryPrimitives.WriteUInt32BigEndian(destination[4..], packetId);
        BinaryPrimitives.WriteUInt16BigEndian(destination[8..], checked((ushort)index));
        BinaryPrimitives.WriteUInt16BigEndian(destination[10..], checked((ushort)count));
        BinaryPrimitives.WriteUInt16BigEndian(destination[12..], checked((ushort)totalLength));
        BinaryPrimitives.WriteUInt16BigEndian(destination[14..], checked((ushort)payloadLength));
    }

    /// <summary>校验并解码一条长度精确的分片消息。</summary>
    private static bool TryReadFragmentHeader(ReadOnlySpan<byte> source, out uint packetId,
        out int index, out int count, out int totalLength, out int payloadLength)
    {
        packetId = 0; index = count = totalLength = payloadLength = 0;
        if (source.Length < FragmentHeaderLength || BinaryPrimitives.ReadUInt32BigEndian(source) != FragmentMagic)
            return false;
        packetId = BinaryPrimitives.ReadUInt32BigEndian(source[4..]);
        index = BinaryPrimitives.ReadUInt16BigEndian(source[8..]);
        count = BinaryPrimitives.ReadUInt16BigEndian(source[10..]);
        totalLength = BinaryPrimitives.ReadUInt16BigEndian(source[12..]);
        payloadLength = BinaryPrimitives.ReadUInt16BigEndian(source[14..]);
        return packetId != 0 && count is >= 1 and <= 64 && index < count &&
            totalLength is >= 20 and <= MaximumPacketSize && payloadLength is >= 1 and <= FragmentPayloadSize &&
            count == (totalLength + FragmentPayloadSize - 1) / FragmentPayloadSize &&
            source.Length == FragmentHeaderLength + payloadLength;
    }

    /// <summary>以幂等方式停止两个数据泵并释放 TUN 及分片资源。</summary>
    /// <returns>数据泵关闭后结束的异步操作。</returns>
    public async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0) return;
        _lifetime.Cancel();
        try { await _tunDevice.DisposeAsync().ConfigureAwait(false); } catch { }
        Task[] tasks = [_tunReadTask ?? Task.CompletedTask, _sessionReadTask ?? Task.CompletedTask];
        try { await Task.WhenAll(tasks).WaitAsync(TimeSpan.FromSeconds(5)).ConfigureAwait(false); } catch { }
        _runLifetime?.Dispose();
        foreach (FragmentAssembly assembly in _assemblies.Values) assembly.Dispose();
        _assemblies.Clear();
        _lifetime.Dispose();
    }

    /// <summary>
    /// 表示 Assembly Key，并提供相关数据或行为。
    /// </summary>
    /// <param name="PeerId">Peer Id参数。</param>
    /// <param name="PacketId">Packet Id参数。</param>
    private readonly record struct AssemblyKey(ulong PeerId, uint PacketId);

    /// <summary>
/// 表示 Fragment Assembly，并提供相关数据或行为。
/// </summary>
private sealed class FragmentAssembly : IDisposable
    {
        private readonly object _sync = new();
        private readonly bool[] _received;
        private readonly int _totalLength;
        private P2POwnedBuffer? _owner;
        private int _receivedCount;
        /// <summary>
        /// 初始化 <see cref="FragmentAssembly"/> 类的新实例。
        /// </summary>
        /// <param name="count">数据数量。</param>
        /// <param name="totalLength">total Length参数。</param>
        public FragmentAssembly(int count, int totalLength)
        {
            _received = new bool[count];
            _totalLength = totalLength;
            _owner = P2POwnedBuffer.Rent(totalLength);
            CreatedTimestamp = Stopwatch.GetTimestamp();
        }
        /// <summary>
        /// 获取或设置Created Timestamp。
        /// </summary>
        /// <returns>Created Timestamp。</returns>
        public long CreatedTimestamp { get; }
        /// <summary>
        /// 获取或设置Is Complete。
        /// </summary>
        /// <returns>Is Complete。</returns>
        public bool IsComplete { get { lock (_sync) return _receivedCount == _received.Length; } }
        /// <summary>
        /// 获取或设置Packet。
        /// </summary>
        /// <returns>Packet。</returns>
        public ReadOnlyMemory<byte> Packet { get { lock (_sync) return (_owner ?? throw new ObjectDisposedException(nameof(FragmentAssembly))).Memory; } }
        /// <summary>
        /// 执行Matches操作。
        /// </summary>
        /// <param name="count">数据数量。</param>
        /// <param name="totalLength">total Length参数。</param>
        /// <returns>操作结果。</returns>
        public bool Matches(int count, int totalLength) => count == _received.Length && totalLength == _totalLength;
        /// <summary>
        /// 尝试Add。
        /// </summary>
        /// <param name="index">index参数。</param>
        /// <param name="payload">payload参数。</param>
        /// <returns>操作是否成功。</returns>
        public bool TryAdd(int index, ReadOnlySpan<byte> payload)
        {
            lock (_sync)
            {
                if (_owner is null || index >= _received.Length || _received[index]) return false;
                int offset = index * FragmentPayloadSize;
                int requiredLength = index == _received.Length - 1
                    ? _totalLength - offset
                    : FragmentPayloadSize;
                if (requiredLength <= 0 || payload.Length != requiredLength) return false;
                payload.CopyTo(_owner.Memory.Span[offset..]);
                _received[index] = true; _receivedCount++;
                return true;
            }
        }
        /// <summary>
        /// 执行Dispose操作。
        /// </summary>
        public void Dispose() { lock (_sync) { _owner?.Dispose(); _owner = null; } }
    }
}
