namespace Qcxt.Net.P2P;

/// <summary>标识 P2P 链路使用的物理传输类型。</summary>
public enum P2PTransportKind : byte
{
    /// <summary>尚未识别传输类型。</summary>
    Unknown = 0,
    /// <summary>已经认证的 QUIC 连接。</summary>
    Quic = 1,
    /// <summary>通过同时打开建立的 TCP 直连。</summary>
    TcpDirect = 2,
    /// <summary>可靠的服务器中继。</summary>
    QuicRelay = 3,
    /// <summary>不可靠的 QUIC DATAGRAM 中继。</summary>
    QuicDatagramRelay = 4
}

/// <summary>标识一次 P2P 打洞或直连生命周期事件。</summary>
public enum P2PTraversalEventKind : byte
{
    /// <summary>即将开始一轮 UDP 打洞和 QUIC 直连尝试。</summary>
    UdpAttemptStarted = 1,
    /// <summary>本轮 UDP 打洞或 QUIC 建连失败。</summary>
    UdpAttemptFailed = 2,
    /// <summary>即将开始一轮 TCP 同时打开尝试。</summary>
    TcpAttemptStarted = 3,
    /// <summary>本轮 TCP 打洞或身份认证失败。</summary>
    TcpAttemptFailed = 4,
    /// <summary>已经建立并认证 QUIC 直连。</summary>
    QuicDirectSucceeded = 5,
    /// <summary>已经建立并认证 TCP 直连。</summary>
    TcpDirectSucceeded = 6,
    /// <summary>一条活动直连已经断开。</summary>
    DirectDisconnected = 7,
    /// <summary>直连尚未达到最佳状态，已经安排下一轮重试。</summary>
    RetryScheduled = 8,
    /// <summary>UDP 和 TCP 已连续失败到配置上限，本代候选不再主动重试。</summary>
    AttemptsExhausted = 9
}

/// <summary>描述一次可用于日志和监控的打洞状态变化。</summary>
/// <param name="Kind">事件类型。</param>
/// <param name="PeerId">远程节点的文本标识。</param>
/// <param name="NumericPeerId">远程节点的数字线路标识。</param>
/// <param name="Transport">本次事件对应的传输类型。</param>
/// <param name="AttemptNumber">当前连接代次内从一开始递增的尝试序号。</param>
/// <param name="RemoteEndPoint">已经确认或正在尝试的可选远程端点。</param>
/// <param name="RetryDelay">下一轮重试等待时间；不是重试事件时为空。</param>
/// <param name="Detail">适合直接记录的中文状态或失败原因。</param>
public sealed record P2PTraversalEvent(P2PTraversalEventKind Kind, string PeerId, ulong NumericPeerId,
    P2PTransportKind Transport, int AttemptNumber, IPEndPoint? RemoteEndPoint = null,
    TimeSpan? RetryDelay = null, string? Detail = null);

/// <summary>标识 P2P 链路中承载的帧类型。</summary>
public enum P2PFrameType : byte
{
    /// <summary>应用数据或隧道载荷。</summary>
    Data = 1,
    /// <summary>确认一个可靠应用帧。</summary>
    Ack = 2,
    /// <summary>不携带应用数据的存活探测。</summary>
    KeepAlive = 3,
    /// <summary>关闭一条逻辑对端路径。</summary>
    Close = 4
}

/// <summary>控制单条消息的交付和调度行为。</summary>
public enum P2PDeliveryMode : byte
{
    /// <summary>保持消息顺序并重传丢失数据。</summary>
    ReliableOrdered = 0,
    /// <summary>仅发送一次，允许丢失或乱序。</summary>
    Unreliable = 1
}

/// <summary>为延迟感知调度划分流量等级。</summary>
public enum P2PTrafficClass : byte
{
    /// <summary>ICMP、控制输入和小型 TCP 包等交互流量。</summary>
    Interactive = 0,
    /// <summary>普通应用流量。</summary>
    Normal = 1,
    /// <summary>不得阻塞交互包的大流量数据。</summary>
    Bulk = 2
}

/// <summary>提供经过校验且资源有界的 P2P 节点配置。</summary>
public sealed class P2PConnectionOptions
{
    /// <summary>Device credential checked by the coordinator, independently of the network PSK.</summary>
    public string RegistrationCredential { get; set; } = "";
    /// <summary>Legacy in-band relay is disabled in the public service.</summary>
    public bool EnableCoordinatorRelay { get; set; }
    /// <summary>Time reserved for initial direct traversal before opening fallback paths.</summary>
    public TimeSpan RelayFallbackDelay { get; set; } = TimeSpan.FromSeconds(12);
    /// <summary>Independent, authenticated WebSocket relay endpoints.</summary>
    public string[] RelayUrls { get; set; } = [];
    /// <summary>Credential sent only in the relay Authorization header.</summary>
    public string RelayCredential { get; set; } = "";
    /// <summary>End-to-end relay payload key; never sent to the relay node.</summary>
    public byte[]? RelayEncryptionKey { get; set; }

    /// <summary>获取或设置逻辑组网或房间标识。</summary>
    public string SessionId { get; set; } = Guid.NewGuid().ToString("N");
    /// <summary>获取或设置会话内唯一的节点标识。</summary>
    public string PeerId { get; set; } = Guid.NewGuid().ToString("N");
    /// <summary>获取或设置单条消息的最大应用载荷。</summary>
    public int MaximumPayloadSize { get; set; } = 64 * 1024;
    /// <summary>获取或设置流式链路可接收的最大编码帧长度。</summary>
    public int MaximumFrameSize { get; set; } = 128 * 1024;
    /// <summary>获取或设置每个对端允许的最大未确认可靠帧数。</summary>
    public int MaxInFlightPackets { get; set; } = 2048;
    /// <summary>获取或设置每个对端最多保留的乱序帧数。</summary>
    public int ReceiveWindowPackets { get; set; } = 2048;
    /// <summary>获取或设置等待应用读取的最大消息数。</summary>
    public int ReceiveQueueCapacity { get; set; } = 4096;
    /// <summary>获取或设置初始重传超时。</summary>
    public TimeSpan RetransmitTimeout { get; set; } = TimeSpan.FromMilliseconds(300);
    /// <summary>获取或设置指数退避后的最大重传超时。</summary>
    public TimeSpan MaximumRetransmitTimeout { get; set; } = TimeSpan.FromSeconds(3);
    /// <summary>获取或设置判定帧及其路径失败前的重试次数。</summary>
    public int MaximumRetries { get; set; } = 12;
    /// <summary>获取或设置空闲路径探测间隔。</summary>
    public TimeSpan KeepAliveInterval { get; set; } = TimeSpan.FromSeconds(15);
    /// <summary>获取或设置将静默路径判定为不健康的时间。</summary>
    public TimeSpan LinkIdleTimeout { get; set; } = TimeSpan.FromSeconds(45);
    /// <summary>获取或设置单次链路发送允许卡住的最长时间。</summary>
    public TimeSpan SendStallTimeout { get; set; } = TimeSpan.FromSeconds(10);
    /// <summary>获取或设置每个对端最多保留的物理路径数。</summary>
    public int MaxLinksPerPeer { get; set; } = 6;
    /// <summary>Gets or sets an optional externally reachable UDP endpoint, such as one created through UPnP.</summary>
    public IPEndPoint? AdvertisedUdpEndPoint { get; set; }
    /// <summary>Gets or sets an optional externally reachable TCP endpoint, such as one created through UPnP.</summary>
    public IPEndPoint? AdvertisedTcpEndPoint { get; set; }
    /// <summary>Optional application version reported to the coordinator.</summary>
    public string ClientVersion { get; set; } = string.Empty;
    /// <summary>Optional runtime platform reported to the coordinator.</summary>
    public string ClientPlatform { get; set; } = string.Empty;
    /// <summary>获取或设置是否启用 UDP 打洞和 QUIC 直连。</summary>
    public bool EnableUdpHolePunching { get; set; } = true;
    /// <summary>获取或设置是否启用 TCP 公网映射登记和 TCP 打洞后备路径。</summary>
    public bool EnableTcpHolePunching { get; set; } = true;
    /// <summary>When true, immediately attempts direct links to every discovered peer.</summary>
    public bool EagerHolePunching { get; set; }
    /// <summary>Releases an on-demand direct link after this period without application traffic.</summary>
    public TimeSpan DirectLinkIdleTimeout { get; set; } = TimeSpan.FromHours(1);
    /// <summary>Rejects physical candidates that would recursively traverse the VPN.</summary>
    public Func<IPAddress, IPEndPoint, bool>? DirectCandidateFilter { get; set; }
    /// <summary>获取或设置一次 UDP 打洞等待认证确认的最长时间。</summary>
    public TimeSpan UdpPunchTimeout { get; set; } = TimeSpan.FromSeconds(10);
    /// <summary>获取或设置一次 TCP 打洞及身份认证的总超时时间。</summary>
    public TimeSpan TcpPunchTimeout { get; set; } = TimeSpan.FromSeconds(6);
    /// <summary>获取或设置 UDP 和 TCP 均失败时允许的最大合并打洞轮数。</summary>
    public int MaximumHolePunchRounds { get; set; } = 5;
    /// <summary>获取或设置两轮合并打洞之间的等待时间。</summary>
    public TimeSpan HolePunchRetryInterval { get; set; } = TimeSpan.FromSeconds(5);
    /// <summary>获取或设置 UDP 公网候选端口向上和向下猜测的数量。</summary>
    public int UdpPublicPortFanout { get; set; } = 8;
    /// <summary>获取或设置 TCP 公网候选端口向上和向下猜测的数量。</summary>
    public int TcpPublicPortFanout { get; set; } = 8;
    /// <summary>获取或设置后台任务停止的最长等待时间。</summary>
    public TimeSpan ShutdownTimeout { get; set; } = TimeSpan.FromSeconds(5);

    /// <summary>在网络任务启动前校验全部配置。</summary>
    /// <exception cref="ArgumentException">字符串配置为空时抛出。</exception>
    /// <exception cref="ArgumentOutOfRangeException">数值或时间配置超出安全范围时抛出。</exception>
    public void Validate()
    {
        if (string.IsNullOrWhiteSpace(SessionId)) throw new ArgumentException("必须提供会话标识。", nameof(SessionId));
        if (string.IsNullOrWhiteSpace(PeerId)) throw new ArgumentException("必须提供对端标识。", nameof(PeerId));
        if (Encoding.UTF8.GetByteCount(SessionId) > 1024) throw new ArgumentOutOfRangeException(nameof(SessionId));
        if (Encoding.UTF8.GetByteCount(PeerId) > 1024) throw new ArgumentOutOfRangeException(nameof(PeerId));
        if (MaximumPayloadSize is < 1 or > 16 * 1024 * 1024) throw new ArgumentOutOfRangeException(nameof(MaximumPayloadSize));
        if (MaximumFrameSize < MaximumPayloadSize + Protocol.P2PFrameCodec.HeaderLength || MaximumFrameSize > 32 * 1024 * 1024)
            throw new ArgumentOutOfRangeException(nameof(MaximumFrameSize));
        if (MaxInFlightPackets is < 1 or > 1_048_576) throw new ArgumentOutOfRangeException(nameof(MaxInFlightPackets));
        if (ReceiveWindowPackets is < 1 or > 1_048_576) throw new ArgumentOutOfRangeException(nameof(ReceiveWindowPackets));
        if (ReceiveQueueCapacity is < 1 or > 1_048_576) throw new ArgumentOutOfRangeException(nameof(ReceiveQueueCapacity));
        if (RetransmitTimeout < TimeSpan.FromMilliseconds(20)) throw new ArgumentOutOfRangeException(nameof(RetransmitTimeout));
        if (MaximumRetransmitTimeout < RetransmitTimeout) throw new ArgumentOutOfRangeException(nameof(MaximumRetransmitTimeout));
        if (MaximumRetries is < 1 or > 1000) throw new ArgumentOutOfRangeException(nameof(MaximumRetries));
        if (KeepAliveInterval <= TimeSpan.Zero || LinkIdleTimeout <= KeepAliveInterval) throw new ArgumentOutOfRangeException(nameof(KeepAliveInterval));
        if (SendStallTimeout <= TimeSpan.Zero) throw new ArgumentOutOfRangeException(nameof(SendStallTimeout));
        if (MaxLinksPerPeer is < 1 or > 64) throw new ArgumentOutOfRangeException(nameof(MaxLinksPerPeer));
        ValidateAdvertisedEndPoint(AdvertisedUdpEndPoint, nameof(AdvertisedUdpEndPoint));
        ValidateAdvertisedEndPoint(AdvertisedTcpEndPoint, nameof(AdvertisedTcpEndPoint));
        if (Encoding.UTF8.GetByteCount(ClientVersion) > 64) throw new ArgumentOutOfRangeException(nameof(ClientVersion));
        if (Encoding.UTF8.GetByteCount(ClientPlatform) > 64) throw new ArgumentOutOfRangeException(nameof(ClientPlatform));
        if (UdpPunchTimeout < TimeSpan.FromMilliseconds(100) || UdpPunchTimeout > TimeSpan.FromMinutes(2))
            throw new ArgumentOutOfRangeException(nameof(UdpPunchTimeout));
        if (TcpPunchTimeout < TimeSpan.FromMilliseconds(200) || TcpPunchTimeout > TimeSpan.FromMinutes(2))
            throw new ArgumentOutOfRangeException(nameof(TcpPunchTimeout));
        if (DirectLinkIdleTimeout < TimeSpan.FromMinutes(1) || DirectLinkIdleTimeout > TimeSpan.FromDays(7))
            throw new ArgumentOutOfRangeException(nameof(DirectLinkIdleTimeout));
        if (MaximumHolePunchRounds is < 1 or > 100)
            throw new ArgumentOutOfRangeException(nameof(MaximumHolePunchRounds));
        if (HolePunchRetryInterval < TimeSpan.FromMilliseconds(100) || HolePunchRetryInterval > TimeSpan.FromMinutes(5))
            throw new ArgumentOutOfRangeException(nameof(HolePunchRetryInterval));
        if (UdpPublicPortFanout is < 0 or > 128)
            throw new ArgumentOutOfRangeException(nameof(UdpPublicPortFanout));
        if (TcpPublicPortFanout is < 0 or > 128)
            throw new ArgumentOutOfRangeException(nameof(TcpPublicPortFanout));
        if (ShutdownTimeout <= TimeSpan.Zero) throw new ArgumentOutOfRangeException(nameof(ShutdownTimeout));
    }

    /// <summary>
    /// 执行Validate Advertised End Point操作。
    /// </summary>
    /// <param name="endpoint">网络端点。</param>
    /// <param name="parameterName">parameter Name参数。</param>
    private static void ValidateAdvertisedEndPoint(IPEndPoint? endpoint, string parameterName)
    {
        if (endpoint is null) return;
        if (endpoint.Port is < 1 or > 65535 || endpoint.Address.Equals(IPAddress.Any) ||
            endpoint.Address.Equals(IPAddress.IPv6Any) || IPAddress.IsLoopback(endpoint.Address) ||
            endpoint.Address.IsIPv6Multicast)
            throw new ArgumentOutOfRangeException(parameterName);
    }
}

/// <summary>拥有一个由 ArrayPool 支持的消息缓冲区。</summary>
public sealed class P2POwnedBuffer : IMemoryOwner<byte>
{
    private byte[]? _buffer;
    private readonly bool _clearOnReturn;

    /// <summary>
    /// 初始化 <see cref="P2POwnedBuffer"/> 类的新实例。
    /// </summary>
    /// <param name="buffer">用于暂存数据的缓冲区。</param>
    /// <param name="length">数据数量。</param>
    /// <param name="clearOnReturn">clear On Return参数。</param>
    private P2POwnedBuffer(byte[] buffer, int length, bool clearOnReturn)
    {
        _buffer = buffer;
        Length = length;
        _clearOnReturn = clearOnReturn;
    }

    /// <summary>获取缓冲区中的有效字节数。</summary>
    public int Length { get; private set; }
    /// <summary>获取池化缓冲区中的有效区域。</summary>
    public Memory<byte> Memory => (_buffer ?? throw new ObjectDisposedException(nameof(P2POwnedBuffer))).AsMemory(0, Length);

    /// <summary>租用具有指定逻辑长度的缓冲区。</summary>
    /// <param name="length">所需的有效字节数。</param>
    /// <param name="clearOnReturn">归还数组前是否清除敏感字节。</param>
    /// <returns>必须且只能释放一次的缓冲区所有者。</returns>
    public static P2POwnedBuffer Rent(int length, bool clearOnReturn = false)
    {
        if (length < 0) throw new ArgumentOutOfRangeException(nameof(length));
        return new P2POwnedBuffer(ArrayPool<byte>.Shared.Rent(Math.Max(1, length)), length, clearOnReturn);
    }

    /// <summary>把源字节复制到新租用的缓冲区。</summary>
    /// <param name="source">需要复制的字节。</param>
    /// <returns>包含独立副本的缓冲区所有者。</returns>
    public static P2POwnedBuffer CopyFrom(ReadOnlySpan<byte> source)
    {
        P2POwnedBuffer owner = Rent(source.Length);
        source.CopyTo(owner.Memory.Span);
        return owner;
    }

    /// <summary>把租用的数组归还共享池。</summary>
    public void Dispose()
    {
        byte[]? buffer = Interlocked.Exchange(ref _buffer, null);
        if (buffer is null) return;
        if (_clearOnReturn && Length != 0) CryptographicOperations.ZeroMemory(buffer.AsSpan(0, Length));
        Length = 0;
        ArrayPool<byte>.Shared.Return(buffer);
    }
}

/// <summary>拥有从物理链路收到的一个帧。</summary>
public sealed class P2PReceiveResult : IDisposable
{
    private IMemoryOwner<byte>? _owner;

    /// <summary>创建链路接收结果。</summary>
    /// <param name="owner">接收字节的所有者。</param>
    /// <param name="length">有效字节数。</param>
    /// <param name="timestamp">由 <see cref="Stopwatch.GetTimestamp"/> 取得的单调接收时间戳。</param>
    public P2PReceiveResult(IMemoryOwner<byte> owner, int length, long timestamp)
    {
        ArgumentNullException.ThrowIfNull(owner);
        if ((uint)length > (uint)owner.Memory.Length) throw new ArgumentOutOfRangeException(nameof(length));
        _owner = owner;
        Length = length;
        Timestamp = timestamp;
    }

    /// <summary>在结果有效期内获取接收字节。</summary>
    public ReadOnlyMemory<byte> Memory => (_owner ?? throw new ObjectDisposedException(nameof(P2PReceiveResult))).Memory[..Length];
    /// <summary>获取接收字节数。</summary>
    public int Length { get; }
    /// <summary>获取单调接收时间戳。</summary>
    public long Timestamp { get; }
    /// <summary>把所有权转交上层协议并清空当前结果。</summary>
    /// <returns>已分离的缓冲区所有者。</returns>
    internal IMemoryOwner<byte> DetachOwner() => Interlocked.Exchange(ref _owner, null) ??
        throw new ObjectDisposedException(nameof(P2PReceiveResult));
    /// <summary>释放底层池化缓冲区所有者。</summary>
    public void Dispose() => Interlocked.Exchange(ref _owner, null)?.Dispose();
}

/// <summary>表示两个对端之间的一条有界物理路径。</summary>
public interface IP2PLink : IAsyncDisposable
{
    /// <summary>获取稳定的链路标识。</summary>
    string Id { get; }
    /// <summary>获取链路传输类型。</summary>
    P2PTransportKind Kind { get; }
    /// <summary>获取本地网络端点，不可用时为空。</summary>
    EndPoint? LocalEndPoint { get; }
    /// <summary>获取当前远端网络端点，不可用时为空。</summary>
    EndPoint? RemoteEndPoint { get; }
    /// <summary>获取底层传输是否已经保证有序交付。</summary>
    bool IsReliable { get; }
    /// <summary>获取链路当前是否可以接受发送。</summary>
    bool IsConnected { get; }
    /// <summary>获取 <see cref="SendAsync"/> 可接受的最大数据包长度。</summary>
    int MaximumPacketSize { get; }
    /// <summary>获取在路径关闭时完成的任务。</summary>
    Task Closed { get; }

    /// <summary>在传输背压控制下发送一个完整链路包。</summary>
    /// <param name="packet">完整编码的 P2P 帧。</param>
    /// <param name="trafficClass">数据包的调度等级。</param>
    /// <param name="cancellationToken">用于取消排队的令牌。</param>
    /// <returns>传输层接受字节后完成的操作。</returns>
    ValueTask SendAsync(ReadOnlyMemory<byte> packet, P2PTrafficClass trafficClass = P2PTrafficClass.Normal,
        CancellationToken cancellationToken = default);

    /// <summary>接收一个完整链路包。</summary>
    /// <param name="cancellationToken">用于取消等待的令牌。</param>
    /// <returns>必须释放的接收数据包所有者。</returns>
    ValueTask<P2PReceiveResult> ReceiveAsync(CancellationToken cancellationToken = default);
}

/// <summary>为数据报传输提供可选的无分配立即发送路径。</summary>
public interface IP2PFastSendLink
{
    /// <summary>尝试把一个数据包复制到有界传输队列且不等待。</summary>
    /// <param name="packet">完整编码的 P2P 帧。</param>
    /// <param name="trafficClass">数据包的调度等级。</param>
    /// <returns>传输层接受数据包时返回 <see langword="true"/>。</returns>
    bool TrySend(ReadOnlySpan<byte> packet, P2PTrafficClass trafficClass = P2PTrafficClass.Normal);
}

/// <summary>拥有多路径会话交付的一条应用消息。</summary>
public sealed class P2PMessage : IDisposable
{
    private IMemoryOwner<byte>? _owner;
    private readonly int _offset;
    private readonly int _length;

    /// <summary>创建拥有数据所有权的应用消息。</summary>
    /// <param name="sourcePeerId">数字形式的来源对端标识。</param>
    /// <param name="deliveryMode">发送方使用的交付模式。</param>
    /// <param name="trafficClass">发送方提供的流量等级。</param>
    /// <param name="owner">消息载荷的所有者。</param>
    public P2PMessage(ulong sourcePeerId, P2PDeliveryMode deliveryMode, P2PTrafficClass trafficClass,
        P2POwnedBuffer owner)
    {
        SourcePeerId = sourcePeerId;
        DeliveryMode = deliveryMode;
        TrafficClass = trafficClass;
        _owner = owner;
        _length = owner.Length;
    }

    /// <summary>在接收帧所有者上创建零拷贝视图。</summary>
    /// <param name="sourcePeerId">数字形式的来源对端标识。</param>
    /// <param name="deliveryMode">发送方使用的交付模式。</param>
    /// <param name="trafficClass">发送方提供的流量等级。</param>
    /// <param name="owner">完整接收帧的所有者。</param>
    /// <param name="offset">载荷在所有者缓冲区中的偏移。</param>
    /// <param name="length">载荷长度。</param>
    internal P2PMessage(ulong sourcePeerId, P2PDeliveryMode deliveryMode, P2PTrafficClass trafficClass,
        IMemoryOwner<byte> owner, int offset, int length)
    {
        if (offset < 0 || length < 0 || offset + length > owner.Memory.Length)
            throw new ArgumentOutOfRangeException(nameof(length));
        SourcePeerId = sourcePeerId;
        DeliveryMode = deliveryMode;
        TrafficClass = trafficClass;
        _owner = owner;
        _offset = offset;
        _length = length;
    }

    /// <summary>获取数字形式的来源对端标识。</summary>
    public ulong SourcePeerId { get; }
    /// <summary>获取该消息使用的交付模式。</summary>
    public P2PDeliveryMode DeliveryMode { get; }
    /// <summary>获取消息流量等级。</summary>
    public P2PTrafficClass TrafficClass { get; }
    /// <summary>在对象有效期内获取消息载荷。</summary>
    public ReadOnlyMemory<byte> Payload => (_owner ?? throw new ObjectDisposedException(nameof(P2PMessage))).Memory.Slice(_offset, _length);
    /// <summary>释放池化载荷。</summary>
    public void Dispose() => Interlocked.Exchange(ref _owner, null)?.Dispose();
}

/// <summary>包含观测到的本地及公网 UDP 映射。</summary>
/// <param name="LocalEndPoint">已经绑定的本地 UDP 端点。</param>
/// <param name="PublicEndPoint">STUN 或协调服务器观测到的公网端点。</param>
/// <param name="Source">观测来源。</param>
public readonly record struct P2PPublicEndPoint(IPEndPoint LocalEndPoint, IPEndPoint PublicEndPoint, string Source);
