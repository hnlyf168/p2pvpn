namespace Qcxt.Net.P2P.Punching;

/// <summary>配置有界的双向同时 UDP 打洞。</summary>
public sealed class P2PHolePunchOptions
{
    /// <summary>获取或设置一次完整打洞尝试的超时时间。</summary>
    public TimeSpan Timeout { get; set; } = TimeSpan.FromSeconds(10);
    /// <summary>获取或设置打洞突发发送之间的初始间隔。</summary>
    public TimeSpan InitialRetryInterval { get; set; } = TimeSpan.FromMilliseconds(40);
    /// <summary>获取或设置退避后的最大重试间隔。</summary>
    public TimeSpan MaximumRetryInterval { get; set; } = TimeSpan.FromMilliseconds(500);
    /// <summary>获取或设置向上下两个方向探测的相邻公网端口数量。</summary>
    public int PublicPortFanout { get; set; } = 8;

    /// <summary>校验打洞参数限制。</summary>
    public void Validate()
    {
        if (Timeout <= TimeSpan.Zero) throw new ArgumentOutOfRangeException(nameof(Timeout));
        if (InitialRetryInterval < TimeSpan.FromMilliseconds(10)) throw new ArgumentOutOfRangeException(nameof(InitialRetryInterval));
        if (MaximumRetryInterval < InitialRetryInterval) throw new ArgumentOutOfRangeException(nameof(MaximumRetryInterval));
        if (PublicPortFanout is < 0 or > 128) throw new ArgumentOutOfRangeException(nameof(PublicPortFanout));
    }
}

/// <summary>描述一个对端候选集合及其配对专用认证令牌。</summary>
/// <param name="PeerId">数字形式的远程对端标识。</param>
/// <param name="PublicEndPoint">会合服务器观察到的公网端点。</param>
/// <param name="PrivateEndPoint">对端公布的可选局域网端点。</param>
/// <param name="Token">仅该对端配对已知的 32 字节随机令牌。</param>
public sealed record P2PPunchCandidate(ulong PeerId, IPEndPoint PublicEndPoint,
    IPEndPoint? PrivateEndPoint, byte[] Token);

/// <summary>包含通过打洞发现并通过认证的双向 UDP 路径。</summary>
/// <param name="PeerId">数字形式的远程对端标识。</param>
/// <param name="RemoteEndPoint">从对端获知并通过认证的来源端点。</param>
/// <param name="RoundTripTime">首次突发发送到路径确认之间的时间。</param>
public readonly record struct P2PPunchResult(ulong PeerId, IPEndPoint RemoteEndPoint, TimeSpan RoundTripTime);

/// <summary>在一个 QUIC 共享 UDP 端点上复用已认证的双向同时打洞尝试。</summary>
public sealed class P2PHolePuncher : IAsyncDisposable
{
    private const uint Magic = 0x51585048;
    private const byte Version = 1;
    private const int PacketLength = 48;
    private const int AuthenticatedLength = 32;
    private const int TagLength = 16;
    private readonly QuicSharedUdpEndpoint _endpoint;
    private readonly ulong _localPeerId;
    private readonly P2PHolePunchOptions _options;
    private readonly ConcurrentDictionary<ulong, Attempt> _attempts = new();
    private readonly CancellationTokenSource _lifetime = new();
    private readonly Task _receiveTask;
    private long _sequence;
    private int _disposed;

    /// <summary>为共享套接字启动唯一的原始数据报接收循环。</summary>
    /// <param name="endpoint">后续供 QUIC 直连使用的共享 UDP 端点。</param>
    /// <param name="localPeerId">数字形式的本地对端标识。</param>
    /// <param name="options">有界打洞重试选项。</param>
    public P2PHolePuncher(QuicSharedUdpEndpoint endpoint, ulong localPeerId, P2PHolePunchOptions? options = null)
    {
        ArgumentNullException.ThrowIfNull(endpoint);
        if (localPeerId == 0) throw new ArgumentOutOfRangeException(nameof(localPeerId));
        _options = options ?? new P2PHolePunchOptions();
        _options.Validate();
        _endpoint = endpoint;
        _localPeerId = localPeerId;
        _receiveTask = ReceiveLoopAsync(_lifetime.Token);
    }

    /// <summary>在双方客户端并发发送期间认证一条双向路径。</summary>
    /// <param name="candidate">远程公网、私网候选端点及配对令牌。</param>
    /// <param name="cancellationToken">用于取消当前调用方等待的标记。</param>
    /// <returns>已确认的端点；超时后返回 <see langword="null"/>。</returns>
    public async Task<P2PPunchResult?> PunchAsync(P2PPunchCandidate candidate,
        CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) != 0, this);
        ValidateCandidate(candidate);
        Attempt attempt = _attempts.GetOrAdd(candidate.PeerId, _ => new Attempt(candidate));
        if (!CryptographicOperations.FixedTimeEquals(attempt.Candidate.Token, candidate.Token))
            throw new InvalidOperationException("该对端的现有打洞尝试正在使用不同令牌。");
        if (attempt.TryStart()) _ = RunAttemptAsync(attempt, _lifetime.Token);
        try
        {
            return await attempt.Completion.Task.WaitAsync(_options.Timeout, cancellationToken).ConfigureAwait(false);
        }
        catch (TimeoutException) { return null; }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            attempt.Completion.TrySetResult(null);
            throw;
        }
        finally
        {
            if (attempt.Completion.Task.IsCompleted)
                _attempts.TryRemove(new KeyValuePair<ulong, Attempt>(candidate.PeerId, attempt));
        }
    }

    /// <summary>有界地突发发送打洞包，直至接收循环确认路径。</summary>
    /// <param name="attempt">每个对端共享的尝试状态。</param>
    /// <param name="cancellationToken">打洞器生命周期取消标记。</param>
    /// <returns>在成功、超时或释放时结束的任务。</returns>
    private async Task RunAttemptAsync(Attempt attempt, CancellationToken cancellationToken)
    {
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(_options.Timeout);
        TimeSpan delay = _options.InitialRetryInterval;
        try
        {
            while (!attempt.Completion.Task.IsCompleted && !timeout.IsCancellationRequested)
            {
                await SendBurstAsync(attempt.Candidate, PunchPacketType.Probe, timeout.Token).ConfigureAwait(false);
                await Task.Delay(delay, timeout.Token).ConfigureAwait(false);
                delay = TimeSpan.FromMilliseconds(Math.Min(_options.MaximumRetryInterval.TotalMilliseconds,
                    delay.TotalMilliseconds * 1.5));
            }
        }
        catch (OperationCanceledException) { }
        catch (Exception exception) { attempt.Completion.TrySetException(exception); }
        finally
        {
            attempt.Completion.TrySetResult(null);
            _attempts.TryRemove(new KeyValuePair<ulong, Attempt>(attempt.Candidate.PeerId, attempt));
        }
    }

    /// <summary>向公网扇出端口及局域网候选端点发送一个已认证数据包。</summary>
    /// <param name="candidate">远程候选端点。</param>
    /// <param name="type">探测或确认类型。</param>
    /// <param name="cancellationToken">用于取消套接字发送的标记。</param>
    /// <returns>尝试向每个候选端点发送后结束的异步操作。</returns>
    private async ValueTask SendBurstAsync(P2PPunchCandidate candidate, PunchPacketType type,
        CancellationToken cancellationToken)
    {
        byte[] buffer = ArrayPool<byte>.Shared.Rent(PacketLength);
        try
        {
            WritePacket(buffer, type, _localPeerId, candidate.PeerId,
                unchecked((ulong)Interlocked.Increment(ref _sequence)), candidate.Token);
            if (candidate.PrivateEndPoint is not null &&
                !candidate.PrivateEndPoint.Equals(candidate.PublicEndPoint))
            {
                try { await _endpoint.SendRawDatagramAsync(buffer.AsMemory(0, PacketLength),
                    candidate.PrivateEndPoint, cancellationToken).ConfigureAwait(false); } catch (SocketException) { }
            }
            foreach (int port in CandidatePorts(candidate.PublicEndPoint.Port, _options.PublicPortFanout))
            {
                try
                {
                    await _endpoint.SendRawDatagramAsync(buffer.AsMemory(0, PacketLength),
                        new IPEndPoint(candidate.PublicEndPoint.Address, port), cancellationToken).ConfigureAwait(false);
                }
                catch (SocketException) { }
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(buffer.AsSpan(0, PacketLength));
            ArrayPool<byte>.Shared.Return(buffer);
        }
    }

    /// <summary>统一接收所有非 QUIC 数据报，并将其路由到对应的对端尝试。</summary>
    /// <param name="cancellationToken">打洞器生命周期取消标记。</param>
    /// <returns>在释放期间结束的任务。</returns>
    private async Task ReceiveLoopAsync(CancellationToken cancellationToken)
    {
        try
        {
            while (!cancellationToken.IsCancellationRequested)
            {
                using QuicUdpDatagram datagram = await _endpoint.ReceiveRawDatagramAsync(cancellationToken)
                    .ConfigureAwait(false);
                if (!TryReadHeader(datagram.Memory.Span, out PunchPacketType type, out ulong source,
                    out ulong target) || target != _localPeerId ||
                    !_attempts.TryGetValue(source, out Attempt? attempt) ||
                    !ValidatePacket(datagram.Memory.Span, attempt.Candidate.Token)) continue;
                IPEndPoint remote = datagram.RemoteEndPoint;
                if (type == PunchPacketType.Probe)
                {
                    try { await SendSingleAsync(attempt.Candidate, remote, PunchPacketType.Acknowledgement,
                        cancellationToken).ConfigureAwait(false); } catch (SocketException) { }
                }
                attempt.Completion.TrySetResult(new P2PPunchResult(source, remote,
                    Stopwatch.GetElapsedTime(attempt.StartTimestamp)));
            }
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { }
        catch (ChannelClosedException) when (cancellationToken.IsCancellationRequested) { }
    }

    /// <summary>向观察到的来源端点发送一个已认证响应。</summary>
    /// <param name="candidate">对端认证状态。</param>
    /// <param name="remote">观察到的来源端点。</param>
    /// <param name="type">响应类型。</param>
    /// <param name="cancellationToken">用于取消发送的标记。</param>
    /// <returns>提交到套接字后结束的异步操作。</returns>
    private async ValueTask SendSingleAsync(P2PPunchCandidate candidate, IPEndPoint remote,
        PunchPacketType type, CancellationToken cancellationToken)
    {
        byte[] buffer = ArrayPool<byte>.Shared.Rent(PacketLength);
        try
        {
            WritePacket(buffer, type, _localPeerId, candidate.PeerId,
                unchecked((ulong)Interlocked.Increment(ref _sequence)), candidate.Token);
            await _endpoint.SendRawDatagramAsync(buffer.AsMemory(0, PacketLength), remote,
                cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(buffer.AsSpan(0, PacketLength));
            ArrayPool<byte>.Shared.Return(buffer);
        }
    }

    /// <summary>写入一个固定长度的打洞包并生成认证标签。</summary>
    /// <param name="destination">目标缓冲区。</param>
    /// <param name="type">数据包类型。</param>
    /// <param name="source">来源对端标识。</param>
    /// <param name="target">目标对端标识。</param>
    /// <param name="sequence">不重复的发送方序号。</param>
    /// <param name="token">配对专用的 32 字节令牌。</param>
    private static void WritePacket(Span<byte> destination, PunchPacketType type, ulong source,
        ulong target, ulong sequence, ReadOnlySpan<byte> token)
    {
        destination = destination[..PacketLength];
        destination.Clear();
        BinaryPrimitives.WriteUInt32BigEndian(destination, Magic);
        destination[4] = Version;
        destination[5] = (byte)type;
        BinaryPrimitives.WriteUInt64BigEndian(destination[8..], source);
        BinaryPrimitives.WriteUInt64BigEndian(destination[16..], target);
        BinaryPrimitives.WriteUInt64BigEndian(destination[24..], sequence);
        Span<byte> tag = stackalloc byte[32];
        HMACSHA256.HashData(token, destination[..AuthenticatedLength], tag);
        tag[..TagLength].CopyTo(destination[AuthenticatedLength..]);
        CryptographicOperations.ZeroMemory(tag);
    }

    /// <summary>读取定位配对令牌所需的未认证路由字段。</summary>
    /// <param name="packet">收到的原始数据报。</param>
    /// <param name="type">解析出的数据包类型。</param>
    /// <param name="source">解析出的来源对端标识。</param>
    /// <param name="target">解析出的目标对端标识。</param>
    /// <returns>固定首部结构有效时返回 <see langword="true"/>。</returns>
    private static bool TryReadHeader(ReadOnlySpan<byte> packet, out PunchPacketType type,
        out ulong source, out ulong target)
    {
        type = default;
        source = target = 0;
        if (packet.Length != PacketLength || BinaryPrimitives.ReadUInt32BigEndian(packet) != Magic ||
            packet[4] != Version || packet[5] is < 1 or > 2 || packet[6] != 0 || packet[7] != 0) return false;
        type = (PunchPacketType)packet[5];
        source = BinaryPrimitives.ReadUInt64BigEndian(packet[8..]);
        target = BinaryPrimitives.ReadUInt64BigEndian(packet[16..]);
        return source != 0 && target != 0;
    }

    /// <summary>以常量时间验证数据包认证标签。</summary>
    /// <param name="packet">完整的打洞包。</param>
    /// <param name="token">预期的配对令牌。</param>
    /// <returns>HMAC 标签有效时返回 <see langword="true"/>。</returns>
    private static bool ValidatePacket(ReadOnlySpan<byte> packet, ReadOnlySpan<byte> token)
    {
        Span<byte> tag = stackalloc byte[32];
        HMACSHA256.HashData(token, packet[..AuthenticatedLength], tag);
        bool valid = CryptographicOperations.FixedTimeEquals(tag[..TagLength], packet[AuthenticatedLength..]);
        CryptographicOperations.ZeroMemory(tag);
        return valid;
    }

    /// <summary>生成不重复的相邻公网端口候选集合。</summary>
    /// <param name="basePort">服务器观察到的公网端口。</param>
    /// <param name="fanout">向上和向下测试的端口数量。</param>
    /// <returns>以观察端口开头的有效 UDP 端口集合。</returns>
    public static IEnumerable<int> CandidatePorts(int basePort, int fanout)
    {
        if (basePort is < 1 or > 65_535) throw new ArgumentOutOfRangeException(nameof(basePort));
        if (fanout is < 0 or > 128) throw new ArgumentOutOfRangeException(nameof(fanout));
        yield return basePort;
        for (int offset = 1; offset <= fanout; offset++)
        {
            if (basePort + offset <= 65_535) yield return basePort + offset;
            if (basePort - offset >= 1) yield return basePort - offset;
        }
    }

    /// <summary>校验候选身份、端点和密钥长度。</summary>
    /// <param name="candidate">要校验的候选信息。</param>
    private void ValidateCandidate(P2PPunchCandidate candidate)
    {
        ArgumentNullException.ThrowIfNull(candidate);
        if (candidate.PeerId == 0 || candidate.PeerId == _localPeerId) throw new ArgumentOutOfRangeException(nameof(candidate));
        if (candidate.PublicEndPoint.AddressFamily != _endpoint.LocalEndPoint.AddressFamily)
            throw new ArgumentException("对端地址族与共享 UDP 套接字不一致。", nameof(candidate));
        if (candidate.Token is not { Length: 32 }) throw new ArgumentException("配对令牌必须包含 32 字节。", nameof(candidate));
    }

    /// <summary>停止接收及尝试任务，但不释放外部持有的共享端点。</summary>
    /// <returns>接收循环停止后结束的异步操作。</returns>
    public async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0) return;
        _lifetime.Cancel();
        foreach (Attempt attempt in _attempts.Values) attempt.Completion.TrySetCanceled();
        try { await _receiveTask.ConfigureAwait(false); } catch { }
        _attempts.Clear();
        _lifetime.Dispose();
    }

    /// <summary>
/// 表示 Punch Packet Type，并提供相关数据或行为。
/// </summary>
private enum PunchPacketType : byte { /// <summary>
    /// 表示Probe选项。
    /// </summary>
    Probe = 1, /// <summary>
    /// 表示Acknowledgement选项。
    /// </summary>
    Acknowledgement = 2 }

    /// <summary>
/// 表示 Attempt，并提供相关数据或行为。
/// </summary>
private sealed class Attempt
    {
        private int _started;
        /// <summary>
        /// 初始化 <see cref="Attempt"/> 类的新实例。
        /// </summary>
        /// <param name="candidate">candidate参数。</param>
        public Attempt(P2PPunchCandidate candidate)
        {
            Candidate = candidate;
            StartTimestamp = Stopwatch.GetTimestamp();
        }
        /// <summary>
        /// 获取或设置Candidate。
        /// </summary>
        /// <returns>Candidate。</returns>
        public P2PPunchCandidate Candidate { get; }
        /// <summary>
        /// 获取或设置Start Timestamp。
        /// </summary>
        /// <returns>Start Timestamp。</returns>
        public long StartTimestamp { get; }
        /// <summary>
        /// 获取或设置Completion。
        /// </summary>
        /// <returns>Completion。</returns>
        public TaskCompletionSource<P2PPunchResult?> Completion { get; } =
            new(TaskCreationOptions.RunContinuationsAsynchronously);
        /// <summary>
        /// 尝试Start。
        /// </summary>
        /// <returns>操作是否成功。</returns>
        public bool TryStart() => Interlocked.Exchange(ref _started, 1) == 0;
    }
}
