namespace Qcxt.Net.Quic.Recovery;

/// <summary>
/// 表示 Congestion Controller，并提供相关数据或行为。
/// </summary>
internal sealed class CongestionController
{
    private const long MinimumWindow = 2400;
    private static readonly long MaximumAckDelayTicks = Stopwatch.Frequency / 100;
    private static readonly long MinimumProbeTimeoutTicks = Stopwatch.Frequency / 20;
    private static readonly long RecoveryTimerResolutionTicks = Stopwatch.Frequency / 100;
    private readonly int _maxDatagramSize;
    private long _congestionWindow;
    private long _slowStartThreshold = long.MaxValue;
    private long _bytesInFlight;
    private long _recoveryStarted;
    private long _smoothedRttTicks;
    private long _rttVarianceTicks;
    private long _minimumRttTicks = long.MaxValue;
    private long _latestRttTicks;
    private int _ptoCount;

    /// <summary>
    /// 初始化 <see cref="CongestionController"/> 类的新实例。
    /// </summary>
    /// <param name="maxDatagramSize">max Datagram Size参数。</param>
    public CongestionController(int maxDatagramSize)
    {
        _maxDatagramSize = maxDatagramSize;
        _congestionWindow = Math.Min(10L * maxDatagramSize,
            Math.Max(2L * maxDatagramSize, 14_720L));
    }

    /// <summary>
    /// 获取或设置Congestion Window。
    /// </summary>
    /// <returns>Congestion Window。</returns>
    public long CongestionWindow => _congestionWindow;
    /// <summary>
    /// 获取或设置Bytes In Flight。
    /// </summary>
    /// <returns>Bytes In Flight。</returns>
    public long BytesInFlight => _bytesInFlight;
    /// <summary>
    /// 执行Can Send操作。
    /// </summary>
    /// <param name="bytes">bytes参数。</param>
    /// <returns>操作结果。</returns>
    public bool CanSend(int bytes) => bytes <= _congestionWindow - _bytesInFlight;

    /// <summary>允许少量控制或交互包临时借用窗口，同时限制异常高优先级洪泛。</summary>
    /// <param name="bytes">准备发送的加密 UDP 包字节数。</param>
    /// <returns>发送后不超过拥塞窗口外四个最大 DATAGRAM 时返回 true。</returns>
    public bool CanSendPriority(int bytes) =>
        bytes <= _congestionWindow + 4L * _maxDatagramSize - _bytesInFlight;
    /// <summary>
    /// 获取或设置Probe Timeout Ticks。
    /// </summary>
    /// <returns>Probe Timeout Ticks。</returns>
    public long ProbeTimeoutTicks
    {
        get
        {
            long baseTicks = _smoothedRttTicks == 0 ? Stopwatch.Frequency / 3 :
                _smoothedRttTicks + Math.Max(4 * _rttVarianceTicks, Stopwatch.Frequency / 1000) +
                MaximumAckDelayTicks;
            baseTicks = Math.Max(baseTicks, MinimumProbeTimeoutTicks);
            long multiplier = 1L << Math.Min(_ptoCount, 6);
            return Math.Min(baseTicks * multiplier, 10L * Stopwatch.Frequency);
        }
    }

    /// <summary>
    /// 获取或设置Loss Delay Ticks。
    /// </summary>
    /// <returns>Loss Delay Ticks。</returns>
    public long LossDelayTicks
    {
        get
        {
            long basis = Math.Max(_latestRttTicks, _smoothedRttTicks);
            if (basis == 0) basis = Stopwatch.Frequency / 3;
            return Math.Max(RecoveryTimerResolutionTicks, basis + basis / 8);
        }
    }

    /// <summary>
    /// 执行On Packet Sent操作。
    /// </summary>
    /// <param name="bytes">bytes参数。</param>
    /// <param name="inFlight">in Flight参数。</param>
    public void OnPacketSent(int bytes, bool inFlight)
    {
        if (inFlight) _bytesInFlight += bytes;
    }

    /// <summary>
    /// 执行On Packet Acknowledged操作。
    /// </summary>
    /// <param name="bytes">bytes参数。</param>
    /// <param name="sentAt">sent At参数。</param>
    /// <param name="acknowledgedAt">acknowledged At参数。</param>
    /// <param name="ackDelayTicks">ack Delay Ticks参数。</param>
    /// <param name="updateRtt">update Rtt参数。</param>
    public void OnPacketAcknowledged(int bytes, long sentAt, long acknowledgedAt, long ackDelayTicks, bool updateRtt)
    {
        _bytesInFlight = Math.Max(0, _bytesInFlight - bytes);
        if (updateRtt) UpdateRtt(acknowledgedAt - sentAt, ackDelayTicks);
        _ptoCount = 0;
        if (sentAt <= _recoveryStarted) return;
        if (_congestionWindow < _slowStartThreshold) _congestionWindow += bytes;
        else _congestionWindow += Math.Max(1, _maxDatagramSize * bytes / _congestionWindow);
    }

    /// <summary>
    /// 执行On Packets Lost操作。
    /// </summary>
    /// <param name="bytes">bytes参数。</param>
    /// <param name="newestLostSentAt">newest Lost Sent At参数。</param>
    public void OnPacketsLost(int bytes, long newestLostSentAt)
    {
        _bytesInFlight = Math.Max(0, _bytesInFlight - bytes);
        if (newestLostSentAt <= _recoveryStarted) return;
        _recoveryStarted = Stopwatch.GetTimestamp();
        _congestionWindow = Math.Max(MinimumWindow, _congestionWindow / 2);
        _slowStartThreshold = _congestionWindow;
    }

    /// <summary>
    /// 执行On Probe Timeout操作。
    /// </summary>
    public void OnProbeTimeout() => _ptoCount++;

    /// <summary>
    /// 执行Update Rtt操作。
    /// </summary>
    /// <param name="latest">latest参数。</param>
    /// <param name="ackDelay">ack Delay参数。</param>
    private void UpdateRtt(long latest, long ackDelay)
    {
        if (latest <= 0) return;
        _latestRttTicks = latest;
        _minimumRttTicks = Math.Min(_minimumRttTicks, latest);
        long adjusted = latest;
        if (latest - _minimumRttTicks > ackDelay) adjusted -= ackDelay;
        if (_smoothedRttTicks == 0)
        {
            _smoothedRttTicks = adjusted; _rttVarianceTicks = adjusted / 2; return;
        }
        long difference = Math.Abs(_smoothedRttTicks - adjusted);
        _rttVarianceTicks = (3 * _rttVarianceTicks + difference) / 4;
        _smoothedRttTicks = (7 * _smoothedRttTicks + adjusted) / 8;
    }
}
