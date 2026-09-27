namespace Qcxt.Net.Quic.Recovery;

/// <summary>
/// 表示 Send Flow Controller，并提供相关数据或行为。
/// </summary>
internal sealed class SendFlowController
{
    private readonly object _gate = new();
    private readonly Dictionary<ulong, ulong> _streamUsed = new();
    private readonly Dictionary<ulong, ulong> _streamLimits = new();
    private ulong _connectionLimit;
    private ulong _streamLimit;
    private ulong _connectionUsed;
    private TaskCompletionSource _changed = NewSignal();

    /// <summary>
    /// 初始化 <see cref="SendFlowController"/> 类的新实例。
    /// </summary>
    /// <param name="connectionLimit">connection Limit参数。</param>
    /// <param name="streamLimit">stream Limit参数。</param>
    public SendFlowController(ulong connectionLimit, ulong streamLimit)
    {
        _connectionLimit = connectionLimit;
        _streamLimit = streamLimit;
    }

    /// <summary>
    /// 执行Reserve操作。
    /// </summary>
    /// <param name="streamId">stream Id参数。</param>
    /// <param name="count">数据数量。</param>
    /// <param name="cancellationToken">用于取消异步操作的令牌。</param>
    /// <returns>操作结果。</returns>
    public async ValueTask ReserveAsync(ulong streamId, int count, CancellationToken cancellationToken)
    {
        if (count <= 0) return;
        ulong amount = (ulong)count;
        while (true)
        {
            Task wait;
            lock (_gate)
            {
                _streamUsed.TryGetValue(streamId, out ulong streamUsed);
                ulong streamLimit = _streamLimits.GetValueOrDefault(streamId, _streamLimit);
                if (amount <= _connectionLimit - Math.Min(_connectionUsed, _connectionLimit) &&
                    amount <= streamLimit - Math.Min(streamUsed, streamLimit))
                {
                    _connectionUsed += amount;
                    _streamUsed[streamId] = streamUsed + amount;
                    return;
                }
                wait = _changed.Task;
            }
            await wait.WaitAsync(cancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// 执行Update Connection Limit操作。
    /// </summary>
    /// <param name="value">待处理的值。</param>
    public void UpdateConnectionLimit(ulong value)
    {
        lock (_gate)
        {
            if (value <= _connectionLimit) return;
            _connectionLimit = value;
            Pulse();
        }
    }

    /// <summary>
    /// 执行Update Stream Limit操作。
    /// </summary>
    /// <param name="streamId">stream Id参数。</param>
    /// <param name="value">待处理的值。</param>
    public void UpdateStreamLimit(ulong streamId, ulong value)
    {
        lock (_gate)
        {
            ulong current = _streamLimits.GetValueOrDefault(streamId, _streamLimit);
            if (value <= current) return;
            _streamLimits[streamId] = value;
            Pulse();
        }
    }

    /// <summary>
    /// 执行Update Default Stream Limit操作。
    /// </summary>
    /// <param name="value">待处理的值。</param>
    public void UpdateDefaultStreamLimit(ulong value)
    {
        lock (_gate)
        {
            if (value <= _streamLimit) return;
            _streamLimit = value;
            Pulse();
        }
    }

    /// <summary>
    /// 执行Pulse操作。
    /// </summary>
    private void Pulse()
    {
        TaskCompletionSource previous = _changed;
        _changed = NewSignal();
        previous.TrySetResult();
    }

    /// <summary>
    /// 执行New Signal操作。
    /// </summary>
    /// <returns>操作结果。</returns>
    private static TaskCompletionSource NewSignal() =>
        new(TaskCreationOptions.RunContinuationsAsynchronously);
}
