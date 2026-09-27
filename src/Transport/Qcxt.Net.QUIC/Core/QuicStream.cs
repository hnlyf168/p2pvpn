using Qcxt.Net.Quic.Memory;

namespace Qcxt.Net.Quic;

/// <summary>表示一条可靠且有序的 QUIC 字节流。</summary>
public sealed class QuicStream : IAsyncDisposable
{
    private readonly Channel<PooledSegment> _received;
    private readonly Func<QuicStream, ReadOnlyMemory<byte>, bool, CancellationToken, ValueTask> _sender;
    private readonly Action<QuicStream, int> _onBytesConsumed;
    private readonly SemaphoreSlim _writeLock = new(1, 1);
    private PooledSegment? _currentRead;
    private int _currentReadOffset;
    private long _writeOffset;
    private ulong _nextReceiveOffset;
    private long _receiveLimit;
    private long _advertisedReceiveLimit;
    private readonly long _receiveWindow;
    private ulong? _finalReceiveOffset;
    private readonly SortedDictionary<ulong, (PooledSegment Segment, bool Fin)> _outOfOrder = new();
    private int _writeCompleted;
    private int _readCompleted;
    private int _disposed;

    /// <summary>
    /// 初始化 <see cref="QuicStream"/> 类的新实例。
    /// </summary>
    /// <param name="id">唯一标识。</param>
    /// <param name="canRead">can Read参数。</param>
    /// <param name="canWrite">can Write参数。</param>
    /// <param name="queueCapacity">queue Capacity参数。</param>
    /// <param name="receiveLimit">receive Limit参数。</param>
    /// <param name="sender">sender参数。</param>
    /// <param name="onBytesConsumed">on Bytes Consumed参数。</param>
    internal QuicStream(ulong id, bool canRead, bool canWrite, int queueCapacity, ulong receiveLimit,
        Func<QuicStream, ReadOnlyMemory<byte>, bool, CancellationToken, ValueTask> sender,
        Action<QuicStream, int> onBytesConsumed)
    {
        Id = id; CanRead = canRead; CanWrite = canWrite; _sender = sender;
        _receiveLimit = checked((long)receiveLimit); _onBytesConsumed = onBytesConsumed;
        _advertisedReceiveLimit = _receiveWindow = _receiveLimit;
        _received = Channel.CreateBounded<PooledSegment>(new BoundedChannelOptions(queueCapacity)
        { SingleReader = true, SingleWriter = true, FullMode = BoundedChannelFullMode.Wait });
    }

    /// <summary>获取 QUIC 流标识符。</summary>
    public ulong Id { get; }
    /// <summary>获取本地端点是否可以读取此流。</summary>
    public bool CanRead { get; }
    /// <summary>获取本地端点是否可以写入此流。</summary>
    public bool CanWrite { get; }
    /// <summary>
    /// 获取或设置Write Offset。
    /// </summary>
    /// <returns>Write Offset。</returns>
    internal long WriteOffset => Interlocked.Read(ref _writeOffset);

    /// <summary>从流中读取有序字节。</summary>
    /// <param name="buffer">目标缓冲区。</param>
    /// <param name="cancellationToken">用于取消等待的标记。</param>
    /// <returns>读取的字节数；对端发送 FIN 后返回零。</returns>
    public async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();
        if (!CanRead) throw new InvalidOperationException("The stream is write-only.");
        if (buffer.IsEmpty) return 0;
        while (true)
        {
            if (_currentRead is not null)
            {
                int count = Math.Min(buffer.Length, _currentRead.Length - _currentReadOffset);
                _currentRead.Memory.Span.Slice(_currentReadOffset, count).CopyTo(buffer.Span);
                _currentReadOffset += count;
                if (_currentReadOffset == _currentRead.Length)
                { _currentRead.Dispose(); _currentRead = null; _currentReadOffset = 0; }
                _onBytesConsumed(this, count);
                return count;
            }
            if (_received.Reader.TryRead(out _currentRead)) continue;
            if (Volatile.Read(ref _readCompleted) != 0) return 0;
            if (!await _received.Reader.WaitToReadAsync(cancellationToken).ConfigureAwait(false)) return 0;
        }
    }

    /// <summary>在有界传输背压控制下向流写入字节。</summary>
    /// <param name="buffer">来源字节；本方法返回前会将其复制到池化传输内存。</param>
    /// <param name="cancellationToken">用于取消排队的标记。</param>
    /// <returns>全部字节进入连接发送队列后结束的操作。</returns>
    public async ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();
        if (!CanWrite) throw new InvalidOperationException("The stream is read-only.");
        if (Volatile.Read(ref _writeCompleted) != 0) throw new InvalidOperationException("Writes are completed.");
        await _writeLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try { await _sender(this, buffer, false, cancellationToken).ConfigureAwait(false); Interlocked.Add(ref _writeOffset, buffer.Length); }
        finally { _writeLock.Release(); }
    }

    /// <summary>在此前排队的全部流数据之后发送 FIN。</summary>
    /// <param name="cancellationToken">用于取消排队的标记。</param>
    /// <returns>表示 FIN 排队过程的操作。</returns>
    public async ValueTask CompleteWritesAsync(CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();
        if (!CanWrite) throw new InvalidOperationException("The stream is read-only.");
        if (Interlocked.Exchange(ref _writeCompleted, 1) != 0) return;
        await _sender(this, ReadOnlyMemory<byte>.Empty, true, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// 尝试Receive。
    /// </summary>
    /// <param name="offset">数据起始偏移量。</param>
    /// <param name="data">待处理的数据。</param>
    /// <param name="fin">fin参数。</param>
    /// <param name="newlyAccepted">newly Accepted参数。</param>
    /// <returns>操作是否成功。</returns>
    internal bool TryReceive(ulong offset, ReadOnlySpan<byte> data, bool fin, out int newlyAccepted)
    {
        newlyAccepted = 0;
        ulong end = offset + (ulong)data.Length;
        if (end < offset) return false;
        if (end > (ulong)Volatile.Read(ref _receiveLimit)) return false;
        if (fin)
        {
            if (_finalReceiveOffset is not null && _finalReceiveOffset != end) return false;
            _finalReceiveOffset = end;
        }
        if (end <= _nextReceiveOffset)
        {
            if (_finalReceiveOffset == _nextReceiveOffset) CompleteReceive();
            return true;
        }
        if (offset < _nextReceiveOffset)
        { data = data[(int)(_nextReceiveOffset - offset)..]; offset = _nextReceiveOffset; }
        end = offset + (ulong)data.Length;
        if (_outOfOrder.TryGetValue(offset, out var duplicate))
            return duplicate.Segment.Length == data.Length && (!fin || duplicate.Fin);
        foreach (var pair in _outOfOrder)
        {
            ulong bufferedEnd = pair.Key + (ulong)pair.Value.Segment.Length;
            if (bufferedEnd > offset && pair.Key < end) return false;
            if (pair.Key >= end) break;
        }
        if (_outOfOrder.Count >= 1024) return false;
        _outOfOrder[offset] = (PooledSegment.CopyFrom(data), fin);
        newlyAccepted = data.Length;
        while (_outOfOrder.Remove(_nextReceiveOffset, out var item))
        {
            _nextReceiveOffset += (ulong)item.Segment.Length;
            if (item.Segment.Length != 0 && !_received.Writer.TryWrite(item.Segment))
            { item.Segment.Dispose(); return false; }
            if (item.Segment.Length == 0) item.Segment.Dispose();
        }
        if (_finalReceiveOffset == _nextReceiveOffset)
            CompleteReceive();
        return true;
    }

    /// <summary>
    /// 执行Complete Receive操作。
    /// </summary>
    private void CompleteReceive()
    {
        Volatile.Write(ref _readCompleted, 1);
        _received.Writer.TryComplete();
    }

    /// <summary>
    /// 执行Extend Receive Limit操作。
    /// </summary>
    /// <param name="consumed">consumed参数。</param>
    /// <returns>操作结果。</returns>
    internal ulong ExtendReceiveLimit(int consumed)
    {
        if (consumed <= 0) return (ulong)Volatile.Read(ref _receiveLimit);
        return (ulong)Interlocked.Add(ref _receiveLimit, consumed);
    }

    internal bool ShouldAdvertiseReceiveLimit(ulong limit)
    {
        long previous = Volatile.Read(ref _advertisedReceiveLimit);
        while ((long)limit - previous >= Math.Max(1, _receiveWindow / 2))
        {
            long observed = Interlocked.CompareExchange(ref _advertisedReceiveLimit, (long)limit, previous);
            if (observed == previous) return true;
            previous = observed;
        }
        return false;
    }

    /// <summary>
    /// 执行Abort操作。
    /// </summary>
    internal void Abort()
    {
        Volatile.Write(ref _readCompleted, 1);
        Volatile.Write(ref _writeCompleted, 1);
        _received.Writer.TryComplete();
    }

    /// <summary>释放池化缓冲区并关闭本地流的两个方向。</summary>
    /// <returns>已经完成的操作。</returns>
    public ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0) return ValueTask.CompletedTask;
        _received.Writer.TryComplete(); _currentRead?.Dispose();
        while (_received.Reader.TryRead(out var item)) item.Dispose();
        foreach (var item in _outOfOrder.Values) item.Segment.Dispose(); _outOfOrder.Clear();
        _writeLock.Dispose(); return ValueTask.CompletedTask;
    }
    /// <summary>
    /// 执行Throw If Disposed操作。
    /// </summary>
    private void ThrowIfDisposed() { if (Volatile.Read(ref _disposed) != 0) throw new ObjectDisposedException(nameof(QuicStream)); }
}
