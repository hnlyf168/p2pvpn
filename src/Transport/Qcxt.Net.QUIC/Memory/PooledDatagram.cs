namespace Qcxt.Net.Quic.Memory;

/// <summary>
/// 表示 Pooled Datagram，并提供相关数据或行为。
/// </summary>
internal sealed class PooledDatagram : IDisposable
{
    private const int MaxRetainedObjects = 4096;
    private static readonly ConcurrentBag<PooledDatagram> Objects = new();
    private static int _retainedObjects;
    private byte[]? _buffer;
    private int _disposed;

    /// <summary>
    /// 初始化 <see cref="PooledDatagram"/> 类的新实例。
    /// </summary>
    private PooledDatagram() { }
    /// <summary>
    /// 获取或设置Length。
    /// </summary>
    /// <returns>Length。</returns>
    public int Length { get; set; }
    /// <summary>
    /// 获取或设置Remote End Point。
    /// </summary>
    /// <returns>Remote End Point。</returns>
    public EndPoint? RemoteEndPoint { get; set; }
    /// <summary>
    /// 获取或设置Writable Memory。
    /// </summary>
    /// <returns>Writable Memory。</returns>
    public Memory<byte> WritableMemory => _buffer ?? throw new ObjectDisposedException(nameof(PooledDatagram));
    /// <summary>
    /// 获取或设置Memory。
    /// </summary>
    /// <returns>Memory。</returns>
    public ReadOnlyMemory<byte> Memory => WritableMemory[..Length];

    /// <summary>
    /// 执行Rent操作。
    /// </summary>
    /// <param name="minimumLength">minimum Length参数。</param>
    /// <returns>操作结果。</returns>
    public static PooledDatagram Rent(int minimumLength)
    {
        if (!Objects.TryTake(out var item)) item = new PooledDatagram();
        else Interlocked.Decrement(ref _retainedObjects);
        item._buffer = ArrayPool<byte>.Shared.Rent(minimumLength);
        item._disposed = 0; item.Length = 0; item.RemoteEndPoint = null;
        return item;
    }

    /// <summary>
    /// 执行Dispose操作。
    /// </summary>
    public void Dispose()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0) return;
        var buffer = Interlocked.Exchange(ref _buffer, null);
        if (buffer is not null) ArrayPool<byte>.Shared.Return(buffer);
        Length = 0; RemoteEndPoint = null;
        if (Interlocked.Increment(ref _retainedObjects) <= MaxRetainedObjects) Objects.Add(this);
        else Interlocked.Decrement(ref _retainedObjects);
    }
}
