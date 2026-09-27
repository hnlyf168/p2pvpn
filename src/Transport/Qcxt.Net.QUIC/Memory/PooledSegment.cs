namespace Qcxt.Net.Quic.Memory;

/// <summary>
/// 表示 Pooled Segment，并提供相关数据或行为。
/// </summary>
internal sealed class PooledSegment : IDisposable
{
    private byte[]? _buffer;
    /// <summary>
    /// 初始化 <see cref="PooledSegment"/> 类的新实例。
    /// </summary>
    /// <param name="buffer">用于暂存数据的缓冲区。</param>
    /// <param name="length">数据数量。</param>
    private PooledSegment(byte[] buffer, int length) { _buffer = buffer; Length = length; }
    /// <summary>
    /// 获取或设置Length。
    /// </summary>
    /// <returns>Length。</returns>
    public int Length { get; private set; }
    /// <summary>
    /// 获取或设置Memory。
    /// </summary>
    /// <returns>Memory。</returns>
    public Memory<byte> Memory => (_buffer ?? throw new ObjectDisposedException(nameof(PooledSegment))).AsMemory(0, Length);
    /// <summary>
    /// 执行Copy From操作。
    /// </summary>
    /// <param name="source">source参数。</param>
    /// <returns>操作结果。</returns>
    public static PooledSegment CopyFrom(ReadOnlySpan<byte> source)
    {
        byte[] buffer = ArrayPool<byte>.Shared.Rent(Math.Max(1, source.Length));
        source.CopyTo(buffer); return new(buffer, source.Length);
    }
    /// <summary>
    /// 执行Dispose操作。
    /// </summary>
    public void Dispose()
    {
        var buffer = Interlocked.Exchange(ref _buffer, null);
        if (buffer is not null) ArrayPool<byte>.Shared.Return(buffer);
        Length = 0;
    }
}
