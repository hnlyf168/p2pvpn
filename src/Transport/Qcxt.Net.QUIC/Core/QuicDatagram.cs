using Qcxt.Net.Quic.Memory;

namespace Qcxt.Net.Quic;

/// <summary>拥有一个由共享数组池支持的不可靠应用数据报。</summary>
public sealed class QuicDatagram : IMemoryOwner<byte>
{
    private PooledSegment? _segment;

    /// <summary>
    /// 初始化 <see cref="QuicDatagram"/> 类的新实例。
    /// </summary>
    /// <param name="segment">segment参数。</param>
    internal QuicDatagram(PooledSegment segment) => _segment = segment;

    /// <summary>获取已接收的数据报字节；该内存在释放前有效。</summary>
    public Memory<byte> Memory => (_segment ?? throw new ObjectDisposedException(nameof(QuicDatagram))).Memory;

    /// <summary>将后备数组归还共享池。</summary>
    public void Dispose() => Interlocked.Exchange(ref _segment, null)?.Dispose();
}
