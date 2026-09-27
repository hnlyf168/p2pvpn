using Qcxt.Net.Quic.Memory;

namespace Qcxt.Net.Quic;

/// <summary>拥有一个由 <see cref="QuicSharedUdpEndpoint"/> 接收的非 QUIC UDP 数据报。</summary>
public sealed class QuicUdpDatagram : IDisposable
{
    private PooledDatagram? _owner;

    /// <summary>
    /// 初始化 <see cref="QuicUdpDatagram"/> 类的新实例。
    /// </summary>
    /// <param name="owner">owner参数。</param>
    internal QuicUdpDatagram(PooledDatagram owner) => _owner = owner;

    /// <summary>在所有者尚未释放时获取接收载荷。</summary>
    public ReadOnlyMemory<byte> Memory => (_owner ?? throw new ObjectDisposedException(nameof(QuicUdpDatagram))).Memory;

    /// <summary>获取共享接收循环记录的 UDP 来源端点。</summary>
    public IPEndPoint RemoteEndPoint => (_owner ?? throw new ObjectDisposedException(nameof(QuicUdpDatagram))).RemoteEndPoint
        as IPEndPoint ?? throw new InvalidDataException("The UDP source endpoint is not an IP endpoint.");

    /// <summary>将接收缓冲区归还共享池。</summary>
    public void Dispose() => Interlocked.Exchange(ref _owner, null)?.Dispose();
}
