using Qcxt.Net.Quic.Protocol;
using Qcxt.Net.Quic.Security;

namespace Qcxt.Net.Quic.Configuration;

/// <summary>提供 QUIC 端点通用的有界资源和超时设置。</summary>
public abstract class QuicEndpointOptions
{
    /// <summary>获取每条连接允许排队的最大出站操作数量。</summary>
    public int ConnectionQueueCapacity { get; init; } = 1024;
    /// <summary>获取等待连接级解码的最大已接收 UDP 数据包数量。</summary>
    public int PacketReceiveQueueCapacity { get; init; } = 4096;
    /// <summary>获取等待应用接受的最大对端创建流数量。</summary>
    public int StreamAcceptQueueCapacity { get; init; } = 256;
    /// <summary>获取等待应用读取的最大已接收不可靠数据报数量。</summary>
    public int DatagramQueueCapacity { get; init; } = 1024;
    /// <summary>获取端点可发送或接受的最大 UDP 载荷长度。</summary>
    public int MaxUdpPayloadSize { get; init; } = 1200;
    /// <summary>获取任一端点可发起的最大双向流数量。</summary>
    public int MaxBidirectionalStreams { get; init; } = 256;
    /// <summary>获取任一端点可发起的最大单向流数量。</summary>
    public int MaxUnidirectionalStreams { get; init; } = 64;
    /// <summary>获取以字节为单位的初始连接总接收窗口。</summary>
    public long InitialConnectionWindow { get; init; } = 16L * 1024 * 1024;
    /// <summary>获取每条流以字节为单位的初始接收窗口。</summary>
    public long InitialStreamWindow { get; init; } = 2L * 1024 * 1024;
    /// <summary>获取允许建立连接的最长时间。</summary>
    public TimeSpan HandshakeTimeout { get; init; } = TimeSpan.FromSeconds(10);
    /// <summary>获取连接因无活动而自行关闭前的空闲时间。</summary>
    public TimeSpan IdleTimeout { get; init; } = TimeSpan.FromMinutes(2);
    /// <summary>获取单次发送无传输进展时允许等待的最长时间，超时后中止连接。</summary>
    public TimeSpan SendStallTimeout { get; init; } = TimeSpan.FromSeconds(30);
    /// <summary>获取自动发送可触发确认的保活数据包间隔。</summary>
    public TimeSpan KeepAliveInterval { get; init; } = TimeSpan.FromSeconds(20);
    /// <summary>获取释放期间允许后台操作停止的最长时间。</summary>
    public TimeSpan ShutdownTimeout { get; init; } = TimeSpan.FromSeconds(5);
    /// <summary>获取共享套接字路由器使用的连接标识符长度。</summary>
    public int ConnectionIdLength { get; init; } = 12;
    /// <summary>获取外部认证密钥和握手提供程序。</summary>
    public required IQuicKeyProvider KeyProvider { get; init; }

    /// <summary>
    /// 执行Validate操作。
    /// </summary>
    internal virtual void Validate()
    {
        if (ConnectionQueueCapacity is < 16 or > 1_048_576) throw new ArgumentOutOfRangeException(nameof(ConnectionQueueCapacity));
        if (PacketReceiveQueueCapacity is < 16 or > 1_048_576) throw new ArgumentOutOfRangeException(nameof(PacketReceiveQueueCapacity));
        if (StreamAcceptQueueCapacity is < 1 or > 65_536) throw new ArgumentOutOfRangeException(nameof(StreamAcceptQueueCapacity));
        if (DatagramQueueCapacity is < 1 or > 1_048_576) throw new ArgumentOutOfRangeException(nameof(DatagramQueueCapacity));
        if (MaxUdpPayloadSize is < 1200 or > 65_527) throw new ArgumentOutOfRangeException(nameof(MaxUdpPayloadSize));
        if (MaxBidirectionalStreams is < 0 or > 1_000_000) throw new ArgumentOutOfRangeException(nameof(MaxBidirectionalStreams));
        if (MaxUnidirectionalStreams is < 0 or > 1_000_000) throw new ArgumentOutOfRangeException(nameof(MaxUnidirectionalStreams));
        if (InitialConnectionWindow < 64 * 1024) throw new ArgumentOutOfRangeException(nameof(InitialConnectionWindow));
        if (InitialStreamWindow < 16 * 1024) throw new ArgumentOutOfRangeException(nameof(InitialStreamWindow));
        if (ConnectionIdLength is < 8 or > QuicConnectionId.MaxLength) throw new ArgumentOutOfRangeException(nameof(ConnectionIdLength));
        if (HandshakeTimeout <= TimeSpan.Zero) throw new ArgumentOutOfRangeException(nameof(HandshakeTimeout));
        if (IdleTimeout <= TimeSpan.Zero) throw new ArgumentOutOfRangeException(nameof(IdleTimeout));
        if (SendStallTimeout <= TimeSpan.Zero) throw new ArgumentOutOfRangeException(nameof(SendStallTimeout));
        if (KeepAliveInterval <= TimeSpan.Zero || KeepAliveInterval >= IdleTimeout)
            throw new ArgumentOutOfRangeException(nameof(KeepAliveInterval), "Keep-alive must be positive and shorter than the idle timeout.");
        if (ShutdownTimeout <= TimeSpan.Zero) throw new ArgumentOutOfRangeException(nameof(ShutdownTimeout));
        ArgumentNullException.ThrowIfNull(KeyProvider);
    }
}

/// <summary>配置使用共享套接字的 QUIC 服务端。</summary>
public sealed class QuicServerOptions : QuicEndpointOptions
{
    /// <summary>获取服务端监听的本地 UDP 端点。</summary>
    public required IPEndPoint ListenEndPoint { get; init; }
    /// <summary>获取最大活动连接数量。</summary>
    public int MaxConnections { get; init; } = 100_000;
    /// <summary>获取可并发处理的最大未认证握手数量。</summary>
    public int MaxPendingHandshakes { get; init; } = 4096;
    /// <summary>获取请求设置的操作系统接收缓冲区大小。</summary>
    public int SocketReceiveBufferSize { get; init; } = 16 * 1024 * 1024;
    /// <summary>获取请求设置的操作系统发送缓冲区大小。</summary>
    public int SocketSendBufferSize { get; init; } = 16 * 1024 * 1024;

    /// <summary>
    /// 执行Validate操作。
    /// </summary>
    internal override void Validate()
    {
        base.Validate();
        if (MaxConnections is < 1 or > 10_000_000) throw new ArgumentOutOfRangeException(nameof(MaxConnections));
        if (MaxPendingHandshakes < 1 || MaxPendingHandshakes > MaxConnections) throw new ArgumentOutOfRangeException(nameof(MaxPendingHandshakes));
        if (SocketReceiveBufferSize < 64 * 1024) throw new ArgumentOutOfRangeException(nameof(SocketReceiveBufferSize));
        if (SocketSendBufferSize < 64 * 1024) throw new ArgumentOutOfRangeException(nameof(SocketSendBufferSize));
        ArgumentNullException.ThrowIfNull(ListenEndPoint);
    }
}

/// <summary>配置一条出站 QUIC 连接。</summary>
public sealed class QuicClientOptions : QuicEndpointOptions
{
    /// <summary>获取远程 UDP 端点。</summary>
    public required IPEndPoint RemoteEndPoint { get; init; }
    /// <summary>获取可选本地端点；未提供时使用通配地址和临时端口。</summary>
    public IPEndPoint? LocalEndPoint { get; init; }
    /// <summary>获取传递给密钥提供程序进行认证的逻辑服务端名称。</summary>
    public required string ServerName { get; init; }

    /// <summary>
    /// 执行Validate操作。
    /// </summary>
    internal override void Validate()
    {
        base.Validate();
        ArgumentNullException.ThrowIfNull(RemoteEndPoint);
        if (string.IsNullOrWhiteSpace(ServerName)) throw new ArgumentException("A server name is required.", nameof(ServerName));
        if (LocalEndPoint is not null && LocalEndPoint.AddressFamily != RemoteEndPoint.AddressFamily)
            throw new ArgumentException("Local and remote endpoints must use the same address family.", nameof(LocalEndPoint));
    }
}
