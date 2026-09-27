using Qcxt.Net.P2P.Links;

namespace Qcxt.Net.P2P.Quic;

/// <summary>从已认证的 QUIC 连接创建可靠流或低延迟 DATAGRAM 链路。</summary>
public static class QuicP2PConnector
{
    /// <summary>使用专用 UDP 套接字连接并打开可靠 P2P 流。</summary>
    /// <param name="remoteEndPoint">远程 QUIC 端点。</param>
    /// <param name="keyProvider">已认证的握手及密钥提供程序。</param>
    /// <param name="serverName">经过认证的逻辑服务器名称。</param>
    /// <param name="maximumPacketSize">P2P 流允许的最大帧长度。</param>
    /// <param name="cancellationToken">用于取消握手的标记。</param>
    /// <returns>具有所有权的可靠 QUIC 链路。</returns>
    public static async Task<QuicP2PLink> ConnectAsync(IPEndPoint remoteEndPoint,
        IQuicKeyProvider keyProvider, string serverName = "p2p-peer", int maximumPacketSize = 128 * 1024,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(remoteEndPoint);
        ArgumentNullException.ThrowIfNull(keyProvider);
        QuicConnection connection = await QuicClient.ConnectAsync(new QuicClientOptions
        {
            RemoteEndPoint = remoteEndPoint,
            ServerName = serverName,
            KeyProvider = keyProvider
        }, cancellationToken).ConfigureAwait(false);
        try { return CreateReliable(connection, maximumPacketSize); }
        catch { await connection.DisposeAsync().ConfigureAwait(false); throw; }
    }

    /// <summary>通过已打洞的共享 UDP 端点连接，且不改变其 NAT 映射。</summary>
    /// <param name="endpoint">已绑定的共享 UDP 端点。</param>
    /// <param name="remoteEndPoint">通过打洞获知的已认证对端端点。</param>
    /// <param name="keyProvider">对端配对专用的密钥提供程序。</param>
    /// <param name="serverName">经过认证的逻辑对端名称。</param>
    /// <param name="maximumPacketSize">可靠流允许的最大数据包长度。</param>
    /// <param name="cancellationToken">用于取消握手的标记。</param>
    /// <returns>具有所有权的可靠 QUIC 直连链路。</returns>
    public static async Task<QuicP2PLink> ConnectSharedAsync(QuicSharedUdpEndpoint endpoint,
        IPEndPoint remoteEndPoint, IQuicKeyProvider keyProvider, string serverName,
        int maximumPacketSize = 128 * 1024, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(endpoint);
        QuicConnection connection = await endpoint.ConnectAsync(new QuicClientOptions
        {
            RemoteEndPoint = remoteEndPoint,
            ServerName = serverName,
            KeyProvider = keyProvider,
            MaxUdpPayloadSize = 1200,
            DatagramQueueCapacity = 4096,
            PacketReceiveQueueCapacity = 4096
        }, cancellationToken).ConfigureAwait(false);
        try { return CreateReliable(connection, maximumPacketSize); }
        catch { await connection.DisposeAsync().ConfigureAwait(false); throw; }
    }

    /// <summary>接受入站直连连接上的第一条双向流。</summary>
    /// <param name="connection">已认证的入站 QUIC 连接。</param>
    /// <param name="maximumPacketSize">可靠流允许的最大数据包长度。</param>
    /// <param name="cancellationToken">用于取消接受流的标记。</param>
    /// <returns>具有所有权的可靠链路。</returns>
    public static async Task<QuicP2PLink> AcceptAsync(QuicConnection connection,
        int maximumPacketSize = 128 * 1024, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(connection);
        try
        {
            QuicStream stream = await connection.AcceptStreamAsync(cancellationToken).ConfigureAwait(false);
            return new QuicP2PLink(connection, stream, maximumPacketSize);
        }
        catch { await connection.DisposeAsync().ConfigureAwait(false); throw; }
    }

    /// <summary>在出站连接上打开可靠的双向 P2P 流。</summary>
    /// <param name="connection">已认证的出站连接。</param>
    /// <param name="maximumPacketSize">允许的最大 P2P 帧长度。</param>
    /// <returns>具有所有权的可靠链路。</returns>
    private static QuicP2PLink CreateReliable(QuicConnection connection, int maximumPacketSize) =>
        new(connection, connection.OpenBidirectionalStream(), maximumPacketSize);
}
