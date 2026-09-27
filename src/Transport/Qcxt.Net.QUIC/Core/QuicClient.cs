using Qcxt.Net.Quic.Configuration;
using Qcxt.Net.Quic.Protocol;

namespace Qcxt.Net.Quic;

/// <summary>创建出站 QUIC 传输连接。</summary>
public static class QuicClient
{
    /// <summary>连接远程 QUIC 服务端。</summary>
    /// <param name="options">客户端传输限制、端点和密钥提供程序选项。</param>
    /// <param name="cancellationToken">用于取消连接建立的标记。</param>
    /// <returns>已认证且已连接的传输连接。</returns>
    public static async ValueTask<QuicConnection> ConnectAsync(QuicClientOptions options,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(options); options.Validate();
        var socket = new Socket(options.RemoteEndPoint.AddressFamily, SocketType.Dgram, ProtocolType.Udp);
        try
        {
            socket.Bind(options.LocalEndPoint ?? new IPEndPoint(
                options.RemoteEndPoint.AddressFamily == AddressFamily.InterNetwork ? IPAddress.Any : IPAddress.IPv6Any, 0));
            socket.Connect(options.RemoteEndPoint);
            var localCid = QuicConnectionId.CreateRandom(options.ConnectionIdLength);
            var initialDestinationCid = QuicConnectionId.CreateRandom(options.ConnectionIdLength);
            return await QuicConnection.CreateClientAsync(options, socket, localCid, initialDestinationCid,
                cancellationToken).ConfigureAwait(false);
        }
        catch { socket.Dispose(); throw; }
    }
}
