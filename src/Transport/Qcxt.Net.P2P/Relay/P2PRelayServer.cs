using Qcxt.Net.P2P.Signaling;

namespace Qcxt.Net.P2P.Relay;

/// <summary>为包含中转服务的已认证 QUIC 协调服务器提供兼容外观。</summary>
public sealed class P2PRelayServer : IAsyncDisposable
{
    private readonly P2PSignalingServer _server;

    /// <summary>在一个 UDP 端点上创建已认证的中转和信令服务器。</summary>
    /// <param name="options">服务器端点、密钥及资源限制。</param>
    public P2PRelayServer(P2PServerOptions options) => _server = new P2PSignalingServer(options);

    /// <summary>开始接受已认证的客户端。</summary>
    /// <param name="cancellationToken">控制服务器生命周期的取消标记。</param>
    /// <returns>套接字绑定完成后结束的异步操作。</returns>
    public Task StartAsync(CancellationToken cancellationToken = default) => _server.StartAsync(cancellationToken);

    /// <summary>停止中转和信令任务。</summary>
    /// <returns>有界关闭完成后结束的异步操作。</returns>
    public ValueTask DisposeAsync() => _server.DisposeAsync();
}
