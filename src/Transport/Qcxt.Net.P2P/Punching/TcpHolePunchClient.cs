using Qcxt.Net.P2P.Links;

namespace Qcxt.Net.P2P.Punching;

/// <summary>为支持 TCP 同时打开的 NAT 提供有界后备打洞方案。</summary>
public sealed class TcpHolePunchClient
{
    /// <summary>并发尝试候选端点并释放所有未胜出的套接字。</summary>
    /// <param name="remoteCandidates">远程公网或局域网 TCP 候选端点。</param>
    /// <param name="localBindEndPoint">真实的本地接口和端口，不能使用映射后的公网地址。</param>
    /// <param name="timeoutMs">整体尝试超时毫秒数。</param>
    /// <param name="cancellationToken">用于取消尝试的标记。</param>
    /// <returns>首条通过验证的 TCP 路径；不存在时返回 <see langword="null"/>。</returns>
    public async Task<TcpP2PLink?> ConnectAsync(IEnumerable<IPEndPoint> remoteCandidates,
        IPEndPoint? localBindEndPoint = null, int timeoutMs = 5000,
        CancellationToken cancellationToken = default)
    {
        Socket? socket = await ConnectSocketAsync(remoteCandidates, localBindEndPoint, timeoutMs,
            cancellationToken).ConfigureAwait(false);
        return socket is null ? null : new TcpP2PLink(socket);
    }

    /// <summary>并发尝试所有 TCP 候选端点并返回首个已连接套接字。</summary>
    /// <param name="remoteCandidates">远程公网或局域网 TCP 候选端点。</param>
    /// <param name="localBindEndPoint">真实的本地接口和固定 TCP 端口。</param>
    /// <param name="timeoutMs">整体尝试超时毫秒数。</param>
    /// <param name="cancellationToken">用于取消尝试的标记。</param>
    /// <returns>首个已连接套接字；全部失败时返回 <see langword="null"/>。</returns>
    public async Task<Socket?> ConnectSocketAsync(IEnumerable<IPEndPoint> remoteCandidates,
        IPEndPoint? localBindEndPoint = null, int timeoutMs = 5000,
        CancellationToken cancellationToken = default) => await ConnectSocketCoreAsync(remoteCandidates,
            localBindEndPoint, timeoutMs, validator: null, cancellationToken).ConfigureAwait(false);

    /// <summary>并发连接全部候选，并且仅把通过调用方身份认证的套接字作为胜者。</summary>
    /// <param name="remoteCandidates">远程公网、猜测端口或局域网 TCP 候选端点。</param>
    /// <param name="localBindEndPoint">真实的本地接口和固定 TCP 端口。</param>
    /// <param name="timeoutMs">全部连接和认证共享的整体超时毫秒数。</param>
    /// <param name="validator">连接后执行的异步身份认证；返回真才允许发布该套接字。</param>
    /// <param name="cancellationToken">用于取消整轮尝试的标记。</param>
    /// <returns>首个连接且认证成功的套接字；全部失败时返回空。</returns>
    internal async Task<Socket?> ConnectAuthenticatedSocketAsync(IEnumerable<IPEndPoint> remoteCandidates,
        IPEndPoint? localBindEndPoint, int timeoutMs,
        Func<Socket, CancellationToken, ValueTask<bool>> validator,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(validator);
        return await ConnectSocketCoreAsync(remoteCandidates, localBindEndPoint, timeoutMs,
            validator, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>执行候选并发连接、可选认证、胜者选择及失败套接字清理。</summary>
    /// <param name="remoteCandidates">需要并发尝试的远程候选。</param>
    /// <param name="localBindEndPoint">可选固定本地端点。</param>
    /// <param name="timeoutMs">整轮超时毫秒数。</param>
    /// <param name="validator">可选的连接后身份认证。</param>
    /// <param name="cancellationToken">调用方取消标记。</param>
    /// <returns>首个合格套接字；没有合格候选时返回空。</returns>
    private static async Task<Socket?> ConnectSocketCoreAsync(IEnumerable<IPEndPoint> remoteCandidates,
        IPEndPoint? localBindEndPoint, int timeoutMs,
        Func<Socket, CancellationToken, ValueTask<bool>>? validator,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(remoteCandidates);
        if (timeoutMs < 100) throw new ArgumentOutOfRangeException(nameof(timeoutMs));
        IPEndPoint[] candidates = remoteCandidates.Distinct().Take(512).ToArray();
        if (candidates.Length == 0) return null;
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(timeoutMs);
        Task<Socket?>[] tasks = candidates.Select(candidate => ConnectOneAsync(candidate,
            localBindEndPoint, validator, timeout.Token)).ToArray();
        var remaining = new HashSet<Task<Socket?>>(tasks);
        Socket? winner = null;
        while (remaining.Count != 0 && winner is null)
        {
            Task<Socket?> completed = await Task.WhenAny(remaining).ConfigureAwait(false);
            remaining.Remove(completed);
            try { winner = await completed.ConfigureAwait(false); } catch (OperationCanceledException) { }
        }
        timeout.Cancel();
        foreach (Task<Socket?> task in tasks)
        {
            try { Socket? socket = await task.ConfigureAwait(false); if (socket is not null && socket != winner) socket.Dispose(); }
            catch { }
        }
        return winner;
    }

    /// <summary>创建并连接一个可复用的本地 TCP 套接字。</summary>
    /// <param name="remote">远程候选端点。</param>
    /// <param name="local">可选的真实本地绑定端点。</param>
    /// <param name="validator">可选的连接后身份认证。</param>
    /// <param name="cancellationToken">共享的超时取消标记。</param>
    /// <returns>已连接的套接字；失败时返回 <see langword="null"/>。</returns>
    private static async Task<Socket?> ConnectOneAsync(IPEndPoint remote, IPEndPoint? local,
        Func<Socket, CancellationToken, ValueTask<bool>>? validator, CancellationToken cancellationToken)
    {
        var socket = new Socket(remote.AddressFamily, SocketType.Stream, ProtocolType.Tcp) { NoDelay = true };
        try
        {
            ConfigureReusablePort(socket);
            if (local is not null) socket.Bind(local);
            await socket.ConnectAsync(remote, cancellationToken).ConfigureAwait(false);
            if (validator is not null && !await validator(socket, cancellationToken).ConfigureAwait(false))
            {
                socket.Dispose();
                return null;
            }
            return socket;
        }
        catch { socket.Dispose(); return null; }
    }

    /// <summary>配置允许监听和多个出站连接共享一个本地 TCP 打洞端口。</summary>
    /// <param name="socket">尚未绑定的 TCP 套接字。</param>
    internal static void ConfigureReusablePort(Socket socket)
    {
        socket.ExclusiveAddressUse = false;
        socket.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);
        try { socket.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseUnicastPort, true); }
        catch (SocketException) { }
        catch (PlatformNotSupportedException) { }
    }
}
