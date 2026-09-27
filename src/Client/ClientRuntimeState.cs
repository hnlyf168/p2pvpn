using System.Text.Json;
using System.Text.Json.Serialization;
using Qcxt.Net.P2P.Signaling;

namespace P2PVpnClient;

/// <summary>
/// 表示 Client Peer Runtime State，并提供相关数据或行为。
/// </summary>
/// <param name="PeerId">Peer Id参数。</param>
/// <param name="VirtualIp">Virtual Ip参数。</param>
/// <param name="DirectConnected">Direct Connected参数。</param>
/// <param name="Transport">Transport参数。</param>
/// <param name="LocalEndPoint">Local End Point参数。</param>
/// <param name="RemoteEndPoint">网络端点。</param>
/// <param name="PeerPublicEndPoint">Peer Public End Point参数。</param>
internal sealed record ClientPeerRuntimeState(string PeerId, string VirtualIp, bool DirectConnected,
    string Transport, string LocalEndPoint, string RemoteEndPoint, string PeerPublicEndPoint);

/// <summary>
/// 表示 Client Runtime State，并提供相关数据或行为。
/// </summary>
/// <param name="Connected">Connected参数。</param>
/// <param name="ClientId">Client Id参数。</param>
/// <param name="Server">Server参数。</param>
/// <param name="VirtualIp">Virtual Ip参数。</param>
/// <param name="PrefixLength">Prefix Length参数。</param>
/// <param name="LocalEndPoint">Local End Point参数。</param>
/// <param name="Peers">Peers参数。</param>
/// <param name="LastEvent">Last Event参数。</param>
/// <param name="LastError">Last Error参数。</param>
/// <param name="UpdatedAt">Updated At参数。</param>
internal sealed record ClientRuntimeState(bool Connected, string ClientId, string Server,
    string VirtualIp, int PrefixLength, string LocalEndPoint, ClientPeerRuntimeState[] Peers,
    string LastEvent, string LastError, DateTimeOffset UpdatedAt);

/// <summary>
/// 表示 Client Runtime Json Context，并提供相关数据或行为。
/// </summary>
[JsonSourceGenerationOptions(PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase, WriteIndented = true)]
[JsonSerializable(typeof(ClientRuntimeState))]
[JsonSerializable(typeof(ClientPeerRuntimeState[]))]
internal sealed partial class ClientRuntimeJsonContext : JsonSerializerContext;

/// <summary>
/// 表示 Client Runtime State Store，并提供相关数据或行为。
/// </summary>
internal static class ClientRuntimeStateStore
{
    private static readonly object Sync = new();
    private static string _lastEvent = "正在启动";
    private static string _lastError = "";
    /// <summary>
    /// 获取或设置State Path。
    /// </summary>
    /// <returns>State Path。</returns>
    internal static string StatePath => Path.Combine(ClientConfigStore.DirectoryPath, "runtime-status.json");

    /// <summary>
    /// 执行Event操作。
    /// </summary>
    /// <param name="message">消息内容。</param>
    internal static void Event(string message)
    {
        lock (Sync) _lastEvent = message;
    }

    /// <summary>
    /// 执行Error操作。
    /// </summary>
    /// <param name="message">消息内容。</param>
    internal static void Error(string message)
    {
        lock (Sync) { _lastEvent = "运行异常"; _lastError = message; }
        Write(new ClientRuntimeState(false, PersistentDeviceIdentity.GetOrCreate(), "", "", 0, "", [],
            "运行异常", message, DateTimeOffset.Now));
    }

    /// <summary>
    /// 执行Publish操作。
    /// </summary>
    /// <param name="connected">connected参数。</param>
    /// <param name="clientId">client Id参数。</param>
    /// <param name="server">server参数。</param>
    /// <param name="virtualIp">virtual Ip参数。</param>
    /// <param name="prefixLength">prefix Length参数。</param>
    /// <param name="localEndPoint">local End Point参数。</param>
    /// <param name="relayLocalEndPoint">relay Local End Point参数。</param>
    /// <param name="relayServerEndPoint">relay Server End Point参数。</param>
    /// <param name="peers">peers参数。</param>
    internal static void Publish(bool connected, string clientId, string server, string virtualIp,
        int prefixLength, string localEndPoint, string relayLocalEndPoint, string relayServerEndPoint,
        IReadOnlyList<DiscoveredPeer> peers)
    {
        string lastEvent;
        string lastError;
        lock (Sync) { lastEvent = _lastEvent; lastError = _lastError; }
        var items = peers.Select(peer => new ClientPeerRuntimeState(peer.PeerId,
            peer.VirtualAddress.ToString(), peer.DirectConnected,
            peer.DirectConnected ? peer.DirectTransport.ToString() : "Relay",
            peer.DirectConnected ? peer.DirectLocalEndPoint?.ToString() ?? localEndPoint : relayLocalEndPoint,
            peer.DirectConnected ? peer.DirectRemoteEndPoint?.ToString() ?? "" : relayServerEndPoint,
            (peer.DirectTransport == Qcxt.Net.P2P.P2PTransportKind.TcpDirect
                ? peer.TcpPublicEndPoint : peer.PublicEndPoint)?.ToString() ?? "")).ToArray();
        Write(new ClientRuntimeState(connected, clientId, server, virtualIp, prefixLength,
            localEndPoint, items, lastEvent, lastError, DateTimeOffset.Now));
    }

    /// <summary>
    /// 执行Write操作。
    /// </summary>
    /// <param name="state">state参数。</param>
    private static void Write(ClientRuntimeState state)
    {
        try
        {
            lock (Sync)
            {
                Directory.CreateDirectory(ClientConfigStore.DirectoryPath);
                string temporary = StatePath + ".tmp";
                File.WriteAllBytes(temporary, JsonSerializer.SerializeToUtf8Bytes(state,
                    ClientRuntimeJsonContext.Default.ClientRuntimeState));
                File.Move(temporary, StatePath, true);
            }
        }
        catch { }
    }
}
