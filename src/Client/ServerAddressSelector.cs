using System.Net;
using System.Net.Sockets;

namespace P2PVpnClient;

/// <summary>按目标路由选择地址，而不是把 ::1 或网卡支持 IPv6 当成公网 IPv6 可用。</summary>
internal static class ServerAddressSelector
{
    internal static IPEndPoint Select(IEnumerable<IPAddress> addresses, int port,
        AddressFamily? family = null, int offset = 0, Func<IPEndPoint, bool>? routeAvailable = null)
    {
        routeAvailable ??= HasRoute;
        var candidates = addresses.Distinct()
            .Where(a => a.AddressFamily is AddressFamily.InterNetwork or AddressFamily.InterNetworkV6)
            .Where(a => family is null || a.AddressFamily == family)
            .Select(a => new IPEndPoint(a, port)).ToArray();
        if (candidates.Length == 0) throw new SocketException((int)SocketError.HostNotFound);
        var reachable = candidates.Where(routeAvailable)
            .OrderBy(e => e.AddressFamily == AddressFamily.InterNetworkV6 ? 0 : 1).ToArray();
        if (reachable.Length == 0) throw new SocketException((int)SocketError.NetworkUnreachable);
        return reachable[(int)((uint)offset % (uint)reachable.Length)];
    }

    private static bool HasRoute(IPEndPoint endpoint)
    {
        try
        {
            // UDP Connect only consults the local route; no application packet is sent.
            using var socket = new Socket(endpoint.AddressFamily, SocketType.Dgram, ProtocolType.Udp);
            socket.Connect(endpoint);
            if (socket.LocalEndPoint is not IPEndPoint local) return false;
            if (local.Address.Equals(IPAddress.Any) || local.Address.Equals(IPAddress.IPv6Any)) return false;
            return IPAddress.IsLoopback(endpoint.Address) || !IPAddress.IsLoopback(local.Address);
        }
        catch (SocketException) { return false; }
        catch (NotSupportedException) { return false; }
    }
}
