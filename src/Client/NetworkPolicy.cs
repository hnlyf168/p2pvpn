using System.Net;
using System.Net.Sockets;
using System.Text.Json.Serialization;

namespace P2PVpn.Policy;

public sealed class GatewayNetwork
{
    public bool Enabled { get; set; } = true;
    public string Interface { get; set; } = "";
    public string Subnet { get; set; } = "";
    public string[] AllowedClients { get; set; } = ["*"];
}
public sealed class RemoteRoute
{
    public bool Enabled { get; set; } = true;
    public string Subnet { get; set; } = "";
    public string DestinationSubnet { get; set; } = "";
    public string GatewayVirtualIp { get; set; } = "";
}
public sealed class NetworkPolicy
{
    // ACL-only changes are immutable snapshot swaps; topology changes still rebuild.
    public bool HasSameTopology(NetworkPolicy other) => NetworkMode == other.NetworkMode && GatewayMode == other.GatewayMode &&
        GatewayNetworks.Select(n => (n.Enabled, n.Interface, n.Subnet)).SequenceEqual(other.GatewayNetworks.Select(n => (n.Enabled, n.Interface, n.Subnet))) &&
        RemoteSubnetRoutes.Select(r => (r.Enabled, r.Subnet, r.DestinationSubnet, r.GatewayVirtualIp)).SequenceEqual(other.RemoteSubnetRoutes.Select(r => (r.Enabled, r.Subnet, r.DestinationSubnet, r.GatewayVirtualIp)));
    public string NetworkMode { get; set; } = "tun";
    public string GatewayMode { get; set; } = "local";
    public GatewayNetwork[] GatewayNetworks { get; set; } = [];
    public RemoteRoute[] RemoteSubnetRoutes { get; set; } = [];

    public void Validate()
    {
        if (NetworkMode is not ("tun" or "veth" or "proxy")) throw new InvalidDataException("网卡模式只能为 tun、veth 或 proxy（程序网关）。");
        if (GatewayMode is not ("local" or "nat" or "route")) throw new InvalidDataException("网关模式无效。");
        if (NetworkMode == "proxy" && GatewayMode == "route") throw new InvalidDataException("无 TUN 模式不支持静态路由网关，请选择 NAT 或仅本机。");
        if (GatewayNetworks is null || GatewayNetworks.Length > 32 || RemoteSubnetRoutes is null || RemoteSubnetRoutes.Length > 64)
            throw new InvalidDataException("网关网段最多 32 条，远端路由最多 64 条。");
        var unique = new HashSet<string>();
        foreach (var n in GatewayNetworks)
        {
            if (n is null || !Cidr(n.Subnet, out var cidr)) throw new InvalidDataException("网关网段必须为规范 IPv4 CIDR。");
            if (!unique.Add(n.Subnet)) throw new InvalidDataException("网关网段重复。");
            if (n.Interface is null || n.Interface.Length > 128 || n.Interface.Any(c => char.IsControl(c))) throw new InvalidDataException("网卡名称无效。");
            if (n.AllowedClients is null || n.AllowedClients.Length > 128) throw new InvalidDataException("白名单无效；空列表表示拒绝所有客户端。");
            foreach (var a in n.AllowedClients)
                if (a != "*" && (!IPAddress.TryParse(a, out var ip) || ip.AddressFamily != AddressFamily.InterNetwork || ip.Equals(IPAddress.Any)))
                    throw new InvalidDataException("白名单只允许 VPN IPv4 地址或 *。");
            if (n.AllowedClients.Contains("*") && n.AllowedClients.Length != 1) throw new InvalidDataException("* 不能与指定客户端同时填写。");
        }
        unique.Clear();
        foreach (var r in RemoteSubnetRoutes)
        {
            if (r is null || !Cidr(r.Subnet, out var subnet) || !unique.Add(r.Subnet)) throw new InvalidDataException("远端访问网段无效或重复。");
            if (string.IsNullOrWhiteSpace(r.DestinationSubnet)) r.DestinationSubnet = r.Subnet;
            if (!Cidr(r.DestinationSubnet, out var destination) || subnet.PrefixLength != destination.PrefixLength ||
                !IPAddress.TryParse(r.GatewayVirtualIp, out var ip) || ip.AddressFamily != AddressFamily.InterNetwork || ip.Equals(IPAddress.Any))
                throw new InvalidDataException("远端真实网段、掩码或网关 VPN IP 无效。");
        }
    }
    public static bool Cidr(string? value, out IPNetwork network) => IPNetwork.TryParse(value, out network) && network.BaseAddress.AddressFamily == AddressFamily.InterNetwork;
    // 最长网段优先；同一目标不能通过宽泛的 * 规则绕过更精确的规则。
    public GatewayNetwork? Match(IPAddress destination) => GatewayNetworks.Where(n => n.Enabled && Cidr(n.Subnet, out var c) && c.Contains(destination))
        .OrderByDescending(n => IPNetwork.Parse(n.Subnet).PrefixLength).FirstOrDefault();
    public bool Allows(IPAddress peer, IPAddress destination) => GatewayMode != "local" && Match(destination) is { } n &&
        (n.AllowedClients.Contains("*") || n.AllowedClients.Contains(peer.ToString(), StringComparer.Ordinal));
}
public sealed class PolicyReport
{
    // null = older client did not report; [] = enumerated but none eligible.
    public LanInterfaceReport[]? NetworkInterfaces { get; set; }
    public string ClientId { get; set; } = "";
    public string Version { get; set; } = "";
    public string Platform { get; set; } = "";
    public string[] SupportedModes { get; set; } = ["tun", "proxy"];
    public bool TunAvailable { get; set; }
    public bool? VethAvailable { get; set; }
    public string VethError { get; set; } = "";
    public long AppliedRevision { get; set; }
    public string ApplyError { get; set; } = "";
    public NetworkPolicy Reported { get; set; } = new();
}
public sealed class LanInterfaceReport
{
    public string Name { get; set; } = "";
    public string Description { get; set; } = "";
    public string Type { get; set; } = "";
    public string Status { get; set; } = "";
    public LanAddressReport[] Addresses { get; set; } = [];
}
public sealed class LanAddressReport
{
    public string Address { get; set; } = "";
    public int PrefixLength { get; set; }
}
public sealed class PolicyEntry
{
    public string ClientId { get; set; } = "";
    public PolicyReport? Report { get; set; }
    public NetworkPolicy? Desired { get; set; }
    public long Revision { get; set; }
    public DateTimeOffset LastSeen { get; set; }
}
public sealed class PolicyUpdate
{
    public long ExpectedRevision { get; set; }
    public NetworkPolicy? Desired { get; set; }
}
[JsonSourceGenerationOptions(PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase, PropertyNameCaseInsensitive = true)]
[JsonSerializable(typeof(NetworkPolicy))]
[JsonSerializable(typeof(PolicyReport))]
[JsonSerializable(typeof(PolicyEntry))]
[JsonSerializable(typeof(PolicyEntry[]))]
[JsonSerializable(typeof(PolicyUpdate))]
public partial class PolicyJson : JsonSerializerContext;
