using System.Text.Json;
using P2PVpn.Policy;
namespace P2PVpnClient;
internal static class ClientNetworkPolicy
{
    internal static NetworkPolicy FromConfig(ClientConfig c) => new()
    {
        NetworkMode = c.NetworkMode, GatewayMode = c.GatewayMode,
        GatewayNetworks = (c.GatewayNetworks.Count > 0 ? c.GatewayNetworks : ClientConfigStore.GetGatewayNetworks(c)).Select(n => new GatewayNetwork { Enabled = n.Enabled, Interface = n.Interface, Subnet = n.Subnet, AllowedClients = n.AllowedClients }).ToArray(),
        RemoteSubnetRoutes = c.RemoteSubnetRoutes.Select(r => new RemoteRoute { Enabled = r.Enabled, Subnet = r.Subnet, DestinationSubnet = r.DestinationSubnet, GatewayVirtualIp = r.GatewayVirtualIp }).ToArray()
    };
    internal static void Apply(ClientConfig c, NetworkPolicy p, long revision)
    {
        p.Validate(); c.NetworkMode = p.NetworkMode; c.GatewayMode = p.GatewayMode;
        c.GatewayLanInterface = ""; c.GatewayLanSubnet = "";
        c.GatewayNetworks = p.GatewayNetworks.Select(n => new ClientGatewayNetwork { Enabled = n.Enabled, Interface = n.Interface, Subnet = n.Subnet, AllowedClients = n.AllowedClients }).ToList();
        c.RemoteSubnetRoutes = p.RemoteSubnetRoutes.Select(r => new ClientSubnetRoute { Enabled = r.Enabled, Subnet = r.Subnet, DestinationSubnet = r.DestinationSubnet, GatewayVirtualIp = r.GatewayVirtualIp }).ToList();
        c.NetworkPolicyRevision = revision;
    }
    internal static string Fingerprint(ClientConfig c) => JsonSerializer.Serialize(FromConfig(c), PolicyJson.Default.NetworkPolicy);
}
