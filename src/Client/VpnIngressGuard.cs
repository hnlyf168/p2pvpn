using System.Buffers.Binary;
using System.Net;
using Qcxt.Net.P2P.Tunneling;

namespace P2PVpn.Policy;

// Runs before either direct or relayed packets reach the OS/proxy. Never rely on
// the host firewall: forwarding/NAT may be enabled by Docker or older software.
internal sealed class VpnIngressGuard(IP2PPacketTranslator translator) : IP2PPacketTranslator
{
    private readonly object _gate = new();
    private readonly Dictionary<Flow, long> _flows = new();
    private readonly Dictionary<Fragment, long> _fragments = new();
    private const int MaximumFlows = 8192;
    private const long Lifetime = 300_000;

    public ReadOnlyMemory<byte> TranslateOutbound(ReadOnlyMemory<byte> packet, ulong peer)
    {
        var translated = translator.TranslateOutbound(packet, peer);
        if (TryFlow(translated.Span, peer, false, out var key))
            lock (_gate)
            {
                long now = Environment.TickCount64;
                if (_flows.Count >= MaximumFlows) Expire(_flows, now, Lifetime);
                if (_flows.Count < MaximumFlows || _flows.ContainsKey(key)) _flows[key] = now;
            }
        return translated;
    }
    public ReadOnlyMemory<byte> TranslateInbound(ReadOnlyMemory<byte> packet, ulong peer) => translator.TranslateInbound(packet, peer);

    public bool Allows(ReadOnlyMemory<byte> packet, ulong peerId, IPAddress? peerAddress, IPAddress localAddress, NetworkPolicy policy)
    {
        var p = packet.Span;
        if (peerAddress is null || !Ipv4(p, out int header) || BinaryPrimitives.ReadUInt16BigEndian(p[2..]) != p.Length) return false;
        var source = new IPAddress(p.Slice(12, 4)); var destination = new IPAddress(p.Slice(16, 4));
        // VPN services on this endpoint stay reachable; this does not authorize a LAN destination.
        if (destination.Equals(localAddress)) return true;
        if (!policy.Allows(peerAddress, destination)) return false;
        if (source.Equals(peerAddress)) return true;
        if (policy.NetworkMode == "proxy") return false;
        // Static-routing replies to local LAN hosts must match an actually sent flow
        // AND the current gateway ACL and remote route. Being a configured peer alone
        // must never grant arbitrary forwarding or keep deleted networks accessible.
        bool fromRemoteNetwork = policy.RemoteSubnetRoutes.Any(r => r.Enabled &&
            IPAddress.TryParse(r.GatewayVirtualIp, out var gateway) && gateway.Equals(peerAddress) &&
            NetworkPolicy.Cidr(r.DestinationSubnet, out var subnet) && subnet.Contains(source));
        if (!fromRemoteNetwork) return false;
        long now = Environment.TickCount64;
        var fragment = new Fragment(peerId, U32(p,12), U32(p,16), BinaryPrimitives.ReadUInt16BigEndian(p[4..]), p[9]);
        ushort flags = BinaryPrimitives.ReadUInt16BigEndian(p[6..]);
        lock (_gate)
        {
            if ((flags & 0x1fff) != 0)
                return _fragments.TryGetValue(fragment, out long seen) && now - seen < 30_000;
            bool matched = TryFlow(p, peerId, true, out var flow) && _flows.TryGetValue(flow, out long sent) && now - sent < Lifetime;
            // ICMP errors quote the outgoing packet, including its original ports.
            if (!matched && p[9] == 1 && p.Length >= header + 8 && p[header] is 3 or 11 or 12 &&
                TryFlow(p[(header + 8)..], peerId, false, out var quoted))
                matched = _flows.TryGetValue(quoted, out sent) && now - sent < Lifetime && quoted.Source == U32(p,16);
            if (matched && (flags & 0x2000) != 0)
            {
                if (_fragments.Count >= 1024) Expire(_fragments, now, 30_000);
                if (_fragments.Count < 1024) _fragments[fragment] = now;
            }
            return matched;
        }
    }
    private static void Expire<T>(Dictionary<T,long> map, long now, long ttl) where T : notnull
    { foreach (var key in map.Where(x => now - x.Value >= ttl).Select(x => x.Key).ToArray()) map.Remove(key); }
    private static bool Ipv4(ReadOnlySpan<byte> p, out int header)
    { header = p.Length == 0 ? 0 : (p[0] & 15) * 4; return p.Length >= 20 && p[0] >> 4 == 4 && header >= 20 && p.Length >= header; }
    private static bool TryFlow(ReadOnlySpan<byte> p, ulong peer, bool reverse, out Flow flow)
    {
        flow = default;
        if (!Ipv4(p, out int h) || p.Length < h + 8 || (BinaryPrimitives.ReadUInt16BigEndian(p[6..]) & 0x1fff) != 0) return false;
        ushort a, b;
        if (p[9] is 6 or 17) { a=BinaryPrimitives.ReadUInt16BigEndian(p[h..]); b=BinaryPrimitives.ReadUInt16BigEndian(p[(h+2)..]); }
        else if (p[9] == 1 && p[h] == (reverse ? 0 : 8)) { a=BinaryPrimitives.ReadUInt16BigEndian(p[(h+4)..]); b=BinaryPrimitives.ReadUInt16BigEndian(p[(h+6)..]); }
        else return false;
        flow = reverse ? new(peer,U32(p,16),U32(p,12),p[9],p[9]==1?a:b,p[9]==1?b:a) : new(peer,U32(p,12),U32(p,16),p[9],a,b);
        return true;
    }
    private static uint U32(ReadOnlySpan<byte> p,int offset) => BinaryPrimitives.ReadUInt32BigEndian(p[offset..]);
    private readonly record struct Flow(ulong Peer,uint Source,uint Destination,byte Protocol,ushort SourcePort,ushort DestinationPort);
    private readonly record struct Fragment(ulong Peer,uint Source,uint Destination,ushort Id,byte Protocol);
}
