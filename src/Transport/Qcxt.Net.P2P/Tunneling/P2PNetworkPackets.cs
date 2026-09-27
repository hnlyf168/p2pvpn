namespace Qcxt.Net.P2P.Tunneling;

/// <summary>标识常见的 IP 下一头部协议号。</summary>
public enum P2PNetworkProtocol : byte
{
    /// <summary>未分类协议。</summary>
    Unknown = 0,
    /// <summary>互联网控制消息协议。</summary>
    Icmp = 1,
    /// <summary>传输控制协议。</summary>
    Tcp = 6,
    /// <summary>用户数据报协议。</summary>
    Udp = 17,
    /// <summary>互联网控制消息协议第 6 版。</summary>
    IcmpV6 = 58
}

/// <summary>包含从 IPv4 或 IPv6 包零分配解析出的元数据。</summary>
/// <param name="Version">IP 版本，值为 4 或 6。</param>
/// <param name="Protocol">最终解析出的下一头部协议。</param>
/// <param name="SourceIpv4">网络字节序的 IPv4 来源地址；IPv6 时为零。</param>
/// <param name="DestinationIpv4">网络字节序的 IPv4 目标地址；IPv6 时为零。</param>
/// <param name="SourcePort">首个分片中存在的 TCP 或 UDP 来源端口。</param>
/// <param name="DestinationPort">首个分片中存在的 TCP 或 UDP 目标端口。</param>
/// <param name="PacketLength">校验后的数据包长度。</param>
/// <param name="IsFragment">数据包是否为 IP 分片。</param>
public readonly record struct P2PNetworkPacketInfo(byte Version, P2PNetworkProtocol Protocol,
    uint SourceIpv4, uint DestinationIpv4, ushort SourcePort, ushort DestinationPort,
    int PacketLength, bool IsFragment);

/// <summary>仅解析路由和优先级字段，不保留或复制数据包字节。</summary>
public static class P2PNetworkPacketParser
{
    /// <summary>校验 IP 包并提取热路径元数据。</summary>
    /// <param name="packet">原始三层数据包。</param>
    /// <param name="info">解析后的元数据。</param>
    /// <returns>IPv4 或基础 IPv6 包结构有效时返回 <see langword="true"/>。</returns>
    public static bool TryParse(ReadOnlySpan<byte> packet, out P2PNetworkPacketInfo info)
    {
        info = default;
        if (packet.Length < 1) return false;
        return (packet[0] >> 4) switch
        {
            4 => TryParseIpv4(packet, out info),
            6 => TryParseIpv6(packet, out info),
            _ => false
        };
    }

    /// <summary>解析 IPv4 头部，包括分片和传输端口状态。</summary>
    private static bool TryParseIpv4(ReadOnlySpan<byte> packet, out P2PNetworkPacketInfo info)
    {
        info = default;
        if (packet.Length < 20) return false;
        int headerLength = (packet[0] & 0x0f) * 4;
        if (headerLength < 20 || headerLength > packet.Length) return false;
        int totalLength = BinaryPrimitives.ReadUInt16BigEndian(packet[2..]);
        if (totalLength < headerLength || totalLength > packet.Length) return false;
        ushort fragment = BinaryPrimitives.ReadUInt16BigEndian(packet[6..]);
        bool isFragment = (fragment & 0x3fff) != 0;
        bool firstFragment = (fragment & 0x1fff) == 0;
        var protocol = (P2PNetworkProtocol)packet[9];
        ushort sourcePort = 0, destinationPort = 0;
        if (firstFragment && protocol is P2PNetworkProtocol.Tcp or P2PNetworkProtocol.Udp &&
            totalLength >= headerLength + 4)
        {
            sourcePort = BinaryPrimitives.ReadUInt16BigEndian(packet[headerLength..]);
            destinationPort = BinaryPrimitives.ReadUInt16BigEndian(packet[(headerLength + 2)..]);
        }
        info = new(4, protocol, BinaryPrimitives.ReadUInt32BigEndian(packet[12..]),
            BinaryPrimitives.ReadUInt32BigEndian(packet[16..]), sourcePort, destinationPort,
            totalLength, isFragment);
        return true;
    }

    /// <summary>解析固定 IPv6 头部及直接相邻的 TCP、UDP 或 ICMPv6 下一头部。</summary>
    private static bool TryParseIpv6(ReadOnlySpan<byte> packet, out P2PNetworkPacketInfo info)
    {
        info = default;
        if (packet.Length < 40) return false;
        int payloadLength = BinaryPrimitives.ReadUInt16BigEndian(packet[4..]);
        int totalLength = 40 + payloadLength;
        if (totalLength > packet.Length) return false;
        var protocol = (P2PNetworkProtocol)packet[6];
        ushort sourcePort = 0, destinationPort = 0;
        if (protocol is P2PNetworkProtocol.Tcp or P2PNetworkProtocol.Udp && totalLength >= 44)
        {
            sourcePort = BinaryPrimitives.ReadUInt16BigEndian(packet[40..]);
            destinationPort = BinaryPrimitives.ReadUInt16BigEndian(packet[42..]);
        }
        info = new(6, protocol, 0, 0, sourcePort, destinationPort, totalLength, false);
        return true;
    }

    /// <summary>对已校验数据包分类，避免大文件流量饿死控制流量。</summary>
    /// <param name="info">解析后的数据包元数据。</param>
    /// <returns>交互、普通或大流量调度等级。</returns>
    public static P2PTrafficClass Classify(in P2PNetworkPacketInfo info)
    {
        if (info.Protocol is P2PNetworkProtocol.Icmp or P2PNetworkProtocol.IcmpV6) return P2PTrafficClass.Interactive;
        if (info.Protocol == P2PNetworkProtocol.Tcp && info.PacketLength <= 256) return P2PTrafficClass.Interactive;
        if (info.PacketLength >= 1200) return P2PTrafficClass.Bulk;
        return P2PTrafficClass.Normal;
    }

    /// <summary>根据网络层协议选择传输交付模式。</summary>
    /// <param name="info">已解析的数据包信息。</param>
    /// <returns>ICMP 和 ICMPv6 使用可靠有序交付；其他协议使用不可靠低延迟交付。</returns>
    /// <remarks>
    /// TCP 自身具备重传和排序能力，若在隧道层再次可靠传输，会在丢包时产生队头阻塞。
    /// ICMP 没有端到端重传能力且流量很低，因此通过可靠路径传输可避免中转链路上的随机丢包。
    /// </remarks>
    public static P2PDeliveryMode SelectDeliveryMode(in P2PNetworkPacketInfo info) =>
        P2PDeliveryMode.Unreliable;
}

/// <summary>把一个原始 IP 包映射到数字形式的 P2P 对端。</summary>
public interface IP2PPacketRouter
{
    /// <summary>解析目标组网对端。</summary>
    /// <param name="packet">已经或尚未校验的原始 IP 包。</param>
    /// <param name="targetPeerId">解析得到的数字对端标识。</param>
    /// <returns>存在路由时返回 <see langword="true"/>。</returns>
    bool TryResolve(ReadOnlySpan<byte> packet, out ulong targetPeerId);
}

/// <summary>提供无锁的 IPv4 目标地址到对端路由表。</summary>
public sealed class P2PIpv4PacketRouter : IP2PPacketRouter
{
    private readonly ConcurrentDictionary<uint, ulong> _routes = new();
    private readonly object _subnetGate = new();
    private SubnetRoute[] _subnetRoutes = [];

    /// <summary>添加或替换一条精确 IPv4 主机路由。</summary>
    /// <param name="address">目标 IPv4 地址。</param>
    /// <param name="peerId">数字形式的组网对端标识。</param>
    public void SetRoute(IPAddress address, ulong peerId)
    {
        if (peerId == 0) throw new ArgumentOutOfRangeException(nameof(peerId));
        Span<byte> bytes = stackalloc byte[4];
        if (!address.TryWriteBytes(bytes, out int written) || written != 4)
            throw new ArgumentException("必须提供 IPv4 地址。", nameof(address));
        _routes[BinaryPrimitives.ReadUInt32BigEndian(bytes)] = peerId;
    }

    /// <summary>删除一条精确 IPv4 主机路由。</summary>
    /// <param name="address">目标 IPv4 地址。</param>
    /// <returns>成功删除路由时返回真。</returns>
    public bool RemoveRoute(IPAddress address)
    {
        Span<byte> bytes = stackalloc byte[4];
        return address.TryWriteBytes(bytes, out int written) && written == 4 &&
            _routes.TryRemove(BinaryPrimitives.ReadUInt32BigEndian(bytes), out _);
    }

    /// <summary>
    /// 设置Subnet Route。
    /// </summary>
    /// <param name="network">network参数。</param>
    /// <param name="prefixLength">prefix Length参数。</param>
    /// <param name="peerId">peer Id参数。</param>
    public void SetSubnetRoute(IPAddress network, int prefixLength, ulong peerId)
    {
        if (peerId == 0) throw new ArgumentOutOfRangeException(nameof(peerId));
        if (prefixLength is < 1 or > 32) throw new ArgumentOutOfRangeException(nameof(prefixLength));
        Span<byte> bytes = stackalloc byte[4];
        if (!network.TryWriteBytes(bytes, out int written) || written != 4)
            throw new ArgumentException("An IPv4 network is required.", nameof(network));
        uint mask = prefixLength == 32 ? uint.MaxValue : uint.MaxValue << (32 - prefixLength);
        uint normalized = BinaryPrimitives.ReadUInt32BigEndian(bytes) & mask;
        lock (_subnetGate)
        {
            _subnetRoutes = _subnetRoutes
                .Where(route => route.Network != normalized || route.PrefixLength != prefixLength)
                .Append(new SubnetRoute(normalized, mask, prefixLength, peerId))
                .OrderByDescending(static route => route.PrefixLength).ToArray();
        }
    }

    /// <summary>
    /// 移除Subnet Route。
    /// </summary>
    /// <param name="network">network参数。</param>
    /// <param name="prefixLength">prefix Length参数。</param>
    /// <returns>操作结果。</returns>
    public bool RemoveSubnetRoute(IPAddress network, int prefixLength)
    {
        Span<byte> bytes = stackalloc byte[4];
        if (!network.TryWriteBytes(bytes, out int written) || written != 4 || prefixLength is < 1 or > 32)
            return false;
        uint mask = prefixLength == 32 ? uint.MaxValue : uint.MaxValue << (32 - prefixLength);
        uint normalized = BinaryPrimitives.ReadUInt32BigEndian(bytes) & mask;
        lock (_subnetGate)
        {
            SubnetRoute[] next = _subnetRoutes
                .Where(route => route.Network != normalized || route.PrefixLength != prefixLength).ToArray();
            if (next.Length == _subnetRoutes.Length) return false;
            _subnetRoutes = next;
            return true;
        }
    }

    /// <inheritdoc />
    public bool TryResolve(ReadOnlySpan<byte> packet, out ulong targetPeerId)
    {
        targetPeerId = 0;
        if (packet.Length < 20 || packet[0] >> 4 != 4) return false;
        uint destination = BinaryPrimitives.ReadUInt32BigEndian(packet[16..]);
        if (_routes.TryGetValue(destination, out targetPeerId)) return true;
        foreach (SubnetRoute route in _subnetRoutes)
        {
            if ((destination & route.Mask) != route.Network) continue;
            targetPeerId = route.PeerId;
            return true;
        }
        return false;
    }

    /// <summary>
    /// 表示 Subnet Route，并提供相关数据或行为。
    /// </summary>
    /// <param name="Network">Network参数。</param>
    /// <param name="Mask">Mask参数。</param>
    /// <param name="PrefixLength">Prefix Length参数。</param>
    /// <param name="PeerId">Peer Id参数。</param>
    private readonly record struct SubnetRoute(uint Network, uint Mask, int PrefixLength, ulong PeerId);
}
