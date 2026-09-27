using System.Buffers.Binary;
using System.Net;
using Qcxt.Net.P2P.Tunneling;

namespace P2PVpnClient;

/// <summary>
/// 表示 Client Subnet Packet Translator，并提供相关数据或行为。
/// </summary>
internal sealed class ClientSubnetPacketTranslator : IP2PPacketTranslator
{
    private TranslationRule[] _rules = [];

    /// <summary>
    /// 执行Replace Rules操作。
    /// </summary>
    /// <param name="rules">rules参数。</param>
    internal void ReplaceRules(IEnumerable<ClientSubnetTranslationRule> rules) =>
        Volatile.Write(ref _rules, rules.Select(static rule => new TranslationRule(
            ToUInt32(rule.ExposedNetwork), ToUInt32(rule.DestinationNetwork),
            PrefixMask(rule.PrefixLength), rule.PeerId)).ToArray());

    /// <summary>
    /// 执行Translate Outbound操作。
    /// </summary>
    /// <param name="packet">packet参数。</param>
    /// <param name="targetPeerId">target Peer Id参数。</param>
    /// <returns>操作结果。</returns>
    public ReadOnlyMemory<byte> TranslateOutbound(ReadOnlyMemory<byte> packet, ulong targetPeerId)
    {
        if (!TryGetIpv4Address(packet.Span, 16, out uint destination)) return packet;
        foreach (TranslationRule rule in Volatile.Read(ref _rules))
        {
            if (rule.PeerId != targetPeerId || (destination & rule.Mask) != rule.ExposedNetwork ||
                rule.ExposedNetwork == rule.DestinationNetwork) continue;
            return RewriteAddress(packet, 16, destination,
                rule.DestinationNetwork | (destination & ~rule.Mask));
        }
        return packet;
    }

    /// <summary>
    /// 执行Translate Inbound操作。
    /// </summary>
    /// <param name="packet">packet参数。</param>
    /// <param name="sourcePeerId">source Peer Id参数。</param>
    /// <returns>操作结果。</returns>
    public ReadOnlyMemory<byte> TranslateInbound(ReadOnlyMemory<byte> packet, ulong sourcePeerId)
    {
        if (!TryGetIpv4Address(packet.Span, 12, out uint source)) return packet;
        foreach (TranslationRule rule in Volatile.Read(ref _rules))
        {
            if (rule.PeerId != sourcePeerId || (source & rule.Mask) != rule.DestinationNetwork ||
                rule.ExposedNetwork == rule.DestinationNetwork) continue;
            return RewriteAddress(packet, 12, source,
                rule.ExposedNetwork | (source & ~rule.Mask));
        }
        return packet;
    }

    /// <summary>
    /// 执行Rewrite Address操作。
    /// </summary>
    /// <param name="packet">packet参数。</param>
    /// <param name="offset">数据起始偏移量。</param>
    /// <param name="oldAddress">old Address参数。</param>
    /// <param name="newAddress">new Address参数。</param>
    /// <returns>操作结果。</returns>
    private static ReadOnlyMemory<byte> RewriteAddress(ReadOnlyMemory<byte> packet, int offset,
        uint oldAddress, uint newAddress)
    {
        byte[] result = packet.ToArray();
        Span<byte> bytes = result;
        int headerLength = (bytes[0] & 0x0f) * 4;
        UpdateTransportChecksum(bytes, headerLength, oldAddress, newAddress);
        BinaryPrimitives.WriteUInt32BigEndian(bytes[offset..], newAddress);
        bytes[10] = bytes[11] = 0;
        BinaryPrimitives.WriteUInt16BigEndian(bytes[10..], ComputeChecksum(bytes[..headerLength]));
        return result;
    }

    /// <summary>
    /// 执行Update Transport Checksum操作。
    /// </summary>
    /// <param name="packet">packet参数。</param>
    /// <param name="headerLength">header Length参数。</param>
    /// <param name="oldAddress">old Address参数。</param>
    /// <param name="newAddress">new Address参数。</param>
    private static void UpdateTransportChecksum(Span<byte> packet, int headerLength,
        uint oldAddress, uint newAddress)
    {
        if (packet.Length < headerLength + 8 ||
            (BinaryPrimitives.ReadUInt16BigEndian(packet[6..]) & 0x1fff) != 0) return;
        int checksumOffset = packet[9] switch
        {
            6 when packet.Length >= headerLength + 20 => headerLength + 16,
            17 => headerLength + 6,
            _ => -1
        };
        if (checksumOffset < 0) return;
        ushort checksum = BinaryPrimitives.ReadUInt16BigEndian(packet[checksumOffset..]);
        if (packet[9] == 17 && checksum == 0) return;
        uint sum = (uint)(~checksum & 0xffff);
        sum += (uint)(~(oldAddress >> 16) & 0xffff) + (newAddress >> 16);
        sum += (uint)(~oldAddress & 0xffff) + (newAddress & 0xffff);
        while ((sum >> 16) != 0) sum = (sum & 0xffff) + (sum >> 16);
        ushort updated = unchecked((ushort)~sum);
        if (packet[9] == 17 && updated == 0) updated = 0xffff;
        BinaryPrimitives.WriteUInt16BigEndian(packet[checksumOffset..], updated);
    }

    /// <summary>
    /// 执行Compute Checksum操作。
    /// </summary>
    /// <param name="bytes">bytes参数。</param>
    /// <returns>操作结果。</returns>
    private static ushort ComputeChecksum(ReadOnlySpan<byte> bytes)
    {
        uint sum = 0;
        int index = 0;
        for (; index + 1 < bytes.Length; index += 2)
            sum += BinaryPrimitives.ReadUInt16BigEndian(bytes[index..]);
        if (index < bytes.Length) sum += (uint)bytes[index] << 8;
        while ((sum >> 16) != 0) sum = (sum & 0xffff) + (sum >> 16);
        return unchecked((ushort)~sum);
    }

    /// <summary>
    /// 尝试Get Ipv4 Address。
    /// </summary>
    /// <param name="packet">packet参数。</param>
    /// <param name="offset">数据起始偏移量。</param>
    /// <param name="address">网络地址。</param>
    /// <returns>操作是否成功。</returns>
    private static bool TryGetIpv4Address(ReadOnlySpan<byte> packet, int offset, out uint address)
    {
        address = 0;
        if (packet.Length < 20 || packet[0] >> 4 != 4) return false;
        int headerLength = (packet[0] & 0x0f) * 4;
        if (headerLength < 20 || headerLength > packet.Length) return false;
        address = BinaryPrimitives.ReadUInt32BigEndian(packet[offset..]);
        return true;
    }

    /// <summary>
    /// 执行To U Int32操作。
    /// </summary>
    /// <param name="address">网络地址。</param>
    /// <returns>操作结果。</returns>
    private static uint ToUInt32(IPAddress address) =>
        BinaryPrimitives.ReadUInt32BigEndian(address.GetAddressBytes());
    /// <summary>
    /// 执行Prefix Mask操作。
    /// </summary>
    /// <param name="prefixLength">prefix Length参数。</param>
    /// <returns>操作结果。</returns>
    private static uint PrefixMask(int prefixLength) =>
        prefixLength == 32 ? uint.MaxValue : uint.MaxValue << (32 - prefixLength);

    /// <summary>
    /// 表示 Translation Rule，并提供相关数据或行为。
    /// </summary>
    /// <param name="ExposedNetwork">Exposed Network参数。</param>
    /// <param name="DestinationNetwork">Destination Network参数。</param>
    /// <param name="Mask">Mask参数。</param>
    /// <param name="PeerId">Peer Id参数。</param>
    private readonly record struct TranslationRule(uint ExposedNetwork, uint DestinationNetwork,
        uint Mask, ulong PeerId);
}

/// <summary>
/// 表示 Client Subnet Translation Rule，并提供相关数据或行为。
/// </summary>
/// <param name="ExposedNetwork">Exposed Network参数。</param>
/// <param name="DestinationNetwork">Destination Network参数。</param>
/// <param name="PrefixLength">Prefix Length参数。</param>
/// <param name="PeerId">Peer Id参数。</param>
internal sealed record ClientSubnetTranslationRule(IPAddress ExposedNetwork,
    IPAddress DestinationNetwork, int PrefixLength, ulong PeerId);
