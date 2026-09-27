using System.Buffers.Binary;
using System.Net;
using Qcxt.Net.P2P.Tunneling;

namespace P2PVpnAndroid;

internal sealed class SubnetPacketTranslator : IP2PPacketTranslator
{
    private Rule[] _rules = [];
    public void ReplaceRules(IEnumerable<TranslationRule> rules) => Volatile.Write(ref _rules,
        rules.Select(x => new Rule(ToUInt32(x.ExposedNetwork), ToUInt32(x.DestinationNetwork), Mask(x.PrefixLength), x.PeerId)).ToArray());

    public ReadOnlyMemory<byte> TranslateOutbound(ReadOnlyMemory<byte> packet, ulong targetPeerId)
    {
        if (!TryAddress(packet.Span, 16, out uint destination)) return packet;
        foreach (Rule rule in Volatile.Read(ref _rules))
            if (rule.PeerId == targetPeerId && (destination & rule.Mask) == rule.Exposed && rule.Exposed != rule.Destination)
                return Rewrite(packet, 16, destination, rule.Destination | (destination & ~rule.Mask));
        return packet;
    }

    public ReadOnlyMemory<byte> TranslateInbound(ReadOnlyMemory<byte> packet, ulong sourcePeerId)
    {
        if (!TryAddress(packet.Span, 12, out uint source)) return packet;
        foreach (Rule rule in Volatile.Read(ref _rules))
            if (rule.PeerId == sourcePeerId && (source & rule.Mask) == rule.Destination && rule.Exposed != rule.Destination)
                return Rewrite(packet, 12, source, rule.Exposed | (source & ~rule.Mask));
        return packet;
    }

    private static ReadOnlyMemory<byte> Rewrite(ReadOnlyMemory<byte> packet, int offset, uint oldAddress, uint newAddress)
    {
        byte[] result = packet.ToArray(); Span<byte> bytes = result; int headerLength = (bytes[0] & 0x0f) * 4;
        UpdateTransportChecksum(bytes, headerLength, oldAddress, newAddress);
        BinaryPrimitives.WriteUInt32BigEndian(bytes[offset..], newAddress); bytes[10] = bytes[11] = 0;
        BinaryPrimitives.WriteUInt16BigEndian(bytes[10..], Checksum(bytes[..headerLength])); return result;
    }

    private static void UpdateTransportChecksum(Span<byte> packet, int headerLength, uint oldAddress, uint newAddress)
    {
        if (packet.Length < headerLength + 8 || (BinaryPrimitives.ReadUInt16BigEndian(packet[6..]) & 0x1fff) != 0) return;
        int offset = packet[9] switch { 6 when packet.Length >= headerLength + 20 => headerLength + 16, 17 => headerLength + 6, _ => -1 };
        if (offset < 0) return; ushort checksum = BinaryPrimitives.ReadUInt16BigEndian(packet[offset..]);
        if (packet[9] == 17 && checksum == 0) return;
        uint sum = (uint)(~checksum & 0xffff) + (uint)(~(oldAddress >> 16) & 0xffff) + (newAddress >> 16) + (uint)(~oldAddress & 0xffff) + (newAddress & 0xffff);
        while ((sum >> 16) != 0) sum = (sum & 0xffff) + (sum >> 16);
        ushort updated = unchecked((ushort)~sum); if (packet[9] == 17 && updated == 0) updated = 0xffff;
        BinaryPrimitives.WriteUInt16BigEndian(packet[offset..], updated);
    }

    private static ushort Checksum(ReadOnlySpan<byte> bytes)
    {
        uint sum = 0; int i = 0; for (; i + 1 < bytes.Length; i += 2) sum += BinaryPrimitives.ReadUInt16BigEndian(bytes[i..]);
        if (i < bytes.Length) sum += (uint)bytes[i] << 8; while ((sum >> 16) != 0) sum = (sum & 0xffff) + (sum >> 16);
        return unchecked((ushort)~sum);
    }

    private static bool TryAddress(ReadOnlySpan<byte> packet, int offset, out uint address)
    {
        address = 0; if (packet.Length < 20 || packet[0] >> 4 != 4) return false;
        int length = (packet[0] & 0x0f) * 4; if (length < 20 || length > packet.Length) return false;
        address = BinaryPrimitives.ReadUInt32BigEndian(packet[offset..]); return true;
    }
    private static uint ToUInt32(IPAddress value) => BinaryPrimitives.ReadUInt32BigEndian(value.GetAddressBytes());
    private static uint Mask(int prefix) => prefix == 32 ? uint.MaxValue : uint.MaxValue << (32 - prefix);
    private readonly record struct Rule(uint Exposed, uint Destination, uint Mask, ulong PeerId);
}

internal sealed record TranslationRule(IPAddress ExposedNetwork, IPAddress DestinationNetwork, int PrefixLength, ulong PeerId);
