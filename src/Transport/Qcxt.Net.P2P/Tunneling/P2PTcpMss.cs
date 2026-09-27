using System.Buffers.Binary;

namespace Qcxt.Net.P2P.Tunneling;

/// <summary>Bounds TCP handshake segment sizes before a packet crosses the VPN.
/// Applies equally to TUN, veth and program gateways; does not modify host firewall rules.</summary>
public static class P2PTcpMss
{
    /// <summary>Clamp existing MSS options in SYN/SYN-ACK, preserving lower values.
    /// Returns the original memory for ordinary data, fragments and malformed/unsupported headers.</summary>
    public static ReadOnlyMemory<byte> Clamp(ReadOnlyMemory<byte> packet, int mtu)
    {
        var p = packet.Span;
        if (p.Length < 20 || mtu < 68 || mtu > 65535) return packet;
        int tcp, maximum;
        if (p[0] >> 4 == 4)
        {
            tcp = (p[0] & 15) * 4;
            if (tcp < 20 || p[9] != 6 || BinaryPrimitives.ReadUInt16BigEndian(p[2..]) != p.Length ||
                (BinaryPrimitives.ReadUInt16BigEndian(p[6..]) & 0x3fff) != 0) return packet;
            maximum = mtu - tcp - 20;
        }
        else if (p[0] >> 4 == 6)
        {
            if (p.Length < 40 || BinaryPrimitives.ReadUInt16BigEndian(p[4..]) + 40 != p.Length) return packet;
            tcp = 40; int next = p[6], count = 0;
            // Do not rewrite fragmented packets, authenticated headers or routing headers.
            while (next is 0 or 60)
            {
                if (++count > 8 || tcp + 2 > p.Length) return packet;
                int size = (p[tcp + 1] + 1) * 8;
                if (tcp + size > p.Length) return packet;
                next = p[tcp]; tcp += size;
            }
            if (next != 6) return packet;
            maximum = mtu - tcp - 20;
        }
        else return packet;
        if (maximum < 1 || tcp + 20 > p.Length || (p[tcp + 13] & 0x06) != 0x02) return packet;
        int end = tcp + (p[tcp + 12] >> 4) * 4;
        if (end < tcp + 20 || end > p.Length) return packet;
        bool change = false;
        // Validate the complete options area before changing anything.
        for (int i = tcp + 20; i < end;)
        {
            byte kind = p[i]; if (kind == 0) break;
            if (kind == 1) { i++; continue; }
            if (i + 2 > end || p[i + 1] < 2 || i + p[i + 1] > end) return packet;
            if (kind == 2)
            {
                if (p[i + 1] != 4) return packet;
                if (BinaryPrimitives.ReadUInt16BigEndian(p[(i + 2)..]) > maximum) change = true;
            }
            // TCP MD5 / TCP-AO authenticate the header; rewriting would invalidate them.
            if (kind is 19 or 29) return packet;
            i += p[i + 1];
        }
        if (!change) return packet;
        byte[] result = packet.ToArray(); var b = result.AsSpan();
        uint sum = (uint)(~BinaryPrimitives.ReadUInt16BigEndian(b[(tcp + 16)..]) & 0xffff);
        for (int i = tcp + 20; i < end;)
        {
            byte kind = b[i]; if (kind == 0) break;
            if (kind == 1) { i++; continue; }
            if (kind == 2)
            {
                ushort old = BinaryPrimitives.ReadUInt16BigEndian(b[(i + 2)..]);
                if (old > maximum)
                {
                    ushort value = (ushort)maximum;
                    BinaryPrimitives.WriteUInt16BigEndian(b[(i + 2)..], value);
                    // An MSS option can follow a NOP and be unaligned to TCP checksum words.
                    if (((i + 2 - tcp) & 1) != 0)
                    { old = BinaryPrimitives.ReverseEndianness(old); value = BinaryPrimitives.ReverseEndianness(value); }
                    sum += (uint)(~old & 0xffff) + value;
                    while (sum >> 16 != 0) sum = (sum & 0xffff) + (sum >> 16);
                }
            }
            i += b[i + 1];
        }
        BinaryPrimitives.WriteUInt16BigEndian(b[(tcp + 16)..], (ushort)~sum);
        return result;
    }
}
