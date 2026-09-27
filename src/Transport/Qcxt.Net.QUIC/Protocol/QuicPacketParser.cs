namespace Qcxt.Net.Quic.Protocol;

/// <summary>
/// 表示 Quic Packet Type，并提供相关数据或行为。
/// </summary>
internal enum QuicPacketType : byte { /// <summary>
/// 表示Initial选项。
/// </summary>
Initial, /// <summary>
/// 表示Zero Rtt选项。
/// </summary>
ZeroRtt, /// <summary>
/// 表示Handshake选项。
/// </summary>
Handshake, /// <summary>
/// 表示Retry选项。
/// </summary>
Retry, /// <summary>
/// 表示One Rtt选项。
/// </summary>
OneRtt, /// <summary>
/// 表示Version Negotiation选项。
/// </summary>
VersionNegotiation }

/// <summary>
/// 表示 Quic Packet Header，并提供相关数据或行为。
/// </summary>
/// <param name="Type">Type参数。</param>
/// <param name="Version">Version参数。</param>
/// <param name="DestinationConnectionId">Destination Connection Id参数。</param>
/// <param name="SourceConnectionId">Source Connection Id参数。</param>
/// <param name="PacketOffset">Packet Offset参数。</param>
/// <param name="PacketLength">Packet Length参数。</param>
/// <param name="ProtectedPayloadOffset">Protected Payload Offset参数。</param>
/// <param name="ProtectedPayloadLength">Protected Payload Length参数。</param>
/// <param name="TokenOffset">Token Offset参数。</param>
/// <param name="TokenLength">Token Length参数。</param>
/// <param name="KeyPhase">Key Phase参数。</param>
internal readonly record struct QuicPacketHeader(
    QuicPacketType Type, uint Version, QuicConnectionId DestinationConnectionId,
    QuicConnectionId SourceConnectionId, int PacketOffset, int PacketLength,
    int ProtectedPayloadOffset, int ProtectedPayloadLength, int TokenOffset, int TokenLength,
    bool KeyPhase);

/// <summary>
/// 表示 Quic Packet Parser，并提供相关数据或行为。
/// </summary>
internal static class QuicPacketParser
{
    public const uint Version1 = 0x0000_0001;

    /// <summary>
    /// 尝试Parse。
    /// </summary>
    /// <param name="datagram">datagram参数。</param>
    /// <param name="shortHeaderCidLength">short Header Cid Length参数。</param>
    /// <param name="header">header参数。</param>
    /// <returns>操作是否成功。</returns>
    public static bool TryParse(ReadOnlySpan<byte> datagram, int shortHeaderCidLength, out QuicPacketHeader header)
    {
        header = default;
        if (datagram.IsEmpty) return false;
        return (datagram[0] & 0x80) != 0
            ? TryParseLong(datagram, out header)
            : TryParseShort(datagram, shortHeaderCidLength, out header);
    }

    /// <summary>
    /// 尝试Read Destination Connection Id。
    /// </summary>
    /// <param name="datagram">datagram参数。</param>
    /// <param name="shortHeaderCidLength">short Header Cid Length参数。</param>
    /// <param name="connectionId">connection Id参数。</param>
    /// <param name="isInitial">is Initial参数。</param>
    /// <returns>操作是否成功。</returns>
    public static bool TryReadDestinationConnectionId(ReadOnlySpan<byte> datagram, int shortHeaderCidLength,
        out QuicConnectionId connectionId, out bool isInitial)
    {
        connectionId = default; isInitial = false;
        if (datagram.IsEmpty) return false;
        if ((datagram[0] & 0x80) == 0)
        {
            if (shortHeaderCidLength is < 1 or > QuicConnectionId.MaxLength || datagram.Length < 1 + shortHeaderCidLength) return false;
            return QuicConnectionId.TryRead(datagram.Slice(1, shortHeaderCidLength), out connectionId);
        }
        if (datagram.Length < 6) return false;
        int length = datagram[5];
        if (length > QuicConnectionId.MaxLength || datagram.Length < 6 + length) return false;
        isInitial = ((datagram[0] >> 4) & 0x03) == 0;
        return QuicConnectionId.TryRead(datagram.Slice(6, length), out connectionId);
    }

    /// <summary>
    /// 尝试Parse Long。
    /// </summary>
    /// <param name="source">source参数。</param>
    /// <param name="header">header参数。</param>
    /// <returns>操作是否成功。</returns>
    private static bool TryParseLong(ReadOnlySpan<byte> source, out QuicPacketHeader header)
    {
        header = default;
        if (source.Length < 7) return false;
        byte flags = source[0];
        uint version = BinaryPrimitives.ReadUInt32BigEndian(source[1..]);
        int offset = 5;
        int dcidLength = source[offset++];
        if (dcidLength > QuicConnectionId.MaxLength || dcidLength > source.Length - offset) return false;
        if (!QuicConnectionId.TryRead(source.Slice(offset, dcidLength), out var dcid)) return false;
        offset += dcidLength;
        if (offset >= source.Length) return false;
        int scidLength = source[offset++];
        if (scidLength > QuicConnectionId.MaxLength || scidLength > source.Length - offset) return false;
        if (!QuicConnectionId.TryRead(source.Slice(offset, scidLength), out var scid)) return false;
        offset += scidLength;

        if (version == 0)
        {
            if ((source.Length - offset) < 4 || ((source.Length - offset) & 3) != 0) return false;
            header = new(QuicPacketType.VersionNegotiation, 0, dcid, scid, 0, source.Length, offset,
                source.Length - offset, 0, 0, false);
            return true;
        }
        if ((flags & 0x40) == 0) return false;
        var type = (QuicPacketType)((flags >> 4) & 0x03);
        if (type == QuicPacketType.Retry)
        {
            if (source.Length - offset < 16) return false;
            header = new(type, version, dcid, scid, 0, source.Length, offset, source.Length - offset,
                offset, source.Length - offset - 16, false);
            return true;
        }

        int tokenOffset = 0, tokenLength = 0;
        if (type == QuicPacketType.Initial)
        {
            if (!QuicVarInt.TryRead(source[offset..], out var tokenLength64, out int read)) return false;
            offset += read;
            if (tokenLength64 > (ulong)(source.Length - offset)) return false;
            tokenOffset = offset; tokenLength = (int)tokenLength64; offset += tokenLength;
        }
        if (!QuicVarInt.TryRead(source[offset..], out var payloadLength64, out int lengthBytes)) return false;
        offset += lengthBytes;
        if (payloadLength64 > (ulong)(source.Length - offset)) return false;
        int payloadLength = (int)payloadLength64;
        header = new(type, version, dcid, scid, 0, offset + payloadLength, offset, payloadLength,
            tokenOffset, tokenLength, false);
        return true;
    }

    /// <summary>
    /// 尝试Parse Short。
    /// </summary>
    /// <param name="source">source参数。</param>
    /// <param name="cidLength">cid Length参数。</param>
    /// <param name="header">header参数。</param>
    /// <returns>操作是否成功。</returns>
    private static bool TryParseShort(ReadOnlySpan<byte> source, int cidLength, out QuicPacketHeader header)
    {
        header = default;
        if (cidLength is < 1 or > QuicConnectionId.MaxLength || source.Length < 1 + cidLength + 17) return false;
        if ((source[0] & 0x40) == 0) return false;
        if (!QuicConnectionId.TryRead(source.Slice(1, cidLength), out var dcid)) return false;
        int offset = 1 + cidLength;
        header = new(QuicPacketType.OneRtt, Version1, dcid, default, 0, source.Length, offset,
            source.Length - offset, 0, 0, (source[0] & 0x04) != 0);
        return true;
    }
}
