using Qcxt.Net.Quic.Memory;
using Qcxt.Net.Quic.Security;

namespace Qcxt.Net.Quic.Protocol;

/// <summary>
/// 表示 Protected Packet Codec，并提供相关数据或行为。
/// </summary>
internal static class ProtectedPacketCodec
{
    private const int PacketNumberLength = 4;

    /// <summary>
    /// 执行Encode Initial操作。
    /// </summary>
    /// <param name="dcid">dcid参数。</param>
    /// <param name="scid">scid参数。</param>
    /// <param name="packetNumber">packet Number参数。</param>
    /// <param name="frames">frames参数。</param>
    /// <param name="protector">protector参数。</param>
    /// <param name="minimumSize">minimum Size参数。</param>
    /// <returns>操作结果。</returns>
    public static PooledDatagram EncodeInitial(QuicConnectionId dcid, QuicConnectionId scid, long packetNumber,
        ReadOnlySpan<byte> frames, AesGcmPacketProtector protector, int minimumSize = 1200)
    {
        int estimatedHeader = 1 + 4 + 1 + dcid.Length + 1 + scid.Length + 1 + 2;
        int total = Math.Max(minimumSize, estimatedHeader + PacketNumberLength + frames.Length + AesGcmPacketProtector.TagLength);
        var packet = PooledDatagram.Rent(total);
        Span<byte> span = packet.WritableMemory.Span;
        int offset = 0;
        span[offset++] = 0xc3;
        BinaryPrimitives.WriteUInt32BigEndian(span[offset..], QuicPacketParser.Version1); offset += 4;
        span[offset++] = dcid.Length; dcid.TryWrite(span[offset..]); offset += dcid.Length;
        span[offset++] = scid.Length; scid.TryWrite(span[offset..]); offset += scid.Length;
        span[offset++] = 0;
        int paddedFrameLength = Math.Max(frames.Length,
            total - estimatedHeader - PacketNumberLength - AesGcmPacketProtector.TagLength);
        int protectedLength = PacketNumberLength + paddedFrameLength + AesGcmPacketProtector.TagLength;
        QuicVarInt.TryWrite(span[offset..], (ulong)protectedLength, out int lengthBytes); offset += lengthBytes;
        int pnOffset = offset;
        BinaryPrimitives.WriteUInt32BigEndian(span[offset..], (uint)packetNumber); offset += PacketNumberLength;
        int cipherOffset = offset;
        byte[] scratch = ArrayPool<byte>.Shared.Rent(paddedFrameLength);
        try
        {
            Span<byte> padded = scratch.AsSpan(0, paddedFrameLength);
            padded.Clear(); frames.CopyTo(padded);
            protector.Encrypt(span[..offset], padded, packetNumber, span.Slice(cipherOffset, paddedFrameLength),
                span.Slice(cipherOffset + paddedFrameLength, AesGcmPacketProtector.TagLength));
        }
        finally { ArrayPool<byte>.Shared.Return(scratch); }
        offset += paddedFrameLength + AesGcmPacketProtector.TagLength;
        ApplyHeaderProtection(span[..offset], pnOffset, longHeader: true, protector);
        packet.Length = offset;
        return packet;
    }

    /// <summary>
    /// 执行Encode One Rtt操作。
    /// </summary>
    /// <param name="dcid">dcid参数。</param>
    /// <param name="packetNumber">packet Number参数。</param>
    /// <param name="frames">frames参数。</param>
    /// <param name="protector">protector参数。</param>
    /// <returns>操作结果。</returns>
    public static PooledDatagram EncodeOneRtt(QuicConnectionId dcid, long packetNumber,
        ReadOnlySpan<byte> frames, AesGcmPacketProtector protector)
    {
        int total = 1 + dcid.Length + PacketNumberLength + frames.Length + AesGcmPacketProtector.TagLength;
        var packet = PooledDatagram.Rent(total);
        Span<byte> span = packet.WritableMemory.Span;
        int offset = 0;
        span[offset++] = 0x43; dcid.TryWrite(span[offset..]); offset += dcid.Length;
        BinaryPrimitives.WriteUInt32BigEndian(span[offset..], (uint)packetNumber); offset += PacketNumberLength;
        protector.Encrypt(span[..offset], frames, packetNumber, span.Slice(offset, frames.Length),
            span.Slice(offset + frames.Length, AesGcmPacketProtector.TagLength));
        ApplyHeaderProtection(span, 1 + dcid.Length, longHeader: false, protector);
        packet.Length = total;
        return packet;
    }

    /// <summary>
    /// 尝试Decode。
    /// </summary>
    /// <param name="packet">packet参数。</param>
    /// <param name="cidLength">cid Length参数。</param>
    /// <param name="protector">protector参数。</param>
    /// <param name="expectedPacketNumber">expected Packet Number参数。</param>
    /// <param name="plaintext">plaintext参数。</param>
    /// <param name="header">header参数。</param>
    /// <param name="packetNumber">packet Number参数。</param>
    /// <param name="plaintextLength">plaintext Length参数。</param>
    /// <returns>操作是否成功。</returns>
    public static bool TryDecode(ReadOnlySpan<byte> packet, int cidLength, AesGcmPacketProtector protector,
        long expectedPacketNumber, Span<byte> plaintext, out QuicPacketHeader header, out long packetNumber,
        out int plaintextLength)
    {
        packetNumber = 0; plaintextLength = 0;
        if (!QuicPacketParser.TryParse(packet, cidLength, out header)) return false;
        int pnOffset = header.ProtectedPayloadOffset;
        if (header.ProtectedPayloadLength < PacketNumberLength + AesGcmPacketProtector.TagLength) return false;
        int cipherOffset = pnOffset + PacketNumberLength;
        int cipherLength = header.ProtectedPayloadLength - PacketNumberLength - AesGcmPacketProtector.TagLength;
        if (cipherLength > plaintext.Length) return false;
        byte[]? rentedHeader = null;
        Span<byte> unprotectedHeader = cipherOffset <= 128
            ? stackalloc byte[cipherOffset]
            : (rentedHeader = ArrayPool<byte>.Shared.Rent(cipherOffset)).AsSpan(0, cipherOffset);
        try
        {
            packet[..cipherOffset].CopyTo(unprotectedHeader);
            Span<byte> mask = stackalloc byte[5];
            if (!protector.TryCreateHeaderMask(packet[cipherOffset..], mask, sending: false)) return false;
            bool longHeader = (unprotectedHeader[0] & 0x80) != 0;
            unprotectedHeader[0] ^= (byte)(mask[0] & (longHeader ? 0x0f : 0x1f));
            for (int i = 0; i < PacketNumberLength; i++) unprotectedHeader[pnOffset + i] ^= mask[i + 1];
            uint truncated = BinaryPrimitives.ReadUInt32BigEndian(unprotectedHeader[pnOffset..]);
            packetNumber = DecodePacketNumber(truncated, expectedPacketNumber);
            if (!protector.TryDecrypt(unprotectedHeader, packet.Slice(cipherOffset, cipherLength), packetNumber,
                packet.Slice(cipherOffset + cipherLength, AesGcmPacketProtector.TagLength), plaintext)) return false;
            plaintextLength = cipherLength;
            return true;
        }
        finally
        {
            if (rentedHeader is not null) ArrayPool<byte>.Shared.Return(rentedHeader, clearArray: true);
        }
    }

    /// <summary>
    /// 执行Decode Packet Number操作。
    /// </summary>
    /// <param name="truncated">truncated参数。</param>
    /// <param name="expected">expected参数。</param>
    /// <returns>操作结果。</returns>
    private static long DecodePacketNumber(uint truncated, long expected)
    {
        const long window = 1L << 32;
        const long halfWindow = window / 2;
        long candidate = (expected & ~(window - 1)) | truncated;
        if (candidate <= expected - halfWindow && candidate < (long)QuicVarInt.MaxValue - window) candidate += window;
        else if (candidate > expected + halfWindow && candidate >= window) candidate -= window;
        return candidate;
    }

    /// <summary>
    /// 执行Apply Header Protection操作。
    /// </summary>
    /// <param name="packet">packet参数。</param>
    /// <param name="packetNumberOffset">packet Number Offset参数。</param>
    /// <param name="longHeader">long Header参数。</param>
    /// <param name="protector">protector参数。</param>
    private static void ApplyHeaderProtection(Span<byte> packet, int packetNumberOffset, bool longHeader,
        AesGcmPacketProtector protector)
    {
        Span<byte> mask = stackalloc byte[5];
        if (!protector.TryCreateHeaderMask(packet[(packetNumberOffset + PacketNumberLength)..], mask, sending: true))
            throw new InvalidOperationException("A protected packet must provide a complete header-protection sample.");
        packet[0] ^= (byte)(mask[0] & (longHeader ? 0x0f : 0x1f));
        for (int i = 0; i < PacketNumberLength; i++) packet[packetNumberOffset + i] ^= mask[i + 1];
    }
}
