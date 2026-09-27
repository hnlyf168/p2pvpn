namespace Qcxt.Net.Quic.Protocol;

/// <summary>读取和写入 QUIC 定义的变长整数编码。</summary>
public static class QuicVarInt
{
    /// <summary>获取可编码的最大值。</summary>
    public const ulong MaxValue = (1UL << 62) - 1;
    /// <summary>获取指定值编码后的字节数。</summary>
    /// <param name="value">要测量的值。</param>
    /// <returns>返回一、二、四或八；值超出范围时返回零。</returns>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static int GetEncodedLength(ulong value) => value switch
    {
        <= 63 => 1, <= 16_383 => 2, <= 1_073_741_823 => 4, <= MaxValue => 8, _ => 0
    };

    /// <summary>尝试在不分配内存的情况下解码变长整数。</summary>
    /// <param name="source">已编码的来源字节。</param>
    /// <param name="value">接收解码后的值。</param>
    /// <param name="consumed">接收已消耗的字节数。</param>
    /// <returns>成功解码完整值时返回 <see langword="true"/>。</returns>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static bool TryRead(ReadOnlySpan<byte> source, out ulong value, out int consumed)
    {
        value = 0; consumed = 0;
        if (source.IsEmpty) return false;
        int length = 1 << (source[0] >> 6);
        if (source.Length < length) return false;
        value = length switch
        {
            1 => (ulong)(source[0] & 0x3f),
            2 => BinaryPrimitives.ReadUInt16BigEndian(source) & 0x3fffUL,
            4 => BinaryPrimitives.ReadUInt32BigEndian(source) & 0x3fff_ffffUL,
            _ => BinaryPrimitives.ReadUInt64BigEndian(source) & MaxValue
        };
        consumed = length;
        return true;
    }

    /// <summary>尝试在不分配内存的情况下编码变长整数。</summary>
    /// <param name="destination">目标字节区域。</param>
    /// <param name="value">要编码的值。</param>
    /// <param name="written">接收已写入的字节数。</param>
    /// <returns>值和目标区域有效时返回 <see langword="true"/>。</returns>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static bool TryWrite(Span<byte> destination, ulong value, out int written)
    {
        written = GetEncodedLength(value);
        if (written == 0 || destination.Length < written) { written = 0; return false; }
        switch (written)
        {
            case 1: destination[0] = (byte)value; break;
            case 2: BinaryPrimitives.WriteUInt16BigEndian(destination, (ushort)(value | 0x4000)); break;
            case 4: BinaryPrimitives.WriteUInt32BigEndian(destination, (uint)(value | 0x8000_0000)); break;
            default: BinaryPrimitives.WriteUInt64BigEndian(destination, value | 0xc000_0000_0000_0000); break;
        }
        return true;
    }
}
