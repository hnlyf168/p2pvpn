namespace Qcxt.Net.Quic.Protocol;

/// <summary>以内联方式存储连接标识符，避免分配托管数组。</summary>
public readonly struct QuicConnectionId : IEquatable<QuicConnectionId>
{
    /// <summary>获取支持的最大标识符长度。</summary>
    public const int MaxLength = 20;
    private readonly ulong _a, _b;
    private readonly uint _c;
    /// <summary>获取标识符的字节长度。</summary>
    public byte Length { get; }
    /// <summary>
    /// 初始化 <see cref="QuicConnectionId"/> 类的新实例。
    /// </summary>
    /// <param name="a">a参数。</param>
    /// <param name="b">b参数。</param>
    /// <param name="c">c参数。</param>
    /// <param name="length">数据数量。</param>
    private QuicConnectionId(ulong a, ulong b, uint c, byte length) => (_a, _b, _c, Length) = (a, b, c, length);

    /// <summary>尝试从来源字节创建标识符。</summary>
    /// <param name="source">零到二十个标识符字节。</param>
    /// <param name="value">接收创建的标识符。</param>
    /// <returns>长度受支持时返回 <see langword="true"/>。</returns>
    public static bool TryRead(ReadOnlySpan<byte> source, out QuicConnectionId value)
    {
        value = default;
        if (source.Length > MaxLength) return false;
        Span<byte> storage = stackalloc byte[MaxLength];
        source.CopyTo(storage);
        value = new(BinaryPrimitives.ReadUInt64BigEndian(storage),
            BinaryPrimitives.ReadUInt64BigEndian(storage[8..]),
            BinaryPrimitives.ReadUInt32BigEndian(storage[16..]), (byte)source.Length);
        return true;
    }

    /// <summary>创建密码学安全的随机标识符。</summary>
    /// <param name="length">一到二十字节的长度。</param>
    /// <returns>生成的标识符。</returns>
    public static QuicConnectionId CreateRandom(int length)
    {
        if (length is < 1 or > MaxLength) throw new ArgumentOutOfRangeException(nameof(length));
        Span<byte> bytes = stackalloc byte[MaxLength];
        RandomNumberGenerator.Fill(bytes[..length]);
        TryRead(bytes[..length], out var value);
        return value;
    }

    /// <summary>尝试将当前标识符写入目标区域。</summary>
    /// <param name="destination">目标字节区域。</param>
    /// <returns>目标区域足够大时返回 <see langword="true"/>。</returns>
    public bool TryWrite(Span<byte> destination)
    {
        if (destination.Length < Length) return false;
        Span<byte> storage = stackalloc byte[MaxLength];
        BinaryPrimitives.WriteUInt64BigEndian(storage, _a);
        BinaryPrimitives.WriteUInt64BigEndian(storage[8..], _b);
        BinaryPrimitives.WriteUInt32BigEndian(storage[16..], _c);
        storage[..Length].CopyTo(destination);
        return true;
    }

    /// <inheritdoc />
    public bool Equals(QuicConnectionId other) => Length == other.Length && _a == other._a && _b == other._b && _c == other._c;
    /// <inheritdoc />
    public override bool Equals(object? obj) => obj is QuicConnectionId other && Equals(other);
    /// <inheritdoc />
    public override int GetHashCode() => HashCode.Combine(_a, _b, _c, Length);
    /// <summary>判断两个标识符是否相等。</summary>
    /// <param name="x">左侧标识符。</param><param name="y">右侧标识符。</param>
    /// <returns>两个标识符相等时返回 <see langword="true"/>。</returns>
    public static bool operator ==(QuicConnectionId x, QuicConnectionId y) => x.Equals(y);
    /// <summary>判断两个标识符是否不相等。</summary>
    /// <param name="x">左侧标识符。</param><param name="y">右侧标识符。</param>
    /// <returns>两个标识符不相等时返回 <see langword="true"/>。</returns>
    public static bool operator !=(QuicConnectionId x, QuicConnectionId y) => !x.Equals(y);
}
