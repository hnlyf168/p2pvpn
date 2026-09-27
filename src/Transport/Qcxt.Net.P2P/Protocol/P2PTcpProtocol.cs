namespace Qcxt.Net.P2P.Protocol;

/// <summary>表示不分配内存的一次性 TCP 公网映射登记键。</summary>
/// <param name="First">令牌的第一段。</param>
/// <param name="Second">令牌的第二段。</param>
/// <param name="Third">令牌的第三段。</param>
/// <param name="Fourth">令牌的第四段。</param>
internal readonly record struct P2PTcpObservationKey(ulong First, ulong Second, ulong Third, ulong Fourth)
{
    /// <summary>从精确的 32 字节随机令牌创建登记键。</summary>
    /// <param name="token">由已认证 QUIC 注册消息传递的一次性令牌。</param>
    /// <param name="key">解析后的固定长度键。</param>
    /// <returns>令牌长度正确时返回 <see langword="true"/>。</returns>
    public static bool TryCreate(ReadOnlySpan<byte> token, out P2PTcpObservationKey key)
    {
        key = default;
        if (token.Length != 32) return false;
        key = new(BinaryPrimitives.ReadUInt64BigEndian(token), BinaryPrimitives.ReadUInt64BigEndian(token[8..]),
            BinaryPrimitives.ReadUInt64BigEndian(token[16..]), BinaryPrimitives.ReadUInt64BigEndian(token[24..]));
        return true;
    }
}

/// <summary>编码 TCP 公网映射登记和配对专用直连身份认证消息。</summary>
internal static class P2PTcpProtocol
{
    private const uint ObservationMagic = 0x5158544F;
    private const uint DirectMagic = 0x51585444;
    private const byte Version = 1;
    private const int DirectAuthenticatedLength = 40;
    /// <summary>获取 TCP 公网映射登记请求长度。</summary>
    public const int ObservationRequestLength = 40;
    /// <summary>获取 TCP 公网映射登记响应长度。</summary>
    public const int ObservationResponseLength = 28;
    /// <summary>获取 TCP 直连身份消息长度。</summary>
    public const int DirectHelloLength = 72;

    /// <summary>写入携带一次性令牌的 TCP 公网映射登记请求。</summary>
    /// <param name="destination">至少包含 <see cref="ObservationRequestLength"/> 字节的目标缓冲区。</param>
    /// <param name="token">通过已认证 QUIC 控制流登记的 32 字节一次性令牌。</param>
    public static void WriteObservationRequest(Span<byte> destination, ReadOnlySpan<byte> token)
    {
        if (destination.Length < ObservationRequestLength) throw new ArgumentOutOfRangeException(nameof(destination));
        if (token.Length != 32) throw new ArgumentOutOfRangeException(nameof(token));
        Span<byte> message = destination[..ObservationRequestLength];
        message.Clear();
        BinaryPrimitives.WriteUInt32BigEndian(message, ObservationMagic);
        message[4] = Version;
        token.CopyTo(message[8..]);
    }

    /// <summary>校验 TCP 公网映射登记请求并提取一次性登记键。</summary>
    /// <param name="source">完整登记请求。</param>
    /// <param name="key">解析后的登记键。</param>
    /// <returns>协议头和令牌有效时返回 <see langword="true"/>。</returns>
    public static bool TryReadObservationRequest(ReadOnlySpan<byte> source, out P2PTcpObservationKey key)
    {
        key = default;
        return source.Length == ObservationRequestLength &&
            BinaryPrimitives.ReadUInt32BigEndian(source) == ObservationMagic && source[4] == Version &&
            source[5] == 0 && source[6] == 0 && source[7] == 0 &&
            P2PTcpObservationKey.TryCreate(source[8..], out key);
    }

    /// <summary>写入包含服务器观察端点的 TCP 公网映射登记响应。</summary>
    /// <param name="destination">至少包含 <see cref="ObservationResponseLength"/> 字节的目标缓冲区。</param>
    /// <param name="endpoint">服务器观察到的客户端 TCP 端点。</param>
    public static void WriteObservationResponse(Span<byte> destination, IPEndPoint endpoint)
    {
        if (destination.Length < ObservationResponseLength) throw new ArgumentOutOfRangeException(nameof(destination));
        Span<byte> message = destination[..ObservationResponseLength];
        message.Clear();
        BinaryPrimitives.WriteUInt32BigEndian(message, ObservationMagic);
        message[4] = Version;
        message[5] = 1;
        Span<byte> address = message[12..28];
        if (!endpoint.Address.TryWriteBytes(address, out int written) || written is not 4 and not 16)
            throw new ArgumentException("TCP 公网映射地址无效。", nameof(endpoint));
        message[6] = checked((byte)written);
        BinaryPrimitives.WriteUInt16BigEndian(message[8..], checked((ushort)endpoint.Port));
    }

    /// <summary>校验 TCP 公网映射登记响应并读取服务器观察端点。</summary>
    /// <param name="source">完整登记响应。</param>
    /// <param name="endpoint">服务器观察到的客户端 TCP 端点。</param>
    /// <returns>响应字段有效时返回 <see langword="true"/>。</returns>
    public static bool TryReadObservationResponse(ReadOnlySpan<byte> source, out IPEndPoint? endpoint)
    {
        endpoint = null;
        if (source.Length != ObservationResponseLength ||
            BinaryPrimitives.ReadUInt32BigEndian(source) != ObservationMagic || source[4] != Version ||
            source[5] != 1 || source[6] is not 4 and not 16 || source[7] != 0 || source[10] != 0 ||
            source[11] != 0) return false;
        int port = BinaryPrimitives.ReadUInt16BigEndian(source[8..]);
        if (port == 0) return false;
        endpoint = new(new IPAddress(source.Slice(12, source[6])), port);
        return true;
    }

    /// <summary>写入带随机数和配对 HMAC 的 TCP 直连身份消息。</summary>
    /// <param name="destination">至少包含 <see cref="DirectHelloLength"/> 字节的目标缓冲区。</param>
    /// <param name="sourcePeerId">数字形式的来源对端标识。</param>
    /// <param name="targetPeerId">数字形式的目标对端标识。</param>
    /// <param name="pairToken">仅当前两个对端持有的 32 字节配对令牌。</param>
    public static void WriteDirectHello(Span<byte> destination, ulong sourcePeerId, ulong targetPeerId,
        ReadOnlySpan<byte> pairToken)
    {
        if (destination.Length < DirectHelloLength) throw new ArgumentOutOfRangeException(nameof(destination));
        if (sourcePeerId == 0 || targetPeerId == 0 || sourcePeerId == targetPeerId)
            throw new ArgumentOutOfRangeException(nameof(sourcePeerId));
        if (pairToken.Length != 32) throw new ArgumentOutOfRangeException(nameof(pairToken));
        Span<byte> message = destination[..DirectHelloLength];
        message.Clear();
        BinaryPrimitives.WriteUInt32BigEndian(message, DirectMagic);
        message[4] = Version;
        BinaryPrimitives.WriteUInt64BigEndian(message[8..], sourcePeerId);
        BinaryPrimitives.WriteUInt64BigEndian(message[16..], targetPeerId);
        RandomNumberGenerator.Fill(message[24..40]);
        HMACSHA256.HashData(pairToken, message[..DirectAuthenticatedLength], message[DirectAuthenticatedLength..]);
    }

    /// <summary>以常量时间校验 TCP 直连身份消息。</summary>
    /// <param name="source">完整身份消息。</param>
    /// <param name="expectedSourcePeerId">预期的来源对端标识。</param>
    /// <param name="expectedTargetPeerId">预期的目标对端标识。</param>
    /// <param name="pairToken">对应对端配对的 32 字节令牌。</param>
    /// <returns>协议字段、身份和 HMAC 均有效时返回 <see langword="true"/>。</returns>
    public static bool ValidateDirectHello(ReadOnlySpan<byte> source, ulong expectedSourcePeerId,
        ulong expectedTargetPeerId, ReadOnlySpan<byte> pairToken)
    {
        if (source.Length != DirectHelloLength || pairToken.Length != 32 ||
            BinaryPrimitives.ReadUInt32BigEndian(source) != DirectMagic || source[4] != Version ||
            source[5] != 0 || source[6] != 0 || source[7] != 0 ||
            BinaryPrimitives.ReadUInt64BigEndian(source[8..]) != expectedSourcePeerId ||
            BinaryPrimitives.ReadUInt64BigEndian(source[16..]) != expectedTargetPeerId) return false;
        Span<byte> expected = stackalloc byte[32];
        HMACSHA256.HashData(pairToken, source[..DirectAuthenticatedLength], expected);
        bool valid = CryptographicOperations.FixedTimeEquals(expected, source[DirectAuthenticatedLength..]);
        CryptographicOperations.ZeroMemory(expected);
        return valid;
    }

    /// <summary>读取用于定位配对令牌的 TCP 直连路由身份字段。</summary>
    /// <param name="source">完整身份消息。</param>
    /// <param name="sourcePeerId">未认证的来源对端标识。</param>
    /// <param name="targetPeerId">未认证的目标对端标识。</param>
    /// <returns>固定协议头和身份字段结构有效时返回 <see langword="true"/>。</returns>
    public static bool TryReadDirectRoute(ReadOnlySpan<byte> source, out ulong sourcePeerId, out ulong targetPeerId)
    {
        sourcePeerId = targetPeerId = 0;
        if (source.Length != DirectHelloLength || BinaryPrimitives.ReadUInt32BigEndian(source) != DirectMagic ||
            source[4] != Version || source[5] != 0 || source[6] != 0 || source[7] != 0) return false;
        sourcePeerId = BinaryPrimitives.ReadUInt64BigEndian(source[8..]);
        targetPeerId = BinaryPrimitives.ReadUInt64BigEndian(source[16..]);
        return sourcePeerId != 0 && targetPeerId != 0 && sourcePeerId != targetPeerId;
    }

    /// <summary>从流中精确读取指定长度的数据。</summary>
    /// <param name="stream">已连接的网络流。</param>
    /// <param name="destination">目标内存。</param>
    /// <param name="cancellationToken">用于取消读取的标记。</param>
    /// <returns>全部数据到达后结束的异步操作。</returns>
    public static async ValueTask ReadExactlyAsync(Stream stream, Memory<byte> destination,
        CancellationToken cancellationToken)
    {
        int offset = 0;
        while (offset < destination.Length)
        {
            int read = await stream.ReadAsync(destination[offset..], cancellationToken).ConfigureAwait(false);
            if (read == 0) throw new EndOfStreamException("TCP 对端在协议消息读取完成前关闭。");
            offset += read;
        }
    }
}
