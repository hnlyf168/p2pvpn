namespace Qcxt.Net.P2P.Protocol;

/// <summary>标识可靠的协调服务器控制消息。</summary>
internal enum P2PControlType : byte
{
    /// <summary>
    /// 表示Register选项。
    /// </summary>
    Register = 1,
    /// <summary>
    /// 表示Registered选项。
    /// </summary>
    Registered = 2,
    /// <summary>
    /// 表示Peer Offer选项。
    /// </summary>
    PeerOffer = 3,
    /// <summary>
    /// 表示Peer Gone选项。
    /// </summary>
    PeerGone = 4,
    /// <summary>
    /// 表示Punch Request选项。
    /// </summary>
    PunchRequest = 5,
    /// <summary>
    /// 表示Relay Reliable选项。
    /// </summary>
    RelayReliable = 6,
    /// <summary>
    /// 表示Ping选项。
    /// </summary>
    Ping = 7,
    /// <summary>
    /// 表示Error选项。
    /// </summary>
    Error = 8
}

/// <summary>表示一条已解码的协调服务器消息。</summary>
internal sealed record P2PControlMessage(P2PControlType Type, string SessionId = "", string PeerId = "",
    ulong SourcePeerId = 0, ulong TargetPeerId = 0, IPEndPoint? PublicEndPoint = null,
    IPEndPoint? PrivateEndPoint = null, IPEndPoint? TcpPublicEndPoint = null,
    IPEndPoint? TcpPrivateEndPoint = null, byte[]? Token = null, ReadOnlyMemory<byte> Payload = default,
    P2PTrafficClass TrafficClass = P2PTrafficClass.Normal, string Error = "", uint VirtualAddress = 0,
    byte VirtualPrefixLength = 0);

/// <summary>通过一条可靠 QUIC 流序列化有界的协调服务器消息。</summary>
internal sealed class P2PControlChannel : IAsyncDisposable
{
    private const uint Magic = 0x51584332;
    private const byte Version = 5;
    private const int MaximumMessageLength = 256 * 1024;
    private readonly QuicStream _stream;
    private readonly SemaphoreSlim _sendLock = new(1, 1);
    private int _disposed;

    /// <summary>在专用双向流上创建带帧控制通道。</summary>
    /// <param name="stream">具有所有权的双向 QUIC 流。</param>
    public P2PControlChannel(QuicStream stream)
    {
        ArgumentNullException.ThrowIfNull(stream);
        if (!stream.CanRead || !stream.CanWrite) throw new ArgumentException("必须提供双向流。", nameof(stream));
        _stream = stream;
    }

    /// <summary>在每流写锁保护下写入一条完整控制消息。</summary>
    /// <param name="message">要编码的消息。</param>
    /// <param name="cancellationToken">用于取消有界传输排队的标记。</param>
    /// <returns>字节进入 QUIC 发送队列后结束的异步操作。</returns>
    public async ValueTask SendAsync(P2PControlMessage message, CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) != 0, this);
        using P2POwnedBuffer encoded = Encode(message);
        byte[] header = ArrayPool<byte>.Shared.Rent(4);
        await _sendLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            BinaryPrimitives.WriteInt32BigEndian(header, encoded.Length);
            await _stream.WriteAsync(header.AsMemory(0, 4), cancellationToken).ConfigureAwait(false);
            await _stream.WriteAsync(encoded.Memory, cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            _sendLock.Release();
            ArrayPool<byte>.Shared.Return(header);
        }
    }

    /// <summary>读取、限制并解码一条完整控制消息。</summary>
    /// <param name="cancellationToken">用于取消等待的标记。</param>
    /// <returns>已解码的消息；收到正常 FIN 后返回 <see langword="null"/>。</returns>
    public async ValueTask<P2PControlMessage?> ReceiveAsync(CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) != 0, this);
        byte[] header = ArrayPool<byte>.Shared.Rent(4);
        try
        {
            if (!await ReadExactlyAsync(header.AsMemory(0, 4), allowEndOfStream: true, cancellationToken).ConfigureAwait(false))
                return null;
            int length = BinaryPrimitives.ReadInt32BigEndian(header);
            if (length is < 8 or > MaximumMessageLength) throw new InvalidDataException("协调服务器消息长度无效。");
            using P2POwnedBuffer owner = P2POwnedBuffer.Rent(length);
            await ReadExactlyAsync(owner.Memory, allowEndOfStream: false, cancellationToken).ConfigureAwait(false);
            if (!TryDecode(owner.Memory.Span, out P2PControlMessage? message))
                throw new InvalidDataException("协调服务器消息格式错误。");
            return message;
        }
        finally { ArrayPool<byte>.Shared.Return(header); }
    }

    /// <summary>精确读取一个指定的内存区域。</summary>
    /// <param name="destination">目标内存。</param>
    /// <param name="allowEndOfStream">首字节前读取零字节是否表示有效 FIN。</param>
    /// <param name="cancellationToken">用于取消读取的标记。</param>
    /// <returns>仅当未读取任何字节便收到允许的 FIN 时返回 <see langword="false"/>。</returns>
    private async ValueTask<bool> ReadExactlyAsync(Memory<byte> destination, bool allowEndOfStream,
        CancellationToken cancellationToken)
    {
        int offset = 0;
        while (offset < destination.Length)
        {
            int read = await _stream.ReadAsync(destination[offset..], cancellationToken).ConfigureAwait(false);
            if (read == 0)
            {
                if (allowEndOfStream && offset == 0) return false;
                throw new EndOfStreamException("协调服务器流在消息读取过程中关闭。");
            }
            offset += read;
        }
        return true;
    }

    /// <summary>将一条控制消息编码到池化内存。</summary>
    /// <param name="message">要编码的消息。</param>
    /// <returns>包含已编码消息的缓冲区所有者。</returns>
    private static P2POwnedBuffer Encode(P2PControlMessage message)
    {
        byte[] session = Encoding.UTF8.GetBytes(message.SessionId);
        byte[] peer = Encoding.UTF8.GetBytes(message.PeerId);
        byte[] error = Encoding.UTF8.GetBytes(message.Error);
        byte[] token = message.Token ?? [];
        ReadOnlyMemory<byte> payload = message.Payload;
        if (session.Length > 1024 || peer.Length > 1024 || error.Length > 4096 ||
            token.Length is not 0 and not 32 || payload.Length > MaximumMessageLength - 128)
            throw new ArgumentOutOfRangeException(nameof(message));
        int length = 8 + 8 + 8 + 4 + 1 + 2 + session.Length + 2 + peer.Length + EndpointLength(message.PublicEndPoint) +
            EndpointLength(message.PrivateEndPoint) + EndpointLength(message.TcpPublicEndPoint) +
            EndpointLength(message.TcpPrivateEndPoint) + 1 + token.Length + 1 + 4 + payload.Length +
            2 + error.Length;
        if (length > MaximumMessageLength) throw new ArgumentOutOfRangeException(nameof(message));
        P2POwnedBuffer owner = P2POwnedBuffer.Rent(length);
        Span<byte> buffer = owner.Memory.Span;
        BinaryPrimitives.WriteUInt32BigEndian(buffer, Magic);
        buffer[4] = Version;
        buffer[5] = (byte)message.Type;
        buffer[6] = buffer[7] = 0;
        int offset = 8;
        BinaryPrimitives.WriteUInt64BigEndian(buffer[offset..], message.SourcePeerId); offset += 8;
        BinaryPrimitives.WriteUInt64BigEndian(buffer[offset..], message.TargetPeerId); offset += 8;
        BinaryPrimitives.WriteUInt32BigEndian(buffer[offset..], message.VirtualAddress); offset += 4;
        buffer[offset++] = message.VirtualPrefixLength;
        WriteBytes16(buffer, ref offset, session);
        WriteBytes16(buffer, ref offset, peer);
        WriteEndPoint(buffer, ref offset, message.PublicEndPoint);
        WriteEndPoint(buffer, ref offset, message.PrivateEndPoint);
        WriteEndPoint(buffer, ref offset, message.TcpPublicEndPoint);
        WriteEndPoint(buffer, ref offset, message.TcpPrivateEndPoint);
        buffer[offset++] = (byte)token.Length;
        token.CopyTo(buffer[offset..]); offset += token.Length;
        buffer[offset++] = (byte)message.TrafficClass;
        BinaryPrimitives.WriteInt32BigEndian(buffer[offset..], payload.Length); offset += 4;
        payload.Span.CopyTo(buffer[offset..]); offset += payload.Length;
        WriteBytes16(buffer, ref offset, error);
        return owner;
    }

    /// <summary>解码一条长度精确的控制消息。</summary>
    /// <param name="buffer">完整的已编码消息。</param>
    /// <param name="message">解码后的消息。</param>
    /// <returns>所有字段均有效时返回 <see langword="true"/>。</returns>
    private static bool TryDecode(ReadOnlySpan<byte> buffer, out P2PControlMessage? message)
    {
        message = null;
        if (buffer.Length < 43 || BinaryPrimitives.ReadUInt32BigEndian(buffer) != Magic || buffer[4] != Version ||
            buffer[5] is < 1 or > 8 || buffer[6] != 0 || buffer[7] != 0) return false;
        P2PControlType type = (P2PControlType)buffer[5];
        int offset = 8;
        ulong source = BinaryPrimitives.ReadUInt64BigEndian(buffer[offset..]); offset += 8;
        ulong target = BinaryPrimitives.ReadUInt64BigEndian(buffer[offset..]); offset += 8;
        uint virtualAddress = BinaryPrimitives.ReadUInt32BigEndian(buffer[offset..]); offset += 4;
        byte virtualPrefixLength = buffer[offset++];
        if (virtualPrefixLength != 0 && virtualPrefixLength is < 8 or > 30) return false;
        if (!TryReadString16(buffer, ref offset, 1024, out string session) ||
            !TryReadString16(buffer, ref offset, 1024, out string peer) ||
            !TryReadEndPoint(buffer, ref offset, out IPEndPoint? publicEndPoint) ||
            !TryReadEndPoint(buffer, ref offset, out IPEndPoint? privateEndPoint) ||
            !TryReadEndPoint(buffer, ref offset, out IPEndPoint? tcpPublicEndPoint) ||
            !TryReadEndPoint(buffer, ref offset, out IPEndPoint? tcpPrivateEndPoint) || offset >= buffer.Length) return false;
        int tokenLength = buffer[offset++];
        if (tokenLength is not 0 and not 32 || tokenLength > buffer.Length - offset) return false;
        byte[]? token = tokenLength == 0 ? null : buffer.Slice(offset, tokenLength).ToArray(); offset += tokenLength;
        if (offset + 5 > buffer.Length || buffer[offset] > (byte)P2PTrafficClass.Bulk) return false;
        P2PTrafficClass traffic = (P2PTrafficClass)buffer[offset++];
        int payloadLength = BinaryPrimitives.ReadInt32BigEndian(buffer[offset..]); offset += 4;
        if (payloadLength < 0 || payloadLength > buffer.Length - offset) return false;
        ReadOnlyMemory<byte> payload = payloadLength == 0 ? ReadOnlyMemory<byte>.Empty :
            buffer.Slice(offset, payloadLength).ToArray(); offset += payloadLength;
        if (!TryReadString16(buffer, ref offset, 4096, out string error) || offset != buffer.Length) return false;
        message = new(type, session, peer, source, target, publicEndPoint, privateEndPoint,
            tcpPublicEndPoint, tcpPrivateEndPoint, token, payload, traffic, error, virtualAddress,
            virtualPrefixLength);
        return true;
    }

    /// <summary>
    /// 执行Endpoint Length操作。
    /// </summary>
    /// <param name="endpoint">网络端点。</param>
    /// <returns>操作结果。</returns>
    private static int EndpointLength(IPEndPoint? endpoint) => endpoint is null ? 1 :
        endpoint.AddressFamily == AddressFamily.InterNetwork ? 7 : 19;

    /// <summary>
    /// 执行Write Bytes16操作。
    /// </summary>
    /// <param name="destination">destination参数。</param>
    /// <param name="offset">数据起始偏移量。</param>
    /// <param name="value">待处理的值。</param>
    private static void WriteBytes16(Span<byte> destination, ref int offset, ReadOnlySpan<byte> value)
    {
        BinaryPrimitives.WriteUInt16BigEndian(destination[offset..], checked((ushort)value.Length)); offset += 2;
        value.CopyTo(destination[offset..]); offset += value.Length;
    }

    /// <summary>
    /// 尝试Read String16。
    /// </summary>
    /// <param name="source">source参数。</param>
    /// <param name="offset">数据起始偏移量。</param>
    /// <param name="maximum">maximum参数。</param>
    /// <param name="value">待处理的值。</param>
    /// <returns>操作是否成功。</returns>
    private static bool TryReadString16(ReadOnlySpan<byte> source, ref int offset, int maximum, out string value)
    {
        value = "";
        if (offset + 2 > source.Length) return false;
        int length = BinaryPrimitives.ReadUInt16BigEndian(source[offset..]); offset += 2;
        if (length > maximum || length > source.Length - offset) return false;
        value = Encoding.UTF8.GetString(source.Slice(offset, length)); offset += length;
        return true;
    }

    /// <summary>
    /// 执行Write End Point操作。
    /// </summary>
    /// <param name="destination">destination参数。</param>
    /// <param name="offset">数据起始偏移量。</param>
    /// <param name="endpoint">网络端点。</param>
    private static void WriteEndPoint(Span<byte> destination, ref int offset, IPEndPoint? endpoint)
    {
        if (endpoint is null) { destination[offset++] = 0; return; }
        Span<byte> address = stackalloc byte[16];
        if (!endpoint.Address.TryWriteBytes(address, out int written)) throw new ArgumentException("端点地址无效。");
        destination[offset++] = checked((byte)written);
        address[..written].CopyTo(destination[offset..]); offset += written;
        BinaryPrimitives.WriteUInt16BigEndian(destination[offset..], checked((ushort)endpoint.Port)); offset += 2;
    }

    /// <summary>
    /// 尝试Read End Point。
    /// </summary>
    /// <param name="source">source参数。</param>
    /// <param name="offset">数据起始偏移量。</param>
    /// <param name="endpoint">网络端点。</param>
    /// <returns>操作是否成功。</returns>
    private static bool TryReadEndPoint(ReadOnlySpan<byte> source, ref int offset, out IPEndPoint? endpoint)
    {
        endpoint = null;
        if (offset >= source.Length) return false;
        int length = source[offset++];
        if (length == 0) return true;
        if (length is not 4 and not 16 || offset + length + 2 > source.Length) return false;
        IPAddress address = new(source.Slice(offset, length)); offset += length;
        int port = BinaryPrimitives.ReadUInt16BigEndian(source[offset..]); offset += 2;
        if (port == 0) return false;
        endpoint = new IPEndPoint(address, port);
        return true;
    }

    /// <summary>以幂等方式关闭流并释放写锁。</summary>
    /// <returns>流释放后结束的异步操作。</returns>
    public async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0) return;
        await _stream.DisposeAsync().ConfigureAwait(false);
        _sendLock.Dispose();
    }
}

/// <summary>以零分配方式编码热路径上的不可靠中转数据报。</summary>
internal static class P2PRelayDatagramCodec
{
    private const uint Magic = 0x51585232;
    public const int HeaderLength = 32;

    /// <summary>
    /// 执行Write操作。
    /// </summary>
    /// <param name="destination">destination参数。</param>
    /// <param name="sessionId">session Id参数。</param>
    /// <param name="source">source参数。</param>
    /// <param name="target">target参数。</param>
    /// <param name="trafficClass">traffic Class参数。</param>
    /// <param name="payload">payload参数。</param>
    /// <returns>操作结果。</returns>
    public static int Write(Span<byte> destination, ulong sessionId, ulong source, ulong target,
        P2PTrafficClass trafficClass, ReadOnlySpan<byte> payload)
    {
        int total = HeaderLength + payload.Length;
        if (destination.Length < total) throw new ArgumentOutOfRangeException(nameof(destination));
        BinaryPrimitives.WriteUInt32BigEndian(destination, Magic);
        destination[4] = 2;
        destination[5] = (byte)trafficClass;
        destination[6] = destination[7] = 0;
        BinaryPrimitives.WriteUInt64BigEndian(destination[8..], sessionId);
        BinaryPrimitives.WriteUInt64BigEndian(destination[16..], source);
        BinaryPrimitives.WriteUInt64BigEndian(destination[24..], target);
        payload.CopyTo(destination[HeaderLength..]);
        return total;
    }

    /// <summary>
    /// 尝试Read。
    /// </summary>
    /// <param name="packet">packet参数。</param>
    /// <param name="sessionId">session Id参数。</param>
    /// <param name="source">source参数。</param>
    /// <param name="target">target参数。</param>
    /// <param name="trafficClass">traffic Class参数。</param>
    /// <param name="payload">payload参数。</param>
    /// <returns>操作是否成功。</returns>
    public static bool TryRead(ReadOnlySpan<byte> packet, out ulong sessionId, out ulong source,
        out ulong target, out P2PTrafficClass trafficClass, out ReadOnlySpan<byte> payload)
    {
        sessionId = source = target = 0; trafficClass = default; payload = default;
        if (packet.Length < HeaderLength || BinaryPrimitives.ReadUInt32BigEndian(packet) != Magic ||
            packet[4] != 2 || packet[5] > (byte)P2PTrafficClass.Bulk || packet[6] != 0 || packet[7] != 0) return false;
        trafficClass = (P2PTrafficClass)packet[5];
        sessionId = BinaryPrimitives.ReadUInt64BigEndian(packet[8..]);
        source = BinaryPrimitives.ReadUInt64BigEndian(packet[16..]);
        target = BinaryPrimitives.ReadUInt64BigEndian(packet[24..]);
        payload = packet[HeaderLength..];
        return sessionId != 0 && source != 0 && target != 0;
    }
}
