namespace Qcxt.Net.P2P.Protocol;

/// <summary>包含已校验且零分配的 P2P 解码帧视图。</summary>
/// <param name="Type">帧类型。</param>
/// <param name="DeliveryMode">请求的交付语义。</param>
/// <param name="TrafficClass">调度等级。</param>
/// <param name="SessionId">稳定的 64 位会话标识。</param>
/// <param name="SourcePeerId">数字形式的来源对端标识。</param>
/// <param name="TargetPeerId">数字形式的目标对端标识。</param>
/// <param name="Sequence">按来源独立的可靠序号。</param>
/// <param name="Acknowledgement">按来源独立的确认序号。</param>
/// <param name="Payload">由调用方输入缓冲区支持的载荷切片。</param>
public readonly ref struct P2PDecodedFrame(P2PFrameType Type, P2PDeliveryMode DeliveryMode,
    P2PTrafficClass TrafficClass, ulong SessionId, ulong SourcePeerId, ulong TargetPeerId,
    ulong Sequence, ulong Acknowledgement, ReadOnlySpan<byte> Payload)
{
    /// <summary>获取帧类型。</summary>
    public P2PFrameType Type { get; } = Type;
    /// <summary>获取请求的交付模式。</summary>
    public P2PDeliveryMode DeliveryMode { get; } = DeliveryMode;
    /// <summary>获取流量等级。</summary>
    public P2PTrafficClass TrafficClass { get; } = TrafficClass;
    /// <summary>获取会话标识。</summary>
    public ulong SessionId { get; } = SessionId;
    /// <summary>获取来源对端标识。</summary>
    public ulong SourcePeerId { get; } = SourcePeerId;
    /// <summary>获取目标对端标识。</summary>
    public ulong TargetPeerId { get; } = TargetPeerId;
    /// <summary>获取按来源独立的序号。</summary>
    public ulong Sequence { get; } = Sequence;
    /// <summary>获取已确认的序号。</summary>
    public ulong Acknowledgement { get; } = Acknowledgement;
    /// <summary>以零拷贝方式获取载荷。</summary>
    public ReadOnlySpan<byte> Payload { get; } = Payload;
}

/// <summary>编码和校验固定头 P2P 帧，不产生对象图或字符串分配。</summary>
public static class P2PFrameCodec
{
    private const uint Magic = 0x51585032;
    private const byte Version = 2;
    /// <summary>获取固定帧头的字节长度。</summary>
    public const int HeaderLength = 56;

    /// <summary>把一个帧编码到池化内存，并且仅复制载荷一次。</summary>
    /// <param name="type">帧类型。</param>
    /// <param name="deliveryMode">交付语义。</param>
    /// <param name="trafficClass">调度等级。</param>
    /// <param name="sessionId">数字形式的会话标识。</param>
    /// <param name="sourcePeerId">数字形式的来源对端标识。</param>
    /// <param name="targetPeerId">数字形式的目标对端标识。</param>
    /// <param name="sequence">按来源独立的序号。</param>
    /// <param name="acknowledgement">按来源独立的确认序号。</param>
    /// <param name="payload">应用载荷。</param>
    /// <returns>包含完整编码帧的缓冲区所有者。</returns>
    public static P2POwnedBuffer Encode(P2PFrameType type, P2PDeliveryMode deliveryMode,
        P2PTrafficClass trafficClass, ulong sessionId, ulong sourcePeerId, ulong targetPeerId,
        ulong sequence, ulong acknowledgement, ReadOnlySpan<byte> payload)
    {
        if (type is < P2PFrameType.Data or > P2PFrameType.Close) throw new ArgumentOutOfRangeException(nameof(type));
        if (deliveryMode is < P2PDeliveryMode.ReliableOrdered or > P2PDeliveryMode.Unreliable)
            throw new ArgumentOutOfRangeException(nameof(deliveryMode));
        if (trafficClass is < P2PTrafficClass.Interactive or > P2PTrafficClass.Bulk)
            throw new ArgumentOutOfRangeException(nameof(trafficClass));
        if (sessionId == 0) throw new ArgumentOutOfRangeException(nameof(sessionId));
        if (sourcePeerId == 0) throw new ArgumentOutOfRangeException(nameof(sourcePeerId));
        if (targetPeerId == 0) throw new ArgumentOutOfRangeException(nameof(targetPeerId));
        if ((type != P2PFrameType.Data && deliveryMode != P2PDeliveryMode.Unreliable) ||
            (type == P2PFrameType.Data && deliveryMode == P2PDeliveryMode.ReliableOrdered && sequence == 0) ||
            (type == P2PFrameType.Data && deliveryMode == P2PDeliveryMode.Unreliable && sequence != 0) ||
            (type == P2PFrameType.Ack && (sequence != 0 || acknowledgement == 0 || !payload.IsEmpty)) ||
            (type is P2PFrameType.KeepAlive or P2PFrameType.Close &&
                (sequence != 0 || acknowledgement != 0 || !payload.IsEmpty)))
            throw new ArgumentException("数据帧字段与其类型及交付模式不匹配。");
        int length = checked(HeaderLength + payload.Length);
        P2POwnedBuffer owner = P2POwnedBuffer.Rent(length);
        Span<byte> destination = owner.Memory.Span;
        BinaryPrimitives.WriteUInt32BigEndian(destination, Magic);
        destination[4] = Version;
        destination[5] = (byte)type;
        destination[6] = (byte)deliveryMode;
        destination[7] = (byte)trafficClass;
        BinaryPrimitives.WriteUInt64BigEndian(destination[8..], sessionId);
        BinaryPrimitives.WriteUInt64BigEndian(destination[16..], sourcePeerId);
        BinaryPrimitives.WriteUInt64BigEndian(destination[24..], targetPeerId);
        BinaryPrimitives.WriteUInt64BigEndian(destination[32..], sequence);
        BinaryPrimitives.WriteUInt64BigEndian(destination[40..], acknowledgement);
        BinaryPrimitives.WriteInt32BigEndian(destination[48..], payload.Length);
        BinaryPrimitives.WriteUInt32BigEndian(destination[52..], 0);
        payload.CopyTo(destination[HeaderLength..]);
        return owner;
    }

    /// <summary>以零分配方式校验并解码一个完整帧。</summary>
    /// <param name="buffer">完整编码帧。</param>
    /// <param name="frame">解码视图，仅在 <paramref name="buffer"/> 有效期间可用。</param>
    /// <returns>全部字段和精确长度有效时返回 <see langword="true"/>。</returns>
    public static bool TryDecode(ReadOnlySpan<byte> buffer, out P2PDecodedFrame frame)
    {
        frame = default;
        if (buffer.Length < HeaderLength || BinaryPrimitives.ReadUInt32BigEndian(buffer) != Magic ||
            buffer[4] != Version || BinaryPrimitives.ReadUInt32BigEndian(buffer[52..]) != 0) return false;
        P2PFrameType type = (P2PFrameType)buffer[5];
        P2PDeliveryMode mode = (P2PDeliveryMode)buffer[6];
        P2PTrafficClass traffic = (P2PTrafficClass)buffer[7];
        if (type is < P2PFrameType.Data or > P2PFrameType.Close ||
            mode is < P2PDeliveryMode.ReliableOrdered or > P2PDeliveryMode.Unreliable ||
            traffic is < P2PTrafficClass.Interactive or > P2PTrafficClass.Bulk) return false;
        int payloadLength = BinaryPrimitives.ReadInt32BigEndian(buffer[48..]);
        if (payloadLength < 0 || payloadLength != buffer.Length - HeaderLength) return false;
        ulong session = BinaryPrimitives.ReadUInt64BigEndian(buffer[8..]);
        ulong source = BinaryPrimitives.ReadUInt64BigEndian(buffer[16..]);
        ulong target = BinaryPrimitives.ReadUInt64BigEndian(buffer[24..]);
        ulong sequence = BinaryPrimitives.ReadUInt64BigEndian(buffer[32..]);
        ulong acknowledgement = BinaryPrimitives.ReadUInt64BigEndian(buffer[40..]);
        if (session == 0 || source == 0 || target == 0 ||
            (type != P2PFrameType.Data && mode != P2PDeliveryMode.Unreliable) ||
            (type == P2PFrameType.Data && mode == P2PDeliveryMode.ReliableOrdered && sequence == 0) ||
            (type == P2PFrameType.Data && mode == P2PDeliveryMode.Unreliable && sequence != 0) ||
            (type == P2PFrameType.Ack && (sequence != 0 || acknowledgement == 0 || payloadLength != 0)) ||
            (type is P2PFrameType.KeepAlive or P2PFrameType.Close &&
                (sequence != 0 || acknowledgement != 0 || payloadLength != 0))) return false;
        frame = new P2PDecodedFrame(type, mode, traffic, session, source, target,
            sequence, acknowledgement, buffer[HeaderLength..]);
        return true;
    }

    /// <summary>从 UTF-8 名称派生稳定且非零的 64 位协议标识。</summary>
    /// <param name="value">会话名或对端名称。</param>
    /// <returns>适合写入帧头的稳定标识。</returns>
    public static ulong HashIdentifier(string value)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(value);
        int count = Encoding.UTF8.GetByteCount(value);
        byte[]? rented = null;
        Span<byte> utf8 = count <= 256 ? stackalloc byte[count] : (rented = ArrayPool<byte>.Shared.Rent(count));
        try
        {
            Encoding.UTF8.GetBytes(value, utf8);
            Span<byte> hash = stackalloc byte[32];
            SHA256.HashData(utf8[..count], hash);
            ulong result = BinaryPrimitives.ReadUInt64BigEndian(hash);
            return result == 0 ? 1UL : result;
        }
        finally
        {
            if (rented is not null) ArrayPool<byte>.Shared.Return(rented);
        }
    }
}
