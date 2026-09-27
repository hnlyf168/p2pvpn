using System.Buffers.Binary;

namespace Qcxt.Net.Quic.Mesh;

/// <summary>定义 QUIC Mesh 可靠控制流中的消息类型。</summary>
public enum QuicMeshControlType : byte
{
    /// <summary>客户端提交稳定节点标识符并申请虚拟地址。</summary>
    Register = 1,
    /// <summary>服务端返回虚拟地址、网段和 UDP 注册令牌。</summary>
    Lease = 2,
    /// <summary>客户端请求与指定虚拟地址的节点进行 UDP 打洞。</summary>
    PunchRequest = 3,
    /// <summary>服务端向客户端提供对端公网地址和临时会话密钥。</summary>
    PunchOffer = 4,
    /// <summary>服务端通知一个虚拟节点已经离线。</summary>
    PeerGone = 5,
    /// <summary>通过 QUIC 可靠流传输一个低频、高优先级完整 IPv4 包。</summary>
    ReliablePacket = 6
}

/// <summary>表示一条已经解码的 QUIC Mesh 控制消息。</summary>
/// <param name="Type">控制消息类型。</param>
/// <param name="PeerId">注册消息中的稳定节点标识符。</param>
/// <param name="Address">租约地址、请求目标或打洞对端虚拟地址。</param>
/// <param name="PrefixLength">租约 IPv4 前缀长度。</param>
/// <param name="ServerAddress">租约中的服务端虚拟 IPv4 地址。</param>
/// <param name="PublicAddress">打洞对端或服务器的公网 IPv4 地址。</param>
/// <param name="Port">UDP rendezvous 或打洞端口。</param>
/// <param name="Token">32 字节注册令牌或端到端会话密钥。</param>
/// <param name="Payload">可靠传输消息中的完整 IPv4 包。</param>
/// <param name="PrivateAddress">客户端声明的局域网 IPv4 打洞候选。</param>
/// <param name="PrivatePort">客户端打洞套接字的局域网端口。</param>
public readonly record struct QuicMeshControlMessage(QuicMeshControlType Type,
    string? PeerId = null, uint Address = 0, byte PrefixLength = 0,
    uint ServerAddress = 0, uint PublicAddress = 0, ushort Port = 0,
    byte[]? Token = null, byte[]? Payload = null,
    uint PrivateAddress = 0, ushort PrivatePort = 0);

/// <summary>无反射编解码 QUIC Mesh 控制消息。</summary>
public static class QuicMeshControlCodec
{
    /// <summary>控制帧允许的最大内容长度。</summary>
    public const int MaximumMessageLength = 1_200;
    /// <summary>可靠控制流允许承载的最大 IPv4 包长度。</summary>
    public const int MaximumReliablePacketLength = 1_100;

    /// <summary>把控制消息编码为紧凑二进制内容。</summary>
    /// <param name="message">要编码的控制消息。</param>
    /// <returns>不含流长度前缀的控制消息。</returns>
    public static byte[] Encode(QuicMeshControlMessage message)
    {
        byte[] result;
        switch (message.Type)
        {
            case QuicMeshControlType.Register:
                byte[] id = Encoding.UTF8.GetBytes(message.PeerId ?? string.Empty);
                if (id.Length is < 1 or > 128) throw new ArgumentOutOfRangeException(nameof(message));
                result = new byte[2 + id.Length]; result[0] = (byte)message.Type;
                result[1] = (byte)id.Length; id.CopyTo(result.AsSpan(2)); return result;
            case QuicMeshControlType.Lease:
                ValidateToken(message.Token);
                result = new byte[48]; result[0] = (byte)message.Type;
                BinaryPrimitives.WriteUInt32BigEndian(result.AsSpan(1), message.Address);
                result[5] = message.PrefixLength;
                BinaryPrimitives.WriteUInt32BigEndian(result.AsSpan(6), message.ServerAddress);
                BinaryPrimitives.WriteUInt32BigEndian(result.AsSpan(10), message.PublicAddress);
                BinaryPrimitives.WriteUInt16BigEndian(result.AsSpan(14), message.Port);
                message.Token!.CopyTo(result.AsSpan(16)); return result;
            case QuicMeshControlType.PunchRequest:
            case QuicMeshControlType.PeerGone:
                result = new byte[5]; result[0] = (byte)message.Type;
                BinaryPrimitives.WriteUInt32BigEndian(result.AsSpan(1), message.Address); return result;
            case QuicMeshControlType.PunchOffer:
                ValidateToken(message.Token);
                result = new byte[49]; result[0] = (byte)message.Type;
                BinaryPrimitives.WriteUInt32BigEndian(result.AsSpan(1), message.Address);
                BinaryPrimitives.WriteUInt32BigEndian(result.AsSpan(5), message.PublicAddress);
                BinaryPrimitives.WriteUInt16BigEndian(result.AsSpan(9), message.Port);
                message.Token!.CopyTo(result.AsSpan(11));
                BinaryPrimitives.WriteUInt32BigEndian(result.AsSpan(43), message.PrivateAddress);
                BinaryPrimitives.WriteUInt16BigEndian(result.AsSpan(47), message.PrivatePort);
                return result;
            case QuicMeshControlType.ReliablePacket:
                byte[] packet = message.Payload ?? throw new ArgumentException(
                    "A reliable packet payload is required.", nameof(message));
                if (packet.Length is < 20 or > MaximumReliablePacketLength)
                    throw new ArgumentOutOfRangeException(nameof(message));
                result = new byte[3 + packet.Length]; result[0] = (byte)message.Type;
                BinaryPrimitives.WriteUInt16BigEndian(result.AsSpan(1), (ushort)packet.Length);
                packet.CopyTo(result.AsSpan(3)); return result;
            default: throw new ArgumentOutOfRangeException(nameof(message));
        }
    }

    /// <summary>尝试解码一条完整控制消息。</summary>
    /// <param name="data">不含流长度前缀的消息内容。</param>
    /// <param name="message">成功时返回控制消息。</param>
    /// <returns>消息类型、长度和字段均有效时返回 true。</returns>
    public static bool TryDecode(ReadOnlySpan<byte> data, out QuicMeshControlMessage message)
    {
        message = default;
        if (data.IsEmpty || data.Length > MaximumMessageLength) return false;
        var type = (QuicMeshControlType)data[0];
        switch (type)
        {
            case QuicMeshControlType.Register:
                if (data.Length < 3 || data[1] is 0 or > 128 || data.Length != data[1] + 2) return false;
                string id;
                try { id = new UTF8Encoding(false, true).GetString(data[2..]); }
                catch (DecoderFallbackException) { return false; }
                message = new(type, PeerId: id); return true;
            case QuicMeshControlType.Lease:
                if (data.Length != 48 || data[5] is < 1 or > 30) return false;
                message = new(type,
                    Address: BinaryPrimitives.ReadUInt32BigEndian(data[1..]),
                    PrefixLength: data[5],
                    ServerAddress: BinaryPrimitives.ReadUInt32BigEndian(data[6..]),
                    PublicAddress: BinaryPrimitives.ReadUInt32BigEndian(data[10..]),
                    Port: BinaryPrimitives.ReadUInt16BigEndian(data[14..]), Token: data[16..48].ToArray());
                return true;
            case QuicMeshControlType.PunchRequest:
            case QuicMeshControlType.PeerGone:
                if (data.Length != 5) return false;
                message = new(type, Address: BinaryPrimitives.ReadUInt32BigEndian(data[1..])); return true;
            case QuicMeshControlType.PunchOffer:
                if (data.Length != 49) return false;
                message = new(type,
                    Address: BinaryPrimitives.ReadUInt32BigEndian(data[1..]),
                    PublicAddress: BinaryPrimitives.ReadUInt32BigEndian(data[5..]),
                    Port: BinaryPrimitives.ReadUInt16BigEndian(data[9..]), Token: data[11..43].ToArray(),
                    PrivateAddress: BinaryPrimitives.ReadUInt32BigEndian(data[43..]),
                    PrivatePort: BinaryPrimitives.ReadUInt16BigEndian(data[47..]));
                return true;
            case QuicMeshControlType.ReliablePacket:
                if (data.Length < 23 || data.Length > MaximumReliablePacketLength + 3 ||
                    BinaryPrimitives.ReadUInt16BigEndian(data[1..]) != data.Length - 3) return false;
                message = new(type, Payload: data[3..].ToArray()); return true;
            default: return false;
        }
    }

    /// <summary>验证控制消息中的随机令牌或节点对密钥长度。</summary>
    /// <param name="token">必须恰好包含 32 字节的敏感值。</param>
    private static void ValidateToken(byte[]? token)
    {
        if (token is null || token.Length != 32)
            throw new ArgumentException("Mesh token must contain 32 bytes.", nameof(token));
    }
}

/// <summary>提供 IPv4 地址和无序节点对的无分配辅助操作。</summary>
public static class QuicMeshAddress
{
    /// <summary>把网络字节序 IPv4 整数转换为地址对象。</summary>
    /// <param name="value">网络字节序表示的 IPv4 地址。</param>
    /// <returns>IPv4 地址对象。</returns>
    public static IPAddress ToIPAddress(uint value)
    {
        Span<byte> bytes = stackalloc byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(bytes, value); return new IPAddress(bytes);
    }

    /// <summary>把 IPv4 地址转换为网络字节序整数。</summary>
    /// <param name="address">IPv4 地址。</param>
    /// <returns>网络字节序表示的 IPv4 地址。</returns>
    public static uint FromIPAddress(IPAddress address)
    {
        Span<byte> bytes = stackalloc byte[4];
        if (!address.TryWriteBytes(bytes, out int written) || written != 4)
            throw new ArgumentException("An IPv4 address is required.", nameof(address));
        return BinaryPrimitives.ReadUInt32BigEndian(bytes);
    }

    /// <summary>生成与节点顺序无关的 64 位节点对键。</summary>
    /// <param name="first">第一个虚拟 IPv4 地址。</param>
    /// <param name="second">第二个虚拟 IPv4 地址。</param>
    /// <returns>可用于缓存打洞密钥的无序节点对键。</returns>
    public static ulong PairKey(uint first, uint second) => first < second
        ? ((ulong)first << 32) | second : ((ulong)second << 32) | first;
}

/// <summary>编解码客户端 UDP 注册报文。</summary>
public static class QuicMeshRegistrationCodec
{
    private const uint Magic = 0x51584D52;
    /// <summary>UDP 注册报文固定长度。</summary>
    public const int PacketLength = 48;

    /// <summary>写入注册或确认报文。</summary>
    /// <param name="destination">至少 48 字节的目标缓冲区。</param>
    /// <param name="acknowledgement">是否为服务端确认报文。</param>
    /// <param name="token">QUIC 控制流下发的 32 字节注册令牌。</param>
    /// <param name="privateAddress">客户端用于访问服务器的局域网 IPv4 候选。</param>
    /// <param name="privatePort">客户端打洞套接字的本机 UDP 端口。</param>
    /// <returns>写入的固定报文长度。</returns>
    public static int Write(Span<byte> destination, bool acknowledgement, ReadOnlySpan<byte> token,
        uint privateAddress = 0, ushort privatePort = 0)
    {
        if (destination.Length < PacketLength || token.Length != 32) throw new ArgumentOutOfRangeException();
        BinaryPrimitives.WriteUInt32BigEndian(destination, Magic); destination[4] = 2;
        destination[5] = acknowledgement ? (byte)2 : (byte)1; destination[6] = destination[7] = 0;
        token.CopyTo(destination[8..40]);
        BinaryPrimitives.WriteUInt32BigEndian(destination[40..], privateAddress);
        BinaryPrimitives.WriteUInt16BigEndian(destination[44..], privatePort);
        destination[46] = destination[47] = 0;
        return PacketLength;
    }

    /// <summary>验证并读取注册报文。</summary>
    /// <param name="packet">完整 UDP 报文。</param>
    /// <param name="acknowledgement">返回是否为确认报文。</param>
    /// <param name="token">成功时返回报文中的 32 字节令牌。</param>
    /// <param name="privateAddress">成功时返回客户端声明的局域网 IPv4。</param>
    /// <param name="privatePort">成功时返回客户端声明的 UDP 端口。</param>
    /// <returns>格式和版本有效时返回 true。</returns>
    public static bool TryRead(ReadOnlySpan<byte> packet, out bool acknowledgement,
        out ReadOnlySpan<byte> token, out uint privateAddress, out ushort privatePort)
    {
        acknowledgement = false; token = default; privateAddress = 0; privatePort = 0;
        if (packet.Length != PacketLength || BinaryPrimitives.ReadUInt32BigEndian(packet) != Magic ||
            packet[4] != 2 || packet[5] is < 1 or > 2) return false;
        acknowledgement = packet[5] == 2; token = packet[8..40];
        privateAddress = BinaryPrimitives.ReadUInt32BigEndian(packet[40..]);
        privatePort = BinaryPrimitives.ReadUInt16BigEndian(packet[44..]);
        return true;
    }
}

/// <summary>定义加密客户端直连 UDP 报文类型。</summary>
public enum QuicMeshPeerPacketType : byte
{
    /// <summary>用于打开 NAT 映射并验证双向路径。</summary>
    Punch = 1,
    /// <summary>确认已收到对端打洞报文。</summary>
    PunchAck = 2,
    /// <summary>携带一个完整的加密三层 IP 包。</summary>
    Data = 3,
    /// <summary>保持已经建立的 NAT 映射。</summary>
    KeepAlive = 4
}

/// <summary>使用 AES-GCM 编解码客户端之间的加密 UDP 报文。</summary>
public static class QuicMeshPeerPacketCodec
{
    private const uint Magic = 0x51584D50;
    /// <summary>不含密文和认证标签的报文头长度。</summary>
    public const int HeaderLength = 24;
    /// <summary>AES-GCM 认证标签长度。</summary>
    public const int TagLength = 16;
    /// <summary>直连封装的固定额外字节数。</summary>
    public const int Overhead = HeaderLength + TagLength;

    /// <summary>在解密前读取用于选择节点对密钥的认证头字段。</summary>
    /// <param name="packet">完整 UDP 报文。</param>
    /// <param name="type">成功时返回报文类型。</param>
    /// <param name="source">成功时返回源虚拟 IPv4 地址。</param>
    /// <param name="target">成功时返回目标虚拟 IPv4 地址。</param>
    /// <param name="sequence">成功时返回报文序号。</param>
    /// <returns>固定头部格式和版本有效时返回 true；字段仍须由 AES-GCM 标签认证。</returns>
    public static bool TryReadHeader(ReadOnlySpan<byte> packet, out QuicMeshPeerPacketType type,
        out uint source, out uint target, out ulong sequence)
    {
        type = default; source = target = 0; sequence = 0;
        if (packet.Length < Overhead || BinaryPrimitives.ReadUInt32BigEndian(packet) != Magic || packet[4] != 1)
            return false;
        type = (QuicMeshPeerPacketType)packet[5];
        if (type is < QuicMeshPeerPacketType.Punch or > QuicMeshPeerPacketType.KeepAlive) return false;
        source = BinaryPrimitives.ReadUInt32BigEndian(packet[8..]);
        target = BinaryPrimitives.ReadUInt32BigEndian(packet[12..]);
        sequence = BinaryPrimitives.ReadUInt64BigEndian(packet[16..]); return true;
    }

    /// <summary>加密并写入一条客户端直连报文。</summary>
    /// <param name="destination">容纳头部、密文和标签的目标缓冲区。</param>
    /// <param name="type">直连报文类型。</param>
    /// <param name="source">源虚拟 IPv4 地址。</param>
    /// <param name="target">目标虚拟 IPv4 地址。</param>
    /// <param name="sequence">本方向单调递增且不重复的序号。</param>
    /// <param name="plaintext">要加密的完整 IP 包；打洞和保活可为空。</param>
    /// <param name="cipher">使用服务端下发密钥创建的 AES-GCM 实例。</param>
    /// <returns>写入的 UDP 报文长度。</returns>
    public static int Encrypt(Span<byte> destination, QuicMeshPeerPacketType type,
        uint source, uint target, ulong sequence, ReadOnlySpan<byte> plaintext, AesGcm cipher)
    {
        int total = HeaderLength + plaintext.Length + TagLength;
        if (destination.Length < total) throw new ArgumentOutOfRangeException(nameof(destination));
        BinaryPrimitives.WriteUInt32BigEndian(destination, Magic); destination[4] = 1;
        destination[5] = (byte)type; destination[6] = destination[7] = 0;
        BinaryPrimitives.WriteUInt32BigEndian(destination[8..], source);
        BinaryPrimitives.WriteUInt32BigEndian(destination[12..], target);
        BinaryPrimitives.WriteUInt64BigEndian(destination[16..], sequence);
        Span<byte> nonce = stackalloc byte[12];
        BinaryPrimitives.WriteUInt32BigEndian(nonce, source);
        BinaryPrimitives.WriteUInt64BigEndian(nonce[4..], sequence);
        cipher.Encrypt(nonce, plaintext, destination.Slice(HeaderLength, plaintext.Length),
            destination.Slice(HeaderLength + plaintext.Length, TagLength), destination[..HeaderLength]);
        return total;
    }

    /// <summary>验证头部和 AES-GCM 标签，并解密客户端直连报文。</summary>
    /// <param name="packet">完整 UDP 报文。</param>
    /// <param name="expectedTarget">本机虚拟 IPv4 地址。</param>
    /// <param name="cipher">使用对应节点对密钥创建的 AES-GCM 实例。</param>
    /// <param name="plaintext">接收解密内容的缓冲区。</param>
    /// <param name="type">成功时返回报文类型。</param>
    /// <param name="source">成功时返回源虚拟 IPv4 地址。</param>
    /// <param name="sequence">成功时返回对端序号。</param>
    /// <param name="plaintextLength">成功时返回解密字节数。</param>
    /// <returns>格式、目标和认证标签全部有效时返回 true。</returns>
    public static bool TryDecrypt(ReadOnlySpan<byte> packet, uint expectedTarget, AesGcm cipher,
        Span<byte> plaintext, out QuicMeshPeerPacketType type, out uint source,
        out ulong sequence, out int plaintextLength)
    {
        type = default; source = 0; sequence = 0; plaintextLength = 0;
        if (!TryReadHeader(packet, out type, out source, out uint target, out sequence) ||
            target != expectedTarget) return false;
        int encryptedLength = packet.Length - Overhead;
        if (encryptedLength > plaintext.Length) return false;
        Span<byte> nonce = stackalloc byte[12];
        BinaryPrimitives.WriteUInt32BigEndian(nonce, source);
        BinaryPrimitives.WriteUInt64BigEndian(nonce[4..], sequence);
        try
        {
            cipher.Decrypt(nonce, packet.Slice(HeaderLength, encryptedLength),
                packet[^TagLength..], plaintext[..encryptedLength], packet[..HeaderLength]);
            plaintextLength = encryptedLength; return true;
        }
        catch (CryptographicException)
        {
            CryptographicOperations.ZeroMemory(plaintext[..encryptedLength]); return false;
        }
    }
}
