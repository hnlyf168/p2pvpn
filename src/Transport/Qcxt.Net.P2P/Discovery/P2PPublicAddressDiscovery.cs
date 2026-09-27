namespace Qcxt.Net.P2P.Discovery;

/// <summary>在保留调用方已绑定 UDP 端口的同时查询 RFC 5389 STUN 服务器。</summary>
public static class P2PPublicAddressDiscovery
{
    private const uint MagicCookie = 0x2112A442;
    private static readonly string[] DefaultServers = ["stun.cloudflare.com", "stun.l.google.com"];

    /// <summary>使用临时套接字发现公网端点。</summary>
    /// <param name="preferredStunHost">首选 STUN 主机名；为 <see langword="null"/> 时使用内置后备服务器。</param>
    /// <param name="preferredStunPort">STUN UDP 端口。</param>
    /// <param name="timeoutMs">查询总超时毫秒数。</param>
    /// <param name="cancellationToken">用于取消 DNS 或 UDP 输入输出的标记。</param>
    /// <returns>观察到的映射；所有服务器均失败时返回 <see langword="null"/>。</returns>
    public static async Task<P2PPublicEndPoint?> DiscoverAsync(string? preferredStunHost = null,
        int preferredStunPort = 3478, int timeoutMs = 3000, CancellationToken cancellationToken = default)
        => await DiscoverAsync(AddressFamily.InterNetwork, preferredStunHost, preferredStunPort,
            timeoutMs, cancellationToken).ConfigureAwait(false);

    /// <summary>使用指定 IPv4 或 IPv6 地址族的临时套接字发现公网端点。</summary>
    /// <param name="addressFamily">要查询的 IPv4 或 IPv6 地址族。</param>
    /// <param name="preferredStunHost">首选 STUN 主机名；为空时使用内置后备服务器。</param>
    /// <param name="preferredStunPort">STUN UDP 端口。</param>
    /// <param name="timeoutMs">查询总超时毫秒数。</param>
    /// <param name="cancellationToken">用于取消 DNS 或 UDP 输入输出的标记。</param>
    /// <returns>观察到的映射；所有服务器均失败时返回空。</returns>
    public static async Task<P2PPublicEndPoint?> DiscoverAsync(AddressFamily addressFamily,
        string? preferredStunHost = null, int preferredStunPort = 3478, int timeoutMs = 3000,
        CancellationToken cancellationToken = default)
    {
        if (addressFamily is not AddressFamily.InterNetwork and not AddressFamily.InterNetworkV6)
            throw new ArgumentOutOfRangeException(nameof(addressFamily), "只支持 IPv4 或 IPv6 地址族。");
        using var socket = new Socket(addressFamily, SocketType.Dgram, ProtocolType.Udp);
        socket.Bind(new IPEndPoint(addressFamily == AddressFamily.InterNetwork
            ? IPAddress.Any : IPAddress.IPv6Any, 0));
        return await DiscoverAsync(socket, preferredStunHost, preferredStunPort,
            TimeSpan.FromMilliseconds(timeoutMs), cancellationToken).ConfigureAwait(false);
    }

    /// <summary>发现已绑定且未连接 UDP 套接字的 NAT 映射。</summary>
    /// <param name="socket">已绑定的 UDP 套接字，后续将用于打洞和 QUIC。</param>
    /// <param name="preferredStunHost">首选 STUN 主机名；为 <see langword="null"/> 时使用内置后备服务器。</param>
    /// <param name="preferredStunPort">STUN UDP 端口。</param>
    /// <param name="timeout">每台服务器的查询总超时时间。</param>
    /// <param name="cancellationToken">用于取消 DNS 或 UDP 输入输出的标记。</param>
    /// <returns>为该套接字观察到的映射；未发现时返回 <see langword="null"/>。</returns>
    public static async Task<P2PPublicEndPoint?> DiscoverAsync(Socket socket, string? preferredStunHost = null,
        int preferredStunPort = 3478, TimeSpan? timeout = null, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(socket);
        if (socket.SocketType != SocketType.Dgram || socket.ProtocolType != ProtocolType.Udp || socket.LocalEndPoint is not IPEndPoint local)
            throw new ArgumentException("必须提供已绑定的 UDP 套接字。", nameof(socket));
        if (socket.Connected) throw new ArgumentException("STUN 套接字必须处于未连接状态。", nameof(socket));
        if (preferredStunPort is < 1 or > 65_535) throw new ArgumentOutOfRangeException(nameof(preferredStunPort));
        TimeSpan effectiveTimeout = timeout ?? TimeSpan.FromSeconds(3);
        if (effectiveTimeout <= TimeSpan.Zero) throw new ArgumentOutOfRangeException(nameof(timeout));
        string[] hosts = string.IsNullOrWhiteSpace(preferredStunHost) ? DefaultServers : [preferredStunHost];
        foreach (string host in hosts)
        {
            IPAddress[] addresses;
            try { addresses = await Dns.GetHostAddressesAsync(host, cancellationToken).ConfigureAwait(false); }
            catch when (!cancellationToken.IsCancellationRequested) { continue; }
            foreach (IPAddress address in addresses)
            {
                if (address.AddressFamily != local.AddressFamily) continue;
                IPEndPoint server = new(address, preferredStunPort);
                IPEndPoint? mapped = await QueryServerAsync(socket, server, effectiveTimeout,
                    cancellationToken).ConfigureAwait(false);
                if (mapped is not null) return new P2PPublicEndPoint(local, mapped, $"stun:{host}");
            }
        }
        return null;
    }

    /// <summary>发送一条 STUN 绑定请求并校验对应事务响应。</summary>
    /// <param name="socket">已绑定的 UDP 套接字。</param>
    /// <param name="server">已解析的 STUN 端点。</param>
    /// <param name="timeout">请求超时时间。</param>
    /// <param name="cancellationToken">调用方取消标记。</param>
    /// <returns>映射后的端点；失败时返回 <see langword="null"/>。</returns>
    private static async Task<IPEndPoint?> QueryServerAsync(Socket socket, IPEndPoint server,
        TimeSpan timeout, CancellationToken cancellationToken)
    {
        byte[] request = ArrayPool<byte>.Shared.Rent(20);
        byte[] response = ArrayPool<byte>.Shared.Rent(2048);
        try
        {
            {
                Span<byte> packet = request.AsSpan(0, 20);
                packet.Clear();
                BinaryPrimitives.WriteUInt16BigEndian(packet, 0x0001);
                BinaryPrimitives.WriteUInt32BigEndian(packet[4..], MagicCookie);
                RandomNumberGenerator.Fill(packet[8..20]);
            }
            using var linked = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            linked.CancelAfter(timeout);
            await socket.SendToAsync(request.AsMemory(0, 20), SocketFlags.None, server, linked.Token)
                .ConfigureAwait(false);
            EndPoint any = server.AddressFamily == AddressFamily.InterNetwork
                ? new IPEndPoint(IPAddress.Any, 0) : new IPEndPoint(IPAddress.IPv6Any, 0);
            while (true)
            {
                SocketReceiveFromResult result = await socket.ReceiveFromAsync(response, SocketFlags.None, any,
                    linked.Token).ConfigureAwait(false);
                if (!result.RemoteEndPoint.Equals(server)) continue;
                ReadOnlySpan<byte> received = response.AsSpan(0, result.ReceivedBytes);
                if (TryParseResponse(received, request.AsSpan(8, 12), out IPEndPoint? mapped)) return mapped;
            }
        }
        catch (Exception exception) when (exception is SocketException or OperationCanceledException)
        {
            if (cancellationToken.IsCancellationRequested) throw;
            return null;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(request.AsSpan(0, 20));
            ArrayPool<byte>.Shared.Return(request);
            ArrayPool<byte>.Shared.Return(response);
        }
    }

    /// <summary>从绑定成功响应中解析 XOR-MAPPED-ADDRESS 或 MAPPED-ADDRESS。</summary>
    /// <param name="packet">完整的 STUN 数据报。</param>
    /// <param name="transactionId">预期的 96 位事务标识。</param>
    /// <param name="mapped">解码后的公网端点。</param>
    /// <returns>响应有效且包含地址时返回 <see langword="true"/>。</returns>
    private static bool TryParseResponse(ReadOnlySpan<byte> packet, ReadOnlySpan<byte> transactionId,
        out IPEndPoint? mapped)
    {
        mapped = null;
        if (packet.Length < 20 || BinaryPrimitives.ReadUInt16BigEndian(packet) != 0x0101 ||
            BinaryPrimitives.ReadUInt32BigEndian(packet[4..]) != MagicCookie ||
            !packet.Slice(8, 12).SequenceEqual(transactionId)) return false;
        int bodyLength = BinaryPrimitives.ReadUInt16BigEndian(packet[2..]);
        if (bodyLength > packet.Length - 20) return false;
        int offset = 20;
        int end = 20 + bodyLength;
        while (offset + 4 <= end)
        {
            ushort type = BinaryPrimitives.ReadUInt16BigEndian(packet[offset..]);
            int length = BinaryPrimitives.ReadUInt16BigEndian(packet[(offset + 2)..]);
            offset += 4;
            if (length > end - offset) return false;
            if ((type == 0x0020 || type == 0x0001) && TryReadAddress(packet.Slice(offset, length),
                type == 0x0020, transactionId, out mapped)) return true;
            offset += (length + 3) & ~3;
        }
        return false;
    }

    /// <summary>解码一个 STUN 地址属性。</summary>
    /// <param name="attribute">属性值。</param>
    /// <param name="xor">是否需要使用魔数和事务标识执行异或解码。</param>
    /// <param name="transactionId">响应事务标识。</param>
    /// <param name="endpoint">解码后的端点。</param>
    /// <returns>地址族和长度有效时返回 <see langword="true"/>。</returns>
    private static bool TryReadAddress(ReadOnlySpan<byte> attribute, bool xor, ReadOnlySpan<byte> transactionId,
        out IPEndPoint? endpoint)
    {
        endpoint = null;
        if (attribute.Length < 8) return false;
        int port = BinaryPrimitives.ReadUInt16BigEndian(attribute[2..]);
        if (xor) port ^= (int)(MagicCookie >> 16);
        if (port is < 1 or > 65_535) return false;
        if (attribute[1] == 0x01 && attribute.Length >= 8)
        {
            Span<byte> address = stackalloc byte[4];
            attribute.Slice(4, 4).CopyTo(address);
            if (xor)
            {
                Span<byte> cookie = stackalloc byte[4];
                BinaryPrimitives.WriteUInt32BigEndian(cookie, MagicCookie);
                for (int index = 0; index < 4; index++) address[index] ^= cookie[index];
            }
            endpoint = new IPEndPoint(new IPAddress(address), port);
            return true;
        }
        if (attribute[1] == 0x02 && attribute.Length >= 20)
        {
            Span<byte> address = stackalloc byte[16];
            attribute.Slice(4, 16).CopyTo(address);
            if (xor)
            {
                Span<byte> mask = stackalloc byte[16];
                BinaryPrimitives.WriteUInt32BigEndian(mask, MagicCookie);
                transactionId.CopyTo(mask[4..]);
                for (int index = 0; index < 16; index++) address[index] ^= mask[index];
            }
            endpoint = new IPEndPoint(new IPAddress(address), port);
            return true;
        }
        return false;
    }
}
