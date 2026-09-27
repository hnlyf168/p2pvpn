namespace Qcxt.Net.Quic.Mesh;

/// <summary>为稳定节点标识符分配可重复使用的 IPv4 租约。</summary>
public sealed class QuicMeshAddressPool
{
    private readonly uint _network;
    private readonly byte _prefixLength;
    private readonly uint _serverAddress;
    private readonly int _firstHost;
    private readonly int _lastHost;
    private readonly Dictionary<string, uint> _byPeer = new(StringComparer.Ordinal);
    private readonly Dictionary<uint, string> _byAddress = new();
    private readonly object _sync = new();

    /// <summary>创建一个保留网络地址、服务端地址和广播地址的租约池。</summary>
    /// <param name="network">网段中的任意 IPv4 地址。</param>
    /// <param name="prefixLength">IPv4 前缀长度，当前支持 16..29。</param>
    /// <param name="serverAddress">必须位于网段内的服务端虚拟地址。</param>
    public QuicMeshAddressPool(IPAddress network, byte prefixLength, IPAddress serverAddress)
    {
        if (prefixLength is < 16 or > 29) throw new ArgumentOutOfRangeException(nameof(prefixLength));
        uint mask = uint.MaxValue << (32 - prefixLength);
        _network = QuicMeshAddress.FromIPAddress(network) & mask;
        _prefixLength = prefixLength;
        _serverAddress = QuicMeshAddress.FromIPAddress(serverAddress);
        uint hostCount = 1u << (32 - prefixLength);
        if ((_serverAddress & mask) != _network || _serverAddress == _network ||
            _serverAddress == _network + hostCount - 1)
            throw new ArgumentException("Server address must be a usable address in the pool.", nameof(serverAddress));
        _firstHost = 1;
        _lastHost = checked((int)hostCount - 2);
    }

    /// <summary>获取网段前缀长度。</summary>
    public byte PrefixLength => _prefixLength;

    /// <summary>获取服务端虚拟 IPv4 地址。</summary>
    public uint ServerAddress => _serverAddress;

    /// <summary>为节点取得稳定租约；同一进程生命周期内重连会得到相同地址。</summary>
    /// <param name="peerId">1..128 字节 UTF-8 稳定节点标识符。</param>
    /// <returns>网络字节序表示的客户端虚拟 IPv4 地址。</returns>
    public uint Acquire(string peerId)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(peerId);
        if (Encoding.UTF8.GetByteCount(peerId) > 128) throw new ArgumentOutOfRangeException(nameof(peerId));
        lock (_sync)
        {
            if (_byPeer.TryGetValue(peerId, out uint existing)) return existing;
            int capacity = _lastHost - _firstHost + 1;
            uint hash = 2166136261;
            foreach (byte value in Encoding.UTF8.GetBytes(peerId)) hash = (hash ^ value) * 16777619;
            int start = _firstHost + (int)(hash % (uint)capacity);
            for (int offset = 0; offset < capacity; offset++)
            {
                int host = _firstHost + (start - _firstHost + offset) % capacity;
                uint candidate = _network + (uint)host;
                if (candidate == _serverAddress || _byAddress.ContainsKey(candidate)) continue;
                _byPeer.Add(peerId, candidate); _byAddress.Add(candidate, peerId); return candidate;
            }
        }
        throw new InvalidOperationException("The QUIC mesh IPv4 address pool is exhausted.");
    }

    /// <summary>尝试查找已经分配的节点地址。</summary>
    /// <param name="peerId">稳定节点标识符。</param>
    /// <param name="address">找到时返回网络字节序 IPv4 地址。</param>
    /// <returns>节点已有租约时返回 true。</returns>
    public bool TryGetAddress(string peerId, out uint address)
    {
        lock (_sync) return _byPeer.TryGetValue(peerId, out address);
    }
}
