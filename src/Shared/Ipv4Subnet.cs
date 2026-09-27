using System.Buffers.Binary;
using System.Net;
namespace EdgeVpn;
public sealed record Ipv4Subnet(uint Network, int Prefix)
{
    public uint Last => Network + (uint)((1UL << (32 - Prefix)) - 1);
    public int Available => (int)Math.Min(65534, (1UL << (32 - Prefix)) - 2);
    public IPAddress Address => IPAddress.Parse(ToAddress(Network));
    public override string ToString() => $"{Address}/{Prefix}";
    public bool Overlaps(Ipv4Subnet other) => Network <= other.Last && other.Network <= Last;
    public static string ToAddress(uint value) => $"{value >> 24}.{(value >> 16) & 255}.{(value >> 8) & 255}.{value & 255}";
    public string Allocate(IEnumerable<string> occupied)
    {
        var used = occupied.ToHashSet();
        // At most one more candidate than existing leases is needed, even for a /8.
        for (uint candidate = Network + 1; candidate < Last && candidate <= (ulong)Network + (uint)used.Count + 1; candidate++)
            if (!used.Contains(ToAddress(candidate))) return ToAddress(candidate);
        throw new InvalidOperationException("这个网段的可用地址已分配完，请使用更大的空网络。");
    }
    public static Ipv4Subnet Parse(string value)
    {
        var parts = (value ?? "").Trim().Split('/');
        if (parts.Length != 2 || !IPAddress.TryParse(parts[0], out var address) || address.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork ||
            address.ToString() != parts[0] || !int.TryParse(parts[1], out var prefix) || prefix is < 8 or > 30)
            throw new ArgumentException("网段请填写标准 IPv4 CIDR，例如 10.88.0.0/24；前缀支持 /8–/30。");
        uint network = BinaryPrimitives.ReadUInt32BigEndian(address.GetAddressBytes());
        var subnet = new Ipv4Subnet(network, prefix);
        if ((network & (uint.MaxValue << (32 - prefix))) != network)
            throw new ArgumentException("请填写网段起始地址，例如 192.168.50.0/24，不能填写设备地址。");
        if (!((network >= 0x0a000000 && subnet.Last <= 0x0affffff) || (network >= 0xac100000 && subnet.Last <= 0xac1fffff) ||
              (network >= 0xc0a80000 && subnet.Last <= 0xc0a8ffff)))
            throw new ArgumentException("仅支持私有网段：10.0.0.0/8、172.16.0.0/12、192.168.0.0/16 范围内的子网。");
        return subnet;
    }
}
