using System.Net;
using System.Net.Sockets;
using System.Text.Json;
using System.Text.Json.Serialization;
using Android.Content;

namespace P2PVpnAndroid;

internal sealed class VpnProfile
{
    public string Server { get; set; } = "";
    public string Group { get; set; } = "";
    public string SharedSecret { get; set; } = "";
    public string DeviceId { get; set; } = "";
    public string DeviceToken { get; set; } = "";
    public string ControlUrl { get; set; } = "";
    public string[] CoordinatorServers { get; set; } = [];
    public string[] RelayUrls { get; set; } = [];
    public string DataSecret { get; set; } = "";
    public string Subnet { get; set; } = "";
    public bool AccessRevoked { get; set; }
    public int LocalPort { get; set; }
    public int DirectIdleMinutes { get; set; } = 60;
    public List<SubnetRoute> Routes { get; set; } = [];
}

internal sealed class SubnetRoute
{
    public bool Enabled { get; set; } = true;
    public string Subnet { get; set; } = "";
    public string DestinationSubnet { get; set; } = "";
    public string GatewayVirtualIp { get; set; } = "";
}

[JsonSourceGenerationOptions(PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase, WriteIndented = true)]
[JsonSerializable(typeof(VpnProfile))]
[JsonSerializable(typeof(InstallClaim))]
internal sealed partial class VpnJsonContext : JsonSerializerContext;

internal static partial class ProfileStore
{
    public static void Validate(VpnProfile profile)
    {
        if (string.IsNullOrWhiteSpace(profile.Server)) throw new InvalidDataException("请填写服务器地址");
        if (string.IsNullOrWhiteSpace(profile.Group) || profile.Group.Length > 128) throw new InvalidDataException("请填写有效的 VPN 分组");
        if (profile.SharedSecret.Length < 12) throw new InvalidDataException("客户端共享密钥至少需要 12 个字符");
        if (profile.LocalPort is < 0 or > 65535) throw new InvalidDataException("本地端口必须为 0～65535");
        _ = ControlApi.Origin(profile.ControlUrl);
        if (profile.DeviceId.Length is < 1 or > 128 || profile.DeviceToken.Length is < 20 or > 128)
            throw new InvalidDataException("请先使用控制台生成的加入链接添加设备。");
        if (Convert.FromBase64String(profile.DataSecret).Length != 32)
            throw new InvalidDataException("数据加密密钥无效。");
        if (!TryParseCidr(profile.Subnet, out _, out int networkPrefix) || networkPrefix is < 8 or > 30)
            throw new InvalidDataException("平台返回的网络网段无效。");
        if (profile.CoordinatorServers is null || profile.RelayUrls is null ||
            profile.CoordinatorServers.Length > 32 || profile.RelayUrls.Length > 32)
            throw new InvalidDataException("平台节点配置无效。");
        foreach (var endpoint in profile.CoordinatorServers.Append(profile.Server))
            if (!Uri.TryCreate("vpn://" + endpoint, UriKind.Absolute, out var coordinator) ||
                coordinator.Host.Length == 0 || coordinator.Port is < 1 or > 65535 || coordinator.UserInfo.Length > 0)
                throw new InvalidDataException("协调节点地址无效。");
        foreach (var endpoint in profile.RelayUrls)
            if (!Uri.TryCreate(endpoint, UriKind.Absolute, out var relay) || relay.Scheme != "wss" ||
                relay.UserInfo.Length > 0 || relay.Fragment.Length > 0)
                throw new InvalidDataException("中继节点必须使用加密 WSS 连接。");
        if (profile.DirectIdleMinutes is < 1 or > 10080) throw new InvalidDataException("直连空闲时间无效。");
        if (profile.Routes.Count > 64) throw new InvalidDataException("远端子网映射不能超过 64 条");
        foreach (SubnetRoute route in profile.Routes.Where(x => x.Enabled))
        {
            if (!TryParseCidr(route.Subnet, out _, out int prefix)) throw new InvalidDataException($"访问网段无效：{route.Subnet}");
            if (!TryParseCidr(route.DestinationSubnet, out _, out int destinationPrefix) || prefix != destinationPrefix)
                throw new InvalidDataException($"远端真实网段无效或前缀不一致：{route.DestinationSubnet}");
            if (!IPAddress.TryParse(route.GatewayVirtualIp, out IPAddress? gateway) || gateway.AddressFamily != AddressFamily.InterNetwork)
                throw new InvalidDataException($"网关客户端 VPN 地址无效：{route.GatewayVirtualIp}");
        }
    }

    public static bool TryParseCidr(string value, out IPAddress network, out int prefix)
    {
        network = IPAddress.Any; prefix = 0;
        string[] parts = value.Trim().Split('/', 2);
        if (parts.Length != 2 || !IPAddress.TryParse(parts[0], out IPAddress? address) ||
            address.AddressFamily != AddressFamily.InterNetwork || !int.TryParse(parts[1], out prefix) || prefix is < 1 or > 32) return false;
        byte[] bytes = address.GetAddressBytes(); int remaining = prefix;
        for (int i = 0; i < 4; i++) { int bits = Math.Clamp(remaining, 0, 8); bytes[i] &= (byte)(bits == 0 ? 0 : 0xff << (8 - bits)); remaining -= bits; }
        network = new IPAddress(bytes); return true;
    }
}
