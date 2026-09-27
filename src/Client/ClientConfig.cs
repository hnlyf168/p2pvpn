using System.Net;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace P2PVpnClient;

/// <summary>保存 Windows VPN 客户端服务配置。</summary>
internal sealed class ClientConfig
{
    public bool AccessRevoked { get; set; }
    public string DeviceId { get; set; } = "";
    public string DeviceToken { get; set; } = "";
    public string ControlUrl { get; set; } = "";
    public string[] CoordinatorServers { get; set; } = [];
    public string[] RelayUrls { get; set; } = [];
    public string DataSecret { get; set; } = "";
    public string NetworkMode { get; set; } = "tun";
    public long NetworkPolicyRevision { get; set; }
    /// <summary>获取或设置协调与中继服务器地址。</summary>
    public string Server { get; set; } = string.Empty;
    /// <summary>获取或设置客户端所属的隔离 VPN 分组。</summary>
    public string Group { get; set; } = string.Empty;
    /// <summary>仅用于从旧版 room 字段迁移，保存时不会继续写出。</summary>
    [JsonPropertyName("room")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? LegacyRoom { get; set; }
    /// <summary>获取或设置服务端与客户端共享的认证密钥。</summary>
    public string SharedSecret { get; set; } = string.Empty;
    /// <summary>获取或设置 Windows 虚拟网卡名称。</summary>
    public string AdapterName { get; set; } = "Edge VPN";
    /// <summary>管理服务根地址，用于版本检查、强制更新和打洞结果上报。</summary>
    public string ManagementUrl { get; set; } = string.Empty;
    /// <summary>服务端客户端包平台标识；留空时自动识别。</summary>
    public string Platform { get; set; } = string.Empty;
    /// <summary>自动检查并安装服务端发布的强制更新。</summary>
    public bool EnableAutoUpdate { get; set; } = false;
    /// <summary>固定的本地 UDP/TCP 端口；为 0 时客户端会选择可用端口。</summary>
    public int LocalPort { get; set; }
    /// <summary>路由器支持时，自动创建 UDP/TCP UPnP 映射并作为首选公网候选。</summary>
    public bool EnableUpnp { get; set; } = true;
    /// <summary>UPnP 映射租期，客户端会在半程自动续租。</summary>
    public int UpnpLeaseSeconds { get; set; } = 3600;
    /// <summary>UDP 公网端口猜测范围，用于没有 UPnP 或对称 NAT 的回退探测。</summary>
    public int UdpPortFanout { get; set; } = 16;
    /// <summary>TCP 公网端口猜测范围。</summary>
    public int TcpPortFanout { get; set; } = 16;
    /// <summary>直连建立模式：on-demand 按业务触发，eager 上线后立即尝试所有节点。</summary>
    public string TraversalMode { get; set; } = "on-demand";
    /// <summary>按需直连连续无业务后释放的分钟数。</summary>
    public int DirectIdleMinutes { get; set; } = 60;
    /// <summary>
    /// 获取或设置Gateway Mode。
    /// </summary>
    /// <returns>Gateway Mode。</returns>
    public string GatewayMode { get; set; } = "local";
    /// <summary>
    /// 获取或设置Gateway Lan Interface。
    /// </summary>
    /// <returns>Gateway Lan Interface。</returns>
    public string GatewayLanInterface { get; set; } = string.Empty;
    /// <summary>
    /// 获取或设置Gateway Lan Subnet。
    /// </summary>
    /// <returns>Gateway Lan Subnet。</returns>
    public string GatewayLanSubnet { get; set; } = string.Empty;
    /// <summary>
    /// 获取或设置Gateway Networks。
    /// </summary>
    /// <returns>Gateway Networks。</returns>
    public List<ClientGatewayNetwork> GatewayNetworks { get; set; } = [];
    /// <summary>
    /// 获取或设置Remote Subnet Routes。
    /// </summary>
    /// <returns>Remote Subnet Routes。</returns>
    public List<ClientSubnetRoute> RemoteSubnetRoutes { get; set; } = [];
}

/// <summary>
/// 表示 Client Gateway Network，并提供相关数据或行为。
/// </summary>
internal sealed class ClientGatewayNetwork
{
    public string[] AllowedClients { get; set; } = ["*"];
    /// <summary>
    /// 获取或设置Enabled。
    /// </summary>
    /// <returns>Enabled。</returns>
    public bool Enabled { get; set; } = true;
    /// <summary>
    /// 获取或设置Interface。
    /// </summary>
    /// <returns>Interface。</returns>
    public string Interface { get; set; } = string.Empty;
    /// <summary>
    /// 获取或设置Subnet。
    /// </summary>
    /// <returns>Subnet。</returns>
    public string Subnet { get; set; } = string.Empty;
}

/// <summary>
/// 表示 Client Subnet Route，并提供相关数据或行为。
/// </summary>
internal sealed class ClientSubnetRoute
{
    /// <summary>
    /// 获取或设置Enabled。
    /// </summary>
    /// <returns>Enabled。</returns>
    public bool Enabled { get; set; } = true;
    /// <summary>
    /// 获取或设置Subnet。
    /// </summary>
    /// <returns>Subnet。</returns>
    public string Subnet { get; set; } = string.Empty;
    /// <summary>
    /// 获取或设置Destination Subnet。
    /// </summary>
    /// <returns>Destination Subnet。</returns>
    public string DestinationSubnet { get; set; } = string.Empty;
    /// <summary>
    /// 获取或设置Gateway Virtual Ip。
    /// </summary>
    /// <returns>Gateway Virtual Ip。</returns>
    public string GatewayVirtualIp { get; set; } = string.Empty;
}

/// <summary>
/// 表示 Client Json Context，并提供相关数据或行为。
/// </summary>
[JsonSourceGenerationOptions(PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase,
    PropertyNameCaseInsensitive = true, WriteIndented = true)]
[JsonSerializable(typeof(ClientConfig))]
[JsonSerializable(typeof(Dictionary<string, string>))]
[JsonSerializable(typeof(ClientGatewayNetwork))]
[JsonSerializable(typeof(ClientSubnetRoute))]
internal sealed partial class ClientJsonContext : JsonSerializerContext;

/// <summary>在受保护的公共程序数据目录中读取和写入客户端配置。</summary>
internal static class ClientConfigStore
{
    internal static readonly string DirectoryPath = OperatingSystem.IsWindows()
        ? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "Edge VPN")
        : "/var/lib/edge-vpn";
    /// <summary>获取真实可执行文件目录，不受 Windows 服务工作目录影响。</summary>
    internal static string ExecutableDirectory => Path.GetDirectoryName(Environment.ProcessPath)
        ?? AppContext.BaseDirectory;
    /// <summary>
    /// 获取或设置Config Path。
    /// </summary>
    /// <returns>Config Path。</returns>
    internal static string ConfigPath => Path.Combine(ExecutableDirectory, "client.json");
    /// <summary>
    /// 获取或设置Device Id Path。
    /// </summary>
    /// <returns>Device Id Path。</returns>
    internal static string DeviceIdPath => Path.Combine(DirectoryPath, "device-id.txt");
    /// <summary>
    /// 获取或设置Log Path。
    /// </summary>
    /// <returns>Log Path。</returns>
    internal static string LogPath => Path.Combine(DirectoryPath, "client.log");

    /// <summary>读取并验证当前客户端配置。</summary>
    /// <param name="path">要读取的配置路径；为空时读取 ProgramData 中的已安装配置。</param>
    /// <returns>可以启动服务的客户端配置。</returns>
    internal static ClientConfig Load(string? path = null)
    {
        string actualPath = path ?? ConfigPath;
        ReadOnlySpan<byte> json = File.ReadAllBytes(actualPath);
        if (json.Length >= 3 && json[0] == 0xef && json[1] == 0xbb && json[2] == 0xbf) json = json[3..];
        ClientConfig config = JsonSerializer.Deserialize(json,
            ClientJsonContext.Default.ClientConfig) ?? throw new InvalidDataException("客户端配置内容为空。");
        if (string.IsNullOrWhiteSpace(config.Group) && !string.IsNullOrWhiteSpace(config.LegacyRoom))
            config.Group = config.LegacyRoom;
        config.LegacyRoom = null;
        Validate(config);
        return config;
    }

    /// <summary>验证并原子保存客户端配置。</summary>
    /// <param name="config">需要保存的客户端配置。</param>
    internal static void Save(ClientConfig config)
    {
        Validate(config);
        Directory.CreateDirectory(Path.GetDirectoryName(ConfigPath)!);
        ProtectDirectory();
        byte[] json = JsonSerializer.SerializeToUtf8Bytes(config, ClientJsonContext.Default.ClientConfig);
        string temporary = ConfigPath + ".tmp";
        using (var stream = new FileStream(temporary, FileMode.Create, FileAccess.Write,
            FileShare.None, 4096, FileOptions.WriteThrough))
        {
            stream.Write(json);
            stream.Flush(true);
        }
        File.Move(temporary, ConfigPath, true);
    }

    /// <summary>验证客户端配置中的必填字段和资源上限。</summary>
    /// <param name="config">需要验证的客户端配置。</param>
    private static void Validate(ClientConfig config)
    {
        ClientNetworkPolicy.FromConfig(config).Validate();
        if (string.IsNullOrWhiteSpace(config.Server)) throw new InvalidDataException("必须配置服务器地址。");
        if (string.IsNullOrWhiteSpace(config.Group) || config.Group.Length > 128)
            throw new InvalidDataException("分组名称不能为空且不能超过 128 个字符。");
        if (config.SharedSecret.Length < 12 || config.SharedSecret.Contains("请替换", StringComparison.Ordinal) ||
            config.SharedSecret.StartsWith("replace-with", StringComparison.OrdinalIgnoreCase))
            throw new InvalidDataException("共享密钥无效，请在 client.json 中填入服务端生成的真实共享密钥。");
        if (config.LocalPort is < 0 or > 65535)
            throw new InvalidDataException("本地端口必须是 0 到 65535；0 表示自动选择。");
        if (config.UpnpLeaseSeconds is < 300 or > 86400)
            throw new InvalidDataException("UPnP 租期必须是 300 到 86400 秒。");
        if (config.UdpPortFanout is < 0 or > 128 || config.TcpPortFanout is < 0 or > 128)
            throw new InvalidDataException("公网端口猜测范围必须是 0 到 128。");
        if (config.TraversalMode is not ("on-demand" or "eager"))
            throw new InvalidDataException("直连模式只能是 on-demand 或 eager。");
        if (config.DirectIdleMinutes is < 1 or > 10080)
            throw new InvalidDataException("直连空闲释放时间必须是 1 到 10080 分钟。");
        if (config.RemoteSubnetRoutes.Count > 64)
            throw new InvalidDataException("Remote subnet routes cannot exceed 64 entries.");
        foreach (ClientSubnetRoute route in config.RemoteSubnetRoutes)
        {
            if (!route.Enabled) continue;
            if (!TryParseIpv4Cidr(route.Subnet, out _, out int exposedPrefix))
                throw new InvalidDataException($"Invalid remote IPv4 subnet: {route.Subnet}");
            if (!string.IsNullOrWhiteSpace(route.DestinationSubnet) &&
                (!TryParseIpv4Cidr(route.DestinationSubnet, out _, out int destinationPrefix) ||
                 destinationPrefix != exposedPrefix))
                throw new InvalidDataException($"Destination subnet must be valid and use the same prefix: {route.DestinationSubnet}");
            if (!IPAddress.TryParse(route.GatewayVirtualIp, out IPAddress? gateway) ||
                gateway.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork || gateway.Equals(IPAddress.Any))
                throw new InvalidDataException($"Invalid VPN gateway IPv4 address: {route.GatewayVirtualIp}");
        }
        if (config.GatewayMode is not ("local" or "nat" or "route"))
            throw new InvalidDataException("Gateway mode must be local, nat or route.");
        if (config.GatewayLanInterface.Length > 128)
            throw new InvalidDataException("Gateway LAN interface name is too long.");
        if (config.GatewayNetworks.Count > 32)
            throw new InvalidDataException("Gateway networks cannot exceed 32 entries.");
        IReadOnlyList<ClientGatewayNetwork> gatewayNetworks = GetGatewayNetworks(config);
        if (config.GatewayMode != "local" && gatewayNetworks.Count == 0)
            throw new InvalidDataException("Gateway mode requires at least one enabled gateway network.");
        foreach (ClientGatewayNetwork network in gatewayNetworks)
        {
            if (network.Interface.Length > 128)
                throw new InvalidDataException("Gateway LAN interface name is too long.");
            if (!TryParseIpv4Cidr(network.Subnet, out _, out _))
                throw new InvalidDataException($"Invalid gateway IPv4 subnet: {network.Subnet}");
        }
        if (string.IsNullOrWhiteSpace(config.AdapterName) || config.AdapterName.Length > 64)
            throw new InvalidDataException("虚拟网卡名称无效。");
        if (!string.IsNullOrWhiteSpace(config.ManagementUrl) &&
            (!Uri.TryCreate(config.ManagementUrl, UriKind.Absolute, out Uri? management) ||
             management.Scheme is not ("http" or "https")))
            throw new InvalidDataException("ManagementUrl 必须是 http 或 https 绝对地址。");
        if (!string.IsNullOrWhiteSpace(config.Platform) && config.Platform is not
            ("win-x64" or "win-x86" or "linux-x64" or "linux-arm64" or "linux-arm"))
            throw new InvalidDataException("客户端平台标识无效。");
    }

    /// <summary>把配置目录权限限制为本机 SYSTEM 和管理员。</summary>
    internal static bool TryParseIpv4Cidr(string value, out IPAddress network, out int prefixLength)
    {
        network = IPAddress.Any;
        prefixLength = 0;
        string[] parts = value.Trim().Split('/', 2);
        if (parts.Length != 2 || !IPAddress.TryParse(parts[0], out IPAddress? address) ||
            address.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork ||
            !int.TryParse(parts[1], out prefixLength) || prefixLength is < 1 or > 32) return false;
        byte[] bytes = address.GetAddressBytes();
        int remaining = prefixLength;
        for (int index = 0; index < bytes.Length; index++)
        {
            int bits = Math.Clamp(remaining, 0, 8);
            bytes[index] &= (byte)(bits == 0 ? 0 : 0xff << (8 - bits));
            remaining -= bits;
        }
        network = new IPAddress(bytes);
        return true;
    }

    /// <summary>
    /// 获取Gateway Networks。
    /// </summary>
    /// <param name="config">config参数。</param>
    /// <returns>操作结果。</returns>
    internal static IReadOnlyList<ClientGatewayNetwork> GetGatewayNetworks(ClientConfig config)
    {
        ClientGatewayNetwork[] configured = config.GatewayNetworks
            .Where(static item => item.Enabled)
            .Select(static item => new ClientGatewayNetwork
            {
                Enabled = true,
                Interface = item.Interface.Trim(),
                Subnet = item.Subnet.Trim(),
                AllowedClients = item.AllowedClients
            })
            .ToArray();
        if (configured.Length > 0) return configured;
        if (string.IsNullOrWhiteSpace(config.GatewayLanSubnet)) return [];
        return [new ClientGatewayNetwork
        {
            Enabled = true,
            Interface = config.GatewayLanInterface.Trim(),
            Subnet = config.GatewayLanSubnet.Trim()
        }];
    }

    /// <summary>
    /// 执行Protect Directory操作。
    /// </summary>
    internal static void ProtectDirectory()
    {
        Directory.CreateDirectory(DirectoryPath);
        if (!OperatingSystem.IsWindows())
        {
            File.SetUnixFileMode(DirectoryPath, UnixFileMode.UserRead | UnixFileMode.UserWrite |
                UnixFileMode.UserExecute);
            return;
        }
        var security = new System.Security.AccessControl.DirectorySecurity();
        security.SetAccessRuleProtection(true, false);
        const System.Security.AccessControl.InheritanceFlags inheritance =
            System.Security.AccessControl.InheritanceFlags.ContainerInherit |
            System.Security.AccessControl.InheritanceFlags.ObjectInherit;
        security.AddAccessRule(new System.Security.AccessControl.FileSystemAccessRule(
            new System.Security.Principal.SecurityIdentifier(
                System.Security.Principal.WellKnownSidType.LocalSystemSid, null),
            System.Security.AccessControl.FileSystemRights.FullControl, inheritance,
            System.Security.AccessControl.PropagationFlags.None,
            System.Security.AccessControl.AccessControlType.Allow));
        security.AddAccessRule(new System.Security.AccessControl.FileSystemAccessRule(
            new System.Security.Principal.SecurityIdentifier(
                System.Security.Principal.WellKnownSidType.BuiltinAdministratorsSid, null),
            System.Security.AccessControl.FileSystemRights.FullControl, inheritance,
            System.Security.AccessControl.PropagationFlags.None,
            System.Security.AccessControl.AccessControlType.Allow));
        new DirectoryInfo(DirectoryPath).SetAccessControl(security);
    }
}
