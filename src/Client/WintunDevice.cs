using System.ComponentModel;
using System.Diagnostics;
using System.Net;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace QuicSample;

/// <summary>封装 wintun.dll 的适配器、会话、收包环和发包环。</summary>
internal sealed class WintunDevice : IAsyncDisposable
{
    private const uint RingCapacity = 8 * 1024 * 1024;
    private const int ErrorNoMoreItems = 259;
    private const int ErrorBufferOverflow = 111;
    private static readonly Guid AdapterGuid = new("B34E3A2F-7B8D-4CCB-A9C9-74E7B6C9A201");
    private readonly IntPtr _adapter;
    private readonly IntPtr _session;
    private readonly EventWaitHandle _readEvent;
    private readonly HashSet<string> _peerNeighbors = new(StringComparer.Ordinal);
    private readonly HashSet<string> _remoteRoutes = new(StringComparer.Ordinal);
    private int _disposed;

    /// <summary>初始化一个已经启动并配置地址的 Wintun 设备。</summary>
    /// <param name="adapter">Wintun 适配器句柄。</param>
    /// <param name="session">Wintun 会话句柄。</param>
    /// <param name="readEvent">收包环可读事件。</param>
    /// <param name="name">Windows 网络接口名称。</param>
    /// <param name="address">接口 IPv4 地址。</param>
    /// <param name="mtu">接口 IPv4 MTU。</param>
    private WintunDevice(IntPtr adapter, IntPtr session, EventWaitHandle readEvent,
        string name, IPAddress address, int mtu)
    {
        _adapter = adapter;
        _session = session;
        _readEvent = readEvent;
        Name = name;
        Address = address;
        Mtu = mtu;
    }

    /// <summary>获取 Windows 网络接口名称。</summary>
    public string Name { get; }

    /// <summary>获取接口 IPv4 地址。</summary>
    public IPAddress Address { get; private set; }

    /// <summary>获取接口 MTU。</summary>
    public int Mtu { get; }

    /// <summary>在适配器和 Wintun 会话保持打开时更新本机 IPv4 租约。</summary>
    /// <param name="address">服务端新分配的 IPv4 地址。</param>
    /// <param name="prefixLength">IPv4 前缀长度。</param>
    /// <param name="cancellationToken">netsh 配置取消令牌。</param>
    /// <returns>地址和 MTU 更新完成时结束的任务。</returns>
    public async Task ReconfigureAsync(IPAddress address, int prefixLength,
        CancellationToken cancellationToken)
    {
        ThrowIfDisposed();
        ArgumentNullException.ThrowIfNull(address);
        if (address.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork)
            throw new ArgumentException("本示例当前只配置 IPv4 TUN 地址。", nameof(address));
        await ConfigureInterfaceAsync(Name, address, prefixLength, Mtu, cancellationToken)
            .ConfigureAwait(false);
        Address = address;
    }

    /// <summary>
    /// 执行Synchronize Peer Addresses操作。
    /// </summary>
    /// <param name="addresses">addresses参数。</param>
    /// <param name="cancellationToken">用于取消异步操作的令牌。</param>
    /// <returns>操作结果。</returns>
    public async Task SynchronizePeerAddressesAsync(IReadOnlyCollection<IPAddress> addresses,
        CancellationToken cancellationToken)
    {
        ThrowIfDisposed();
        var desired = addresses.Where(static value =>
                value.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
            .Select(static value => value.ToString()).ToHashSet(StringComparer.Ordinal);
        foreach (string address in _peerNeighbors.Except(desired).ToArray())
        {
            try { await RunNetshAsync(["interface", "ipv4", "delete", "neighbors", Name, address],
                cancellationToken).ConfigureAwait(false); }
            catch { }
            _peerNeighbors.Remove(address);
        }
        foreach (string address in desired.Except(_peerNeighbors).ToArray())
        {
            try { await RunNetshAsync(["interface", "ipv4", "delete", "neighbors", Name, address],
                cancellationToken).ConfigureAwait(false); }
            catch { }
            await RunNetshAsync(["interface", "ipv4", "add", "neighbors", Name, address,
                "00-00-00-00-00-00", "store=active"], cancellationToken).ConfigureAwait(false);
            _peerNeighbors.Add(address);
        }
    }

    /// <summary>
    /// 执行Synchronize Remote Routes操作。
    /// </summary>
    /// <param name="cidrs">cidrs参数。</param>
    /// <param name="cancellationToken">用于取消异步操作的令牌。</param>
    /// <returns>操作结果。</returns>
    public async Task SynchronizeRemoteRoutesAsync(IReadOnlyCollection<string> cidrs,
        CancellationToken cancellationToken)
    {
        ThrowIfDisposed();
        var desired = cidrs.ToHashSet(StringComparer.Ordinal);
        foreach (string cidr in _remoteRoutes.Except(desired).ToArray())
        {
            try
            {
                await RunNetshAsync(["interface", "ipv4", "delete", "route",
                    $"prefix={cidr}", $"interface={Name}", "nexthop=0.0.0.0", "store=active"],
                    cancellationToken).ConfigureAwait(false);
            }
            catch { }
            _remoteRoutes.Remove(cidr);
        }
        foreach (string cidr in desired.Except(_remoteRoutes).ToArray())
        {
            await RunNetshAsync(["interface", "ipv4", "add", "route",
                $"prefix={cidr}", $"interface={Name}", "nexthop=0.0.0.0", "metric=1", "store=active"],
                cancellationToken).ConfigureAwait(false);
            _remoteRoutes.Add(cidr);
        }
    }

    /// <summary>验证当前进程可以加载 wintun.dll，且所有必需 API 均已导出。</summary>
    public static void ValidateNativeLibrary()
    {
        string[] exports =
        [
            "WintunOpenAdapter", "WintunCreateAdapter", "WintunCloseAdapter",
            "WintunStartSession", "WintunEndSession", "WintunGetReadWaitEvent",
            "WintunReceivePacket", "WintunReleaseReceivePacket",
            "WintunAllocateSendPacket", "WintunSendPacket"
        ];
        IntPtr library = NativeLibrary.Load("wintun.dll");
        try
        {
            foreach (string export in exports)
            {
                if (!NativeLibrary.TryGetExport(library, export, out _))
                    throw new EntryPointNotFoundException($"wintun.dll 缺少导出函数 {export}。");
            }
        }
        finally
        {
            NativeLibrary.Free(library);
        }
    }

    /// <summary>打开或创建 Wintun 适配器，并配置静态 IPv4 地址和 MTU。</summary>
    /// <param name="name">持久化适配器名称。</param>
    /// <param name="address">要配置的 IPv4 地址。</param>
    /// <param name="prefixLength">IPv4 前缀长度，本示例使用 30。</param>
    /// <param name="mtu">不超过 QUIC DATAGRAM 负载上限的 MTU。</param>
    /// <param name="cancellationToken">配置过程取消令牌。</param>
    /// <returns>已经可以收发 IP 包的 Wintun 设备。</returns>
    public static async Task<WintunDevice> CreateAsync(string name, IPAddress address,
        int prefixLength, int mtu, CancellationToken cancellationToken)
    {
        if (!OperatingSystem.IsWindows())
            throw new PlatformNotSupportedException("Wintun 只支持 Windows。");
        ArgumentException.ThrowIfNullOrWhiteSpace(name);
        ArgumentNullException.ThrowIfNull(address);
        if (address.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork)
            throw new ArgumentException("本示例当前只配置 IPv4 TUN 地址。", nameof(address));
        if (prefixLength is < 1 or > 32) throw new ArgumentOutOfRangeException(nameof(prefixLength));
        if (mtu is < 576 or > 65_535) throw new ArgumentOutOfRangeException(nameof(mtu));

        string actualName = FindInterfaceName(AdapterGuid) ?? name;
        IntPtr adapter = Native.WintunOpenAdapter(actualName);
        if (adapter != IntPtr.Zero && !HasExpectedGuid(adapter))
        {
            Native.WintunCloseAdapter(adapter);
            adapter = IntPtr.Zero;
        }
        if (adapter == IntPtr.Zero && FindInterfaceByName(name) is NetworkInterface legacy &&
            !HasInterfaceGuid(legacy, AdapterGuid) && IsP2PVpnInterface(legacy))
            await MoveLegacyInterfaceAsideAsync(legacy.Name, cancellationToken).ConfigureAwait(false);
        if (adapter == IntPtr.Zero)
        {
            Guid requestedGuid = AdapterGuid;
            adapter = Native.WintunCreateAdapter(name, "Edge VPN", ref requestedGuid);
            if (adapter == IntPtr.Zero) ThrowNative("创建 Wintun 适配器失败");
        }

        actualName = await WaitForInterfaceNameAsync(AdapterGuid, name, cancellationToken)
            .ConfigureAwait(false);
        if (!string.Equals(actualName, name, StringComparison.OrdinalIgnoreCase))
        {
            NetworkInterface? occupied = FindInterfaceByName(name);
            if (occupied is not null && !HasInterfaceGuid(occupied, AdapterGuid) && IsP2PVpnInterface(occupied))
                await MoveLegacyInterfaceAsideAsync(occupied.Name, cancellationToken).ConfigureAwait(false);
            try
            {
                await RunNetshAsync(["interface", "set", "interface", $"name={actualName}", $"newname={name}"],
                    cancellationToken).ConfigureAwait(false);
                actualName = await WaitForInterfaceNameAsync(AdapterGuid, name, cancellationToken)
                    .ConfigureAwait(false);
            }
            catch { }
        }

        IntPtr session = Native.WintunStartSession(adapter, RingCapacity);
        if (session == IntPtr.Zero)
        {
            Native.WintunCloseAdapter(adapter);
            ThrowNative("启动 Wintun 收发会话失败");
        }

        EventWaitHandle? readEvent = null;
        try
        {
            IntPtr nativeEvent = Native.WintunGetReadWaitEvent(session);
            if (nativeEvent == IntPtr.Zero) ThrowNative("获取 Wintun 可读事件失败");
            readEvent = new EventWaitHandle(false, EventResetMode.AutoReset);
            readEvent.SafeWaitHandle = new SafeWaitHandle(nativeEvent, ownsHandle: false);
            await ConfigureInterfaceAsync(actualName, address, prefixLength, mtu, cancellationToken)
                .ConfigureAwait(false);
            return new WintunDevice(adapter, session, readEvent, actualName, address, mtu);
        }
        catch
        {
            readEvent?.Dispose();
            Native.WintunEndSession(session);
            Native.WintunCloseAdapter(adapter);
            throw;
        }
    }

    /// <summary>
    /// 执行Has Expected Guid操作。
    /// </summary>
    /// <param name="adapter">adapter参数。</param>
    /// <returns>操作结果。</returns>
    private static bool HasExpectedGuid(IntPtr adapter)
    {
        try
        {
            Native.WintunGetAdapterLuid(adapter, out ulong luid);
            return Native.ConvertInterfaceLuidToGuid(ref luid, out Guid guid) == 0 && guid == AdapterGuid;
        }
        catch { return false; }
    }

    /// <summary>
    /// 执行Find Interface By Name操作。
    /// </summary>
    /// <param name="name">名称。</param>
    /// <returns>操作结果。</returns>
    private static NetworkInterface? FindInterfaceByName(string name) =>
        NetworkInterface.GetAllNetworkInterfaces().FirstOrDefault(item =>
            string.Equals(item.Name, name, StringComparison.OrdinalIgnoreCase));

    /// <summary>
    /// 执行Find Interface Name操作。
    /// </summary>
    /// <param name="guid">guid参数。</param>
    /// <returns>操作结果。</returns>
    private static string? FindInterfaceName(Guid guid) =>
        NetworkInterface.GetAllNetworkInterfaces().FirstOrDefault(item => HasInterfaceGuid(item, guid))?.Name;

    /// <summary>
    /// 执行Has Interface Guid操作。
    /// </summary>
    /// <param name="item">item参数。</param>
    /// <param name="expected">expected参数。</param>
    /// <returns>操作结果。</returns>
    private static bool HasInterfaceGuid(NetworkInterface item, Guid expected) =>
        Guid.TryParse(item.Id, out Guid actual) && actual == expected;

    /// <summary>
    /// 执行Is P2P Vpn Interface操作。
    /// </summary>
    /// <param name="item">item参数。</param>
    /// <returns>操作结果。</returns>
    private static bool IsP2PVpnInterface(NetworkInterface item) =>
        item.Description.Contains("Edge VPN", StringComparison.OrdinalIgnoreCase) ||
        item.Description.Contains("Wintun", StringComparison.OrdinalIgnoreCase);

    /// <summary>
    /// 执行Wait For Interface Name操作。
    /// </summary>
    /// <param name="guid">guid参数。</param>
    /// <param name="fallback">fallback参数。</param>
    /// <param name="cancellationToken">用于取消异步操作的令牌。</param>
    /// <returns>操作结果。</returns>
    private static async Task<string> WaitForInterfaceNameAsync(Guid guid, string fallback,
        CancellationToken cancellationToken)
    {
        for (int attempt = 0; attempt < 30; attempt++)
        {
            string? value = FindInterfaceName(guid);
            if (!string.IsNullOrWhiteSpace(value)) return value;
            await Task.Delay(200, cancellationToken).ConfigureAwait(false);
        }
        return fallback;
    }

    /// <summary>
    /// 执行Move Legacy Interface Aside操作。
    /// </summary>
    /// <param name="currentName">current Name参数。</param>
    /// <param name="cancellationToken">用于取消异步操作的令牌。</param>
    /// <returns>操作结果。</returns>
    private static async Task MoveLegacyInterfaceAsideAsync(string currentName,
        CancellationToken cancellationToken)
    {
        string suffix = Guid.NewGuid().ToString("N")[..8];
        string legacyName = $"Edge VPN 旧设备 {suffix}";
        try
        {
            await RunNetshAsync(["interface", "set", "interface", $"name={currentName}", "admin=disabled"],
                cancellationToken).ConfigureAwait(false);
        }
        catch { }
        await RunNetshAsync(["interface", "set", "interface", $"name={currentName}", $"newname={legacyName}"],
            cancellationToken).ConfigureAwait(false);
    }

    /// <summary>从 Wintun 收包环读取一个完整的三层 IP 包。</summary>
    /// <param name="destination">接收完整 IP 包的缓冲区。</param>
    /// <param name="cancellationToken">等待收包取消令牌。</param>
    /// <returns>完整 IP 包字节数。</returns>
    public async ValueTask<int> ReadAsync(Memory<byte> destination,
        CancellationToken cancellationToken)
    {
        ThrowIfDisposed();
        while (true)
        {
            cancellationToken.ThrowIfCancellationRequested();
            IntPtr packet = Native.WintunReceivePacket(_session, out uint packetSize);
            if (packet != IntPtr.Zero)
            {
                try
                {
                    if (packetSize > destination.Length)
                        throw new InvalidDataException($"Wintun 包 {packetSize} 字节超过接收缓冲区。");
                    CopyFromNative(packet, destination.Span, checked((int)packetSize));
                    return checked((int)packetSize);
                }
                finally
                {
                    Native.WintunReleaseReceivePacket(_session, packet);
                }
            }

            int error = Marshal.GetLastPInvokeError();
            if (error != ErrorNoMoreItems)
                throw new Win32Exception(error, "从 Wintun 收包环读取失败。");
            await WaitForPacketAsync(cancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>把一个完整的三层 IP 包写入 Wintun 发包环。</summary>
    /// <param name="packet">要注入本机协议栈的完整 IP 包。</param>
    /// <param name="cancellationToken">发包环拥塞等待取消令牌。</param>
    /// <returns>包提交到 Wintun 后完成的操作。</returns>
    public async ValueTask WriteAsync(ReadOnlyMemory<byte> packet,
        CancellationToken cancellationToken)
    {
        ThrowIfDisposed();
        if (packet.IsEmpty || packet.Length > ushort.MaxValue)
            throw new ArgumentOutOfRangeException(nameof(packet));
        while (true)
        {
            cancellationToken.ThrowIfCancellationRequested();
            IntPtr destination = Native.WintunAllocateSendPacket(_session, checked((uint)packet.Length));
            if (destination != IntPtr.Zero)
            {
                CopyToNative(packet.Span, destination);
                Native.WintunSendPacket(_session, destination);
                return;
            }

            int error = Marshal.GetLastPInvokeError();
            if (error != ErrorBufferOverflow)
                throw new Win32Exception(error, "向 Wintun 发包环分配空间失败。");
            await Task.Delay(1, cancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>丢弃 Wintun 收包环中断联期间积压的旧 IP 包。</summary>
    /// <param name="cancellationToken">清理过程取消令牌。</param>
    /// <returns>已经从收包环释放的旧包数量。</returns>
    public long DiscardPendingPackets(CancellationToken cancellationToken)
    {
        ThrowIfDisposed();
        long discarded = 0;
        while (true)
        {
            cancellationToken.ThrowIfCancellationRequested();
            IntPtr packet = Native.WintunReceivePacket(_session, out _);
            if (packet != IntPtr.Zero)
            {
                Native.WintunReleaseReceivePacket(_session, packet);
                discarded++;
                continue;
            }

            int error = Marshal.GetLastPInvokeError();
            if (error == ErrorNoMoreItems) return discarded;
            throw new Win32Exception(error, "清理 Wintun 收包环失败。");
        }
    }

    /// <summary>结束会话并关闭适配器句柄；适配器本身保留供下次复用。</summary>
    /// <returns>资源释放完成的操作。</returns>
    public ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0) return ValueTask.CompletedTask;
        _readEvent.Dispose();
        Native.WintunEndSession(_session);
        Native.WintunCloseAdapter(_adapter);
        return ValueTask.CompletedTask;
    }

    /// <summary>异步等待 Wintun 可读事件或取消事件，空闲时不占用线程池工作线程。</summary>
    /// <param name="cancellationToken">等待取消令牌。</param>
    /// <returns>事件触发时完成的任务。</returns>
    private async Task WaitForPacketAsync(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var completion = new TaskCompletionSource<bool>(
            TaskCreationOptions.RunContinuationsAsynchronously);
        RegisteredWaitHandle? registeredWait = null;
        using CancellationTokenRegistration cancellationRegistration = cancellationToken.Register(
            static state =>
            {
                var value = ((TaskCompletionSource<bool> Completion,
                    CancellationToken Token))state!;
                value.Completion.TrySetCanceled(value.Token);
            },
            (completion, cancellationToken));
        try
        {
            // Wintun 官方模型是“读空后只等待一次，再重新读取”。一次性注册可避免
            // 断联期间 ring 非空时，电平触发事件持续回调并耗尽线程池。
            registeredWait = ThreadPool.RegisterWaitForSingleObject(
                _readEvent,
                static (state, _) => ((TaskCompletionSource<bool>)state!).TrySetResult(true),
                completion,
                250,
                executeOnlyOnce: true);
            await completion.Task.ConfigureAwait(false);
        }
        finally
        {
            registeredWait?.Unregister(null);
        }
    }

    /// <summary>使用 netsh 为刚创建的接口配置地址和链路 MTU。</summary>
    /// <param name="name">Windows 接口名称。</param>
    /// <param name="address">静态 IPv4 地址。</param>
    /// <param name="prefixLength">IPv4 前缀长度。</param>
    /// <param name="mtu">IPv4 MTU。</param>
    /// <param name="cancellationToken">进程等待取消令牌。</param>
    /// <returns>两个配置命令均成功时完成的任务。</returns>
    private static async Task ConfigureInterfaceAsync(string name, IPAddress address,
        int prefixLength, int mtu, CancellationToken cancellationToken)
    {
        string mask = PrefixToMask(prefixLength);
        foreach (IPAddress existing in GetInterfaceIpv4Addresses(name).Where(item => !item.Equals(address)))
        {
            try
            {
                await RunNetshAsync([
                    "interface", "ipv4", "delete", "address", $"name={name}",
                    $"address={existing}", "gateway=all", "store=persistent"
                ], cancellationToken).ConfigureAwait(false);
            }
            catch { }
        }
        await RunNetshAsync([
            "interface", "ipv4", "set", "address", $"name={name}", "source=static",
            $"address={address}", $"mask={mask}", "gateway=none", "store=persistent"
        ], cancellationToken).ConfigureAwait(false);
        await RunNetshAsync([
            "interface", "ipv4", "set", "subinterface", name, $"mtu={mtu}", "store=persistent"
        ], cancellationToken).ConfigureAwait(false);
        for (int attempt = 0; attempt < 20; attempt++)
        {
            IPAddress[] configured = GetInterfaceIpv4Addresses(name);
            if (configured.Length == 1 && configured[0].Equals(address))
            {
                await ConfigureVpnFirewallAsync(address, prefixLength, cancellationToken)
                    .ConfigureAwait(false);
                return;
            }
            await Task.Delay(250, cancellationToken).ConfigureAwait(false);
        }
        string actual = string.Join(',', GetInterfaceIpv4Addresses(name));
        throw new InvalidOperationException($"Wintun 地址回读校验失败：期望 {address}/{prefixLength}，实际 [{actual}]。");
    }

    /// <summary>只允许同一虚拟 IPv4 网段访问本机 VPN 地址。</summary>
    private static async Task ConfigureVpnFirewallAsync(IPAddress address, int prefixLength,
        CancellationToken cancellationToken)
    {
        const string ruleName = "Edge VPN 虚拟网络入站";
        string cidr = GetNetworkCidr(address, prefixLength);
        try
        {
            await RunNetshAsync(["advfirewall", "firewall", "delete", "rule", $"name={ruleName}"],
                cancellationToken).ConfigureAwait(false);
        }
        catch { }
        await RunNetshAsync([
            "advfirewall", "firewall", "add", "rule", $"name={ruleName}", "dir=in",
            "action=allow", "enable=yes", "profile=any", $"localip={address}", $"remoteip={cidr}"
        ], cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// 获取Network Cidr。
    /// </summary>
    /// <param name="address">网络地址。</param>
    /// <param name="prefixLength">prefix Length参数。</param>
    /// <returns>操作结果。</returns>
    private static string GetNetworkCidr(IPAddress address, int prefixLength)
    {
        byte[] bytes = address.GetAddressBytes();
        int remaining = prefixLength;
        for (int index = 0; index < bytes.Length; index++)
        {
            int bits = Math.Clamp(remaining, 0, 8);
            bytes[index] &= (byte)(bits == 0 ? 0 : 0xff << (8 - bits));
            remaining -= bits;
        }
        return $"{new IPAddress(bytes)}/{prefixLength}";
    }

    /// <summary>
    /// 获取Interface Ipv4 Addresses。
    /// </summary>
    /// <param name="name">名称。</param>
    /// <returns>操作结果。</returns>
    private static IPAddress[] GetInterfaceIpv4Addresses(string name) => NetworkInterface
        .GetAllNetworkInterfaces()
        .Where(item => string.Equals(item.Name, name, StringComparison.OrdinalIgnoreCase))
        .SelectMany(static item => item.GetIPProperties().UnicastAddresses)
        .Select(static item => item.Address)
        .Where(static item => item.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
        .ToArray();

    /// <summary>运行单个参数化 netsh 命令并检查退出码。</summary>
    /// <param name="arguments">不经过 shell 拼接的参数列表。</param>
    /// <param name="cancellationToken">进程等待取消令牌。</param>
    /// <returns>netsh 成功退出时完成的任务。</returns>
    private static async Task RunNetshAsync(string[] arguments, CancellationToken cancellationToken)
    {
        var startInfo = new ProcessStartInfo("netsh.exe")
        {
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true
        };
        foreach (string argument in arguments) startInfo.ArgumentList.Add(argument);
        using Process process = Process.Start(startInfo)
            ?? throw new InvalidOperationException("无法启动 netsh.exe。");
        Task<string> outputTask = process.StandardOutput.ReadToEndAsync();
        Task<string> errorTask = process.StandardError.ReadToEndAsync();
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(TimeSpan.FromSeconds(15));
        try
        {
            await process.WaitForExitAsync(timeout.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            if (!process.HasExited) process.Kill(entireProcessTree: true);
            await process.WaitForExitAsync(CancellationToken.None).ConfigureAwait(false);
            if (cancellationToken.IsCancellationRequested) throw;
            throw new TimeoutException("netsh 配置 Wintun 接口超过 15 秒，已终止该配置进程。");
        }
        string output = await outputTask.ConfigureAwait(false);
        string error = await errorTask.ConfigureAwait(false);
        if (process.ExitCode != 0)
            throw new InvalidOperationException(
                $"配置 Wintun 接口失败（netsh={process.ExitCode}）：{error}{output}".Trim());
    }

    /// <summary>把 IPv4 CIDR 前缀长度转换为点分十进制掩码。</summary>
    /// <param name="prefixLength">零到 32 的前缀长度。</param>
    /// <returns>点分十进制子网掩码。</returns>
    private static string PrefixToMask(int prefixLength)
    {
        uint mask = prefixLength == 0 ? 0 : uint.MaxValue << (32 - prefixLength);
        return $"{mask >> 24}.{(mask >> 16) & 255}.{(mask >> 8) & 255}.{mask & 255}";
    }

    /// <summary>从 Wintun 原生环复制一个包到托管缓冲区。</summary>
    /// <param name="source">原生包地址。</param>
    /// <param name="destination">托管目标缓冲区。</param>
    /// <param name="length">要复制的字节数。</param>
    private static unsafe void CopyFromNative(IntPtr source, Span<byte> destination, int length) =>
        new ReadOnlySpan<byte>((void*)source, length).CopyTo(destination);

    /// <summary>从托管缓冲区复制一个包到 Wintun 原生环。</summary>
    /// <param name="source">托管源缓冲区。</param>
    /// <param name="destination">原生包地址。</param>
    private static unsafe void CopyToNative(ReadOnlySpan<byte> source, IntPtr destination) =>
        source.CopyTo(new Span<byte>((void*)destination, source.Length));

    /// <summary>在原生调用失败后抛出包含 Windows 错误码的异常。</summary>
    /// <param name="message">错误上下文。</param>
    private static void ThrowNative(string message) =>
        throw new Win32Exception(Marshal.GetLastPInvokeError(), message);

    /// <summary>在设备已经释放时阻止继续访问原生句柄。</summary>
    private void ThrowIfDisposed() => ObjectDisposedException.ThrowIf(_disposed != 0, this);

    /// <summary>声明 Wintun 官方 C ABI。</summary>
    private static class Native
    {
        private const string Library = "wintun.dll";

        /// <summary>打开一个已存在的命名适配器。</summary>
        /// <param name="name">适配器名称。</param>
        /// <returns>适配器句柄，失败为零。</returns>
        [DllImport(Library, EntryPoint = "WintunOpenAdapter", CharSet = CharSet.Unicode,
            ExactSpelling = true, SetLastError = true)]
        internal static extern IntPtr WintunOpenAdapter(string name);

        /// <summary>创建一个 Wintun 适配器。</summary>
        /// <param name="name">适配器名称。</param>
        /// <param name="tunnelType">设备管理器中显示的隧道类型。</param>
        /// <param name="requestedGuid">固定网络接口 GUID。</param>
        /// <returns>适配器句柄，失败为零。</returns>
        [DllImport(Library, EntryPoint = "WintunCreateAdapter", CharSet = CharSet.Unicode,
            ExactSpelling = true, SetLastError = true)]
        internal static extern IntPtr WintunCreateAdapter(
            string name, string tunnelType, ref Guid requestedGuid);

        /// <summary>
        /// 执行Wintun Get Adapter Luid操作。
        /// </summary>
        /// <param name="adapter">adapter参数。</param>
        /// <param name="luid">luid参数。</param>
        [DllImport(Library, EntryPoint = "WintunGetAdapterLUID", ExactSpelling = true)]
        internal static extern void WintunGetAdapterLuid(IntPtr adapter, out ulong luid);

        /// <summary>
        /// 执行Convert Interface Luid To Guid操作。
        /// </summary>
        /// <param name="interfaceLuid">interface Luid参数。</param>
        /// <param name="interfaceGuid">interface Guid参数。</param>
        /// <returns>操作结果。</returns>
        [DllImport("iphlpapi.dll", ExactSpelling = true)]
        internal static extern uint ConvertInterfaceLuidToGuid(ref ulong interfaceLuid, out Guid interfaceGuid);

        /// <summary>关闭适配器句柄。</summary>
        /// <param name="adapter">适配器句柄。</param>
        [DllImport(Library, EntryPoint = "WintunCloseAdapter", ExactSpelling = true)]
        internal static extern void WintunCloseAdapter(IntPtr adapter);

        /// <summary>启动共享收发环会话。</summary>
        /// <param name="adapter">适配器句柄。</param>
        /// <param name="capacity">环容量，必须为二次幂。</param>
        /// <returns>会话句柄，失败为零。</returns>
        [DllImport(Library, EntryPoint = "WintunStartSession", ExactSpelling = true,
            SetLastError = true)]
        internal static extern IntPtr WintunStartSession(IntPtr adapter, uint capacity);

        /// <summary>结束收发环会话。</summary>
        /// <param name="session">会话句柄。</param>
        [DllImport(Library, EntryPoint = "WintunEndSession", ExactSpelling = true)]
        internal static extern void WintunEndSession(IntPtr session);

        /// <summary>获取收包环可读事件。</summary>
        /// <param name="session">会话句柄。</param>
        /// <returns>由 Wintun 拥有的事件句柄。</returns>
        [DllImport(Library, EntryPoint = "WintunGetReadWaitEvent", ExactSpelling = true)]
        internal static extern IntPtr WintunGetReadWaitEvent(IntPtr session);

        /// <summary>从收包环取得一个包。</summary>
        /// <param name="session">会话句柄。</param>
        /// <param name="packetSize">返回包字节数。</param>
        /// <returns>包地址，无数据时为零。</returns>
        [DllImport(Library, EntryPoint = "WintunReceivePacket", ExactSpelling = true,
            SetLastError = true)]
        internal static extern IntPtr WintunReceivePacket(IntPtr session, out uint packetSize);

        /// <summary>把已读取包归还收包环。</summary>
        /// <param name="session">会话句柄。</param>
        /// <param name="packet">包地址。</param>
        [DllImport(Library, EntryPoint = "WintunReleaseReceivePacket", ExactSpelling = true)]
        internal static extern void WintunReleaseReceivePacket(IntPtr session, IntPtr packet);

        /// <summary>在发包环分配一个包。</summary>
        /// <param name="session">会话句柄。</param>
        /// <param name="packetSize">包字节数。</param>
        /// <returns>可写包地址，环满时为零。</returns>
        [DllImport(Library, EntryPoint = "WintunAllocateSendPacket", ExactSpelling = true,
            SetLastError = true)]
        internal static extern IntPtr WintunAllocateSendPacket(IntPtr session, uint packetSize);

        /// <summary>把已填充包提交给本机网络协议栈。</summary>
        /// <param name="session">会话句柄。</param>
        /// <param name="packet">包地址。</param>
        [DllImport(Library, EntryPoint = "WintunSendPacket", ExactSpelling = true)]
        internal static extern void WintunSendPacket(IntPtr session, IntPtr packet);
    }
}
