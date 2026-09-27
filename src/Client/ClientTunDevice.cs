using System.ComponentModel;
using System.Diagnostics;
using System.Net;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
using Qcxt.Net.P2P.Tunneling;
using QuicSample;

namespace P2PVpnClient;

/// <summary>
/// 表示 I Client Tun Device，并提供相关数据或行为。
/// </summary>
internal interface IClientTunDevice : IP2PTunDevice
{
    /// <summary>
    /// 获取或设置Name。
    /// </summary>
    /// <returns>Name。</returns>
    string Name { get; }
    /// <summary>
    /// 执行Reconfigure操作。
    /// </summary>
    /// <param name="address">网络地址。</param>
    /// <param name="prefixLength">prefix Length参数。</param>
    /// <param name="cancellationToken">用于取消异步操作的令牌。</param>
    /// <returns>操作结果。</returns>
    Task ReconfigureAsync(IPAddress address, int prefixLength, CancellationToken cancellationToken);
    /// <summary>
    /// 执行Synchronize Peer Addresses操作。
    /// </summary>
    /// <param name="addresses">addresses参数。</param>
    /// <param name="cancellationToken">用于取消异步操作的令牌。</param>
    /// <returns>操作结果。</returns>
    Task SynchronizePeerAddressesAsync(IReadOnlyCollection<IPAddress> addresses,
        CancellationToken cancellationToken);
    /// <summary>
    /// 执行Synchronize Remote Routes操作。
    /// </summary>
    /// <param name="cidrs">cidrs参数。</param>
    /// <param name="cancellationToken">用于取消异步操作的令牌。</param>
    /// <returns>操作结果。</returns>
    Task SynchronizeRemoteRoutesAsync(IReadOnlyCollection<string> cidrs,
        CancellationToken cancellationToken);
}

/// <summary>
/// 表示 Client Tun Device，并提供相关数据或行为。
/// </summary>
internal static class ClientTunDevice
{
    /// <summary>
    /// 创建。
    /// </summary>
    /// <param name="configuredName">configured Name参数。</param>
    /// <param name="address">网络地址。</param>
    /// <param name="prefixLength">prefix Length参数。</param>
    /// <param name="mtu">mtu参数。</param>
    /// <param name="cancellationToken">用于取消异步操作的令牌。</param>
    /// <returns>操作结果。</returns>
    public static async Task<IClientTunDevice> CreateAsync(string configuredName, IPAddress address,
        int prefixLength, int mtu, CancellationToken cancellationToken)
    {
        if (OperatingSystem.IsWindows())
        {
            WintunDevice.ValidateNativeLibrary();
            return new WindowsTunDevice(await WintunDevice.CreateAsync(configuredName, address,
                prefixLength, mtu, cancellationToken).ConfigureAwait(false));
        }
        if (OperatingSystem.IsLinux())
            return await LinuxTunDevice.CreateAsync("p2pvpn0", address, prefixLength, mtu,
                cancellationToken).ConfigureAwait(false);
        throw new PlatformNotSupportedException("Edge VPN 客户端仅支持 Windows 和 Linux。");
    }

    /// <summary>
/// 表示 Windows Tun Device，并提供相关数据或行为。
/// </summary>
private sealed class WindowsTunDevice(WintunDevice device) : IClientTunDevice
    {
        /// <summary>
        /// 获取或设置Name。
        /// </summary>
        /// <returns>Name。</returns>
        public string Name => device.Name;
        /// <summary>
        /// 执行Read操作。
        /// </summary>
        /// <param name="buffer">用于暂存数据的缓冲区。</param>
        /// <param name="cancellationToken">用于取消异步操作的令牌。</param>
        /// <returns>操作结果。</returns>
        public ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default) =>
            device.ReadAsync(buffer, cancellationToken);
        /// <summary>
        /// 执行Write操作。
        /// </summary>
        /// <param name="buffer">用于暂存数据的缓冲区。</param>
        /// <param name="cancellationToken">用于取消异步操作的令牌。</param>
        /// <returns>操作结果。</returns>
        public ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default) =>
            device.WriteAsync(buffer, cancellationToken);
        /// <summary>
        /// 执行Reconfigure操作。
        /// </summary>
        /// <param name="address">网络地址。</param>
        /// <param name="prefixLength">prefix Length参数。</param>
        /// <param name="cancellationToken">用于取消异步操作的令牌。</param>
        /// <returns>操作结果。</returns>
        public Task ReconfigureAsync(IPAddress address, int prefixLength, CancellationToken cancellationToken) =>
            device.ReconfigureAsync(address, prefixLength, cancellationToken);
        /// <summary>
        /// 执行Synchronize Peer Addresses操作。
        /// </summary>
        /// <param name="addresses">addresses参数。</param>
        /// <param name="cancellationToken">用于取消异步操作的令牌。</param>
        /// <returns>操作结果。</returns>
        public Task SynchronizePeerAddressesAsync(IReadOnlyCollection<IPAddress> addresses,
            CancellationToken cancellationToken) => device.SynchronizePeerAddressesAsync(addresses, cancellationToken);
        /// <summary>
        /// 执行Synchronize Remote Routes操作。
        /// </summary>
        /// <param name="cidrs">cidrs参数。</param>
        /// <param name="cancellationToken">用于取消异步操作的令牌。</param>
        /// <returns>操作结果。</returns>
        public Task SynchronizeRemoteRoutesAsync(IReadOnlyCollection<string> cidrs,
            CancellationToken cancellationToken) => device.SynchronizeRemoteRoutesAsync(cidrs, cancellationToken);
        /// <summary>
        /// 执行Dispose操作。
        /// </summary>
        /// <returns>操作结果。</returns>
        public ValueTask DisposeAsync() => device.DisposeAsync();
    }
}

/// <summary>
/// 表示 Linux Tun Device，并提供相关数据或行为。
/// </summary>
internal sealed class LinuxTunDevice : IClientTunDevice
{
    // Linux ioctl() takes an unsigned long on glibc and an int request on musl.
    // TUNSETIFF itself is a 32-bit ioctl number. Passing C# ulong on ARM32 consumes
    // two ABI argument registers and shifts the following pointer, producing EBADFD (77).
    private const uint TunSetIff = 0x400454ca;
    private const short IffTun = 0x0001;
    private const short IffNoPi = 0x1000;
    private readonly LinuxTunIo _io;
    private readonly string _name;
    /// <summary>
    /// 获取或设置Name。
    /// </summary>
    /// <returns>Name。</returns>
    public string Name => _name;
    private readonly HashSet<string> _remoteRoutes = new(StringComparer.Ordinal);

    /// <summary>
    /// 初始化 <see cref="LinuxTunDevice"/> 类的新实例。
    /// </summary>
    /// <param name="readStream">read Stream参数。</param>
    /// <param name="writeStream">write Stream参数。</param>
    /// <param name="name">名称。</param>
    private LinuxTunDevice(LinuxTunIo io, string name)
    {
        _io = io;
        _name = name;
    }

    /// <summary>
    /// 创建。
    /// </summary>
    /// <param name="name">名称。</param>
    /// <param name="address">网络地址。</param>
    /// <param name="prefixLength">prefix Length参数。</param>
    /// <param name="mtu">mtu参数。</param>
    /// <param name="cancellationToken">用于取消异步操作的令牌。</param>
    /// <returns>操作结果。</returns>
    public static async Task<LinuxTunDevice> CreateAsync(string name, IPAddress address,
        int prefixLength, int mtu, CancellationToken cancellationToken)
    {
        if (!File.Exists("/dev/net/tun"))
            throw new FileNotFoundException("系统未提供 /dev/net/tun，请加载 tun 内核模块。", "/dev/net/tun");
        var stream = LinuxTunIo.Open("/dev/net/tun");
        try
        {
            Attach(stream.Handle, name);
            var result = new LinuxTunDevice(stream, name);
            await result.ConfigureAsync(address, prefixLength, mtu, cancellationToken).ConfigureAwait(false);
            return result;
        }
        catch { await stream.DisposeAsync().ConfigureAwait(false); throw; }
    }

    /// <summary>
    /// 执行Attach操作。
    /// </summary>
    /// <param name="handle">handle参数。</param>
    /// <param name="name">名称。</param>
    private static unsafe void Attach(SafeFileHandle handle, string name)
    {
        Span<byte> request = stackalloc byte[40];
        request.Clear();
        int written = System.Text.Encoding.ASCII.GetBytes(name.AsSpan(), request[..15]);
        request[written] = 0;
        short flags = IffTun | IffNoPi;
        MemoryMarshal.Write(request[16..], in flags);
        fixed (byte* pointer = request)
            if (ioctl(handle.DangerousGetHandle().ToInt32(), TunSetIff, (IntPtr)pointer) != 0)
                throw new Win32Exception(Marshal.GetLastPInvokeError(), "创建 Linux TUN 设备失败");
    }

    /// <summary>
    /// 执行Reconfigure操作。
    /// </summary>
    /// <param name="address">网络地址。</param>
    /// <param name="prefixLength">prefix Length参数。</param>
    /// <param name="cancellationToken">用于取消异步操作的令牌。</param>
    /// <returns>操作结果。</returns>
    public async Task ReconfigureAsync(IPAddress address, int prefixLength,
        CancellationToken cancellationToken) =>
        await ConfigureAsync(address, prefixLength, 1280, cancellationToken).ConfigureAwait(false);

    /// <summary>
    /// 执行Synchronize Peer Addresses操作。
    /// </summary>
    /// <param name="addresses">addresses参数。</param>
    /// <param name="cancellationToken">用于取消异步操作的令牌。</param>
    /// <returns>操作结果。</returns>
    public Task SynchronizePeerAddressesAsync(IReadOnlyCollection<IPAddress> addresses,
        CancellationToken cancellationToken) => Task.CompletedTask;

    /// <summary>
    /// 执行Synchronize Remote Routes操作。
    /// </summary>
    /// <param name="cidrs">cidrs参数。</param>
    /// <param name="cancellationToken">用于取消异步操作的令牌。</param>
    /// <returns>操作结果。</returns>
    public async Task SynchronizeRemoteRoutesAsync(IReadOnlyCollection<string> cidrs,
        CancellationToken cancellationToken)
    {
        var desired = cidrs.ToHashSet(StringComparer.Ordinal);
        foreach (string cidr in _remoteRoutes.Except(desired).ToArray())
        {
            try { await RunIpAsync(["route", "del", cidr, "dev", _name], cancellationToken); } catch { }
            _remoteRoutes.Remove(cidr);
        }
        foreach (string cidr in desired.Except(_remoteRoutes).ToArray())
        {
            await RunIpAsync(["route", "replace", cidr, "dev", _name], cancellationToken);
            _remoteRoutes.Add(cidr);
        }
    }

    /// <summary>
    /// 执行Configure操作。
    /// </summary>
    /// <param name="address">网络地址。</param>
    /// <param name="prefixLength">prefix Length参数。</param>
    /// <param name="mtu">mtu参数。</param>
    /// <param name="cancellationToken">用于取消异步操作的令牌。</param>
    /// <returns>操作结果。</returns>
    private async Task ConfigureAsync(IPAddress address, int prefixLength, int mtu,
        CancellationToken cancellationToken)
    {
        await RunIpAsync(["link", "set", "dev", _name, "mtu", mtu.ToString(), "up"], cancellationToken);
        await RunIpAsync(["addr", "replace", $"{address}/{prefixLength}", "dev", _name], cancellationToken);
    }

    /// <summary>
    /// 执行Run Ip操作。
    /// </summary>
    /// <param name="arguments">arguments参数。</param>
    /// <param name="cancellationToken">用于取消异步操作的令牌。</param>
    /// <returns>操作结果。</returns>
    private static async Task RunIpAsync(string[] arguments, CancellationToken cancellationToken)
    {
        var start = new ProcessStartInfo("ip") { UseShellExecute = false, RedirectStandardError = true };
        foreach (string argument in arguments) start.ArgumentList.Add(argument);
        using Process process = Process.Start(start) ?? throw new InvalidOperationException("无法启动 ip 命令。");
        string error = await process.StandardError.ReadToEndAsync(cancellationToken).ConfigureAwait(false);
        await process.WaitForExitAsync(cancellationToken).ConfigureAwait(false);
        if (process.ExitCode != 0) throw new InvalidOperationException("配置 Linux TUN 失败：" + error.Trim());
    }

    /// <summary>
    /// 执行Read操作。
    /// </summary>
    /// <param name="buffer">用于暂存数据的缓冲区。</param>
    /// <param name="cancellationToken">用于取消异步操作的令牌。</param>
    /// <returns>操作结果。</returns>
    public ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default) =>
        _io.ReadAsync(buffer, cancellationToken);
    /// <summary>
    /// 执行Write操作。
    /// </summary>
    /// <param name="buffer">用于暂存数据的缓冲区。</param>
    /// <param name="cancellationToken">用于取消异步操作的令牌。</param>
    /// <returns>操作结果。</returns>
    public ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default) =>
        _io.WriteAsync(buffer, cancellationToken);
    /// <summary>
    /// 执行Dispose操作。
    /// </summary>
    /// <returns>操作结果。</returns>
    public async ValueTask DisposeAsync()
    {
        await _io.DisposeAsync().ConfigureAwait(false);
    }

    // Linux NativeAOT 静态 musl 可执行文件不能在运行时 dlopen("libc")；
    // csproj 的 DirectPInvoke 会在编译阶段把该调用直接绑定到静态 C 运行库。
    /// <summary>
    /// 执行ioctl操作。
    /// </summary>
    /// <param name="fd">fd参数。</param>
    /// <param name="request">请求数据。</param>
    /// <param name="argument">argument参数。</param>
    /// <returns>操作结果。</returns>
    [DllImport("libc", EntryPoint = "ioctl", SetLastError = true)]
    private static extern int ioctl(int fd, uint request, IntPtr argument);
    /// <summary>
    /// 执行dup操作。
    /// </summary>
    /// <param name="fd">fd参数。</param>
    /// <returns>操作结果。</returns>
    [DllImport("libc", EntryPoint = "dup", SetLastError = true)]
    private static extern int dup(int fd);
}
