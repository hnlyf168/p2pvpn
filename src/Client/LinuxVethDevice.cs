using System.Buffers.Binary;
using System.ComponentModel;
using System.Diagnostics;
using System.Net;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace P2PVpnClient;

// Host IP stack <-> veth pair <-> AF_PACKET in an isolated, addressless netns.
// Only the application's pair/netns is owned. No physical NIC, bridge or default route is modified.
/// <summary>
/// Linux veth 虚拟网卡设备：在隔离的、无地址的网络命名空间（netns）内，用一对 veth 以太网卡
/// 加上 AF_PACKET 原始套接字来替代传统的 TUN 字符设备，实现与宿主 IP 协议栈之间的 IP 包收发。
/// </summary>
/// <remarks>
/// <para>拓扑：宿主协议栈 ⇄ p2pvpn0（宿主侧 veth，持有 VPN IP 与路由） ⇄ p2pvpne0（netns 侧对端，无 IP 地址） ⇄ AF_PACKET 原始套接字。</para>
/// <para>所有权边界：本类型只创建并清理自己别名的 veth 对和 netns；绝不修改物理网卡、网桥或默认路由。</para>
/// <para>与 TUN 的区别：内核交付的是完整以太帧而非裸 IP 包，因此 <see cref="ReadAsync"/> 需要剥掉以太头、
/// <see cref="WriteAsync"/> 需要补上以太头；此外还需在用户态代答 ARP（见 <see cref="ReadAsync"/> 中 type==0x806 分支）。</para>
/// </remarks>
internal sealed class LinuxVethDevice : IClientTunDevice
{
    /// <summary>宿主侧网卡 MAC（02:50:32:00:00:01，本地管理位 1；0x50/0x32 为 'P'/'2' 的 ASCII，便于识别）。</summary>
    /// <summary>netns 侧对端网卡 MAC（02:50:32:00:00:02，末字节与宿主侧区分）。用户态 ARP 代答与以太帧构造依赖这两个固定值。</summary>
    private static readonly byte[] HostMac = [2, 80, 50, 0, 0, 1], PeerMac = [2, 80, 50, 0, 0, 2];

    /// <summary>对端（netns 侧）veth 网卡名、隔离网络命名空间名、所有权标记文件路径（/run/edge-vpn-veth/{ns}.owner）。</summary>
    private readonly string _peer, _ns, _owner;

    /// <summary>独占锁文件流（.owner.lock），保证同一 netns 的创建/清理串行化，防止并发进程误删资源。</summary>
    private readonly FileStream _lock;

    /// <summary>AF_PACKET 收发通道：在 netns 内绑定了对端网卡的原始套接字，负责实际的以太帧读写。</summary>
    private LinuxTunIo? _io;

    /// <summary>收帧缓冲区：按 jumbo/VLAN 场景预留 65550 字节（14 字节以太头 + 65536），避免超长帧越界。</summary>
    private readonly byte[] _frame = new byte[65550];

    /// <summary>已通过 <c>ip route replace</c> 安装到宿主侧网卡的远端子网路由（CIDR 字符串集合），用于增量同步。</summary>
    private readonly HashSet<string> _routes = new(StringComparer.Ordinal);

    /// <summary>当前配置在宿主侧网卡上的 VPN IPv4 地址（null 表示尚未配置地址）。</summary>
    private IPAddress? _address;

    /// <summary>三个状态字段：地址前缀长度、网卡 MTU、Dispose 幂等标志（1 表示已释放）。</summary>
    private int _prefix, _mtu, _disposed;

    /// <summary>宿主侧 veth 网卡名（对外即 IClientTunDevice.Name）。</summary>
    public string Name { get; }
    /// <summary>
    /// 构造函数仅保存参数；实际网卡/netns 创建由 <see cref="CreateAsync"/> 完成，本构造函数不产生副作用。
    /// </summary>
    /// <param name="name">宿主侧 veth 网卡名。</param>
    /// <param name="peer">netns 侧对端 veth 罐卡名。</param>
    /// <param name="ns">隔离网络命名空间名。</param>
    /// <param name="guard">独占锁文件流，生命周期由本实例持有。</param>
    /// <param name="owner">所有权标记文件路径。</param>
    private LinuxVethDevice(string name, string peer, string ns, FileStream guard, string owner)
    { Name = name; _peer = peer; _ns = ns; _lock = guard; _owner = owner; }

    /// <summary>
    /// 创建 veth 对与隔离 netns，并打开 AF_PACKET 通道，返回可收发 IP 包的设备实例。
    /// 任一步失败都会回滚（DisposeAsync 清理已建资源）后重抛异常。
    /// </summary>
    /// <param name="address">VPN IPv4 地址；传 null 表示仅探测通道可用性，不配置地址。</param>
    /// <param name="prefix">地址前缀长度（如 24）。</param>
    /// <param name="mtu">网卡 MTU，读写双向都以此校验包长。</param>
    /// <param name="ct">取消令牌。</param>
    /// <param name="name">宿主侧 veth 网卡名，默认 p2pvpn0。</param>
    /// <param name="peer">netns 侧对端网卡名，默认 p2pvpne0。</param>
    /// <param name="ns">隔离网络命名空间名，默认 edge-vpn-io。</param>
    /// <returns>创建完成的设备实例；调用方负责 DisposeAsync。</returns>
    /// <exception cref="PlatformNotSupportedException">非 Linux 平台。</exception>
    /// <exception cref="ArgumentException">网卡/命名空间名非法（长度 1-15，仅限 ASCII 字母数字与连字符）。</exception>
    /// <exception cref="IOException">名称被占用、ip 命令失败或资源不属于本程序。</exception>
    internal static async Task<LinuxVethDevice> CreateAsync(IPAddress? address, int prefix, int mtu, CancellationToken ct,
        string name = "p2pvpn0", string peer = "p2pvpne0", string ns = "edge-vpn-io")
    {
        // veth/netns 是 Linux 内核特性
        if (!OperatingSystem.IsLinux()) throw new PlatformNotSupportedException("veth 模式仅支持 Linux。");
        // Linux 接口名上限 15 字节（IFNAMSIZ-1）；只允许字母数字与 '-'，避免注入 ip 命令参数
        foreach (string id in new[] { name, peer, ns })
            if (id.Length is < 1 or > 15 || id.Any(c => !char.IsAsciiLetterOrDigit(c) && c != '-')) throw new ArgumentException("Invalid private interface/namespace name");
        // 运行时状态目录（/run 为 tmpfs，重启自动清空），权限收紧为仅 owner 可访问
        Directory.CreateDirectory("/run/edge-vpn-veth");
        File.SetUnixFileMode("/run/edge-vpn-veth", UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        string owner = "/run/edge-vpn-veth/" + ns + ".owner";
        // 独占打开锁文件：同 netns 的创建/清理互斥，防止两个实例并发操作同一套资源
        var guard = new FileStream(owner + ".lock", FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None);
        var device = new LinuxVethDevice(name, peer, ns, guard, owner) { _mtu = mtu };
        try
        {
            // 先清理上次运行可能遗留的同名资源（仅当它们确属本程序）
            await device.CleanupOwnedAsync(ct);
            // 任一名称已被占用则拒绝创建：绝不删除不属于本程序的网卡/netns
            if (Directory.Exists("/sys/class/net/" + name) || Directory.Exists("/sys/class/net/" + peer) || File.Exists("/run/netns/" + ns))
                throw new IOException("veth 名称被其它设备占用；未删除现有网卡或命名空间。");
            File.WriteAllText(owner, device.OwnerTag);
            await Ip(ct, "netns", "add", ns);
            await Ip(ct, "link", "add", name, "type", "veth", "peer", "name", peer);
            // 用 ifalias 标记所有权，清理时校验，避免误删用户同名的其它网卡
            await Ip(ct, "link", "set", "dev", name, "alias", device.OwnerTag);
            await Ip(ct, "link", "set", "dev", peer, "alias", device.OwnerTag);
            // 固定 MAC：宿主侧 ...:01 / netns 侧 ...:02；用户态 ARP 代答与以太帧构造都依赖这两个固定值
            await Ip(ct, "link", "set", "dev", name, "address", "02:50:32:00:00:01", "mtu", mtu.ToString());
            await Ip(ct, "link", "set", "dev", peer, "address", "02:50:32:00:00:02", "mtu", mtu.ToString());
            // veth 的 offload 会让内核做分段/校验和卸载，与 AF_PACKET 原始帧语义冲突，必须关闭并回读验证
            VethNative.DisableOffloads(name); VethNative.DisableOffloads(peer);
            // 把对端移入隔离 netns 并拉起：它在 netns 内无 IP 地址，仅作为原始帧通道
            await Ip(ct, "link", "set", "dev", peer, "netns", ns);
            await Ip(ct, "-n", ns, "link", "set", "dev", peer, "up");
            // 专用线程 setns 进入 netns 打开 AF_PACKET 套接字并 bind 对端网卡（不能在线程池线程 setns：namespace 会泄漏给其它工作项）
            device._io = await VethNative.OpenInNamespaceAsync(ns, peer);
            await Ip(ct, "link", "set", "dev", name, "up");
            if (address is not null) await device.ReconfigureAsync(address, prefix, ct);
            return device;
        }
        catch
        {
            // 失败回滚：DisposeAsync 会清理已建的网卡/netns/owner 文件并释放锁
            await device.DisposeAsync();
            throw;
        }
    }
    /// <summary>所有权标记值："edge-vpn-veth:{netns 名}"，写入 owner 文件与网卡 ifalias。</summary>
    private string OwnerTag => "edge-vpn-veth:" + _ns;
    /// <summary>
    /// 清理默认 netns（edge-vpn-io）中的遗留资源。启动时若检测到 owner 文件仍存在（上次异常退出遗留），
    /// 构造临时实例并利用其 DisposeAsync→CleanupOwnedAsync 完成清理；无遗留时直接返回。
    /// </summary>
    /// <remarks>锁文件独占打开：若另一进程正在使用同一 netns，这里会阻塞等待而非并发清理。</remarks>
    internal static async Task CleanupDefaultAsync()
    {
        const string owner = "/run/edge-vpn-veth/edge-vpn-io.owner";
        if (!File.Exists(owner)) return;
        var guard = new FileStream(owner + ".lock", FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None);
        // await using：离开作用域触发 DisposeAsync → CleanupOwnedAsync（仅当 ifalias 校验通过才删）
        await using var stale = new LinuxVethDevice("p2pvpn0", "p2pvpne0", "edge-vpn-io", guard, owner);
    }
    /// <summary>
    /// 清理属于本程序的所有资源：删除两块 veth 网卡（先校验 ifalias）、删除 netns、删除 owner 标记文件。
    /// owner 文件不存在或内容不匹配时直接返回（资源非本程序创建，不动）。
    /// </summary>
    /// <param name="ct">取消令牌。</param>
    /// <exception cref="IOException">同名网卡的 ifalias 不是本程序标记时抛出，拒绝误删用户网卡。</exception>
    private async Task CleanupOwnedAsync(CancellationToken ct)
    {
        // owner 文件是"本程序创建资源"的唯一凭据；不存在或不匹配则不是我们的资源
        if (!File.Exists(_owner) || File.ReadAllText(_owner) != OwnerTag) return;
        foreach (string nic in new[] { Name, _peer })
            if (Directory.Exists("/sys/class/net/" + nic))
            {
                // 二次校验网卡 ifalias：防止上次异常退出后用户自建了同名网卡
                if (File.ReadAllText("/sys/class/net/" + nic + "/ifalias").Trim() != OwnerTag)
                    throw new IOException("同名网卡不属于 Edge VPN，拒绝清理：" + nic);
                await Ip(ct, "link", "delete", "dev", nic);
            }
        if (File.Exists("/run/netns/" + _ns)) await Ip(ct, "netns", "delete", _ns);
        File.Delete(_owner);
    }
    /// <summary>
    /// 重设宿主侧网卡的 VPN 地址：若旧地址存在且发生变化，先删除旧地址再 replace 新地址，避免地址堆积。
    /// </summary>
    /// <param name="address">新的 VPN IPv4 地址。</param>
    /// <param name="prefixLength">前缀长度。</param>
    /// <param name="ct">取消令牌。</param>
    public async Task ReconfigureAsync(IPAddress address, int prefixLength, CancellationToken ct)
    {
        if (_address is not null && (!_address.Equals(address) || _prefix != prefixLength))
            await Ip(ct, "addr", "del", $"{_address}/{_prefix}", "dev", Name);
        await Ip(ct, "addr", "replace", $"{address}/{prefixLength}", "dev", Name);
        _address = address; _prefix = prefixLength;
    }
    /// <summary>
    /// 空实现：veth 为点对点链路，邻居解析由用户态 ARP 代答（见 <see cref="ReadAsync"/>）完成，
    /// 无需向网卡同步对端地址表。
    /// </summary>
    /// <param name="addresses">对端虚拟地址集合（本模式下忽略）。</param>
    /// <param name="ct">取消令牌。</param>
    public Task SynchronizePeerAddressesAsync(IReadOnlyCollection<IPAddress> addresses, CancellationToken ct) => Task.CompletedTask;
    /// <summary>
    /// 将宿主路由表同步为期望的远端子网路由集合（desired state）：删除多余、补上缺失，全部指向宿主侧 veth 网卡。
    /// </summary>
    /// <param name="cidrs">期望存在的路由 CIDR 集合。</param>
    /// <param name="ct">取消令牌。</param>
    public async Task SynchronizeRemoteRoutesAsync(IReadOnlyCollection<string> cidrs, CancellationToken ct)
    {
        // 期望集合：与 _routes 做差集实现增量同步
        var desired = cidrs.ToHashSet(StringComparer.Ordinal);
        // 先删除不再需要的路由
        foreach (var cidr in _routes.Except(desired).ToArray())
        { await Ip(ct, "route", "del", cidr, "dev", Name); _routes.Remove(cidr); }
        // 再补上新增路由（replace 幂等，重复执行安全）
        foreach (var cidr in desired.Except(_routes).ToArray())
        { await Ip(ct, "route", "replace", cidr, "dev", Name); _routes.Add(cidr); }
    }
    /// <summary>
    /// 从隔离 netns 的 AF_PACKET 套接字读取一个以太网帧，剥离以太头后返回其中的 IPv4 包。
    /// 遇到发给本网卡的 ARP 请求时，在用户态直接构造应答帧写回（代答），使内核 ARP 表永远无需真实对端。
    /// </summary>
    /// <param name="buffer">接收缓冲区，收到 IP 包写入其开头。</param>
    /// <param name="cancellationToken">取消令牌。</param>
    /// <returns>IPv4 包的字节长度（20 ~ MTU）。</returns>
    /// <remarks>
    /// 循环丢弃不满足条件的帧：不足 14 字节、目的 MAC 非本机、非 ARP 且非 IPv4、版本非 4、
    /// IP total length 非法（小于 20、大于 MTU、大于缓冲区、大于帧内实际载荷）。
    /// </remarks>
    public async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
    {
        while (true)
        {
            // 读取一个完整以太网帧（LinuxTunIo 内部保证返回完整帧）
            int count = await _io!.ReadAsync(_frame, cancellationToken);
            // 以太头 14 字节：目的 MAC(6) 源 MAC(6) EtherType(2)；不足或非发往宿主侧网卡则丢弃
            if (count < 14 || !_frame.AsSpan(6, 6).SequenceEqual(HostMac)) continue;
            ushort type = BinaryPrimitives.ReadUInt16BigEndian(_frame.AsSpan(12));
            // ARP 帧（EtherType 0x0806）：用户态代答，应答"所有经 VPN 显式路由的下一跳都在链路上"
            if (type == 0x806)
            {
                // 校验 ARP 报文：硬件类型=以太网(1)、协议类型=IPv4(0x800)、MAC 长度 6、IP 长度 4、操作码=请求(1)、目标 MAC 是本机
                if (count < 42 || BinaryPrimitives.ReadUInt16BigEndian(_frame.AsSpan(14)) != 1 ||
                    BinaryPrimitives.ReadUInt16BigEndian(_frame.AsSpan(16)) != 0x800 || _frame[18] != 6 || _frame[19] != 4 ||
                    BinaryPrimitives.ReadUInt16BigEndian(_frame.AsSpan(20)) != 1 || !_frame.AsSpan(22, 6).SequenceEqual(HostMac)) continue;
                // Resolve every next-hop reached through our explicit VPN routes to the isolated peer.
                // 构造 42 字节应答：以太头(14) + ARP 应答体(28)。把请求的发送方 MAC/IP 与目标 MAC/IP 互换，
                // 操作码改为 2（应答），目标 MAC 填对端网卡 MAC——宿主内核由此把对端 IP 解析为 p2pvpne0 的 MAC
                byte[] reply = new byte[42]; HostMac.CopyTo(reply, 0); PeerMac.CopyTo(reply, 6);
                _frame.AsSpan(12, 10).CopyTo(reply.AsSpan(12)); reply[21] = 2;
                PeerMac.CopyTo(reply, 22); _frame.AsSpan(38, 4).CopyTo(reply.AsSpan(28));
                HostMac.CopyTo(reply, 32); _frame.AsSpan(28, 4).CopyTo(reply.AsSpan(38));
                // 写回应答帧后继续读下一帧（ARP 不上传给协议栈）
                await _io.WriteAsync(reply, cancellationToken); continue;
            }
            // 仅接受 IPv4（EtherType 0x0800）：帧至少 14+20 字节，且 IP 版本号为 4
            if (type != 0x800 || count < 34 || _frame[14] >> 4 != 4) continue;
            // IP 头第 2-3 字节为总长度（大端）：需为合法的 20 ~ MTU 且不超过帧内实际载荷与缓冲区
            int size = BinaryPrimitives.ReadUInt16BigEndian(_frame.AsSpan(16));
            if (size < 20 || size > _mtu || size > buffer.Length || size > count - 14) continue;
            // 剥离 14 字节以太头，把纯 IP 包拷入调用方缓冲区
            _frame.AsMemory(14, size).CopyTo(buffer); return size;
        }
    }
    /// <summary>
    /// 为 IPv4 包封装 14 字节以太头后，经 AF_PACKET 套接字把完整以太网帧写入 netns 侧对端网卡，
    /// 内核随后将其视为宿主侧网卡的入站帧送入协议栈。
    /// </summary>
    /// <param name="buffer">待发送的 IPv4 包（不含以太头）。</param>
    /// <param name="cancellationToken">取消令牌。</param>
    /// <remarks>非法包（版本非 4、长度小于 20 或超过 MTU）直接静默丢弃（返回已完成任务）。</remarks>
    public ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
    {
        // 基本合法性：IPv4 版本号 4，长度 20 ~ MTU
        if (buffer.Length < 20 || buffer.Span[0] >> 4 != 4 || buffer.Length > _mtu) return ValueTask.CompletedTask;
        // 以太头：目的 MAC=宿主侧网卡(发往协议栈)，源 MAC=对端网卡，EtherType=0x0800(IPv4)。
        // 大端：frame[12]=0x08（高位），frame[13]=0x00（低位）
        byte[] frame = new byte[14 + buffer.Length]; HostMac.CopyTo(frame, 0); PeerMac.CopyTo(frame, 6);
        frame[12] = 8; buffer.CopyTo(frame.AsMemory(14));
        return _io!.WriteAsync(frame, cancellationToken);
    }
    /// <summary>
    /// 释放设备：关闭 AF_PACKET 通道，清理属于本程序的网卡/netns/owner 文件（10 秒超时保护），最后释放锁文件。
    /// 使用 <see cref="Interlocked"/> 保证幂等，多次调用安全。
    /// </summary>
    public async ValueTask DisposeAsync()
    {
        // 原子交换标志：仅第一个调用者执行清理，其余直接返回
        if (Interlocked.Exchange(ref _disposed, 1) != 0) return;
        try
        {
            // 先关套接字再删网卡，避免清理期间仍有帧读写
            if (_io is not null) await _io.DisposeAsync();
            // 清理挂起时 10 秒超时，防止单个 ip 命令卡死整个关闭流程
            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(10));
            await CleanupOwnedAsync(timeout.Token);
        }
        finally { _lock.Dispose(); }
    }
    /// <summary>
    /// 以 10 秒超时运行外部 ip 命令；非零退出码时抛 <see cref="IOException"/> 并附带 stderr 内容，
    /// 超时或异常时强制终止进程（整棵进程树）。
    /// </summary>
    /// <param name="ct">取消令牌，与 10 秒内部超时合并生效。</param>
    /// <param name="args">ip 命令参数（逐个加入 ArgumentList，无 shell 注入风险）。</param>
    /// <exception cref="IOException">ip 进程无法启动、退出码非 0 或超时。</exception>
    internal static async Task Ip(CancellationToken ct, params string[] args)
    {
        // 关联外部令牌 + 10 秒绝对超时
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(ct); deadline.CancelAfter(TimeSpan.FromSeconds(10));
        var start = new ProcessStartInfo("ip") { UseShellExecute = false, RedirectStandardError = true, RedirectStandardOutput = true };
        foreach (string arg in args) start.ArgumentList.Add(arg);
        using var process = Process.Start(start) ?? throw new IOException("无法运行 ip 命令");
        try
        {
            // 先异步读管道再等待退出，避免管道缓冲区写满导致死锁
            var error = process.StandardError.ReadToEndAsync(deadline.Token);
            var output = process.StandardOutput.ReadToEndAsync(deadline.Token);
            await process.WaitForExitAsync(deadline.Token);
            string message = await error; await output;
            if (process.ExitCode != 0) throw new IOException("veth 配置失败：" + message.Trim());
        }
        catch { try { if (!process.HasExited) process.Kill(true); } catch { } throw; }
    }
}

/// <summary>
/// veth 模式的原生层：直接通过 libc P/Invoke 完成网络命名空间切换、AF_PACKET 套接字操作与
/// ethtool ioctl 卸载特性控制。这些操作无法用纯托管 API 实现。
/// </summary>
internal static class VethNative
{
    /// <summary>
    /// 在专用后台线程内 setns 进入指定 netns，创建 AF_PACKET 原始套接字并 bind 到对端网卡，
    /// 返回包装该套接字的 <see cref="LinuxTunIo"/> 读写通道。
    /// </summary>
    /// <param name="ns">目标网络命名空间名（对应 /run/netns/{ns}）。</param>
    /// <param name="peer">netns 内要绑定的 veth 对端网卡名。</param>
    /// <returns>绑定完成的非阻塞原始套接字通道。</returns>
    /// <remarks>
    /// 必须用专用线程：setns 会改变整个线程的 namespace，若在线程池线程执行，
    /// 该线程归还池后 namespace 会泄漏给无关的应用代码。socket 需 CAP_NET_RAW 权限。
    /// </remarks>
    internal static Task<LinuxTunIo> OpenInNamespaceAsync(string ns, string peer)
    {
        // 异步等待后台线程结果；RunContinuationsAsynchronously 避免延续在线程池线程上同步执行
        var result = new TaskCompletionSource<LinuxTunIo>(TaskCreationOptions.RunContinuationsAsynchronously);
        // Never call setns on a pool thread: its namespace would leak into unrelated application work.
        new Thread(() =>
        {
            SafeFileHandle? socketHandle = null;
            try
            {
                // 打开 netns 挥发性文件获取其文件描述符
                using var nsHandle = File.OpenHandle("/run/netns/" + ns);
                // setns(fd, CLONE_NEWNET=0x40000000)：把当前线程切换进目标网络命名空间
                if (setns(nsHandle.DangerousGetHandle().ToInt32(), 0x40000000) != 0) throw Error("进入 veth 网络命名空间失败");
                // socket(AF_PACKET=17, SOCK_RAW|SOCK_NONBLOCK|SOCK_CLOEXEC, htons(ETH_P_ALL)=0x0300)：
                // 原始套接字收发完整以太网帧；非阻塞供 LinuxTunIo 轮询；协议号 0x0003 按 RID 小端惯例传 0x0300
                int fd = socket(17, 3 | 0x800 | 0x80000, 0x0300); // AF_PACKET / SOCK_RAW / ETH_P_ALL, little-endian supported RIDs.
                if (fd < 0) throw Error("创建 AF_PACKET 套接字失败（需要 CAP_NET_RAW）");
                socketHandle = new SafeFileHandle((IntPtr)fd, true);
                // 网卡名 → 接口索引（ifindex），0 表示不存在
                uint index = if_nametoindex(peer);
                if (index == 0) throw Error("无法定位 veth 对端");
                // sockaddr_ll(20 字节)：family=AF_PACKET(17)、sll_protocol=ETH_P_ALL(主机序 3)、sll_ifindex=index
                byte[] address = new byte[20]; address[0] = 17; address[3] = 3; BitConverter.GetBytes(index).CopyTo(address, 4);
                // 仅绑定该网卡：套接字只收发这一块 veth 对端的帧
                if (bind(fd, address, (uint)address.Length) != 0) throw Error("绑定 veth 对端失败");
                // 交出句柄所有权给 LinuxTunIo（置 null 防止 finally 误关）
                result.SetResult(new LinuxTunIo(socketHandle)); socketHandle = null;
            }
            catch (Exception error) { result.TrySetException(error); }
            finally { socketHandle?.Dispose(); }
        }) { IsBackground = true, Name = "Edge VPN veth namespace" }.Start();
        return result.Task;
    }
    /// <summary>
    /// 通过 ethtool ioctl 关闭 veth 网卡的分段/校验和卸载特性（GSO/GRO/TSO/checksum offload 等），
    /// 并回读验证确已关闭——否则内核交付给 AF_PACKET 的帧可能是未分段/校验未完成的，与原始帧语义冲突，
    /// 此时抛异常拒绝启用该模式以免传输数据损坏。
    /// </summary>
    /// <param name="name">网卡名。</param>
    /// <exception cref="IOException">套接字创建失败、内核特性表异常或卸载无法关闭。</exception>
    internal static void DisableOffloads(string name)
    {
        // AF_INET(2) + SOCK_DGRAM(2)|SOCK_CLOEXEC：ethtool ioctl 使用的普通控制套接字
        int fd = socket(2, 2 | 0x80000, 0);
        if (fd < 0) throw Error("创建网卡配置套接字失败");
        using var handle = new SafeFileHandle((IntPtr)fd, true);
        // 第一步 ETHTOOL_GSSET_INFO(0x37)：查询字符串集 16（netdev 特性名）的条目数
        byte[] info = new byte[24]; Put(info, 0, 0x37); info[8] = 16; Ethtool(fd, name, info);
        int count = checked((int)BitConverter.ToUInt32(info, 16));
        if (count is < 1 or > 512) throw new IOException("内核未提供可验证的 veth offload 特性");
        // 第二步 ETHTOOL_GSTR(0x1b)：读取全部特性名（每项固定 32 字节，NUL 结尾）
        byte[] names = new byte[12 + count * 32]; Put(names, 0, 0x1b); Put(names, 4, 4); Put(names, 8, (uint)count); Ethtool(fd, name, names);
        // 特性位图按 32 位块组织：get 请求块(8B/块) 读当前值，set 请求块(8B/块: valid+value) 写目标值
        int blocks = (count + 31) / 32;
        byte[] get = new byte[8 + blocks * 16]; Put(get, 0, 0x3a); Put(get, 4, (uint)blocks); Ethtool(fd, name, get);
        byte[] set = new byte[8 + blocks * 8]; Put(set, 0, 0x3b); Put(set, 4, (uint)blocks);
        var required = new List<int>();
        for (int i = 0; i < count; i++)
        {
            // 只处理影响原始帧语义的发送卸载（checksum/scatter/segmentation/gso）与接收聚合（gro/lro）特性
            string feature = Encoding.ASCII.GetString(names, 12 + i * 32, 32).TrimEnd('\0');
            if (!(feature.StartsWith("tx-checksum") || feature.StartsWith("tx-scatter") || feature.Contains("segmentation") || feature.StartsWith("tx-gso") || feature.StartsWith("rx-gro") || feature == "rx-lro")) continue;
            // 位 i 位于第 i/32 块的第 i%32 位；仅当当前处于开启状态才需要写入 set 请求
            uint bit = 1u << (i % 32); int block = i / 32;
            if ((BitConverter.ToUInt32(get, 8 + block * 16) & bit) != 0)
                Put(set, 8 + block * 8, BitConverter.ToUInt32(set, 8 + block * 8) | bit);
            required.Add(i);
        }
        // 第三步 ETHTOOL_SFEATURES(0x3b) 写入；第四步 ETHTOOL_GFEATURES(0x3a) 回读 active 位（偏移 +8）验证确实关闭
        Ethtool(fd, name, set); Ethtool(fd, name, get);
        foreach (int i in required)
            if ((BitConverter.ToUInt32(get, 16 + (i / 32) * 16) & (1u << (i % 32))) != 0)
                throw new IOException("veth 无法关闭分段/校验卸载，拒绝启用以免传输损坏");
    }
    /// <summary>把 uint 以本机小端序写入缓冲区指定偏移（供 ethtool 结构体填充）。</summary>
    private static void Put(byte[] data, int offset, uint value) => BitConverter.GetBytes(value).CopyTo(data, offset);
    /// <summary>
    /// 执行 ethtool ioctl（SIOCETHTOOL=0x8946）：请求头 16 字节（网卡名 + 命令），
    /// 后接数据区指针。失败时抛 <see cref="Win32Exception"/>。
    /// </summary>
    private static unsafe void Ethtool(int fd, string name, byte[] data)
    {
        // ifreq：前 16 字节为网卡名（IFNAMSIZ=16，ASCII），随后为 union 数据指针
        byte[] request = new byte[40]; Encoding.ASCII.GetBytes(name).CopyTo(request, 0);
        fixed (byte* pointer = data)
        {
            fixed (byte* req = request)
            {
                *(IntPtr*)(req + 16) = (IntPtr)pointer;
                if (ioctl(fd, 0x8946, (IntPtr)req) < 0) throw Error("配置 veth offload 失败");
            }
        }
    }
    /// <summary>用最近一次 P/Invoke 错误码（errno）构造 <see cref="Win32Exception"/>。</summary>
    private static Win32Exception Error(string message) => new(Marshal.GetLastPInvokeError(), message);
    /// <summary>创建套接字：domain=AF_PACKET/AF_INET，type 含 SOCK_RAW/SOCK_DGRAM/SOCK_NONBLOCK/SOCK_CLOEXEC 标志。</summary>
    [DllImport("libc", SetLastError = true)] private static extern int socket(int domain, int type, int protocol);
    /// <summary>绑定套接字到指定地址（此处为 sockaddr_ll，即某块网卡）。</summary>
    [DllImport("libc", SetLastError = true)] private static extern int bind(int fd, byte[] address, uint length);
    /// <summary>网卡名 → 接口索引 ifindex；返回 0 表示网卡不存在。</summary>
    [DllImport("libc", SetLastError = true)] private static extern uint if_nametoindex(string name);
    /// <summary>把当前线程加入 fd 指代的 namespace；type=0x40000000 即 CLONE_NEWNET（网络命名空间）。</summary>
    [DllImport("libc", SetLastError = true)] private static extern int setns(int fd, int type);
    /// <summary>通用设备控制 ioctl；此处用于 SIOCETHTOOL(0x8946) 卸载特性读写。</summary>
    [DllImport("libc", SetLastError = true)] private static extern int ioctl(int fd, uint command, IntPtr request);
}

/// <summary>
/// veth 模式能力探测（进程内仅执行一次并缓存结果）：
/// 用一次性网卡名 p2pchk0/p2pchk1 与独立 netns edge-vpn-probe 试跑完整创建/销毁流程，
/// 验证当前环境（内核权限、CAP_NET_RAW、ip 命令等）能否使用 veth 模式。
/// </summary>
internal static class VethSupport
{
    /// <summary>Lazy 缓存的探测任务：首次 GetAsync 才执行，此后复用同一结果。</summary>
    private static readonly Lazy<Task<(bool Available, string Error)>> Cached = new(ProbeAsync);
    /// <summary>获取（必要时触发）veth 支持性探测结果：(是否可用, 不可用原因)。失败消息截断至 500 字符。</summary>
    internal static Task<(bool Available, string Error)> GetAsync() => Cached.Value;
    /// <summary>
    /// 实际探测逻辑：Linux 平台才继续；CreateAsync 传 address=null 纯建通道（20 秒超时），
    /// await using 确保探测资源立即清理。异常被捕获并转为"不可用"结果而非抛出。
    /// </summary>
    private static async Task<(bool, string)> ProbeAsync()
    {
        if (!OperatingSystem.IsLinux()) return (false, "veth 模式仅支持 Linux");
        try
        {
            using var ct = new CancellationTokenSource(TimeSpan.FromSeconds(20));
            // 一次性探测网卡名与 netns，不与正式运行的 p2pvpn0/p2pvpne0/edge-vpn-io 冲突
            await using var device = await LinuxVethDevice.CreateAsync(null, 32, 1280, ct.Token, "p2pchk0", "p2pchk1", "edge-vpn-probe");
            return (true, "");
        }
        catch (Exception ex) { return (false, ex.Message.Length > 500 ? ex.Message[..500] : ex.Message); }
    }
}
