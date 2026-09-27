using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Threading.Channels;
using P2PVpn.Policy;

namespace P2PVpnClient;

/// <summary>无 TUN 被访问网关：IP 包在程序中终止，TCP/UDP 由普通系统 socket 访问目标。
/// 不创建网卡、不修改路由、不启用 IP forwarding。不支持原始 IP 分片及非 TCP/UDP/echo 协议。
/// TCP 使用有界批量发送窗口、累积确认和丢失段重传；不为每个 IP 包调度线程池工作项。</summary>
internal sealed class ProxyGatewayDevice : IClientTunDevice
{
    private NetworkPolicy _policy;
    private readonly CancellationTokenSource _stop = new();
    private readonly Channel<byte[]> _replies = Channel.CreateBounded<byte[]>(new BoundedChannelOptions(512) { FullMode = BoundedChannelFullMode.Wait });
    private readonly ConcurrentDictionary<string, Flow> _flows = new();
    private readonly SemaphoreSlim _packets = new(128);
    private readonly Task _cleanup;
    private sealed class Flow : IDisposable
    {
        internal required byte Protocol;
        internal required IPAddress Source, Destination;
        internal required ushort SourcePort, DestinationPort;
        internal required Socket Socket;
        internal readonly SemaphoreSlim Gate = new(1);
        internal readonly CancellationTokenSource Stop = new();
        internal readonly TaskCompletionSource Handshake = new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal TaskCompletionSource? Ack;
        internal uint NextReceive, NextSend, AckTarget, LastAck;
        internal ushort Window = 65535;
        internal int Mss = 536, SendBudget = 4 * 536;
        internal readonly List<Segment> Pending = new();
        internal TaskCompletionSource WindowChanged = new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal bool RemoteFin, Closed;
        internal long Used = Environment.TickCount64;
        public void Dispose() { if (Closed) return; Closed = true; Stop.Cancel(); Socket.Dispose(); Handshake.TrySetCanceled(); Ack?.TrySetCanceled(); WindowChanged.TrySetCanceled(); }
    }
    private sealed record Segment(uint End, byte[] Packet);
    public ProxyGatewayDevice(NetworkPolicy policy) { _policy = policy; _cleanup = CleanupAsync(); }
    public void UpdatePolicy(NetworkPolicy policy)
    {
        Volatile.Write(ref _policy, policy);
        foreach (var pair in _flows)
            if (!policy.Allows(pair.Value.Source, pair.Value.Destination)) Remove(pair.Key, pair.Value);
    }
    public string Name => "userspace-proxy";
    public Task ReconfigureAsync(IPAddress address, int prefixLength, CancellationToken ct) => Task.CompletedTask;
    public Task SynchronizePeerAddressesAsync(IReadOnlyCollection<IPAddress> addresses, CancellationToken ct) => Task.CompletedTask;
    public Task SynchronizeRemoteRoutesAsync(IReadOnlyCollection<string> cidrs, CancellationToken ct) => Task.CompletedTask;
    public async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
    {
        var packet = await _replies.Reader.ReadAsync(cancellationToken); packet.CopyTo(buffer); return packet.Length;
    }
    public ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
    {
        if (!_stop.IsCancellationRequested && _packets.Wait(0))
        {
            byte[] packet = buffer.ToArray();
            // Start synchronously to preserve arrival order until a real socket wait is needed.
            // Task.Run per packet could reorder adjacent TCP segments and force retransmission.
            _ = ProcessPacketAsync(packet);
        }
        return ValueTask.CompletedTask;
    }
    private async Task ProcessPacketAsync(byte[] packet)
    {
        try { await ProcessAsync(packet); }
        catch (Exception ex) when (ex is not OutOfMemoryException) { }
        finally { _packets.Release(); }
    }
    private async Task ProcessAsync(byte[] p)
    {
        if (p.Length < 20 || p[0] >> 4 != 4) return;
        int h = (p[0] & 15) * 4, total = U16(p, 2);
        if (h < 20 || total != p.Length || h > total || (U16(p, 6) & 0x3fff) != 0 || Checksum(p.AsSpan(0, h)) != 0) return;
        var source = new IPAddress(p.AsSpan(12, 4)); var dest = new IPAddress(p.AsSpan(16, 4));
        var policy = Volatile.Read(ref _policy);
        var network = policy.Match(dest);
        if (!policy.Allows(source, dest) || network is null || IPAddress.IsLoopback(dest) || dest.Equals(IPAddress.Any) || dest.GetAddressBytes()[0] >= 224) return;
        byte protocol = p[9];
        if (protocol == 1)
        {
            if (total < h + 8 || p[h] != 8 || p[h + 1] != 0 || Checksum(p.AsSpan(h)) != 0) return;
            using var ping = new Ping();
            var reply = await ping.SendPingAsync(dest, TimeSpan.FromSeconds(3), p.AsSpan(h + 8).ToArray(), cancellationToken: _stop.Token);
            if (reply.Status == IPStatus.Success) { var data = p.AsSpan(h).ToArray(); data[0] = 0; data[2] = data[3] = 0; Put16(data, 2, Checksum(data)); Emit(Ip(1, dest, source, data)); }
            return;
        }
        if (protocol is not (6 or 17) || total < h + (protocol == 6 ? 20 : 8)) return;
        int th = protocol == 6 ? (p[h + 12] >> 4) * 4 : 8;
        if (th < (protocol == 6 ? 20 : 8) || h + th > total) return;
        ushort sp = U16(p, h), dp = U16(p, h + 2); if (dp == 0) return;
        if (protocol == 6 && TransportChecksum(6, source, dest, p.AsSpan(h)) != 0) return;
        if (protocol == 17 && (U16(p, h + 4) != total - h || (U16(p, h + 6) != 0 && TransportChecksum(17, source, dest, p.AsSpan(h)) != 0))) return;
        string key = $"{protocol}:{source}:{sp}:{dest}:{dp}";
        if (!_flows.TryGetValue(key, out var f))
        {
            if (_flows.Count >= 256 || (protocol == 6 && (p[h + 13] & 0x17) != 2)) return;
            var socket = new Socket(AddressFamily.InterNetwork, protocol == 6 ? SocketType.Stream : SocketType.Dgram, protocol == 6 ? ProtocolType.Tcp : ProtocolType.Udp);
            try
            {
                if (network.Interface.Length > 0)
                {
                    var nic = NetworkInterface.GetAllNetworkInterfaces().FirstOrDefault(n => n.Name == network.Interface || n.Id == network.Interface)
                        ?? throw new IOException("指定网卡不存在");
                    var local = nic.GetIPProperties().UnicastAddresses.FirstOrDefault(a => a.Address.AddressFamily == AddressFamily.InterNetwork)
                        ?? throw new IOException("指定网卡没有 IPv4 地址");
                    socket.Bind(new IPEndPoint(local.Address, 0));
                }
                f = new Flow { Protocol = protocol, Source = source, Destination = dest, SourcePort = sp, DestinationPort = dp, Socket = socket,
                    NextReceive = protocol == 6 ? U32(p, h + 4) + 1 : 0, NextSend = BinaryPrimitives.ReadUInt32BigEndian(RandomNumberGenerator.GetBytes(4)) };
                if (!_flows.TryAdd(key, f)) { f.Dispose(); return; }
                using var timeout = CancellationTokenSource.CreateLinkedTokenSource(_stop.Token, f.Stop.Token); timeout.CancelAfter(TimeSpan.FromSeconds(5));
                await socket.ConnectAsync(new IPEndPoint(dest, dp), timeout.Token);
                if (protocol == 6)
                {
                    f.Window = U16(p, h + 14); socket.NoDelay = true;
                    f.LastAck = f.NextSend;
                    // Without a peer MSS option, IPv4 TCP's default is 536 bytes.
                    for (int i = h + 20; i < h + th;)
                    {
                        int kind = p[i]; if (kind == 0) break;
                        if (kind == 1) { i++; continue; }
                        if (i + 1 >= h + th || p[i + 1] < 2 || i + p[i + 1] > h + th) break;
                        if (kind == 2 && p[i + 1] == 4 && U16(p, i + 2) != 0) f.Mss = Math.Min(1160, (int)U16(p, i + 2));
                        i += p[i + 1];
                    }
                    f.SendBudget = Math.Min(32768, 4 * f.Mss);
                    _ = RunTcpAsync(key, f); return;
                }
                _ = ReceiveUdpAsync(key, f);
            }
            catch { socket.Dispose(); if (f is not null) { if (protocol == 6) Emit(Tcp(f, 0x14, [], f.NextSend)); Remove(key, f); } return; }
        }
        f.Used = Environment.TickCount64;
        if (protocol == 17) { await f.Socket.SendAsync(p.AsMemory(h + 8), SocketFlags.None, f.Stop.Token); return; }
        byte flags = p[h + 13]; uint seq = U32(p, h + 4), ack = U32(p, h + 8);
        if ((flags & 4) != 0) { Remove(key, f); return; }
        await f.Gate.WaitAsync(f.Stop.Token);
        try
        {
            if ((flags & 16) != 0)
            {
                // Sequence-number arithmetic must also work across uint wraparound.
                if (unchecked((int)(ack - f.LastAck)) < 0 || unchecked((int)(f.NextSend - ack)) < 0) return;
                f.LastAck = ack;
                f.Window = U16(p, h + 14);
                f.WindowChanged.TrySetResult();
                f.WindowChanged = new(TaskCreationOptions.RunContinuationsAsynchronously);
                f.Pending.RemoveAll(segment => unchecked((int)(ack - segment.End)) >= 0);
                if (f.Ack is not null && ack == f.AckTarget) { f.Ack.TrySetResult(); f.Handshake.TrySetResult(); }
            }
            if ((flags & 2) != 0) { foreach (var segment in f.Pending) Emit(segment.Packet); return; }
            if (!f.Handshake.Task.IsCompletedSuccessfully) return;
            int size = total - h - th;
            if (size > 0 || (flags & 1) != 0)
            {
                if (seq != f.NextReceive || f.RemoteFin) { Emit(Tcp(f, 0x10, [], f.NextSend)); return; }
                int sent = 0;
                while (sent < size) { int n = await f.Socket.SendAsync(p.AsMemory(h + th + sent, size - sent), SocketFlags.None, f.Stop.Token); if (n == 0) throw new IOException("TCP 已关闭"); sent += n; }
                f.NextReceive += (uint)size;
                if ((flags & 1) != 0) { f.NextReceive++; f.RemoteFin = true; f.Socket.Shutdown(SocketShutdown.Send); }
                Emit(Tcp(f, 0x10, [], f.NextSend));
            }
        }
        catch { Remove(key, f); }
        finally { f.Gate.Release(); }
    }
    private async Task RunTcpAsync(string key, Flow f)
    {
        try
        {
            await SendReliableAsync(f, 0x12, ReadOnlyMemory<byte>.Empty);
            var b = new byte[32768];
            while (!f.Stop.IsCancellationRequested)
            {
                int n = await f.Socket.ReceiveAsync(b, SocketFlags.None, f.Stop.Token);
                if (n == 0) { await SendReliableAsync(f, 0x11, ReadOnlyMemory<byte>.Empty); await Task.Delay(2000, f.Stop.Token); break; }
                int offset = 0;
                while (offset < n)
                {
                    int window = await WaitForWindowAsync(f);
                    int count = Math.Min(n - offset, Math.Min(window, Math.Min(f.SendBudget, 64 * f.Mss)));
                    await SendReliableAsync(f, 0x18, b.AsMemory(offset, count)); offset += count;
                }
            }
        }
        catch { if (!f.Closed) Emit(Tcp(f, 0x14, [], f.NextSend)); }
        finally { Remove(key, f); }
    }
    private async Task<int> WaitForWindowAsync(Flow f)
    {
        long until = Environment.TickCount64 + 30000;
        while (Environment.TickCount64 < until)
        {
            Task changed;
            await f.Gate.WaitAsync(f.Stop.Token);
            try
            {
                if (f.Window > 0) return f.Window;
                changed = f.WindowChanged.Task;
                Emit(Tcp(f, 0x10, [], f.NextSend - 1));
            }
            finally { f.Gate.Release(); }
            try { await changed.WaitAsync(TimeSpan.FromSeconds(1), f.Stop.Token); }
            catch (TimeoutException) { }
        }
        throw new IOException("TCP 零窗口超时");
    }
    private async Task SendReliableAsync(Flow f, byte flags, ReadOnlyMemory<byte> data)
    {
        await f.Gate.WaitAsync(f.Stop.Token);
        Task ack;
        try
        {
            f.Pending.Clear();
            int offset = 0;
            do
            {
                int count = Math.Min(f.Mss, data.Length - offset);
                byte[] packet = Tcp(f, flags, data.Span.Slice(offset, count), f.NextSend);
                f.NextSend += (uint)count + ((flags & 3) != 0 ? 1u : 0u);
                f.Pending.Add(new(f.NextSend, packet)); offset += count;
            } while (offset < data.Length);
            f.AckTarget = f.NextSend; f.Ack = new(TaskCreationOptions.RunContinuationsAsynchronously); ack = f.Ack.Task;
        }
        finally { f.Gate.Release(); }
        for (int attempt = 0; attempt < 10; attempt++)
        {
            Segment[] pending;
            await f.Gate.WaitAsync(f.Stop.Token);
            try { pending = f.Pending.ToArray(); }
            finally { f.Gate.Release(); }
            // Backpressure instead of silently dropping a whole HTTP burst when the VPN
            // output queue is busy. Never hold the ACK/input gate while waiting for it.
            foreach (var segment in pending)
            {
                if (f.Closed) break;
                var policy = Volatile.Read(ref _policy);
                if (!policy.Allows(f.Source, f.Destination)) throw new IOException("网关访问权限已撤销");
                await _replies.Writer.WriteAsync(segment.Packet, f.Stop.Token);
            }
            try
            {
                await ack.WaitAsync(TimeSpan.FromMilliseconds(Math.Min(2000, 400 * (attempt + 1))), f.Stop.Token);
                f.SendBudget = Math.Min(32768, f.SendBudget + Math.Max(data.Length, f.Mss));
                f.Used = Environment.TickCount64; return;
            }
            catch (TimeoutException) { f.SendBudget = Math.Max(2 * f.Mss, f.SendBudget / 2); }
        }
        throw new IOException("无 TUN TCP 重传超时");
    }
    private async Task ReceiveUdpAsync(string key, Flow f)
    {
        var b = new byte[65507];
        try
        {
            while (!f.Stop.IsCancellationRequested)
            {
                int n = await f.Socket.ReceiveAsync(b, SocketFlags.None, f.Stop.Token); f.Used = Environment.TickCount64;
                byte[] udp = new byte[8 + n]; Put16(udp, 0, f.DestinationPort); Put16(udp, 2, f.SourcePort); Put16(udp, 4, (ushort)udp.Length); b.AsSpan(0, n).CopyTo(udp.AsSpan(8));
                Emit(Ip(17, f.Destination, f.Source, udp));
            }
        }
        catch { } finally { Remove(key, f); }
    }
    private void Emit(byte[] p) { if (!_stop.IsCancellationRequested && Volatile.Read(ref _policy).Allows(new IPAddress(p.AsSpan(16, 4)), new IPAddress(p.AsSpan(12, 4)))) _replies.Writer.TryWrite(p); }
    private void Remove(string key, Flow f) { _flows.TryRemove(new KeyValuePair<string, Flow>(key, f)); f.Dispose(); }
    private async Task CleanupAsync()
    {
        try { using var timer = new PeriodicTimer(TimeSpan.FromSeconds(15)); while (await timer.WaitForNextTickAsync(_stop.Token)) foreach (var pair in _flows) if (Environment.TickCount64 - pair.Value.Used > (pair.Value.Protocol == 6 ? 600000 : 120000)) Remove(pair.Key, pair.Value); }
        catch (OperationCanceledException) { }
    }
    public async ValueTask DisposeAsync() { _stop.Cancel(); foreach (var pair in _flows) Remove(pair.Key, pair.Value); _replies.Writer.TryComplete(); await _cleanup; }
    private static byte[] Tcp(Flow f, byte flags, ReadOnlySpan<byte> payload, uint seq)
    {
        int h = (flags & 2) != 0 ? 24 : 20; byte[] tcp = new byte[h + payload.Length];
        Put16(tcp, 0, f.DestinationPort); Put16(tcp, 2, f.SourcePort); Put32(tcp, 4, seq); Put32(tcp, 8, f.NextReceive); tcp[12] = (byte)(h << 2); tcp[13] = flags; Put16(tcp, 14, 32768);
        if (h == 24) { tcp[20] = 2; tcp[21] = 4; Put16(tcp, 22, 1160); }
        payload.CopyTo(tcp.AsSpan(h)); Put16(tcp, 16, TransportChecksum(6, f.Destination, f.Source, tcp)); return Ip(6, f.Destination, f.Source, tcp);
    }
    private static byte[] Ip(byte protocol, IPAddress source, IPAddress dest, byte[] data)
    {
        byte[] p = new byte[20 + data.Length]; p[0] = 0x45; Put16(p, 2, (ushort)p.Length); p[6] = 0x40; p[8] = 64; p[9] = protocol;
        source.GetAddressBytes().CopyTo(p, 12); dest.GetAddressBytes().CopyTo(p, 16); Put16(p, 10, Checksum(p.AsSpan(0, 20))); data.CopyTo(p, 20); return p;
    }
    private static ushort TransportChecksum(byte protocol, IPAddress s, IPAddress d, ReadOnlySpan<byte> data)
    {
        Span<byte> pseudo = stackalloc byte[12]; pseudo.Clear();
        s.TryWriteBytes(pseudo[..4], out _); d.TryWriteBytes(pseudo.Slice(4, 4), out _);
        pseudo[9] = protocol; BinaryPrimitives.WriteUInt16BigEndian(pseudo[10..], (ushort)data.Length);
        uint sum = (uint)(ushort)~Checksum(pseudo) + (ushort)~Checksum(data);
        while (sum >> 16 != 0) sum = (sum & 65535) + (sum >> 16);
        return (ushort)~sum;
    }
    private static ushort Checksum(ReadOnlySpan<byte> b) { uint sum = 0; int i = 0; for (; i + 1 < b.Length; i += 2) sum += BinaryPrimitives.ReadUInt16BigEndian(b[i..]); if (i < b.Length) sum += (uint)b[i] << 8; while (sum >> 16 != 0) sum = (sum & 65535) + (sum >> 16); return (ushort)~sum; }
    private static ushort U16(byte[] b, int p) => BinaryPrimitives.ReadUInt16BigEndian(b.AsSpan(p));
    private static uint U32(byte[] b, int p) => BinaryPrimitives.ReadUInt32BigEndian(b.AsSpan(p));
    private static void Put16(byte[] b, int p, ushort v) => BinaryPrimitives.WriteUInt16BigEndian(b.AsSpan(p), v);
    private static void Put32(byte[] b, int p, uint v) => BinaryPrimitives.WriteUInt32BigEndian(b.AsSpan(p), v);
}
