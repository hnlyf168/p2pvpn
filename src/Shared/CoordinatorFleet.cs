using System.Collections.Concurrent;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Qcxt.Net.P2P.Signaling;
using Qcxt.Net.Quic.Security;
namespace EdgeVpn;

// Every network has its own PSK listener; a device credential additionally binds group and identity.
public sealed class CoordinatorFleet(Func<CancellationToken, Task<NodeSnapshot>> fetch,
    ILogger<CoordinatorFleet> logger, IPAddress? listenAddress = null) : BackgroundService
{
    private NodeSnapshot snapshot = new(DateTimeOffset.MinValue, []);
    private readonly ConcurrentDictionary<string, RunningNetwork> running = new();
    public Qcxt.Net.P2P.Signaling.P2PConnectedClient[] Clients => running.Values.SelectMany(x => x.Server.Clients).ToArray();
    public object Status => new { networks = running.Count, clients = running.Values.Sum(x => x.Server.ClientCount),
        relayPackets = running.Values.Sum(x => x.Server.RelayConnectionCount), relayEnabled = false };
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        try
        {
            while (!stoppingToken.IsCancellationRequested)
            {
                try
                {
                    var next = await fetch(stoppingToken);
                    Volatile.Write(ref snapshot, next);
                    foreach (var old in running.ToArray())
                        if (!next.Networks.Any(n => n.Id == old.Key && n.SharedSecret == old.Value.Secret && n.Subnet == old.Value.Subnet))
                            if (running.TryRemove(old.Key, out var removed)) await removed.DisposeAsync();
                    foreach (var network in next.Networks)
                    {
                        if (running.ContainsKey(network.Id)) continue;
                        var subnet = Ipv4Subnet.Parse(network.Subnet);
                        var keys = new PreSharedKeyProvider(SHA256.HashData(Encoding.UTF8.GetBytes(network.SharedSecret)));
                        var server = new P2PSignalingServer(new P2PServerOptions
                        {
                            ListenEndPoint = new IPEndPoint(listenAddress ?? IPAddress.Any, network.Port), KeyProvider = keys,
                            EnableRelay = false, MaximumClients = 512, MaximumPeersPerSession = Math.Min(256, subnet.Available),
                            VirtualNetworkAddress = subnet.Address, VirtualNetworkPrefixLength = subnet.Prefix,
                            SocketBufferSize = 262144, VirtualAddressLeaseProvider = new Leases(this, network.Id),
                            AuthorizeRegistration = (session, peer, token) => Authorize(network.Id, session, peer, token)
                        });
                        try { await server.StartAsync(stoppingToken); running[network.Id] = new(server, keys, network.SharedSecret, network.Subnet); }
                        catch { await server.DisposeAsync(); keys.Dispose(); throw; }
                    }
                }
                catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested) { break; }
                catch (Exception e) { logger.LogWarning("Coordinator synchronization failed: {Message}", e.Message); }
                await Task.Delay(TimeSpan.FromSeconds(3), stoppingToken);
            }
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested) { }
        finally { foreach (var value in running.Values) await value.DisposeAsync(); running.Clear(); }
    }
    private Device? Find(string networkId, string session, string peer)
    {
        var current = Volatile.Read(ref snapshot);
        if (DateTimeOffset.UtcNow - current.At > TimeSpan.FromSeconds(30)) return null;
        return current.Networks.FirstOrDefault(n => n.Id == networkId)?.Devices
            .FirstOrDefault(d => d.Id == peer && Secrets.Session(d) == session && !d.Revoked);
    }
    private bool Authorize(string networkId, string session, string peer, string token) =>
        Find(networkId, session, peer) is { } device && Secrets.Equal(device.TokenHash, Secrets.Hash(token));
    private sealed class Leases(CoordinatorFleet owner, string network) : IP2PVirtualAddressLeaseProvider
    {
        public IPAddress Acquire(string sessionId, string peerId, IPAddress networkAddress, int prefixLength) =>
            IPAddress.Parse(owner.Find(network, sessionId, peerId)?.Address ?? throw new UnauthorizedAccessException());
    }
    private sealed record RunningNetwork(P2PSignalingServer Server, PreSharedKeyProvider Keys, string Secret, string Subnet) : IAsyncDisposable
    {
        public async ValueTask DisposeAsync() { await Server.DisposeAsync(); Keys.Dispose(); }
    }
}
