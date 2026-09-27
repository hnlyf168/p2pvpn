using System.Net.WebSockets;
using System.Text.Json;
using Qcxt.Net.P2P.Protocol;
using Qcxt.Net.P2P.Session;
using Qcxt.Net.P2P.Signaling;
namespace Qcxt.Net.P2P.Relay;

/// <summary>Independent WSS fallback paths. Network data stays encrypted end-to-end through relay nodes.</summary>
public sealed class ExternalRelayConnection : IAsyncDisposable
{
    private readonly P2PConnectionOptions options;
    private readonly P2PMultipathSession session;
    private readonly CancellationTokenSource lifetime;
    private readonly Task[] tasks;
    private readonly string generation = Guid.NewGuid().ToString("N");
    private readonly Dictionary<ulong, string> peerGenerations = new();
    private readonly ConcurrentDictionary<string, DiscoveredPeer[]> directories = new();
    private readonly TaskCompletionSource ready = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private IPAddress? address;
    private int prefixLength = 16;
    /// <summary>Authenticated relay directory network prefix.</summary>
    public int PrefixLength => Volatile.Read(ref prefixLength);
    /// <summary>Completes after the relay authenticates the device and supplies its directory.</summary>
    public Task Ready => ready.Task;
    /// <summary>Relay directory's local address.</summary>
    public IPAddress? Address => Volatile.Read(ref address);
    /// <summary>Currently reachable authenticated peers across relay nodes.</summary>
    public IReadOnlyList<DiscoveredPeer> Peers => directories.Values.SelectMany(x => x).DistinctBy(p => p.PeerId).ToArray();
    /// <summary>True when at least one relay directory is available.</summary>
    public bool IsConnected => !directories.IsEmpty;
    /// <summary>Starts independently reconnecting fallback connections.</summary>
    public ExternalRelayConnection(P2PConnectionOptions options, P2PMultipathSession session, CancellationToken ct)
    {
        this.options = options; this.session = session;
        if (options.RelayEncryptionKey is not { Length: 32 }) throw new ArgumentException("Relay encryption key must contain 32 bytes.");
        lifetime = CancellationTokenSource.CreateLinkedTokenSource(ct);
        tasks = options.RelayUrls.Distinct().Take(2).Select(url => Run(url, lifetime.Token)).ToArray();
    }
    private async Task Run(string url, CancellationToken ct)
    {
        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri) || (uri.Scheme != "wss" && !(uri.Scheme == "ws" && uri.IsLoopback)))
            return;
        try { await Task.Delay(options.RelayFallbackDelay, ct); } catch (OperationCanceledException) { return; }
        while (!ct.IsCancellationRequested)
        {
            var links = new Dictionary<ulong, P2PRelayLink>();
            using var socket = new ClientWebSocket();
            using var sending = new SemaphoreSlim(1);
            using var generation = CancellationTokenSource.CreateLinkedTokenSource(ct);
            try
            {
                socket.Options.SetRequestHeader("Authorization", "Bearer " + options.RelayCredential);
                socket.Options.SetRequestHeader("X-Device-Generation", this.generation);
                socket.Options.KeepAliveInterval = TimeSpan.FromSeconds(10);
                using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
                timeout.CancelAfter(TimeSpan.FromSeconds(10));
                await socket.ConnectAsync(uri, timeout.Token);
                var buffer = new byte[132096];
                while (!ct.IsCancellationRequested)
                {
                    int length = 0; ValueWebSocketReceiveResult read;
                    do
                    {
                        if (length == buffer.Length) throw new IOException("Relay message too large.");
                        read = await socket.ReceiveAsync(buffer.AsMemory(length), generation.Token);
                        if (read.MessageType == WebSocketMessageType.Close) throw new IOException("Relay closed.");
                        length += read.Count;
                    } while (!read.EndOfMessage);
                    if (read.MessageType == WebSocketMessageType.Text)
                    {
                        using var json = JsonDocument.Parse(buffer.AsMemory(0, length));
                        var peers = new List<DiscoveredPeer>();
                        var retained = new HashSet<ulong>();
                        foreach (var item in json.RootElement.EnumerateArray())
                        {
                            string id = item.GetProperty("id").GetString()!;
                            var ip = IPAddress.Parse(item.GetProperty("address").GetString()!);
                            if (id == options.PeerId) {
                                int prefix = item.TryGetProperty("prefixLength", out var prefixValue) ? prefixValue.GetInt32() : 16;
                                if (prefix is < 8 or > 30) throw new IOException("Invalid relay address prefix.");
                                Volatile.Write(ref prefixLength, prefix); Volatile.Write(ref address, ip); continue; }
                            ulong peer = P2PFrameCodec.HashIdentifier(id);
                            string peerGeneration = item.GetProperty("generation").GetString()!;
                            lock (peerGenerations)
                            {
                                if (peerGenerations.TryGetValue(peer, out var previous) && previous != peerGeneration)
                                    session.ResetPeerGeneration(peer);
                                peerGenerations[peer] = peerGeneration;
                            }
                            retained.Add(peer);
                            peers.Add(new(id, peer, new(IPAddress.Any, 0), null, null, null, false, P2PTransportKind.Unknown, ip, null, null));
                            if (!links.ContainsKey(peer))
                            {
                                var link = new P2PRelayLink("wss-" + uri.Host + "-" + peer, P2PTransportKind.QuicRelay,
                                    options.MaximumFrameSize, 256, async (packet, traffic, token) =>
                                    {
                                        var frame = Encrypt(packet, session.LocalPeerId, peer, options.RelayEncryptionKey!);
                                        using var sendTimeout = CancellationTokenSource.CreateLinkedTokenSource(token, generation.Token);
                                        sendTimeout.CancelAfter(TimeSpan.FromSeconds(5));
                                        await sending.WaitAsync(sendTimeout.Token);
                                        try { await socket.SendAsync(frame.AsMemory(), WebSocketMessageType.Binary, true, sendTimeout.Token); }
                                        finally { sending.Release(); }
                                    });
                                links[peer] = link; session.AddLink(peer, link);
                            }
                        }
                        foreach (var obsolete in links.Keys.Except(retained).ToArray())
                        { await links[obsolete].DisposeAsync(); links.Remove(obsolete); }
                        directories[url] = peers.ToArray(); ready.TrySetResult();
                    }
                    else
                    {
                        if (length < 45 || buffer[0] != 1 || BinaryPrimitives.ReadUInt64BigEndian(buffer.AsSpan(9)) != session.LocalPeerId) continue;
                        ulong source = BinaryPrimitives.ReadUInt64BigEndian(buffer.AsSpan(1));
                        if (!links.TryGetValue(source, out var link)) continue;
                        byte[] plain = new byte[length - 45];
                        using var aes = new AesGcm(options.RelayEncryptionKey!, 16);
                        try { aes.Decrypt(buffer.AsSpan(17, 12), buffer.AsSpan(45, length - 45), buffer.AsSpan(29, 16), plain, buffer.AsSpan(0, 17)); }
                        catch (CryptographicException) { continue; }
                        await link.DeliverAsync(plain, generation.Token);
                    }
                }
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested) { break; }
            catch (Exception e) when (e is WebSocketException or IOException or OperationCanceledException or JsonException or InvalidOperationException or FormatException) { }
            finally
            {
                generation.Cancel(); socket.Abort(); directories.TryRemove(url, out _);
                foreach (var link in links.Values) await link.DisposeAsync();
            }
            try { await Task.Delay(TimeSpan.FromSeconds(5), ct); } catch (OperationCanceledException) { break; }
        }
    }
    private static byte[] Encrypt(ReadOnlyMemory<byte> packet, ulong source, ulong target, byte[] key)
    {
        var bytes = new byte[45 + packet.Length]; bytes[0] = 1;
        BinaryPrimitives.WriteUInt64BigEndian(bytes.AsSpan(1), source);
        BinaryPrimitives.WriteUInt64BigEndian(bytes.AsSpan(9), target);
        RandomNumberGenerator.Fill(bytes.AsSpan(17, 12));
        using var aes = new AesGcm(key, 16);
        aes.Encrypt(bytes.AsSpan(17, 12), packet.Span, bytes.AsSpan(45), bytes.AsSpan(29, 16), bytes.AsSpan(0, 17));
        return bytes;
    }
    /// <inheritdoc />
    public async ValueTask DisposeAsync()
    {
        lifetime.Cancel();
        try { await Task.WhenAll(tasks).WaitAsync(TimeSpan.FromSeconds(8)); } catch (OperationCanceledException) { }
        lifetime.Dispose();
    }
}
