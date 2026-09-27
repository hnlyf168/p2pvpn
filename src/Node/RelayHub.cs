using System.Collections.Concurrent;
using System.Net.WebSockets;
using System.Text.Json;
using System.Buffers.Binary;
using EdgeVpn;
namespace EdgeVpn.Node;

// The relay never receives the network PSK or end-to-end payload key.
public sealed class RelayHub(HttpClient control, IConfiguration configuration, ILogger<RelayHub> logger)
{
    private readonly ConcurrentDictionary<(string Session, ulong Peer), Connection> clients = new();
    public string[] OnlineDeviceIds => clients.Values.Select(c => c.Identity.DeviceId).Distinct().ToArray();
    private readonly SemaphoreSlim admission = new(configuration.GetValue("MaximumConnections", 1000));
    private readonly Dictionary<string, int> perAddress = new();
    public async Task HandleAsync(HttpContext ctx)
    {
        if (!ctx.WebSockets.IsWebSocketRequest) { ctx.Response.StatusCode = 400; return; }
        string header = ctx.Request.Headers.Authorization.ToString();
        if (!header.StartsWith("Bearer ") || header.Length > 256) { ctx.Response.StatusCode = 401; return; }
        string token = header[7..];
        string address = ctx.Connection.RemoteIpAddress?.ToString() ?? "unknown";
        if (!await admission.WaitAsync(0, ctx.RequestAborted)) { ctx.Response.StatusCode = 503; return; }
        int count; lock (perAddress) { count = perAddress.GetValueOrDefault(address) + 1; perAddress[address] = count; }
        Connection? connection = null;
        try
        {
            if (count > 32) { ctx.Response.StatusCode = 429; return; }
            var identity = await Inspect(token, ctx.RequestAborted);
            if (identity is null) { ctx.Response.StatusCode = 403; return; }
            using var socket = await ctx.WebSockets.AcceptWebSocketAsync();
            using var lifetime = CancellationTokenSource.CreateLinkedTokenSource(ctx.RequestAborted);
            string generation = ctx.Request.Headers["X-Device-Generation"].ToString();
            if (!Guid.TryParseExact(generation, "N", out _)) generation = Guid.NewGuid().ToString("N");
            connection = new(socket, identity, generation, lifetime);
            var key = (identity.SessionId, identity.PeerId);
            clients.AddOrUpdate(key, connection, (_, previous) => { previous.Stop(); return connection; });
            await Broadcast(identity.SessionId, lifetime.Token);
            var receive = Receive(connection, lifetime.Token);
            var validate = Revalidate(connection, token, lifetime.Token);
            await Task.WhenAny(receive, validate);
            connection.Stop();
            try { await Task.WhenAll(receive, validate); } catch (Exception e) when (e is OperationCanceledException or WebSocketException or IOException or HttpRequestException) { }
        }
        catch (Exception e) when (e is OperationCanceledException or WebSocketException or HttpRequestException or IOException)
        {
            if (!ctx.Response.HasStarted) ctx.Response.StatusCode = 503;
            logger.LogDebug("Relay connection ended: {Type}", e.GetType().Name);
        }
        finally
        {
            if (connection is not null)
            {
                clients.TryRemove(new KeyValuePair<(string, ulong), Connection>((connection.Identity.SessionId, connection.Identity.PeerId), connection));
                connection.Stop();
                using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(2));
                await Broadcast(connection.Identity.SessionId, timeout.Token);
            }
            lock (perAddress) { if (--perAddress[address] == 0) perAddress.Remove(address); }
            admission.Release();
        }
    }
    private async Task<RelayIdentity?> Inspect(string token, CancellationToken ct)
    {
        using var result = await control.PostAsJsonAsync("internal/relay/inspect", new InspectRequest(token), ct);
        return result.IsSuccessStatusCode ? await result.Content.ReadFromJsonAsync<RelayIdentity>(ct) : null;
    }
    private async Task Revalidate(Connection connection, string token, CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            await Task.Delay(TimeSpan.FromSeconds(5), ct);
            var identity = await Inspect(token, ct);
            if (identity is null || identity.SessionId != connection.Identity.SessionId) return;
            connection.Limit = identity.BytesPerSecond;
        }
    }
    private async Task Broadcast(string session, CancellationToken ct)
    {
        var members = clients.Values.Where(c => c.Identity.SessionId == session).ToArray();
        var bytes = JsonSerializer.SerializeToUtf8Bytes(members.Select(c =>
            new { id = c.Identity.DeviceId, address = c.Identity.Address, prefixLength = c.Identity.PrefixLength, generation = c.Generation }).ToArray());
        await Task.WhenAll(members.Select(async c =>
        {
            try { await c.Send(bytes, WebSocketMessageType.Text, ct); }
            catch { c.Stop(); }
        }));
    }
    private async Task Receive(Connection source, CancellationToken ct)
    {
        var buffer = new byte[132096];
        long window = Environment.TickCount64;
        int bytes = 0;
        while (!ct.IsCancellationRequested)
        {
            int length = 0; ValueWebSocketReceiveResult read;
            do
            {
                if (length == buffer.Length) throw new IOException("Oversized relay frame.");
                read = await source.Socket.ReceiveAsync(buffer.AsMemory(length), ct);
                if (read.MessageType != WebSocketMessageType.Binary) return;
                length += read.Count;
            } while (!read.EndOfMessage);
            if (length < 45 || buffer[0] != 1 || BinaryPrimitives.ReadUInt64BigEndian(buffer.AsSpan(1)) != source.Identity.PeerId) return;
            long now = Environment.TickCount64;
            if (now - window >= 1000) { window = now; bytes = 0; }
            bytes += length;
            if (bytes > source.Limit)
            {
                int duration = (int)Math.Ceiling(1000.0 * bytes / Math.Max(1024, source.Limit));
                await Task.Delay((int)Math.Max(1, duration - (now - window)), ct);
                window = Environment.TickCount64; bytes = 0;
            }
            ulong target = BinaryPrimitives.ReadUInt64BigEndian(buffer.AsSpan(9));
            if (target == source.Identity.PeerId) continue;
            if (clients.TryGetValue((source.Identity.SessionId, target), out var destination))
                try { await destination.Send(buffer.AsMemory(0, length), WebSocketMessageType.Binary, ct); }
                catch { destination.Stop(); }
        }
    }
    private sealed class Connection(WebSocket socket, RelayIdentity identity, string generation, CancellationTokenSource lifetime)
    {
        private readonly SemaphoreSlim sending = new(1);
        public WebSocket Socket => socket;
        public RelayIdentity Identity => identity;
        public string Generation => generation;
        public int Limit = identity.BytesPerSecond;
        public void Stop() { try { lifetime.Cancel(); socket.Abort(); } catch (ObjectDisposedException) { } }
        public async Task Send(ReadOnlyMemory<byte> payload, WebSocketMessageType type, CancellationToken ct)
        {
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
            timeout.CancelAfter(TimeSpan.FromSeconds(3));
            await sending.WaitAsync(timeout.Token);
            try { await socket.SendAsync(payload, type, true, timeout.Token); }
            finally { sending.Release(); }
        }
    }
}
