using System.Diagnostics;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Net.Sockets;
using System.Net.WebSockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using EdgeVpn;
using Qcxt.Net.P2P;
using Qcxt.Net.P2P.Protocol;
using Qcxt.Net.Quic.Security;

var root = Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "../../../../../"));
var run = Path.Combine(root, "artifacts", "tests", Guid.NewGuid().ToString("N"));
Directory.CreateDirectory(run);
var testDownloads = Path.Combine(run, "downloads");
Directory.CreateDirectory(testDownloads);
const string testPackage = "edge-vpn-client-linux-x64-0.0.1.zip";
using (var zip = System.IO.Compression.ZipFile.Open(Path.Combine(testDownloads, testPackage), System.IO.Compression.ZipArchiveMode.Create))
using (var writer = new StreamWriter(zip.CreateEntry("test.txt").Open())) writer.Write("isolated integration fixture");
File.Copy(Path.Combine(testDownloads, testPackage), Path.Combine(testDownloads, "edge-vpn-client-linux-x64-0.0.2.zip"));
File.Copy(Path.Combine(testDownloads, testPackage), Path.Combine(testDownloads, "edge-vpn-client-android-1.1.0.apk"));
File.Copy(Path.Combine(testDownloads, testPackage), Path.Combine(testDownloads, "edge-vpn-relay-android-1.1.0.apk"));
File.Copy(Path.Combine(testDownloads, testPackage), Path.Combine(testDownloads, "edge-vpn-client-linux-arm-1.1.0.apk"));
var children = new List<Process>();
var admin = Secrets.Token(); var punch = Secrets.Token(); var relay = Secrets.Token();
int webPort = FreePort(), relayPort = FreePort(), vpnPort = FreePort(), punchPort = FreePort();
string controlUrl = $"http://127.0.0.1:{webPort}", relayUrl = $"ws://127.0.0.1:{relayPort}/relay";
using var http = new HttpClient { BaseAddress = new(controlUrl), Timeout = TimeSpan.FromSeconds(15) };
using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(180));
var ct = timeout.Token;
try
{
    Start("ControlPlane", "EdgeVpn.ControlPlane", new()
    {
        ["ASPNETCORE_ENVIRONMENT"] = "Development", ["Mail__PickupDirectory"] = Path.Combine(run, "mail"),
        ["ASPNETCORE_URLS"] = controlUrl, ["PublicUrl"] = controlUrl, ["DataDirectory"] = Path.Combine(run, "data"),
        ["DownloadDirectory"] = testDownloads, ["AdminKey"] = admin, ["PunchNodeKey"] = punch, ["RelayNodeKey"] = relay,
        ["Coordinator__ListenAddress"] = "127.0.0.1", ["Coordinator__FirstPort"] = vpnPort.ToString(), ["Coordinator__Capacity"] = "1",
        ["Coordinator__Hosts__0"] = "127.0.0.1", ["RelayUrls__0"] = relayUrl,
        ["Logging__LogLevel__Default"] = "Warning"
    });
    Start("Node", "EdgeVpn.Node", new()
    {
        ["ASPNETCORE_URLS"] = $"http://127.0.0.1:{relayPort}", ["Role"] = "relay",
        ["ControlUrl"] = controlUrl, ["NodeKey"] = relay, ["Logging__LogLevel__Default"] = "Warning"
    });
    Start("Node", "EdgeVpn.Node", new()
    {
        ["ASPNETCORE_URLS"] = $"http://127.0.0.1:{punchPort}", ["Role"] = "punch",
        ["ControlUrl"] = controlUrl, ["NodeKey"] = punch, ["Coordinator__ListenAddress"] = "127.0.0.2",
        ["Logging__LogLevel__Default"] = "Warning"
    });
    await Until(async () => { try { return (await http.GetAsync("/health", ct)).IsSuccessStatusCode; } catch { return false; } });
    using var nodeHttp = new HttpClient();
    await Until(async () => { try { return (await nodeHttp.GetAsync($"http://127.0.0.1:{relayPort}/health", ct)).IsSuccessStatusCode; } catch { return false; } });
    var downloadCatalog = await Call("/api/downloads", null, null, "GET");
    Check(downloadCatalog.GetArrayLength() == 2 && downloadCatalog.EnumerateArray().Any(x => x.GetProperty("platform").GetString() == "linux-x64" && x.GetProperty("version").GetString() == "0.0.2"), "catalog lists latest package while historical URLs remain downloadable");
    await Expect("/admin/traffic", null, null, 401, "GET");
    await http.GetStringAsync("/", ct);
    await http.GetStringAsync("/downloads?ticket=must-not-be-stored", ct);
    await http.GetStringAsync("/site.css", ct);
    await http.GetStringAsync("/install.sh", ct);
    using (var full = await http.GetAsync("/downloads/" + testPackage, ct)) full.EnsureSuccessStatusCode();
    foreach (var range in new[] { "bytes=0-3", "bytes=4-7" })
    {
        using var req = new HttpRequestMessage(HttpMethod.Get, "/downloads/" + testPackage);
        req.Headers.Range = RangeHeaderValue.Parse(range);
        using var response = await http.SendAsync(req, ct);
        Check(response.StatusCode == HttpStatusCode.PartialContent, "real package range response");
    }
    using (var head = new HttpRequestMessage(HttpMethod.Head, "/downloads/" + testPackage))
    using (var response = await http.SendAsync(head, ct)) { }
    using (var missing = await http.GetAsync("/downloads/missing.zip", ct)) Check(missing.StatusCode == HttpStatusCode.NotFound, "missing package response");
    await Until(async () => (await Admin("/admin/traffic?days=7", null, "GET")).GetProperty("today").GetProperty("downloads").GetInt64() == 2);
    var trafficReport = await Admin("/admin/traffic?days=7", null, "GET");
    Check(trafficReport.GetProperty("today").GetProperty("pageViews").GetInt64() == 2 &&
        trafficReport.GetProperty("today").GetProperty("scriptRequests").GetInt64() == 1,
        "real HTTP traffic excludes API/static/HEAD/failures and separates installer requests");
    Check(!trafficReport.GetRawText().Contains("must-not-be-stored"), "traffic report excludes query secrets");
    var owner = await Call("/api/register", new { email = "owner@example.com", password = "Owner-test-password-2026" });
    string ownerToken = owner.GetProperty("token").GetString()!, ownerId = owner.GetProperty("account").GetProperty("id").GetString()!;
    var other = await Call("/api/register", new { email = "other@example.com", password = "Other-test-password-2026" });
    string otherToken = other.GetProperty("token").GetString()!;
    await Expect("/admin/traffic", null, ownerToken, 401, "GET");
    var network = await Call("/api/networks", new { name = "Regression network", subnet = "10.89.16.0/28" }, ownerToken);
    string id = network.GetProperty("id").GetString()!, group = network.GetProperty("groups")[0].GetProperty("id").GetString()!;
    await Expect("/api/networks/" + id + "/groups", new { name = "intrusion" }, otherToken, 404);
    var hidden = await Call("/api/networks", null, otherToken, "GET");
    Check(hidden.GetArrayLength() == 0, "tenant lists isolated");
    await Expect("/admin/accounts/" + ownerId + "/plan", new { plan = "pro", expiresAt = DateTimeOffset.UtcNow.AddDays(1) }, ownerToken, 401, "PUT");
    using (var apk = await http.GetAsync("/downloads/edge-vpn-client-android-1.1.0.apk", ct))
    {
        Check(apk.IsSuccessStatusCode && apk.Content.Headers.ContentType?.MediaType == "application/vnd.android.package-archive",
            "Android APK uses installable MIME type");
        Check(apk.Headers.ETag is not null, "APK downloads expose integrity-based cache identity");
    }
    await Expect("/downloads/edge-vpn-relay-android-1.1.0.apk", null, null, 404, "GET");
    await Expect("/downloads/edge-vpn-client-linux-arm-1.1.0.apk", null, null, 404, "GET");
    var mobileTicket = await Call("/api/networks/" + id + "/installations",
        new { name = "Android phone", groupId = group, platform = "android" }, ownerToken);
    string mobileUri = mobileTicket.GetProperty("joinUri").GetString()!;
    var mobileLink = new Uri(mobileUri);
    Check(mobileLink.Scheme == "edgevpn" && mobileLink.Host == "join" &&
        Uri.UnescapeDataString(mobileLink.Query[8..]) == controlUrl && mobileLink.Fragment.Length == 44,
        "Android join link carries origin and fragment ticket");
    Check(mobileTicket.GetProperty("command").GetString() == "" && mobileTicket.GetProperty("script").GetString() == "" &&
        mobileTicket.GetProperty("qrDataUrl").GetString()!.StartsWith("data:image/svg+xml;base64,"),
        "Android returns local QR data without desktop shell command");
    string mobileToken = mobileLink.Fragment[1..], mobileClaim = new string('a', 43);
    await Expect("/api/networks/" + id + "/installations/" + mobileTicket.GetProperty("id").GetString(), null, otherToken, 404, "GET");
    await Expect("/api/install/redeem", new { claim = mobileClaim, platform = "linux-arm64" }, mobileToken, 400);
    var mobile = (await Call("/api/install/redeem", new { claim = mobileClaim, platform = "android" }, mobileToken)).Deserialize<ClientProfile>(WebJson())!;
    var retriedMobile = (await Call("/api/install/redeem", new { claim = mobileClaim, platform = "android" }, mobileToken)).Deserialize<ClientProfile>(WebJson())!;
    Check(mobile.DeviceId == retriedMobile.DeviceId && mobile.DeviceToken == retriedMobile.DeviceToken &&
        mobile.Subnet == "10.89.16.0/28" && mobile.RelayUrls.Length == 0, "Android retry is idempotent and respects subnet and basic membership");
    await Expect("/api/install/redeem", new { claim = new string('b', 43), platform = "android" }, mobileToken, 401);
    await Call("/api/networks/" + id + "/devices/" + mobile.DeviceId, null, ownerToken, "DELETE");
    await Expect("/api/device/profile", null, mobile.DeviceToken, 401, "GET");
    await Expect("/api/install/redeem", new { claim = mobileClaim, platform = "android" }, mobileToken, 401);
    // Respect the real per-IP authentication limiter between enrollment test groups.
    await Task.Delay(TimeSpan.FromSeconds(61), ct);
    var key = await Call("/api/networks/" + id + "/keys", new { name = "test", groupId = group, uses = 3, validHours = 1 }, ownerToken);
    string joinKey = key.GetProperty("key").GetString()!;
    var a = (await Call("/api/enroll", new { key = joinKey, name = "alpha" })).Deserialize<ClientProfile>(WebJson())!;
    var b = (await Call("/api/enroll", new { key = joinKey, name = "beta" })).Deserialize<ClientProfile>(WebJson())!;
    var c = (await Call("/api/enroll", new { key = joinKey, name = "gamma" })).Deserialize<ClientProfile>(WebJson())!;
    await Expect("/api/enroll", new { key = joinKey, name = "overused" }, null, 401);
    Check(a.RelayUrls.Length == 0 && a.DeviceToken != b.DeviceToken, "basic plan has no relay and devices have distinct credentials");
    await RejectRelay(a);
    var group2 = await Call("/api/networks/" + id + "/groups", new { name = "isolated" }, ownerToken);
    var key2 = await Call("/api/networks/" + id + "/keys", new { name = "isolated", groupId = group2.GetProperty("id").GetString(), uses = 1, validHours = 1 }, ownerToken);
    var isolated = (await Call("/api/enroll", new { key = key2.GetProperty("key").GetString(), name = "isolated" })).Deserialize<ClientProfile>(WebJson())!;
    await Task.Delay(3500, ct);
    using var keys = new PreSharedKeyProvider(SHA256.HashData(Encoding.UTF8.GetBytes(a.SharedSecret)));
    await using (var first = Make(a, direct: true))
    await using (var second = Make(b, direct: true))
    await using (var separate = Make(isolated, direct: true))
    {
        await Task.WhenAll(first.StartAsync(new IPEndPoint(IPAddress.Loopback,vpnPort),keys,cancellationToken:ct),
            second.StartAsync(new IPEndPoint(IPAddress.Loopback,vpnPort),keys,cancellationToken:ct),
            separate.StartAsync(new IPEndPoint(IPAddress.Loopback,vpnPort),keys,cancellationToken:ct));
        await Until(() => Task.FromResult(first.Peers.Any(p => p.DirectConnected) && second.Peers.Any(p => p.DirectConnected)));
        Check(separate.Peers.Count == 0 && first.Peers.All(p => p.PeerId != isolated.DeviceId), "group isolation at coordinator");
        await Transfer(first, second, "basic direct UDP/TCP transport");
        Check(first.VirtualPrefixLength == 28 && first.VirtualAddress!.ToString().StartsWith("10.89.16."), "custom subnet address and /28 prefix on direct path");
        var onlineDevices = await Admin("/admin/devices", null, "GET");
        Check(onlineDevices.EnumerateArray().Count(d => d.GetProperty("online").GetBoolean()) >= 2, "administrator sees real connected devices");
    }
    // The secondary punch process independently authenticates devices and exchanges direct candidates.
    await using (var first = Make(a, direct: true))
    await using (var second = Make(b, direct: true))
    {
        int triesA = 0, triesB = 0;
        Task<IPEndPoint> ResolveA(CancellationToken _) => Task.FromResult(new IPEndPoint(IPAddress.Parse(++triesA == 1 ? "127.0.0.3" : "127.0.0.2"), vpnPort));
        Task<IPEndPoint> ResolveB(CancellationToken _) => Task.FromResult(new IPEndPoint(IPAddress.Parse(++triesB == 1 ? "127.0.0.3" : "127.0.0.2"), vpnPort));
        await Task.WhenAll(first.StartAsync(ResolveA, keys, cancellationToken: ct), second.StartAsync(ResolveB, keys, cancellationToken: ct));
        await Until(() => Task.FromResult(first.Peers.Any(p => p.DirectConnected) && second.Peers.Any(p => p.DirectConnected)));
        Check(triesA >= 2 && triesB >= 2, "failed coordinator attempts switch to secondary punch node");
        await Transfer(first, second, "standalone backup punch node direct transfer");
    }
    // Authenticated network membership alone cannot impersonate another device or group.
    await using (var invalid = new Qcxt.Net.P2P.Signaling.P2PSignalingClient(new P2PConnectionOptions {
        SessionId = a.Group, PeerId = a.DeviceId, RegistrationCredential = c.DeviceToken }, keys))
    {
        using var deadline = new CancellationTokenSource(4000); bool accepted = false;
        try { await invalid.ConnectAsync(new IPEndPoint(IPAddress.Loopback, vpnPort), cancellationToken: deadline.Token); accepted = true; }
        catch (Exception ex) when (ex is IOException or InvalidDataException or OperationCanceledException) { }
        Check(!accepted, "device credentials cannot impersonate another member");
    }
    // A deliberately modified client asks for legacy relay; the coordinator must still drop all payload.
    await using (var first = Make(a, direct: false, legacy: true))
    await using (var second = Make(b, direct: false, legacy: true))
    {
        await Task.WhenAll(first.StartAsync(new IPEndPoint(IPAddress.Loopback,vpnPort),keys,cancellationToken:ct),
            second.StartAsync(new IPEndPoint(IPAddress.Loopback,vpnPort),keys,cancellationToken:ct));
        await Until(() => Task.FromResult(first.Session.LinkCount > 0 && second.Session.LinkCount > 0));
        await first.Session.SendAsync(P2PFrameCodec.HashIdentifier(b.DeviceId), Encoding.UTF8.GetBytes("must not forward"),
            P2PDeliveryMode.Unreliable, cancellationToken:ct);
        using var noData = new CancellationTokenSource(1500);
        bool delivered = false;
        try { using var received = await second.Session.ReceiveAsync(noData.Token); delivered = true; } catch (OperationCanceledException) { }
        Check(!delivered, "control server rejects legacy relay data even for modified clients");
    }
    var status = await Admin("/admin/status", null, "GET");
    Check(status.GetProperty("relayPackets").GetInt32() == 0, "control relay counter is zero");
    await Admin("/admin/accounts/" + ownerId + "/plan", new { plan = "pro", expiresAt = DateTimeOffset.UtcNow.AddMinutes(10) }, "PUT");
    a = (await Call("/api/device/profile", null, a.DeviceToken, "GET")).Deserialize<ClientProfile>(WebJson())!;
    b = (await Call("/api/device/profile", null, b.DeviceToken, "GET")).Deserialize<ClientProfile>(WebJson())!;
    c = (await Call("/api/device/profile", null, c.DeviceToken, "GET")).Deserialize<ClientProfile>(WebJson())!;
    isolated = (await Call("/api/device/profile", null, isolated.DeviceToken, "GET")).Deserialize<ClientProfile>(WebJson())!;
    Check(a.RelayUrls.Length == 1, "pro plan receives independent relay");
    // Unreachable coordinator proves WSS can carry VPN frames when UDP is unavailable.
    await using (var first = Make(a, direct:false))
    await using (var second = Make(b, direct:false))
    await using (var separate = Make(isolated, direct:false))
    {
        int unavailable = FreePort();
        await Task.WhenAll(first.StartAsync(new IPEndPoint(IPAddress.Loopback,unavailable),keys,cancellationToken:ct),
            second.StartAsync(new IPEndPoint(IPAddress.Loopback,unavailable),keys,cancellationToken:ct),
            separate.StartAsync(new IPEndPoint(IPAddress.Loopback,unavailable),keys,cancellationToken:ct));
        await Until(() => Task.FromResult(first.Session.LinkCount > 0 && second.Session.LinkCount > 0));
        Check(first.VirtualAddress is not null && first.VirtualPrefixLength == 28, "relay-only startup supplies VPN address");
        Check(separate.Peers.Count == 0 && first.Peers.All(p => p.PeerId != isolated.DeviceId), "relay group isolation");
        await Transfer(first, second, "pro encrypted WSS relay with coordinator unreachable");
        Check(first.VirtualPrefixLength == 28, "relay-only custom subnet prefix is preserved");
        await second.DisposeAsync();
        await using var restarted = Make(b, direct: false);
        await restarted.StartAsync(new IPEndPoint(IPAddress.Loopback, unavailable), keys, cancellationToken: ct);
        await Until(() => Task.FromResult(restarted.Session.LinkCount > 0 && first.Peers.Any(p => p.PeerId == b.DeviceId)));
        await Task.Delay(500, ct);
        await Transfer(first, restarted, "relay-only peer restart resumes forward transfer");
        await Transfer(restarted, first, "relay-only peer restart resumes reverse transfer");
        await Call("/api/networks/" + id + "/devices/" + b.DeviceId, null, ownerToken, "DELETE");
        await Until(() => Task.FromResult(!restarted.IsConnected), seconds:15);
        await Expect("/api/device/profile", null, b.DeviceToken, 401, "GET");
        Console.WriteLine("PASS: active relay device revocation");
        await Admin("/admin/accounts/" + ownerId + "/plan", new { plan = "basic", expiresAt = (DateTimeOffset?)null }, "PUT");
        await Until(() => Task.FromResult(!first.IsConnected), seconds:15);
        await RejectRelay(a);
        Console.WriteLine("PASS: active relay entitlement revocation and bypass rejection");
    }
    await Admin("/admin/accounts/" + ownerId + "/plan", new { plan = "pro", expiresAt = DateTimeOffset.UtcNow.AddSeconds(2) }, "PUT");
    await Task.Delay(2500, ct);
    var afterExpiry = (await Call("/api/device/profile", null, a.DeviceToken, "GET")).Deserialize<ClientProfile>(WebJson())!;
    Check(afterExpiry.RelayUrls.Length == 0, "expired pro plan falls back to basic");
    await RejectRelay(a);
    var beforeRotation = a.SharedSecret;
    await Call("/api/networks/" + id + "/rotate", null, ownerToken, "POST");
    var rotated = (await Call("/api/device/profile", null, a.DeviceToken, "GET")).Deserialize<ClientProfile>(WebJson())!;
    Check(rotated.SharedSecret != beforeRotation && rotated.DataSecret != a.DataSecret, "key rotation refreshes authorized profiles");
    await Expect("/api/networks/" + id + "/devices/" + a.DeviceId, null, otherToken, 404, "DELETE");
    var downloads = await Call("/api/downloads", null, null, "GET");
    Console.WriteLine("ALL INTEGRATION CHECKS PASSED. No TUN or OS network settings were changed.");
}
finally
{
    foreach (var process in children) { try { if (!process.HasExited) process.Kill(entireProcessTree:true); } catch {} process.Dispose(); }
}

static JsonSerializerOptions WebJson() => new(JsonSerializerDefaults.Web);
void Check(bool value, string name) { if (!value) throw new Exception("FAIL: " + name); Console.WriteLine("PASS: " + name); }
async Task Until(Func<Task<bool>> condition, int seconds = 20)
{
    var start = Stopwatch.StartNew();
    while (start.Elapsed < TimeSpan.FromSeconds(seconds)) { if (await condition()) return; await Task.Delay(150, ct); }
    throw new TimeoutException("Condition did not become true.");
}
P2PNode Make(ClientProfile profile, bool direct, bool legacy = false) => new(new P2PConnectionOptions
{
    SessionId = profile.Group, PeerId = profile.DeviceId, RegistrationCredential = profile.DeviceToken,
    EnableCoordinatorRelay = legacy, EnableUdpHolePunching = direct, EnableTcpHolePunching = direct, EagerHolePunching = direct,
    RelayUrls = profile.RelayUrls, RelayCredential = profile.DeviceToken, RelayEncryptionKey = Convert.FromBase64String(profile.DataSecret),
    RelayFallbackDelay = TimeSpan.Zero, KeepAliveInterval = TimeSpan.FromSeconds(2), LinkIdleTimeout = TimeSpan.FromSeconds(15)
});
async Task Transfer(P2PNode from, P2PNode to, string name)
{
    byte[] payload = RandomNumberGenerator.GetBytes(16000);
    await from.Session.SendAsync(to.Session.LocalPeerId, payload, cancellationToken:ct);
    using var deadline = CancellationTokenSource.CreateLinkedTokenSource(ct); deadline.CancelAfter(TimeSpan.FromSeconds(10));
    using var actual = await to.Session.ReceiveAsync(deadline.Token);
    Check(actual.Payload.Span.SequenceEqual(payload), name);
}
async Task RejectRelay(ClientProfile profile)
{
    using var ws = new ClientWebSocket(); ws.Options.SetRequestHeader("Authorization", "Bearer " + profile.DeviceToken);
    bool connected = false;
    try { await ws.ConnectAsync(new(relayUrl), ct); connected = true; } catch (WebSocketException) {}
    Check(!connected, "relay refuses non-entitled device");
}
async Task<JsonElement> Call(string path, object? data, string? token = null, string method = "POST")
{
    if (path == "/api/register")
    {
        var input = JsonSerializer.SerializeToElement(data); var email = input.GetProperty("email").GetString()!;
        using var sent = await http.PostAsJsonAsync("/api/auth/email-code", new { email }, ct); sent.EnsureSuccessStatusCode();
        var message = Directory.GetFiles(Path.Combine(run, "mail")).Select(f => JsonDocument.Parse(File.ReadAllText(f)))
            .Last(m => m.RootElement.GetProperty("To").GetString() == email);
        var code = System.Text.RegularExpressions.Regex.Match(message.RootElement.GetProperty("Body").GetString()!, @"\b\d{6}\b").Value;
        data = new { email, password = input.GetProperty("password").GetString(), verificationCode = code };
    }
    using var request = new HttpRequestMessage(new HttpMethod(method), path);
    if (token is not null) request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
    if (data is not null) request.Content = JsonContent.Create(data);
    using var response = await http.SendAsync(request, ct);
    if (!response.IsSuccessStatusCode) throw new Exception(path + " returned " + (int)response.StatusCode + ": " + await response.Content.ReadAsStringAsync(ct));
    if (response.StatusCode == HttpStatusCode.NoContent) return default;
    return await response.Content.ReadFromJsonAsync<JsonElement>(ct);
}
async Task Expect(string path, object? data, string? token, int status, string method = "POST")
{
    using var request = new HttpRequestMessage(new HttpMethod(method), path);
    if (token is not null) request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
    if (data is not null) request.Content = JsonContent.Create(data);
    using var response = await http.SendAsync(request, ct);
    Check((int)response.StatusCode == status, path + " rejects unauthorized/invalid request");
}
async Task<JsonElement> Admin(string path, object? data, string method)
{
    using var request = new HttpRequestMessage(new HttpMethod(method), path); request.Headers.Add("X-Admin-Key",admin);
    if (data is not null) request.Content = JsonContent.Create(data);
    using var response = await http.SendAsync(request,ct); response.EnsureSuccessStatusCode();
    return await response.Content.ReadFromJsonAsync<JsonElement>(ct);
}
void Start(string project, string assembly, Dictionary<string,string> variables)
{
    var info = new ProcessStartInfo("dotnet") { WorkingDirectory = Path.Combine(root,"src",project), UseShellExecute=false, CreateNoWindow=true,
        RedirectStandardOutput=true, RedirectStandardError=true };
    info.ArgumentList.Add(Path.Combine(root,"src",project,"bin","Release","net10.0",assembly+".dll"));
    foreach (var pair in variables) info.Environment[pair.Key] = pair.Value;
    var process = Process.Start(info)!;
    process.OutputDataReceived += (_, e) => { if (e.Data is not null) File.AppendAllText(Path.Combine(run,project+"-"+process.Id+".out.log"),e.Data+Environment.NewLine); };
    process.ErrorDataReceived += (_, e) => { if (e.Data is not null) File.AppendAllText(Path.Combine(run,project+"-"+process.Id+".err.log"),e.Data+Environment.NewLine); };
    process.BeginOutputReadLine(); process.BeginErrorReadLine(); children.Add(process);
}
static int FreePort() { var listener = new TcpListener(IPAddress.Loopback,0); listener.Start(); int port = ((IPEndPoint)listener.LocalEndpoint).Port; listener.Stop(); return port; }
