using System.Net;
using System.Net.Mail;
using System.Threading.RateLimiting;
using EdgeVpn;
using EdgeVpn.ControlPlane;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.AspNetCore.HttpOverrides;
using Qcxt.Net.P2P.Protocol;

var builder = WebApplication.CreateBuilder(args);
builder.WebHost.ConfigureKestrel(o => o.Limits.MaxRequestBodySize = 16384);
builder.Services.AddSingleton<StateStore>();
builder.Services.AddSingleton<DownloadCatalog>();
builder.Services.AddSingleton<TrafficStatistics>();
builder.Services.AddHostedService(sp => sp.GetRequiredService<TrafficStatistics>());
builder.Services.AddSingleton<PlatformMail>();
builder.Services.Configure<ForwardedHeadersOptions>(o =>
{
    o.ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto;
    o.ForwardLimit = 1;
    o.KnownProxies.Clear();
    foreach (var value in builder.Configuration.GetSection("ReverseProxy:KnownProxies").Get<string[]>() ?? ["127.0.0.1", "::1"])
        o.KnownProxies.Add(IPAddress.Parse(value));
});
builder.Services.AddRateLimiter(o =>
{
    o.RejectionStatusCode = 429;
    o.GlobalLimiter = PartitionedRateLimiter.Create<HttpContext, string>(ctx =>
        RateLimitPartition.GetFixedWindowLimiter(ctx.Connection.RemoteIpAddress?.ToString() ?? "unknown",
        _ => new FixedWindowRateLimiterOptions { PermitLimit = 240, Window = TimeSpan.FromMinutes(1), QueueLimit = 0 }));
    o.AddPolicy("auth", ctx => RateLimitPartition.GetFixedWindowLimiter(
        ctx.Connection.RemoteIpAddress?.ToString() ?? "unknown",
        _ => new FixedWindowRateLimiterOptions { PermitLimit = 12, Window = TimeSpan.FromMinutes(1), QueueLimit = 0 }));
});
builder.Services.AddSingleton<CoordinatorFleet>(sp =>
{
    var store = sp.GetRequiredService<StateStore>();
    return new CoordinatorFleet(_ => Task.FromResult(Snapshot(store)),
        sp.GetRequiredService<ILogger<CoordinatorFleet>>(), IPAddress.Parse(builder.Configuration["Coordinator:ListenAddress"] ?? "0.0.0.0"));
});
builder.Services.AddHostedService(sp => sp.GetRequiredService<CoordinatorFleet>());
var app = builder.Build();
var store = app.Services.GetRequiredService<StateStore>();
var config = app.Configuration;
var catalog = app.Services.GetRequiredService<DownloadCatalog>();
var mail = app.Services.GetRequiredService<PlatformMail>();
var fleet = app.Services.GetRequiredService<CoordinatorFleet>();
var adminKey = RequiredKey("AdminKey");
var punchKey = RequiredKey("PunchNodeKey");
var relayKey = RequiredKey("RelayNodeKey");
if (new[] { adminKey, punchKey, relayKey }.Distinct().Count() != 3)
    throw new InvalidOperationException("AdminKey, PunchNodeKey and RelayNodeKey must be different.");
string controlUrl = config["PublicUrl"] ?? "http://localhost:5080";
if (!Uri.TryCreate(controlUrl, UriKind.Absolute, out var publicUri) ||
    (!publicUri.IsLoopback && publicUri.Scheme != "https")) throw new InvalidOperationException("PublicUrl requires HTTPS.");
int firstPort = config.GetValue("Coordinator:FirstPort", 49000);
int maxNetworks = config.GetValue("Coordinator:Capacity", 100);
if (firstPort < 1024 || maxNetworks < 1 || firstPort + maxNetworks > 65536) throw new InvalidOperationException("Invalid coordinator port range.");
var basic = config.GetSection("Plans:basic").Get<PlanOptions>() ?? new PlanOptions();
var pro = config.GetSection("Plans:pro").Get<PlanOptions>() ?? new PlanOptions { RelayEnabled = true, MaxNetworks = 20, MaxDevices = 100 };
foreach (var p in new[] { basic, pro })
    if (p.MaxNetworks is < 1 or > 100 || p.MaxDevices is < 1 or > 256 || p.RelayBytesPerSecond is < 1024 or > 104857600)
        throw new InvalidOperationException("Invalid plan limits.");

var bootstrapEmail = config["BootstrapAdmin:Email"];
var bootstrapPassword = config["BootstrapAdmin:Password"];
if (!string.IsNullOrEmpty(bootstrapEmail) && !string.IsNullOrEmpty(bootstrapPassword))
{
    var normalized = Email(bootstrapEmail);
    if (bootstrapPassword.Length < 20) throw new InvalidOperationException("Bootstrap password must be at least 20 characters.");
    store.Write(db =>
    {
        var existing = db.Accounts.FirstOrDefault(a => a.Email == normalized);
        if (existing is not null && !existing.IsAdmin) throw new InvalidOperationException("Bootstrap email belongs to a non-admin account.");
        if (existing is null)
        {
            var salt = Secrets.Token();
            db.Accounts.Add(new Account(Secrets.Id(), normalized, Secrets.Password(bootstrapPassword, salt), salt)
                { IsAdmin = true, RecoveryHash = Secrets.Hash(config["BootstrapAdmin:RecoveryCode"] ?? Secrets.Token()) });
        }
        return 0;
    });
}

app.UseForwardedHeaders();
var traffic = app.Services.GetRequiredService<TrafficStatistics>();
var downloadPaths = catalog.Items.Select(i => i.Url).ToHashSet(StringComparer.Ordinal);
app.Use(async (ctx, next) =>
{
    var path = ctx.Request.Path.Value ?? "/";
    if (path.Length > 1) path = path.TrimEnd('/');
    var knownDownload = downloadPaths.Contains(path);
    if (TrafficStatistics.Classify(ctx.Request.Method, path, 200, "text/html", "", knownDownload) is not null)
    {
        var requestedAt = DateTimeOffset.UtcNow;
        var range = ctx.Request.Headers.Range.ToString();
        ctx.Response.OnCompleted(() =>
        {
            var kind = TrafficStatistics.Classify(ctx.Request.Method, path, ctx.Response.StatusCode,
                ctx.Response.ContentType, range, knownDownload);
            if (kind is not null && !ctx.RequestAborted.IsCancellationRequested) traffic.Record(kind, path, requestedAt);
            return Task.CompletedTask;
        });
    }
    await next();
});
app.Use(async (ctx, next) =>
{
    ctx.Response.Headers["X-Content-Type-Options"] = "nosniff";
    ctx.Response.Headers["Referrer-Policy"] = "no-referrer";
    ctx.Response.Headers["X-Frame-Options"] = "DENY";
    ctx.Response.Headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()";
    if (ctx.Request.IsHttps) ctx.Response.Headers["Strict-Transport-Security"] = "max-age=15552000";
    ctx.Response.Headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; form-action 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'self'";
    if (ctx.Request.Path.StartsWithSegments("/api") || ctx.Request.Path.StartsWithSegments("/internal") || ctx.Request.Path.StartsWithSegments("/admin") || ctx.Request.Path.StartsWithSegments("/console") || ctx.Request.Path.StartsWithSegments("/ops"))
        ctx.Response.Headers.CacheControl = "no-store";
    try
    {
        if (ctx.Request.Method is not ("GET" or "HEAD" or "OPTIONS"))
        {
            var origin = ctx.Request.Headers.Origin.ToString();
            var expected = publicUri.GetLeftPart(UriPartial.Authority);
            if (origin.Length > 0 && !string.Equals(origin, expected, StringComparison.OrdinalIgnoreCase) &&
                !(publicUri.IsLoopback && Uri.TryCreate(origin, UriKind.Absolute, out var local) && local.IsLoopback &&
                  local.Port == ctx.Request.Host.Port))
            { ctx.Response.StatusCode = 403; await ctx.Response.WriteAsJsonAsync(new { error = "请求来源不受信任。" }); return; }
            if (!ctx.Request.Headers.Authorization.ToString().StartsWith("Bearer ") &&
                ctx.Request.Cookies.TryGetValue("edge_session", out var cookie) &&
                ctx.Request.Path.Value is not ("/api/login" or "/api/register" or "/api/auth/recover" or "/api/auth/email-code"))
            {
                if (!Secrets.Equal(ctx.Request.Headers["X-CSRF-Token"].ToString(), Csrf(cookie)))
                { ctx.Response.StatusCode = 403; await ctx.Response.WriteAsJsonAsync(new { error = "安全校验已过期，请刷新页面。" }); return; }
            }
        }
        if (ctx.Request.Path == "/internal/node/heartbeat")
        {
            var supplied = ctx.Request.Headers["X-Node-Key"].ToString();
            if (!store.Read(db => db.Nodes.Any(n => n.Enabled && Secrets.Equal(n.TokenHash, Secrets.Hash(supplied)))))
                throw new UnauthorizedAccessException("节点认证失败。");
            var size = ctx.Features.Get<Microsoft.AspNetCore.Http.Features.IHttpMaxRequestBodySizeFeature>();
            if (size is { IsReadOnly: false }) size.MaxRequestBodySize = 1048576;
        }
        await next();
    }
    catch (Exception e) when (e is UnauthorizedAccessException or KeyNotFoundException or ArgumentException or InvalidOperationException or BadHttpRequestException)
    {
        if (ctx.Response.HasStarted) throw;
        ctx.Response.StatusCode = e switch { UnauthorizedAccessException => 401, KeyNotFoundException => 404, InvalidOperationException => 409, _ => 400 };
        await ctx.Response.WriteAsJsonAsync(new { error = e.Message });
    }
});
app.UseRateLimiter();
app.UseDefaultFiles();
app.UseStaticFiles();
app.MapGet("/health", () => new { status = "ok", role = "control", relayEnabled = false });
app.MapPost("/api/register", async (HttpContext ctx, LoginRequest request) =>
{
    var email = Email(request.Email);
    if (request.Password is null || request.Password.Length is < 12 or > 128) throw new ArgumentException("密码长度应为 12–128 位。");
    var verification = store.Write(db => {
        var challenge = db.EmailChallenges.LastOrDefault(c => c.Email == email && c.Ready && !c.Used && c.ExpiresAt > DateTimeOffset.UtcNow);
        if (challenge is null || challenge.Attempts >= 5) return (string?)null;
        challenge.Attempts++;
        return request.VerificationCode?.Length == 6 && Secrets.Equal(challenge.CodeHash, CodeHash(email, request.VerificationCode)) ? challenge.Id : null;
    });
    if (verification is null) throw new UnauthorizedAccessException("邮箱验证码无效或已过期，请重新获取。");
    var salt = Secrets.Token();
    var password = Secrets.Password(request.Password, salt);
    var result = store.Write(db =>
    {
        if (db.Accounts.Any(a => a.Email == email)) throw new InvalidOperationException("该邮箱已注册。");
        if (db.Accounts.Count >= config.GetValue("AccountCapacity", 10000)) throw new InvalidOperationException("注册容量已满。");
        var challenge = db.EmailChallenges.Single(c => c.Id == verification);
        if (challenge.Used || !challenge.Ready || challenge.ExpiresAt <= DateTimeOffset.UtcNow) throw new UnauthorizedAccessException("邮箱验证码已使用或失效。");
        challenge.Used = true;
        var recovery = Secrets.Token();
        var account = new Account(Secrets.Id(), email, password, salt) { RecoveryHash = Secrets.Hash(recovery), EmailVerifiedAt = DateTimeOffset.UtcNow, CreatedAt = DateTimeOffset.UtcNow };
        db.Accounts.Add(account); Audit(db, account.Id, "register", account.Id);
        return Login(db, account, ctx, recovery);
    });
    await mail.Notify("新用户注册 · P2P VPN", "已验证邮箱的新用户注册：" + email);
    return result;
}).RequireRateLimiting("auth");
app.MapPost("/api/login", (HttpContext ctx, LoginRequest request) =>
{
    var email = Email(request.Email);
    if (request.Password is null || request.Password.Length > 128) throw new UnauthorizedAccessException("邮箱或密码错误。");
    var account = store.Read(db => db.Accounts.FirstOrDefault(a => a.Email == email));
    var hash = Secrets.Password(request.Password, account?.Salt ?? Convert.ToBase64String(new byte[32]));
    if (account is null || account.Disabled || account.LockedUntil > DateTimeOffset.UtcNow || !Secrets.Equal(account.PasswordHash, hash))
    {
        if (account is not null) store.Write(db => { var a = db.Accounts.Single(x => x.Id == account.Id);
            if (a.LockedUntil <= DateTimeOffset.UtcNow) { a.LockedUntil = null; a.FailedLogins = 0; }
            if (++a.FailedLogins >= 8) a.LockedUntil = DateTimeOffset.UtcNow.AddMinutes(15);
            return 0; });
        throw new UnauthorizedAccessException("邮箱或密码错误，连续失败后请稍后再试。");
    }
    return store.Write(db => { var current = db.Accounts.Single(a => a.Id == account.Id);
        if (current.Disabled || !Secrets.Equal(current.PasswordHash, account.PasswordHash) || current.LockedUntil > DateTimeOffset.UtcNow)
            throw new UnauthorizedAccessException("登录状态已改变，请重新登录。");
        current.FailedLogins = 0; current.LockedUntil = null; return Login(db, current, ctx); });
}).RequireRateLimiting("auth");
app.MapPost("/api/logout", (HttpContext ctx) =>
{
    var hash = Secrets.Hash(Bearer(ctx));
    store.Write(db => db.Sessions.RemoveAll(s => s.Hash == hash));
    ClearCookie(ctx);
    return Results.NoContent();
});
app.MapGet("/api/me", (HttpContext ctx) =>
{
    var user = User(ctx);
    return new { user.Id, user.Email, user.IsAdmin, plan = EffectivePlan(user), user.PlanExpiresAt, limits = Plan(user),
        relayAvailable = RelayEndpoints().Length > 0, csrfToken = Csrf(Bearer(ctx)) };
});
app.MapGet("/api/networks", (HttpContext ctx) =>
{
    var user = User(ctx);
    return store.Read(db => { var online = OnlineIds(db); return db.Networks.Where(n => n.OwnerId == user.Id).Select(n => new
    {
        n.Id, n.Name, n.Port, n.Subnet, n.Groups,
        installations = db.InstallTickets.Where(t => t.NetworkId == n.Id && !t.Revoked && t.ExpiresAt > DateTimeOffset.UtcNow).Select(t => new { t.Id, t.Name, t.Platform, t.GroupId, t.ExpiresAt, t.Revoked, t.DeviceId }),
        devices = db.Devices.Where(d => d.NetworkId == n.Id).Select(d => new { d.Id, d.Name, d.GroupId, d.Address, d.Revoked, d.CreatedAt, d.LastSeenAt, online = online.Contains(d.Id) }),
        keys = db.JoinKeys.Where(k => k.NetworkId == n.Id).Select(k => new { k.Id, k.Name, k.GroupId, k.ExpiresAt, k.RemainingUses, k.Revoked })
    }).ToArray(); });
});
app.MapPost("/api/networks", (HttpContext ctx, NameRequest request) =>
{
    var user = User(ctx); var name = Name(request.Name);
    return store.Write(db =>
    {
        if (db.Networks.Count(n => n.OwnerId == user.Id) >= Plan(user).MaxNetworks) throw new InvalidOperationException("已达到套餐网络数量上限。");
        var available = Enumerable.Range(firstPort, maxNetworks).Except(db.Networks.Select(n => n.Port)).ToArray();
        if (available.Length == 0) throw new InvalidOperationException("平台网络容量已满。");
        var subnet = SelectSubnet(db, user.Id, request.Subnet);
        var network = new VpnNetwork { Name = name, OwnerId = user.Id, Port = available[0], Subnet = subnet };
        network.Groups.Add(new VpnGroup(Secrets.Id(), "默认分组"));
        db.Networks.Add(network); Audit(db, user.Id, "network.create", network.Id);
        return new { network.Id, network.Name, network.Subnet, network.Groups };
    });
});
app.MapDelete("/api/networks/{id}", (HttpContext ctx, string id) =>
{
    var user = User(ctx);
    store.Write(db => { var n = Owned(db, id, user); db.Networks.Remove(n); db.Devices.RemoveAll(d => d.NetworkId == id);
        db.JoinKeys.RemoveAll(k => k.NetworkId == id); db.InstallTickets.RemoveAll(t => t.NetworkId == id); Audit(db, user.Id, "network.delete", id); return 0; });
    return Results.NoContent();
});
app.MapPost("/api/networks/{id}/groups", (HttpContext ctx, string id, NameRequest request) =>
{
    var user = User(ctx); var name = Name(request.Name);
    return store.Write(db => { var n = Owned(db, id, user); if (n.Groups.Count >= 32) throw new InvalidOperationException("最多 32 个分组。");
        if (n.Groups.Any(g => g.Name == name)) throw new InvalidOperationException("分组名称已存在。");
        var group = new VpnGroup(Secrets.Id(), name); n.Groups.Add(group); Audit(db, user.Id, "group.create", group.Id); return group; });
});
app.MapDelete("/api/networks/{id}/groups/{groupId}", (HttpContext ctx, string id, string groupId) =>
{
    var user = User(ctx);
    store.Write(db => { var n = Owned(db, id, user);
        if (n.Groups.Count == 1) throw new InvalidOperationException("至少保留一个分组。");
        if (!n.Groups.Any(g => g.Id == groupId)) throw new KeyNotFoundException("分组不存在。");
        if (db.Devices.Any(d => d.NetworkId == id && d.GroupId == groupId && !d.Revoked)) throw new InvalidOperationException("请先移除分组内的设备。");
        db.InstallTickets.Where(t => t.NetworkId == id && t.GroupId == groupId).ToList().ForEach(t => t.Revoked = true);
        n.Groups.RemoveAll(g => g.Id == groupId); db.JoinKeys.Where(k => k.NetworkId == id && k.GroupId == groupId).ToList().ForEach(k => k.Revoked = true);
        Audit(db, user.Id, "group.delete", groupId); return 0; });
    return Results.NoContent();
});
app.MapPost("/api/networks/{id}/keys", (HttpContext ctx, string id, KeyRequest request) =>
{
    var user = User(ctx); var name = Name(request.Name);
    if (request.Uses is < 1 or > 100 || request.ValidHours is < 1 or > 720) throw new ArgumentException("密钥次数应为 1–100，有效期 1–720 小时。");
    return store.Write(db => { var n = Owned(db, id, user);
        if (!n.Groups.Any(g => g.Id == request.GroupId)) throw new KeyNotFoundException("分组不存在。");
        if (db.JoinKeys.Count(k => k.NetworkId == id && !k.Revoked && k.ExpiresAt > DateTimeOffset.UtcNow && k.RemainingUses > 0) >= 50)
            throw new InvalidOperationException("最多保留 50 个有效加入密钥。");
        db.JoinKeys.RemoveAll(k => k.NetworkId == id && (k.Revoked || k.ExpiresAt < DateTimeOffset.UtcNow || k.RemainingUses == 0));
        string token = Secrets.Token();
        var key = new JoinKey { NetworkId = id, GroupId = request.GroupId, Name = name, Hash = Secrets.Hash(token),
            RemainingUses = request.Uses, ExpiresAt = DateTimeOffset.UtcNow.AddHours(request.ValidHours) };
        db.JoinKeys.Add(key); Audit(db, user.Id, "key.create", key.Id);
        return new { key.Id, key = token, key.ExpiresAt, key.RemainingUses };
    });
});
app.MapDelete("/api/networks/{id}/keys/{keyId}", (HttpContext ctx, string id, string keyId) =>
{
    var user = User(ctx); store.Write(db => { Owned(db, id, user);
        var key = db.JoinKeys.FirstOrDefault(k => k.Id == keyId && k.NetworkId == id) ?? throw new KeyNotFoundException("密钥不存在。");
        key.Revoked = true; Audit(db, user.Id, "key.revoke", keyId); return 0; }); return Results.NoContent();
});
app.MapDelete("/api/networks/{id}/devices/{deviceId}", (HttpContext ctx, string id, string deviceId) =>
{
    var user = User(ctx); store.Write(db => { Owned(db, id, user);
        var device = db.Devices.FirstOrDefault(d => d.Id == deviceId && d.NetworkId == id) ?? throw new KeyNotFoundException("设备不存在。");
        device.Revoked = true; Audit(db, user.Id, "device.revoke", deviceId); return 0; }); return Results.NoContent();
});
app.MapPost("/api/networks/{id}/rotate", (HttpContext ctx, string id) =>
{
    var user = User(ctx); store.Write(db => { var n = Owned(db, id, user); n.SharedSecret = Secrets.Token(); n.DataSecret = Secrets.Token();
        Audit(db, user.Id, "network.rotate", id); return 0; }); return Results.NoContent();
});
app.MapPost("/api/networks/{id}/installations", (HttpContext ctx, string id, InstallRequest request) =>
{
    var user = User(ctx); var name = Name(request.Name);
    if (request.Platform is not ("win-x64" or "linux" or "linux-x64" or "linux-arm64" or "linux-arm")) throw new ArgumentException("请选择 Windows x64 或 Linux（x64 / ARM64 / ARM32）。");
    return store.Write(db => {
        var n = Owned(db, id, user);
        if (!n.Groups.Any(g => g.Id == request.GroupId)) throw new KeyNotFoundException("分组不存在。");
        if (db.Devices.Count(d => d.NetworkId == id && !d.Revoked) >= Plan(user).MaxDevices) throw new InvalidOperationException("已达到网络设备上限。");
        db.InstallTickets.RemoveAll(t => t.ExpiresAt < DateTimeOffset.UtcNow);
        if (db.InstallTickets.Count(t => t.NetworkId == id && !t.Revoked && t.DeviceId == null) >= 20) throw new InvalidOperationException("待安装命令过多，请先撤销不再使用的命令。");
        var token = Microsoft.AspNetCore.WebUtilities.WebEncoders.Base64UrlEncode(System.Security.Cryptography.RandomNumberGenerator.GetBytes(32));
        var ticket = new InstallTicket { NetworkId = id, GroupId = request.GroupId, Name = name, Platform = request.Platform,
            Hash = Secrets.Hash(token), ExpiresAt = DateTimeOffset.UtcNow.AddMinutes(30) };
        var origin = publicUri.GetLeftPart(UriPartial.Authority);
        var windows = request.Platform == "win-x64";
        var script = File.ReadAllText(Path.Combine(app.Environment.ContentRootPath, "Installers", windows ? "install.ps1" : "install.sh"))
            .Replace("__CONTROL_URL__", origin).Replace("__INSTALL_TICKET__", token).Replace("\r\n", "\n");
        if (!windows) script = RenderLinuxInstaller(script);
        // The short-lived credential is a script argument, never a URL or a permanent device credential.
        var command = windows
            ? "$ErrorActionPreference='Stop'; [Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12; $p=Join-Path $env:TEMP ('EdgeVpn-'+[guid]::NewGuid().ToString('N')+'.ps1'); Invoke-WebRequest -UseBasicParsing '"+origin+"/install.ps1' -OutFile $p; if(Test-Path -LiteralPath $p){ & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $p -Ticket '"+token+"' }"
            : "f=$(mktemp) && curl -fsSL '"+origin+"/install.sh' -o \"$f\" && sudo sh \"$f\" --ticket '"+token+"'; r=$?; [ -z \"${f:-}\" ] || rm -f -- \"$f\"; (exit \"$r\")";
        db.InstallTickets.Add(ticket); Audit(db, user.Id, "installation.create", ticket.Id);
        return new { ticket.Id, ticket.Name, ticket.Platform, ticket.ExpiresAt, command, script };
    });
});
app.MapGet("/api/networks/{id}/installations/{ticketId}", (HttpContext ctx, string id, string ticketId) => {
    var user = User(ctx);
    return store.Read(db => {
        Owned(db, id, user);
        var t = db.InstallTickets.FirstOrDefault(t => t.Id == ticketId && t.NetworkId == id) ?? throw new KeyNotFoundException("安装命令已过期，请重新生成。");
        var d = db.Devices.FirstOrDefault(d => d.Id == t.DeviceId && !d.Revoked);
        return new { t.Id, t.ExpiresAt, t.DeviceId, address = d?.Address,
            status = t.Revoked || (t.DeviceId != null && d == null) ? "revoked" : d != null ? OnlineIds(db).Contains(d.Id) ? "online" : "enrolled" : t.ExpiresAt < DateTimeOffset.UtcNow ? "expired" : "pending" };
    });
});
app.MapDelete("/api/networks/{id}/installations/{ticketId}", (HttpContext ctx, string id, string ticketId) => {
    var user = User(ctx); store.Write(db => {
        Owned(db, id, user);
        var t = db.InstallTickets.FirstOrDefault(t => t.Id == ticketId && t.NetworkId == id) ?? throw new KeyNotFoundException("安装命令不存在。");
        t.Revoked = true; Audit(db, user.Id, "installation.revoke", t.Id); return 0;
    }); return Results.NoContent();
});
app.MapPost("/api/install/redeem", (HttpContext ctx, InstallClaimRequest request) => {
    var supplied = Bearer(ctx);
    if (supplied.Length > 128 || request.Claim == null || !System.Text.RegularExpressions.Regex.IsMatch(request.Claim, "\\A[a-zA-Z0-9_-]{43,64}\\z")) throw new UnauthorizedAccessException("安装凭据无效。");
    return store.Write(db => {
        var t = db.InstallTickets.FirstOrDefault(t => t.Hash == Secrets.Hash(supplied) && !t.Revoked && t.ExpiresAt > DateTimeOffset.UtcNow)
            ?? throw new UnauthorizedAccessException("安装命令已失效，请回控制台重新生成。");
        var linuxTarget = request.Platform is "linux-x64" or "linux-arm64" or "linux-arm";
        if (t.Platform != request.Platform && !(t.Platform == "linux" && linuxTarget)) throw new ArgumentException("安装命令与设备系统不匹配，请回控制台重新生成。");
        if (request.Platform is not ("win-x64" or "linux-x64" or "linux-arm64" or "linux-arm")) throw new ArgumentException("未支持的设备架构。");
        var n = db.Networks.FirstOrDefault(n => n.Id == t.NetworkId) ?? throw new UnauthorizedAccessException("网络已删除。");
        var user = db.Accounts.Single(a => a.Id == n.OwnerId);
        if (user.Disabled || !n.Groups.Any(g => g.Id == t.GroupId)) throw new UnauthorizedAccessException("网络账号或分组已停用。");
        var claimHash = Secrets.Hash(request.Claim);
        // Derive the credential for same-machine retries; no plaintext device token is stored.
        var token = Convert.ToBase64String(System.Security.Cryptography.HMACSHA256.HashData(System.Text.Encoding.UTF8.GetBytes(adminKey),
            System.Text.Encoding.UTF8.GetBytes("installation-v1:" + t.Id + ":" + request.Claim)));
        if (t.DeviceId != null) {
            var existing = db.Devices.FirstOrDefault(d => d.Id == t.DeviceId && !d.Revoked);
            if (t.ClaimHash != claimHash || existing == null || existing.TokenHash != Secrets.Hash(token)) throw new UnauthorizedAccessException("命令已被其他设备使用或设备凭据已撤销，请重新生成。");
            return Profile(n, existing, token, user);
        }
        if (db.Devices.Count(d => d.NetworkId == n.Id && !d.Revoked) >= Plan(user).MaxDevices) throw new InvalidOperationException("已达到网络设备上限。");
        var occupied = db.Devices.Where(d => d.NetworkId == n.Id && d.GroupId == t.GroupId && !d.Revoked).Select(d => d.Address).ToHashSet();
        var device = new Device { NetworkId = n.Id, GroupId = t.GroupId, Name = t.Name, TokenHash = Secrets.Hash(token), Address = Ipv4Subnet.Parse(n.Subnet).Allocate(occupied) };
        db.Devices.Add(device); t.Platform = request.Platform; t.ClaimHash = claimHash; t.DeviceId = device.Id; Audit(db, user.Id, "device.install", device.Id);
        return Profile(n, device, token, user);
    });
}).RequireRateLimiting("auth");

app.MapPost("/api/enroll", (EnrollRequest request) =>
{
    var name = Name(request.Name);
    if (request.Key is null || request.Key.Length > 128) throw new UnauthorizedAccessException("加入密钥无效。");
    return store.Write(db =>
    {
        var key = db.JoinKeys.FirstOrDefault(k => k.Hash == Secrets.Hash(request.Key) && !k.Revoked &&
            k.ExpiresAt > DateTimeOffset.UtcNow && k.RemainingUses > 0) ?? throw new UnauthorizedAccessException("加入密钥无效或已过期。");
        var n = db.Networks.Single(n => n.Id == key.NetworkId);
        var user = db.Accounts.Single(a => a.Id == n.OwnerId);
        if (user.Disabled) throw new UnauthorizedAccessException("网络所属账号已停用。");
        if (db.Devices.Count(d => d.NetworkId == n.Id && !d.Revoked) >= Plan(user).MaxDevices) throw new InvalidOperationException("已达到网络设备上限。");
        var occupied = db.Devices.Where(d => d.NetworkId == n.Id && d.GroupId == key.GroupId && !d.Revoked).Select(d => d.Address).ToHashSet();
        var address = Ipv4Subnet.Parse(n.Subnet).Allocate(occupied);
        var token = Secrets.Token();
        var device = new Device { NetworkId = n.Id, GroupId = key.GroupId, Name = name, TokenHash = Secrets.Hash(token), Address = address };
        db.Devices.Add(device); key.RemainingUses--; Audit(db, user.Id, "device.enroll", device.Id);
        return Profile(n, device, token, user);
    });
}).RequireRateLimiting("auth");
app.MapGet("/api/device/profile", (HttpContext ctx) => store.Write(db =>
{
    string token = Bearer(ctx); var device = DeviceByToken(db, token);
    device.LastSeenAt = DateTimeOffset.UtcNow;
    var n = db.Networks.Single(n => n.Id == device.NetworkId);
    return Profile(n, device, token, db.Accounts.Single(a => a.Id == n.OwnerId));
}));
app.MapGet("/api/downloads", () => catalog.Items);
app.MapGet("/downloads/{file}", (HttpContext ctx, string file) =>
{
    var item = catalog.Items.FirstOrDefault(i => i.Name == file);
    if (item is null) return Results.NotFound();
    ctx.Response.Headers.CacheControl = "public, max-age=3600";
    return Results.File(catalog.PathFor(item), "application/zip", file, enableRangeProcessing: true,
        entityTag: new Microsoft.Net.Http.Headers.EntityTagHeaderValue("\"" + item.Sha256 + "\""));
});
app.MapGet("/internal/punch/snapshot", (HttpContext ctx) => { NodeAuth(ctx, punchKey, "punch"); return Snapshot(store); });
app.MapPost("/internal/relay/inspect", (HttpContext ctx, InspectRequest request) =>
{
    NodeAuth(ctx, relayKey, "relay");
    return store.Read(db =>
    {
        var device = DeviceByToken(db, request.Token);
        var network = db.Networks.Single(n => n.Id == device.NetworkId);
        var owner = db.Accounts.Single(a => a.Id == network.OwnerId);
        var plan = Plan(owner);
        if (!plan.RelayEnabled) return Results.StatusCode(403);
        return Results.Ok(new RelayIdentity(device.Id, Secrets.Session(device), P2PFrameCodec.HashIdentifier(device.Id), device.Address, plan.RelayBytesPerSecond, Ipv4Subnet.Parse(network.Subnet).Prefix));
    });
});
app.MapGet("/admin/accounts", (HttpContext ctx) =>
{
    Admin(ctx); return store.Read(db => db.Accounts.Select(a => AccountView(db, a)).ToArray());
});
app.MapPut("/admin/accounts/{id}/plan", async (HttpContext ctx, string id, PlanRequest request) =>
{
    Admin(ctx);
    if (request.Plan is not ("basic" or "pro") || (request.Plan == "pro" && (request.ExpiresAt is null || request.ExpiresAt <= DateTimeOffset.UtcNow)))
        throw new ArgumentException("高级会员必须设置未来的到期时间。");
    var result = store.Write(db =>
    {
        var user = db.Accounts.SingleOrDefault(a => a.Id == id) ?? throw new KeyNotFoundException("账号不存在。");
        user.Plan = request.Plan; user.PlanExpiresAt = request.Plan == "basic" ? null : request.ExpiresAt;
        Audit(db, "admin", "plan.change:" + request.Plan, id);
        return new { user.Id, user.Plan, user.PlanExpiresAt };
    });
    var changed = store.Read(db => db.Accounts.Single(a => a.Id == id));
    await mail.Notify("会员变更 · P2P VPN", changed.Email + " 的会员已设置为 " + changed.Plan + "，到期：" + changed.PlanExpiresAt, true);
    return result;
});
app.MapGet("/admin/traffic", (HttpContext ctx, int? days) => { Admin(ctx); return traffic.Report(days ?? 30, DateTimeOffset.UtcNow); });
app.MapGet("/admin/audit", (HttpContext ctx) => { Admin(ctx); return store.Read(db => db.Audit.TakeLast(200).Reverse().ToArray()); });
app.MapGet("/admin/status", (HttpContext ctx) => { Admin(ctx); return app.Services.GetRequiredService<CoordinatorFleet>().Status; });

foreach (var route in new[] { "login", "register", "recover", "downloads", "guide", "features", "network", "scenarios", "pricing", "faq" })
{
    var file = route is "login" or "register" or "recover" ? "auth.html" : route + ".html";
    app.MapGet("/" + route, () => Results.File(Path.Combine(app.Environment.WebRootPath, file), "text/html; charset=utf-8"));
}
app.MapGet("/console", (HttpContext ctx) =>
{
    try { _ = User(ctx); }
    catch (UnauthorizedAccessException) { return Results.Redirect("/login"); }
    return Results.File(Path.Combine(app.Environment.ContentRootPath, "Pages", "console.html"), "text/html; charset=utf-8");
});
app.MapGet("/ops", (HttpContext ctx) =>
{
    try { Admin(ctx); }
    catch (UnauthorizedAccessException) { return Results.Redirect("/login"); }
    return Results.File(Path.Combine(app.Environment.ContentRootPath, "Pages", "ops.html"), "text/html; charset=utf-8");
});
app.MapGet("/api/security/sessions", (HttpContext ctx) =>
{
    var user = User(ctx); string current = Secrets.Hash(Bearer(ctx));
    return store.Read(db => db.Sessions.Where(s => s.AccountId == user.Id && s.ExpiresAt > DateTimeOffset.UtcNow)
        .Select(s => new { s.ExpiresAt, current = s.Hash == current }).ToArray());
});
app.MapDelete("/api/security/sessions", (HttpContext ctx) =>
{
    var user = User(ctx); var current = Secrets.Hash(Bearer(ctx));
    store.Write(db => { db.Sessions.RemoveAll(s => s.AccountId == user.Id && s.Hash != current);
        Audit(db, user.Id, "sessions.revoke", user.Id); return 0; });
    return Results.NoContent();
});
app.MapPost("/api/security/password", (HttpContext ctx, PasswordRequest request) =>
{
    var user = User(ctx); ValidatePassword(request.NewPassword);
    if (request.CurrentPassword is null || request.CurrentPassword.Length > 128 ||
        !Secrets.Equal(user.PasswordHash, Secrets.Password(request.CurrentPassword, user.Salt)))
        throw new UnauthorizedAccessException("当前密码不正确。");
    var salt = Secrets.Token(); var hash = Secrets.Password(request.NewPassword, salt);
    store.Write(db =>
    {
        var current = db.Accounts.Single(a => a.Id == user.Id);
        if (current.PasswordHash != user.PasswordHash) throw new InvalidOperationException("账号状态已变化，请重新登录。");
        db.Accounts[db.Accounts.IndexOf(current)] = current with { PasswordHash = hash, Salt = salt, FailedLogins = 0, LockedUntil = null };
        db.Sessions.RemoveAll(s => s.AccountId == user.Id); Audit(db, user.Id, "password.change", user.Id); return 0;
    });
    ClearCookie(ctx); return Results.NoContent();
}).RequireRateLimiting("auth");
app.MapPost("/api/security/recovery-key", (HttpContext ctx, PasswordRequest request) =>
{
    var user = User(ctx);
    if (request.CurrentPassword is null || request.CurrentPassword.Length > 128 ||
        !Secrets.Equal(user.PasswordHash, Secrets.Password(request.CurrentPassword, user.Salt)))
        throw new UnauthorizedAccessException("当前密码不正确。");
    var recovery = Secrets.Token();
    store.Write(db => { db.Accounts.Single(a => a.Id == user.Id).RecoveryHash = Secrets.Hash(recovery);
        Audit(db, user.Id, "recovery.rotate", user.Id); return 0; });
    return new { recoveryCode = recovery };
}).RequireRateLimiting("auth");
app.MapPost("/api/auth/recover", (HttpContext ctx, RecoveryRequest request) =>
{
    var email = Email(request.Email); ValidatePassword(request.NewPassword);
    if (request.RecoveryCode is null || request.RecoveryCode.Length is < 32 or > 128)
        throw new UnauthorizedAccessException("账号或恢复密钥无效。");
    var recovery = Secrets.Token(); var salt = Secrets.Token();
    var hash = Secrets.Password(request.NewPassword, salt);
    store.Write(db =>
    {
        var user = db.Accounts.FirstOrDefault(a => a.Email == email);
        if (user is null || user.RecoveryHash.Length == 0 || !Secrets.Equal(user.RecoveryHash, Secrets.Hash(request.RecoveryCode)))
            throw new UnauthorizedAccessException("账号或恢复密钥无效。");
        db.Accounts[db.Accounts.IndexOf(user)] = user with { PasswordHash = hash, Salt = salt,
            RecoveryHash = Secrets.Hash(recovery), FailedLogins = 0, LockedUntil = null };
        db.Sessions.RemoveAll(s => s.AccountId == user.Id); Audit(db, user.Id, "password.recover", user.Id); return 0;
    });
    ClearCookie(ctx); return new { recoveryCode = recovery };
}).RequireRateLimiting("auth");
app.MapPut("/api/networks/{id}", (HttpContext ctx, string id, NameRequest request) =>
{
    var user = User(ctx); string name = Name(request.Name);
    store.Write(db => { Owned(db, id, user).Name = name; Audit(db, user.Id, "network.rename", id); return 0; });
    return Results.NoContent();
});
app.MapPut("/api/networks/{id}/groups/{groupId}", (HttpContext ctx, string id, string groupId, NameRequest request) =>
{
    var user = User(ctx); string name = Name(request.Name);
    store.Write(db => { var network = Owned(db, id, user); var group = network.Groups.FirstOrDefault(g => g.Id == groupId)
        ?? throw new KeyNotFoundException("分组不存在。");
        if (network.Groups.Any(g => g.Id != groupId && g.Name == name)) throw new InvalidOperationException("分组名称已存在。");
        network.Groups[network.Groups.IndexOf(group)] = group with { Name = name };
        Audit(db, user.Id, "group.rename", groupId); return 0; });
    return Results.NoContent();
});
app.MapPut("/api/networks/{id}/devices/{deviceId}", (HttpContext ctx, string id, string deviceId, NameRequest request) =>
{
    var user = User(ctx); string name = Name(request.Name);
    store.Write(db => { Owned(db, id, user);
        var device = db.Devices.FirstOrDefault(d => d.NetworkId == id && d.Id == deviceId) ?? throw new KeyNotFoundException("设备不存在。");
        device.Name = name; Audit(db, user.Id, "device.rename", deviceId); return 0; });
    return Results.NoContent();
});
app.MapPost("/api/networks/{id}/devices/{deviceId}/configuration", (HttpContext ctx, string id, string deviceId) =>
{
    var user = User(ctx);
    return store.Write(db => {
        var network = Owned(db, id, user);
        var device = db.Devices.FirstOrDefault(d => d.NetworkId == id && d.Id == deviceId && !d.Revoked)
            ?? throw new KeyNotFoundException("设备不存在或已被移除。");
        var token = Secrets.Token(); device.TokenHash = Secrets.Hash(token);
        Audit(db, user.Id, "device.credential.rotate", deviceId);
        return Profile(network, device, token, user);
    });
});
app.MapGet("/api/audit", (HttpContext ctx) =>
{
    var user = User(ctx);
    return store.Read(db => db.Audit.Where(e => e.Actor == user.Id).TakeLast(100).Reverse().ToArray());
});
app.MapGet("/admin/nodes", (HttpContext ctx) =>
{
    Admin(ctx);
    return store.Read(db => db.Nodes.Select(n => new { n.Id, n.Name, n.Role, n.Endpoint, n.Enabled, n.LastSeenAt, n.Version,
        online = n.Enabled && n.LastSeenAt > DateTimeOffset.UtcNow.AddSeconds(-60) }).ToArray());
});
app.MapPost("/admin/nodes", (HttpContext ctx, NodeRequest request) =>
{
    Admin(ctx); string name = Name(request.Name);
    if (request.Role is not ("punch" or "relay")) throw new ArgumentException("节点类型无效。");
    string endpoint = (request.Endpoint ?? "").Trim();
    if (request.Role == "punch")
    {
        if (endpoint.Length > 253 || Uri.CheckHostName(endpoint) == UriHostNameType.Unknown)
            throw new ArgumentException("打洞节点地址应为主机名或 IPv4 地址，不包含协议和端口。");
    }
    else if (!Uri.TryCreate(endpoint, UriKind.Absolute, out var relayUri) ||
        (relayUri.Scheme != "wss" && !(relayUri.Scheme == "ws" && relayUri.IsLoopback)) ||
        relayUri.UserInfo.Length > 0 || relayUri.Query.Length > 0 || relayUri.Fragment.Length > 0 || relayUri.AbsolutePath != "/relay")
        throw new ArgumentException("中继节点地址应为 wss://域名/relay。");
    string secret = Secrets.Token();
    return store.Write(db => {
        if (db.Nodes.Count(n => n.Enabled) >= 16) throw new InvalidOperationException("最多配置 16 个有效节点。");
        if (db.Nodes.Any(n => n.Enabled && n.Role == request.Role && n.Endpoint == endpoint)) throw new InvalidOperationException("节点地址已存在。");
        var node = new PlatformNode { Name = name, Role = request.Role, Endpoint = endpoint, TokenHash = Secrets.Hash(secret) };
        db.Nodes.Add(node); Audit(db, "admin", "node.create", node.Id);
        return new { node.Id, node.Name, node.Role, node.Endpoint, nodeKey = secret, controlUrl };
    });
});
app.MapDelete("/admin/nodes/{id}", (HttpContext ctx, string id) =>
{
    Admin(ctx); store.Write(db => {
        var node = db.Nodes.FirstOrDefault(n => n.Id == id) ?? throw new KeyNotFoundException("节点不存在。");
        node.Enabled = false; Audit(db, "admin", "node.revoke", id); return 0; }); return Results.NoContent();
});
app.MapPost("/internal/node/heartbeat", (HttpContext ctx, NodeHeartbeatRequest request) =>
{
    string token = ctx.Request.Headers["X-Node-Key"].ToString();
    store.Write(db =>
    {
        var node = db.Nodes.FirstOrDefault(n => n.Id == request.NodeId && n.Role == request.Role && n.Enabled &&
            Secrets.Equal(n.TokenHash, Secrets.Hash(token))) ?? throw new UnauthorizedAccessException("节点授权无效。");
        if (request.Version is null || request.Version.Length > 32) throw new ArgumentException("版本无效。");
        if (request.DeviceIds?.Length > 20000) throw new ArgumentException("节点设备列表过大。");
        var valid = db.Devices.Where(d => !d.Revoked && db.Accounts.Any(a => a.Id == db.Networks.FirstOrDefault(n => n.Id == d.NetworkId)?.OwnerId && !a.Disabled)).Select(d => d.Id).ToHashSet();
        node.OnlineDeviceIds = (request.DeviceIds ?? []).Where(valid.Contains).Distinct().ToArray();
        node.LastSeenAt = DateTimeOffset.UtcNow; node.Version = request.Version; return 0;
    });
    return Results.NoContent();
});

app.MapGet("/api/registration", () => new { emailVerificationRequired = true, mailReady = mail.Ready });
app.MapPost("/api/auth/email-code", async (HttpContext ctx, EmailRequest request) =>
{
    var email = Email(request.Email);
    if (!mail.Ready) throw new InvalidOperationException("管理员尚未配置发信邮箱，注册暂不可用。已有账号可正常登录。");
    var now = DateTimeOffset.UtcNow;
    var code = System.Security.Cryptography.RandomNumberGenerator.GetInt32(0, 1000000).ToString("D6");
    var challengeId = store.Write(db => {
        db.EmailChallenges.RemoveAll(c => c.CreatedAt < now.AddHours(-1));
        if (db.EmailChallenges.Count >= 5000) throw new InvalidOperationException("邮件请求较多，请稍后再试。");
        var previous = db.EmailChallenges.Where(c => c.Email == email).ToArray();
        if (previous.Any(c => c.CreatedAt > now.AddSeconds(-60)) || previous.Length >= 5)
            throw new InvalidOperationException("请勿频繁发送验证码：间隔 60 秒，每小时最多 5 次。");
        foreach (var old in previous) old.Ready = false;
        var challenge = new EmailChallenge { Email = email, CodeHash = CodeHash(email, code), ExpiresAt = now.AddMinutes(10) };
        db.EmailChallenges.Add(challenge); return challenge.Id;
    });
    if (!store.Read(db => db.Accounts.Any(a => a.Email == email)))
    {
        await mail.Send(email, "注册邮箱验证码 · P2P VPN", "你的注册验证码：" + code + "\n10 分钟内有效，请勿向任何人透露。\n如果不是你本人申请，请忽略本邮件。", ctx.RequestAborted);
        store.Write(db => { var challenge = db.EmailChallenges.FirstOrDefault(c => c.Id == challengeId); if (challenge is not null) challenge.Ready = true; return 0; });
    }
    return new { message = "如邮箱可用于注册，验证码已发送。已注册邮箱请直接登录。", retryAfter = 60 };
}).RequireRateLimiting("auth");
app.MapGet("/admin/mail", (HttpContext ctx) => { Admin(ctx); return mail.PublicSettings(); });
app.MapPut("/admin/mail", (HttpContext ctx, MailSettingsRequest request) =>
{
    Admin(ctx);
    if (request.Security is not ("ssl" or "starttls") || request.Port is < 1 or > 65535)
        throw new ArgumentException("请选择 SSL/TLS 或 STARTTLS，并填写有效端口。");
    var host = (request.Host ?? "").Trim();
    if (host.Length > 253 || (host.Length > 0 && Uri.CheckHostName(host) == UriHostNameType.Unknown)) throw new ArgumentException("SMTP 主机名无效，不要包含协议或端口。");
    var from = string.IsNullOrWhiteSpace(request.FromEmail) ? "" : Email(request.FromEmail);
    var notification = string.IsNullOrWhiteSpace(request.NotificationEmail) ? "" : Email(request.NotificationEmail);
    var username = (request.Username ?? "").Trim();
    if (username.Length > 254 || username.Any(char.IsControl) || request.Password?.Length > 4096) throw new ArgumentException("发信账号或授权码格式无效。");
    if (request.Enabled && (host.Length == 0 || from.Length == 0)) throw new ArgumentException("启用前请填写 SMTP 主机和发信邮箱。");
    var fromName = Name(request.FromName);
    store.Write(db => {
        if (request.Enabled && username.Length > 0 && string.IsNullOrEmpty(request.Password) &&
            (db.Mail.PasswordCiphertext.Length == 0 || db.Mail.Host != host || db.Mail.Username != username))
            throw new ArgumentException("首次配置或更换发信服务器/账号时，请填写授权码。");
        db.Mail.Enabled = request.Enabled; db.Mail.Host = host; db.Mail.Port = request.Port; db.Mail.Security = request.Security;
        db.Mail.Username = username; db.Mail.FromEmail = from; db.Mail.FromName = fromName; db.Mail.NotificationEmail = notification;
        if (!string.IsNullOrEmpty(request.Password)) db.Mail.PasswordCiphertext = mail.Protect(request.Password);
        db.Mail.NotifyRegistrations = request.NotifyRegistrations; db.Mail.NotifyMembershipChanges = request.NotifyMembershipChanges;
        db.Mail.LastTestAt = null; db.Mail.LastError = "";
        Audit(db, "admin", "mail.configure", "smtp"); return 0;
    });
    return mail.PublicSettings();
});
app.MapPost("/admin/mail/test", async (HttpContext ctx, EmailRequest request) =>
{
    Admin(ctx); var recipient = Email(request.Email);
    await mail.Send(recipient, "发信测试 · P2P VPN", "这是一封平台发信测试邮件。收到此邮件表示当前 SMTP 配置能够向该收件邮箱投递邮件。", ctx.RequestAborted);
    store.Write(db => { db.Mail.LastTestAt = DateTimeOffset.UtcNow; Audit(db, "admin", "mail.test", recipient); return 0; });
    return new { message = "测试邮件已交给发信服务器，请检查收件箱和垃圾邮件。" };
}).RequireRateLimiting("auth");
app.MapGet("/admin/devices", (HttpContext ctx) => { Admin(ctx); return store.Read(db => DeviceViews(db, null)); });
app.MapGet("/admin/networks", (HttpContext ctx) => { Admin(ctx); return store.Read(db => db.Networks.Select(n => new {
    n.Id, n.Name, n.OwnerId, ownerEmail = db.Accounts.Single(a => a.Id == n.OwnerId).Email, n.Subnet, n.Port, n.Groups,
    devices = db.Devices.Count(d => d.NetworkId == n.Id && !d.Revoked) }).ToArray()); });
app.MapGet("/admin/accounts/{id}", (HttpContext ctx, string id) =>
{
    Admin(ctx); return store.Read(db => {
        var user = db.Accounts.FirstOrDefault(a => a.Id == id) ?? throw new KeyNotFoundException("账号不存在。");
        return new { account = AccountView(db, user), networks = db.Networks.Where(n => n.OwnerId == id).Select(n => new {
            n.Id, n.Name, n.Subnet, n.Port, n.Groups, keys = db.JoinKeys.Where(k => k.NetworkId == n.Id).Select(k => new { k.Id, k.Name, k.GroupId, k.RemainingUses, k.ExpiresAt, k.Revoked }) }).ToArray(),
            devices = DeviceViews(db, id), audit = db.Audit.Where(a => a.Actor == id).TakeLast(100).Reverse().ToArray() };
    });
});
app.MapPut("/admin/accounts/{id}/status", (HttpContext ctx, string id, DisabledRequest request) =>
{
    Admin(ctx); store.Write(db => {
        var user = db.Accounts.FirstOrDefault(a => a.Id == id) ?? throw new KeyNotFoundException("账号不存在。");
        if (user.IsAdmin) throw new InvalidOperationException("不能通过此接口停用平台管理员。");
        user.Disabled = request.Disabled; if (user.Disabled) db.Sessions.RemoveAll(s => s.AccountId == id);
        Audit(db, "admin", user.Disabled ? "account.disable" : "account.enable", id); return 0;
    }); return Results.NoContent();
});
app.MapPut("/api/networks/{id}/subnet", (HttpContext ctx, string id, NameRequest request) =>
{
    var user = User(ctx); store.Write(db => {
        var network = Owned(db, id, user);
        if (db.Devices.Any(d => d.NetworkId == id && !d.Revoked)) throw new InvalidOperationException("网络已有设备，为避免中断连接，请先移除所有设备再修改网段。");
        network.Subnet = SelectSubnet(db, user.Id, request.Subnet, id);
        Audit(db, user.Id, "network.subnet", id); return 0;
    }); return Results.NoContent();
});


app.MapGet("/install.ps1", () => {
    var script = File.ReadAllText(Path.Combine(app.Environment.ContentRootPath, "Installers", "install.ps1"))
        .Replace("__CONTROL_URL__", publicUri.GetLeftPart(UriPartial.Authority).Replace("'", "''")).Replace("__INSTALL_TICKET__", "");
    return Results.File(System.Text.Encoding.UTF8.GetPreamble().Concat(System.Text.Encoding.UTF8.GetBytes(script)).ToArray(), "text/plain; charset=utf-8", "install.ps1");
});
app.MapGet("/install.sh", () => {
    var script = File.ReadAllText(Path.Combine(app.Environment.ContentRootPath, "Installers", "install.sh"))
        .Replace("__CONTROL_URL__", publicUri.GetLeftPart(UriPartial.Authority)).Replace("__INSTALL_TICKET__", "").Replace("\r\n", "\n");
    return Results.File(System.Text.Encoding.UTF8.GetBytes(RenderLinuxInstaller(script)), "text/plain; charset=utf-8", "install.sh");
});
app.MapGet("/install.cmd", () => {
    var origin = publicUri.GetLeftPart(UriPartial.Authority);
    var ps = "$ErrorActionPreference='Stop'; [Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12; $p=Join-Path $env:TEMP ('EdgeVpnSetup-'+[Guid]::NewGuid().ToString('N')+'.ps1'); Invoke-WebRequest -UseBasicParsing '" + origin + "/install.ps1' -OutFile $p; $child=Start-Process powershell.exe -Verb RunAs -Wait -PassThru -ArgumentList @('-NoProfile','-ExecutionPolicy','Bypass','-File',('\"'+$p+'\"')); if($child.ExitCode -ne 0){throw 'Installation failed'}";
    var encoded = Convert.ToBase64String(System.Text.Encoding.Unicode.GetBytes(ps));
    var cmd = "@echo off\r\nchcp 65001 >nul\r\npowershell.exe -NoProfile -ExecutionPolicy Bypass -EncodedCommand " + encoded + "\r\npause\r\n";
    return Results.File(System.Text.Encoding.ASCII.GetBytes(cmd), "application/octet-stream", "EdgeVPN-install.cmd");
});

app.Run();

string RenderLinuxInstaller(string script)
{
    foreach (var (platform, key) in new[] { ("linux-x64", "LINUX_X64"), ("linux-arm64", "LINUX_ARM64"), ("linux-arm", "LINUX_ARM") })
    {
        var package = catalog.Items.SingleOrDefault(p => p.Kind == "client" && p.Platform == platform);
        script = script.Replace("__" + key + "_PATH__", package?.Url ?? "")
            .Replace("__" + key + "_SHA256__", package?.Sha256 ?? "");
    }
    return script;
}

string RequiredKey(string name)
{
    var key = config[name];
    if (string.IsNullOrWhiteSpace(key) || key.Length < 32) throw new InvalidOperationException(name + " must be a unique random secret of at least 32 characters.");
    return key;
}
void Admin(HttpContext ctx)
{
    if (Secrets.Equal(ctx.Request.Headers["X-Admin-Key"].ToString(), adminKey)) return;
    if (!User(ctx).IsAdmin) throw new UnauthorizedAccessException("管理员认证失败。");
}
void NodeAuth(HttpContext ctx, string key, string role)
{
    string supplied = ctx.Request.Headers["X-Node-Key"].ToString();
    if (Secrets.Equal(supplied, key)) return;
    if (!store.Read(db => db.Nodes.Any(n => n.Role == role && n.Enabled && Secrets.Equal(n.TokenHash, Secrets.Hash(supplied)))))
        throw new UnauthorizedAccessException("节点认证失败。");
}
static string Bearer(HttpContext ctx)
{
    var value = ctx.Request.Headers.Authorization.ToString();
    if (string.IsNullOrEmpty(value) && ctx.Request.Cookies.TryGetValue("edge_session", out var session)) value = "Bearer " + session;
    if (!value.StartsWith("Bearer ", StringComparison.Ordinal) || value.Length is < 16 or > 256) throw new UnauthorizedAccessException("请先登录。");
    return value[7..];
}
Account User(HttpContext ctx) => store.Read(db =>
{
    var hash = Secrets.Hash(Bearer(ctx));
    var session = db.Sessions.FirstOrDefault(s => s.Hash == hash && s.ExpiresAt > DateTimeOffset.UtcNow) ?? throw new UnauthorizedAccessException("会话已过期，请重新登录。");
    return db.Accounts.SingleOrDefault(a => a.Id == session.AccountId && !a.Disabled) ?? throw new UnauthorizedAccessException("账号已停用。");
});
static string Name(string value)
{
    if (string.IsNullOrWhiteSpace(value) || value.Length > 64 || value.Any(char.IsControl)) throw new ArgumentException("名称长度应为 1–64 位。");
    return value.Trim();
}
static string Email(string value)
{
    if (string.IsNullOrWhiteSpace(value) || value.Length > 254 || !MailAddress.TryCreate(value, out var parsed) || parsed.Address != value.Trim())
        throw new ArgumentException("邮箱格式无效。");
    return value.Trim().ToLowerInvariant();
}
static VpnNetwork Owned(Database db, string id, Account user) =>
    db.Networks.FirstOrDefault(n => n.Id == id && n.OwnerId == user.Id) ?? throw new KeyNotFoundException("网络不存在。");
object Login(Database db, Account account, HttpContext ctx, string? recovery = null)
{
    account.LastLoginAt = DateTimeOffset.UtcNow;
    db.Sessions.RemoveAll(s => s.ExpiresAt <= DateTimeOffset.UtcNow);
    var existing = db.Sessions.Where(s => s.AccountId == account.Id).ToArray();
    foreach (var session in existing.Take(Math.Max(0, existing.Length - 4))) db.Sessions.Remove(session);
    var token = Secrets.Token(); db.Sessions.Add(new(Secrets.Hash(token), account.Id, DateTimeOffset.UtcNow.AddHours(12)));
    if (ctx.Request.Headers["X-Session-Mode"] == "cookie")
    {
        ctx.Response.Cookies.Append("edge_session", token, new CookieOptions { HttpOnly = true,
            Secure = publicUri.Scheme == "https", SameSite = SameSiteMode.Strict, Path = "/", MaxAge = TimeSpan.FromHours(12), IsEssential = true });
        return new { account = new { account.Id, account.Email, account.IsAdmin }, csrfToken = Csrf(token), recoveryCode = recovery };
    }
    return new { token, account = new { account.Id, account.Email }, recoveryCode = recovery };
}
static string EffectivePlan(Account user) => user.Plan == "pro" && user.PlanExpiresAt > DateTimeOffset.UtcNow ? "pro" : "basic";
PlanOptions Plan(Account user) => EffectivePlan(user) == "pro" ? pro : basic;
ClientProfile Profile(VpnNetwork n, Device device, string token, Account user)
{
    var hosts = config.GetSection("Coordinator:Hosts").Get<string[]>() ?? ["localhost"];
    if (hosts.Length == 0) throw new InvalidOperationException("Coordinator hosts are not configured.");
    string[] servers = hosts.Select(host => $"{host}:{n.Port}").ToArray();
    var backups = store.Read(db => db.Nodes.Where(n => n.Enabled && n.Role == "punch" &&
        n.LastSeenAt > DateTimeOffset.UtcNow.AddSeconds(-60)).Select(n => n.Endpoint).ToArray());
    servers = servers.Concat(backups.Select(host => $"{host}:{n.Port}")).Distinct().Take(4).ToArray();
    var relays = Plan(user).RelayEnabled ? RelayEndpoints() : [];
    return new(servers[0], Secrets.Session(device), n.SharedSecret, device.Id, token, controlUrl, servers,
        relays, Secrets.GroupDataKey(n, device.GroupId), Subnet: n.Subnet);
}
static Device DeviceByToken(Database db, string token)
{
    if (string.IsNullOrEmpty(token) || token.Length > 128) throw new UnauthorizedAccessException("设备凭据无效。");
    return db.Devices.FirstOrDefault(d => !d.Revoked && db.Accounts.Any(a => !a.Disabled && a.Id == db.Networks.FirstOrDefault(n => n.Id == d.NetworkId)!.OwnerId) && Secrets.Equal(d.TokenHash, Secrets.Hash(token)))
        ?? throw new UnauthorizedAccessException("设备凭据无效或已吊销。");
}
static void Audit(Database db, string actor, string action, string target)
{
    db.Audit.Add(new(DateTimeOffset.UtcNow, actor, action, target));
    if (db.Audit.Count > 10000) db.Audit.RemoveRange(0, db.Audit.Count - 10000);
}
static NodeSnapshot Snapshot(StateStore store) => store.Read(db => new NodeSnapshot(DateTimeOffset.UtcNow,
    db.Networks.Where(n => db.Accounts.Any(a => a.Id == n.OwnerId && !a.Disabled)).Select(n => new NetworkSnapshot(n.Id, n.Port, n.SharedSecret, db.Devices.Where(d => d.NetworkId == n.Id && !d.Revoked).ToArray(), n.Subnet)).ToArray()));


string Csrf(string token) => Convert.ToHexString(System.Security.Cryptography.HMACSHA256.HashData(
    System.Text.Encoding.UTF8.GetBytes(adminKey), System.Text.Encoding.UTF8.GetBytes("csrf:" + token)));
void ClearCookie(HttpContext ctx) => ctx.Response.Cookies.Delete("edge_session",
    new CookieOptions { Path = "/", Secure = publicUri.Scheme == "https", HttpOnly = true, SameSite = SameSiteMode.Strict });
string[] RelayEndpoints() => (config.GetSection("RelayUrls").Get<string[]>() ?? [])
    .Concat(store.Read(db => db.Nodes.Where(n => n.Enabled && n.Role == "relay" &&
        n.LastSeenAt > DateTimeOffset.UtcNow.AddSeconds(-60)).Select(n => n.Endpoint).ToArray())).Distinct().Take(2).ToArray();

static void ValidatePassword(string password)
{
    if (password is null || password.Length is < 12 or > 128) throw new ArgumentException("密码长度应为 12–128 位。");
}
string CodeHash(string email, string code) => Convert.ToHexString(System.Security.Cryptography.HMACSHA256.HashData(
    System.Text.Encoding.UTF8.GetBytes(adminKey), System.Text.Encoding.UTF8.GetBytes("email:" + email + ":" + code)));
HashSet<string> OnlineIds(Database db)
{
    var valid = db.Devices.Where(d => !d.Revoked && db.Networks.Any(n => n.Id == d.NetworkId && db.Accounts.Any(a => a.Id == n.OwnerId && !a.Disabled))).Select(d => d.Id).ToHashSet();
    return fleet.Clients.Select(c => c.PeerId).Concat(db.Nodes.Where(n => n.Enabled && n.LastSeenAt > DateTimeOffset.UtcNow.AddSeconds(-45))
        .SelectMany(n => n.OnlineDeviceIds)).Where(valid.Contains).ToHashSet();
}
object AccountView(Database db, Account a)
{
    var networkIds = db.Networks.Where(n => n.OwnerId == a.Id).Select(n => n.Id).ToHashSet();
    var devices = db.Devices.Where(d => networkIds.Contains(d.NetworkId) && !d.Revoked).ToArray(); var online = OnlineIds(db);
    return new { a.Id, a.Email, a.IsAdmin, a.Disabled, a.CreatedAt, a.EmailVerifiedAt, a.LastLoginAt, a.Plan, a.PlanExpiresAt,
        effectivePlan = EffectivePlan(a), networks = networkIds.Count, devices = devices.Length, onlineDevices = devices.Count(d => online.Contains(d.Id)) };
}
object[] DeviceViews(Database db, string? ownerId)
{
    var connected = fleet.Clients; var online = OnlineIds(db);
    var owners = db.Accounts.ToDictionary(a => a.Id); var networks = db.Networks.ToDictionary(n => n.Id);
    return db.Devices.Where(d => ownerId is null || networks[d.NetworkId].OwnerId == ownerId).Select(d => {
        var network = networks[d.NetworkId]; var owner = owners[network.OwnerId]; var connection = connected.FirstOrDefault(c => c.PeerId == d.Id);
        var nodes = db.Nodes.Where(n => n.Enabled && n.LastSeenAt > DateTimeOffset.UtcNow.AddSeconds(-45) && n.OnlineDeviceIds.Contains(d.Id)).ToArray();
        return (object)new { d.Id, d.Name, d.Address, d.NetworkId, networkName = network.Name, network.Subnet, d.GroupId,
            groupName = network.Groups.FirstOrDefault(g => g.Id == d.GroupId)?.Name ?? "已删除", ownerId = owner.Id, ownerEmail = owner.Email,
            d.Revoked, d.CreatedAt, d.LastSeenAt, online = online.Contains(d.Id), connectedAt = connection?.ConnectedAt,
            publicEndpoint = connection?.PublicEndPoint.ToString(), clientVersion = connection?.ClientVersion, platform = connection?.ClientPlatform,
            connections = (connection is not null ? new[] { "主协调" } : Array.Empty<string>()).Concat(nodes.Select(n => n.Name + (n.Role == "relay" ? "（中继）" : "（备用协调）"))).ToArray() };
    }).ToArray();
}
string SelectSubnet(Database db, string ownerId, string? requested, string? exceptId = null)
{
    var used = db.Networks.Where(n => n.OwnerId == ownerId && n.Id != exceptId).Select(n => Ipv4Subnet.Parse(n.Subnet)).ToArray();
    if (string.IsNullOrWhiteSpace(requested))
    {
        for (uint value = 0x0a4d0000; value < 0x0aff0000; value += 256)
        { var candidate = new Ipv4Subnet(value, 24); if (!used.Any(candidate.Overlaps)) return candidate.ToString(); }
        throw new InvalidOperationException("无法自动分配网段，请指定其他私有网段。");
    }
    var subnet = Ipv4Subnet.Parse(requested);
    if (used.Any(subnet.Overlaps)) throw new InvalidOperationException("该网段与账号现有网络重叠，请选择不重叠的网段。");
    return subnet.ToString();
}
