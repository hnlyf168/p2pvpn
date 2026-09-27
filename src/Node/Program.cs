using EdgeVpn;
using EdgeVpn.Node;
var builder = WebApplication.CreateBuilder(args);
builder.WebHost.ConfigureKestrel(o => o.Limits.MaxRequestBodySize = 16384);
builder.Services.Configure<Microsoft.AspNetCore.Builder.ForwardedHeadersOptions>(o =>
{
    o.ForwardedHeaders = Microsoft.AspNetCore.HttpOverrides.ForwardedHeaders.XForwardedFor | Microsoft.AspNetCore.HttpOverrides.ForwardedHeaders.XForwardedProto;
    o.ForwardLimit = 1; // Only the framework default loopback proxies are trusted.
});
var role = builder.Configuration["Role"] ?? "punch";
if (role is not ("punch" or "relay")) throw new InvalidOperationException("Role must be punch or relay.");
string url = builder.Configuration["ControlUrl"] ?? throw new InvalidOperationException("ControlUrl is required.");
if (!Uri.TryCreate(url, UriKind.Absolute, out var uri) || (!uri.IsLoopback && uri.Scheme != "https"))
    throw new InvalidOperationException("ControlUrl requires HTTPS.");
string key = builder.Configuration["NodeKey"] ?? "";
if (key.Length < 32) throw new InvalidOperationException("NodeKey must be at least 32 characters.");
builder.Services.AddSingleton(new HttpClient { BaseAddress = new Uri(url.TrimEnd('/') + "/"), Timeout = TimeSpan.FromSeconds(5),
    DefaultRequestHeaders = { { "X-Node-Key", key } } });
if (role == "punch")
{
    builder.Services.AddSingleton<CoordinatorFleet>(sp => new CoordinatorFleet(async ct =>
        await sp.GetRequiredService<HttpClient>().GetFromJsonAsync<NodeSnapshot>("internal/punch/snapshot", ct)
            ?? throw new IOException("Empty snapshot"), sp.GetRequiredService<ILogger<CoordinatorFleet>>(), System.Net.IPAddress.Parse(builder.Configuration["Coordinator:ListenAddress"] ?? "0.0.0.0")));
    builder.Services.AddHostedService(sp => sp.GetRequiredService<CoordinatorFleet>());
}
else builder.Services.AddSingleton<RelayHub>();
builder.Services.AddHostedService<NodeHeartbeat>();
var app = builder.Build();
app.UseForwardedHeaders();
app.UseWebSockets(new WebSocketOptions { KeepAliveInterval = TimeSpan.FromSeconds(15) });
app.MapGet("/health", () => new { status = "ok", role, relayEnabled = role == "relay" });
if (role == "relay") app.Map("/relay", (HttpContext ctx, RelayHub hub) => hub.HandleAsync(ctx));
app.Run();
