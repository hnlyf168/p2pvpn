using EdgeVpn;
namespace EdgeVpn.Node;

public sealed class NodeHeartbeat(HttpClient control, IConfiguration config, ILogger<NodeHeartbeat> logger, IServiceProvider services) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken ct)
    {
        string id = config["NodeId"] ?? "";
        if (id.Length == 0) return; // Compatibility for operator-managed static credentials.
        while (!ct.IsCancellationRequested)
        {
            try
            {
                using var response = await control.PostAsJsonAsync("internal/node/heartbeat",
                    new NodeHeartbeatRequest(id, config["Role"] ?? "punch", "0.3.0",
                        config["Role"] == "relay" ? services.GetRequiredService<RelayHub>().OnlineDeviceIds :
                        services.GetRequiredService<CoordinatorFleet>().Clients.Select(c => c.PeerId).Distinct().ToArray()), ct);
                if (!response.IsSuccessStatusCode) logger.LogWarning("Node heartbeat rejected: {Status}", (int)response.StatusCode);
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested) { return; }
            catch (Exception e) { logger.LogWarning("Node heartbeat unavailable: {Type}", e.GetType().Name); }
            await Task.Delay(TimeSpan.FromSeconds(15), ct);
        }
    }
}
