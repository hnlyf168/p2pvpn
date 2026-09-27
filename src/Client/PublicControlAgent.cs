using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
namespace P2PVpnClient;

internal static class PublicControlAgent
{
    internal static string Fingerprint(ClientConfig c) => string.Join("|", c.AccessRevoked, c.Server, c.Group,
        c.SharedSecret, c.DeviceId, c.DeviceToken, c.DataSecret, string.Join(",", c.CoordinatorServers), string.Join(",", c.RelayUrls));
    private static Uri ValidateUrl(string url)
    {
        var uri = new Uri(url.TrimEnd('/') + "/");
        if (uri.Scheme != "https" && !(uri.Scheme == "http" && uri.IsLoopback))
            throw new InvalidOperationException("公网控制服务必须使用 HTTPS。");
        return uri;
    }
    internal static async Task<int> JoinAsync(string url)
    {
        if (File.Exists(ClientConfigStore.ConfigPath)) throw new InvalidOperationException("当前目录已有 client.json，请在新目录加入或先备份配置。");
        using var client = new HttpClient { BaseAddress = ValidateUrl(url), Timeout = TimeSpan.FromSeconds(20) };
        Console.Write("粘贴控制台生成的加入码："); string key = Console.ReadLine()?.Trim() ?? "";
        Console.Write("设备名称（直接回车使用本机名称）："); string name = Console.ReadLine()?.Trim() ?? "";
        if (string.IsNullOrWhiteSpace(name)) name = Environment.MachineName;
        string payload = JsonSerializer.Serialize(new Dictionary<string, string> { ["key"] = key, ["name"] = name }, ClientJsonContext.Default.DictionaryStringString);
        using var response = await client.PostAsync("api/enroll", new StringContent(payload, Encoding.UTF8, "application/json"));
        if (!response.IsSuccessStatusCode) throw new IOException(await response.Content.ReadAsStringAsync());
        var profile = JsonSerializer.Deserialize(await response.Content.ReadAsByteArrayAsync(), ClientJsonContext.Default.ClientConfig)
            ?? throw new IOException("服务端未返回配置。");
        ClientConfigStore.Save(profile);
        Console.WriteLine("已生成 client.json。Windows 可运行 install 安装服务，Linux 可运行安装脚本。");
        return 0;
    }
    internal static async Task RunAsync(CancellationToken ct)
    {
        using var client = new HttpClient { Timeout = TimeSpan.FromSeconds(10) };
        while (!ct.IsCancellationRequested)
        {
            try
            {
                var current = ClientConfigStore.Load();
                using var request = new HttpRequestMessage(HttpMethod.Get, new Uri(ValidateUrl(current.ControlUrl), "api/device/profile"));
                request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", current.DeviceToken);
                using var response = await client.SendAsync(request, ct);
                if (response.StatusCode is HttpStatusCode.Unauthorized or HttpStatusCode.Forbidden)
                {
                    if (!current.AccessRevoked) { current.AccessRevoked = true; ClientConfigStore.Save(current); }
                }
                else
                {
                    response.EnsureSuccessStatusCode();
                    var latest = JsonSerializer.Deserialize(await response.Content.ReadAsByteArrayAsync(ct), ClientJsonContext.Default.ClientConfig)
                        ?? throw new IOException("Empty profile");
                    var before = Fingerprint(current);
                    current.Server = latest.Server; current.Group = latest.Group; current.SharedSecret = latest.SharedSecret;
                    current.DeviceId = latest.DeviceId; current.DeviceToken = latest.DeviceToken; current.DataSecret = latest.DataSecret;
                    current.CoordinatorServers = latest.CoordinatorServers; current.RelayUrls = latest.RelayUrls; current.AccessRevoked = false;
                    if (Fingerprint(current) != before) ClientConfigStore.Save(current);
                }
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested) { return; }
            catch (Exception e) { ClientLog.Write("公网配置同步失败：" + e.Message); }
            await Task.Delay(TimeSpan.FromSeconds(15), ct);
        }
    }
}
