using System.Diagnostics;
using System.IO.Compression;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Qcxt.Net.P2P;

namespace P2PVpnClient;

/// <summary>
/// 表示 Client Update Manifest，并提供相关数据或行为。
/// </summary>
/// <param name="Available">Available参数。</param>
/// <param name="ForceUpdate">Force Update参数。</param>
/// <param name="Platform">Platform参数。</param>
/// <param name="Version">Version参数。</param>
/// <param name="Size">Size参数。</param>
/// <param name="Sha256">Sha256参数。</param>
/// <param name="DownloadUrl">Download Url参数。</param>
/// <param name="Signature">Signature参数。</param>
internal sealed record ClientUpdateManifest(bool Available, bool ForceUpdate, string Platform,
    string Version, long Size, string Sha256, string DownloadUrl, string Signature);
/// <summary>
/// 表示 Client Traversal Report，并提供相关数据或行为。
/// </summary>
/// <param name="ClientId">Client Id参数。</param>
/// <param name="PeerId">Peer Id参数。</param>
/// <param name="Kind">Kind参数。</param>
/// <param name="Transport">Transport参数。</param>
/// <param name="Succeeded">Succeeded参数。</param>
/// <param name="AttemptNumber">Attempt Number参数。</param>
/// <param name="Detail">Detail参数。</param>
/// <param name="Timestamp">Timestamp参数。</param>
internal sealed record ClientTraversalReport(string ClientId, string PeerId, string Kind,
    string Transport, bool Succeeded, int AttemptNumber, string Detail, DateTimeOffset Timestamp);

/// <summary>
/// 表示 Client Management Json Context，并提供相关数据或行为。
/// </summary>
[JsonSourceGenerationOptions(PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase,
    PropertyNameCaseInsensitive = true, WriteIndented = false)]
[JsonSerializable(typeof(ClientUpdateManifest))]
[JsonSerializable(typeof(ClientTraversalReport))]
internal sealed partial class ClientManagementJsonContext : JsonSerializerContext;

/// <summary>
/// 表示 Client Management Agent，并提供相关数据或行为。
/// </summary>
internal sealed class ClientManagementAgent : IAsyncDisposable
{
    internal long AppliedPolicyRevision;
    internal string PolicyError = "";
    private string _syncError = "";
    private readonly ClientConfig _config;
    private readonly string _clientId;
    private readonly string _platform;
    private readonly HttpClient _http = new(new SocketsHttpHandler
    {
        PooledConnectionLifetime = TimeSpan.FromMinutes(2),
        PooledConnectionIdleTimeout = TimeSpan.FromMinutes(1),
        ConnectTimeout = TimeSpan.FromSeconds(15)
    }) { Timeout = TimeSpan.FromMinutes(5) };
    private int _updating;
    private readonly SemaphoreSlim _policyWake = new(0, 1);
    internal void MarkPolicyApplied(long revision)
    {
        Interlocked.Exchange(ref AppliedPolicyRevision, revision);
        PolicyError = "";
        try { _policyWake.Release(); } catch (SemaphoreFullException) { }
    }

    /// <summary>
    /// 初始化 <see cref="ClientManagementAgent"/> 类的新实例。
    /// </summary>
    /// <param name="config">config参数。</param>
    /// <param name="clientId">client Id参数。</param>
    public ClientManagementAgent(ClientConfig config, string clientId)
    {
        _config = config;
        _clientId = clientId;
        _platform = string.IsNullOrWhiteSpace(config.Platform) ? ClientRuntimeInfo.Platform : config.Platform;
    }

    /// <summary>
    /// 执行Run操作。
    /// </summary>
    /// <param name="cancellationToken">用于取消异步操作的令牌。</param>
    /// <returns>操作结果。</returns>
    public async Task RunAsync(CancellationToken cancellationToken)
    {
        if (!string.IsNullOrEmpty(_config.ControlUrl)) { await PublicControlAgent.RunAsync(cancellationToken); return; }
        if (string.IsNullOrWhiteSpace(_config.ManagementUrl)) return;
        await Task.WhenAll(PolicyLoopAsync(cancellationToken), UpdateLoopAsync(cancellationToken));
    }
    private async Task PolicyLoopAsync(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            await SyncPolicyAsync(ct);
            await _policyWake.WaitAsync(TimeSpan.FromSeconds(5), ct);
        }
    }
    private async Task UpdateLoopAsync(CancellationToken ct)
    {
        using var timer = new PeriodicTimer(TimeSpan.FromMinutes(15));
        do { await TryCheckForUpdateAsync(ct); } while (await timer.WaitForNextTickAsync(ct));
    }

    private async Task SyncPolicyAsync(CancellationToken ct)
    {
        if (!Uri.TryCreate(_config.ManagementUrl, UriKind.Absolute, out var url) || url.Scheme != "https") return;
        try
        {
            ClientConfig current = ClientConfigStore.Load();
            var veth = await VethSupport.GetAsync();
            string tokenPath = Path.Combine(ClientConfigStore.DirectoryPath, "network-policy-token");
            if (!File.Exists(tokenPath)) { ClientConfigStore.ProtectDirectory(); using var file = new FileStream(tokenPath, FileMode.CreateNew, FileAccess.Write, FileShare.None); file.Write(Encoding.ASCII.GetBytes(Convert.ToHexString(RandomNumberGenerator.GetBytes(32)))); if (OperatingSystem.IsLinux()) File.SetUnixFileMode(tokenPath, UnixFileMode.UserRead | UnixFileMode.UserWrite); }
            var report = new P2PVpn.Policy.PolicyReport { ClientId = _clientId, Version = ClientRuntimeInfo.Version, Platform = _platform,
                SupportedModes = OperatingSystem.IsLinux() ? ["tun", "veth", "proxy"] : ["tun", "proxy"], VethAvailable = veth.Available, VethError = veth.Error,
                TunAvailable = OperatingSystem.IsWindows() || File.Exists("/dev/net/tun"), AppliedRevision = Interlocked.Read(ref AppliedPolicyRevision),
                ApplyError = string.IsNullOrEmpty(PolicyError) ? _syncError : PolicyError, Reported = ClientNetworkPolicy.FromConfig(current), NetworkInterfaces = LanInterfaceCollector.Collect() };
            byte[] body = JsonSerializer.SerializeToUtf8Bytes(report, P2PVpn.Policy.PolicyJson.Default.PolicyReport);
            using var req = CreateRequest(HttpMethod.Post, "/api/vpn/network-policy/sync?sha256=" + Convert.ToHexString(SHA256.HashData(body)));
            req.Headers.TryAddWithoutValidation("X-P2P-Policy-Token", File.ReadAllText(tokenPath));
            req.Content = new ByteArrayContent(body); req.Content.Headers.ContentType = new("application/json");
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct); timeout.CancelAfter(TimeSpan.FromSeconds(15));
            using var res = await _http.SendAsync(req, timeout.Token);
            if (res.StatusCode == System.Net.HttpStatusCode.NotFound) return;
            res.EnsureSuccessStatusCode();
            var entry = await res.Content.ReadFromJsonAsync(P2PVpn.Policy.PolicyJson.Default.PolicyEntry, timeout.Token);
            _syncError = "";
            if (entry?.Desired is null || entry.Revision < current.NetworkPolicyRevision) return;
            if (entry.Revision == current.NetworkPolicyRevision && JsonSerializer.Serialize(entry.Desired, P2PVpn.Policy.PolicyJson.Default.NetworkPolicy) == ClientNetworkPolicy.Fingerprint(current)) return;
            if (entry.Desired.NetworkMode == "tun" && !report.TunAvailable) throw new InvalidOperationException("服务端要求 TUN，但本机没有 TUN 设备，保留现有配置。");
            if (entry.Desired.NetworkMode == "veth" && !veth.Available) throw new InvalidOperationException("本机无法使用 veth：" + veth.Error);
            ClientNetworkPolicy.Apply(current, entry.Desired, entry.Revision); ClientConfigStore.Save(current);
            PolicyError = ""; ClientLog.Write($"收到网络配置版本 {entry.Revision}，正在切换。");
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
        catch (Exception ex) { _syncError = ex.Message.Length > 1000 ? ex.Message[..1000] : ex.Message; ClientLog.Write("网络配置同步失败：" + _syncError); }
    }

    /// <summary>
    /// 尝试Check For Update。
    /// </summary>
    /// <param name="cancellationToken">用于取消异步操作的令牌。</param>
    /// <returns>操作是否成功。</returns>
    private async Task TryCheckForUpdateAsync(CancellationToken cancellationToken)
    {
        try { await CheckForUpdateAsync(cancellationToken).ConfigureAwait(false); }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
        catch (Exception exception) { ClientLog.Write("客户端自动更新检查异常：" + exception.Message); }
    }

    /// <summary>
    /// 执行Report操作。
    /// </summary>
    /// <param name="value">待处理的值。</param>
    public void Report(P2PTraversalEvent value)
    {
        if (!string.IsNullOrEmpty(_config.ControlUrl)) return;
        if (string.IsNullOrWhiteSpace(_config.ManagementUrl)) return;
        bool relevant = value.Kind is P2PTraversalEventKind.QuicDirectSucceeded or
            P2PTraversalEventKind.TcpDirectSucceeded or P2PTraversalEventKind.AttemptsExhausted or
            P2PTraversalEventKind.DirectDisconnected;
        if (!relevant) return;
        bool succeeded = value.Kind is P2PTraversalEventKind.QuicDirectSucceeded or
            P2PTraversalEventKind.TcpDirectSucceeded;
        var report = new ClientTraversalReport(_clientId, value.PeerId, value.Kind.ToString(),
            value.Transport.ToString(), succeeded, value.AttemptNumber, value.Detail ?? "", DateTimeOffset.UtcNow);
        _ = Task.Run(async () =>
        {
            try
            {
                byte[] payload = JsonSerializer.SerializeToUtf8Bytes(report,
                    ClientManagementJsonContext.Default.ClientTraversalReport);
                using var request = CreateRequest(HttpMethod.Post, "/api/vpn/traversal-report");
                request.Content = new ByteArrayContent(payload);
                request.Content.Headers.ContentType = new("application/json");
                using HttpResponseMessage response = await _http.SendAsync(request).ConfigureAwait(false);
                if (!response.IsSuccessStatusCode) ClientLog.Write($"打洞结果上报失败：HTTP {(int)response.StatusCode}");
            }
            catch (Exception exception) { ClientLog.Write("打洞结果上报异常：" + exception.Message); }
        });
    }

    /// <summary>
    /// 执行Check For Update操作。
    /// </summary>
    /// <param name="cancellationToken">用于取消异步操作的令牌。</param>
    /// <returns>操作结果。</returns>
    private async Task CheckForUpdateAsync(CancellationToken cancellationToken)
    {
        string query = $"?platform={Uri.EscapeDataString(_platform)}&version={Uri.EscapeDataString(ClientRuntimeInfo.Version)}";
        using var request = CreateRequest(HttpMethod.Get, "/api/vpn/client-update" + query);
        using HttpResponseMessage response = await _http.SendAsync(request, cancellationToken).ConfigureAwait(false);
        if (!response.IsSuccessStatusCode)
        {
            ClientLog.Write($"客户端更新检查失败：HTTP {(int)response.StatusCode}");
            return;
        }
        ClientUpdateManifest? manifest = await response.Content.ReadFromJsonAsync(
            ClientManagementJsonContext.Default.ClientUpdateManifest, cancellationToken).ConfigureAwait(false);
        if (manifest is null || !manifest.Available || !manifest.ForceUpdate || !_config.EnableAutoUpdate) return;
        if (!ValidateManifest(manifest)) throw new InvalidDataException("服务端更新清单签名无效。");
        if (Interlocked.Exchange(ref _updating, 1) != 0) return;
        ClientLog.Write($"发现强制更新 {_platform} {ClientRuntimeInfo.Version} -> {manifest.Version}，开始下载。");
        await DownloadAndInstallAsync(manifest, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// 执行Validate Manifest操作。
    /// </summary>
    /// <param name="manifest">manifest参数。</param>
    /// <returns>操作结果。</returns>
    private bool ValidateManifest(ClientUpdateManifest manifest)
    {
        string value = $"{manifest.Platform}\n{manifest.Version}\n{manifest.ForceUpdate}\n{manifest.Sha256}\n{manifest.Size}";
        byte[] expected = HMACSHA256.HashData(Encoding.UTF8.GetBytes(_config.SharedSecret), Encoding.UTF8.GetBytes(value));
        try
        {
            byte[] actual = Convert.FromHexString(manifest.Signature);
            return actual.Length == expected.Length && CryptographicOperations.FixedTimeEquals(actual, expected);
        }
        catch { return false; }
    }

    /// <summary>
    /// 执行Download And Install操作。
    /// </summary>
    /// <param name="manifest">manifest参数。</param>
    /// <param name="cancellationToken">用于取消异步操作的令牌。</param>
    /// <returns>操作结果。</returns>
    private async Task DownloadAndInstallAsync(ClientUpdateManifest manifest, CancellationToken cancellationToken)
    {
        string root = Path.Combine(Path.GetTempPath(), "edge-vpn-update-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        string archive = Path.Combine(root, "package.zip");
        using (var request = CreateAbsoluteRequest(HttpMethod.Get, manifest.DownloadUrl))
        using (HttpResponseMessage response = await _http.SendAsync(request,
            HttpCompletionOption.ResponseHeadersRead, cancellationToken).ConfigureAwait(false))
        {
            response.EnsureSuccessStatusCode();
            await using Stream input = await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
            await using FileStream output = new(archive, FileMode.CreateNew, FileAccess.Write,
                FileShare.None, 65536, FileOptions.Asynchronous);
            await input.CopyToAsync(output, cancellationToken).ConfigureAwait(false);
        }
        await using (FileStream stream = File.OpenRead(archive))
        {
            string sha = Convert.ToHexString(await SHA256.HashDataAsync(stream, cancellationToken)).ToLowerInvariant();
            if (!string.Equals(sha, manifest.Sha256, StringComparison.OrdinalIgnoreCase))
                throw new InvalidDataException("客户端更新包 SHA256 校验失败。");
        }
        string extracted = Path.Combine(root, "payload");
        Directory.CreateDirectory(extracted);
        using (ZipArchive zip = ZipFile.OpenRead(archive))
        {
            foreach (ZipArchiveEntry entry in zip.Entries)
            {
                string target = Path.GetFullPath(Path.Combine(extracted, entry.FullName));
                if (!target.StartsWith(Path.GetFullPath(extracted) + Path.DirectorySeparatorChar,
                    StringComparison.Ordinal)) throw new InvalidDataException("更新包包含越界路径。");
                if (entry.Name.Length == 0) { Directory.CreateDirectory(target); continue; }
                Directory.CreateDirectory(Path.GetDirectoryName(target)!);
                entry.ExtractToFile(target, true);
            }
        }
        string packageConfig = Path.Combine(extracted, "client.json");
        if (File.Exists(packageConfig)) File.Delete(packageConfig);
        if (OperatingSystem.IsLinux())
            ApplyLinuxUpdate(extracted);
        else
            StartUpdater(extracted, root);
        ClientLog.Write("强制更新已下载并校验，客户端即将重启。");
        if (OperatingSystem.IsWindows()) WindowsServiceHost.RequestStop();
        else Environment.Exit(20);
    }

    /// <summary>
    /// 执行Apply Linux Update操作。
    /// </summary>
    /// <param name="payload">payload参数。</param>
    private static void ApplyLinuxUpdate(string payload)
    {
        string destination = ClientConfigStore.ExecutableDirectory;
        string payloadRoot = Path.GetFullPath(payload) + Path.DirectorySeparatorChar;
        string destinationRoot = Path.GetFullPath(destination) + Path.DirectorySeparatorChar;
        string[] files = Directory.GetFiles(payload, "*", SearchOption.AllDirectories)
            .OrderBy(static path => Path.GetFileName(path) == "P2PVpnClient" ? 1 : 0)
            .ToArray();
        foreach (string source in files)
        {
            string relative = Path.GetRelativePath(payload, source);
            string target = Path.GetFullPath(Path.Combine(destination, relative));
            if (!Path.GetFullPath(source).StartsWith(payloadRoot, StringComparison.Ordinal) ||
                !target.StartsWith(destinationRoot, StringComparison.Ordinal))
                throw new InvalidDataException("Linux update package contains an invalid path.");
            Directory.CreateDirectory(Path.GetDirectoryName(target)!);
            string temporary = target + ".update-" + Guid.NewGuid().ToString("N");
            try
            {
                File.Copy(source, temporary, true);
                if (OperatingSystem.IsLinux() && Path.GetFileName(target) == "P2PVpnClient")
                    File.SetUnixFileMode(temporary, UnixFileMode.UserRead | UnixFileMode.UserWrite |
                        UnixFileMode.UserExecute | UnixFileMode.GroupRead | UnixFileMode.GroupExecute |
                        UnixFileMode.OtherRead | UnixFileMode.OtherExecute);
                File.Move(temporary, target, true);
            }
            finally
            {
                try { File.Delete(temporary); } catch { }
            }
        }
    }

    /// <summary>
    /// 执行Start Updater操作。
    /// </summary>
    /// <param name="payload">payload参数。</param>
    /// <param name="root">root参数。</param>
    private void StartUpdater(string payload, string root)
    {
        string destination = ClientConfigStore.ExecutableDirectory;
        if (OperatingSystem.IsWindows())
        {
            string script = Path.Combine(root, "update.cmd");
            File.WriteAllText(script, $"@echo off\r\ntimeout /t 3 /nobreak >nul\r\nsc stop P2PVpnClient >nul 2>&1\r\ntimeout /t 10 /nobreak >nul\r\ntaskkill /F /PID {Environment.ProcessId} >nul 2>&1\r\nset COPY_OK=\r\nfor /L %%I in (1,1,30) do (\r\n  sc stop P2PVpnClient >nul 2>&1\r\n  xcopy /E /I /Y \"{payload}\\*\" \"{destination}\\\" >nul 2>&1 && set COPY_OK=1 && goto copied\r\n  timeout /t 1 /nobreak >nul\r\n)\r\n:copied\r\nif not defined COPY_OK exit /b 1\r\nsc start P2PVpnClient >nul 2>&1\r\ntimeout /t 2 /nobreak >nul\r\nrmdir /S /Q \"{root}\"\r\n");
            Process.Start(new ProcessStartInfo("cmd.exe", $"/c \"{script}\"")
                { UseShellExecute = false, CreateNoWindow = true });
        }
        else
        {
            string script = Path.Combine(root, "update.sh");
            File.WriteAllText(script, $"#!/bin/sh\nsleep 2\ncp -Rf '{EscapeShell(payload)}/.' '{EscapeShell(destination)}/'\nchmod 755 '{EscapeShell(destination)}/P2PVpnClient'\n(systemctl restart edge-vpn.service || /etc/init.d/edge-vpn restart) >/dev/null 2>&1\nrm -rf '{EscapeShell(root)}'\n");
            Process.Start(new ProcessStartInfo("/bin/sh", script) { UseShellExecute = false });
        }
    }

    /// <summary>
    /// 创建Request。
    /// </summary>
    /// <param name="method">method参数。</param>
    /// <param name="pathAndQuery">path And Query参数。</param>
    /// <returns>操作结果。</returns>
    private HttpRequestMessage CreateRequest(HttpMethod method, string pathAndQuery) =>
        CreateAbsoluteRequest(method, _config.ManagementUrl.TrimEnd('/') + pathAndQuery);

    /// <summary>
    /// 创建Absolute Request。
    /// </summary>
    /// <param name="method">method参数。</param>
    /// <param name="url">url参数。</param>
    /// <returns>操作结果。</returns>
    private HttpRequestMessage CreateAbsoluteRequest(HttpMethod method, string url)
    {
        var request = new HttpRequestMessage(method, url);
        Uri uri = request.RequestUri!;
        string timestamp = DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString();
        string canonical = $"{method.Method}\n{uri.AbsolutePath}\n{uri.Query}\n{_clientId}\n{timestamp}";
        string signature = Convert.ToHexString(HMACSHA256.HashData(Encoding.UTF8.GetBytes(_config.SharedSecret),
            Encoding.UTF8.GetBytes(canonical))).ToLowerInvariant();
        request.Headers.TryAddWithoutValidation("X-P2P-Client", _clientId);
        request.Headers.TryAddWithoutValidation("X-P2P-Timestamp", timestamp);
        request.Headers.TryAddWithoutValidation("X-P2P-Signature", signature);
        return request;
    }

    /// <summary>
    /// 执行Escape Shell操作。
    /// </summary>
    /// <param name="value">待处理的值。</param>
    /// <returns>操作结果。</returns>
    private static string EscapeShell(string value) => value.Replace("'", "'\\''", StringComparison.Ordinal);
    /// <summary>
    /// 执行Dispose操作。
    /// </summary>
    /// <returns>操作结果。</returns>
    public ValueTask DisposeAsync() { _http.Dispose(); return ValueTask.CompletedTask; }
}
