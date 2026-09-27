using System.Text.Json;
using Microsoft.Net.Http.Headers;

namespace EdgeVpn.ControlPlane;

// Aggregates only: never persist addresses, cookies, query strings or install tickets.
public sealed class TrafficStatistics : BackgroundService
{
    public const int RetentionDays = 400;
    private static readonly TimeSpan Offset = TimeSpan.FromHours(8);
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);
    private static readonly HashSet<string> Pages = new(StringComparer.OrdinalIgnoreCase)
    {
        "/", "/index.html", "/login", "/register", "/recover", "/downloads", "/guide",
        "/features", "/network", "/scenarios", "/pricing", "/faq", "/auth.html",
        "/downloads.html", "/guide.html", "/features.html", "/network.html", "/scenarios.html", "/pricing.html", "/faq.html"
    };
    private static readonly HashSet<string> Scripts = new(StringComparer.OrdinalIgnoreCase)
        { "/install.sh", "/install.ps1", "/install.cmd" };
    private readonly object sync = new();
    private readonly string path;
    private readonly ILogger<TrafficStatistics> logger;
    private TrafficDocument document;
    private bool dirty, canSave = true, persistenceHealthy = true;

    public TrafficStatistics(IConfiguration config, IHostEnvironment environment, ILogger<TrafficStatistics> logger)
    {
        this.logger = logger;
        var directory = Path.GetFullPath(config["DataDirectory"] ?? Path.Combine(environment.ContentRootPath, "data"));
        Directory.CreateDirectory(directory);
        path = Path.Combine(directory, "traffic-statistics.json");
        document = new() { StartedAt = DateTimeOffset.UtcNow };
        try
        {
            if (File.Exists(path))
            {
                var saved = JsonSerializer.Deserialize<TrafficDocument>(File.ReadAllText(path), Json)
                    ?? throw new InvalidDataException("Empty traffic statistics");
                if (saved.SchemaVersion != 1 || saved.Days is null || saved.Days.Values.Any(d => d.Downloads is null || d.PageViews < 0 || d.ScriptRequests < 0 || d.Downloads.Values.Any(n => n < 0)))
                    throw new InvalidDataException("Unsupported traffic statistics");
                document = saved;
            }
            else { dirty = true; Flush(); }
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException or JsonException or InvalidDataException)
        {
            // Keep the original file intact and keep authentication/coordination available.
            canSave = false; persistenceHealthy = false;
            logger.LogError(e, "Cannot load traffic statistics; historical file preserved, counting in memory only.");
        }
    }

    public static DateOnly DayAt(DateTimeOffset at) => DateOnly.FromDateTime(at.ToOffset(Offset).DateTime);

    public static string? Classify(string method, string path, int status, string? contentType, string range, bool knownDownload)
    {
        if (method != "GET") return null;
        if (status == 200 && Pages.Contains(path) && contentType?.StartsWith("text/html", StringComparison.OrdinalIgnoreCase) == true)
            return "page";
        if (status == 200 && Scripts.Contains(path)) return "script";
        if (!knownDownload) return null;
        if (status == 200) return "download";
        if (status == 206 && RangeHeaderValue.TryParse(range, out var parsed) && parsed.Unit == "bytes" &&
            parsed.Ranges.Count == 1 && parsed.Ranges.Single().From == 0) return "download";
        return null;
    }

    public void Record(string kind, string path, DateTimeOffset at)
    {
        lock (sync)
        {
            var date = DayAt(at);
            if (!document.Days.TryGetValue(date, out var day)) document.Days[date] = day = new();
            if (kind == "page") day.PageViews++;
            else if (kind == "script") day.ScriptRequests++;
            else if (kind == "download")
            {
                var file = path["/downloads/".Length..];
                day.Downloads[file] = day.Downloads.GetValueOrDefault(file) + 1;
            }
            else throw new ArgumentException("Unknown traffic kind");
            foreach (var old in document.Days.Keys.Where(d => d < date.AddDays(1 - RetentionDays)).ToArray()) document.Days.Remove(old);
            dirty = true;
        }
    }

    public TrafficReport Report(int days, DateTimeOffset now)
    {
        if (days is not (7 or 30 or 90)) throw new ArgumentException("统计范围支持近 7、30 或 90 天。");
        lock (sync)
        {
            var today = DayAt(now);
            TrafficDaily Row(DateOnly date)
            {
                document.Days.TryGetValue(date, out var d);
                return new(date, d?.PageViews ?? 0, d?.Downloads.Values.Sum() ?? 0, d?.ScriptRequests ?? 0);
            }
            var daily = Enumerable.Range(0, days).Select(i => Row(today.AddDays(i + 1 - days))).ToArray();
            var packages = document.Days.Where(d => d.Key >= daily[0].Date && d.Key <= today)
                .SelectMany(d => d.Value.Downloads).GroupBy(d => d.Key)
                .Select(g => new TrafficPackage(g.Key, g.Sum(d => d.Value)))
                .OrderByDescending(d => d.Count).ThenBy(d => d.File).ToArray();
            return new("Asia/Shanghai", now, document.StartedAt, document.HistoryImported, document.LastSavedAt,
                persistenceHealthy, RetentionDays, Row(today), Row(today.AddDays(-1)),
                new(daily.Sum(d => d.PageViews), daily.Sum(d => d.Downloads), daily.Sum(d => d.ScriptRequests)), daily, packages);
        }
    }

    private void Flush()
    {
        lock (sync)
        {
            if (!dirty || !canSave) return;
            var previous = document.LastSavedAt;
            try
            {
                document.LastSavedAt = DateTimeOffset.UtcNow;
                var temporary = path + ".tmp";
                using (var stream = new FileStream(temporary, FileMode.Create, FileAccess.Write, FileShare.None, 4096, FileOptions.WriteThrough))
                { JsonSerializer.Serialize(stream, document, Json); stream.Flush(true); }
                if (!OperatingSystem.IsWindows()) File.SetUnixFileMode(temporary, UnixFileMode.UserRead | UnixFileMode.UserWrite);
                File.Move(temporary, path, true);
                dirty = false; persistenceHealthy = true;
            }
            catch (Exception e) when (e is IOException or UnauthorizedAccessException)
            {
                document.LastSavedAt = previous;
                if (persistenceHealthy) logger.LogError(e, "Cannot persist traffic statistics; will retry.");
                persistenceHealthy = false;
            }
        }
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        using var timer = new PeriodicTimer(TimeSpan.FromSeconds(10));
        try { while (await timer.WaitForNextTickAsync(stoppingToken)) Flush(); }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested) { }
        finally { Flush(); }
    }
    public override async Task StopAsync(CancellationToken cancellationToken)
    {
        await base.StopAsync(cancellationToken);
        Flush();
    }
}

public sealed class TrafficDocument
{
    public int SchemaVersion { get; set; } = 1;
    public DateTimeOffset StartedAt { get; set; }
    public bool HistoryImported { get; set; }
    public DateTimeOffset? LastSavedAt { get; set; }
    public Dictionary<DateOnly, TrafficDay> Days { get; set; } = new();
}
public sealed class TrafficDay
{
    public long PageViews { get; set; }
    public long ScriptRequests { get; set; }
    public Dictionary<string, long> Downloads { get; set; } = new(StringComparer.Ordinal);
}
public sealed record TrafficDaily(DateOnly Date, long PageViews, long Downloads, long ScriptRequests);
public sealed record TrafficTotals(long PageViews, long Downloads, long ScriptRequests);
public sealed record TrafficPackage(string File, long Count);
public sealed record TrafficReport(string TimeZone, DateTimeOffset GeneratedAt, DateTimeOffset StartedAt,
    bool HistoryImported, DateTimeOffset? LastSavedAt, bool PersistenceHealthy, int RetentionDays,
    TrafficDaily Today, TrafficDaily Yesterday, TrafficTotals Totals, TrafficDaily[] Daily, TrafficPackage[] Packages);
