using EdgeVpn.ControlPlane;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging.Abstractions;

var root = Path.Combine(Path.GetTempPath(), "edge-vpn-traffic-test-" + Guid.NewGuid().ToString("N"));
Directory.CreateDirectory(root);
try
{
    var builder = Host.CreateApplicationBuilder();
    builder.Configuration["DataDirectory"] = root;
    TrafficStatistics Open() => new(builder.Configuration, builder.Environment, NullLogger<TrafficStatistics>.Instance);
    var beforeMidnight = DateTimeOffset.Parse("2026-09-26T15:59:59Z");
    var afterMidnight = beforeMidnight.AddSeconds(1);
    Check(TrafficStatistics.DayAt(beforeMidnight) == new DateOnly(2026, 9, 26), "UTC+8 before midnight");
    Check(TrafficStatistics.DayAt(afterMidnight) == new DateOnly(2026, 9, 27), "UTC+8 day boundary");
    string? Classify(string method, string path, int status, string range = "", bool known = false, string type = "text/html")
        => TrafficStatistics.Classify(method, path, status, type, range, known);
    Check(Classify("GET", "/", 200) == "page", "homepage counted");
    foreach (var path in new[] { "/ops", "/console", "/api/me", "/admin/traffic", "/health", "/site.css", "/unknown" })
        Check(Classify("GET", path, 200) is null, "non-page excluded: " + path);
    Check(Classify("GET", "/downloads", 200) == "page", "download center is a page");
    Check(Classify("GET", "/install.sh", 200) == "script", "script separate from package");
    const string package = "/downloads/edge-vpn-client-linux-arm64-0.3.3.zip";
    Check(Classify("GET", package, 200, known:true) == "download", "full package response counted");
    Check(Classify("GET", package, 206, "bytes=0-99", true) == "download", "first range counted");
    foreach (var range in new[] { "bytes=100-", "bytes=-100", "bytes=0-99,200-299", "broken" })
        Check(Classify("GET", package, 206, range, true) is null, "continuation/multipart range excluded");
    foreach (var status in new[] { 304, 404, 416, 500 })
        Check(Classify("GET", package, status, known:true) is null, "unsuccessful response excluded");
    Check(Classify("HEAD", package, 200, known:true) is null && Classify("GET", package, 200) is null, "HEAD and unknown packages excluded");
    using (var stats = Open())
    {
        stats.Record("page", "/", beforeMidnight);
        Parallel.For(0, 500, _ => stats.Record("page", "/", afterMidnight));
        stats.Record("download", package, afterMidnight);
        stats.Record("script", "/install.sh", afterMidnight);
        var report = stats.Report(7, afterMidnight);
        Check(report.Daily.Length == 7 && report.Daily[0].PageViews == 0, "missing days filled with zero");
        Check(report.Today.PageViews == 500 && report.Yesterday.PageViews == 1 && report.Totals.PageViews == 501, "concurrent updates and daily totals");
        Check(report.Today.Downloads == 1 && report.Today.ScriptRequests == 1 && report.Packages.Single().Count == 1, "package and script totals separated");
        bool rejected = false; try { stats.Report(365000, afterMidnight); } catch (ArgumentException) { rejected = true; }
        Check(rejected, "unbounded date ranges rejected");
        await stats.StopAsync(CancellationToken.None);
    }
    using (var stats = Open())
    {
        Check(stats.Report(7, afterMidnight).Today.PageViews == 500, "counts survive restart");
        stats.Record("page", "/", afterMidnight.AddDays(TrafficStatistics.RetentionDays));
        await stats.StopAsync(CancellationToken.None);
    }
    var text = File.ReadAllText(Path.Combine(root, "traffic-statistics.json"));
    Check(!text.Contains("2026-09-26\"") && !text.Contains("2026-09-27\""), "expired daily buckets pruned");
    File.WriteAllText(Path.Combine(root, "traffic-statistics.json"), "corrupt historical file");
    using (var stats = Open())
    {
        Check(!stats.Report(7, afterMidnight).PersistenceHealthy, "corrupt history reported as degraded");
        stats.Record("page", "/", afterMidnight);
        await stats.StopAsync(CancellationToken.None);
    }
    Check(File.ReadAllText(Path.Combine(root, "traffic-statistics.json")) == "corrupt historical file", "corrupt history preserved without blocking service");
}
finally { Directory.Delete(root, true); }
static void Check(bool value, string name) { if (!value) throw new Exception("FAIL: " + name); Console.WriteLine("PASS: " + name); }
