using System.Security.Cryptography;
using System.Text.RegularExpressions;
namespace EdgeVpn.ControlPlane;

public sealed record DownloadItem(string Name, string Kind, string Platform, string Version,
    long Size, string Sha256, string Url, DateTimeOffset PublishedAt);
public sealed class DownloadCatalog
{
    private readonly string directory;
    public DownloadItem[] Items { get; }
    public DownloadCatalog(IWebHostEnvironment environment, IConfiguration configuration)
    {
        directory = Path.GetFullPath(configuration["DownloadDirectory"] ?? Path.Combine(environment.ContentRootPath, "downloads"));
        Items = Directory.Exists(directory) ? Directory.GetFiles(directory, "edge-vpn-*.zip")
            .Select(Read).Where(x => x is not null).Cast<DownloadItem>()
            .GroupBy(x => (x.Kind, x.Platform)).Select(g => g.OrderByDescending(x => System.Version.Parse(x.Version)).First())
            .OrderBy(x => x.Kind).ThenBy(x => x.Platform).ToArray() : [];
    }
    private static DownloadItem? Read(string path)
    {
        var info = new FileInfo(path);
        var match = Regex.Match(info.Name, @"^edge-vpn-(client|control|relay|punch)-(win-x64|win-x86|linux-x64|linux-arm64|linux-arm)-(\d+\.\d+\.\d+)\.zip$");
        if (!match.Success || info.LinkTarget is not null) return null;
        using var stream = File.OpenRead(path);
        return new(info.Name, match.Groups[1].Value, match.Groups[2].Value, match.Groups[3].Value, info.Length,
            Convert.ToHexString(SHA256.HashData(stream)).ToLowerInvariant(),
            "/downloads/" + info.Name, info.LastWriteTimeUtc);
    }
    public string PathFor(DownloadItem item) => Path.Combine(directory, item.Name);
}
