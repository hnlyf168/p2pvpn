using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using Android.Content;

namespace P2PVpnAndroid;

internal sealed record JoinLink(string Origin, string Ticket)
{
    public static JoinLink Parse(string value)
    {
        if (value.Length > 2048 || !Uri.TryCreate(value.Trim(), UriKind.Absolute, out var uri) ||
            uri.Scheme != "edgevpn" || uri.Host != "join" || uri.AbsolutePath is not ("" or "/"))
            throw new InvalidDataException("请粘贴控制台生成的完整安卓加入链接。");
        var query = uri.Query.TrimStart('?').Split('&', StringSplitOptions.RemoveEmptyEntries);
        if (query.Length != 1 || !query[0].StartsWith("server=", StringComparison.Ordinal))
            throw new InvalidDataException("加入链接不完整。");
        var origin = ControlApi.Origin(Uri.UnescapeDataString(query[0][7..]));
        var ticket = uri.Fragment.TrimStart('#');
        if (!Regex.IsMatch(ticket, @"\A[a-zA-Z0-9_-]{43}\z"))
            throw new InvalidDataException("加入凭据格式无效，请在控制台重新生成。");
        return new(origin, ticket);
    }
}

internal sealed class AccessRevokedException() : Exception("设备凭据已失效或被撤销，请回控制台重新添加设备。");

internal static class ControlApi
{
    // Never follow a redirect while carrying a ticket or a permanent device token.
    private static readonly HttpClient Http = new(new HttpClientHandler { AllowAutoRedirect = false })
        { Timeout = TimeSpan.FromSeconds(15), MaxResponseContentBufferSize = 65536 };

    public static string Origin(string value)
    {
        if (!Uri.TryCreate(value, UriKind.Absolute, out var uri) || uri.Scheme != "https" ||
            uri.UserInfo.Length != 0 || uri.Query.Length != 0 || uri.Fragment.Length != 0 ||
            uri.AbsolutePath != "/" || string.IsNullOrEmpty(uri.Host))
            throw new InvalidDataException("平台地址必须是 HTTPS 网站根地址。");
        return uri.GetLeftPart(UriPartial.Authority);
    }

    public static async Task<VpnProfile> RedeemAsync(Context context, JoinLink link, CancellationToken ct)
    {
        // Stable, bounded installation identity makes retries idempotent without persisting the ticket.
        var prefs = context.GetSharedPreferences("installation", FileCreationMode.Private)!;
        var hash = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(link.Origin + link.Ticket)));
        var claim = prefs.GetString("ticket-hash", "") == hash ? prefs.GetString("claim", null) : null;
        if (claim is null)
        {
            claim = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)).TrimEnd('=').Replace('+', '-').Replace('/', '_');
            if (!prefs.Edit()!.PutString("ticket-hash", hash)!.PutString("claim", claim)!.Commit())
                throw new IOException("无法保存安装身份，请检查手机可用空间。");
        }
        using var request = new HttpRequestMessage(HttpMethod.Post, link.Origin + "/api/install/redeem");
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", link.Ticket);
        request.Content = new StringContent(JsonSerializer.Serialize(new InstallClaim(claim, "android"),
            VpnJsonContext.Default.InstallClaim), Encoding.UTF8, "application/json");
        return await SendAsync(request, link.Origin, ct).ConfigureAwait(false);
    }

    public static async Task<VpnProfile> RefreshAsync(VpnProfile current, CancellationToken ct)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, Origin(current.ControlUrl) + "/api/device/profile");
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", current.DeviceToken);
        var next = await SendAsync(request, current.ControlUrl, ct).ConfigureAwait(false);
        if (next.DeviceId != current.DeviceId || next.DeviceToken != current.DeviceToken)
            throw new InvalidDataException("平台返回了不匹配的设备身份。");
        next.Routes = current.Routes;
        next.LocalPort = current.LocalPort;
        next.DirectIdleMinutes = current.DirectIdleMinutes;
        return next;
    }

    private static async Task<VpnProfile> SendAsync(HttpRequestMessage request, string origin, CancellationToken ct)
    {
        using var response = await Http.SendAsync(request, ct).ConfigureAwait(false);
        if (response.StatusCode is HttpStatusCode.Unauthorized or HttpStatusCode.Forbidden)
            throw new AccessRevokedException();
        if (!response.IsSuccessStatusCode)
            throw new HttpRequestException($"平台请求失败（{(int)response.StatusCode}），请检查网络或重新生成加入链接。");
        var profile = JsonSerializer.Deserialize(await response.Content.ReadAsByteArrayAsync(ct).ConfigureAwait(false),
            VpnJsonContext.Default.VpnProfile) ?? throw new InvalidDataException("平台没有返回设备配置。");
        if (Origin(profile.ControlUrl) != Origin(origin))
            throw new InvalidDataException("平台返回的认证地址与加入链接不一致。");
        ProfileStore.Validate(profile);
        return profile;
    }

    public static string Fingerprint(VpnProfile profile) => Convert.ToHexString(SHA256.HashData(
        JsonSerializer.SerializeToUtf8Bytes(profile, VpnJsonContext.Default.VpnProfile)));
}

internal sealed record InstallClaim(string Claim, string Platform);
