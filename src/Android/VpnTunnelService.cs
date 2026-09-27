using Android.App;
using Android.Content;
using Android.Content.PM;
using Android.Net;
using Android.OS;

namespace P2PVpnAndroid;

[Service(Name = "pub.hngs.vpn.VpnTunnelService", Permission = "android.permission.BIND_VPN_SERVICE",
    Exported = true, ForegroundServiceType = ForegroundService.TypeSpecialUse)]
[IntentFilter([Android.Net.VpnService.ServiceInterface])]
[MetaData("android.app.PROPERTY_SPECIAL_USE_FGS_SUBTYPE", Value = "Encrypted P2P VPN tunnel")]
public sealed class VpnTunnelService : Android.Net.VpnService
{
    public const string ActionConnect = "pub.hngs.vpn.CONNECT";
    public const string ActionDisconnect = "pub.hngs.vpn.DISCONNECT";
    private const int NotificationId = 77;
    private CancellationTokenSource? _lifetime;
    private Task? _worker;

    public override void OnCreate()
    {
        base.OnCreate();
        if (Build.VERSION.SdkInt >= BuildVersionCodes.O)
            ((NotificationManager)GetSystemService(NotificationService)!).CreateNotificationChannel(
                new NotificationChannel("p2p-vpn", "P2P VPN 连接", NotificationImportance.Low));
    }

    public override StartCommandResult OnStartCommand(Intent? intent, StartCommandFlags flags, int startId)
    {
        if (intent?.Action == ActionDisconnect) { StopTunnel(); return StartCommandResult.NotSticky; }
        if (_worker is { IsCompleted: false }) return StartCommandResult.Sticky;
        StartForeground(NotificationId, BuildNotification("正在连接…"));
        _lifetime = new CancellationTokenSource();
        _worker = RunAsync(_lifetime.Token);
        return StartCommandResult.Sticky;
    }

    private async Task RunAsync(CancellationToken cancellationToken)
    {
        try { await new VpnEngine(this).RunAsync(cancellationToken).ConfigureAwait(false); }
        catch (System.OperationCanceledException) when (cancellationToken.IsCancellationRequested) { }
        catch (Exception ex) { VpnRuntimeState.Publish(new(false, false, "连接失败", "--", 0, ex.Message)); }
        finally
        {
            StopForeground(StopForegroundFlags.Remove);
            StopSelf();
        }
    }

    internal ParcelFileDescriptor EstablishTunnel(System.Net.IPAddress address, int prefixLength, IEnumerable<SubnetRoute> routes)
    {
        var builder = new Builder(this).SetSession("P2P VPN").SetMtu(1200)
            .AddAddress(address.ToString(), prefixLength);
        byte[] addressBytes = address.GetAddressBytes(); int remaining = prefixLength;
        for (int i = 0; i < 4; i++) { int bits = Math.Clamp(remaining, 0, 8); addressBytes[i] &= (byte)(bits == 0 ? 0 : 0xff << (8 - bits)); remaining -= bits; }
        builder.AddRoute(new System.Net.IPAddress(addressBytes).ToString(), prefixLength);
        foreach (SubnetRoute route in routes.Where(x => x.Enabled))
            if (ProfileStore.TryParseCidr(route.Subnet, out System.Net.IPAddress network, out int prefix))
                builder.AddRoute(network.ToString(), prefix);
        builder.AddDisallowedApplication(PackageName ?? "pub.hngs.vpn");
        if (Build.VERSION.SdkInt >= BuildVersionCodes.Lollipop) builder.SetBlocking(true);
        var open = new Intent(this, typeof(MainActivity));
        builder.SetConfigureIntent(PendingIntent.GetActivity(this, 0, open, PendingIntentFlags.Immutable | PendingIntentFlags.UpdateCurrent)!);
        return builder.Establish() ?? throw new IOException("Android 系统没有建立 VPN 虚拟网卡");
    }

    internal void UpdateNotification(string text)
    {
        var manager = (NotificationManager)GetSystemService(NotificationService)!;
        manager.Notify(NotificationId, BuildNotification(text));
    }

    private Notification BuildNotification(string text)
    {
        var open = PendingIntent.GetActivity(this, 0, new Intent(this, typeof(MainActivity)), PendingIntentFlags.Immutable | PendingIntentFlags.UpdateCurrent);
        var stop = PendingIntent.GetService(this, 1, new Intent(this, typeof(VpnTunnelService)).SetAction(ActionDisconnect), PendingIntentFlags.Immutable | PendingIntentFlags.UpdateCurrent);
        return new Notification.Builder(this, Build.VERSION.SdkInt >= BuildVersionCodes.O ? "p2p-vpn" : null)
            .SetContentTitle("P2P VPN").SetContentText(text).SetSmallIcon(Resource.Drawable.ic_p2p_notification)
            .SetContentIntent(open).SetOngoing(true).AddAction(new Notification.Action.Builder(null, "断开", stop).Build()).Build();
    }

    private void StopTunnel()
    {
        try { _lifetime?.Cancel(); } catch { }
        VpnRuntimeState.Publish(new(false, false, "未连接", "--", 0, "--"));
        StopForeground(StopForegroundFlags.Remove); StopSelf();
    }

    public override void OnRevoke() { StopTunnel(); base.OnRevoke(); }
    public override void OnDestroy() { try { _lifetime?.Cancel(); } catch { } base.OnDestroy(); }
    public override IBinder? OnBind(Intent? intent) => base.OnBind(intent);
}
