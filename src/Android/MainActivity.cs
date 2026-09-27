using Android.App;
using Android.Content;
using Android.Content.PM;
using Android.Graphics;
using Android.Graphics.Drawables;
using Android.OS;
using Android.Text;
using Android.Text.Method;
using Android.Views;
using Android.Views.InputMethods;
using Android.Widget;

namespace P2PVpnAndroid;

[Activity(Label = "P2P VPN", MainLauncher = true, Exported = true, Theme = "@style/AppTheme",
    LaunchMode = LaunchMode.SingleTop)]
[IntentFilter([Intent.ActionView], Categories = [Intent.CategoryDefault, Intent.CategoryBrowsable],
    DataScheme = "edgevpn", DataHost = "join")]
public sealed class MainActivity : Activity
{
    private const int VpnPermissionRequest = 901, CameraQrRequest = 903, CameraPermissionRequest = 904;
    private readonly List<SubnetRoute> _routes = [];
    private readonly CancellationTokenSource _lifetime = new();
    private EditText _join = null!;
    private TextView _status = null!, _detail = null!, _identity = null!;
    private Button _connect = null!, _disconnect = null!, _import = null!;
    private LinearLayout _routeList = null!;
    private bool _joining;

    protected override void OnCreate(Bundle? savedInstanceState)
    {
        base.OnCreate(savedInstanceState);
        Window?.SetSoftInputMode(SoftInput.AdjustResize);
        Window?.AddFlags(WindowManagerFlags.Secure);
        BuildUi(); LoadProfile(); ApplyIncomingConfiguration(Intent);
        const string permission = "android.permission.POST_NOTIFICATIONS";
        if (Build.VERSION.SdkInt >= BuildVersionCodes.Tiramisu && CheckSelfPermission(permission) != Permission.Granted)
            RequestPermissions([permission], 902);
    }

    protected override void OnNewIntent(Intent? intent)
    {
        base.OnNewIntent(intent); Intent = intent; ApplyIncomingConfiguration(intent);
    }
    protected override void OnResume()
    {
        base.OnResume(); VpnRuntimeState.Changed += OnStateChanged; LoadProfile(); RenderState(VpnRuntimeState.Current);
    }
    protected override void OnPause() { VpnRuntimeState.Changed -= OnStateChanged; base.OnPause(); }
    protected override void OnDestroy() { _lifetime.Cancel(); base.OnDestroy(); }

    private void BuildUi()
    {
        var scroll = new ScrollView(this) { FillViewport = true };
        scroll.SetFitsSystemWindows(true);
        var root = Stack(Orientation.Vertical, 18);
        root.SetPadding(Dp(18), Dp(24), Dp(18), Dp(36));
        root.SetBackgroundColor(Color.ParseColor("#071724")); scroll.AddView(root);
        root.AddView(Text("P2P VPN", 30, Color.White, true));
        root.AddView(Text("把手机，加入你的私人网络", 14, Color.ParseColor("#21D4BE")), Margin(bottom: 20));
        var state = Card();
        _status = Text("未连接", 22, Color.White, true); state.AddView(_status);
        _detail = Text("虚拟地址 -- · 对端 0", 13, Color.ParseColor("#86A5BA")); state.AddView(_detail, Margin(top: 10, bottom: 12));
        _connect = Button("连接 VPN", true); _connect.Click += (_, _) => Connect(); state.AddView(_connect, Full());
        _disconnect = Button("断开连接", false); _disconnect.Click += (_, _) => StopVpn(); state.AddView(_disconnect, Margin(top: 8));
        root.AddView(state, Margin(bottom: 18));
        var identity = Card();
        identity.AddView(SectionTitle("我的设备"));
        _identity = Text("尚未加入网络", 13, Color.ParseColor("#86A5BA")); identity.AddView(_identity);
        var forget = Button("移除此手机的配置", false);
        forget.Click += (_, _) => {
            if (VpnRuntimeState.Current.Running || _joining) { ShowError("请先断开 VPN，等待连接停止。"); return; }
            new AlertDialog.Builder(this).SetTitle("移除本机配置？")
                .SetMessage("只清除手机保存的密钥。不再使用的设备请同时在网页控制台撤销。")
                .SetNegativeButton("取消", (_, _) => { }).SetPositiveButton("移除", (_, _) => { ProfileStore.Clear(this); LoadProfile(); }).Show();
        };
        identity.AddView(forget, Margin(top: 10)); root.AddView(identity, Margin(bottom: 18));

        var join = Card(); join.AddView(SectionTitle("添加设备 · 三步开始"));
        join.AddView(Text("1. 登录平台，创建网络\n2. 添加设备，选择 Android\n3. 粘贴加入链接，确认后连接", 14, Color.ParseColor("#DCECF5")));
        var portal = Button("打开平台控制台", false); portal.Click += (_, _) => OpenWeb("https://vpn.hngs.pub/console#setup");
        join.AddView(portal, Margin(top: 12));
        _join = Field(join, "专属加入链接（30 分钟有效）", "edgevpn://join?server=…#…", true);
        _join.InputType = InputTypes.ClassText | InputTypes.TextVariationPassword | InputTypes.TextFlagNoSuggestions;
        _join.SaveEnabled = false;
        _import = Button("确认加入此网络", true); _import.Click += (_, _) => ConfirmJoin(); join.AddView(_import, Margin(top: 10));
        var scan = Button("扫描加入二维码", false); scan.Click += (_, _) => ScanConfiguration(); join.AddView(scan, Margin(top: 8));
        join.AddView(Text("链接仅供一台设备使用，请勿转发。确认平台地址后才会提交凭据。", 12, Color.ParseColor("#86A5BA")), Margin(top: 10));
        root.AddView(join, Margin(bottom: 18));

        var routes = Horizontal();
        routes.AddView(SectionTitle("远端子网 · 可选"), new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WrapContent, 1));
        var add = Button("＋ 添加", false); add.Click += (_, _) => EditRoute(null, -1); routes.AddView(add); root.AddView(routes);
        root.AddView(Text("访问同组虚拟 IP 无需设置。访问远端局域网，需要远端客户端启用子网出口。", 12, Color.ParseColor("#86A5BA")), Margin(bottom: 8));
        _routeList = Stack(Orientation.Vertical, 10); root.AddView(_routeList);
        var update = Button("下载更新 / 使用说明", false); update.Click += (_, _) => OpenWeb("https://vpn.hngs.pub/downloads");
        root.AddView(update, Margin(top: 20)); root.AddView(Text("Android 1.1.0 · 独立新版", 12, Color.ParseColor("#86A5BA")), Margin(top: 12));
        SetContentView(scroll);
    }

    private void OpenWeb(string url)
    {
        try { StartActivity(new Intent(Intent.ActionView, Android.Net.Uri.Parse(url))); }
        catch (ActivityNotFoundException) { ShowError("没有可用的浏览器，请手动访问 vpn.hngs.pub。"); }
    }
    private void LoadProfile()
    {
        try {
            var p = ProfileStore.Load(this);
            _identity.Text = p.DeviceId.Length == 0 ? "尚未加入网络" :
                $"平台 {p.ControlUrl}\n网段 {p.Subnet}\n设备 {p.DeviceId}\n" +
                (p.AccessRevoked ? "设备已停用，请重新添加" : p.RelayUrls.Length > 0 ? "直连优先 · 独立中继备用" : "认证与打洞 · 当前未分配中继");
            _routes.Clear(); _routes.AddRange(p.Routes); RenderRoutes();
        } catch { _identity.Text = "无法读取本机配置，请移除本机配置后重新添加设备。"; }
        RenderState(VpnRuntimeState.Current);
    }
    private bool SaveProfile(bool notify)
    {
        try {
            var p = ProfileStore.Load(this); p.Routes = _routes.Select(Clone).ToList(); ProfileStore.Save(this, p);
            if (notify) Toast.MakeText(this, "配置已保存", ToastLength.Short)?.Show();
            return true;
        } catch (Exception ex) { ShowError(ex.Message); return false; }
    }
    private void ConfirmJoin()
    {
        if (_joining || VpnRuntimeState.Current.Running) { ShowError("请先断开当前 VPN。"); return; }
        try {
            var link = JoinLink.Parse(_join.Text ?? "");
            new AlertDialog.Builder(this).SetTitle("确认加入网络")
                .SetMessage($"即将向以下平台兑换设备凭据：\n\n{link.Origin}\n\n成功后替换本机配置。请确认这是你信任的平台。")
                .SetNegativeButton("取消", (_, _) => { })
                .SetPositiveButton("确认加入", async (_, _) => await JoinAsync(link)).Show();
        } catch (Exception ex) { ShowError(ex.Message); }
    }
    private async Task JoinAsync(JoinLink link)
    {
        if (_joining || VpnRuntimeState.Current.Running) return;
        _joining = true; _import.Enabled = false; _connect.Enabled = false;
        try {
            var profile = await ControlApi.RedeemAsync(this, link, _lifetime.Token);
            ProfileStore.Save(this, profile);
            if (IsDestroyed || IsFinishing) return;
            _join.Text = ""; LoadProfile();
            Toast.MakeText(this, "已加入网络，点击连接 VPN 即可上线。", ToastLength.Long)?.Show();
        } catch (System.OperationCanceledException) when (_lifetime.IsCancellationRequested) { }
        catch (Exception ex) { if (!IsDestroyed && !IsFinishing) ShowError(ex.Message); }
        finally {
            _joining = false;
            if (!IsDestroyed && !IsFinishing) { _import.Enabled = true; RenderState(VpnRuntimeState.Current); }
        }
    }
    private void ApplyIncomingConfiguration(Intent? intent)
    {
        var value = intent?.DataString; intent?.SetData(null);
        if (value is null) return;
        AcceptLink(value);
    }
    private void AcceptLink(string value)
    {
        try { _ = JoinLink.Parse(value); _join.Text = value; ConfirmJoin(); }
        catch (Exception ex) { ShowError(ex.Message); }
    }
    private void Connect()
    {
        if (_joining) return;
        try { var p = ProfileStore.Load(this); ProfileStore.Validate(p); if (p.AccessRevoked) throw new AccessRevokedException(); }
        catch (Exception ex) { ShowError(ex.Message); return; }
        var permission = Android.Net.VpnService.Prepare(this);
        if (permission is not null) StartActivityForResult(permission, VpnPermissionRequest); else StartVpn();
    }
    private void StartVpn()
    {
        VpnRuntimeState.Publish(new(true, false, "正在连接", "--", 0, "正在认证设备"));
        StartForegroundService(new Intent(this, typeof(VpnTunnelService)).SetAction(VpnTunnelService.ActionConnect));
    }
    private void StopVpn() => StartService(new Intent(this, typeof(VpnTunnelService)).SetAction(VpnTunnelService.ActionDisconnect));
    protected override void OnActivityResult(int requestCode, Result resultCode, Intent? data)
    {
        base.OnActivityResult(requestCode, resultCode, data);
        if (requestCode == VpnPermissionRequest && resultCode == Result.Ok) StartVpn();
        if (requestCode == CameraQrRequest && resultCode == Result.Ok && data?.GetStringExtra(QrScannerActivity.ResultExtra) is string value) AcceptLink(value);
    }
    private void ScanConfiguration()
    {
        if (CheckSelfPermission(Android.Manifest.Permission.Camera) != Permission.Granted)
            RequestPermissions([Android.Manifest.Permission.Camera], CameraPermissionRequest);
        else StartActivityForResult(new Intent(this, typeof(QrScannerActivity)), CameraQrRequest);
    }
    public override void OnRequestPermissionsResult(int requestCode, string[] permissions, Permission[] grantResults)
    {
        base.OnRequestPermissionsResult(requestCode, permissions, grantResults);
        if (requestCode != CameraPermissionRequest) return;
        if (grantResults.Length > 0 && grantResults[0] == Permission.Granted)
            StartActivityForResult(new Intent(this, typeof(QrScannerActivity)), CameraQrRequest);
        else ShowError("相机权限未开启，可以改为粘贴加入链接。");
    }
    private void ApplyProfileChange(string message)
    {
        if (SaveProfile(false)) Toast.MakeText(this, message + (VpnRuntimeState.Current.Running ? "，连接会自动更新" : ""), ToastLength.Long)?.Show();
    }
    private void OnStateChanged(VpnSnapshot state) => RunOnUiThread(() => { if (!IsDestroyed) RenderState(state); });
    private void RenderState(VpnSnapshot state)
    {
        _status.Text = state.Status; _status.SetTextColor(Color.ParseColor(state.Connected ? "#21D4BE" : state.Running ? "#FFD27D" : "#F3FAFF"));
        _detail.Text = $"虚拟地址 {state.VirtualIp} · 对端 {state.PeerCount}\n{state.Paths}";
        _connect.Enabled = !state.Running && !_joining; _disconnect.Enabled = state.Running;
    }

    private void EditRoute(SubnetRoute? route, int index)
    {
        var form = Stack(Orientation.Vertical, 8); form.SetPadding(Dp(20), Dp(4), Dp(20), 0);
        var enabled = new CheckBox(this) { Text = "启用此映射", Checked = route?.Enabled ?? true }; enabled.SetTextColor(Color.ParseColor("#86A5BA")); form.AddView(enabled);
        EditText subnet = DialogField(form, "手机访问网段，例如 192.168.2.0/24", route?.Subnet);
        EditText destination = DialogField(form, "远端真实网段，例如 192.168.1.0/24", route?.DestinationSubnet);
        EditText gateway = DialogField(form, "从哪个 VPN 地址出去，例如 10.77.0.6", route?.GatewayVirtualIp);
        var builder = new AlertDialog.Builder(this);
        builder.SetTitle(index < 0 ? "添加远端子网出口" : "编辑远端子网出口");
        builder.SetView(form);
        builder.SetNegativeButton("取消", (_, _) => { });
        builder.SetPositiveButton("保存", (dialog, _) =>
        {
            var value = new SubnetRoute { Enabled = enabled.Checked, Subnet = subnet.Text?.Trim() ?? "", DestinationSubnet = destination.Text?.Trim() ?? "", GatewayVirtualIp = gateway.Text?.Trim() ?? "" };
            try
            {
                var candidate = ProfileStore.Load(this); candidate.Routes = [value]; ProfileStore.Validate(candidate);
                if (index < 0) _routes.Add(value); else _routes[index] = value;
                RenderRoutes();
                ApplyProfileChange("远端子网出口已保存");
            }
            catch (Exception ex) { ShowError(ex.Message); }
        });
        builder.Show();
    }

    private void RenderRoutes()
    {
        _routeList.RemoveAllViews();
        if (_routes.Count == 0) { var empty = Text("尚未配置远端网段；仍可访问 VPN 虚拟地址。", 13, Color.ParseColor("#86A5BA")); empty.SetPadding(Dp(12), Dp(18), Dp(12), Dp(18)); empty.Background = CardBackground(); _routeList.AddView(empty); return; }
        for (int i = 0; i < _routes.Count; i++)
        {
            int index = i; SubnetRoute route = _routes[i]; var card = Card();
            var title = Text(route.Subnet, 16, Color.White, true); card.AddView(title);
            card.AddView(Text($"→ {route.DestinationSubnet}\n经由 VPN 客户端 {route.GatewayVirtualIp}\n{(route.Enabled ? "已启用" : "已停用")}", 13, route.Enabled ? Color.ParseColor("#86A5BA") : Color.Gray));
            var actions = Horizontal(); var edit = Button("编辑", false); edit.Click += (_, _) => EditRoute(Clone(route), index); actions.AddView(edit);
            var delete = Button("删除", false); delete.SetTextColor(Color.ParseColor("#FF7185")); delete.Click += (_, _) => { _routes.RemoveAt(index); RenderRoutes(); ApplyProfileChange("远端子网出口已删除"); }; actions.AddView(delete); card.AddView(actions);
            _routeList.AddView(card);
        }
    }

    private void ShowError(string message)
    {
        var builder = new AlertDialog.Builder(this);
        builder.SetTitle("无法完成"); builder.SetMessage(message); builder.SetPositiveButton("知道了", (_, _) => { }); builder.Show();
    }
    private static SubnetRoute Clone(SubnetRoute x) => new() { Enabled = x.Enabled, Subnet = x.Subnet, DestinationSubnet = x.DestinationSubnet, GatewayVirtualIp = x.GatewayVirtualIp };
    private LinearLayout Card() { var view = Stack(Orientation.Vertical, 10); view.SetPadding(Dp(16), Dp(16), Dp(16), Dp(16)); view.Background = Rounded("#102638", 16); return view; }
    private LinearLayout Horizontal() { var view = Stack(Orientation.Horizontal, 10); view.SetGravity(GravityFlags.CenterVertical); return view; }
    private LinearLayout Stack(Orientation orientation, int gap) { var view = new LinearLayout(this) { Orientation = orientation }; if (Build.VERSION.SdkInt >= BuildVersionCodes.N) view.ShowDividers = ShowDividers.None; return view; }
    private TextView SectionTitle(string value) { var t = Text(value, 18, Color.White, true); t.SetPadding(0, Dp(5), 0, Dp(9)); return t; }
    private TextView Label(string value) { var t = Text(value, 12, Color.ParseColor("#86A5BA")); t.SetPadding(0, Dp(8), 0, Dp(3)); return t; }
    private EditText Field(LinearLayout parent, string label, string hint, bool password = false) { parent.AddView(Label(label)); var e = DialogField(parent, hint, null); e.SetTextColor(Color.White); e.SetHintTextColor(Color.ParseColor("#607D91")); if (password) e.TransformationMethod = PasswordTransformationMethod.Instance; return e; }
    private EditText DialogField(LinearLayout parent, string hint, string? value) { var e = new EditText(this) { Hint = hint, Text = value ?? "" }; e.SetSingleLine(true); e.SetPadding(Dp(12), Dp(8), Dp(12), Dp(8)); parent.AddView(e, Full()); return e; }
    private TextView Text(string value, float size, Color color, bool bold = false) { var t = new TextView(this) { Text = value, TextSize = size }; t.SetTextColor(color); if (bold) t.SetTypeface(null, TypefaceStyle.Bold); return t; }
    private Button Button(string text, bool primary) { var b = new Button(this) { Text = text }; b.SetAllCaps(false); b.SetTextColor(primary ? Color.ParseColor("#05221F") : Color.ParseColor("#DCECF5")); b.Background = Rounded(primary ? "#21D4BE" : "#173348", 12); return b; }
    private Drawable Rounded(string color, int radius) { var drawable = new GradientDrawable(); drawable.SetColor(Color.ParseColor(color)); drawable.SetCornerRadius(Dp(radius)); return drawable; }
    private LinearLayout.LayoutParams Full() => new(ViewGroup.LayoutParams.MatchParent, ViewGroup.LayoutParams.WrapContent);
    private LinearLayout.LayoutParams Margin(int top = 0, int bottom = 0) { var p = Full(); p.SetMargins(0, Dp(top), 0, Dp(bottom)); return p; }
    private Drawable CardBackground() => Rounded("#102638", 16);
    private int Dp(int value) => (int)(value * Resources!.DisplayMetrics!.Density + .5f);
}
