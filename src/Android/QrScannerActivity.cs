using Android.App;
using Android.Content;
using Android.Content.PM;
using Android.Graphics;
using Android.Hardware.Camera2;
using Android.Hardware.Camera2.Params;
using Android.OS;
using Android.Views;
using Android.Widget;
using ZXing;
using ZXing.Common;

namespace P2PVpnAndroid;

[Activity(Label = "扫描 VPN 配置", Exported = false, Theme = "@style/AppTheme",
    ScreenOrientation = ScreenOrientation.Portrait)]
public sealed class QrScannerActivity : Activity, TextureView.ISurfaceTextureListener
{
    public const string ResultExtra = "p2p-vpn-config";
    private TextureView _preview = null!;
    private TextView _tip = null!;
    private HandlerThread? _cameraThread;
    private Handler? _cameraHandler;
    private Handler? _uiHandler;
    private CameraDevice? _camera;
    private CameraCaptureSession? _session;
    private Surface? _cameraSurface;
    private int _opening;
    private int _decoding;
    private int _completed;
    private int _decodeAttempts;
    private bool _active;
    private readonly BarcodeReaderGeneric _fastReader = new()
    {
        Options = new DecodingOptions
        {
            TryHarder = false,
            PossibleFormats = [BarcodeFormat.QR_CODE]
        }
    };
    private readonly BarcodeReaderGeneric _hardReader = new()
    {
        Options = new DecodingOptions
        {
            TryHarder = true,
            PossibleFormats = [BarcodeFormat.QR_CODE]
        }
    };

    protected override void OnCreate(Bundle? savedInstanceState)
    {
        base.OnCreate(savedInstanceState);
        Window?.SetStatusBarColor(Color.Black);
        _uiHandler = new Handler(Looper.MainLooper!);

        var root = new FrameLayout(this);
        root.SetBackgroundColor(Color.Black);
        _preview = new TextureView(this) { SurfaceTextureListener = this };
        root.AddView(_preview, new FrameLayout.LayoutParams(
            ViewGroup.LayoutParams.MatchParent, ViewGroup.LayoutParams.MatchParent));

        var overlay = new LinearLayout(this) { Orientation = Android.Widget.Orientation.Vertical };
        overlay.SetGravity(GravityFlags.CenterHorizontal);
        overlay.SetPadding(Dp(20), Dp(24), Dp(20), Dp(24));
        _tip = new TextView(this)
        {
            Text = "对准二维码即可自动导入\n整个画面均可识别，无需放入固定框",
            TextSize = 17,
            Gravity = GravityFlags.Center
        };
        _tip.SetTextColor(Color.White);
        _tip.SetShadowLayer(6, 0, 2, Color.Black);
        overlay.AddView(_tip, new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MatchParent, 0, 1));

        var scanArea = new TextView(this)
        {
            Text = "正在全屏扫描…",
            TextSize = 16,
            Gravity = GravityFlags.Center
        };
        scanArea.SetTextColor(Color.ParseColor("#20D8C0"));
        scanArea.SetShadowLayer(6, 0, 2, Color.Black);
        overlay.AddView(scanArea, new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MatchParent, 0, 3));

        var cancel = new Button(this) { Text = "取消扫描" };
        cancel.SetAllCaps(false);
        cancel.Click += (_, _) => { SetResult(Android.App.Result.Canceled); Finish(); };
        overlay.AddView(cancel, new LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MatchParent, ViewGroup.LayoutParams.WrapContent));
        root.AddView(overlay, new FrameLayout.LayoutParams(
            ViewGroup.LayoutParams.MatchParent, ViewGroup.LayoutParams.MatchParent));
        SetContentView(root);
    }

    protected override void OnResume()
    {
        base.OnResume();
        _active = true;
        _cameraThread = new HandlerThread("p2p-qr-camera");
        _cameraThread.Start();
        _cameraHandler = new Handler(_cameraThread.Looper!);
        if (_preview.IsAvailable) OpenCamera(_preview.SurfaceTexture);
    }

    protected override void OnPause()
    {
        _active = false;
        _uiHandler?.RemoveCallbacksAndMessages(null);
        CloseCamera();
        _cameraThread?.QuitSafely();
        try { _cameraThread?.Join(1000); } catch { }
        _cameraThread?.Dispose();
        _cameraThread = null;
        _cameraHandler = null;
        base.OnPause();
    }

    public void OnSurfaceTextureAvailable(SurfaceTexture surface, int width, int height) => OpenCamera(surface);
    public bool OnSurfaceTextureDestroyed(SurfaceTexture surface) { CloseCamera(); return true; }
    public void OnSurfaceTextureSizeChanged(SurfaceTexture surface, int width, int height) { }
    public void OnSurfaceTextureUpdated(SurfaceTexture surface) { }

    private void OpenCamera(SurfaceTexture? texture)
    {
        if (texture is null || !_active || IsFinishing ||
            Interlocked.Exchange(ref _opening, 1) != 0) return;
        try
        {
            var manager = (CameraManager)GetSystemService(CameraService)!;
            string[] cameraIds = manager.GetCameraIdList();
            string? id = cameraIds.FirstOrDefault(cameraId =>
            {
                CameraCharacteristics characteristics = manager.GetCameraCharacteristics(cameraId);
                var facing = characteristics.Get(CameraCharacteristics.LensFacing) as Java.Lang.Integer;
                return facing?.IntValue() == (int)LensFacing.Back;
            }) ?? cameraIds.FirstOrDefault();
            if (id is null) throw new InvalidOperationException("没有找到可用摄像头");

            CameraCharacteristics selected = manager.GetCameraCharacteristics(id);
            var map = selected.Get(CameraCharacteristics.ScalerStreamConfigurationMap) as StreamConfigurationMap;
            Android.Util.Size[] sizes = map?.GetOutputSizes(Java.Lang.Class.FromType(typeof(SurfaceTexture))) ?? [];
            Android.Util.Size? previewSize = sizes
                .Where(x => x.Width * x.Height <= 1920 * 1080)
                .OrderByDescending(x => x.Width * x.Height)
                .FirstOrDefault() ?? sizes.OrderBy(x => x.Width * x.Height).FirstOrDefault();
            if (previewSize is not null)
                texture.SetDefaultBufferSize(previewSize.Width, previewSize.Height);

            _cameraSurface?.Dispose();
            _cameraSurface = new Surface(texture);
            manager.OpenCamera(id, new CameraState(this), _cameraHandler);
        }
        catch (Exception ex)
        {
            Interlocked.Exchange(ref _opening, 0);
            ShowCameraError("摄像头启动失败：" + ex.Message);
        }
    }

    private void StartPreview(CameraDevice camera)
    {
        try
        {
            Surface surface = _cameraSurface ?? throw new InvalidOperationException("摄像头预览尚未就绪");
            CaptureRequest.Builder request = camera.CreateCaptureRequest(CameraTemplate.Preview);
            request.AddTarget(surface);
            request.Set(CaptureRequest.ControlAfMode, (int)ControlAFMode.ContinuousPicture);
            request.Set(CaptureRequest.ControlAeMode, (int)ControlAEMode.On);
            camera.CreateCaptureSession([surface], new SessionState(this, request), _cameraHandler);
        }
        catch (Exception ex) { ShowCameraError("无法启动实时扫描：" + ex.Message); }
    }

    private void ScheduleDecode()
    {
        if (!_active || Volatile.Read(ref _completed) != 0) return;
        _uiHandler?.PostDelayed(CapturePreviewFrame, 80);
    }

    private void CapturePreviewFrame()
    {
        if (!_active || IsFinishing || Volatile.Read(ref _completed) != 0) return;
        if (Interlocked.Exchange(ref _decoding, 1) != 0) { ScheduleDecode(); return; }
        Bitmap? bitmap = null;
        bool handedToDecoder = false;
        try
        {
            if (!_preview.IsAvailable) return;
            int width = Math.Min(960, Math.Max(720, _preview.Width));
            int height = Math.Max(360, (int)(width * Math.Max(1, _preview.Height) / (double)Math.Max(1, _preview.Width)));
            height = Math.Min(height, 1440);
            bitmap = _preview.GetBitmap(width, height);
            if (bitmap is null) return;
            Bitmap captured = bitmap;
            bitmap = null;
            handedToDecoder = true;
            _ = Task.Run(() => DecodeBitmap(captured));
        }
        catch (Exception ex)
        {
            Android.Util.Log.Warn("P2PVpnQr", "读取预览帧失败：" + ex);
        }
        finally
        {
            bitmap?.Dispose();
            if (!handedToDecoder)
            {
                Interlocked.Exchange(ref _decoding, 0);
                ScheduleDecode();
            }
        }
    }

    private void DecodeBitmap(Bitmap bitmap)
    {
        try
        {
            int width = bitmap.Width, height = bitmap.Height;
            int[] pixels = new int[width * height];
            bitmap.GetPixels(pixels, 0, width, 0, 0, width, height);
            byte[] luminance = new byte[pixels.Length];
            for (int i = 0; i < pixels.Length; i++)
            {
                int pixel = pixels[i];
                int r = (pixel >> 16) & 0xff, g = (pixel >> 8) & 0xff, b = pixel & 0xff;
                luminance[i] = (byte)((r * 306 + g * 601 + b * 117) >> 10);
            }
            var source = new PlanarYUVLuminanceSource(luminance, width, height, 0, 0, width, height, false);
            int attempt = Interlocked.Increment(ref _decodeAttempts);
            string? text = _fastReader.Decode(source)?.Text
                ?? _fastReader.Decode(new InvertedLuminanceSource(source))?.Text;
            // 快速识别优先；每三帧追加一次深度识别，兼顾高密度、远距离和反色二维码。
            if (text is null && attempt % 3 == 0)
                text = _hardReader.Decode(source)?.Text
                    ?? _hardReader.Decode(new InvertedLuminanceSource(source))?.Text;
            if (string.IsNullOrWhiteSpace(text) || Interlocked.Exchange(ref _completed, 1) != 0) return;
            RunOnUiThread(() =>
            {
                if (!_active || IsFinishing) return;
                var result = new Intent();
                result.PutExtra(ResultExtra, text);
                SetResult(Android.App.Result.Ok, result);
                Finish();
            });
        }
        catch (Exception ex) { Android.Util.Log.Warn("P2PVpnQr", "二维码识别失败：" + ex); }
        finally
        {
            bitmap.Dispose();
            Interlocked.Exchange(ref _decoding, 0);
            RunOnUiThread(ScheduleDecode);
        }
    }

    private void CloseCamera()
    {
        try { _session?.StopRepeating(); } catch { }
        try { _session?.AbortCaptures(); } catch { }
        try { _session?.Close(); } catch { }
        try { _session?.Dispose(); } catch { }
        _session = null;
        try { _camera?.Close(); } catch { }
        try { _camera?.Dispose(); } catch { }
        _camera = null;
        try { _cameraSurface?.Release(); } catch { }
        try { _cameraSurface?.Dispose(); } catch { }
        _cameraSurface = null;
        Interlocked.Exchange(ref _opening, 0);
    }

    private void ShowCameraError(string message)
    {
        Android.Util.Log.Error("P2PVpnQr", message);
        RunOnUiThread(() => { if (!IsFinishing) _tip.Text = message; });
    }

    private int Dp(int value) => (int)(value * Resources!.DisplayMetrics!.Density + .5f);

    private sealed class CameraState(QrScannerActivity owner) : CameraDevice.StateCallback
    {
        public override void OnOpened(CameraDevice camera)
        {
            if (!owner._active) { camera.Close(); return; }
            owner._camera = camera;
            owner.StartPreview(camera);
        }
        public override void OnDisconnected(CameraDevice camera)
        {
            camera.Close();
            owner.ShowCameraError("摄像头已断开");
        }
        public override void OnError(CameraDevice camera, CameraError error)
        {
            camera.Close();
            owner.ShowCameraError($"摄像头错误：{error}");
        }
    }

    private sealed class SessionState(QrScannerActivity owner, CaptureRequest.Builder request)
        : CameraCaptureSession.StateCallback
    {
        public override void OnConfigured(CameraCaptureSession session)
        {
            if (!owner._active) { session.Close(); return; }
            owner._session = session;
            try
            {
                session.SetRepeatingRequest(request.Build(), null, owner._cameraHandler);
                owner.RunOnUiThread(owner.ScheduleDecode);
            }
            catch (Exception ex) { owner.ShowCameraError("实时扫描启动失败：" + ex.Message); }
        }

        public override void OnConfigureFailed(CameraCaptureSession session) =>
            owner.ShowCameraError("摄像头不支持当前实时扫描模式");
    }
}
