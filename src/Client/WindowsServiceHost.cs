using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;

namespace P2PVpnClient;

/// <summary>不依赖额外 NuGet 包的 Native AOT Windows 服务宿主。</summary>
internal static class WindowsServiceHost
{
    internal const string ServiceName = "EdgeVpnClient";
    private const uint ServiceWin32OwnProcess = 0x10, ServiceAcceptStop = 1, ServiceAcceptShutdown = 4;
    private const uint ServiceStopped = 1, ServiceStartPending = 2, ServiceStopPending = 3, ServiceRunning = 4;
    private const uint ControlStop = 1, ControlShutdown = 5;
    private const int ErrorFailedServiceControllerConnect = 1063;
    private static readonly ServiceMainCallback MainCallback = ServiceMain;
    private static readonly ServiceControlCallback ControlCallback = HandleControl;
    private static CancellationTokenSource? _stopSource;
    private static IntPtr _statusHandle;

    /// <summary>尝试连接服务控制管理器并运行服务主循环。</summary>
    /// <returns>由服务控制管理器启动时返回 true，普通启动时返回 false。</returns>
    internal static bool TryRun()
    {
        var table = new[] { new ServiceTableEntry { ServiceName = ServiceName, Callback = MainCallback }, new() };
        if (StartServiceCtrlDispatcher(table)) return true;
        int error = Marshal.GetLastWin32Error();
        if (error == ErrorFailedServiceControllerConnect) return false;
        throw new Win32Exception(error, "无法连接 Windows 服务控制管理器。");
    }

    /// <summary>请求当前 Windows 服务完成有界清理后正常退出。</summary>
    internal static void RequestStop() => _stopSource?.Cancel();

    /// <summary>注册停止处理器并启动 VPN 工作器。</summary>
    /// <param name="argumentCount">服务参数数量。</param>
    /// <param name="arguments">服务参数地址。</param>
    private static void ServiceMain(int argumentCount, IntPtr arguments)
    {
        _statusHandle = RegisterServiceCtrlHandler(ServiceName, ControlCallback);
        if (_statusHandle == IntPtr.Zero) return;
        SetState(ServiceStartPending, 0, 15_000);
        _stopSource = new CancellationTokenSource();
        SetState(ServiceRunning, ServiceAcceptStop | ServiceAcceptShutdown, 0);
        UpdateServiceMetadata();
        try
        {
            VpnClientWorker.RunAsync(_stopSource.Token).GetAwaiter().GetResult();
            SetState(ServiceStopped, 0, 0);
        }
        catch (Exception exception)
        {
            ClientLog.Write($"Windows 服务异常退出：{exception}");
            SetState(ServiceStopped, 0, 0, 1);
        }
        finally { _stopSource.Dispose(); _stopSource = null; }
    }

    /// <summary>
    /// 执行Update Service Metadata操作。
    /// </summary>
    private static void UpdateServiceMetadata()
    {
        TryRunSc(["config", ServiceName, "DisplayName=", "Edge VPN 客户端"]);
        TryRunSc(["description", ServiceName,
            "Edge VPN 虚拟网卡客户端；自动打洞并在失败时通过服务器中继。"]);
    }

    /// <summary>
    /// 尝试Run Sc。
    /// </summary>
    /// <param name="arguments">arguments参数。</param>
    private static void TryRunSc(string[] arguments)
    {
        try
        {
            var startInfo = new ProcessStartInfo(Path.Combine(Environment.SystemDirectory, "sc.exe"))
            { UseShellExecute = false, CreateNoWindow = true };
            foreach (string argument in arguments) startInfo.ArgumentList.Add(argument);
            using Process? process = Process.Start(startInfo);
            process?.WaitForExit(5000);
        }
        catch { }
    }

    /// <summary>响应服务停止和系统关机控制码。</summary>
    /// <param name="control">服务控制码。</param>
    private static void HandleControl(uint control)
    {
        if (control is not (ControlStop or ControlShutdown)) return;
        SetState(ServiceStopPending, 0, 20_000);
        _stopSource?.Cancel();
    }

    /// <summary>向服务控制管理器报告当前状态。</summary>
    /// <param name="state">需要报告的服务状态。</param>
    /// <param name="acceptedControls">当前接受的服务控制码。</param>
    /// <param name="waitHint">启动或停止预计等待毫秒数。</param>
    /// <param name="exitCode">服务停止时的 Win32 退出码。</param>
    private static void SetState(uint state, uint acceptedControls, uint waitHint, uint exitCode = 0)
    {
        if (_statusHandle == IntPtr.Zero) return;
        var status = new ServiceStatus { ServiceType = ServiceWin32OwnProcess, CurrentState = state,
            ControlsAccepted = acceptedControls, Win32ExitCode = exitCode, WaitHint = waitHint };
        SetServiceStatus(_statusHandle, ref status);
    }

    /// <summary>
    /// 表示 Service Table Entry，并提供相关数据或行为。
    /// </summary>
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct ServiceTableEntry
    {
        [MarshalAs(UnmanagedType.LPWStr)] public string? ServiceName;
        public ServiceMainCallback? Callback;
    }

    /// <summary>
    /// 表示 Service Status，并提供相关数据或行为。
    /// </summary>
    [StructLayout(LayoutKind.Sequential)]
    private struct ServiceStatus
    {
        public uint ServiceType, CurrentState, ControlsAccepted, Win32ExitCode,
            ServiceSpecificExitCode, CheckPoint, WaitHint;
    }

    /// <summary>
    /// 定义处理 Service Main Callback 的回调方法。
    /// </summary>
    /// <param name="count">数据数量。</param>
    /// <param name="args">args参数。</param>
    [UnmanagedFunctionPointer(CallingConvention.Winapi)] private delegate void ServiceMainCallback(int count, IntPtr args);
    /// <summary>
    /// 定义处理 Service Control Callback 的回调方法。
    /// </summary>
    /// <param name="control">control参数。</param>
    [UnmanagedFunctionPointer(CallingConvention.Winapi)] private delegate void ServiceControlCallback(uint control);

    /// <summary>
    /// 执行Start Service Ctrl Dispatcher操作。
    /// </summary>
    /// <param name="serviceTable">service Table参数。</param>
    /// <returns>操作结果。</returns>
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool StartServiceCtrlDispatcher([In] ServiceTableEntry[] serviceTable);
    /// <summary>
    /// 执行Register Service Ctrl Handler操作。
    /// </summary>
    /// <param name="serviceName">service Name参数。</param>
    /// <param name="callback">callback参数。</param>
    /// <returns>操作结果。</returns>
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr RegisterServiceCtrlHandler(string serviceName, ServiceControlCallback callback);
    /// <summary>
    /// 设置Service Status。
    /// </summary>
    /// <param name="statusHandle">status Handle参数。</param>
    /// <param name="status">status参数。</param>
    /// <returns>操作结果。</returns>
    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetServiceStatus(IntPtr statusHandle, ref ServiceStatus status);
}
