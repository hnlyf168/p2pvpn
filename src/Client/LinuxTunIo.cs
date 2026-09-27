using System.ComponentModel;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace P2PVpnClient;

// Character devices cannot use buffered FileStream cancellation/flush semantics.
// Every syscall is nonblocking; poll bounds cancellation and descriptor shutdown.
internal sealed class LinuxTunIo(SafeFileHandle handle) : IAsyncDisposable
{
    private readonly object _gate = new();
    private readonly TaskCompletionSource _drained = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private int _active;
    private bool _closed;
    public SafeFileHandle Handle => handle;
    public static LinuxTunIo Open(string path)
    {
        int fd = open(path, 2 | 0x800 | 0x80000); // O_RDWR | O_NONBLOCK | O_CLOEXEC
        if (fd < 0) throw new Win32Exception(Marshal.GetLastPInvokeError(), "打开 Linux TUN 失败");
        return new(new SafeFileHandle((IntPtr)fd, true));
    }
    private int Enter()
    {
        lock (_gate)
        {
            ObjectDisposedException.ThrowIf(_closed, this);
            _active++;
            return handle.DangerousGetHandle().ToInt32();
        }
    }
    private void Leave()
    {
        lock (_gate)
        {
            if (--_active == 0 && _closed) { handle.Dispose(); _drained.TrySetResult(); }
        }
    }
    private void Check(CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        lock (_gate) if (_closed) throw new OperationCanceledException("TUN 已关闭", ct);
    }
    private void Wait(int fd, short events, CancellationToken ct)
    {
        Check(ct);
        var p = new PollFd { Fd = fd, Events = events };
        int result = poll(ref p, 1, 100);
        if (result < 0 && Marshal.GetLastPInvokeError() != 4) throw new Win32Exception(Marshal.GetLastPInvokeError());
        if ((p.Returned & 0x38) != 0) throw new IOException("TUN poll descriptor closed or failed");
    }
    public ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken ct = default)
    {
        int fd = Enter();
        return new(Task.Run(() =>
        {
            try
            {
                while (true)
                {
                    Check(ct);
                    nint size;
                    unsafe { using var pin = buffer.Pin(); size = read(fd, (IntPtr)pin.Pointer, (nuint)buffer.Length); }
                    if (size >= 0) return checked((int)size);
                    int error = Marshal.GetLastPInvokeError();
                    if (error == 4) continue;
                    if (error != 11) throw new Win32Exception(error, "读取 TUN 失败");
                    Wait(fd, 1, ct);
                }
            }
            finally { Leave(); }
        }));
    }
    public ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken ct = default)
    {
        int fd = Enter();
        try
        {
            Check(ct);
            if (TryWrite(fd, buffer)) { Leave(); return ValueTask.CompletedTask; }
        }
        catch { Leave(); throw; }
        return new(Task.Run(() =>
        {
            try { do { Wait(fd, 4, ct); Check(ct); } while (!TryWrite(fd, buffer)); }
            finally { Leave(); }
        }));
    }
    private static unsafe bool TryWrite(int fd, ReadOnlyMemory<byte> buffer)
    {
        using var pin = buffer.Pin();
        nint size = write(fd, (IntPtr)pin.Pointer, (nuint)buffer.Length);
        if (size == buffer.Length) return true;
        if (size >= 0) throw new IOException("TUN packet write was incomplete");
        int error = Marshal.GetLastPInvokeError();
        if (error is 4 or 11) return false;
        throw new Win32Exception(error, "写入 TUN 失败");
    }
    public ValueTask DisposeAsync()
    {
        lock (_gate)
        {
            _closed = true;
            if (_active == 0) { handle.Dispose(); _drained.TrySetResult(); }
            return new(_drained.Task);
        }
    }
    [StructLayout(LayoutKind.Sequential)]
    private struct PollFd { public int Fd; public short Events; public short Returned; }
    [DllImport("libc", SetLastError = true)] private static extern int open(string path, int flags);
    [DllImport("libc", SetLastError = true)] private static extern int poll(ref PollFd fds, nuint count, int timeout);
    [DllImport("libc", SetLastError = true)] private static extern nint read(int fd, IntPtr buffer, nuint count);
    [DllImport("libc", SetLastError = true)] private static extern nint write(int fd, IntPtr buffer, nuint count);
}
