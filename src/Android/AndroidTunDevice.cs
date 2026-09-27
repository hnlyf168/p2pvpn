using System.Runtime.InteropServices;
using System.Buffers;
using System.Threading.Channels;
using Android.OS;
using Qcxt.Net.P2P.Tunneling;

namespace P2PVpnAndroid;

internal sealed class AndroidTunDevice : IP2PTunDevice
{
    private readonly ParcelFileDescriptor.AutoCloseInputStream _input;
    private readonly ParcelFileDescriptor.AutoCloseOutputStream _output;
    private readonly Channel<Packet> _packets = Channel.CreateBounded<Packet>(new BoundedChannelOptions(64)
    {
        FullMode = BoundedChannelFullMode.Wait,
        SingleReader = true,
        SingleWriter = true
    });
    private readonly CancellationTokenSource _lifetime = new();
    private readonly Task _reader;
    private int _disposed;

    public AndroidTunDevice(ParcelFileDescriptor descriptor)
    {
        ParcelFileDescriptor outputDescriptor = ParcelFileDescriptor.Dup(descriptor.FileDescriptor!)
            ?? throw new IOException("无法复制 Android VPN 文件描述符");
        _input = new ParcelFileDescriptor.AutoCloseInputStream(descriptor);
        _output = new ParcelFileDescriptor.AutoCloseOutputStream(outputDescriptor);
        _reader = Task.Run(ReadPumpAsync);
    }

    public async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
    {
        Packet packet = await _packets.Reader.ReadAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            int count = Math.Min(packet.Length, buffer.Length);
            packet.Buffer.AsMemory(0, count).CopyTo(buffer);
            return count;
        }
        finally { ArrayPool<byte>.Shared.Return(packet.Buffer); }
    }

    public ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (!MemoryMarshal.TryGetArray(buffer, out ArraySegment<byte> segment) || segment.Array is null)
            segment = new ArraySegment<byte>(buffer.ToArray());
        _output.Write(segment.Array!, segment.Offset, segment.Count);
        return ValueTask.CompletedTask;
    }

    private async Task ReadPumpAsync()
    {
        Exception? error = null;
        try
        {
            while (!_lifetime.IsCancellationRequested)
            {
                byte[] buffer = ArrayPool<byte>.Shared.Rent(65_535);
                int count;
                try { count = _input.Read(buffer, 0, 65_535); }
                catch { ArrayPool<byte>.Shared.Return(buffer); throw; }
                if (count <= 0) { ArrayPool<byte>.Shared.Return(buffer); break; }
                try { await _packets.Writer.WriteAsync(new Packet(buffer, count), _lifetime.Token).ConfigureAwait(false); }
                catch { ArrayPool<byte>.Shared.Return(buffer); throw; }
            }
        }
        catch (System.OperationCanceledException) when (_lifetime.IsCancellationRequested) { }
        catch (Exception ex) { error = ex; }
        finally { _packets.Writer.TryComplete(error); }
    }

    public async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0) return;
        _lifetime.Cancel();
        try { _input.Close(); } catch { }
        try { _output.Close(); } catch { }
        try { await _reader.WaitAsync(TimeSpan.FromSeconds(2)).ConfigureAwait(false); } catch { }
        while (_packets.Reader.TryRead(out Packet packet)) ArrayPool<byte>.Shared.Return(packet.Buffer);
        _lifetime.Dispose();
    }

    private readonly record struct Packet(byte[] Buffer, int Length);
}
