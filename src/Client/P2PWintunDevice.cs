using Qcxt.Net.P2P.Tunneling;
using QuicSample;

namespace P2PSample;

/// <summary>将示例 Wintun 实现适配到 P2P 隧道设备约定。</summary>
internal sealed class P2PWintunDevice : IP2PTunDevice
{
    private readonly WintunDevice _device;

    /// <summary>围绕具有所有权的 Wintun 设备创建适配器。</summary>
    /// <param name="device">已初始化且所有权由适配器接管的 Wintun 设备。</param>
    public P2PWintunDevice(WintunDevice device) => _device = device ?? throw new ArgumentNullException(nameof(device));

    /// <inheritdoc />
    public ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default) =>
        _device.ReadAsync(buffer, cancellationToken);

    /// <inheritdoc />
    public ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default) =>
        _device.WriteAsync(buffer, cancellationToken);

    /// <inheritdoc />
    public ValueTask DisposeAsync() => _device.DisposeAsync();
}
