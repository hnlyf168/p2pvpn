namespace P2PVpnAndroid;

internal sealed record VpnSnapshot(bool Running, bool Connected, string Status, string VirtualIp, int PeerCount, string Paths);

internal static class VpnRuntimeState
{
    private static VpnSnapshot _current = new(false, false, "未连接", "--", 0, "--");
    public static VpnSnapshot Current => Volatile.Read(ref _current);
    public static event Action<VpnSnapshot>? Changed;
    public static void Publish(VpnSnapshot value)
    {
        Volatile.Write(ref _current, value);
        Changed?.Invoke(value);
    }
}
