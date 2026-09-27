using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using P2PVpn.Policy;

namespace P2PVpnClient;

internal static class LanInterfaceCollector
{
    internal static bool IsVirtualName(string name, string description)
    {
        string n = name.ToLowerInvariant(), d = description.ToLowerInvariant();
        return n == "lo" || new[] { "docker", "veth", "br-", "virbr", "cni", "flannel", "tun", "tap", "p2pvpn", "p2p vpn", "wg", "tailscale", "zt", "vethernet" }.Any(n.StartsWith) ||
            new[] { "wintun", "wireguard", "tap-windows", "hyper-v virtual", "virtualbox", "vmware virtual ethernet", "loopback", "docker", "p2p vpn", "vpn adapter" }.Any(d.Contains);
    }
    internal static LanInterfaceReport[]? Collect()
    {
        try
        {
            var result = new List<LanInterfaceReport>();
            foreach (var nic in NetworkInterface.GetAllNetworkInterfaces().OrderBy(n => n.Name, StringComparer.Ordinal))
            {
                try
                {
                    if (nic.NetworkInterfaceType is NetworkInterfaceType.Loopback or NetworkInterfaceType.Tunnel || IsVirtualName(nic.Name, nic.Description)) continue;
                    if (OperatingSystem.IsLinux() && !Directory.Exists("/sys/class/net/" + nic.Name + "/device")) continue;
                    if (OperatingSystem.IsLinux() && File.ReadAllText("/sys/class/net/" + nic.Name + "/type").Trim() == "280") continue; // CAN bus is not an IP LAN adapter.
#if !ANDROID
                    if (OperatingSystem.IsWindows() && !IsWindowsHardware(nic.Id)) continue;
#endif
                    // Android exposes physical transports as wlan/rmnet/ccmni devices.
                    if (OperatingSystem.IsAndroid() && !(nic.Name.StartsWith("wlan") || nic.Name.StartsWith("rmnet") || nic.Name.StartsWith("ccmni") || nic.Name.StartsWith("eth"))) continue;
                    var addresses = nic.GetIPProperties().UnicastAddresses
                        .Where(a => a.Address.AddressFamily is AddressFamily.InterNetwork or AddressFamily.InterNetworkV6 && !IPAddress.IsLoopback(a.Address))
                        .Select(a => new LanAddressReport { Address = a.Address.ToString(), PrefixLength = a.PrefixLength }).Take(16).ToArray();
                    result.Add(new() { Name = nic.Name, Description = nic.Description.Length > 256 ? nic.Description[..256] : nic.Description,
                        Type = nic.NetworkInterfaceType.ToString(), Status = nic.OperationalStatus.ToString(), Addresses = addresses });
                    if (result.Count == 32) break;
                }
                catch (Exception ex) when (ex is not OutOfMemoryException) { }
            }
            return result.ToArray();
        }
        catch (Exception ex) when (ex is not OutOfMemoryException) { return null; }
    }
#if !ANDROID
    [System.Runtime.Versioning.SupportedOSPlatform("windows")]
    private static bool IsWindowsHardware(string id)
    {
        // NCF_PHYSICAL (0x4), not the friendly name or Ethernet type, identifies
        // actual host adapters. Guest VM hardware NICs are kept; host virtual switches are not.
        using var root = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}");
        if (root is null) return false;
        foreach (string name in root.GetSubKeyNames())
        {
            using var key = root.OpenSubKey(name);
            if (string.Equals(key?.GetValue("NetCfgInstanceId") as string, id, StringComparison.OrdinalIgnoreCase))
                return key?.GetValue("Characteristics") is int flags && (flags & 4) != 0;
        }
        return false;
    }
#endif
}
