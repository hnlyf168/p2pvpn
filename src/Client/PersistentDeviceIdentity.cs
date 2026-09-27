using System.Net.NetworkInformation;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Win32;

namespace P2PVpnClient;

/// <summary>创建一次并永久保存不随服务重启和网卡顺序变化的客户端 ID。</summary>
internal static class PersistentDeviceIdentity
{
    /// <summary>读取持久 ID；首次安装时结合 MachineGuid、机器名和物理 MAC 生成。</summary>
    /// <returns>以 node 开头且不泄露原始硬件标识的稳定 ID。</returns>
    internal static string GetOrCreate()
    {
        ClientConfigStore.ProtectDirectory();
        if (File.Exists(ClientConfigStore.DeviceIdPath))
        {
            string existing = File.ReadAllText(ClientConfigStore.DeviceIdPath, Encoding.UTF8).Trim();
            if (existing.StartsWith("node-", StringComparison.Ordinal) && existing.Length is >= 21 and <= 80)
                return existing;
            throw new InvalidDataException("持久客户端 ID 文件已损坏。");
        }

        string machineGuid = OperatingSystem.IsWindows()
            ? Convert.ToString(Registry.GetValue(
                @"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Cryptography", "MachineGuid", "")) ?? string.Empty
            : ReadLinuxMachineId();
        string[] macs = NetworkInterface.GetAllNetworkInterfaces()
            .Where(static item => item.NetworkInterfaceType is NetworkInterfaceType.Ethernet or
                NetworkInterfaceType.Wireless80211 or NetworkInterfaceType.GigabitEthernet or
                NetworkInterfaceType.FastEthernetFx or NetworkInterfaceType.FastEthernetT)
            .Select(static item => Convert.ToHexString(item.GetPhysicalAddress().GetAddressBytes()))
            .Where(static value => value.Length >= 12).Order(StringComparer.Ordinal).ToArray();
        string material = machineGuid + "|" + Environment.MachineName + "|" + string.Join('|', macs);
        string id = "node-" + Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(material)).AsSpan(0, 16))
            .ToLowerInvariant();
        using (var stream = new FileStream(ClientConfigStore.DeviceIdPath, FileMode.CreateNew,
            FileAccess.Write, FileShare.Read, 4096, FileOptions.WriteThrough))
        using (var writer = new StreamWriter(stream, new UTF8Encoding(false)))
        {
            writer.Write(id);
            writer.Flush();
            stream.Flush(true);
        }
        return id;
    }

    /// <summary>
    /// 执行Read Linux Machine Id操作。
    /// </summary>
    /// <returns>操作结果。</returns>
    private static string ReadLinuxMachineId()
    {
        foreach (string path in new[] { "/etc/machine-id", "/var/lib/dbus/machine-id" })
            if (File.Exists(path)) return File.ReadAllText(path, Encoding.UTF8).Trim();
        return Environment.MachineName;
    }
}
