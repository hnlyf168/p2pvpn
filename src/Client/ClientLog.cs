using System.Text;

namespace P2PVpnClient;

/// <summary>记录低频服务、连接和打洞状态。</summary>
internal static class ClientLog
{
    private static readonly object Sync = new();

    /// <summary>以单行、线程安全和允许其他进程读取的方式追加日志。</summary>
    /// <param name="message">需要记录的中文诊断消息。</param>
    internal static void Write(string message)
    {
        try
        {
            lock (Sync)
            {
                Directory.CreateDirectory(ClientConfigStore.DirectoryPath);
                File.AppendAllText(ClientConfigStore.LogPath,
                    $"{DateTimeOffset.Now:yyyy-MM-dd HH:mm:ss.fff zzz} {message}{Environment.NewLine}", Encoding.UTF8);
            }
        }
        catch { }
    }
}
