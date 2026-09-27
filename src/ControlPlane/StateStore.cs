using System.Text.Json;
using EdgeVpn;
namespace EdgeVpn.ControlPlane;
public sealed class StateStore : IDisposable
{
    private readonly object sync = new();
    private readonly string path;
    private readonly FileStream processLock;
    private static readonly JsonSerializerOptions Json = new() { WriteIndented = true };
    public StateStore(IConfiguration config, IHostEnvironment environment)
    {
        var directory = Path.GetFullPath(config["DataDirectory"] ?? Path.Combine(environment.ContentRootPath, "data"));
        Directory.CreateDirectory(directory);
        if (!OperatingSystem.IsWindows()) File.SetUnixFileMode(directory, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        path = Path.Combine(directory, "state.json");
        processLock = new FileStream(path + ".lock", FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None);
        if (!File.Exists(path)) Save(new Database());
        _ = Load(); // Corrupt state fails startup; never silently reset accounts or keys.
    }
    private Database Load() => JsonSerializer.Deserialize<Database>(File.ReadAllText(path)) ?? throw new InvalidDataException("Empty state");
    public T Read<T>(Func<Database, T> action) { lock (sync) return action(Load()); }
    public T Write<T>(Func<Database, T> action)
    {
        lock (sync) { var state = Load(); var result = action(state); Save(state); return result; }
    }
    private void Save(Database state)
    {
        string temp = path + ".tmp";
        using (var stream = new FileStream(temp, FileMode.Create, FileAccess.Write, FileShare.None, 4096, FileOptions.WriteThrough))
        { JsonSerializer.Serialize(stream, state, Json); stream.Flush(true); }
        if (!OperatingSystem.IsWindows()) File.SetUnixFileMode(temp, UnixFileMode.UserRead | UnixFileMode.UserWrite);
        File.Move(temp, path, true);
    }
    public void Dispose() => processLock.Dispose();
}
