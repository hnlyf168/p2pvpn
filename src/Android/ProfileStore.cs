using Android.Content;
using Android.Security.Keystore;
using Java.Security;
using Javax.Crypto;
using Javax.Crypto.Spec;
using System.Text.Json;

namespace P2PVpnAndroid;

internal static partial class ProfileStore
{
    private static readonly object Gate = new();
    private const string Alias = "edge-vpn-device-v1";
    private static string FilePath(Context context) => Path.Combine(context.FilesDir!.AbsolutePath, "device-profile.enc");

    private static IKey Key()
    {
        using var store = KeyStore.GetInstance("AndroidKeyStore")!;
        store.Load(null);
        if (store.ContainsAlias(Alias)) return store.GetKey(Alias, null)!;
        using var generator = KeyGenerator.GetInstance("AES", "AndroidKeyStore")!;
        using var spec = new KeyGenParameterSpec.Builder(Alias, KeyStorePurpose.Encrypt | KeyStorePurpose.Decrypt)
            .SetBlockModes(KeyProperties.BlockModeGcm)
            .SetEncryptionPaddings(KeyProperties.EncryptionPaddingNone)
            .SetRandomizedEncryptionRequired(true).Build();
        generator.Init(spec);
        return generator.GenerateKey()!;
    }

    public static VpnProfile Load(Context context)
    {
        lock (Gate)
        {
            string path = FilePath(context);
            if (!File.Exists(path)) return new();
            byte[] bytes = File.ReadAllBytes(path);
            if (bytes.Length is < 29 or > 65536) throw new InvalidDataException("设备配置已损坏，请重新添加设备。");
            using var key = Key();
            using var cipher = Cipher.GetInstance("AES/GCM/NoPadding")!;
            using var spec = new GCMParameterSpec(128, bytes[..12]);
            cipher.Init(CipherMode.DecryptMode, key, spec);
            byte[] plain = cipher.DoFinal(bytes[12..])!;
            try { return JsonSerializer.Deserialize(plain, VpnJsonContext.Default.VpnProfile) ?? throw new InvalidDataException("配置为空。"); }
            finally { System.Security.Cryptography.CryptographicOperations.ZeroMemory(plain); }
        }
    }

    public static void Save(Context context, VpnProfile profile)
    {
        Validate(profile);
        lock (Gate)
        {
            using var key = Key();
            using var cipher = Cipher.GetInstance("AES/GCM/NoPadding")!;
            cipher.Init(CipherMode.EncryptMode, key);
            byte[] plain = JsonSerializer.SerializeToUtf8Bytes(profile, VpnJsonContext.Default.VpnProfile);
            byte[] encrypted;
            try { encrypted = cipher.DoFinal(plain)!; }
            finally { System.Security.Cryptography.CryptographicOperations.ZeroMemory(plain); }
            byte[] iv = cipher.GetIV()!;
            if (iv.Length != 12) throw new InvalidDataException("设备密钥的加密参数无效。");
            string path = FilePath(context);
            File.WriteAllBytes(path + ".tmp", [.. iv, .. encrypted]);
            File.Move(path + ".tmp", path, true);
        }
    }

    public static bool ReplaceIfCurrent(Context context, string expectedFingerprint, VpnProfile profile)
    {
        lock (Gate)
        {
            if (ControlApi.Fingerprint(Load(context)) != expectedFingerprint) return false;
            Save(context, profile);
            return true;
        }
    }

    public static void Clear(Context context)
    {
        lock (Gate) { File.Delete(FilePath(context)); File.Delete(FilePath(context) + ".tmp"); }
    }
}
