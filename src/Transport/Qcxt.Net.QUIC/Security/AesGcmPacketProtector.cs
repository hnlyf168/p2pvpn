namespace Qcxt.Net.Quic.Security;

/// <summary>
/// 表示 Aes Gcm Packet Protector，并提供相关数据或行为。
/// </summary>
internal sealed class AesGcmPacketProtector : IDisposable
{
    public const int TagLength = 16;
    private readonly AesGcm _send;
    private readonly AesGcm _receive;
    private readonly HeaderCipher _sendHeader;
    private readonly HeaderCipher _receiveHeader;
    private readonly byte[] _sendIv;
    private readonly byte[] _receiveIv;

    /// <summary>
    /// 初始化 <see cref="AesGcmPacketProtector"/> 类的新实例。
    /// </summary>
    /// <param name="keys">keys参数。</param>
    public AesGcmPacketProtector(QuicKeySet keys)
    {
        if (keys.SendIv.Length != 12 || keys.ReceiveIv.Length != 12)
            throw new ArgumentException("QUIC IV must contain 12 bytes", nameof(keys));
        _send = new AesGcm(keys.SendKey, TagLength);
        _receive = new AesGcm(keys.ReceiveKey, TagLength);
        _sendHeader = CreateHeaderCipher(keys.SendHeaderKey);
        _receiveHeader = CreateHeaderCipher(keys.ReceiveHeaderKey);
        _sendIv = keys.SendIv.ToArray(); _receiveIv = keys.ReceiveIv.ToArray();
    }

    /// <summary>
    /// 尝试Create Header Mask。
    /// </summary>
    /// <param name="sample">sample参数。</param>
    /// <param name="mask">mask参数。</param>
    /// <param name="sending">sending参数。</param>
    /// <returns>操作是否成功。</returns>
    public bool TryCreateHeaderMask(ReadOnlySpan<byte> sample, Span<byte> mask, bool sending)
    {
        if (sample.Length < 16 || mask.Length < 5) return false;
        (sending ? _sendHeader : _receiveHeader).CreateMask(sample, mask);
        return true;
    }

    /// <summary>
    /// 执行Encrypt操作。
    /// </summary>
    /// <param name="header">header参数。</param>
    /// <param name="plaintext">plaintext参数。</param>
    /// <param name="packetNumber">packet Number参数。</param>
    /// <param name="ciphertext">ciphertext参数。</param>
    /// <param name="tag">tag参数。</param>
    public void Encrypt(ReadOnlySpan<byte> header, ReadOnlySpan<byte> plaintext, long packetNumber,
        Span<byte> ciphertext, Span<byte> tag)
    {
        Span<byte> nonce = stackalloc byte[12]; BuildNonce(_sendIv, packetNumber, nonce);
        _send.Encrypt(nonce, plaintext, ciphertext, tag[..TagLength], header);
    }

    /// <summary>
    /// 尝试Decrypt。
    /// </summary>
    /// <param name="header">header参数。</param>
    /// <param name="ciphertext">ciphertext参数。</param>
    /// <param name="packetNumber">packet Number参数。</param>
    /// <param name="tag">tag参数。</param>
    /// <param name="plaintext">plaintext参数。</param>
    /// <returns>操作是否成功。</returns>
    public bool TryDecrypt(ReadOnlySpan<byte> header, ReadOnlySpan<byte> ciphertext, long packetNumber,
        ReadOnlySpan<byte> tag, Span<byte> plaintext)
    {
        if (tag.Length < TagLength || plaintext.Length < ciphertext.Length) return false;
        Span<byte> nonce = stackalloc byte[12]; BuildNonce(_receiveIv, packetNumber, nonce);
        try { _receive.Decrypt(nonce, ciphertext, tag[..TagLength], plaintext[..ciphertext.Length], header); return true; }
        catch (CryptographicException) { CryptographicOperations.ZeroMemory(plaintext[..ciphertext.Length]); return false; }
    }

    /// <summary>
    /// 执行Build Nonce操作。
    /// </summary>
    /// <param name="iv">iv参数。</param>
    /// <param name="packetNumber">packet Number参数。</param>
    /// <param name="nonce">nonce参数。</param>
    private static void BuildNonce(ReadOnlySpan<byte> iv, long packetNumber, Span<byte> nonce)
    {
        iv.CopyTo(nonce);
        ulong number = (ulong)packetNumber;
        for (int i = 11; i >= 4; i--) { nonce[i] ^= (byte)number; number >>= 8; }
    }

    /// <summary>
    /// 执行Dispose操作。
    /// </summary>
    public void Dispose()
    {
        _send.Dispose(); _receive.Dispose();
        _sendHeader.Dispose(); _receiveHeader.Dispose();
        CryptographicOperations.ZeroMemory(_sendIv); CryptographicOperations.ZeroMemory(_receiveIv);
    }

    /// <summary>
    /// 创建Header Cipher。
    /// </summary>
    /// <param name="key">key参数。</param>
    /// <returns>操作结果。</returns>
    private static HeaderCipher CreateHeaderCipher(ReadOnlySpan<byte> key) => new(key);

    // ECB header protection encrypts independent, fixed-size blocks. Keep one native
    // transform per direction/key epoch instead of creating an EVP context per packet.
    private sealed class HeaderCipher : IDisposable
    {
        private readonly Aes _cipher;
        private readonly ICryptoTransform _encryptor;
        private readonly byte[] _sample = new byte[16], _block = new byte[16];
        private readonly object _gate = new();
        private bool _disposed;
        internal HeaderCipher(ReadOnlySpan<byte> key)
        {
            _cipher = Aes.Create(); _cipher.Mode = CipherMode.ECB; _cipher.Padding = PaddingMode.None;
            _cipher.Key = key.ToArray(); _encryptor = _cipher.CreateEncryptor();
        }
        internal void CreateMask(ReadOnlySpan<byte> sample, Span<byte> mask)
        {
            lock (_gate)
            {
                ObjectDisposedException.ThrowIf(_disposed, this);
                try
                {
                    sample[..16].CopyTo(_sample);
                    if (_encryptor.TransformBlock(_sample, 0, 16, _block, 0) != 16)
                        throw new CryptographicException("Invalid AES header-protection block length.");
                    _block.AsSpan(0, 5).CopyTo(mask);
                }
                finally { CryptographicOperations.ZeroMemory(_sample); CryptographicOperations.ZeroMemory(_block); }
            }
        }
        public void Dispose()
        {
            lock (_gate)
            {
                if (_disposed) return; _disposed = true;
                _encryptor.Dispose(); _cipher.Dispose();
                CryptographicOperations.ZeroMemory(_sample); CryptographicOperations.ZeroMemory(_block);
            }
        }
    }
}
