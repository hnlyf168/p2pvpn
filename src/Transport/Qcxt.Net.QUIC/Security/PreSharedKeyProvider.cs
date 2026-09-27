namespace Qcxt.Net.Quic.Security;

/// <summary>
/// 从预共享密钥派生经过认证的数据包密钥，适用于受控网络和测试。
/// 此提供程序不是 TLS，不能与互联网标准 QUIC 端点互通。
/// </summary>
public sealed class PreSharedKeyProvider : IQuicKeyProvider, IDisposable
{
    private readonly byte[] _secret;
    private int _disposed;

    /// <summary>
    /// 使用至少 32 字节密码学随机秘密材料初始化提供程序。
    /// </summary>
    /// <param name="secret">双方端点共同持有的共享密钥。</param>
    public PreSharedKeyProvider(ReadOnlySpan<byte> secret)
    {
        if (secret.Length < 32)
            throw new ArgumentException("The pre-shared secret must contain at least 32 bytes.", nameof(secret));
        _secret = secret.ToArray();
    }

    /// <inheritdoc />
    public ValueTask<IQuicHandshake> CreateClientAsync(string serverName, CancellationToken cancellationToken)
    {
        ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) != 0, this);
        cancellationToken.ThrowIfCancellationRequested();
        return ValueTask.FromResult<IQuicHandshake>(new Handshake(_secret, isServer: false));
    }

    /// <inheritdoc />
    public ValueTask<IQuicHandshake> CreateServerAsync(CancellationToken cancellationToken)
    {
        ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) != 0, this);
        cancellationToken.ThrowIfCancellationRequested();
        return ValueTask.FromResult<IQuicHandshake>(new Handshake(_secret, isServer: true));
    }

    /// <summary>清零提供程序持有的共享密钥副本。</summary>
    public void Dispose()
    {
        if (Interlocked.Exchange(ref _disposed, 1) == 0) CryptographicOperations.ZeroMemory(_secret);
    }

    /// <summary>
/// 表示 Handshake，并提供相关数据或行为。
/// </summary>
private sealed class Handshake : IQuicHandshake
    {
        private readonly QuicKeySet _keys;
        /// <summary>
        /// 初始化 <see cref="Handshake"/> 类的新实例。
        /// </summary>
        /// <param name="secret">secret参数。</param>
        /// <param name="isServer">is Server参数。</param>
        public Handshake(byte[] secret, bool isServer)
        {
            byte[] clientKey = Derive(secret, "qcxt quic client key", 16);
            byte[] serverKey = Derive(secret, "qcxt quic server key", 16);
            byte[] clientIv = Derive(secret, "qcxt quic client iv", 12);
            byte[] serverIv = Derive(secret, "qcxt quic server iv", 12);
            byte[] clientHp = Derive(secret, "qcxt quic client hp", 16);
            byte[] serverHp = Derive(secret, "qcxt quic server hp", 16);
            _keys = isServer
                ? new(serverKey, clientKey, serverIv, clientIv, serverHp, clientHp)
                : new(clientKey, serverKey, clientIv, serverIv, clientHp, serverHp);
            CryptographicOperations.ZeroMemory(clientKey); CryptographicOperations.ZeroMemory(serverKey);
            CryptographicOperations.ZeroMemory(clientIv); CryptographicOperations.ZeroMemory(serverIv);
            CryptographicOperations.ZeroMemory(clientHp); CryptographicOperations.ZeroMemory(serverHp);
        }

        /// <summary>
        /// 获取或设置Is Complete。
        /// </summary>
        /// <returns>Is Complete。</returns>
        public bool IsComplete => true;
        /// <summary>
        /// 获取或设置Is Peer Authenticated。
        /// </summary>
        /// <returns>Is Peer Authenticated。</returns>
        public bool IsPeerAuthenticated => true;
        /// <summary>
        /// 获取或设置Initial Keys。
        /// </summary>
        /// <returns>Initial Keys。</returns>
        public QuicKeySet? InitialKeys => _keys;
        /// <summary>
        /// 获取或设置Handshake Keys。
        /// </summary>
        /// <returns>Handshake Keys。</returns>
        public QuicKeySet? HandshakeKeys => _keys;
        /// <summary>
        /// 获取或设置Application Keys。
        /// </summary>
        /// <returns>Application Keys。</returns>
        public QuicKeySet? ApplicationKeys => _keys;
        /// <summary>
        /// 执行Process操作。
        /// </summary>
        /// <param name="cryptoData">crypto Data参数。</param>
        /// <param name="output">output参数。</param>
        /// <returns>操作结果。</returns>
        public HandshakeResult Process(ReadOnlySpan<byte> cryptoData, Span<byte> output) => new(0, false, true);
        /// <summary>
        /// 执行Dispose操作。
        /// </summary>
        /// <returns>操作结果。</returns>
        public ValueTask DisposeAsync() { _keys.Dispose(); return ValueTask.CompletedTask; }

        /// <summary>
        /// 执行Derive操作。
        /// </summary>
        /// <param name="secret">secret参数。</param>
        /// <param name="label">label参数。</param>
        /// <param name="length">数据数量。</param>
        /// <returns>操作结果。</returns>
        private static byte[] Derive(byte[] secret, string label, int length)
        {
            using var hmac = new HMACSHA256(secret);
            byte[] digest = hmac.ComputeHash(System.Text.Encoding.ASCII.GetBytes(label));
            byte[] result = digest.AsSpan(0, length).ToArray();
            CryptographicOperations.ZeroMemory(digest);
            return result;
        }
    }
}
