namespace Qcxt.Net.Quic.Security;

/// <summary>创建经过认证的客户端和服务端握手上下文，并提供数据包保护密钥。</summary>
public interface IQuicKeyProvider
{
    /// <summary>为出站连接创建握手。</summary>
    /// <param name="serverName">提供程序必须认证的逻辑对端名称。</param>
    /// <param name="cancellationToken">用于取消提供程序工作的标记。</param>
    /// <returns>新的连接级握手对象。</returns>
    ValueTask<IQuicHandshake> CreateClientAsync(string serverName, CancellationToken cancellationToken);

    /// <summary>为入站连接创建握手。</summary>
    /// <param name="cancellationToken">用于取消提供程序工作的标记。</param>
    /// <returns>新的连接级握手对象。</returns>
    ValueTask<IQuicHandshake> CreateServerAsync(CancellationToken cancellationToken);
}

/// <summary>表示连接级认证握手及其双向密钥时期。</summary>
public interface IQuicHandshake : IAsyncDisposable
{
    /// <summary>获取密钥协商是否已经完成。</summary>
    bool IsComplete { get; }
    /// <summary>获取远程身份或共享密钥是否已经通过认证。</summary>
    bool IsPeerAuthenticated { get; }
    /// <summary>在可用时获取 Initial 数据包密钥。</summary>
    QuicKeySet? InitialKeys { get; }
    /// <summary>在可用时获取 Handshake 数据包密钥。</summary>
    QuicKeySet? HandshakeKeys { get; }
    /// <summary>在可用时获取应用数据包密钥。</summary>
    QuicKeySet? ApplicationKeys { get; }

    /// <summary>处理对端握手字节并写入需要返回的响应字节。</summary>
    /// <param name="cryptoData">对端 CRYPTO 帧字节。</param>
    /// <param name="output">响应 CRYPTO 帧字节的目标区域。</param>
    /// <returns>处理结果及响应长度。</returns>
    HandshakeResult Process(ReadOnlySpan<byte> cryptoData, Span<byte> output);
}

/// <summary>报告握手字节处理结果。</summary>
public readonly record struct HandshakeResult
{
    /// <summary>初始化握手处理结果。</summary>
    /// <param name="bytesWritten">已写入的响应字节数。</param>
    /// <param name="keysChanged">一个或多个密钥时期是否发生变化。</param>
    /// <param name="completed">握手是否已经完成。</param>
    public HandshakeResult(int bytesWritten, bool keysChanged, bool completed) =>
        (BytesWritten, KeysChanged, Completed) = (bytesWritten, keysChanged, completed);

    /// <summary>获取已写入的响应字节数。</summary>
    public int BytesWritten { get; }
    /// <summary>获取数据包保护密钥是否发生变化。</summary>
    public bool KeysChanged { get; }
    /// <summary>获取握手是否已经完成。</summary>
    public bool Completed { get; }
}

/// <summary>拥有一个加密时期的双向 AEAD 密钥、初始向量和头部保护密钥。</summary>
public sealed class QuicKeySet : IDisposable
{
    /// <summary>将双向密钥材料复制到连接拥有且释放时清零的存储区。</summary>
    /// <param name="sendKey">本地 AEAD 密钥。</param>
    /// <param name="receiveKey">对端 AEAD 密钥。</param>
    /// <param name="sendIv">本地 12 字节数据包随机数初始向量。</param>
    /// <param name="receiveIv">对端 12 字节数据包随机数初始向量。</param>
    /// <param name="sendHeaderKey">本地头部保护密钥。</param>
    /// <param name="receiveHeaderKey">对端头部保护密钥。</param>
    public QuicKeySet(ReadOnlySpan<byte> sendKey, ReadOnlySpan<byte> receiveKey,
        ReadOnlySpan<byte> sendIv, ReadOnlySpan<byte> receiveIv,
        ReadOnlySpan<byte> sendHeaderKey, ReadOnlySpan<byte> receiveHeaderKey)
    {
        if (sendKey.Length is not (16 or 24 or 32)) throw new ArgumentException("An AES key must contain 16, 24, or 32 bytes.", nameof(sendKey));
        if (receiveKey.Length != sendKey.Length) throw new ArgumentException("Directional AES keys must use the same size.", nameof(receiveKey));
        if (sendIv.Length != 12) throw new ArgumentException("A packet IV must contain 12 bytes.", nameof(sendIv));
        if (receiveIv.Length != 12) throw new ArgumentException("A packet IV must contain 12 bytes.", nameof(receiveIv));
        if (sendHeaderKey.IsEmpty) throw new ArgumentException("A header-protection key is required.", nameof(sendHeaderKey));
        if (receiveHeaderKey.IsEmpty) throw new ArgumentException("A header-protection key is required.", nameof(receiveHeaderKey));
        SendKey = sendKey.ToArray(); ReceiveKey = receiveKey.ToArray();
        SendIv = sendIv.ToArray(); ReceiveIv = receiveIv.ToArray();
        SendHeaderKey = sendHeaderKey.ToArray(); ReceiveHeaderKey = receiveHeaderKey.ToArray();
    }

    /// <summary>
    /// 获取或设置Send Key。
    /// </summary>
    /// <returns>Send Key。</returns>
    internal byte[] SendKey { get; }
    /// <summary>
    /// 获取或设置Receive Key。
    /// </summary>
    /// <returns>Receive Key。</returns>
    internal byte[] ReceiveKey { get; }
    /// <summary>
    /// 获取或设置Send Iv。
    /// </summary>
    /// <returns>Send Iv。</returns>
    internal byte[] SendIv { get; }
    /// <summary>
    /// 获取或设置Receive Iv。
    /// </summary>
    /// <returns>Receive Iv。</returns>
    internal byte[] ReceiveIv { get; }
    /// <summary>
    /// 获取或设置Send Header Key。
    /// </summary>
    /// <returns>Send Header Key。</returns>
    internal byte[] SendHeaderKey { get; }
    /// <summary>
    /// 获取或设置Receive Header Key。
    /// </summary>
    /// <returns>Receive Header Key。</returns>
    internal byte[] ReceiveHeaderKey { get; }

    /// <summary>清零拥有的全部密钥材料。</summary>
    public void Dispose()
    {
        CryptographicOperations.ZeroMemory(SendKey); CryptographicOperations.ZeroMemory(ReceiveKey);
        CryptographicOperations.ZeroMemory(SendIv); CryptographicOperations.ZeroMemory(ReceiveIv);
        CryptographicOperations.ZeroMemory(SendHeaderKey); CryptographicOperations.ZeroMemory(ReceiveHeaderKey);
    }
}

/// <summary>未配置认证密钥提供程序时拒绝建立连接。</summary>
public sealed class MissingQuicKeyProvider : IQuicKeyProvider
{
    /// <summary>
    /// 执行Error操作。
    /// </summary>
    /// <returns>操作结果。</returns>
    private static NotSupportedException Error() => new("QUIC requires an authenticated key provider. No provider was configured.");
    /// <inheritdoc />
    public ValueTask<IQuicHandshake> CreateClientAsync(string serverName, CancellationToken cancellationToken) =>
        ValueTask.FromException<IQuicHandshake>(Error());
    /// <inheritdoc />
    public ValueTask<IQuicHandshake> CreateServerAsync(CancellationToken cancellationToken) =>
        ValueTask.FromException<IQuicHandshake>(Error());
}
