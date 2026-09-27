using Qcxt.Net.Quic.Protocol;

namespace Qcxt.Net.Quic.Security;

/// <summary>
/// 表示 Connection Key Derivation，并提供相关数据或行为。
/// </summary>
internal static class ConnectionKeyDerivation
{
    /// <summary>
    /// 执行Derive操作。
    /// </summary>
    /// <param name="source">source参数。</param>
    /// <param name="localId">local Id参数。</param>
    /// <param name="remoteId">remote Id参数。</param>
    /// <param name="isServer">is Server参数。</param>
    /// <returns>操作结果。</returns>
    public static QuicKeySet Derive(QuicKeySet source, QuicConnectionId localId,
        QuicConnectionId remoteId, bool isServer)
    {
        Span<byte> context = stackalloc byte[2 + (2 * QuicConnectionId.MaxLength)];
        QuicConnectionId clientId = isServer ? remoteId : localId;
        QuicConnectionId serverId = isServer ? localId : remoteId;
        int offset = 0;
        context[offset++] = clientId.Length;
        clientId.TryWrite(context[offset..]); offset += clientId.Length;
        context[offset++] = serverId.Length;
        serverId.TryWrite(context[offset..]); offset += serverId.Length;
        ReadOnlySpan<byte> connectionContext = context[..offset];

        byte[] sendKey = Expand(source.SendKey, connectionContext, "qcxt/aead", source.SendKey.Length);
        byte[] receiveKey = Expand(source.ReceiveKey, connectionContext, "qcxt/aead", source.ReceiveKey.Length);
        byte[] sendIv = Expand(source.SendIv, connectionContext, "qcxt/iv", 12);
        byte[] receiveIv = Expand(source.ReceiveIv, connectionContext, "qcxt/iv", 12);
        byte[] sendHeader = Expand(source.SendHeaderKey, connectionContext, "qcxt/hp", source.SendHeaderKey.Length);
        byte[] receiveHeader = Expand(source.ReceiveHeaderKey, connectionContext, "qcxt/hp", source.ReceiveHeaderKey.Length);
        try { return new(sendKey, receiveKey, sendIv, receiveIv, sendHeader, receiveHeader); }
        finally
        {
            CryptographicOperations.ZeroMemory(sendKey); CryptographicOperations.ZeroMemory(receiveKey);
            CryptographicOperations.ZeroMemory(sendIv); CryptographicOperations.ZeroMemory(receiveIv);
            CryptographicOperations.ZeroMemory(sendHeader); CryptographicOperations.ZeroMemory(receiveHeader);
            CryptographicOperations.ZeroMemory(context);
        }
    }

    /// <summary>
    /// 执行Expand操作。
    /// </summary>
    /// <param name="key">key参数。</param>
    /// <param name="context">当前操作上下文。</param>
    /// <param name="label">label参数。</param>
    /// <param name="length">数据数量。</param>
    /// <returns>操作结果。</returns>
    private static byte[] Expand(ReadOnlySpan<byte> key, ReadOnlySpan<byte> context, string label, int length)
    {
        byte[] input = new byte[Encoding.ASCII.GetByteCount(label) + context.Length];
        int labelLength = Encoding.ASCII.GetBytes(label, input);
        context.CopyTo(input.AsSpan(labelLength));
        byte[] digest = HMACSHA256.HashData(key, input);
        try { return digest.AsSpan(0, length).ToArray(); }
        finally
        {
            CryptographicOperations.ZeroMemory(input);
            CryptographicOperations.ZeroMemory(digest);
        }
    }
}
