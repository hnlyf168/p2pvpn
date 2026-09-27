using Qcxt.Net.Quic.Configuration;
using Qcxt.Net.Quic.Memory;

namespace Qcxt.Net.Quic.Protocol;

/// <summary>
/// 表示 Transport Parameter Codec，并提供相关数据或行为。
/// </summary>
internal static class TransportParameterCodec
{
    private const int MagicLength = 4;

    /// <summary>
    /// 执行Encode操作。
    /// </summary>
    /// <param name="server">server参数。</param>
    /// <param name="parameters">parameters参数。</param>
    /// <returns>操作结果。</returns>
    public static PooledSegment Encode(bool server, QuicTransportParameters parameters)
    {
        Span<byte> buffer = stackalloc byte[64];
        (server ? "QSH2"u8 : "QCH2"u8).CopyTo(buffer);
        int offset = MagicLength;
        if (!Write(buffer, ref offset, parameters.InitialConnectionWindow) ||
            !Write(buffer, ref offset, parameters.InitialStreamWindow) ||
            !Write(buffer, ref offset, parameters.MaxBidirectionalStreams) ||
            !Write(buffer, ref offset, parameters.MaxUnidirectionalStreams) ||
            !Write(buffer, ref offset, parameters.MaxDatagramFrameSize))
            throw new InvalidOperationException("A transport parameter exceeds the QUIC variable integer range.");
        return PooledSegment.CopyFrom(buffer[..offset]);
    }

    /// <summary>
    /// 尝试Decode。
    /// </summary>
    /// <param name="data">待处理的数据。</param>
    /// <param name="server">server参数。</param>
    /// <param name="parameters">parameters参数。</param>
    /// <returns>操作是否成功。</returns>
    public static bool TryDecode(ReadOnlySpan<byte> data, bool server, out QuicTransportParameters parameters)
    {
        parameters = default;
        ReadOnlySpan<byte> magic = server ? "QSH2"u8 : "QCH2"u8;
        if (data.Length < MagicLength || !data[..MagicLength].SequenceEqual(magic)) return false;
        data = data[MagicLength..];
        if (!Read(ref data, out ulong connectionWindow) || !Read(ref data, out ulong streamWindow) ||
            !Read(ref data, out ulong bidi) || !Read(ref data, out ulong uni) ||
            !Read(ref data, out ulong maxDatagram) || !data.IsEmpty) return false;
        if (connectionWindow < 64 * 1024 || streamWindow < 16 * 1024 ||
            bidi > 1_000_000 || uni > 1_000_000 || maxDatagram > 65_527) return false;
        parameters = new()
        {
            InitialConnectionWindow = connectionWindow,
            InitialStreamWindow = streamWindow,
            MaxBidirectionalStreams = bidi,
            MaxUnidirectionalStreams = uni,
            MaxDatagramFrameSize = maxDatagram
        };
        return true;
    }

    /// <summary>
    /// 执行Write操作。
    /// </summary>
    /// <param name="buffer">用于暂存数据的缓冲区。</param>
    /// <param name="offset">数据起始偏移量。</param>
    /// <param name="value">待处理的值。</param>
    /// <returns>操作结果。</returns>
    private static bool Write(Span<byte> buffer, ref int offset, ulong value)
    {
        if (!QuicVarInt.TryWrite(buffer[offset..], value, out int written)) return false;
        offset += written;
        return true;
    }

    /// <summary>
    /// 执行Read操作。
    /// </summary>
    /// <param name="data">待处理的数据。</param>
    /// <param name="value">待处理的值。</param>
    /// <returns>操作结果。</returns>
    private static bool Read(ref ReadOnlySpan<byte> data, out ulong value)
    {
        if (!QuicVarInt.TryRead(data, out value, out int consumed)) return false;
        data = data[consumed..];
        return true;
    }
}
