namespace Qcxt.Net.Quic.Protocol;

using Qcxt.Net.Quic.Recovery;

/// <summary>
/// 表示 Quic Frame Writer，并提供相关数据或行为。
/// </summary>
internal ref struct QuicFrameWriter
{
    private Span<byte> _remaining;
    private readonly int _capacity;
    /// <summary>
    /// 初始化 <see cref="QuicFrameWriter"/> 类的新实例。
    /// </summary>
    /// <param name="destination">destination参数。</param>
    public QuicFrameWriter(Span<byte> destination) { _remaining = destination; _capacity = destination.Length; }
    /// <summary>
    /// 获取或设置Written。
    /// </summary>
    /// <returns>Written。</returns>
    public int Written => _capacity - _remaining.Length;

    /// <summary>
    /// 执行Write Ping操作。
    /// </summary>
    /// <returns>操作结果。</returns>
    public bool WritePing() => WriteVar(1);
    /// <summary>
    /// 执行Write Handshake操作。
    /// </summary>
    /// <param name="data">待处理的数据。</param>
    /// <returns>操作结果。</returns>
    public bool WriteHandshake(ReadOnlySpan<byte> data) => WriteCrypto(0, data);
    /// <summary>
    /// 执行Write Crypto操作。
    /// </summary>
    /// <param name="offset">数据起始偏移量。</param>
    /// <param name="data">待处理的数据。</param>
    /// <returns>操作结果。</returns>
    public bool WriteCrypto(ulong offset, ReadOnlySpan<byte> data) =>
        WriteVar(6) && WriteVar(offset) && WriteVar((ulong)data.Length) && WriteBytes(data);
    /// <summary>
    /// 执行Write Stream操作。
    /// </summary>
    /// <param name="id">唯一标识。</param>
    /// <param name="offset">数据起始偏移量。</param>
    /// <param name="data">待处理的数据。</param>
    /// <param name="fin">fin参数。</param>
    /// <returns>操作结果。</returns>
    public bool WriteStream(ulong id, ulong offset, ReadOnlySpan<byte> data, bool fin) =>
        WriteVar(fin ? 0x0fUL : 0x0eUL) && WriteVar(id) && WriteVar(offset) &&
        WriteVar((ulong)data.Length) && WriteBytes(data);
    /// <summary>
    /// 执行Write Ack操作。
    /// </summary>
    /// <param name="largest">largest参数。</param>
    /// <param name="firstRange">first Range参数。</param>
    /// <returns>操作结果。</returns>
    public bool WriteAck(ulong largest, ulong firstRange) =>
        WriteVar(2) && WriteVar(largest) && WriteVar(0) && WriteVar(0) && WriteVar(firstRange);
    /// <summary>
    /// 执行Write Ack操作。
    /// </summary>
    /// <param name="ranges">ranges参数。</param>
    /// <returns>操作结果。</returns>
    public bool WriteAck(AckRangeSet ranges)
    {
        if (ranges.Count == 0) return false;
        var first = ranges[0];
        int fixedLength = QuicVarInt.GetEncodedLength(2) +
            QuicVarInt.GetEncodedLength((ulong)first.End) +
            QuicVarInt.GetEncodedLength(0) +
            QuicVarInt.GetEncodedLength((ulong)(first.End - first.Start));
        int selectedRanges = 1;
        int pairsLength = 0;
        long measuredPreviousStart = first.Start;
        for (int i = 1; i < ranges.Count; i++)
        {
            var current = ranges[i];
            long gap = measuredPreviousStart - current.End - 2;
            if (gap < 0) break;
            int nextPairsLength = pairsLength + QuicVarInt.GetEncodedLength((ulong)gap) +
                QuicVarInt.GetEncodedLength((ulong)(current.End - current.Start));
            int totalLength = fixedLength + QuicVarInt.GetEncodedLength((ulong)i) + nextPairsLength;
            if (totalLength > _remaining.Length) break;
            pairsLength = nextPairsLength;
            selectedRanges++;
            measuredPreviousStart = current.Start;
        }
        if (fixedLength + QuicVarInt.GetEncodedLength((ulong)(selectedRanges - 1)) +
            pairsLength > _remaining.Length) return false;
        if (!WriteVar(2) || !WriteVar((ulong)first.End) || !WriteVar(0) ||
            !WriteVar((ulong)(selectedRanges - 1)) || !WriteVar((ulong)(first.End - first.Start))) return false;
        long previousStart = first.Start;
        for (int i = 1; i < selectedRanges; i++)
        {
            var current = ranges[i];
            long gap = previousStart - current.End - 2;
            if (gap < 0 || !WriteVar((ulong)gap) || !WriteVar((ulong)(current.End - current.Start))) return false;
            previousStart = current.Start;
        }
        return true;
    }
    /// <summary>
    /// 执行Write Max Data操作。
    /// </summary>
    /// <param name="maximum">maximum参数。</param>
    /// <returns>操作结果。</returns>
    public bool WriteMaxData(ulong maximum) => WriteVar(0x10) && WriteVar(maximum);
    /// <summary>
    /// 执行Write Max Stream Data操作。
    /// </summary>
    /// <param name="id">唯一标识。</param>
    /// <param name="maximum">maximum参数。</param>
    /// <returns>操作结果。</returns>
    public bool WriteMaxStreamData(ulong id, ulong maximum) => WriteVar(0x11) && WriteVar(id) && WriteVar(maximum);
    /// <summary>
    /// 执行Write Datagram操作。
    /// </summary>
    /// <param name="data">待处理的数据。</param>
    /// <returns>操作结果。</returns>
    public bool WriteDatagram(ReadOnlySpan<byte> data) =>
        WriteVar(0x31) && WriteVar((ulong)data.Length) && WriteBytes(data);
    /// <summary>
    /// 执行Write Close操作。
    /// </summary>
    /// <param name="errorCode">error Code参数。</param>
    /// <param name="reason">reason参数。</param>
    /// <returns>操作结果。</returns>
    public bool WriteClose(ulong errorCode, ReadOnlySpan<byte> reason) =>
        WriteVar(0x1c) && WriteVar(errorCode) && WriteVar(0) && WriteVar((ulong)reason.Length) && WriteBytes(reason);

    /// <summary>
    /// 执行Write Var操作。
    /// </summary>
    /// <param name="value">待处理的值。</param>
    /// <returns>操作结果。</returns>
    private bool WriteVar(ulong value)
    {
        if (!QuicVarInt.TryWrite(_remaining, value, out int written)) return false;
        _remaining = _remaining[written..]; return true;
    }
    /// <summary>
    /// 执行Write Bytes操作。
    /// </summary>
    /// <param name="value">待处理的值。</param>
    /// <returns>操作结果。</returns>
    private bool WriteBytes(ReadOnlySpan<byte> value)
    {
        if (value.Length > _remaining.Length) return false;
        value.CopyTo(_remaining); _remaining = _remaining[value.Length..]; return true;
    }
}
