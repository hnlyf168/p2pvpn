namespace Qcxt.Net.Quic.Protocol;

/// <summary>
/// 表示 Quic Frame Kind，并提供相关数据或行为。
/// </summary>
internal enum QuicFrameKind : byte
{
    /// <summary>
    /// 表示Padding选项。
    /// </summary>
    Padding, /// <summary>
    /// 表示Ping选项。
    /// </summary>
    Ping, /// <summary>
    /// 表示Ack选项。
    /// </summary>
    Ack, /// <summary>
    /// 表示Reset Stream选项。
    /// </summary>
    ResetStream, /// <summary>
    /// 表示Stop Sending选项。
    /// </summary>
    StopSending, /// <summary>
    /// 表示Crypto选项。
    /// </summary>
    Crypto, /// <summary>
    /// 表示New Token选项。
    /// </summary>
    NewToken, /// <summary>
    /// 表示Stream选项。
    /// </summary>
    Stream,
    /// <summary>
    /// 表示Max Data选项。
    /// </summary>
    MaxData, /// <summary>
    /// 表示Max Stream Data选项。
    /// </summary>
    MaxStreamData, /// <summary>
    /// 表示Max Streams选项。
    /// </summary>
    MaxStreams, /// <summary>
    /// 表示Data Blocked选项。
    /// </summary>
    DataBlocked, /// <summary>
    /// 表示Stream Data Blocked选项。
    /// </summary>
    StreamDataBlocked, /// <summary>
    /// 表示Streams Blocked选项。
    /// </summary>
    StreamsBlocked,
    /// <summary>
    /// 表示New Connection Id选项。
    /// </summary>
    NewConnectionId, /// <summary>
    /// 表示Retire Connection Id选项。
    /// </summary>
    RetireConnectionId, /// <summary>
    /// 表示Path Challenge选项。
    /// </summary>
    PathChallenge, /// <summary>
    /// 表示Path Response选项。
    /// </summary>
    PathResponse, /// <summary>
    /// 表示Connection Close选项。
    /// </summary>
    ConnectionClose,
    /// <summary>
    /// 表示Handshake Done选项。
    /// </summary>
    HandshakeDone, /// <summary>
    /// 表示Datagram选项。
    /// </summary>
    Datagram
}

/// <summary>
/// 表示 Quic Frame View，并提供相关数据或行为。
/// </summary>
internal readonly ref struct QuicFrameView
{
    /// <summary>
    /// 初始化 <see cref="QuicFrameView"/> 类的新实例。
    /// </summary>
    /// <param name="kind">kind参数。</param>
    /// <param name="a">a参数。</param>
    /// <param name="b">b参数。</param>
    /// <param name="c">c参数。</param>
    /// <param name="flag">flag参数。</param>
    /// <param name="data">待处理的数据。</param>
    public QuicFrameView(QuicFrameKind kind, ulong a = 0, ulong b = 0, ulong c = 0,
        bool flag = false, ReadOnlySpan<byte> data = default)
    { Kind = kind; A = a; B = b; C = c; Flag = flag; Data = data; }
    /// <summary>
    /// 获取或设置Kind。
    /// </summary>
    /// <returns>Kind。</returns>
    public QuicFrameKind Kind { get; }
    /// <summary>
    /// 获取或设置A。
    /// </summary>
    /// <returns>A。</returns>
    public ulong A { get; }
    /// <summary>
    /// 获取或设置B。
    /// </summary>
    /// <returns>B。</returns>
    public ulong B { get; }
    /// <summary>
    /// 获取或设置C。
    /// </summary>
    /// <returns>C。</returns>
    public ulong C { get; }
    /// <summary>
    /// 获取或设置Flag。
    /// </summary>
    /// <returns>Flag。</returns>
    public bool Flag { get; }
    /// <summary>
    /// 获取或设置Data。
    /// </summary>
    /// <returns>Data。</returns>
    public ReadOnlySpan<byte> Data { get; }
}

/// <summary>
/// 表示 Quic Frame Reader，并提供相关数据或行为。
/// </summary>
internal ref struct QuicFrameReader
{
    private ReadOnlySpan<byte> _remaining;
    /// <summary>
    /// 初始化 <see cref="QuicFrameReader"/> 类的新实例。
    /// </summary>
    /// <param name="payload">payload参数。</param>
    public QuicFrameReader(ReadOnlySpan<byte> payload) => _remaining = payload;
    /// <summary>
    /// 获取或设置Remaining。
    /// </summary>
    /// <returns>Remaining。</returns>
    public int Remaining => _remaining.Length;

    /// <summary>
    /// 尝试Read。
    /// </summary>
    /// <param name="frame">frame参数。</param>
    /// <returns>操作是否成功。</returns>
    public bool TryRead(out QuicFrameView frame)
    {
        frame = default;
        if (!ReadVar(out ulong type)) return false;
        if (type == 0)
        {
            int count = 1;
            while (!_remaining.IsEmpty && _remaining[0] == 0) { _remaining = _remaining[1..]; count++; }
            frame = new(QuicFrameKind.Padding, (ulong)count); return true;
        }
        if (type == 1) { frame = new(QuicFrameKind.Ping); return true; }
        if (type is 2 or 3) return ReadAck(type == 3, out frame);
        if (type == 4 && Read3(out var a, out var b, out var c)) { frame = new(QuicFrameKind.ResetStream, a, b, c); return true; }
        if (type == 5 && Read2(out a, out b)) { frame = new(QuicFrameKind.StopSending, a, b); return true; }
        if (type == 6 && Read2(out a, out b) && Take(b, out var data)) { frame = new(QuicFrameKind.Crypto, a, b, data: data); return true; }
        if (type == 7 && ReadVar(out a) && Take(a, out data)) { frame = new(QuicFrameKind.NewToken, a, data: data); return true; }
        if (type is >= 8 and <= 15) return ReadStream(type, out frame);
        if (type == 0x10 && ReadVar(out a)) { frame = new(QuicFrameKind.MaxData, a); return true; }
        if (type == 0x11 && Read2(out a, out b)) { frame = new(QuicFrameKind.MaxStreamData, a, b); return true; }
        if (type is 0x12 or 0x13 && ReadVar(out a)) { frame = new(QuicFrameKind.MaxStreams, a, flag: type == 0x12); return true; }
        if (type == 0x14 && ReadVar(out a)) { frame = new(QuicFrameKind.DataBlocked, a); return true; }
        if (type == 0x15 && Read2(out a, out b)) { frame = new(QuicFrameKind.StreamDataBlocked, a, b); return true; }
        if (type is 0x16 or 0x17 && ReadVar(out a)) { frame = new(QuicFrameKind.StreamsBlocked, a, flag: type == 0x16); return true; }
        if (type == 0x19 && ReadVar(out a)) { frame = new(QuicFrameKind.RetireConnectionId, a); return true; }
        if (type is 0x1a or 0x1b && Take(8, out data)) { frame = new(type == 0x1a ? QuicFrameKind.PathChallenge : QuicFrameKind.PathResponse, data: data); return true; }
        if (type is 0x1c or 0x1d) return ReadClose(type == 0x1d, out frame);
        if (type == 0x1e) { frame = new(QuicFrameKind.HandshakeDone); return true; }
        if (type is 0x30 or 0x31)
        {
            ulong length = (ulong)_remaining.Length;
            if (type == 0x31 && !ReadVar(out length)) return false;
            if (!Take(length, out data)) return false;
            frame = new(QuicFrameKind.Datagram, length, data: data); return true;
        }
        return false;
    }

    /// <summary>
    /// 执行Read Stream操作。
    /// </summary>
    /// <param name="type">type参数。</param>
    /// <param name="frame">frame参数。</param>
    /// <returns>操作结果。</returns>
    private bool ReadStream(ulong type, out QuicFrameView frame)
    {
        frame = default;
        if (!ReadVar(out var id)) return false;
        ulong offset = 0;
        if ((type & 4) != 0 && !ReadVar(out offset)) return false;
        ulong length = (ulong)_remaining.Length;
        if ((type & 2) != 0 && !ReadVar(out length)) return false;
        if (!Take(length, out var data)) return false;
        frame = new(QuicFrameKind.Stream, id, offset, length, (type & 1) != 0, data); return true;
    }

    /// <summary>
    /// 执行Read Ack操作。
    /// </summary>
    /// <param name="ecn">ecn参数。</param>
    /// <param name="frame">frame参数。</param>
    /// <returns>操作结果。</returns>
    private bool ReadAck(bool ecn, out QuicFrameView frame)
    {
        frame = default;
        if (!Read3(out var largest, out var delay, out var count) || !ReadVar(out var first)) return false;
        if (first > largest || count > (ulong)(_remaining.Length / 2)) return false;
        ReadOnlySpan<byte> ranges = _remaining;
        for (ulong i = 0; i < count; i++) if (!Read2(out _, out _)) return false;
        ranges = ranges[..(ranges.Length - _remaining.Length)];
        if (ecn && !Read3(out _, out _, out _)) return false;
        frame = new(QuicFrameKind.Ack, largest, delay, first, ecn, ranges); return true;
    }

    /// <summary>
    /// 执行Read Close操作。
    /// </summary>
    /// <param name="app">app参数。</param>
    /// <param name="frame">frame参数。</param>
    /// <returns>操作结果。</returns>
    private bool ReadClose(bool app, out QuicFrameView frame)
    {
        frame = default;
        if (!ReadVar(out var error)) return false;
        ulong trigger = 0;
        if (!app && !ReadVar(out trigger)) return false;
        if (!ReadVar(out var length) || !Take(length, out var reason)) return false;
        frame = new(QuicFrameKind.ConnectionClose, error, trigger, length, app, reason); return true;
    }

    /// <summary>
    /// 执行Read Var操作。
    /// </summary>
    /// <param name="value">待处理的值。</param>
    /// <returns>操作结果。</returns>
    private bool ReadVar(out ulong value)
    {
        if (!QuicVarInt.TryRead(_remaining, out value, out int read)) return false;
        _remaining = _remaining[read..]; return true;
    }
    /// <summary>
    /// 执行Read2操作。
    /// </summary>
    /// <param name="a">a参数。</param>
    /// <param name="b">b参数。</param>
    /// <returns>操作结果。</returns>
    private bool Read2(out ulong a, out ulong b) { a = b = 0; return ReadVar(out a) && ReadVar(out b); }
    /// <summary>
    /// 执行Read3操作。
    /// </summary>
    /// <param name="a">a参数。</param>
    /// <param name="b">b参数。</param>
    /// <param name="c">c参数。</param>
    /// <returns>操作结果。</returns>
    private bool Read3(out ulong a, out ulong b, out ulong c) { a = b = c = 0; return ReadVar(out a) && ReadVar(out b) && ReadVar(out c); }
    /// <summary>
    /// 执行Take操作。
    /// </summary>
    /// <param name="length">数据数量。</param>
    /// <param name="data">待处理的数据。</param>
    /// <returns>操作结果。</returns>
    private bool Take(ulong length, out ReadOnlySpan<byte> data)
    {
        data = default;
        if (length > (ulong)_remaining.Length) return false;
        int count = (int)length; data = _remaining[..count]; _remaining = _remaining[count..]; return true;
    }
}
