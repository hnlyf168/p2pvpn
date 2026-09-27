namespace Qcxt.Net.Quic.Configuration;

/// <summary>描述认证握手期间向对端通告的资源限制。</summary>
public readonly record struct QuicTransportParameters
{
    /// <summary>获取对端在收到窗口更新前可发送的最大流总字节数。</summary>
    public required ulong InitialConnectionWindow { get; init; }

    /// <summary>获取每条流初始允许发送的最大字节数。</summary>
    public required ulong InitialStreamWindow { get; init; }

    /// <summary>获取允许对端发起的双向流数量。</summary>
    public required ulong MaxBidirectionalStreams { get; init; }

    /// <summary>获取允许对端发起的单向流数量。</summary>
    public required ulong MaxUnidirectionalStreams { get; init; }

    /// <summary>获取对端可发送的最大不可靠 DATAGRAM 帧长度。</summary>
    public required ulong MaxDatagramFrameSize { get; init; }
}
