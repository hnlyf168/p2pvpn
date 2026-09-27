namespace Qcxt.Net.Quic;

/// <summary>指定不可靠 DATAGRAM 在本地发送调度器中的服务等级。</summary>
public enum QuicDatagramPriority
{
    /// <summary>普通批量流量，遵守拥塞窗口并使用普通有界队列。</summary>
    Normal = 0,

    /// <summary>低带宽交互流量，使用独立有界队列并可借用一个包的拥塞窗口。</summary>
    Interactive = 1
}
