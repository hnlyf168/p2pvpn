namespace Qcxt.Net.P2P.Signaling;

/// <summary>Bounded, monotonic per-peer control request limiter; never limits data forwarding.</summary>
internal sealed class PeerRequestLimiter
{
    private readonly Dictionary<ulong, long> _next = new();
    private readonly object _gate = new();
    internal bool TryAcquire(ulong peer, long now, long interval)
    {
        lock (_gate)
        {
            if (_next.TryGetValue(peer, out long next) && now < next) return false;
            if (_next.Count >= 1024 && !_next.ContainsKey(peer))
            {
                foreach (var entry in _next)
                    if (entry.Value <= now) _next.Remove(entry.Key);
                if (_next.Count >= 1024) return false;
            }
            _next[peer] = now + Math.Max(1, interval);
            return true;
        }
    }
    internal void Forget(ulong peer) { lock (_gate) _next.Remove(peer); }
}
