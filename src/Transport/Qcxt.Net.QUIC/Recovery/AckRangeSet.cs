namespace Qcxt.Net.Quic.Recovery;

/// <summary>
/// 表示 Ack Range Set，并提供相关数据或行为。
/// </summary>
internal sealed class AckRangeSet
{
    private const int MaximumRanges = 256;
    private readonly List<Range> _ranges = new(16);
    /// <summary>
    /// 获取或设置Count。
    /// </summary>
    /// <returns>Count。</returns>
    public int Count => _ranges.Count;
    /// <summary>
    /// 获取或设置Largest。
    /// </summary>
    /// <returns>Largest。</returns>
    public long Largest => _ranges.Count == 0 ? -1 : _ranges[0].End;

    /// <summary>
    /// 添加。
    /// </summary>
    /// <param name="packetNumber">packet Number参数。</param>
    /// <returns>操作结果。</returns>
    public bool Add(long packetNumber)
    {
        if (packetNumber < 0) return false;
        for (int i = 0; i < _ranges.Count; i++)
        {
            var range = _ranges[i];
            if (packetNumber >= range.Start && packetNumber <= range.End) return false;
            if (packetNumber == range.End + 1)
            {
                range = range with { End = packetNumber }; _ranges[i] = range; MergeAt(i); return true;
            }
            if (packetNumber + 1 == range.Start)
            {
                range = range with { Start = packetNumber }; _ranges[i] = range; MergeAt(i); return true;
            }
            if (packetNumber > range.End)
            {
                _ranges.Insert(i, new(packetNumber, packetNumber)); Trim(); return true;
            }
        }
        _ranges.Add(new(packetNumber, packetNumber)); Trim(); return true;
    }

    /// <summary>
    /// 按索引获取或设置对应的数据项。
    /// </summary>
    /// <param name="index">index参数。</param>
    /// <returns>指定索引对应的数据项。</returns>
    public (long Start, long End) this[int index] => (_ranges[index].Start, _ranges[index].End);
    /// <summary>
    /// 执行Clear Before操作。
    /// </summary>
    /// <param name="packetNumber">packet Number参数。</param>
    public void ClearBefore(long packetNumber)
    {
        for (int i = _ranges.Count - 1; i >= 0; i--)
        {
            if (_ranges[i].End < packetNumber) _ranges.RemoveAt(i);
        }
    }

    /// <summary>
    /// 执行Merge At操作。
    /// </summary>
    /// <param name="index">index参数。</param>
    private void MergeAt(int index)
    {
        if (index > 0 && _ranges[index].End + 1 >= _ranges[index - 1].Start)
        {
            _ranges[index - 1] = new(Math.Min(_ranges[index].Start, _ranges[index - 1].Start),
                Math.Max(_ranges[index].End, _ranges[index - 1].End));
            _ranges.RemoveAt(index); index--;
        }
        if (index + 1 < _ranges.Count && _ranges[index + 1].End + 1 >= _ranges[index].Start)
        {
            _ranges[index] = new(Math.Min(_ranges[index].Start, _ranges[index + 1].Start),
                Math.Max(_ranges[index].End, _ranges[index + 1].End));
            _ranges.RemoveAt(index + 1);
        }
    }
    /// <summary>
    /// 执行Trim操作。
    /// </summary>
    private void Trim() { if (_ranges.Count > MaximumRanges) _ranges.RemoveRange(MaximumRanges, _ranges.Count - MaximumRanges); }
    /// <summary>
    /// 表示 Range，并提供相关数据或行为。
    /// </summary>
    /// <param name="Start">Start参数。</param>
    /// <param name="End">End参数。</param>
    private readonly record struct Range(long Start, long End);
}
