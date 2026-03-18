import type { TimelineEvent } from '../types'

export function TimelinePlayback({
  timeline,
  currentIndex,
  isPlaying,
  speedMs,
  onIndexChange,
  onPlayPause,
  onReset,
  onSpeedChange,
}: {
  timeline: TimelineEvent[]
  currentIndex: number
  isPlaying: boolean
  speedMs: number
  onIndexChange: (index: number) => void
  onPlayPause: () => void
  onReset: () => void
  onSpeedChange: (value: number) => void
}) {
  const maxIndex = Math.max(timeline.length - 1, 0)
  const active = timeline[currentIndex]
  return (
    <section className="panel">
      <div className="playback-header">
        <h2>Timeline playback</h2>
        <div className="playback-controls">
          <button type="button" onClick={onPlayPause} disabled={!timeline.length}>{isPlaying ? 'Pause' : 'Play'}</button>
          <button type="button" onClick={onReset} disabled={!timeline.length}>Reset</button>
        </div>
      </div>
      <label className="slider-label">
        <span className="muted small">Step {timeline.length ? currentIndex + 1 : 0} / {timeline.length}</span>
        <input type="range" min={0} max={maxIndex} value={timeline.length ? currentIndex : 0} onChange={(e) => onIndexChange(Number(e.target.value))} disabled={!timeline.length} />
      </label>
      <label className="slider-label">
        <span className="muted small">Playback speed</span>
        <select value={speedMs} onChange={(e) => onSpeedChange(Number(e.target.value))}>
          <option value={2500}>Slow</option>
          <option value={1500}>Normal</option>
          <option value={700}>Fast</option>
        </select>
      </label>
      {active ? (
        <div className="event-card">
          <strong>{active.kind}</strong>
          <div className="muted">{active.source}</div>
          {active.ts ? <div className="small">{active.ts}</div> : null}
        </div>
      ) : (
        <p className="muted">No timeline events available for playback.</p>
      )}
    </section>
  )
}
