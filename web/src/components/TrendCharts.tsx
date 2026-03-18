import type { BaselineMode, TrendContract, TrendPoint } from '../types'

const componentLabels: Record<string, string> = {
  dns: 'DNS',
  dhcp: 'DHCP',
  tcpip_relay: 'TCP/IP Relay',
  directory: 'Directory',
  nas: 'NAS / CoA',
  tomahawk: 'Tomahawk',
  ntp: 'NTP',
}

function chartPath(points: TrendPoint[], width: number, height: number): string {
  const values = points.map((point) => Number(point.metric_value || 0))
  const finite = values.filter((value) => Number.isFinite(value))
  if (!finite.length) return ''
  const min = Math.min(...finite)
  const max = Math.max(...finite)
  const span = max - min || 1
  return values.map((value, index) => {
    const x = (index / Math.max(values.length - 1, 1)) * width
    const y = height - ((value - min) / span) * height
    return `${index === 0 ? 'M' : 'L'} ${x.toFixed(1)} ${y.toFixed(1)}`
  }).join(' ')
}

function latest(points: TrendPoint[]): TrendPoint | null {
  return points.length ? points[points.length - 1] : null
}

export function TrendCharts({ trends, baselineMode, onBaselineModeChange, windowHours, onWindowHoursChange }: {
  trends?: TrendContract | null
  baselineMode: BaselineMode
  onBaselineModeChange: (value: BaselineMode) => void
  windowHours: number
  onWindowHoursChange: (value: number) => void
}) {
  const components = Object.entries(trends?.components || {}).filter(([, points]) => points.length)
  return (
    <section className="panel">
      <div className="run-card-header">
        <h2>Component trends</h2>
        <div className="baseline-controls-inline">
          <label>
            <span className="muted small">Baseline</span>
            <select value={baselineMode} onChange={(e) => onBaselineModeChange(e.target.value as BaselineMode)}>
              <option value="testcase_weekday_hour">Testcase + weekday/hour</option>
              <option value="testcase_only">Testcase only</option>
              <option value="all_history">All history</option>
            </select>
          </label>
          <label>
            <span className="muted small">Window ±hours</span>
            <select value={windowHours} onChange={(e) => onWindowHoursChange(Number(e.target.value))}>
              {[0, 1, 2, 3, 4, 6, 8, 12].map((value) => <option key={value} value={value}>{value}</option>)}
            </select>
          </label>
        </div>
      </div>
      {components.length ? (
        <div className="trend-grid">
          {components.map(([component, points]) => {
            const d = chartPath(points, 220, 70)
            const baseline = trends?.baselines?.[component]
            const last = latest(points)
            return (
              <article key={component} className="trend-card">
                <div className="run-card-header">
                  <strong>{componentLabels[component] || component}</strong>
                  {last?.status ? <span className="pill">{last.status}</span> : null}
                </div>
                <svg viewBox="0 0 220 70" className="trend-svg" preserveAspectRatio="none" aria-label={`${component} trend chart`}>
                  <path d={d} fill="none" stroke="#4c6ef5" strokeWidth="2.5" strokeLinecap="round" />
                </svg>
                <div className="trend-stats">
                  <span>Latest: {typeof last?.metric_value === 'number' ? last.metric_value : 'N/A'}</span>
                  <span>Samples: {points.length}</span>
                </div>
                {baseline ? (
                  <div className="muted small">Baseline median: {baseline.median ?? 'N/A'} · samples {baseline.samples} · {baseline.window || baseline.mode}</div>
                ) : <p className="muted small">No baseline available yet for this run family.</p>}
              </article>
            )
          })}
        </div>
      ) : <p className="muted">No historical trend data available yet.</p>}
    </section>
  )
}
