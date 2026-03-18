import type { Prognostics } from '../types'

export function PrognosticBadges({ prognostics }: { prognostics?: Prognostics | null }) {
  const trendScore = prognostics?.trend_health?.score
  const warningCount = prognostics?.predictive_warnings?.length || 0
  const anomalyCount = prognostics?.repeated_run_anomalies?.length || 0
  const flake = prognostics?.flake_forecast?.status || 'N/A'
  const baselineDrift = prognostics?.service_baselines?.current_deviation?.filter((item) => item.status === 'DRIFTED').length || 0

  return (
    <div className="badges">
      <span className="badge">Trend score: {typeof trendScore === 'number' ? trendScore.toFixed(1) : 'N/A'}</span>
      <span className="badge">Flake: {flake}</span>
      <span className="badge">Warnings: {warningCount}</span>
      <span className="badge">Anomalies: {anomalyCount}</span>
      <span className="badge">Baseline drift: {baselineDrift}</span>
    </div>
  )
}
