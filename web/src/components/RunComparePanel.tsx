import type { Bundle, NodeDiff, RecommendationRollup, RunListItem } from '../types'

export function RunComparePanel({ runs, compareRunId, onCompareRunChange, primaryBundle, compareBundle, diffMode, onDiffModeChange, nodeDiffs, rollup }: {
  runs: RunListItem[]
  compareRunId: string
  onCompareRunChange: (runId: string) => void
  primaryBundle?: Bundle | null
  compareBundle?: Bundle | null
  diffMode: boolean
  onDiffModeChange: (enabled: boolean) => void
  nodeDiffs: NodeDiff[]
  rollup?: RecommendationRollup | null
}) {
  const changed = nodeDiffs.filter((item) => item.changed)
  return (
    <section className="panel">
      <div className="run-card-header">
        <h2>Compare runs</h2>
        <select value={compareRunId} onChange={(e) => onCompareRunChange(e.target.value)}>
          <option value="">No comparison</option>
          {runs.map((run) => <option key={run.run_id} value={run.run_id}>{run.run_id}</option>)}
        </select>
      </div>
      <label className="toggle-row">
        <input type="checkbox" checked={diffMode} onChange={(e) => onDiffModeChange(e.target.checked)} disabled={!compareRunId} /> Node diff mode
      </label>
      {compareRunId && compareBundle ? (
        <div className="compare-grid compare-grid-extended">
          <div className="compare-card">
            <h3>Primary</h3>
            <div><strong>{primaryBundle?.run_id}</strong></div>
            <div className="muted small">{primaryBundle?.classification || 'N/A'}</div>
            <div>Findings: {primaryBundle?.findings?.length || 0}</div>
          </div>
          <div className="compare-card">
            <h3>Compare</h3>
            <div><strong>{compareBundle.run_id}</strong></div>
            <div className="muted small">{compareBundle.classification || 'N/A'}</div>
            <div>Findings: {compareBundle.findings?.length || 0}</div>
          </div>
          <div className="compare-card compare-card-wide">
            <h3>Changed nodes</h3>
            {changed.length ? <ul className="diff-list compact">{changed.map((item) => <li key={item.nodeId}><strong>{item.label}</strong> <span className="muted small">{item.primaryStatus} → {item.compareStatus}</span></li>)}</ul> : <p className="muted">No node status deltas detected yet.</p>}
          </div>
          <div className="compare-card compare-card-wide">
            <h3>Recommendation rollups</h3>
            {rollup?.rollups?.length ? (
              <ul className="diff-list compact">
                {rollup.rollups.map((item) => (
                  <li key={item.node_id}>
                    <div className="run-card-header"><strong>{item.node_id}</strong><span className="muted small">{item.recommendations.length} recommendation(s)</span></div>
                    <div className="muted small">{item.primary_finding || item.compare_finding || 'No finding text'}</div>
                    <ul className="recommendation-list nested">
                      {item.recommendations.slice(0, 3).map((recommendation, index) => <li key={`${item.node_id}-${index}`}><strong>{recommendation.severity?.toUpperCase() || 'LOW'}</strong> · {recommendation.source}: {recommendation.recommendation}</li>)}
                    </ul>
                  </li>
                ))}
              </ul>
            ) : <p className="muted">Recommendation rollups appear after you select a comparison run.</p>}
          </div>
        </div>
      ) : <p className="muted">Choose a second run to see a side-by-side comparison.</p>}
    </section>
  )
}
