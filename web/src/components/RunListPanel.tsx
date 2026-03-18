import type { OutcomeFilter, RunListItem } from '../types'

export function RunListPanel({
  runs,
  selectedRunId,
  onSelectRun,
  search,
  onSearchChange,
  classification,
  onClassificationChange,
  outcome,
  onOutcomeChange,
}: {
  runs: RunListItem[]
  selectedRunId: string
  onSelectRun: (runId: string) => void
  search: string
  onSearchChange: (value: string) => void
  classification: string
  onClassificationChange: (value: string) => void
  outcome: OutcomeFilter
  onOutcomeChange: (value: OutcomeFilter) => void
}) {
  return (
    <section className="panel">
      <h2>Runs</h2>
      <div className="filters-grid">
        <label>
          <span className="muted small">Search</span>
          <input value={search} onChange={(e) => onSearchChange(e.target.value)} placeholder="run id or testcase" />
        </label>
        <label>
          <span className="muted small">Classification</span>
          <input value={classification} onChange={(e) => onClassificationChange(e.target.value)} placeholder="PASS_CONFIRMED" />
        </label>
        <label>
          <span className="muted small">Outcome</span>
          <select value={outcome} onChange={(e) => onOutcomeChange(e.target.value as OutcomeFilter)}>
            <option value="all">All</option>
            <option value="pass">Pass</option>
            <option value="fail">Fail</option>
          </select>
        </label>
      </div>
      <div className="run-list">
        {runs.length ? runs.map((run) => (
          <button
            key={run.run_id}
            className={`run-card ${selectedRunId === run.run_id ? 'selected' : ''}`}
            type="button"
            onClick={() => onSelectRun(run.run_id)}
          >
            <div className="run-card-header">
              <strong>{run.run_id}</strong>
              <span className="pill">{run.classification || (run.functional_pass ? 'PASS' : run.functional_pass === 0 ? 'FAIL' : 'UNKNOWN')}</span>
            </div>
            <div className="muted small">{run.testcase_id || 'No testcase id'}</div>
            <div className="run-card-meta">
              <span>Observed: {run.observed_decision || 'N/A'}</span>
              <span>Expected: {run.expected_decision || 'N/A'}</span>
            </div>
            <div className="run-card-meta">
              <span>Confidence: {typeof run.confidence === 'number' ? run.confidence.toFixed(2) : 'N/A'}</span>
              <span>{run.created_at ? new Date(run.created_at).toLocaleString() : 'No timestamp'}</span>
            </div>
          </button>
        )) : <p className="muted">No runs match the current filters.</p>}
      </div>
    </section>
  )
}
