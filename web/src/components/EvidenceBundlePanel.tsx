import type { Bundle, HealthContract, TimelineContract } from '../types'

export function EvidenceBundlePanel({
  bundle,
  health,
  timeline,
}: {
  bundle?: Bundle | null
  health?: HealthContract | null
  timeline?: TimelineContract | null
}) {
  if (!bundle) {
    return (
      <section className="panel">
        <h2>EvidenceBundle</h2>
        <p>Select a run to load its bundle.</p>
      </section>
    )
  }

  return (
    <section className="panel">
      <h2>EvidenceBundle</h2>
      <p><strong>Run:</strong> {bundle.run_id}</p>
      <p><strong>Test case:</strong> {bundle.testcase_id || 'N/A'}</p>
      <p><strong>Classification:</strong> {bundle.classification || 'N/A'}</p>
      <p><strong>Timeline events:</strong> {timeline?.timeline?.length || 0}</p>
      <p><strong>Health components:</strong> {health?.components?.length || 0}</p>
      <h3>Findings</h3>
      {bundle.findings?.length ? (
        <ul>
          {bundle.findings.map((finding) => <li key={finding}>{finding}</li>)}
        </ul>
      ) : (
        <p>No findings available.</p>
      )}
    </section>
  )
}
