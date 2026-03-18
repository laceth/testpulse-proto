import type { ArtifactMap } from '../types'

export function ArtifactPanel({
  artifactMap,
}: {
  artifactMap?: ArtifactMap
}) {
  const entries = Object.entries(artifactMap?.nodes || {}).filter(([, artifacts]) => artifacts.length > 0)
  return (
    <section className="panel">
      <h2>Artifact map</h2>
      {entries.length ? (
        <ul className="artifact-node-list">
          {entries.map(([node, artifacts]) => (
            <li key={node}>
              <strong>{node}</strong>
              <div className="muted small">{artifacts.length} linked artifacts</div>
            </li>
          ))}
        </ul>
      ) : (
        <p>No artifact map loaded.</p>
      )}
    </section>
  )
}
