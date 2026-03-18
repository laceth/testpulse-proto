import { useEffect, useMemo, useRef, useState } from 'react'
import { API_BASE, getArtifactContent, getArtifactDiff } from '../api'
import type { ArtifactContent, ArtifactDiff, ArtifactMap, ComponentContract, TimelineEvent } from '../types'
import { artifactForEvent, componentForNode, severityTone } from '../lib/viewer'

function matchesNode(nodeId: string, event: TimelineEvent): boolean {
  const source = event.source.toLowerCase()
  const message = (event.message || '').toLowerCase()
  switch (nodeId) {
    case 'endpoint_supplicant': return source.includes('framework') || source.includes('dot1x') || event.kind.startsWith('EAP') || event.kind.startsWith('DOT1X')
    case 'dhcp': return Boolean(event.endpoint_ip || event.dhcp_hostname) || source.includes('dhcp') || source.includes('ipconfig')
    case 'tcpip_relay': return source.includes('relay') || source.includes('iphelper') || source.includes('helper-address') || message.includes('relay') || String(event.metadata?.relay || '').toLowerCase() === 'true'
    case 'dns': return Boolean(event.dns_name) || source.includes('dns') || source.includes('nslookup') || source.includes('dig')
    case 'ad_ldap': return Boolean(event.domain || event.login_type) || source.includes('ldap') || event.kind.startsWith('IDENTITY_')
    case 'radius': return event.kind.includes('RADIUS_') || source.includes('radius')
    case 'nas_authorization': return Boolean(event.nas_ip || event.nas_port || event.nas_port_id) || source.includes('auth_session') || source.includes('show_auth')
    case 'tomahawk': return source.includes('tomahawk') || message.includes('tomahawk') || String(event.metadata?.platform || '').toLowerCase().includes('tomahawk')
    case 'coa': return event.kind.includes('COA') || source.includes('coa') || source.includes('syslog')
    case 'ntp': return source.includes('ntp') || source.includes('chrony') || source.includes('w32tm') || source.includes('timedatectl')
    default: return false
  }
}

type RecommendationItem = { source: 'primary' | 'compare'; severity: string; confidence?: number; recommendation: string; finding?: string }
const severityRank = (severity?: string) => (severity || '').toLowerCase() === 'high' ? 3 : (severity || '').toLowerCase() === 'medium' ? 2 : (severity || '').toLowerCase() === 'low' ? 1 : 0

function buildRecommendations(primary?: ComponentContract, compare?: ComponentContract): RecommendationItem[] {
  const items: RecommendationItem[] = []
  if (primary?.recommendation) items.push({ source: 'primary', severity: primary.severity || 'low', confidence: primary.confidence, recommendation: primary.recommendation, finding: primary.finding })
  if (compare?.recommendation) items.push({ source: 'compare', severity: compare.severity || 'low', confidence: compare.confidence, recommendation: compare.recommendation, finding: compare.finding })
  return items.sort((a, b) => severityRank(b.severity) - severityRank(a.severity) || (b.confidence || 0) - (a.confidence || 0))
}

function previewExcerpts(preview: string, query: string): Array<{ index: number; excerpt: string }> {
  if (!query.trim()) return []
  const lower = preview.toLowerCase(); const token = query.toLowerCase(); const results: Array<{ index: number; excerpt: string }> = []
  let start = 0
  while (results.length < 25) {
    const index = lower.indexOf(token, start)
    if (index === -1) break
    const excerptStart = Math.max(0, index - 60)
    const excerptEnd = Math.min(preview.length, index + token.length + 80)
    results.push({ index, excerpt: preview.slice(excerptStart, excerptEnd).replace(/\n/g, ' ') })
    start = index + token.length
  }
  return results
}

export function NodeDetailDrawer({ runId, compareRunId, selectedNode, open, onClose, artifactMap, compareArtifactMap, timeline, components, compareComponents = [], activeEvent }: {
  runId: string
  compareRunId?: string
  selectedNode: string
  open: boolean
  onClose: () => void
  artifactMap?: ArtifactMap
  compareArtifactMap?: ArtifactMap
  timeline: TimelineEvent[]
  components: ComponentContract[]
  compareComponents?: ComponentContract[]
  activeEvent?: TimelineEvent | null
}) {
  const [preview, setPreview] = useState<ArtifactContent | null>(null)
  const [previewError, setPreviewError] = useState('')
  const [search, setSearch] = useState('')
  const [artifactDiff, setArtifactDiff] = useState<ArtifactDiff | null>(null)
  const [diffError, setDiffError] = useState('')
  const previewRef = useRef<HTMLPreElement | null>(null)
  const component = componentForNode(selectedNode, components)
  const compareComponent = componentForNode(selectedNode, compareComponents)
  const recommendations = useMemo(() => buildRecommendations(component, compareComponent), [component, compareComponent])
  const artifacts = artifactMap?.nodes?.[selectedNode] || component?.evidence || []
  const compareArtifacts = compareArtifactMap?.nodes?.[selectedNode] || compareComponent?.evidence || []
  const relevantEvents = useMemo(() => timeline.filter((event) => matchesNode(selectedNode, event)).slice(0, 10), [selectedNode, timeline])
  const matches = useMemo(() => preview?.content_type === 'text' && preview.preview ? previewExcerpts(preview.preview, search) : [], [preview, search])

  useEffect(() => { setSearch(''); setArtifactDiff(null); setDiffError('') }, [selectedNode, preview?.artifact_path, compareRunId])
  if (!open) return null

  async function openArtifact(path: string) { setPreviewError(''); try { setPreview(await getArtifactContent(runId, path)) } catch (error) { setPreviewError(error instanceof Error ? error.message : 'Failed to load artifact preview') } }
  async function openDiff(path?: string) { if (!compareRunId) return; setDiffError(''); try { setArtifactDiff(await getArtifactDiff(runId, compareRunId, selectedNode, path)) } catch (error) { setDiffError(error instanceof Error ? error.message : 'Failed to load artifact diff') } }
  function jumpTo(index: number) {
    if (!previewRef.current || !preview?.preview) return
    const token = search.toLowerCase(); const target = preview.preview.toLowerCase().indexOf(token, index); if (target < 0) return
    const linePrefix = preview.preview.slice(0, target); const lineCount = linePrefix.split('\n').length; previewRef.current.scrollTop = Math.max(0, (lineCount - 2) * 18)
  }

  return (
    <div className="node-drawer" role="dialog" aria-label="Node details drawer">
      <div className="node-drawer-header"><div><div className="muted small">Node details</div><h3>{selectedNode}</h3></div><button className="drawer-close" type="button" onClick={onClose}>Close</button></div>
      <div className="drawer-grid"><div><div className="drawer-stat-label">Status</div><div className="pill">{component?.status || 'UNKNOWN'}</div></div><div><div className="drawer-stat-label">Confidence</div><div>{typeof component?.confidence === 'number' ? component.confidence.toFixed(2) : 'N/A'}</div></div><div><div className="drawer-stat-label">Severity</div><div>{component?.severity || 'N/A'}</div></div></div>
      {compareComponent ? <div className="compare-inline-block"><strong>Compare run:</strong> {compareComponent.status} {compareComponent.severity ? `(${compareComponent.severity})` : ''}</div> : null}
      {component?.finding ? <p><strong>Finding:</strong> {component.finding}</p> : null}
      {compareComponent?.finding ? <p className="muted"><strong>Compare finding:</strong> {compareComponent.finding}</p> : null}
      <h4>Recommendations</h4>
      {recommendations.length ? <ul className="recommendation-list">{recommendations.map((item, idx) => { const tone = severityTone(item.severity); return <li key={`${item.source}-${idx}`}><div className="recommendation-topline"><span className="pill" style={{ background: tone.bg, color: tone.fg }}>{item.severity.toUpperCase()}</span><span className="muted small">{item.source}</span>{typeof item.confidence === 'number' ? <span className="muted small">conf {item.confidence.toFixed(2)}</span> : null}</div><div>{item.recommendation}</div></li> })}</ul> : <p className="muted">No recommendation available for this node yet.</p>}
      <div className="run-card-header"><h4>Artifacts</h4>{compareRunId && (artifacts.length || compareArtifacts.length) ? <button type="button" onClick={() => void openDiff()}>Diff same node</button> : null}</div>
      {artifacts.length ? <ul className="artifact-actions">{artifacts.map((artifact) => <li key={artifact}><button type="button" onClick={() => void openArtifact(artifact)}>{artifact}</button><a href={`${API_BASE}/runs/${encodeURIComponent(runId)}/artifacts/content?path=${encodeURIComponent(artifact)}`} target="_blank" rel="noreferrer">Open raw</a>{compareRunId ? <button type="button" onClick={() => void openDiff(artifact)}>Diff</button> : null}</li>)}</ul> : <p className="muted">No artifacts linked yet.</p>}
      {compareRunId && compareArtifacts.length ? <p className="muted small">Compare run has {compareArtifacts.length} artifact(s) mapped to this node.</p> : null}
      <h4>Current playback step</h4>
      {activeEvent ? <div className="event-card"><strong>{activeEvent.kind}</strong><div className="muted">{activeEvent.source}</div>{activeEvent.ts ? <div className="small">{activeEvent.ts}</div> : null}</div> : <p className="muted">Start playback to highlight the current event.</p>}
      <h4>Mapped timeline events</h4>
      {relevantEvents.length ? <ul className="timeline-link-list">{relevantEvents.map((event, index) => { const artifact = artifactForEvent(event, artifactMap); return <li key={`${event.kind}-${event.source}-${index}`}><div><strong>{event.kind}</strong> <span className="muted">({event.source})</span></div>{artifact ? <div className="small timeline-link-row"><button type="button" onClick={() => void openArtifact(artifact)}>Preview log</button><a href={`${API_BASE}/runs/${encodeURIComponent(runId)}/artifacts/content?path=${encodeURIComponent(artifact)}`} target="_blank" rel="noreferrer">Open raw</a></div> : null}</li> })}</ul> : <p className="muted">No mapped timeline events for this node.</p>}
      {artifactDiff ? <><h4>Cross-run artifact diff</h4><div className="muted small">{artifactDiff.compare_artifact_path || 'N/A'} → {artifactDiff.artifact_path || 'N/A'}</div><pre className="artifact-preview diff-preview">{artifactDiff.diff}</pre></> : null}
      {diffError ? <p className="empty-state error" style={{ position: 'static' }}>{diffError}</p> : null}
      {preview ? <><div className="run-card-header"><h4>Artifact preview</h4>{preview.content_type === 'text' ? <label className="search-inline"><span className="muted small">Search preview</span><input value={search} onChange={(e) => setSearch(e.target.value)} placeholder="jump to text" /></label> : null}</div><div className="muted small">{preview.artifact_path}</div>{preview.content_type === 'text' ? <pre ref={previewRef} className="artifact-preview">{preview.preview}</pre> : <div className="artifact-preview">{preview.preview}</div>}{matches.length ? <div className="search-match-panel"><div className="muted small">Matches</div><ul className="search-match-list">{matches.map((match) => <li key={match.index}><button type="button" onClick={() => jumpTo(match.index)}>{match.excerpt}</button></li>)}</ul></div> : null}</> : null}
      {previewError ? <p className="empty-state error" style={{ position: 'static' }}>{previewError}</p> : null}
    </div>
  )
}
