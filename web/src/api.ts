import type {
  ArtifactContent,
  ArtifactDiff,
  ArtifactMap,
  BaselineMode,
  Bundle,
  HealthContract,
  PrognosticsContract,
  RecommendationRollup,
  RunFilters,
  RunListResponse,
  TimelineContract,
  TrendContract,
} from './types'

const API_BASE = (import.meta.env.VITE_TESTPULSE_API_BASE as string | undefined)?.replace(/\/$/, '') || 'http://127.0.0.1:8000'

async function readJson<T>(path: string): Promise<T> {
  const response = await fetch(`${API_BASE}${path}`)
  if (!response.ok) {
    const body = await response.text()
    throw new Error(body || `Request failed: ${response.status}`)
  }
  return response.json() as Promise<T>
}

function toQuery(filters?: RunFilters): string {
  if (!filters) return ''
  const params = new URLSearchParams()
  if (filters.q) params.set('q', filters.q)
  if (filters.classification) params.set('classification', filters.classification)
  if (filters.outcome) params.set('outcome', filters.outcome)
  if (filters.limit) params.set('limit', String(filters.limit))
  const q = params.toString()
  return q ? `?${q}` : ''
}

export function listRuns(filters?: RunFilters): Promise<RunListResponse> { return readJson(`/runs${toQuery(filters)}`) }
export function getBundle(runId: string): Promise<Bundle> { return readJson(`/runs/${encodeURIComponent(runId)}/bundle`) }
export function getTimeline(runId: string): Promise<TimelineContract> { return readJson(`/runs/${encodeURIComponent(runId)}/timeline`) }
export function getHealth(runId: string): Promise<HealthContract> { return readJson(`/runs/${encodeURIComponent(runId)}/health`) }
export function getArtifacts(runId: string): Promise<ArtifactMap> { return readJson(`/runs/${encodeURIComponent(runId)}/artifacts`) }
export function getPrognostics(runId: string): Promise<PrognosticsContract> { return readJson(`/runs/${encodeURIComponent(runId)}/prognostics`) }
export function getTrends(runId: string, limit = 25, baselineMode: BaselineMode = 'testcase_weekday_hour', windowHours = 2): Promise<TrendContract> { return readJson(`/runs/${encodeURIComponent(runId)}/trends?limit=${limit}&baseline_mode=${encodeURIComponent(baselineMode)}&window_hours=${windowHours}`) }
export function getArtifactContent(runId: string, artifactPath: string): Promise<ArtifactContent> { return readJson(`/runs/${encodeURIComponent(runId)}/artifacts/content?path=${encodeURIComponent(artifactPath)}`) }
export function getRecommendationRollup(runId: string, compareRunId: string): Promise<RecommendationRollup> { return readJson(`/runs/${encodeURIComponent(runId)}/compare/${encodeURIComponent(compareRunId)}/recommendations`) }
export function getArtifactDiff(runId: string, compareRunId: string, nodeId: string, artifactPath?: string): Promise<ArtifactDiff> {
  const params = new URLSearchParams({ node_id: nodeId })
  if (artifactPath) params.set('path', artifactPath)
  return readJson(`/runs/${encodeURIComponent(runId)}/compare/${encodeURIComponent(compareRunId)}/artifacts/diff?${params.toString()}`)
}
export function openRunStream(runId: string, intervalMs = 1500): EventSource { return new EventSource(`${API_BASE}/runs/${encodeURIComponent(runId)}/stream?interval_ms=${intervalMs}`) }

export { API_BASE }
