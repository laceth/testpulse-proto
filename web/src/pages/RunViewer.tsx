import { useCallback, useEffect, useMemo, useState } from 'react'
import { API_BASE, getArtifacts, getBundle, getHealth, getPrognostics, getRecommendationRollup, getTimeline, getTrends, listRuns, openRunStream } from '../api'
import { ArtifactPanel } from '../components/ArtifactPanel'
import { AAAGraph } from '../components/AAAGraph'
import { EvidenceBundlePanel } from '../components/EvidenceBundlePanel'
import { NodeDetailDrawer } from '../components/NodeDetailDrawer'
import { PrognosticBadges } from '../components/PrognosticBadges'
import { RunComparePanel } from '../components/RunComparePanel'
import { RunListPanel } from '../components/RunListPanel'
import { TimelinePlayback } from '../components/TimelinePlayback'
import { TrendCharts } from '../components/TrendCharts'
import type { ArtifactMap, BaselineMode, Bundle, HealthContract, OutcomeFilter, PrognosticsContract, RecommendationRollup, RunFilters, RunListItem, TimelineContract, TrendContract } from '../types'
import { buildNodeDiffs, nodeIdForEvent } from '../lib/viewer'

type RunData = { bundle: Bundle | null; timeline: TimelineContract | null; health: HealthContract | null; artifactMap: ArtifactMap | null; prognostics: PrognosticsContract | null; trends: TrendContract | null }
const EMPTY_RUN_DATA: RunData = { bundle: null, timeline: null, health: null, artifactMap: null, prognostics: null, trends: null }

export function RunViewer() {
  const [runs, setRuns] = useState<RunListItem[]>([])
  const [selectedRunId, setSelectedRunId] = useState('')
  const [compareRunId, setCompareRunId] = useState('')
  const [primary, setPrimary] = useState<RunData>(EMPTY_RUN_DATA)
  const [compare, setCompare] = useState<RunData>(EMPTY_RUN_DATA)
  const [rollup, setRollup] = useState<RecommendationRollup | null>(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const [selectedNode, setSelectedNode] = useState('endpoint_supplicant')
  const [search, setSearch] = useState('')
  const [classification, setClassification] = useState('')
  const [outcome, setOutcome] = useState<OutcomeFilter>('all')
  const [autoRefresh, setAutoRefresh] = useState(false)
  const [refreshMs, setRefreshMs] = useState(15000)
  const [streaming, setStreaming] = useState(false)
  const [playbackIndex, setPlaybackIndex] = useState(0)
  const [playbackMs, setPlaybackMs] = useState(1500)
  const [isPlaying, setIsPlaying] = useState(false)
  const [drawerOpen, setDrawerOpen] = useState(true)
  const [diffMode, setDiffMode] = useState(false)
  const [baselineMode, setBaselineMode] = useState<BaselineMode>('testcase_weekday_hour')
  const [windowHours, setWindowHours] = useState(2)

  const runFilters = useMemo<RunFilters>(() => ({ q: search.trim() || undefined, classification: classification.trim() || undefined, outcome: outcome === 'all' ? undefined : outcome, limit: 100 }), [search, classification, outcome])

  const loadRuns = useCallback(async () => {
    const response = await listRuns(runFilters)
    const nextRuns = response.runs || []
    setRuns(nextRuns)
    if (nextRuns.length > 0) {
      setSelectedRunId((current) => (current && nextRuns.some((run) => run.run_id === current) ? current : nextRuns[0].run_id))
      setCompareRunId((current) => (current && nextRuns.some((run) => run.run_id === current) ? current : ''))
    } else {
      setSelectedRunId('')
      setCompareRunId('')
    }
  }, [runFilters])

  const loadRun = useCallback(async (runId: string): Promise<RunData> => {
    const [bundleResp, timelineResp, healthResp, artifactsResp, prognosticsResp, trendsResp] = await Promise.all([
      getBundle(runId), getTimeline(runId), getHealth(runId), getArtifacts(runId), getPrognostics(runId), getTrends(runId, 25, baselineMode, windowHours),
    ])
    return { bundle: bundleResp, timeline: timelineResp, health: healthResp, artifactMap: artifactsResp, prognostics: prognosticsResp, trends: trendsResp }
  }, [baselineMode, windowHours])

  const refreshSelectedRun = useCallback(async () => {
    if (!selectedRunId) return
    setLoading(true); setError('')
    try {
      const primaryData = await loadRun(selectedRunId)
      setPrimary(primaryData)
      if (compareRunId) {
        const compareData = await loadRun(compareRunId)
        setCompare(compareData)
        setRollup(await getRecommendationRollup(selectedRunId, compareRunId))
      } else {
        setCompare(EMPTY_RUN_DATA)
        setRollup(null)
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : `Failed to load run ${selectedRunId}`)
    } finally {
      setLoading(false)
    }
  }, [loadRun, selectedRunId, compareRunId])

  useEffect(() => { let ignore = false; (async () => { setLoading(true); setError(''); try { await loadRuns() } catch (err) { if (!ignore) { setError(err instanceof Error ? err.message : 'Failed to load runs'); setLoading(false) } } })(); return () => { ignore = true } }, [loadRuns])

  useEffect(() => {
    if (!selectedRunId) { setLoading(false); return }
    let ignore = false
    ;(async () => {
      setLoading(true); setError('')
      try {
        const primaryData = await loadRun(selectedRunId)
        if (!ignore) setPrimary(primaryData)
        if (compareRunId) {
          const compareData = await loadRun(compareRunId)
          if (!ignore) setCompare(compareData)
          const nextRollup = await getRecommendationRollup(selectedRunId, compareRunId)
          if (!ignore) setRollup(nextRollup)
        } else if (!ignore) {
          setCompare(EMPTY_RUN_DATA); setRollup(null)
        }
      } catch (err) {
        if (!ignore) setError(err instanceof Error ? err.message : `Failed to load run ${selectedRunId}`)
      } finally { if (!ignore) setLoading(false) }
    })()
    setPlaybackIndex(0); setIsPlaying(false)
    return () => { ignore = true }
  }, [selectedRunId, compareRunId, loadRun])

  useEffect(() => {
    if (!autoRefresh || !selectedRunId || streaming) return
    const handle = window.setInterval(() => { void loadRuns(); void refreshSelectedRun() }, refreshMs)
    return () => window.clearInterval(handle)
  }, [autoRefresh, streaming, selectedRunId, refreshMs, refreshSelectedRun, loadRuns])

  useEffect(() => {
    if (!streaming || !selectedRunId) return
    const source = openRunStream(selectedRunId, Math.min(refreshMs, 5000))
    source.addEventListener('snapshot', () => { void refreshSelectedRun() })
    source.addEventListener('error', () => { setError(`Stream disconnected for ${selectedRunId}`) })
    return () => source.close()
  }, [streaming, selectedRunId, refreshMs, refreshSelectedRun])

  const timelineEvents = primary.timeline?.timeline || []
  useEffect(() => {
    if (!isPlaying || timelineEvents.length === 0) return
    const handle = window.setInterval(() => setPlaybackIndex((current) => { if (current >= timelineEvents.length - 1) { setIsPlaying(false); return current } return current + 1 }), playbackMs)
    return () => window.clearInterval(handle)
  }, [isPlaying, playbackMs, timelineEvents.length])

  const activeEvent = timelineEvents.length ? timelineEvents[Math.min(playbackIndex, timelineEvents.length - 1)] : null
  const activeNode = activeEvent ? nodeIdForEvent(activeEvent) : null
  const componentList = useMemo(() => primary.health?.components || [], [primary.health])
  const compareComponentList = useMemo(() => compare.health?.components || [], [compare.health])
  const nodeDiffs = useMemo(() => buildNodeDiffs(componentList, compareComponentList), [componentList, compareComponentList])

  return (
    <div className="layout">
      <header className="topbar">
        <div><h1>TestPulse Run Viewer</h1><p>Live viewer over real timeline, health, artifacts, prognostics, and node-to-node deltas.</p></div>
        <div className="topbar-right">
          <div className="refresh-controls">
            <label><input type="checkbox" checked={autoRefresh} onChange={(e) => setAutoRefresh(e.target.checked)} disabled={streaming} /> Auto refresh</label>
            <label><input type="checkbox" checked={streaming} onChange={(e) => setStreaming(e.target.checked)} /> Live stream</label>
            <select value={refreshMs} onChange={(e) => setRefreshMs(Number(e.target.value))}><option value={5000}>5s</option><option value={15000}>15s</option><option value={30000}>30s</option></select>
            <button type="button" onClick={() => { void loadRuns(); void refreshSelectedRun() }}>Refresh now</button>
            <span className="muted small">API: {API_BASE}</span>
          </div>
          <PrognosticBadges prognostics={primary.prognostics?.prognostics} />
        </div>
      </header>
      <main className="content content-expanded">
        <section className="sidebar-left">
          <RunListPanel runs={runs} selectedRunId={selectedRunId} onSelectRun={setSelectedRunId} search={search} onSearchChange={setSearch} classification={classification} onClassificationChange={setClassification} outcome={outcome} onOutcomeChange={setOutcome} />
          <RunComparePanel runs={runs.filter((run) => run.run_id !== selectedRunId)} compareRunId={compareRunId} onCompareRunChange={setCompareRunId} primaryBundle={primary.bundle} compareBundle={compare.bundle} diffMode={diffMode} onDiffModeChange={setDiffMode} nodeDiffs={nodeDiffs} rollup={rollup} />
          <TimelinePlayback timeline={timelineEvents} currentIndex={playbackIndex} isPlaying={isPlaying} speedMs={playbackMs} onIndexChange={setPlaybackIndex} onPlayPause={() => setIsPlaying((current) => !current)} onReset={() => { setPlaybackIndex(0); setIsPlaying(false) }} onSpeedChange={setPlaybackMs} />
          <TrendCharts trends={primary.trends} baselineMode={baselineMode} onBaselineModeChange={setBaselineMode} windowHours={windowHours} onWindowHoursChange={setWindowHours} />
        </section>
        <section className="canvas canvas-compare">
          {error ? <div className="empty-state error">{error}</div> : null}
          {!error && !selectedRunId && !loading ? <div className="empty-state">No runs available yet. Generate a run and refresh the viewer.</div> : null}
          {!error && selectedRunId ? (
            <div className={`graph-compare-grid ${compareRunId ? 'dual' : 'single'}`}>
              <div className="graph-card"><AAAGraph title={`Primary: ${selectedRunId}`} onSelectNode={(id) => { setSelectedNode(id); setDrawerOpen(true) }} selectedNode={selectedNode} activeNode={activeNode} components={componentList} compareComponents={diffMode ? compareComponentList : []} diffMode={diffMode} artifactMap={primary.artifactMap || primary.timeline?.artifact_map} timeline={timelineEvents} bundle={primary.bundle || undefined} /></div>
              {compareRunId ? <div className="graph-card"><AAAGraph title={`Compare: ${compareRunId}`} onSelectNode={(id) => { setSelectedNode(id); setDrawerOpen(true) }} selectedNode={selectedNode} components={compareComponentList} compareComponents={diffMode ? componentList : []} diffMode={diffMode} artifactMap={compare.artifactMap || compare.timeline?.artifact_map} timeline={compare.timeline?.timeline} bundle={compare.bundle || undefined} /></div> : null}
              <NodeDetailDrawer runId={selectedRunId} compareRunId={compareRunId || undefined} selectedNode={selectedNode} open={drawerOpen} onClose={() => setDrawerOpen(false)} artifactMap={primary.artifactMap || primary.timeline?.artifact_map} compareArtifactMap={compare.artifactMap || compare.timeline?.artifact_map} timeline={timelineEvents} components={componentList} compareComponents={compareComponentList} activeEvent={activeNode === selectedNode ? activeEvent : null} />
            </div>
          ) : null}
        </section>
        <aside className="sidebar">
          <section className="panel"><h2>Run state</h2><p><strong>Selected run:</strong> {selectedRunId || 'N/A'}</p><p><strong>Compare run:</strong> {compareRunId || 'None'}</p><p><strong>Loading:</strong> {loading ? 'Yes' : 'No'}</p><p><strong>Streaming:</strong> {streaming ? 'Yes' : 'No'}</p><p><strong>Active node:</strong> {activeNode || 'None'}</p><p><strong>Changed nodes:</strong> {nodeDiffs.filter((item) => item.changed).length}</p><p><strong>Artifacts mapped:</strong> {Object.keys((primary.artifactMap || primary.timeline?.artifact_map || { nodes: {} }).nodes || {}).length}</p></section>
          <EvidenceBundlePanel bundle={primary.bundle} health={primary.health} timeline={primary.timeline} />
          <ArtifactPanel artifactMap={primary.artifactMap || primary.timeline?.artifact_map} />
        </aside>
      </main>
    </div>
  )
}
