import { useMemo } from 'react'
import { Background, Controls, MiniMap, ReactFlow, type Edge, type Node } from '@xyflow/react'
import type { ArtifactMap, Bundle, ComponentContract, HealthStatus, TimelineEvent } from '../types'
import { GRAPH_NODE_LABELS, GRAPH_NODE_IDS, componentForNode, severityTone } from '../lib/viewer'

const nodeDefs = [
  { id: 'endpoint_supplicant', x: 0, y: 120 },
  { id: 'dhcp', x: 220, y: 120 },
  { id: 'tcpip_relay', x: 440, y: 120 },
  { id: 'dns', x: 660, y: 120 },
  { id: 'ad_ldap', x: 880, y: 120 },
  { id: 'radius', x: 1100, y: 120 },
  { id: 'nas_authorization', x: 1320, y: 120 },
  { id: 'tomahawk', x: 1540, y: 120 },
  { id: 'coa', x: 1760, y: 120 },
  { id: 'ntp', x: 1980, y: 120 },
  { id: 'evidence_bundle', x: 2200, y: 120 },
] as const

const componentKeyByNode: Record<string, string> = {
  dhcp: 'dhcp',
  tcpip_relay: 'tcpip_relay',
  dns: 'dns',
  ad_ldap: 'directory',
  radius: 'radius',
  nas_authorization: 'nas',
  tomahawk: 'tomahawk',
  coa: 'nas',
  ntp: 'ntp',
}

function normalizeStatus(status?: string): HealthStatus {
  if (status === 'HEALTHY' || status === 'DEGRADED' || status === 'FAILED' || status === 'UNKNOWN') return status
  return 'UNKNOWN'
}

function statusFromBundle(nodeId: string, bundle?: Bundle, timeline: TimelineEvent[] = []): HealthStatus {
  if (nodeId === 'endpoint_supplicant') return timeline.length > 0 ? 'HEALTHY' : 'UNKNOWN'
  if (nodeId === 'evidence_bundle') return !bundle ? 'UNKNOWN' : bundle.functional_pass === false ? 'FAILED' : 'HEALTHY'
  if (nodeId === 'radius') {
    const hasRadius = timeline.some((event) => event.kind.includes('RADIUS_') || event.source.toLowerCase().includes('radius'))
    if (!hasRadius) return 'UNKNOWN'
    return bundle?.functional_pass === false ? 'FAILED' : 'HEALTHY'
  }
  if (nodeId === 'coa') {
    const hasCoa = timeline.some((event) => event.kind.includes('COA') || event.source.toLowerCase().includes('coa'))
    return hasCoa ? 'HEALTHY' : 'UNKNOWN'
  }
  return 'UNKNOWN'
}

function resolveNodeStatus(nodeId: string, components: ComponentContract[], bundle?: Bundle, timeline: TimelineEvent[] = []): HealthStatus {
  const componentKey = componentKeyByNode[nodeId]
  if (componentKey) {
    const match = components.find((component) => component.component === componentKey)
    if (match) return normalizeStatus(match.status)
  }
  return statusFromBundle(nodeId, bundle, timeline)
}

function statusColors(status: HealthStatus, selected: boolean, active: boolean, changed: boolean): { background: string; border: string; text: string } {
  const palette: Record<HealthStatus, { background: string; border: string; text: string }> = {
    HEALTHY: { background: '#ecfdf3', border: '#12b76a', text: '#065f46' },
    DEGRADED: { background: '#fffaeb', border: '#f79009', text: '#92400e' },
    FAILED: { background: '#fef3f2', border: '#f04438', text: '#991b1b' },
    UNKNOWN: { background: '#eff6ff', border: '#4c6ef5', text: '#1e3a8a' },
  }
  const chosen = palette[status]
  if (active) return { ...chosen, border: '#7c3aed' }
  if (changed) return { ...chosen, border: '#111827' }
  return selected ? { ...chosen, border: '#111827' } : chosen
}

export function AAAGraph({
  onSelectNode,
  selectedNode,
  activeNode,
  components,
  compareComponents = [],
  diffMode = false,
  artifactMap,
  timeline,
  bundle,
  title,
}: {
  onSelectNode: (id: string) => void
  selectedNode: string
  activeNode?: string | null
  components: ComponentContract[]
  compareComponents?: ComponentContract[]
  diffMode?: boolean
  artifactMap?: ArtifactMap
  timeline?: TimelineEvent[]
  bundle?: Bundle
  title?: string
}) {
  const timelineEvents = timeline || []
  const nodes = useMemo<Node[]>(() => nodeDefs.map(({ id, x, y }) => {
    const status = resolveNodeStatus(id, components, bundle, timelineEvents)
    const compareStatus = resolveNodeStatus(id, compareComponents, undefined, [])
    const artifactCount = artifactMap?.nodes?.[id]?.length || 0
    const changed = diffMode && compareComponents.length > 0 && compareStatus !== 'UNKNOWN' && compareStatus !== status
    const colors = statusColors(status, selectedNode === id, activeNode === id, changed)
    const component = componentForNode(id, components)
    const tone = severityTone(component?.severity)
    return {
      id,
      position: { x, y },
      data: {
        label: (
          <div>
            <div style={{ display: 'flex', justifyContent: 'space-between', gap: 8, marginBottom: 6, alignItems: 'flex-start' }}>
              <div style={{ fontWeight: 700 }}>{GRAPH_NODE_LABELS[id]}</div>
              <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap', justifyContent: 'flex-end' }}>
                {diffMode && changed ? <span style={{ fontSize: 10, padding: '2px 6px', borderRadius: 999, background: '#111827', color: '#ffffff', fontWeight: 700 }}>Δ {compareStatus}</span> : null}
                {component?.severity ? <span style={{ fontSize: 10, padding: '2px 6px', borderRadius: 999, background: tone.bg, color: tone.fg, fontWeight: 700 }}>{component.severity.toUpperCase()}</span> : null}
                {activeNode === id ? <span style={{ fontSize: 11, padding: '2px 6px', borderRadius: 999, background: '#ede9fe', color: '#6d28d9' }}>LIVE</span> : null}
              </div>
            </div>
            <div style={{ fontSize: 12, opacity: 0.9 }}>{status}</div>
            <div style={{ fontSize: 12, opacity: 0.7 }}>{artifactCount} artifacts</div>
            {typeof component?.confidence === 'number' ? <div style={{ fontSize: 11, opacity: 0.75 }}>conf {component.confidence.toFixed(2)}</div> : null}
          </div>
        ),
      },
      style: {
        borderRadius: 14,
        padding: 12,
        border: `2px solid ${colors.border}`,
        width: 185,
        background: colors.background,
        color: colors.text,
        boxShadow: activeNode === id ? '0 0 0 6px rgba(124,58,237,0.12)' : changed ? '0 0 0 4px rgba(17,24,39,0.1)' : selectedNode === id ? '0 0 0 3px rgba(17,24,39,0.08)' : 'none',
      },
    }
  }), [artifactMap, bundle, components, compareComponents, diffMode, selectedNode, activeNode, timelineEvents])

  const edges = useMemo<Edge[]>(() => nodeDefs.slice(0, -1).map(({ id }, idx) => {
    const target = nodeDefs[idx + 1].id
    const sourceStatus = resolveNodeStatus(id, components, bundle, timelineEvents)
    const isPlaybackEdge = activeNode === id || activeNode === target
    return {
      id: `e-${id}-${target}`,
      source: id,
      target,
      animated: isPlaybackEdge || sourceStatus !== 'UNKNOWN',
      style: { stroke: isPlaybackEdge ? '#7c3aed' : sourceStatus === 'FAILED' ? '#f04438' : sourceStatus === 'DEGRADED' ? '#f79009' : '#4c6ef5', strokeWidth: isPlaybackEdge ? 3 : 2 },
    }
  }), [bundle, components, timelineEvents, activeNode])

  return (
    <div className="graph-shell">
      {title ? <div className="graph-title">{title}</div> : null}
      <ReactFlow fitView nodes={nodes} edges={edges} onNodeClick={(_, node) => onSelectNode(node.id)} proOptions={{ hideAttribution: true }}>
        <Background />
        <MiniMap pannable zoomable />
        <Controls showInteractive />
      </ReactFlow>
    </div>
  )
}
