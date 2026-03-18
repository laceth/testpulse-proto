import type { ArtifactMap, ComponentContract, HealthStatus, NodeDiff, TimelineEvent } from '../types'

export const GRAPH_NODE_IDS = [
  'endpoint_supplicant',
  'dhcp',
  'tcpip_relay',
  'dns',
  'ad_ldap',
  'radius',
  'nas_authorization',
  'tomahawk',
  'coa',
  'ntp',
  'evidence_bundle',
] as const

export const GRAPH_NODE_LABELS: Record<string, string> = {
  endpoint_supplicant: 'Endpoint / Supplicant',
  dhcp: 'DHCP',
  tcpip_relay: 'TCP/IP Relay',
  dns: 'DNS',
  ad_ldap: 'AD / LDAP',
  radius: 'RADIUS / PEAP / EAP',
  nas_authorization: 'NAS Authorization',
  tomahawk: 'Tomahawk Fabric',
  coa: 'CoA / Reauth',
  ntp: 'NTP / Time Integrity',
  evidence_bundle: 'EvidenceBundle',
}

export function nodeIdForEvent(event: TimelineEvent): string {
  const source = (event.source || '').toLowerCase()
  const kind = event.kind || ''
  const message = (event.message || '').toLowerCase()
  const metadata = event.metadata || {}
  if (source.includes('ntp') || source.includes('chrony') || source.includes('w32tm') || source.includes('timedatectl')) return 'ntp'
  if (kind.includes('COA') || source.includes('coa') || source.includes('syslog')) return 'coa'
  if (source.includes('tomahawk') || message.includes('tomahawk') || String(metadata['platform'] || '').toLowerCase().includes('tomahawk')) return 'tomahawk'
  if (event.nas_ip || event.nas_port || event.nas_port_id || source.includes('auth_session') || source.includes('show_auth')) return 'nas_authorization'
  if (kind.includes('RADIUS_') || source.includes('radius')) return 'radius'
  if (event.domain || event.login_type || source.includes('ldap') || kind.startsWith('IDENTITY_')) return 'ad_ldap'
  if (source.includes('relay') || source.includes('iphelper') || source.includes('helper-address') || message.includes('relay') || String(metadata['relay'] || '').toLowerCase() === 'true') return 'tcpip_relay'
  if (event.dns_name || source.includes('dns') || source.includes('nslookup') || source.includes('dig')) return 'dns'
  if (event.endpoint_ip || event.dhcp_hostname || source.includes('dhcp') || source.includes('ipconfig')) return 'dhcp'
  if (source.includes('framework') || source.includes('dot1x') || kind.startsWith('EAP') || kind.startsWith('DOT1X')) return 'endpoint_supplicant'
  return 'evidence_bundle'
}

export function componentForNode(nodeId: string, components: ComponentContract[]): ComponentContract | undefined {
  const map: Record<string, string> = {
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
  const component = map[nodeId]
  return component ? components.find((item) => item.component === component) : undefined
}

export function artifactForEvent(event: TimelineEvent, artifactMap?: ArtifactMap): string | null {
  if (!artifactMap) return null
  const nodeId = nodeIdForEvent(event)
  const artifacts = artifactMap.nodes?.[nodeId] || []
  const sourceLower = event.source.toLowerCase()
  const direct = artifacts.find((artifact) => artifact.toLowerCase().includes(sourceLower) || sourceLower.includes(artifact.toLowerCase()))
  return direct || artifacts[0] || null
}

export function severityTone(severity?: string): { bg: string; fg: string } {
  switch ((severity || '').toLowerCase()) {
    case 'high':
      return { bg: '#fef2f2', fg: '#b91c1c' }
    case 'medium':
      return { bg: '#fffbeb', fg: '#b45309' }
    case 'low':
      return { bg: '#eff6ff', fg: '#1d4ed8' }
    default:
      return { bg: '#f3f4f6', fg: '#374151' }
  }
}

export function normalizeStatus(status?: string): HealthStatus {
  if (status === 'HEALTHY' || status === 'DEGRADED' || status === 'FAILED' || status === 'UNKNOWN') return status
  return 'UNKNOWN'
}

export function buildNodeDiffs(primary: ComponentContract[], compare: ComponentContract[]): NodeDiff[] {
  return GRAPH_NODE_IDS.map((nodeId) => {
    const primaryComponent = componentForNode(nodeId, primary)
    const compareComponent = componentForNode(nodeId, compare)
    const primaryStatus = normalizeStatus(primaryComponent?.status)
    const compareStatus = normalizeStatus(compareComponent?.status)
    return {
      nodeId,
      label: GRAPH_NODE_LABELS[nodeId],
      primaryStatus,
      compareStatus,
      changed: primaryStatus !== compareStatus || (primaryComponent?.severity || '') !== (compareComponent?.severity || ''),
      primarySeverity: primaryComponent?.severity,
      compareSeverity: compareComponent?.severity,
    }
  })
}
