export type HealthStatus = 'HEALTHY' | 'DEGRADED' | 'FAILED' | 'UNKNOWN'
export type OutcomeFilter = 'all' | 'pass' | 'fail'
export type BaselineMode = 'testcase_weekday_hour' | 'testcase_only' | 'all_history'

export type RunListItem = {
  run_id: string
  has_bundle?: boolean
  testcase_id?: string | null
  classification?: string | null
  observed_decision?: string | null
  expected_decision?: string | null
  functional_pass?: boolean | number | null
  confidence?: number | null
  created_at?: string | null
}

export type RunFilters = {
  q?: string
  classification?: string
  outcome?: Exclude<OutcomeFilter, 'all'>
  limit?: number
}

export type RunListResponse = {
  runs: RunListItem[]
  source?: string
  filters?: Record<string, string | number | null>
}

export type Bundle = {
  run_id: string
  testcase_id?: string
  classification?: string
  functional_pass?: boolean
  findings: string[]
  metadata?: {
    component_health?: Record<string, { status?: HealthStatus; evidence?: string[]; finding?: string; recommendation?: string }>
    prognostics?: Prognostics
    service_metrics?: { metrics?: Record<string, number> }
  }
  artifacts?: string[]
}

export type TimelineEvent = {
  ts?: string | null
  epoch?: number | null
  kind: string
  source: string
  message?: string | null
  endpoint_mac?: string | null
  endpoint_ip?: string | null
  username?: string | null
  domain?: string | null
  login_type?: string | null
  dns_name?: string | null
  dhcp_hostname?: string | null
  nas_ip?: string | null
  nas_port?: string | null
  nas_port_id?: string | null
  metadata?: Record<string, unknown>
}

export type ArtifactMap = {
  run_id: string
  nodes: Record<string, string[]>
}

export type TimelineContract = {
  run_id: string
  testcase_id?: string
  timeline: TimelineEvent[]
  artifact_map?: ArtifactMap
  findings?: string[]
}

export type ComponentContract = {
  component: string
  status: HealthStatus
  severity?: string
  confidence?: number
  finding?: string
  recommendation?: string
  evidence?: string[]
  details?: Record<string, unknown>
}

export type HealthContract = {
  run_id: string
  testcase_id?: string
  components: ComponentContract[]
  component_health?: Record<string, { status?: HealthStatus; evidence?: string[]; finding?: string; recommendation?: string }>
  findings?: string[]
}

export type Prognostics = {
  trend_health?: { score?: number; factors?: string[] }
  predictive_warnings?: Array<{ metric: string; message: string; severity?: string }>
  repeated_run_anomalies?: Array<{ metric: string; message: string; severity?: string }>
  flake_forecast?: { status?: string; risk?: number; message?: string }
  service_baselines?: { current_deviation?: Array<{ metric: string; status: string; deviation_pct?: number }> }
}

export type PrognosticsContract = {
  run_id: string
  testcase_id?: string
  prognostics: Prognostics
}

export type ArtifactContent = {
  run_id: string
  artifact_path: string
  content_type: 'text' | 'binary'
  preview: string
  download_path: string
}

export type ArtifactDiff = {
  run_id: string
  compare_run_id: string
  node_id: string
  artifact_path?: string | null
  compare_artifact_path?: string | null
  content_type: 'text' | 'binary'
  diff: string
}

export type TrendPoint = {
  run_id: string
  created_at?: string | null
  metric_key: string
  metric_value?: number | null
  status?: string
  severity?: string
}

export type TrendBaseline = {
  samples: number
  median?: number | null
  min?: number | null
  max?: number | null
  window?: string
  mode?: string
}

export type TrendContract = {
  run_id: string
  testcase_id?: string
  components: Record<string, TrendPoint[]>
  metric_map?: Record<string, string>
  baselines?: Record<string, TrendBaseline>
  baseline_mode?: string
  window_hours?: number
}

export type NodeDiff = {
  nodeId: string
  label: string
  primaryStatus: HealthStatus
  compareStatus: HealthStatus
  changed: boolean
  primarySeverity?: string
  compareSeverity?: string
}

export type RecommendationRollupItem = {
  node_id: string
  component?: string | null
  primary_finding?: string | null
  compare_finding?: string | null
  recommendations: Array<{
    source: 'primary' | 'compare'
    component?: string | null
    status?: string | null
    severity?: string | null
    confidence?: number | null
    finding?: string | null
    recommendation: string
  }>
}

export type RecommendationRollup = {
  run_id: string
  compare_run_id: string
  changed_nodes: Array<{
    node_id: string
    component?: string | null
    primary_status: string
    compare_status: string
    primary_severity?: string | null
    compare_severity?: string | null
  }>
  rollups: RecommendationRollupItem[]
}

export type StreamSnapshot = {
  run_id: string
  fingerprint: string
  bundle_summary: {
    classification?: string | null
    functional_pass?: boolean | null
    confidence?: number | null
    findings?: string[]
  }
  timeline_count: number
  components: Array<{
    component: string
    status: string
    severity?: string | null
    confidence?: number | null
  }>
  predictive_warnings?: Array<{ metric: string; message: string; severity?: string }>
}
