# TestPulse Next Build Plan

## Executive summary

The **Run Viewer MVP** is now in the repo. The next build should focus on making TestPulse **actually diagnostic, forensic, and prognostic** instead of adding more surface area.

The recommended order is:

1. **Component health evaluators** for DNS, DHCP, AD/LDAP, NTP, and NAS/CoA.
2. **Stable JSON contracts** for service metrics, component health, and per-node artifact maps.
3. **Run-history persistence** so prognostics use real prior runs instead of ad hoc inputs.
4. **Artifact-to-timeline linking** so the React Flow nodes and MCP tools point to the same evidence.
5. **UI overlays** driven by real outputs, not placeholder/sample data.

This keeps the architecture aligned with the dual-surface model:

- **IDE surface**: VS Code / IntelliJ AI chat + MCP tools
- **Product surface**: React Flow Run Viewer
- **Shared middle**: TestPulse MCP + Python diagnostics engine + FastAPI
- **Shared truth**: timeline, component health, prognostics, EvidenceBundle

## Current repo state

### Already present

- CLI-first diagnostics pipeline
- collectors, parsers, correlator, evaluator, bundle builder
- MCP server and shared service layer
- FastAPI Run Viewer MVP routes
- React Flow web scaffold
- first-pass health and prognostics support
- architecture and product docs

### Still missing or incomplete

- first-class DNS / DHCP / AD-LDAP / NTP / NAS evaluators
- durable run-history storage
- canonical per-node artifact maps
- standardized service metrics contract
- React Flow node overlays powered by real run outputs
- MCP responses fully normalized to the same contracts used by the UI

## Build objective

The next build should make TestPulse credible in three modes:

### Diagnostic

Answer **what failed and why** with structured component health findings, evidence references, severity, confidence, and recommendation text.

### Forensic

Answer **what proves it** by linking each AAA flow node to logs, packets, switch state, endpoint artifacts, and timeline events.

### Prognostic

Answer **what is likely to fail next** using run history, timing drift, anomaly detection, flake forecasting, and service baselines.

## First JSON contracts to lock down

### 1. `service_metrics.json`

Purpose: a compact metrics packet for one run that downstream logic can score.

```json
{
  "run_id": "RUN-20260317-001",
  "testcase_id": "TP-PREADM-001",
  "timestamp": "2026-03-17T20:10:00Z",
  "metrics": {
    "radius_decision_ms": 1200,
    "dns_lookup_ms": 35,
    "dhcp_ack_packets": 2,
    "ldap_bind_ms": 48,
    "coa_ack_ms": 210,
    "ntp_offset_ms": 11
  }
}
```

### 2. `component_health.json`

Purpose: normalized verdicts for DNS, DHCP, directory, NTP, and NAS/CoA.

```json
{
  "run_id": "RUN-20260317-001",
  "components": [
    {
      "component": "dns",
      "status": "HEALTHY",
      "severity": "low",
      "finding": "DNS lookups succeeded within threshold",
      "recommendation": "No action",
      "confidence": 0.94,
      "evidence": ["endpoint/nslookup_dc.txt", "pcap/auth_slice.pcap"]
    }
  ]
}
```

### 3. `artifact_map.json`

Purpose: bind React Flow nodes, MCP tools, and EvidenceBundle sections to the same evidence references.

```json
{
  "run_id": "RUN-20260317-001",
  "nodes": {
    "dhcp": ["endpoint/ipconfig.txt", "pcap/auth_slice.pcap"],
    "dns": ["endpoint/nslookup_dc.txt", "pcap/auth_slice.pcap"],
    "ad_ldap": ["identity/local_properties.txt", "pcap/auth_slice.pcap"],
    "radius": ["radius/radiusd.log"],
    "nas_authorization": ["switch/show_auth_session_detail.txt"],
    "coa": ["switch/switch_syslog.txt", "radius/radiusd.log"]
  }
}
```

### 4. `timeline.json`

Purpose: canonical correlated event stream for one run. This already exists conceptually and should become the universal source for UI/MCP drill-down.

### 5. `evidence_bundle.json`

Purpose: final human- and machine-consumable output with verdict, findings, timeline refs, artifact refs, health, and prognostics.

## First five Python modules to create

These five modules should be built first because they directly unlock the diagnostic layer and create the inputs for forensics and prognostics.

### 1. `testpulse/diagnostics/dns_health.py`

Responsibilities:
- parse resolver evidence and DNS timing
- classify `HEALTHY | DEGRADED | FAILED`
- surface lookup latency, wrong-resolver patterns, and DC lookup failures
- emit finding + recommendation + evidence refs

### 2. `testpulse/diagnostics/dhcp_health.py`

Responsibilities:
- detect lease success/failure and abnormal retry patterns
- compare assigned address/subnet to expected policy or VLAN context
- emit DHCP anomaly signals for later prognostics

### 3. `testpulse/diagnostics/directory_health.py`

Responsibilities:
- evaluate AD / LDAP reachability, bind timing, sign-and-seal / machine-account indicators
- distinguish authentication dependency failures from policy failures
- emit structured directory verdicts and recommendation text

### 4. `testpulse/diagnostics/ntp_health.py`

Responsibilities:
- normalize clock-sync outputs from Windows, Linux, and switch evidence
- classify time-integrity risk for TimingBudget and packet/log correlation
- mark runs as time-suspect when skew exceeds threshold

### 5. `testpulse/diagnostics/nas_health.py`

Responsibilities:
- evaluate switch authorization state, VLAN/ACL application, session status, and CoA / reauth evidence
- separate RADIUS decision success from actual network enforcement success

## Immediate follow-on modules

As soon as the first five modules are stable, add:

- `testpulse/services/history_service.py` — persist and query prior runs
- `testpulse/services/metrics_service.py` — build and normalize `service_metrics.json`
- `testpulse/services/artifact_map_service.py` — build per-node artifact references
- `testpulse/storage/sqlite.py` — lightweight local history store
- `testpulse/storage/schema.sql` — run, metric, health, anomaly, and flake tables

## File-by-file build order

### Step 1 — Diagnostics contracts

Add:

- `testpulse/diagnostics/dns_health.py`
- `testpulse/diagnostics/dhcp_health.py`
- `testpulse/diagnostics/directory_health.py`
- `testpulse/diagnostics/ntp_health.py`
- `testpulse/diagnostics/nas_health.py`

Update:

- `testpulse/diagnostics/__init__.py`
- `testpulse/core/bundle.py`
- `testpulse/services/diagnostics_service.py`

Definition of done:
- each evaluator returns a normalized dict/object
- each evaluator includes `status`, `severity`, `finding`, `recommendation`, `confidence`, `evidence`
- EvidenceBundle includes a `component_health` section built from these evaluators

### Step 2 — Forensic artifact map

Add:

- `testpulse/services/artifact_map_service.py`

Update:

- `testpulse/services/timeline_service.py`
- `testpulse/core/bundle.py`
- `testpulse/api/routes/bundle.py`
- `testpulse/api/routes/timeline.py`

Definition of done:
- every major AAA node maps to at least one artifact reference
- the UI and MCP can both ask for node-specific artifacts
- EvidenceBundle references match timeline node IDs

### Step 3 — Run history and prognostic persistence

Add:

- `testpulse/storage/sqlite.py`
- `testpulse/storage/schema.sql`
- `testpulse/services/history_service.py`
- `testpulse/services/metrics_service.py`

Update:

- `testpulse/diagnostics/prognostics.py`
- `testpulse/services/prognostics_service.py`
- `testpulse/api/routes/prognostics.py`

Definition of done:
- prior runs can be queried by run ID, testcase, endpoint, and date
- prognostics read history from storage instead of only manual JSON input
- trend score, drift warning, anomaly, and flake forecast are persisted per run

### Step 4 — React Flow overlays

Update:

- `web/src/components/AAAGraph.tsx`
- `web/src/components/ArtifactPanel.tsx`
- `web/src/components/PrognosticBadges.tsx`
- `web/src/pages/RunViewer.tsx`

Definition of done:
- node colors come from `component_health`
- node badge counts come from `prognostics`
- clicking a node shows timeline steps + artifact refs + findings

### Step 5 — MCP normalization

Update:

- `testpulse/mcp/tools.py`
- `testpulse/mcp/server.py`

Definition of done:
- MCP tools return structured data aligned with the API contracts
- MCP tools reference the same service-layer outputs the UI uses
- no parallel orchestration logic lives only inside MCP handlers

## Recommended API additions

Once the contracts above exist, expose:

- `GET /runs/{run_id}/service-metrics`
- `GET /runs/{run_id}/component-health`
- `GET /runs/{run_id}/artifact-map`
- `GET /runs/{run_id}/timeline`
- `GET /runs/{run_id}/prognostics`

These routes should serve both the React Flow UI and MCP-driven agent flows.

## Test plan for the next build

Add these first tests:

- `tests/test_dns_health.py`
- `tests/test_dhcp_health.py`
- `tests/test_directory_health.py`
- `tests/test_ntp_health.py`
- `tests/test_nas_health.py`
- `tests/test_artifact_map_service.py`
- `tests/test_history_service.py`
- `tests/test_prognostics_from_history.py`
- `tests/test_run_viewer_api_contracts.py`

## Exit criteria

The next build is complete when all of the following are true:

1. A single run produces real component-health outputs for DNS, DHCP, AD/LDAP, NTP, and NAS.
2. React Flow can display those outputs without using placeholder/sample data.
3. MCP tools and the UI consume the same contracts.
4. Prior-run history is stored locally and used for prognostics.
5. EvidenceBundle contains diagnostic, forensic, and prognostic sections that point to the same artifact map.

## Short implementation sequence

### Sprint 1
- build the five diagnostic modules
- normalize their output into `component_health.json`
- update EvidenceBundle

### Sprint 2
- add artifact-map service
- attach artifacts to nodes and timeline
- expose API routes for UI/MCP

### Sprint 3
- add SQLite run history
- upgrade prognostics to consume history
- persist anomalies, baselines, and flake forecasts

### Sprint 4
- drive React Flow node overlays from real health/prognostic data
- normalize MCP outputs to the same contracts

## Final recommendation

The next build should make **the backend smarter before the UI becomes prettier**.

That means:

- **diagnostic** = structured component verdicts
- **forensic** = node-to-artifact evidence linking
- **prognostic** = history-backed risk scoring

Once those are in place, the Run Viewer and MCP surfaces become true synchronized clients over one shared TestPulse truth model.
