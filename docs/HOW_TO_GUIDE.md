# TestPulse Prototype v1 How-To Guide

## 1. Goal
Build a **small, auditable, CLI-first prototype** that turns one RADIUS pre-admission run into an EvidenceBundle. The design should stay narrow: parse `framework.log`, `radiusd.log`, and `dot1x.log`, correlate a single auth flow, determine whether the observed outcome was **Access-Accept** or **Access-Reject**, compare it to the expected decision, and write a compact JSON bundle. This is the exact MVP boundary recommended in the project notes.

The easiest implementation path is also explicit in the notes: **Phase 1 is VS Code + CLI**, **Phase 2 is a thin FastAPI wrapper**, and **MCP for GitHub Copilot comes later**, after the core contracts stabilize.

## 2. Why this architecture
Use a backend-first design, but expose it as a CLI before turning it into a Copilot or MCP product. That keeps the service as the source of truth, avoids extension maintenance too early, and lets engineers run it from the terminal or VS Code tasks right away.

The prototype should stay focused on these four core parts:
- evidence parser
- decision evaluator
- assurance evaluator
- EvidenceBundle output


## Architecture references

Use these docs when positioning the product and the UI split between IDE AI surfaces and the React Flow operations surface:
- [Dual-surface architecture (PDF)](TestPulse_Dual_Surface_Architecture_for_IDE_MCP_ReactFlow.pdf)
- [Dual-surface architecture (Markdown)](TestPulse_Dual_Surface_Architecture_for_IDE_MCP_ReactFlow.md)
- [Dual-surface architecture (DOCX)](TestPulse_Dual_Surface_Architecture_for_IDE_MCP_ReactFlow.docx)

## 3. Repo layout
The recommended v1 repo shape is small. This version keeps the layout Copilot-friendly by putting the docs, playbook, and executable scaffold in the same repo so GitHub Copilot can index it and reuse it in chat.

```text
testpulse_proto_v1/
  .vscode/
    tasks.json
  artifacts/
    latest/
      framework.log
      radiusd.log
      dot1x.log
  docs/
    copilot_playbook.md
    HOW_TO_GUIDE.md
    pcap_agent_guide.md
  testpulse/
    __init__.py
    models.py
    ingest/
      __init__.py
      framework_parser.py
      radiusd_parser.py
      dot1x_parser.py
      eapol_parser.py
      endpoint_parser.py
      redis_parser.py
      identity_parser.py
    core/
      __init__.py
      correlate.py
      evaluate.py
      bundle.py
    collect/
      __init__.py
      appliance_collector.py
      endpoint_collector.py
      pcap_collector.py
      ntp_sync.py
      tunnel_manager.py
    tools/
      __init__.py
      run_diagnostics.py
      mermaid_timeline.py
      eapol_test_runner.py
  pyproject.toml
  README.md
```

## 4. Run-folder contract
The run folder is the first real contract. Keep it stable before adding a wrapper API or MCP. The notes repeatedly emphasize that MCP should wait until the **run folder contract**, **normalized metadata keys**, **EvidenceBundle schema**, **timeline output**, and **timing output** are stable.

### Minimum artifact contract
- `framework.log`
- `radiusd.log`
- `dot1x.log`

### Extended artifact contract (Phase 1 actual)
- `radiusd.log` — RADIUS access request/accept/reject events
- `dot1x.log` — dot1x plugin lifecycle, policy config, MAR
- `framework.log` — fstester framework verification events
- `redis_monitor.log` — Redis command stream
- `redis_hash_dump.txt` — Redis hash state snapshot
- `local_properties.txt` — Forescout local properties
- `fstool_dot1x_status.txt` — fstool dot1x status output
- `fstool_hostinfo_<mac>.txt` — Per-host fstool info
- `endpoint/` — Windows endpoint artifacts (WinRM)
- `*.pcap` / `*.pcapng` — Wire captures

### Required normalized fields
- `testcase_id`
- `run_id`
- `session_id`
- `endpoint_mac`
- `username`
- `nas_port`
- `timestamp`

### Extended metadata keys (Phase 1 actual — 30+ fields)
- `radius_id`, `src_ip`, `src_port`, `dst_ip`, `dst_port`, `packet_length`
- `service_type`, `nas_port_type`, `nas_port_id`, `framed_mtu`, `auth_method`
- `epoch`, `pid`, `plugin_version`, `policy_enabled`, `eap_type`, `vlan_config`
- `context_id`, `property_field`, `property_value`
- `rule_slot`, `rule_action`, `auth_source`, `domain`, `login_type`
- `host_in_mar`, `dhcp_hostname`, `dns_name`, `classification`

## 5. VS Code integration first
The recommended first UI is **VS Code tasks**, not a full extension. That gives you a one-click workflow with almost no integration overhead.

### `.vscode/tasks.json`
```json
{
  "version": "2.0.0",
  "tasks": [
    {
      "label": "TestPulse: Run Diagnostics (latest)",
      "type": "shell",
      "command": "python",
      "args": [
        "-m",
        "testpulse.tools.run_diagnostics",
        "--run-dir",
        "${workspaceFolder}/artifacts/latest",
        "--testcase-id",
        "TP-PREADM-001",
        "--expected-decision",
        "accept",
        "--out",
        "${workspaceFolder}/artifacts/latest/evidence_bundle.json",
        "--pretty"
      ],
      "group": {
        "kind": "test",
        "isDefault": true
      },
      "presentation": {
        "reveal": "always",
        "panel": "shared",
        "clear": true
      },
      "problemMatcher": []
    }
  ]
}
```

## 6. Python package skeleton
### `pyproject.toml`
```toml
[build-system]
requires = ["setuptools>=68", "wheel"]
build-backend = "setuptools.build_meta"

[project]
name = "testpulse-proto"
version = "0.1.0"
description = "CLI-first TestPulse prototype scaffold"
readme = "README.md"
requires-python = ">=3.11"
dependencies = []
```

## 7. Core pipeline

### Data flow

```
logs/pcap  →  Parsers  →  AuthEvent[]  →  Correlator  →  Evaluator  →  EvidenceBundle
                                                                            │
                                          ┌────────┬─────────┬────────┤
                                          ▼        ▼         ▼        ▼
                                        .json   .mmd(x6)  .html   HTTP:8765
                                       bundle   diagrams   pages    server
```

### Diagram types (6 total)

| # | Diagram | Mermaid Type | Direction |
|---|---------|-------------|----------|
| 1 | Protocol Sequence | `sequenceDiagram` | Vertical |
| 2 | Protocol Sequence | `graph LR` | Horizontal |
| 3 | Chronological Timeline | `graph LR` | Horizontal |
| 4 | Component Topology | `graph LR` | Horizontal |
| 5 | EAPOL Wire Trace | `sequenceDiagram` | Vertical (pcap only) |
| 6 | EAPOL Wire Trace | `graph LR` | Horizontal (pcap only) |

Each `.mmd` file is also exported as a self-contained `.html` with embedded Mermaid.js CDN.
An HTTP server auto-starts on port 8765 to serve diagrams in-browser or VS Code Simple Browser (`Ctrl+Shift+P` → `Simple Browser: Show`).

### AuthEvent model (30+ fields)
The core data structure. Every parser produces `AuthEvent` objects with a common schema:
- **Tier 1 (identity)**: `ts`, `kind`, `source`, `message`
- **Tier 2 (auth context)**: MAC, IP, username, NAS, session IDs
- **Tier 3 (rich metadata)**: RADIUS packet details, dot1x state, network topology

### Evaluator decision logic
- Access-Accept seen, no Reject → `ACCEPT` (confidence 0.85–0.95)
- Access-Reject seen, no Accept → `REJECT` (confidence 0.85–0.95)
- Framework confirms → confidence boost to 0.90+
- Multiple corroborating sources → higher confidence

### Classification
- `PASS_CONFIRMED` — observed matches expected, confidence ≥ 0.9
- `PASS_LOW_CONFIDENCE` — observed matches expected, confidence < 0.9
- `MISMATCH` — observed does not match expected
- `INSUFFICIENT_EVIDENCE` — cannot determine decision

## 8. Example run

### Basic analysis
```bash
testpulse \
  --run-dir ./artifacts/latest \
  --testcase-id TP-PREADM-001 \
  --expected-decision accept \
  --out ./artifacts/latest/evidence_bundle.json \
  --pretty
```

### Full single-command workflow
```bash
testpulse \
  --run-dir /tmp/T1316925 \
  --testcase-id T1316925 \
  --expected-decision accept \
  --expected-method mab \
  --collect \
  --appliance-ip 10.100.49.87 \
  --mac 28:80:23:b8:2d:59 \
  --framework-log ./fstester.log \
  --ntp-check \
  --testbed-config ./radius.yml \
  --pretty
```

### Expected result shape
```json
{
  "testcase_id": "T1316925",
  "run_id": "T1316925",
  "observed_decision": "accept",
  "expected_decision": "accept",
  "functional_pass": true,
  "classification": "PASS_CONFIRMED",
  "confidence": 0.9,
  "findings": [
    "Observed decision: accept",
    "Expected decision: accept",
    "Functional pass: True"
  ],
  "timeline": [ ... ],
  "artifacts": [
    "dot1x.log",
    "framework.log",
    "radiusd.log",
    "redis_monitor.log",
    "redis_hash_dump.txt",
    "local_properties.txt",
    "fstool_dot1x_status.txt",
    "fstool_hostinfo_288023b82d59.txt"
  ],
  "metadata": {}
}
```

## 9. Best demo testcase
Use a **wired EAP-TLS assurance flow** that gives you both sides of the pre-admission result:
- valid cert → expect **Access-Accept**
- broken trust path → expect **Access-Reject**

That is the clearest first proof because it demonstrates that the prototype can correctly classify accept vs reject from evidence and compare it to the expected outcome.

For MAB (MAC Authentication Bypass):
- known MAC → expect **Access-Accept**
- unknown MAC → expect **Access-Reject**

## 10. What not to add yet
Do not start v1 with:
- rich web UI
- full MCP server
- identity/IPAM/syslog enrichment
- HTML export
- broad tracker automation

The notes are explicit that the clean first move is to make the one-button workflow work on one representative run first, then layer timing and adapters on top.

## 11. Phase 2: thin API and MCP path
Once the CLI contracts are stable, add a thin FastAPI wrapper and then expose safe read-only tools through MCP. The notes describe MCP as a **Copilot-facing tool layer** that sits in front of the same Python backend and retrieval adapters, not as a replacement for the backend.

### First MCP tool set
- `find_run`
- `list_run_artifacts`
- `ingest_run_folder`
- `get_timeline`
- `get_timing_budget`
- `build_evidence_bundle`
- `lookup_endpoint_identity`
- `lookup_ipam_record`
- `get_switch_auth_session`
- `sync_work_item`

### MCP operating rules
- read-only by default
- no direct SUT/DUT mutation
- no arbitrary shell tool
- return structured excerpts, not giant raw logs
- log every MCP tool call
- support on-prem sidecar deployment first

## 12. Phase 2 timing preflight
When you add timing evaluation, treat clock sync as a required preflight artifact. The notes already call out collecting Windows `w32tm`, Linux `timedatectl`/`chronyc`, and Cisco `show clock`/`show ntp status` so TimingBudget calculations do not get polluted by clock drift.

> **Phase 1 already implements NTP preflight** via `testpulse.collect.ntp_sync.NtpSyncChecker` with thresholds: ≤50ms = SYNC_OK, ≤500ms = SYNC_WARNING, >500ms = SYNC_FAIL.

## 13. Deliverable framing
If you package this for leadership or handoff, align the prototype to the same gate structure already defined for TestPulse: evidence ingestion, correlation, diagnostics bundle, determinism, then workflow closure. That gives the scaffold a direct path into the broader SOW package.

## Run Viewer MVP

The repo now includes a thin **FastAPI** layer in `testpulse/api/` and a **React Flow** UI scaffold in `web/`.

Use them as the shared product seam for the dual-surface architecture:
- IDE / MCP tools
- React Flow Run Viewer

Suggested startup:

```bash
pip install -e .[api]
uvicorn testpulse.api.app:app --reload
```

```bash
cd web
npm install
npm run dev
```

## Planning

- [Next build plan (PDF)](TestPulse_Next_Build_Plan.pdf)
- [Next build plan (Markdown)](TestPulse_Next_Build_Plan.md)
- [Next build plan (DOCX)](TestPulse_Next_Build_Plan.docx)
