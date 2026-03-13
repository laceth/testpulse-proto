# TestPulse Copilot Playbook

This repo is the prototype source of truth for TestPulse v1.

## Copilot rules
- Keep the prototype CLI-first.
- Do not add MCP or a rich UI until the CLI contracts are stable.
- Always preserve the run-folder contract.
- Prefer read-only enrichment patterns.
- Do not add secret values, credentials, or customer-only IPs to committed files.

## Required artifacts for v1
- `framework.log`
- `radiusd.log`
- `dot1x.log`
- `evidence_bundle.json`
- Mermaid diagrams (6 types: protocol V/H, timeline H, components H, EAPOL V/H)
- HTML diagram exports (self-contained, Mermaid.js CDN)

## Diagram conventions
- Horizontal diagrams use `graph LR` (not `flowchart` — compatibility with older Mermaid.js)
- No `direction LR` inside subgraphs
- No `==>` thick arrows — use `-->` only
- No Unicode symbols in labels — use ASCII `[PASS]`, `[FAIL]`, `[WARN]`
- Label text truncated with balanced parentheses/brackets
- HTML export auto-starts HTTP server on port 8765

## Required metadata keys
- `testcase_id`
- `run_id`
- `session_id`
- `endpoint_mac`
- `username`
- `nas_port`
- `timestamp`

## Design intent
This prototype should prove one thing well: ingest one wired EAP-TLS pre-admission
run, reconstruct the auth flow, compare observed Accept/Reject to the expected result,
and emit a compact EvidenceBundle JSON.

## Phase order
1. CLI + VS Code tasks
2. Thin FastAPI wrapper
3. MCP server and richer enrichments
