# TestPulse Prototype v1

CLI-first scaffold for a narrow TestPulse MVP.

## What this prototype proves
- ingest `framework.log`, `radiusd.log`, and `dot1x.log`
- correlate one auth flow
- determine `accept`, `reject`, or `unknown`
- compare observed decision to expected decision
- emit an auditable `evidence_bundle.json`

## Quick start
```bash
python -m venv .venv
source .venv/bin/activate
pip install -e .
python -m testpulse.tools.run_diagnostics \
  --run-dir ./artifacts/latest \
  --testcase-id TP-PREADM-001 \
  --expected-decision accept \
  --out ./artifacts/latest/evidence_bundle.json \
  --pretty
```

Or run the default VS Code task:
- **TestPulse: Run Diagnostics (latest)**

## Repo map
```
testpulse_proto_v1/
  .vscode/tasks.json
  artifacts/latest/ (framework.log, radiusd.log, dot1x.log)
  docs/copilot_playbook.md
  testpulse/ (models.py, ingest/, core/, tools/)
  pyproject.toml, README.md
```

## Phase plan
### Phase 1 - CLI, VS Code task, JSON EvidenceBundle
### Phase 2 - thin FastAPI wrapper, timing-budget evaluation, HTML/PDF export
### Phase 3 - MCP server for Copilot, identity/IPAM/syslog adapters, work-item sync
