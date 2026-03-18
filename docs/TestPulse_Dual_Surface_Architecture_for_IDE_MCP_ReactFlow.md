# TestPulse Dual-Surface Architecture for IDE AI, MCP, and React Flow

## Core design correction

The clean visual story is **not**:

`VS Code / IntelliJ -> React Flow -> MCP -> Copilot`

It should be:

**two front ends over one TestPulse intelligence layer**

- **Developer front end:** VS Code / IntelliJ with AI chat or agent
- **Product front end:** React Flow visualization UI
- **Shared middle:** TestPulse MCP + Python diagnostics engine
- **Shared data plane:** logs, pcaps, switch state, AD/LDAP, DNS/DHCP, EvidenceBundle history

That is the architecture to present.

## Recommended visual architecture

```text
┌─────────────────────────────────────────────────────────────────────────────┐
│                           DEVELOPER / USER SURFACES                        │
├─────────────────────────────────────────────────────────────────────────────┤
│  A) IDE Surface                                                            │
│     ┌───────────────────────┐      ┌─────────────────────────────────────┐ │
│     │ VS Code              │      │ IntelliJ / JetBrains IDE           │ │
│     │ Copilot Chat / Agent │      │ Copilot Chat OR AI Assistant       │ │
│     │ MCP-enabled tools    │      │ MCP-enabled tools                  │ │
│     └──────────┬────────────┘      └──────────────┬──────────────────────┘ │
│                │                                   │                        │
│                └─────────────── Developer asks ────┘                        │
│                         "Diagnose this RADIUS failure"                      │
│                         "Show DHCP drift"                                   │
│                         "Build EvidenceBundle"                              │
│                                                                             │
│  B) Product / Demo Surface                                                  │
│     ┌─────────────────────────────────────────────────────────────────────┐ │
│     │ React Flow Web UI                                                  │ │
│     │ - zoom / pan / minimap / playback                                  │ │
│     │ - clickable AAA nodes                                              │ │
│     │ - diagnostic / forensic / prognostic overlays                      │ │
│     │ - EvidenceBundle drawer / artifact panels                          │ │
│     └─────────────────────────────┬───────────────────────────────────────┘ │
└───────────────────────────────────┼─────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                         TESTPULSE CONTROL / TOOL LAYER                      │
├─────────────────────────────────────────────────────────────────────────────┤
│  MCP Server (safe tool gateway)                                            │
│  - ingest_run_folder                                                       │
│  - get_timeline                                                            │
│  - get_timing_budget                                                       │
│  - build_evidence_bundle                                                   │
│  - get_dns_health / get_dhcp_health / get_directory_health                 │
│  - get_prognostics                                                         │
└───────────────────────────────────┬─────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                       TESTPULSE PYTHON DIAGNOSTICS ENGINE                   │
├─────────────────────────────────────────────────────────────────────────────┤
│  Ingest / Parse                                                            │
│  - framework.log / radiusd.log / dot1x.log / pcap / syslog                │
│                                                                             │
│  Correlate                                                                  │
│  - session timeline                                                         │
│  - EAP / PEAP / CoA / NAS state chain                                      │
│                                                                             │
│  Diagnostic                                                                  │
│  - root cause                                                               │
│  - DNS / DHCP / AD / LDAP health                                            │
│  - NTP / timing / auth dependency checks                                    │
│                                                                             │
│  Forensic                                                                    │
│  - artifact linking                                                         │
│  - packet / log / switch state evidence                                     │
│                                                                             │
│  Prognostic                                                                  │
│  - trend score                                                              │
│  - drift prediction                                                         │
│  - anomaly detection                                                        │
│  - flake forecast                                                           │
│  - service baselines                                                        │
│                                                                             │
│  Output                                                                      │
│  - EvidenceBundle JSON                                                      │
│  - Timeline JSON                                                            │
│  - Work item payload                                                        │
└───────────────────────────────────┬─────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                              DATA / CONNECTOR PLANE                         │
├─────────────────────────────────────────────────────────────────────────────┤
│  Test artifacts       Network/Security      Identity/DDI         History    │
│  - logs               - switch auth         - AD / LDAP          - prior    │
│  - pcap               - syslog              - DNS / DHCP/IPAM      runs     │
│  - screenshots        - CoA / ACL / VLAN    - domain login       - trends   │
│  - endpoint state     - NAS session state   - group / OU         - flakes   │
└─────────────────────────────────────────────────────────────────────────────┘
```

## What the correction means

From a product perspective, **React Flow is not between the IDE and MCP**.

React Flow is a **separate visualization client**.

The correct mental model is:

- **IDE chat client** calls MCP tools
- **React Flow app** calls the same backend or MCP-backed API
- both consume the same TestPulse engine outputs

That is what makes the platform coherent and sellable.

## Commercialization story

**TestPulse gives engineering two synchronized experiences over the same truth.**

### 1) Inside the IDE
- developers use Copilot or AI chat to ask questions and run diagnostics
- no raw log digging
- tool-guided evidence access

### 2) Inside the product UI
- ops, QA, support, and customers see an interactive AAA map
- zoomable, clickable, evidence-backed flow
- diagnostics, forensics, and prognostics in one pane

### 3) Same backend, same EvidenceBundle
- no duplicate logic
- no separate “demo mode” engine
- same output powers IDE workflows, dashboards, and reports

## Recommended component mapping

### IDE layer
Use GitHub Copilot Chat as the common AI layer for VS Code first. For IntelliJ / JetBrains, support GitHub Copilot or JetBrains AI Assistant as the chat surface while keeping the same MCP-backed TestPulse services.

### Visualization layer
Use React Flow as the runtime drawing surface. It provides zoom, pan, selection, minimap, and polished node-based interaction that Mermaid lacks for runtime viewing.

### Tool layer
Use MCP as the safe gateway for:
- timeline retrieval
- DNS/DHCP/AD/LDAP diagnostics
- EvidenceBundle generation
- prognostic scoring

This keeps Copilot and other AI agents on a **tool rail**, not a raw-data rail.

## Synchronization view

```text
IDE Chat Prompt
   -> MCP Tool Call
      -> TestPulse Engine
         -> EvidenceBundle / Timeline / Health / Prognostics
            -> returned to IDE chat
            -> rendered in React Flow UI
            -> stored in run history / tracker
```

Synchronization means:
- the same request context
- the same backend outputs
- the same run ID / session ID / EvidenceBundle
- different user surfaces

## What the React Flow screen should show

Render these primary nodes:
- Endpoint / Supplicant
- DHCP
- DNS
- AD / LDAP
- PEAP / EAP
- RADIUS
- NAS Authorization
- CoA / Reauth
- EvidenceBundle

Add overlays for:
- **Diagnostic:** current failure cause
- **Forensic:** linked artifacts, logs, PCAP, switch state
- **Prognostic:** trend score, drift warning, anomaly, flake risk, baseline deviation

That turns the flow from a static diagram into a **living system map**.

## Phased stack recommendation

### Phase 1
- VS Code + GitHub Copilot + MCP
- React Flow web UI
- Python TestPulse backend
- single MCP server

### Phase 2
- add JetBrains / IntelliJ
- optionally support JetBrains AI Assistant as a second chat front end
- keep the same MCP-backed TestPulse services

### Phase 3
- expose a customer-facing dashboard
- add reporting / export / tracker sync
- make prognostics a visible early-warning panel

## One-line architecture summary

> **TestPulse is a dual-surface platform:** developers interact through **IDE AI chat + MCP tools**, while operators and customers use a **React Flow visualization UI**. Both are synchronized through the same **TestPulse diagnostics engine**, which produces shared timelines, health signals, and EvidenceBundles.
