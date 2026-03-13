# TestPulse Proto v1

**CLI-first 802.1X diagnostic toolkit for Forescout RADIUS/dot1x test automation.**

TestPulse collects logs from Forescout appliances, parses RADIUS/dot1x/framework/Redis/identity data sources, correlates authentication events, evaluates pass/fail against expected outcomes, and generates Mermaid sequence diagrams — all from a single command.

> **Phase 1** — CLI build.  7,300+ lines of Python across 24 modules.

---

## Architecture

```
┌─────────────┐   ┌─────────────┐   ┌─────────────┐   ┌─────────────┐
│  Appliance  │   │   Switch    │   │  Endpoint   │   │  PCAP File  │
│  (SSH/SFTP) │   │   (SSH)     │   │  (WinRM)    │   │  (.pcap)    │
└──────┬──────┘   └──────┬──────┘   └──────┬──────┘   └──────┬──────┘
       │                 │                 │                 │
       └────────┬────────┴────────┬────────┘                 │
                │   COLLECTORS    │                          │
                ▼                 ▼                          │
       ┌─────────────────────────────────────────────────────┤
       │                    RUN DIRECTORY                    │
       │  radiusd.log  dot1x.log  framework.log  redis_*    │
       │  local_properties.txt  fstool_*  endpoint/  *.pcap │
       └────────────────────────┬────────────────────────────┘
                                │
                    ┌───────────▼───────────┐
                    │       PARSERS         │
                    │  7 parsers, 70+ kinds │
                    └───────────┬───────────┘
                                │
                    ┌───────────▼───────────┐
                    │     CORRELATOR        │
                    │  sort + deduplicate   │
                    └───────────┬───────────┘
                                │
                    ┌───────────▼───────────┐
                    │      EVALUATOR        │
                    │  decision + confidence│
                    └───────────┬───────────┘
                                │
          ┌────────┬────────▼────────┬─────────┬──────────┐
          │        │                 │         │          │
          ▼        ▼                 ▼         ▼          ▼
    ┌────────┐ ┌──────────┐   ┌──────────┐ ┌──────────┐ ┌──────────┐
    │ Bundle │ │ Protocol │   │ Timeline │ │Component │ │  EAPOL   │
    │  .json │ │  V + H   │   │  (H)     │ │  (H)     │ │  V + H   │
    │        │ │ .mmd+html│   │ .mmd+html│ │ .mmd+html│ │ .mmd+html│
    └────────┘ └──────────┘   └──────────┘ └──────────┘ └──────────┘
                              │
                    ┌─────────▼─────────┐
                    │   HTTP Server     │
                    │  localhost:8765   │
                    │  (auto-started)   │
                    └───────────────────┘
```

## Quick Start

### Install

```bash
cd testpulse_proto_v1
python3 -m venv .testpulse
source .testpulse/bin/activate
pip install -e .
pip install paramiko pyyaml scapy dpkt         # collection + pcap support
pip install pywinrm pypsrp                      # Windows endpoint support (optional)
```

### Analyze existing logs

```bash
testpulse \
  --run-dir ./my-run \
  --testcase-id T1316925 \
  --expected-decision accept \
  --expected-method mab \
  --out ./my-run/evidence_bundle.json \
  --pretty
```

### Single command: collect + analyze + diagrams

```bash
testpulse \
  --run-dir /tmp/T1316925 \
  --testcase-id T1316925 \
  --expected-decision accept \
  --expected-method mab \
  --collect \
  --appliance-ip 10.100.49.87 \
  --mac 28:80:23:b8:2d:59 \
  --framework-log /home/triley/fstester001-mab/fstester.log \
  --out /tmp/T1316925/evidence_bundle.json \
  --pretty
```

### With testbed config (pulls connection info from YAML)

```bash
testpulse \
  --run-dir /tmp/T1316925 \
  --testcase-id T1316925 \
  --expected-decision accept \
  --collect \
  --testbed-config /path/to/radius.yml \
  --framework-log ./fstester.log \
  --ntp-check \
  --pretty
```

### Parse PCAP files for EAPOL/RADIUS wire traces

```bash
testpulse \
  --run-dir /tmp/T1316925 \
  --testcase-id T1316925 \
  --expected-decision accept \
  --pcap /tmp/capture.pcap \
  --pretty
```

## Output

Every run produces:

| Artifact | Format | Description |
|----------|--------|-------------|
| `evidence_bundle.json` | JSON | Full evidence bundle with decision, confidence, timeline, findings |
| `evidence_bundle.mmd` | `sequenceDiagram` | Protocol sequence — vertical (participants top-to-bottom) |
| `evidence_bundle_protocol_h.mmd` | `graph LR` | Protocol sequence — horizontal (left-to-right flowchart) |
| `evidence_bundle_timeline.mmd` | `graph LR` | Chronological timeline — horizontal with time subgraphs |
| `evidence_bundle_components.mmd` | `graph LR` | Component topology — devices, config, data sources |
| `evidence_bundle_eapol.mmd` | `sequenceDiagram` | EAPOL wire trace — vertical (auto when pcap present) |
| `evidence_bundle_eapol_h.mmd` | `graph LR` | EAPOL wire trace — horizontal (auto when pcap present) |
| `*.html` | HTML | Self-contained HTML for each diagram (Mermaid.js CDN) |

An HTTP server is auto-started on **port 8765** to serve diagrams in-browser or VS Code Simple Browser.

### Example output

```
[OK] Wrote EvidenceBundle: /tmp/T1316925/evidence_bundle.json
     testcase_id=T1316925
     observed_decision=accept
     expected_decision=accept
     classification=PASS_CONFIRMED
     confidence=0.9
     events_parsed=46
     artifacts_found=8
[OK] Wrote protocol diagram (vertical): evidence_bundle.mmd
[OK] Wrote protocol diagram (horizontal): evidence_bundle_protocol_h.mmd
[OK] Wrote timeline diagram (horizontal): evidence_bundle_timeline.mmd
[OK] Wrote component topology (horizontal): evidence_bundle_components.mmd
[OK] Wrote HTML diagram: evidence_bundle.html
[OK] Wrote HTML diagram: evidence_bundle_protocol_h.html
[OK] Wrote HTML diagram: evidence_bundle_timeline.html
[OK] Wrote HTML diagram: evidence_bundle_components.html
[OK] Started HTTP server on port 8765

============================================================
  Diagram URLs (open in browser or VS Code Simple Browser)
  Ctrl+Shift+P -> 'Simple Browser: Show' -> paste URL
============================================================
  http://localhost:8765/evidence_bundle.html
  http://localhost:8765/evidence_bundle_protocol_h.html
  http://localhost:8765/evidence_bundle_timeline.html
  http://localhost:8765/evidence_bundle_components.html
  http://localhost:8765/          (directory listing)
============================================================
```

### Viewing diagrams

| Method | How |
|--------|-----|
| **Browser** | Open any URL from the output above |
| **VS Code Simple Browser** | `Ctrl+Shift+P` → `Simple Browser: Show` → paste URL |
| **Chat** | Diagrams are rendered inline when using Copilot |
| **Markdown Preview** | Open `_preview.md` files with `Ctrl+Shift+V` (requires `bierner.markdown-mermaid`) |

## Repo Structure

```
testpulse/
├── models.py                  # AuthEvent (30+ fields), Decision, EvidenceBundle
├── ingest/                    # Log parsers (text → AuthEvent[])
│   ├── radiusd_parser.py      #   RADIUS Access-Request/Accept/Reject
│   ├── dot1x_parser.py        #   Forescout dot1x plugin lifecycle (24 kinds)
│   ├── framework_parser.py    #   fstester framework.log (24 kinds)
│   ├── endpoint_parser.py     #   Windows endpoint artifacts
│   ├── redis_parser.py        #   Redis monitor + hash dump (4 kinds)
│   ├── identity_parser.py     #   local.properties, hostinfo, fstool (9 kinds)
│   └── eapol_parser.py        #   EAPOL/EAP/RADIUS from pcap (scapy/dpkt)
├── core/                      # Pipeline logic
│   ├── correlate.py           #   Sort + deduplicate events
│   ├── evaluate.py            #   Decision engine + confidence scoring
│   └── bundle.py              #   Build EvidenceBundle + collect artifacts
├── collect/                   # Remote data collection
│   ├── appliance_collector.py #   SSH/SFTP from Forescout appliance
│   ├── endpoint_collector.py  #   WinRM from Windows endpoints
│   ├── pcap_collector.py      #   Multi-device tcpdump/tshark orchestrator
│   ├── ntp_sync.py            #   NTP clock sync preflight checker
│   └── tunnel_manager.py      #   SSH tunnel management
└── tools/                     # CLI + visualization
    ├── run_diagnostics.py     #   Main CLI entry point
    ├── mermaid_timeline.py    #   6 diagram generators + HTML export + HTTP server
    └── eapol_test_runner.py   #   eapol_test probe for RADIUS health
```

## Parsers

| Parser | Source | Event Kinds | Key Fields |
|--------|--------|-------------|------------|
| `radiusd_parser` | `radiusd.log` | `RADIUS_ACCESS_REQUEST`, `RADIUS_ACCESS_ACCEPT`, `RADIUS_ACCESS_REJECT` | MAC, username, NAS IP/port, auth_method, RADIUS Id, Service-Type |
| `dot1x_parser` | `dot1x.log` | 24 kinds (lifecycle, config, MAR, policy) | plugin_version, policy_enabled, eap_type, vlan_config |
| `framework_parser` | `framework.log` | 24 kinds (verify, check, property, verdict) | property_field, property_value, context_id |
| `endpoint_parser` | `endpoint/` dir | Auth success/failure, NIC config | Windows event IDs, adapter info |
| `redis_parser` | `redis_monitor.log`, `redis_hash_dump.txt` | 4 kinds | rule_slot, rule_action, auth_source |
| `identity_parser` | `local_properties.txt`, `fstool_*` | 9 kinds | login_type, domain, classification |
| `eapol_parser` | `.pcap` / `.pcapng` | 30+ kinds (EAPOL, EAP, TLS, RADIUS) | EAP type, TLS handshake, wire MACs |

## Collectors

| Collector | Transport | What it collects |
|-----------|-----------|-----------------|
| `ApplianceCollector` | SSH/SFTP | radiusd.log, dot1x.log, redis_monitor.log, redis_hash_dump.txt, fstool_dot1x_status.txt, fstool_hostinfo, local_properties.txt |
| `EndpointCollector` | WinRM/PSRP | Windows security events, NIC config, EAP logs, certificates |
| `PcapCollector` | SSH | Multi-device tcpdump on appliance/switch, tshark on endpoint |
| `NtpSyncChecker` | SSH/WinRM | NTP offset from all testbed devices |

## Diagrams

TestPulse auto-generates **6 diagram types** in both Mermaid and self-contained HTML:

| # | Diagram | Mermaid Type | Direction | File Suffix |
|---|---------|-------------|-----------|-------------|
| 1 | Protocol Sequence | `sequenceDiagram` | Vertical | `_bundle.mmd` |
| 2 | Protocol Sequence | `graph LR` | **Horizontal** | `_protocol_h.mmd` |
| 3 | Chronological Timeline | `graph LR` | **Horizontal** | `_timeline.mmd` |
| 4 | Component Topology | `graph LR` | **Horizontal** | `_components.mmd` |
| 5 | EAPOL Wire Trace | `sequenceDiagram` | Vertical | `_eapol.mmd` |
| 6 | EAPOL Wire Trace | `graph LR` | **Horizontal** | `_eapol_h.mmd` |

- Diagrams 5 & 6 only generate when pcap capture data is present (`--pcap`)
- Each `.mmd` file also generates a matching `.html` with embedded Mermaid.js
- An HTTP server auto-starts on port 8765 to serve HTML diagrams
- Use `--no-mermaid` to disable protocol + component + EAPOL diagrams
- Use `--no-timeline` to disable the timeline diagram

### Generator functions (`testpulse.tools.mermaid_timeline`)

| Function | Diagram | Output Format |
|----------|---------|---------------|
| `generate_mermaid(bundle)` | Protocol sequence (vertical) | `sequenceDiagram` |
| `generate_mermaid_horizontal(bundle)` | Protocol sequence (horizontal) | `graph LR` |
| `generate_timeline(bundle)` | Chronological timeline | `graph LR` |
| `generate_component_diagram(bundle)` | Component/device topology | `graph LR` |
| `generate_eapol_diagram(events)` | EAPOL wire trace (vertical) | `sequenceDiagram` |
| `generate_eapol_horizontal(events)` | EAPOL wire trace (horizontal) | `graph LR` |

## CLI Reference

```
testpulse --help

Required:
  --run-dir PATH              Directory containing logs (or target for --collect)
  --testcase-id ID            Test case identifier (e.g., T1316925)
  --expected-decision         Expected auth result: accept | reject | unknown

Optional - Analysis:
  --expected-method METHOD    Expected auth method (default: eap-tls)
  --out PATH                  Output bundle path (default: evidence_bundle.json)
  --pretty                    Pretty-print JSON output

Optional - Collection:
  --collect                   Pull logs from appliance via SSH before analysis
  --appliance-ip IP           Appliance IP address
  --appliance-user USER       SSH username (default: root)
  --appliance-pass PASS       SSH password (default: aristo1)
  --mac MAC                   Endpoint MAC for fstool hostinfo lookup
  --framework-log PATH        Local fstester log to include in analysis
  --testbed-config PATH       Testbed YAML for connection info
  --collect-endpoint          Collect Windows endpoint artifacts
  --endpoint-ip / --endpoint-user / --endpoint-pass

Optional - PCAP:
  --pcap FILE [FILE ...]      Parse pcap files for EAPOL/RADIUS frames
  --ntp-check                 NTP clock sync preflight across testbed

Optional - Diagrams:
  --mermaid [PATH]            Protocol diagram (on by default)
  --timeline [PATH]           Timeline diagram (on by default)
  --no-mermaid                Disable protocol diagram
  --no-timeline               Disable timeline diagram
```

## Evidence Dashboard

Every run automatically generates a **combined tabbed HTML dashboard** alongside
the individual diagram files.  The dashboard renders all available Mermaid
diagrams in a single page with tab navigation.

```
[OK] Wrote dashboard: T1316925_dashboard.html (4 tabs)
```

### Dashboard features

| Feature | Details |
|---------|---------|
| **Tabbed layout** | One tab per diagram — click to switch |
| **Auto-detection** | Only diagrams that were generated appear as tabs |
| **Open full size** | Each tab includes an "Open full size ↗" link to the standalone HTML |
| **Mermaid deferred render** | All panes render while visible, then inactive tabs are hidden — avoids blank-tab bugs |
| **HTTP server** | Served on port 8765 alongside individual diagrams |

### Tab mapping

| .mmd file suffix | Dashboard tab label |
|------------------|---------------------|
| `_bundle` (base) | Protocol Sequence |
| `_protocol_h` | Protocol Flow |
| `_timeline` | Timeline Story |
| `_components` | Component Topology |
| `_eapol` | EAPOL Wire Trace |
| `_eapol_h` | EAPOL Horizontal |

Standard authentication tests (pre-admission, post-connect) produce 4 tabs.
Tests that include pcap capture (`--pcap`) produce all 6 tabs.

## eapol_test — Diagnostic Tool for Certificate & RADIUS Validation

`eapol_test` is a command-line EAP supplicant from the hostapd project.
TestPulse wraps it via `testpulse.tools.eapol_test_runner` to probe RADIUS
health and validate certificate-based authentication **without** a physical
switch or 802.1X supplicant.

### When to use

- **Appliance flakiness** — Is RADIUS accepting/rejecting correctly, or is the
  policy engine intermittently broken?
- **Certificate validation** — Does the appliance correctly reject revoked or
  expired client certificates?
- **EKU checking** — Are Extended Key Usage constraints (Client Authentication
  OID `1.3.6.1.5.5.7.3.2`) enforced?
- **MSCA / AD CS integration** — Verify certificates issued by Microsoft
  Certificate Authority work end-to-end through the RADIUS chain.
- **OCSP stapling** — Confirm the appliance checks certificate revocation status
  (CRL / OCSP) before granting access.
- **Baseline before/after** — Run a 3-cert probe (good/revoked/expired) before
  and after a config change to diff behaviour.

### Certificate preparation

Convert PFX (PKCS#12) certificates to PEM for eapol_test:

```bash
# Extract client cert
openssl pkcs12 -in Dot1x-CLT-Good.pfx -clcerts -nokeys -out good.pem -passin pass:aristo

# Extract private key
openssl pkcs12 -in Dot1x-CLT-Good.pfx -nocerts -nodes -out good_key.pem -passin pass:aristo

# Extract CA chain
openssl pkcs12 -in Dot1x-CLT-Good.pfx -cacerts -nokeys -out ca.pem -passin pass:aristo
```

Repeat for revoked and expired certificates.

### Three-certificate validation probe

The gold-standard diagnostic runs three probes with controlled certificates:

| Probe | Certificate | Expected Result | Meaning |
|-------|------------|-----------------|---------|
| **Good** | Valid cert, correct EKU | `Access-Accept` | RADIUS + policy working |
| **Revoked** | CA-revoked cert | `Access-Reject` | OCSP / CRL checking works |
| **Expired** | Expired validity period | `Access-Reject` | Certificate date validation works |

### Python API

```python
from testpulse.tools.eapol_test_runner import run_eapol_test, EapolTestConfig

# Good certificate — expect Accept
good = EapolTestConfig(
    radius_ip="10.16.177.66",
    shared_secret="testing123",
    identity="Dot1x-CLT-Good",
    eap_method="TLS",
    ca_cert="/path/to/ca.pem",
    client_cert="/path/to/good.pem",
    private_key="/path/to/good_key.pem",
    private_key_passwd="aristo",
)
result = run_eapol_test(good)
print(f"Good cert: {'PASS' if result.success else 'FAIL'}")

# Revoked certificate — expect Reject
revoked = EapolTestConfig(
    radius_ip="10.16.177.66",
    shared_secret="testing123",
    identity="Dot1x-CLT-Revoked",
    eap_method="TLS",
    ca_cert="/path/to/ca.pem",
    client_cert="/path/to/revoked.pem",
    private_key="/path/to/revoked_key.pem",
    private_key_passwd="aristo",
)
result = run_eapol_test(revoked)
print(f"Revoked cert: {'PASS' if not result.success else 'FAIL — OCSP not enforced'}")
```

### Interpreting results

| Result | Good cert | Revoked cert | Expired cert | Diagnosis |
|--------|-----------|-------------|-------------|-----------|
| ✅ Expected | Accept | Reject | Reject | Appliance healthy |
| ⚠️ OCSP gap | Accept | **Accept** | Reject | OCSP/CRL not configured — revoked certs pass through |
| ⚠️ Flaky | Intermittent | — | — | RADIUS service unstable, check radiusd logs |
| ❌ Broken | Reject | Reject | Reject | Certificate chain or trust anchor misconfigured |

### EKU / MSCA checklist

When validating certificates issued by Microsoft CA (AD CS):

1. **EKU present** — Client cert must include `Client Authentication` (OID `1.3.6.1.5.5.7.3.2`).
   Verify with: `openssl x509 -in cert.pem -noout -purpose`
2. **CA chain complete** — The full chain (root → intermediate → leaf) must be installed in the
   RADIUS trust store. Missing intermediates cause `Access-Reject` even for valid certs.
3. **CRL Distribution Point** — Cert should include a CDP the appliance can reach.
   Verify with: `openssl x509 -in cert.pem -noout -text | grep -A2 "CRL Distribution"`
4. **OCSP Responder** — If using OCSP, the AIA extension must point to a reachable responder.
   Verify with: `openssl x509 -in cert.pem -noout -text | grep -A2 "Authority Information Access"`
5. **Template name** — AD CS templates control EKU, key usage, and validity.  Common templates
   for 802.1X: `Workstation Authentication`, `Computer`, or custom EAP-TLS templates.

### Running with pcap capture for full evidence

Combine eapol_test with pcap collection for a complete evidence bundle:

```bash
# 1. Start pcap collection on appliance
testpulse --run-dir ./eapol_diag --testcase-id EAPOL-CERT-001 \
  --expected-decision accept --collect \
  --testbed-config radius.yaml --pcap ./eapol_diag/pcap/appliance.pcap \
  --pretty

# 2. Run the three-cert probe (via Python API or manually)

# 3. Analyse collected artifacts — produces 6 diagrams + dashboard
testpulse --run-dir ./eapol_diag --testcase-id EAPOL-CERT-001 \
  --expected-decision accept \
  --pcap ./eapol_diag/pcap/appliance.pcap \
  --pretty
```

The dashboard will contain all 6 diagram tabs showing the full EAP-TLS
handshake, RADIUS exchange, timeline, and component topology for each probe.

## Phase Plan

| Phase | Status | Description |
|-------|--------|-------------|
| **Phase 1** | ✅ Complete | CLI, JSON EvidenceBundle, 7 parsers, 4 collectors, 6 diagram types (sequence + flowchart), HTML export, HTTP server, single-command workflow |
| **Phase 2** | Planned | FastAPI wrapper, timing-budget evaluation, HTML/PDF export |
| **Phase 3** | Planned | MCP server for Copilot, identity/IPAM/syslog adapters, work-item sync |

## Requirements

- Python ≥ 3.11
- `paramiko` — SSH/SFTP collection
- `pyyaml` — testbed config parsing
- `scapy` — EAPOL/RADIUS pcap parsing (primary)
- `dpkt` — pcap parsing (fallback)
- `pywinrm`, `pypsrp` — Windows endpoint collection (optional)

## License

Internal — Forescout Technologies
