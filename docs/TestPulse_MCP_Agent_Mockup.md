# TestPulse MCP Agent -- User Experience Mockup

**Phase 3: How a QA Engineer Interacts with the TestPulse Agent in VS Code**

Test Case: T1316925 -- SAN Detection (EAP-TLS)

---

## Part 1: Setup and Configuration

### Step 1: Install the TestPulse MCP Server

The MCP server is a Python process that Copilot talks to over stdio. One-time setup:

```bash
# Install TestPulse with MCP dependencies
cd ~/testpulse_proto_v1
pip install -e ".[mcp]"
```

### Step 2: Configure VS Code to Connect

Add the TestPulse MCP server to your VS Code settings:

File: .vscode/settings.json

```json
{
  "github.copilot.chat.mcpServers": {
    "testpulse": {
      "command": "python",
      "args": ["-m", "testpulse.mcp.server"],
      "env": {
        "TESTPULSE_CONFIG": "${workspaceFolder}/radius.yaml",
        "TESTPULSE_ARTIFACTS": "${workspaceFolder}/artifacts"
      }
    }
  }
}
```

### Step 3: Verify Connection

When you open VS Code, you see in the Copilot chat panel:

```
+------------------------------------------------------------------+
|  Copilot Chat                                            [v]  [X] |
|------------------------------------------------------------------|
|                                                                  |
|  MCP Servers Connected:                                          |
|    [*] testpulse (5 tools available)                             |
|                                                                  |
|  Available tools:                                                |
|    - testpulse/proof_positive                                    |
|    - testpulse/negative_test                                     |
|    - testpulse/forensic_analyze                                  |
|    - testpulse/stability_probe                                   |
|    - testpulse/cert_probe                                        |
|                                                                  |
+------------------------------------------------------------------+
```

### Step 4: Testbed Configuration (radius.yaml)

The agent reads your existing testbed config automatically:

```yaml
# radius.yaml -- already exists, no changes needed
em:
  ip: 10.16.177.65
ca:
  ip: 10.16.177.66
  user_name: root
  password: aristo1
switch:
  ip: 10.16.128.21
  port1:
    interface: TenGigabitEthernet1/1
    vlan: 1570
passthrough:
  ip: 10.16.133.134
  mac: 98f2b301a055
```

---

## Part 2: User Interaction -- Running T1316925

### The Conversation

Below is the exact chat experience. User messages are prefixed with "You:" and agent responses are shown in boxes.

---

YOU:

```
@testpulse what tests can I run for SAN detection?
```

AGENT:

```
+------------------------------------------------------------------+
|  TestPulse Agent                                                 |
|------------------------------------------------------------------|
|                                                                  |
|  I found 5 test cases in the SAN_DETECTION category:             |
|                                                                  |
|  #  ID              Type      Expected   Description             |
|  -- --------------- --------- ---------- ----------------------- |
|  1  TP-EAPTLS-SAN-001  positive  accept   SAN matches hostname   |
|  2  TP-EAPTLS-SAN-002  positive  accept   SAN matches IP addr    |
|  3  TP-EAPTLS-SAN-003  positive  accept   SAN wildcard match     |
|  4  TP-EAPTLS-SAN-004  negative  reject   SAN mismatch           |
|  5  TP-EAPTLS-SAN-005  negative  reject   SAN field missing      |
|                                                                  |
|  Your testbed is configured:                                     |
|    Appliance: 10.16.177.66 (v8.5.3)                              |
|    Switch:    10.16.128.21 (Te1/1, VLAN 1570)                    |
|    Endpoint:  10.16.133.134 (MAC 98f2b301a055)                   |
|                                                                  |
|  Say "run <number>" or "run all SAN tests" to begin.             |
|                                                                  |
+------------------------------------------------------------------+
```

---

YOU:

```
@testpulse run test 1 for T1316925 with proof positive
```

AGENT:

```
+------------------------------------------------------------------+
|  TestPulse Agent                                                 |
|------------------------------------------------------------------|
|                                                                  |
|  Starting: TP-EAPTLS-SAN-001 (SAN matches hostname)             |
|  Run ID:   T1316925                                              |
|  Type:     PROOF_POSITIVE                                        |
|  Category: SAN_DETECTION                                         |
|  Method:   EAP-TLS                                               |
|  Cert:     Dot1x-CLT-Good                                       |
|  Expected: Access-Accept                                         |
|                                                                  |
|  I will:                                                         |
|  1. Execute fstester EAPTLSPolicySANDetectionTest                |
|  2. Collect logs from appliance 10.16.177.66                     |
|  3. Parse radiusd.log, dot1x.log, redis, identity artifacts      |
|  4. Evaluate decision and generate evidence bundle               |
|  5. Generate diagrams and dashboard                              |
|                                                                  |
|  Proceed? [Yes / Yes with pcap / Cancel]                         |
|                                                                  |
+------------------------------------------------------------------+
```

---

YOU:

```
yes
```

AGENT (progress updates appear in real-time):

```
+------------------------------------------------------------------+
|  TestPulse Agent -- Running T1316925                             |
|------------------------------------------------------------------|
|                                                                  |
|  [1/5] Executing fstester...                                     |
|         python fstester.py                                       |
|           -t tests/radius/functional/                            |
|              radius_functional_eap_tls.py::                      |
|              EAPTLSPolicySANDetectionTest                        |
|           -config test_config/radius/tarik_radius.yml            |
|           --report T1316925                                      |
|         ... running (12s elapsed)                                |
|         DONE -- fstester exit code 0                             |
|                                                                  |
|  [2/5] Collecting from appliance 10.16.177.66...                 |
|         radiusd.log      (14,230 lines)                          |
|         dot1x.log        (8,412 lines)                           |
|         redis_hash_dump  (42 keys)                               |
|         fstool_status    (ok)                                    |
|         fstool_hostinfo  (MAC 98f2b301a055 found)                |
|         local.properties (loaded)                                |
|         DONE                                                     |
|                                                                  |
|  [3/5] Parsing logs...                                           |
|         radiusd_parser:   3 RADIUS packets (1 Req, 1 Accept)     |
|         dot1x_parser:     18 events                              |
|         framework_parser: 24 events                              |
|         redis_parser:     4 events (rule_1 match)                |
|         identity_parser:  6 events                               |
|         TOTAL: 55 events correlated                              |
|                                                                  |
|  [4/5] Evaluating...                                             |
|         Observed:  Access-Accept                                 |
|         Expected:  Access-Accept                                 |
|         Match:     YES                                           |
|         Confidence: 0.95                                         |
|                                                                  |
|  [5/5] Generating diagrams + dashboard...                        |
|         4 diagrams generated                                     |
|         Dashboard: T1316925_dashboard.html                       |
|         HTTP server: http://localhost:8765                        |
|                                                                  |
+------------------------------------------------------------------+
```

AGENT (final result):

```
+==================================================================+
|                                                                  |
|  TEST RESULT: PASS_CONFIRMED                                     |
|                                                                  |
+==================================================================+
|                                                                  |
|  Test Case:    TP-EAPTLS-SAN-001                                 |
|  Run ID:       T1316925                                          |
|  Category:     SAN_DETECTION                                     |
|  Run Type:     PROOF_POSITIVE                                    |
|                                                                  |
|  +------------------------------------------------------------+ |
|  | Decision Summary                                           | |
|  +------------------------------------------------------------+ |
|  | Observed Decision:   Access-Accept                         | |
|  | Expected Decision:   Access-Accept                         | |
|  | Functional Pass:     YES                                   | |
|  | Confidence:          0.95                                  | |
|  | Classification:      PASS_CONFIRMED                        | |
|  +------------------------------------------------------------+ |
|                                                                  |
|  +------------------------------------------------------------+ |
|  | Rule Engine                                                | |
|  +------------------------------------------------------------+ |
|  | Rule Matched:     Pre-Admission Rule 1                     | |
|  | Rule Action:      Accept                                   | |
|  | Auth Method:      EAP-TLS                                  | |
|  | Auth Source:       "Pre-Admission rule 1"                   | |
|  +------------------------------------------------------------+ |
|                                                                  |
|  +------------------------------------------------------------+ |
|  | Identity                                                   | |
|  +------------------------------------------------------------+ |
|  | MAC:              98:f2:b3:01:a0:55                        | |
|  | Username:         98f2b301a055                              | |
|  | Login Type:       dot1x_computer_login                     | |
|  | Domain:           CORP.FORESCOUT.COM                        | |
|  | Classification:   Corporate Laptop                         | |
|  | VLAN:             1570                                      | |
|  +------------------------------------------------------------+ |
|                                                                  |
|  +------------------------------------------------------------+ |
|  | SAN Validation (test-specific)                             | |
|  +------------------------------------------------------------+ |
|  | SAN Field:        DNS:endpoint134.corp.forescout.com       | |
|  | SAN Match:        YES -- matched policy allowed list       | |
|  | Certificate CN:   Dot1x-CLT-Good                           | |
|  | Issuer:           Dot1x-CA                                  | |
|  | EKU:              Client Authentication (1.3.6.1.5.5.7.3.2)| |
|  +------------------------------------------------------------+ |
|                                                                  |
|  Findings:                                                       |
|  1. Observed decision: accept                                    |
|  2. Expected decision: accept                                    |
|  3. Functional pass: True                                        |
|  4. Pre-Admission Rule 1 matched (EAP-TLS)                      |
|  5. SAN field present and matched policy                         |
|  6. Certificate chain valid (Dot1x-CA -> Dot1x-CLT-Good)        |
|  7. Host classified as "Corporate Laptop" (VLAN 1570)            |
|                                                                  |
|  Timeline: 55 events from 5 sources (12.3s span)                |
|  Artifacts: 8 files collected in artifacts/T1316925/             |
|                                                                  |
|  +------------------------------------------------------------+ |
|  | Diagrams                                                   | |
|  +------------------------------------------------------------+ |
|  | Dashboard: http://localhost:8765/T1316925_dashboard.html    | |
|  |                                                            | |
|  | Individual:                                                | |
|  |   Protocol Sequence  -> evidence_bundle.html               | |
|  |   Protocol Flow      -> evidence_bundle_protocol_h.html    | |
|  |   Timeline Story     -> evidence_bundle_timeline.html      | |
|  |   Component Topology -> evidence_bundle_components.html    | |
|  +------------------------------------------------------------+ |
|                                                                  |
|  Evidence bundle saved:                                          |
|    artifacts/T1316925/evidence_bundle.json                        |
|                                                                  |
|  What next?                                                      |
|  - "show timeline" -- display event timeline                     |
|  - "show dashboard" -- open dashboard in browser                 |
|  - "run negative" -- test SAN mismatch (TP-EAPTLS-SAN-004)      |
|  - "run all SAN" -- run all 5 SAN tests                          |
|  - "compare with last run" -- diff against previous result       |
|  - "explain rule 1" -- why Rule 1 matched                        |
|                                                                  |
+==================================================================+
```

---

## Part 3: Follow-up Interactions

### User asks "show timeline"

YOU:

```
@testpulse show timeline for T1316925
```

AGENT:

```
+------------------------------------------------------------------+
|  T1316925 Event Timeline (55 events, showing key 12)             |
|------------------------------------------------------------------|
|                                                                  |
|  TIME       SOURCE          EVENT                                |
|  --------   -------------   ------------------------------------ |
|  14:22:01   radiusd.log     Access-Request Id=47                 |
|             .               MAC=98f2b301a055, NAS=10.16.128.21   |
|             .               Service-Type=Call-Check (MAB probe)  |
|                                                                  |
|  14:22:01   dot1x.log       DOT1X_EAP_START                     |
|             .               EAP-Type=TLS, Policy=enabled         |
|                                                                  |
|  14:22:01   dot1x.log       DOT1X_EAP_TLS_HANDSHAKE             |
|             .               ClientHello -> ServerHello           |
|                                                                  |
|  14:22:02   dot1x.log       DOT1X_CERT_VALIDATION               |
|             .               CN=Dot1x-CLT-Good, SAN=DNS:endpoint  |
|             .               SAN match: YES                       |
|                                                                  |
|  14:22:02   dot1x.log       DOT1X_EAP_TLS_COMPLETE              |
|             .               Handshake successful                 |
|                                                                  |
|  14:22:02   radiusd.log     Access-Accept Id=47                  |
|             .               -> 10.16.128.21:1645                 |
|                                                                  |
|  14:22:02   redis           REDIS_RULE_MATCH                     |
|             .               slot=1, action=accept                |
|             .               source="Pre-Admission rule 1"       |
|                                                                  |
|  14:22:02   fstool          IDENTITY_CLASSIFICATION              |
|             .               "Corporate Laptop"                   |
|             .               login=dot1x_computer_login           |
|                                                                  |
|  14:22:02   framework.log   FRAMEWORK_PROPERTY_SET               |
|             .               dot1x_auth_state = Access-Accept     |
|                                                                  |
|  14:22:03   framework.log   FRAMEWORK_ALL_CHECKS_PASSED          |
|             .               SAN detection: PASS                  |
|                                                                  |
|  End-to-end: 2.0 seconds                                        |
|                                                                  |
|  Full timeline (55 events): evidence_bundle.json -> timeline[]   |
|                                                                  |
+------------------------------------------------------------------+
```

### User asks "run negative"

YOU:

```
@testpulse now run the negative -- SAN mismatch, same endpoint
```

AGENT:

```
+------------------------------------------------------------------+
|  TestPulse Agent                                                 |
|------------------------------------------------------------------|
|                                                                  |
|  Starting: TP-EAPTLS-SAN-004 (SAN mismatch)                     |
|  Run ID:   T1316925-NEG                                          |
|  Type:     NEGATIVE_TEST                                         |
|  Category: SAN_DETECTION                                         |
|  Cert:     Dot1x-CLT-BadSAN                                     |
|  Expected: Access-Reject                                         |
|                                                                  |
|  [1/5] Executing fstester... DONE (8s)                           |
|  [2/5] Collecting logs... DONE                                   |
|  [3/5] Parsing... 42 events                                      |
|  [4/5] Evaluating...                                             |
|                                                                  |
+==================================================================+
|                                                                  |
|  TEST RESULT: PASS_CONFIRMED                                     |
|                                                                  |
+==================================================================+
|                                                                  |
|  Observed: Access-Reject   (expected: Access-Reject)             |
|  Confidence: 0.92                                                |
|                                                                  |
|  The appliance correctly REJECTED the certificate with a         |
|  mismatched SAN field:                                           |
|                                                                  |
|    SAN in cert:     DNS:wrong-host.other.com                     |
|    Expected match:  DNS:endpoint134.corp.forescout.com           |
|    Result:          NO MATCH -> Access-Reject                    |
|                                                                  |
|  This confirms SAN detection policy is enforcing correctly       |
|  for both positive (T1316925) and negative (T1316925-NEG) cases. |
|                                                                  |
|  Comparison:                                                     |
|  +-------------------+----------------+------------------+       |
|  |                   | T1316925       | T1316925-NEG     |       |
|  +-------------------+----------------+------------------+       |
|  | Cert              | Dot1x-CLT-Good | Dot1x-CLT-BadSAN|       |
|  | SAN Match         | YES            | NO               |       |
|  | Decision          | Accept         | Reject           |       |
|  | Expected          | Accept         | Reject           |       |
|  | Result            | PASS           | PASS             |       |
|  | Rule              | Rule 1         | Default reject   |       |
|  +-------------------+----------------+------------------+       |
|                                                                  |
+==================================================================+
```

### User asks for a full sweep

YOU:

```
@testpulse run all 5 SAN tests and give me a summary
```

AGENT:

```
+------------------------------------------------------------------+
|  TestPulse Agent -- SAN Detection Full Sweep                     |
|------------------------------------------------------------------|
|                                                                  |
|  Running 5 tests sequentially...                                 |
|                                                                  |
|  [1/5] TP-EAPTLS-SAN-001 (hostname match)... PASS_CONFIRMED     |
|  [2/5] TP-EAPTLS-SAN-002 (IP match)......... PASS_CONFIRMED     |
|  [3/5] TP-EAPTLS-SAN-003 (wildcard match)... PASS_CONFIRMED     |
|  [4/5] TP-EAPTLS-SAN-004 (mismatch)......... PASS_CONFIRMED     |
|  [5/5] TP-EAPTLS-SAN-005 (SAN missing)...... PASS_CONFIRMED     |
|                                                                  |
+==================================================================+
|                                                                  |
|  SAN DETECTION SUITE: 5/5 PASSED                                 |
|                                                                  |
+==================================================================+
|                                                                  |
|  #  Test Case         Cert         Expected  Observed  Result    |
|  -- ----------------  -----------  --------  --------  -------   |
|  1  SAN hostname      CLT-Good     Accept    Accept    PASS      |
|  2  SAN IP address    CLT-IPSan    Accept    Accept    PASS      |
|  3  SAN wildcard      CLT-Wild     Accept    Accept    PASS      |
|  4  SAN mismatch      CLT-BadSAN   Reject    Reject    PASS      |
|  5  SAN missing       CLT-NoSAN    Reject    Reject    PASS      |
|                                                                  |
|  Confidence range: 0.91 -- 0.96                                  |
|  Total duration:   58 seconds (5 tests)                          |
|  Rule hits:        Rule 1 x3 (accept), Default x2 (reject)      |
|                                                                  |
|  Conclusion: SAN detection policy is working correctly.          |
|  The appliance accepts valid SANs (hostname, IP, wildcard)       |
|  and rejects missing or mismatched SANs.                         |
|                                                                  |
|  Dashboards saved:                                               |
|    artifacts/T1316925-SAN-001/T1316925-SAN-001_dashboard.html    |
|    artifacts/T1316925-SAN-002/T1316925-SAN-002_dashboard.html    |
|    artifacts/T1316925-SAN-003/T1316925-SAN-003_dashboard.html    |
|    artifacts/T1316925-SAN-004/T1316925-SAN-004_dashboard.html    |
|    artifacts/T1316925-SAN-005/T1316925-SAN-005_dashboard.html    |
|                                                                  |
|  What next?                                                      |
|  - "show failures" -- (none this run)                            |
|  - "run OCSP tests" -- switch to OCSP_CRL category              |
|  - "stability check SAN-001" -- run test 1 five times            |
|  - "export report" -- generate PDF summary                       |
|                                                                  |
+==================================================================+
```

---

## Part 4: Error Scenario -- What Happens When a Test FAILS

YOU:

```
@testpulse run SAN test 1 proof positive
```

AGENT (if the test fails):

```
+==================================================================+
|                                                                  |
|  TEST RESULT: FAIL_UNEXPECTED                                    |
|                                                                  |
+==================================================================+
|                                                                  |
|  Test Case:    TP-EAPTLS-SAN-001                                 |
|  Run ID:       T1316925-RETRY                                    |
|  Expected:     Access-Accept                                     |
|  Observed:     Access-Reject     <-- UNEXPECTED                  |
|  Confidence:   0.88                                              |
|                                                                  |
|  INITIAL ANALYSIS:                                               |
|                                                                  |
|  The certificate is valid and SAN matches, but the appliance     |
|  rejected it anyway. Checking why...                             |
|                                                                  |
|  Root Cause Candidates:                                          |
|                                                                  |
|  1. [HIGH] LDAP bind to AD (10.100.49.30) timed out             |
|     - radiusd.log line 14230: "ldap bind timeout after 5s"      |
|     - This caused Rule 1 sub-rule "CN in AD" to fail            |
|     - Without AD validation, Rule 1 rejected                    |
|                                                                  |
|  2. [LOW]  Certificate chain is valid                            |
|     - SAN: DNS:endpoint134.corp.forescout.com (matches)          |
|     - EKU: Client Authentication (present)                       |
|     - Expiry: 2027-06-15 (valid)                                 |
|                                                                  |
|  RECOMMENDATION:                                                 |
|                                                                  |
|  The appliance RADIUS server could not reach Active Directory    |
|  to validate the certificate CN against AD accounts.             |
|                                                                  |
|  Immediate actions:                                              |
|  - Check network connectivity: ping 10.100.49.30 from appliance |
|  - Check AD service: ldapsearch -H ldap://10.100.49.30          |
|  - Increase LDAP timeout in radiusd config (currently 5s)       |
|                                                                  |
|  Want me to:                                                     |
|  - "retry" -- run the same test again                            |
|  - "forensic" -- switch to Sherlock mode with pcap capture       |
|  - "stability 5" -- run 5 times to check if it is flaky         |
|  - "check AD" -- probe AD connectivity from appliance            |
|                                                                  |
+==================================================================+
```

YOU:

```
@testpulse forensic
```

AGENT:

```
+------------------------------------------------------------------+
|  TestPulse Agent -- Switching to FORENSIC mode                   |
|------------------------------------------------------------------|
|                                                                  |
|  I will re-run TP-EAPTLS-SAN-001 with full evidence capture:     |
|                                                                  |
|  1. NTP pre-flight across all 4 devices                          |
|  2. Start pcap capture on appliance + switch + endpoint          |
|  3. Execute fstester test                                        |
|  4. Stop pcap, collect ALL logs                                  |
|  5. Deep analysis with 6 diagrams + wire trace                   |
|                                                                  |
|  This will take longer (~60s). Proceed? [Yes / Cancel]           |
|                                                                  |
+------------------------------------------------------------------+
```

---

## Part 5: Quick Reference Card

### How to invoke the agent

| Command | What it does |
|---------|--------------|
| @testpulse what tests are available? | List all test categories and cases |
| @testpulse run <test> for <run-id> | Run a specific test case |
| @testpulse run all SAN tests | Run entire category |
| @testpulse show timeline for <run-id> | Display event timeline |
| @testpulse show dashboard | Open dashboard in browser |
| @testpulse compare <run1> vs <run2> | Diff two runs |
| @testpulse why did it fail? | Root cause analysis on last run |
| @testpulse forensic | Re-run with full pcap capture |
| @testpulse stability <N> | Run N times, check flakiness |
| @testpulse cert probe | 3-cert sweep (good/revoked/expired) |
| @testpulse export report | Generate PDF summary |
| @testpulse status | Show testbed connectivity |

### Run type modifiers

| Modifier | Effect |
|----------|--------|
| proof positive | Expect accept, report pass/fail |
| negative | Expect reject, verify enforcement |
| forensic | Full pcap + deep analysis |
| with pcap | Add pcap capture to any run type |

### Agent response format

Every test result includes:

- Pass/Fail banner with classification
- Decision summary (observed vs expected, confidence)
- Rule engine details (which rule, which sub-rules)
- Identity details (MAC, user, domain, classification, VLAN)
- Test-specific validation (SAN match, EKU, OCSP, etc.)
- Findings list (numbered, human-readable)
- Diagram links (dashboard + individual HTML files)
- Next actions menu (context-sensitive suggestions)
