# TestPulse Phase 1 to MCP Agent Phase 3

**What, How, Why -- RunTypes, TestCategories, RunMetadata, and the MCP Upgrade Path**

---

## What You Have Now (Phase 1 CLI)

The current EvidenceBundle and AssuranceExpectation are scenario-blind -- they do not know what type of test produced them. Every run looks the same to the system:

```python
# Today: no concept of "run type"
AssuranceExpectation(
    testcase_id="TP-SAN-001",
    expected_decision=Decision.ACCEPT,
    expected_method="eap-tls",
)
```

There is no field for:

- Run type (proof-positive, negative, forensic, flakiness, eapol-probe)
- Test category (SAN, EKU, OCSP, MAB, PEAP, cert-chain)
- Run metadata (who ran it, when, which testbed, which fstester test class, duration)
- Linkage (which fstester test produced the logs, which previous run this compares against)

---

## What "Burn In" Means -- TestCase Run Types + Metadata

### RunType Enum

```python
class RunType(str, Enum):
    PROOF_POSITIVE   = "proof_positive"      # Scenario 1
    NEGATIVE_TEST    = "negative_test"        # Scenario 2
    FORENSIC         = "forensic"            # Scenario 3 (Sherlock)
    STABILITY_PROBE  = "stability_probe"     # Scenario 4 (Flakiness)
    EAPOL_PROBE      = "eapol_probe"         # Scenario 5 (eapol_test bypass)
```

### TestCategory Enum

```python
class TestCategory(str, Enum):
    SAN_DETECTION    = "san_detection"
    EKU_VALIDATION   = "eku_validation"
    OCSP_CRL         = "ocsp_crl"
    CERT_CHAIN       = "cert_chain"
    CERT_EXPIRY      = "cert_expiry"
    MAB_FALLBACK     = "mab_fallback"
    PEAP_MSCHAPV2    = "peap_mschapv2"
    EAP_TLS          = "eap_tls"
    POLICY_RULE      = "policy_rule"
    PRE_ADMISSION    = "pre_admission"
```

### RunMetadata Dataclass

```python
@dataclass
class RunMetadata:
    run_type: RunType
    test_category: TestCategory
    operator: str                          # who ran it
    testbed_id: str                        # which lab
    fstester_test: str | None = None       # pytest node id
    fstester_config: str | None = None     # yaml config path
    cert_name: str | None = None           # which cert was used
    iteration: int | None = None           # run N of M (flakiness)
    total_iterations: int | None = None
    parent_run_id: str | None = None       # links flakiness runs
    started_at: str | None = None          # ISO timestamp
    finished_at: str | None = None
    pcap_enabled: bool = False
    ntp_verified: bool = False
```

The EvidenceBundle gets a run_metadata: RunMetadata field so every bundle self-describes what kind of test produced it.

---

## How MCP Agent (Phase 3) Changes Everything

### Architecture Shift

```
PHASE 1 (CLI):
  Human -> fstester -> Human -> testpulse CLI -> Human reads JSON

PHASE 3 (MCP):
  Copilot <-> MCP Server <-> TestPulse Engine
    |                           |
    |  "run proof-positive      |  executes fstester
    |   for SAN detection"      |  collects evidence
    |                           |  builds bundle
    |  <-- structured result ---|  returns RunMetadata + verdict
    |                           |
    |  "why did it fail?"       |  queries timeline, pcap, redis
    |  <-- root cause ----------|  returns detective analysis
    |                           |
    |  "run 3-cert sweep"       |  loops good/revoked/expired
    |  <-- comparison table ----|  returns diff matrix
```

### The 5 MCP Tools (one per scenario)

| MCP Tool | Maps to | What Copilot can do |
|----------|---------|---------------------|
| testpulse/proof_positive | Scenario 1 | "Run SAN detection test and tell me if it passed" |
| testpulse/negative_test | Scenario 2 | "Verify revoked cert gets rejected" |
| testpulse/forensic_analyze | Scenario 3 | "The last test failed -- find out why" |
| testpulse/stability_probe | Scenario 4 | "Run SAN test 5 times and tell me if it is flaky" |
| testpulse/cert_probe | Scenario 5 | "Probe RADIUS with good/revoked/expired certs" |

---

## Why This Matters -- Concrete Examples

### Example 1: 3-cert sweep

**Today (CLI):**

```bash
# You manually run 3 commands, read 3 JSON files, mentally compare
testpulse --run-dir /tmp/good ... --expected-decision accept
testpulse --run-dir /tmp/revoked ... --expected-decision reject
testpulse --run-dir /tmp/expired ... --expected-decision reject
# Then open 3 dashboards, alt-tab, eyeball differences
```

**MCP Agent:**

```
You: "Run a 3-cert sweep against the appliance"

Copilot: I will probe RADIUS with all three certificates.

  | Cert     | Expected | Observed | Result           |
  |----------|----------|----------|------------------|
  | Good     | Accept   | Accept   | PASS_CONFIRMED   |
  | Revoked  | Reject   | Accept   | FAIL_UNEXPECTED  |
  | Expired  | Reject   | Reject   | PASS_CONFIRMED   |

  WARNING: OCSP/CRL is not configured -- revoked cert was accepted.
  The appliance at 10.16.177.66 is not checking certificate
  revocation status. Check radiusd OCSP configuration.
```

No commands. No file reading. No dashboard juggling.

### Example 2: Sherlock Holmes investigation

**Today (CLI):**

```bash
# You run 4 commands across 2 terminals
# Open dashboard, scan 6 diagrams, read timeline manually
# Spend 15 minutes correlating "why did the TLS handshake fail?"
```

**MCP Agent:**

```
You: "The last SAN test failed. Why?"

Copilot: Analyzing run TP-SAN-003...

  Root cause: TLS handshake failed at Certificate Verify step.

  Timeline:
  1. 14:30:01 -- Access-Request received (MAC 98:f2:b3:01:a0:55)
  2. 14:30:01 -- EAP-TLS started, ClientHello sent
  3. 14:30:02 -- ServerHello + Certificate received
  4. 14:30:02 -- Certificate Verify FAILED  <-- here
  5. 14:30:02 -- Access-Reject sent

  Diagnosis: The server certificate intermediate CA
  (CN=Dot1x-Sub-CA) is not in the client trust store.
  The client rejected the server chain, not the other way.

  Fix: Add Dot1x-Sub-CA.pem to the endpoint trusted root store.
```

### Example 3: Flakiness detection

**Today (CLI):**

```bash
# Write a bash loop, wait for 5 runs, manually diff 5 JSON files
```

**MCP Agent:**

```
You: "Is the SAN detection test flaky? Run it 5 times."

Copilot: Running stability probe (5 iterations)...

  | Run | Decision | Confidence | Duration |
  |-----|----------|------------|----------|
  | 1   | Accept   | 0.95       | 2.1s     |
  | 2   | Accept   | 0.93       | 2.3s     |
  | 3   | Reject   | 0.88       | 8.7s     |
  | 4   | Accept   | 0.95       | 2.0s     |
  | 5   | Accept   | 0.94       | 2.2s     |

  Result: FLAKY (1/5 failures, 80% pass rate)

  Run 3 divergence point: LDAP bind to AD (10.100.49.30)
  timed out after 5s, causing RADIUS to fall back to
  default-reject policy.

  Recommendation: Increase RADIUS LDAP timeout from 5s to 15s.
```

---

## The Three Multipliers

| Factor | Phase 1 CLI | Phase 3 MCP | Multiplier |
|--------|-------------|-------------|------------|
| Time per investigation | 15-30 min (manual) | 30 sec (conversational) | 30-60x faster |
| Context required | Must know CLI flags, read JSON, correlate | Natural language | Zero learning curve |
| Cross-run analysis | Manual diff of JSON | Agent compares linked runs automatically | Impossible to trivial |
| Actionable output | Raw data (JSON, diagrams) | Diagnosis + fix recommendation | Data to insight |
| Repeatability | Bash scripts, copy-paste | "Do what you did last time" | Tribal knowledge to encoded |

---

## The Key Insight

The RunType and TestCategory enums are not just metadata -- they are instructions to the MCP agent:

- RunType.FORENSIC tells the agent to dig deep into the timeline and correlate across sources
- RunType.STABILITY_PROBE tells it to compare across iterations
- TestCategory.OCSP_CRL tells it to specifically check certificate revocation evidence

Phase 1 gave you the engine (parsers, correlators, evaluators, diagrams).

Phase 3 gives you the driver (an agent that knows what to do with the engine based on run type).
