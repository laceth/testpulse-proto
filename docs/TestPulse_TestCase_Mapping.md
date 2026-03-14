# TestPulse Test Case Mapping

**Pre-Admission Rules, Policy Match, Subrules, NPT Stats -- Category x Aspect Matrix**

---

## The Problem: Forescout Auth is a Pipeline

```
Incoming MAC
    |
    v
+-------------------------------------+
|  PRE-ADMISSION RULES (ordered)      |
|                                     |
|  Rule 1: EAP-TLS with valid cert   |--> Accept + classify
|    +-- Sub: CN matches AD           |
|    +-- Sub: EKU = Client Auth        |
|    +-- Sub: SAN in allowed list      |
|                                     |
|  Rule 2: PEAP-MSCHAPv2             |--> Accept + classify
|    +-- Sub: AD group membership      |
|    +-- Sub: password not expired     |
|                                     |
|  Rule 3: MAB known MAC             |--> Accept (limited)
|    +-- Sub: MAC in whitelist         |
|                                     |
|  Default: Reject                    |--> Reject
+-------------------------------------+
    |
    v (if accepted)
+-------------------------------------+
|  POLICY CLASSIFICATION              |
|                                     |
|  Policy A: "Corporate Laptop"       |--> VLAN 100, full access
|    Match: domain=CORP + cert valid  |
|                                     |
|  Policy B: "BYOD Device"           |--> VLAN 200, restricted
|    Match: no domain + MAB only      |
|                                     |
|  No match                          |--> Default VLAN, quarantine
+-------------------------------------+
    |
    v
+-------------------------------------+
|  POST-ADMISSION (NPT STATS)        |
|                                     |
|  NTP offset across devices          |
|  Rule hit counters per slot         |
|  Accept/Reject ratio over N runs    |
|  Latency percentiles                |
+-------------------------------------+
```

---

## Category Model -- Two Tiers

### TestCategory: WHAT feature is under test (~12 values)

```python
class TestCategory(str, Enum):
    # Certificate validation
    SAN_DETECTION    = "san_detection"
    EKU_VALIDATION   = "eku_validation"
    OCSP_CRL         = "ocsp_crl"
    CERT_CHAIN       = "cert_chain"
    CERT_EXPIRY      = "cert_expiry"
    # Auth methods
    EAP_TLS          = "eap_tls"
    PEAP_MSCHAPV2    = "peap_mschapv2"
    MAB_FALLBACK     = "mab_fallback"
    # Rule engine
    PRE_ADMISSION    = "pre_admission"
    POLICY_MATCH     = "policy_match"
    # Infrastructure
    COA_DISCONNECT   = "coa_disconnect"
    VLAN_ASSIGNMENT  = "vlan_assignment"
```

### TestAspect: HOW DEEP to verify (~5 values)

```python
class TestAspect(str, Enum):
    AUTH_DECISION    = "auth_decision"      # Did we get Accept/Reject?
    RULE_SELECTION   = "rule_selection"     # Which rule slot matched?
    SUBRULE_EVAL     = "subrule_eval"      # Which sub-conditions evaluated?
    POLICY_CLASS     = "policy_class"       # Post-auth classification?
    STATS_AGGREGATE  = "stats_aggregate"   # NPT stats across N runs
```

---

## How 90 Test Cases Map

### Pre-Admission Rule Tests

| Test Case ID | Category | Aspect | What it tests |
|---|---|---|---|
| TP-PREADM-001 | PRE_ADMISSION | RULE_SELECTION | Good cert hits Rule 1 (EAP-TLS), Accept |
| TP-PREADM-002 | PRE_ADMISSION | RULE_SELECTION | No cert, falls through to Rule 3 (MAB), Accept |
| TP-PREADM-003 | PRE_ADMISSION | RULE_SELECTION | Unknown MAC, no rule matches, Default Reject |
| TP-PREADM-004 | PRE_ADMISSION | RULE_SELECTION | PEAP creds hit Rule 2, Accept |
| TP-PREADM-005 | PRE_ADMISSION | RULE_SELECTION | Rule 1 disabled, good cert falls to Rule 2 |

Expected evidence for TP-PREADM-001:

```yaml
expected:
  decision: accept
  rule_slot: 1
  rule_action: accept
  auth_source: "Pre-Admission rule 1"
  auth_method: eap-tls
```

### Subrule Evaluation Tests

| Test Case ID | Category | Aspect | What it tests |
|---|---|---|---|
| TP-SUBR-001 | PRE_ADMISSION | SUBRULE_EVAL | Rule 1 sub: CN matches AD account, Accept |
| TP-SUBR-002 | PRE_ADMISSION | SUBRULE_EVAL | Rule 1 sub: CN does NOT match AD, Reject |
| TP-SUBR-003 | PRE_ADMISSION | SUBRULE_EVAL | Rule 1 sub: EKU missing Client Auth OID, fails |
| TP-SUBR-004 | PRE_ADMISSION | SUBRULE_EVAL | Rule 2 sub: AD group = "Dot1x-Users", Accept |
| TP-SUBR-005 | PRE_ADMISSION | SUBRULE_EVAL | Rule 2 sub: AD group = "Disabled-Users", Reject |

Expected evidence for TP-SUBR-002:

```yaml
expected:
  decision: reject
  rule_slot: 1              # Rule 1 was EVALUATED
  rule_action: reject       # But REJECTED because sub-rule failed
  findings:
    - "Sub-rule CN match: FAILED (CN=BadUser not in AD)"
    - "Rule 1 sub-rules: 2/3 passed, 1/3 failed"
    - "Fell through to default reject"
```

### Policy Match / Unmatch Tests

| Test Case ID | Category | Aspect | What it tests |
|---|---|---|---|
| TP-POL-001 | POLICY_MATCH | POLICY_CLASS | After Accept via Rule 1, classified "Corporate Laptop" |
| TP-POL-002 | POLICY_MATCH | POLICY_CLASS | After Accept via Rule 3 (MAB), classified "BYOD Device" |
| TP-POL-003 | POLICY_MATCH | POLICY_CLASS | After Accept, no policy matches, default classification |
| TP-POL-004 | POLICY_MATCH | POLICY_CLASS | Matches Policy A and B, first-match wins |
| TP-POL-005 | POLICY_MATCH | POLICY_CLASS | VLAN assigned matches policy (1570 for corp) |

Expected evidence for TP-POL-001:

```yaml
expected:
  decision: accept
  rule_slot: 1
  classification: "Corporate Laptop"
  login_type: "dot1x_computer_login"
  domain: "CORP.FORESCOUT.COM"
  vlan: 1570
```

### NPT Stats / Aggregate Tests

| Test Case ID | Category | Aspect | What it tests |
|---|---|---|---|
| TP-NPT-001 | PRE_ADMISSION | STATS_AGGREGATE | Rule 1 hit rate across 10 runs (expect 100%) |
| TP-NPT-002 | PRE_ADMISSION | STATS_AGGREGATE | Accept latency p50 < 2s, p99 < 5s across 20 runs |
| TP-NPT-003 | EAP_TLS | STATS_AGGREGATE | TLS handshake success rate (expect > 99%) |
| TP-NPT-004 | POLICY_MATCH | STATS_AGGREGATE | Classification consistency (same MAC = same policy) |
| TP-NPT-005 | MAB_FALLBACK | STATS_AGGREGATE | MAB fallback time after EAP timeout (< 30s) |

Expected evidence for TP-NPT-002:

```yaml
expected:
  run_type: stability_probe
  iterations: 20
  stats:
    accept_rate: ">= 0.99"
    latency_p50: "< 2.0"
    latency_p99: "< 5.0"
    rule_slot_consistency: "100%"
```

---

## Category x Aspect Matrix

```
                    AUTH      RULE       SUBRULE     POLICY     STATS
                  DECISION  SELECTION    EVAL        CLASS    AGGREGATE
                  --------  ---------  ---------  ---------  ---------
EAP_TLS            TC-001    TC-002                            TC-003
SAN_DETECTION      TC-010    TC-011     TC-012      TC-013
EKU_VALIDATION     TC-020    TC-021     TC-022      TC-023
OCSP_CRL           TC-030    TC-031     TC-032
CERT_CHAIN         TC-040    TC-041     TC-042
CERT_EXPIRY        TC-050    TC-051
PEAP_MSCHAPV2      TC-060    TC-061     TC-062      TC-063
MAB_FALLBACK       TC-070    TC-071                 TC-073     TC-074
PRE_ADMISSION      TC-080    TC-081     TC-082      TC-083     TC-084
POLICY_MATCH                                        TC-090     TC-091
VLAN_ASSIGNMENT                                     TC-095
COA_DISCONNECT     TC-098
```

Not every cell needs a test. ~90 tests populate ~60% of the cells.

---

## YAML Registry Format

```yaml
# testcases/pre_admission.yaml
- id: TP-PREADM-001
  category: pre_admission
  aspect: rule_selection
  class: PreAdmissionRuleMatchTest
  path: tests/radius/functional/radius_functional_preadm.py
  decision: accept
  method: eap-tls
  cert: Dot1x-CLT-Good
  description: "Good EAP-TLS cert hits Rule 1, Accept"
  expected_rule_slot: 1
  expected_auth_source: "Pre-Admission rule 1"
  tags: [positive, pre-admission, rule-1, eap-tls]

- id: TP-SUBR-002
  category: pre_admission
  aspect: subrule_eval
  class: PreAdmissionSubruleCNMismatchTest
  path: tests/radius/functional/radius_functional_preadm.py
  decision: reject
  method: eap-tls
  cert: Dot1x-CLT-BadCN
  description: "Rule 1 CN sub-rule fails, fall through, Default reject"
  expected_rule_slot: null
  expected_subrule_failures:
    - rule: 1
      subrule: "cn_match"
      reason: "CN=BadUser not found in AD"
  tags: [negative, pre-admission, subrule, cn-match]

- id: TP-POL-001
  category: policy_match
  aspect: policy_class
  class: PolicyClassificationCorporateTest
  path: tests/radius/functional/radius_functional_policy.py
  decision: accept
  method: eap-tls
  cert: Dot1x-CLT-Good
  description: "Post-accept: classified as Corporate Laptop"
  expected_rule_slot: 1
  expected_classification: "Corporate Laptop"
  expected_vlan: 1570
  expected_login_type: "dot1x_computer_login"
  tags: [positive, policy, classification, vlan]

- id: TP-NPT-002
  category: pre_admission
  aspect: stats_aggregate
  class: PreAdmissionLatencyStabilityTest
  path: tests/radius/functional/radius_functional_npt.py
  decision: accept
  method: eap-tls
  cert: Dot1x-CLT-Good
  description: "Accept latency p50 < 2s, p99 < 5s over 20 runs"
  iterations: 20
  expected_stats:
    accept_rate: 0.99
    latency_p50_max: 2.0
    latency_p99_max: 5.0
  tags: [stability, latency, npt, pre-admission]
```

---

## What TestPulse Already Captures

| Evidence Field | Parser | Used By |
|---|---|---|
| rule_slot | redis_parser | Pre-admission rule selection |
| rule_action | redis_parser | Accept/reject per rule |
| auth_source | redis_parser | "Pre-Admission rule 1" |
| classification | identity_parser | Policy match result |
| login_type | identity_parser | dot1x_user/computer/mac_login |
| domain | identity_parser | AD domain |
| vlan_config | dot1x_parser | VLAN assignment |
| policy_enabled | dot1x_parser | Policy active/inactive |
| property_field + property_value | framework_parser | Sub-rule evaluation trace |
| eap_type | dot1x_parser | Which EAP method was used |

---

## Summary

```
TestCategory  (~12)  = WHAT feature         (pre_admission, policy_match...)
TestAspect    (~5)   = HOW DEEP to verify   (decision, rule, subrule, policy, stats)
TestCaseSpec  (90)   = SPECIFIC test        (ID + class + expected values)
RunType       (5)    = HOW to execute       (positive, negative, forensic...)
```

Do not make 90 categories. Make 12 categories x 5 aspects = 60 possible cells, fill ~90 tests across them, define expected values in YAML, and let the evaluator (Phase 1) or MCP agent (Phase 3) compare actual evidence against expected evidence from the registry.
