# TestPulse Testing Procedures

**fstester + TestPulse Integration Workflows for 802.1X RADIUS Diagnostic Testing**

> Phase 1 CLI -- Proof Positive, Negative, Forensic, Stability, and Direct Probe Scenarios

---

## Execution Order

fstester runs FIRST, TestPulse runs SECOND. They are sequential, not simultaneous. TestPulse is the post-mortem analyst -- it needs the logs that fstester's test run generates.

```
fstester (execute test) --> TestPulse (collect + analyze evidence)
         |                            |
    generates logs              pulls those logs
    on appliance                parses, correlates,
                                evaluates, diagrams
```

The one exception: pcap capture must start BEFORE fstester and stop after.

---

## Scenario 1 -- Proof Positive (Happy Path)

**Goal:** Prove the system correctly accepts what it should accept.

### Step 1: Run the test

```bash
python fstester.py \
  -t tests/radius/functional/radius_functional_eap_tls.py::EAPTLSPolicySANDetectionTest \
  -config test_config/radius/tarik_radius.yml --report SAN
```

### Step 2: Collect evidence + diagnose (immediately after)

```bash
testpulse \
  --run-dir /tmp/SAN_POSITIVE \
  --testcase-id TP-SAN-001 \
  --expected-decision accept \
  --expected-method eap-tls \
  --collect \
  --testbed-config radius.yaml \
  --framework-log /home/triley/fstester001-mab/fstester.log \
  --out /tmp/SAN_POSITIVE/evidence_bundle.json \
  --pretty
```

### What you are proving

- RADIUS sent Access-Accept
- EAP-TLS handshake completed
- SAN matched policy
- Classification = PASS_CONFIRMED, confidence >= 0.9

---

## Scenario 2 -- Negative Testing (Reject Confirmation)

**Goal:** Prove the system correctly REJECTS what it should reject.

### Step 1: Run test with bad/revoked/expired cert

```bash
python fstester.py \
  -t tests/radius/functional/radius_functional_eap_tls.py::EAPTLSRevokedCertTest \
  -config test_config/radius/tarik_radius.yml --report REVOKED
```

### Step 2: Diagnose -- note expected-decision is "reject"

```bash
testpulse \
  --run-dir /tmp/SAN_NEGATIVE \
  --testcase-id TP-SAN-002 \
  --expected-decision reject \
  --expected-method eap-tls \
  --collect \
  --testbed-config radius.yaml \
  --framework-log /home/triley/fstester001-mab/fstester.log \
  --out /tmp/SAN_NEGATIVE/evidence_bundle.json \
  --pretty
```

### What you are proving

- RADIUS sent Access-Reject
- EAP-TLS handshake failed at certificate validation
- Classification = PASS_CONFIRMED (reject was expected and observed)
- If you get Access-Accept instead: FAIL_UNEXPECTED -- appliance is NOT enforcing cert revocation

### Three-cert negative sweep (the gold standard)

| Run | Cert | --expected-decision | Healthy result |
|-----|------|---------------------|----------------|
| TP-SAN-002a | Good cert | accept | PASS_CONFIRMED |
| TP-SAN-002b | Revoked cert | reject | PASS_CONFIRMED |
| TP-SAN-002c | Expired cert | reject | PASS_CONFIRMED |

If 002b comes back FAIL_UNEXPECTED (Accept when Reject expected), OCSP/CRL is not configured.

---

## Scenario 3 -- Sherlock Holmes (Deep Forensic Detective)

**Goal:** The test failed or behaved unexpectedly. Find out WHY. This is the full-evidence workflow with pcap wire capture.

### Step 0: NTP pre-flight (ensure clocks are synced for pcap correlation)

```bash
testpulse --run-dir /tmp/SAN_SHERLOCK --testcase-id TP-SAN-003 \
  --expected-decision accept --ntp-check --testbed-config radius.yaml
```

### Step 1: START pcap capture BEFORE the test

In a separate terminal -- captures wire-level EAP/RADIUS/TLS:

```bash
testpulse --run-dir /tmp/SAN_SHERLOCK --testcase-id TP-SAN-003 \
  --expected-decision accept --collect --testbed-config radius.yaml \
  --pcap /tmp/SAN_SHERLOCK/pcap/appliance.pcap
```

### Step 2: Run the test (while pcap is capturing)

```bash
python fstester.py \
  -t tests/radius/functional/radius_functional_eap_tls.py::EAPTLSPolicySANDetectionTest \
  -config test_config/radius/tarik_radius.yml --report SAN
```

### Step 3: Stop pcap, collect logs, full analysis

```bash
testpulse \
  --run-dir /tmp/SAN_SHERLOCK \
  --testcase-id TP-SAN-003 \
  --expected-decision accept \
  --expected-method eap-tls \
  --collect \
  --testbed-config radius.yaml \
  --framework-log /home/triley/fstester001-mab/fstester.log \
  --pcap /tmp/SAN_SHERLOCK/pcap/appliance.pcap \
  --analyze-pcap \
  --out /tmp/SAN_SHERLOCK/evidence_bundle.json \
  --pretty
```

### What you get -- 6 diagrams + dashboard

- Protocol Sequence -- full RADIUS Request/Accept/Reject flow
- Protocol Flow -- horizontal left-to-right view
- Timeline Story -- chronological event correlation across ALL sources
- Component Topology -- which devices, configs, data sources were involved
- EAPOL Wire Trace -- actual EAP-TLS handshake from pcap (ClientHello to Finished)
- EAPOL Horizontal -- same wire trace as flowchart

### Detective clues to look for

| Symptom in evidence | Diagnosis |
|---------------------|-----------|
| Access-Accept but confidence < 0.5 | Multiple conflicting signals -- flaky |
| Timeline gap > 30s between Request and Accept | RADIUS timeout / LDAP delay |
| EAP-TLS Certificate frame but no Finished | TLS handshake failed -- cert chain broken |
| RADIUS_ACCESS_REJECT with no EAP frames | Policy rejected before EAP started (MAB fallback) |
| Redis shows rule_1 match but dot1x shows no_policy | Policy engine race condition |
| Framework shows property_set but Redis shows stale value | Cache/sync issue between components |
| Multiple Access-Request with same MAC, different Ids | Switch retransmitting -- RADIUS too slow |

---

## Scenario 4 -- Flakiness Detector (Stability Probe)

**Goal:** Is the appliance intermittently broken? Run the same test N times and compare.

```bash
for i in $(seq 1 5); do
  RUN="TP-FLAKY-$(printf '%03d' $i)"

  # Run test
  python fstester.py \
    -t tests/radius/functional/radius_functional_eap_tls.py::EAPTLSPolicySANDetectionTest \
    -config test_config/radius/tarik_radius.yml --report "run_$i"

  # Collect + diagnose
  testpulse \
    --run-dir "/tmp/$RUN" \
    --testcase-id "$RUN" \
    --expected-decision accept \
    --expected-method eap-tls \
    --collect \
    --testbed-config radius.yaml \
    --framework-log /home/triley/fstester001-mab/fstester.log \
    --out "/tmp/$RUN/evidence_bundle.json" \
    --pretty

  sleep 5  # let RADIUS settle between runs
done
```

Then compare: if 4/5 pass and 1 fails, the appliance is flaky. The failed run's dashboard shows exactly where it diverged.

---

## Scenario 5 -- eapol_test Bypass (No fstester, No Switch)

**Goal:** Validate RADIUS certificate handling directly -- no switch, no supplicant, no fstester. Pure diagnostic probe.

```python
from testpulse.tools.eapol_test_runner import run_eapol_test, EapolTestConfig

for name, cert, expect in [
    ("good",    "good.pem",    True),
    ("revoked", "revoked.pem", False),
    ("expired", "expired.pem", False),
]:
    cfg = EapolTestConfig(
        radius_ip="10.16.177.66",
        shared_secret="testing123",
        identity=f"Dot1x-CLT-{name.title()}",
        eap_method="TLS",
        ca_cert="certs/ca.pem",
        client_cert=f"certs/{cert}",
        private_key=f"certs/{name}_key.pem",
        private_key_passwd="aristo",
    )
    result = run_eapol_test(cfg)
    status = "PASS" if result.success == expect else "FAIL"
    print(f"  {name:8s}: {status}  (success={result.success})")
```

---

## Summary -- When to Use What

| Scenario | fstester | TestPulse | pcap | Purpose |
|----------|----------|-----------|------|---------|
| Proof Positive | First | Second (--collect) | No | Confirm accept works |
| Negative Testing | First | Second (--expected-decision reject) | No | Confirm reject works |
| Sherlock Holmes | Middle | Before (pcap) + After (analyze) | Yes | Root cause analysis |
| Flakiness | Loop N times | After each run | Optional | Stability check |
| eapol_test Bypass | Not needed | Not needed (direct API) | Optional | Pure RADIUS cert probe |

---

## Appendix: Testbed Configuration (radius.yaml)

```yaml
em:
  ip: 10.16.177.65          # Enterprise Manager
  user_name: root
  password: aristo1
  version: 8.5.3

ca:
  ip: 10.16.177.66          # Forescout appliance (RADIUS)
  user_name: root
  password: aristo1
  version: 8.5.3

switch:
  ip: 10.16.128.21          # Cisco switch
  user_name: admin
  password: aristo
  port1:
    interface: TenGigabitEthernet1/1
    vlan: 1570

passthrough:
  ip: 10.16.133.134         # Windows passthrough endpoint
  user_name: Administrator
  password: aristo
  mac: 98f2b301a055
  nicname: pciPassthru0
```

## Appendix: Certificate Preparation for Negative Testing

Convert PFX (PKCS#12) certificates to PEM for eapol_test:

```bash
# Extract client cert
openssl pkcs12 -in Dot1x-CLT-Good.pfx -clcerts -nokeys \
  -out good.pem -passin pass:aristo

# Extract private key
openssl pkcs12 -in Dot1x-CLT-Good.pfx -nocerts -nodes \
  -out good_key.pem -passin pass:aristo

# Extract CA chain
openssl pkcs12 -in Dot1x-CLT-Good.pfx -cacerts -nokeys \
  -out ca.pem -passin pass:aristo
```

Repeat for revoked (Dot1x-CLT-Revoked.pfx) and expired (Dot1x-CLT-Expired.pfx) certificates.

## Appendix: EKU / MSCA Validation Checklist

1. **EKU present** -- Client cert must include Client Authentication (OID 1.3.6.1.5.5.7.3.2). Verify: `openssl x509 -in cert.pem -noout -purpose`

2. **CA chain complete** -- Full chain (root to intermediate to leaf) must be in the RADIUS trust store. Missing intermediates cause Access-Reject even for valid certs.

3. **CRL Distribution Point** -- Cert should include a CDP the appliance can reach. Verify: `openssl x509 -in cert.pem -noout -text | grep -A2 "CRL Distribution"`

4. **OCSP Responder** -- If using OCSP, the AIA extension must point to a reachable responder. Verify: `openssl x509 -in cert.pem -noout -text | grep -A2 "Authority Information Access"`

5. **AD CS Template** -- Common templates for 802.1X: Workstation Authentication, Computer, or custom EAP-TLS templates. Template controls EKU, key usage, and validity period.

## Appendix: Interpreting Results Matrix

| Result | Good cert | Revoked cert | Expired cert | Diagnosis |
|--------|-----------|--------------|--------------|-----------|
| Expected | Accept | Reject | Reject | Appliance healthy |
| OCSP gap | Accept | Accept (!) | Reject | OCSP/CRL not configured -- revoked certs pass |
| Flaky | Intermittent | -- | -- | RADIUS service unstable, check radiusd logs |
| Broken | Reject | Reject | Reject | Certificate chain or trust anchor misconfigured |
