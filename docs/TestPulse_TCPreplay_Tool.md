# TCPreplay Tool for TestPulse

## What, Why, and How to Add Packet Replay to the Agent Toolkit

---

## What is tcpreplay?

tcpreplay is a Linux tool that replays captured pcap files back onto a network
interface. It takes a .pcap/.pcapng file and sends the packets out as if they
were real traffic, enabling controlled, repeatable injection of authentication
flows against RADIUS and 802.1X infrastructure.

---

## Why Add It to TestPulse?

TestPulse already has two pcap-related capabilities:

- **pcap_collector.py** — captures live traffic during tests (tcpdump/tshark on
  appliance, switch, endpoint, AD)
- **eapol_parser.py** — parses EAPOL/EAP/RADIUS frames from pcap files into
  structured AuthEvent objects (70+ event kinds)

The missing piece: replaying a known-good pcap to reproduce an exact
authentication flow without needing the actual endpoint, switch, or
certificates.

### Use Cases

| Use Case | Why It Matters |
|----------|----------------|
| Offline regression | Replay a golden pcap from a passed run to verify the appliance still accepts it — no passthrough VM needed |
| Reproducible failures | Capture a failing auth flow once, replay it repeatedly to debug |
| SAN/cert edge cases | Replay specific TLS handshakes with crafted certs without reconfiguring the endpoint |
| Appliance-only testing | Test the RADIUS server behavior by injecting traffic directly, bypassing the switch |
| CI/CD integration | Run automated replay tests without physical hardware |

---

## How It Fits in the TestPulse Architecture

### Data Flow

```
                      Existing                          New
                    +----------------+              +----------------+
                    | pcap_collector |              | tcpreplay      |
                    | (capture)      |              | (replay)       |
                    +-------+--------+              +-------+--------+
                            |                               |
                            v                               v
              +---------------------------------------------------+
              |           Network (appliance port)                |
              +---------------------------------------------------+
                            |
                            v
              +--------------------------+
              |   eapol_parser.py        |  <-- parses the response
              |   (analyze pcap)         |
              +--------------------------+
                            |
                            v
              +--------------------------+
              |   evidence_bundle.json   |  <-- verdict + diagrams
              +--------------------------+
```

### Workflow

1. **Capture** a golden run with pcap_collector -- save as baseline pcap
2. **Replay** that pcap with tcpreplay against the appliance
3. **Capture** the response simultaneously
4. **Analyze** with TestPulse (parsers, correlator, evaluator, diagrams)
5. **Compare** against baseline with compare_to_baseline

---

## Existing TestPulse Pcap Infrastructure

### pcap_collector.py — Multi-Device Capture

Captures are started before a test round and stopped after. One .pcap file
per device:

```
Capture Points:

+---------------+   +-----------+   +--------------+   +------------+
|  Passthru VM  |   |  Cisco    |   |  Forescout   |   |  LDAP / AD |
|  (Endpoint)   |   |  Switch   |   |  Appliance   |   |    VM      |
|  tshark.exe   |   |  monitor  |   |  tcpdump     |   |  tcpdump   |
+-------+-------+   +-----+-----+   +------+-------+   +-----+------+
        |                  |                |                 |
        +------------------+----------------+-----------------+
                     NTP-synchronised clocks
```

NTP requirement: every device MUST report an NTP offset < 50 ms before
captures start. The NtpSyncChecker (ntp_sync.py) verifies this.

### eapol_parser.py — Deep Packet Analysis

Parses EAPOL/EAP/RADIUS frames from pcap files. Supported frame types:

- EAPOL-Start
- EAP-Request Identity / EAP-Response Identity
- EAP-Request (TLS, PEAP, MD5, etc.) / EAP-Response
- EAP-Success / EAP-Failure
- RADIUS Access-Request / Access-Accept / Access-Reject
- TLS handshake sub-messages (Client Hello, Server Hello, Certificate,
  Change Cipher Spec, Finished)

Each recognised frame becomes an AuthEvent with source="pcap" and a kind
string such as EAPOL_START, EAP_REQUEST_IDENTITY, EAP_TLS_CLIENT_HELLO,
RADIUS_ACCESS_ACCEPT, etc.

---

## Implementation Plan

### Step 1: Install tcpreplay

```
sudo apt-get install tcpreplay
```

### Step 2: Create the Tool Module

Module: testpulse/tools/tcpreplay_runner.py

```
@dataclass
class ReplayConfig:
    pcap_file: Path              # source pcap to replay
    interface: str               # NIC to replay on (e.g. eth1)
    speed_multiplier: float      # 1.0 = real-time, 2.0 = 2x speed
    loop: int                    # number of replay iterations
    capture_response: bool       # simultaneously capture response
    capture_interface: str       # NIC to capture on (default: same)
    capture_filter: str          # BPF filter for response capture
    run_dir: Path | None         # where to save response capture
```

Core function:

```
def replay_pcap(cfg: ReplayConfig) -> dict:
    """Replay a pcap file and optionally capture the response.

    1. Starts tcpdump on the capture interface (if capture_response)
    2. Runs tcpreplay to inject packets
    3. Stops capture after replay completes
    4. Returns stats and paths to captured files
    """
```

### Step 3: Register as MCP Tool

Add to testpulse/mcp/server.py:

```
@mcp.tool()
def replay_pcap(
    pcap_file: str,
    interface: str = "eth1",
    run_id: str = "",
    speed: float = 1.0,
    capture_response: bool = True,
) -> str:
    """Replay a pcap file against the network and analyze the response.

    Replays a stored authentication capture (EAPOL/RADIUS) through
    a network interface to regression-test the appliance without
    needing the original endpoint hardware.
    """
```

### Step 4: Wire into the Pipeline

After replay + response capture:

1. Run eapol_parser.parse_pcap() on the response capture
2. Feed events into the correlator and evaluator
3. Generate evidence bundle + diagrams
4. Compare against the original run's baseline

---

## MCP Tool Definition

### replay_pcap

Replays a stored pcap authentication capture against the RADIUS/802.1X
infrastructure and analyzes the response.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| pcap_file | str | required | Path to the .pcap/.pcapng file to replay |
| interface | str | eth1 | Network interface to replay on |
| run_id | str | auto | Run directory name for saving response capture |
| speed | float | 1.0 | Replay speed multiplier (1.0 = real-time) |
| capture_response | bool | True | Whether to capture response traffic |

**Returns:** Structured text report with replay stats, response analysis,
verdict, and paths to generated diagrams.

### Example Usage via MCP Agent

```
User:  "Replay the golden pcap from T1316924 against the appliance"

Agent: [calls replay_pcap(
    pcap_file="artifacts/T1316924/appliance.pcap",
    interface="eth1",
    run_id="T1316924-replay-001"
)]

Result:
    REPLAY RESULT: MATCH

    Source:     artifacts/T1316924/appliance.pcap
    Interface: eth1
    Packets:   847 sent in 12.3s
    Response:  artifacts/T1316924-replay-001/replay_response.pcap

    Analysis:
      Decision:   accept (same as original)
      Confidence: 0.92
      Timeline:   46 events (original: 46)

    Verdict: Appliance behavior unchanged.
```

---

## CLI Usage (without MCP)

While waiting for IT to enable MCP, the replay tool can be used via CLI:

```
# Replay a captured auth flow
python -m testpulse.tools.tcpreplay_runner \
  --pcap artifacts/T1316924/appliance.pcap \
  --interface eth1 \
  --run-dir artifacts/T1316924_replay \
  --speed 1.0 \
  --capture

# Replay + analyze in one shot
python -m testpulse.tools.tcpreplay_runner \
  --pcap artifacts/T1316924/appliance.pcap \
  --interface eth1 \
  --run-dir artifacts/T1316924_replay \
  --analyze \
  --testcase-id T1316924 \
  --expected-decision accept
```

---

## Integration with Source of Truth Baselines

TCPreplay completes the regression testing loop:

```
Golden Run (first time)
    |
    +--> pcap_collector captures traffic
    +--> TestPulse generates evidence_bundle.json
    +--> snapshot_baseline saves dashboard PNG + bundle
    |
    v
Regression Test (later)
    |
    +--> tcpreplay replays the golden pcap
    +--> pcap_collector captures response
    +--> TestPulse generates new evidence_bundle.json
    +--> compare_to_baseline diffs against stored baseline
    |
    v
MATCH / DRIFT / REGRESSION verdict
```

This enables fully automated "does the appliance still behave the same?"
tests without any endpoint hardware, certificates, or switch configuration.

---

## Dependencies

| Package | Purpose | Install |
|---------|---------|---------|
| tcpreplay | Packet replay engine | sudo apt-get install tcpreplay |
| tcpdump | Response capture | Usually pre-installed on Linux |
| scapy | Deep EAPOL/EAP parsing | pip install scapy (already used) |
| dpkt | Lightweight RADIUS parsing | pip install dpkt (already used) |

---

## Component Summary

| Component | Module | Status |
|-----------|--------|--------|
| ReplayConfig dataclass | testpulse/tools/tcpreplay_runner.py | Planned |
| replay_pcap() function | testpulse/tools/tcpreplay_runner.py | Planned |
| MCP replay_pcap tool | testpulse/mcp/server.py | Planned |
| Response analysis | testpulse/ingest/eapol_parser.py | Existing |
| Baseline comparison | testpulse/core/baseline.py | Planned |
| CLI entry point | testpulse/tools/tcpreplay_runner.py | Planned |

---

## Relationship to Other TestPulse Tools

| Tool | Role | Phase |
|------|------|-------|
| pcap_collector | Capture live traffic | Phase 1 (built) |
| eapol_parser | Parse pcap to AuthEvents | Phase 1 (built) |
| tcpreplay_runner | Replay stored pcap | Phase 3 (planned) |
| snapshot_baseline | Save golden run state | Phase 3 (planned) |
| compare_to_baseline | Diff against baseline | Phase 3 (planned) |
| forensic_analyze | Deep analysis with pcap | Phase 3 (built) |
