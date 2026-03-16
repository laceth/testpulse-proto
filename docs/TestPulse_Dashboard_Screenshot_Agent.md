# TestPulse Dashboard Screenshot Agent

## Phase 3 Addendum — Source of Truth via Dashboard Capture

### Purpose

Capture a **screenshot of the expected dashboard state** after each fstester
test case step completes, and store it alongside the evidence bundle in a
`source_of_truth/` folder. This creates a visual baseline that every future
run can be compared against — both visually and structurally.

---

## Phase 3 Review: Current State

### 7 MCP Tools (complete)

| Tool              | Purpose                        | Status |
|-------------------|--------------------------------|--------|
| `status`          | Testbed connectivity check     | Built  |
| `list_tests`      | Browse test categories         | Built  |
| `proof_positive`  | Run test, expect Accept        | Built  |
| `negative_test`   | Run test, expect Reject        | Built  |
| `forensic_analyze`| Deep analysis of existing run  | Built  |
| `stability_probe` | N-iteration flakiness check    | Built  |
| `cert_probe`      | 3-cert RADIUS sweep            | Built  |

**Blocker:** MCP disabled by org policy (`chat.mcp.access = none`). Waiting on IT.

### Current Artifacts Per Run

Each run produces:

- `evidence_bundle.json` — structured verdict + timeline
- `evidence_bundle.mmd` — protocol sequence diagram
- `evidence_bundle_timeline.mmd` — horizontal timeline
- `evidence_bundle_components.mmd` — component flow
- `evidence_bundle_protocol_h.mmd` — horizontal protocol
- `*_dashboard.html` — tabbed dashboard with all diagrams
- Raw logs: `radiusd.log`, `dot1x.log`, `framework.log`, etc.

---

## Next Agent: Dashboard Screenshot Source of Truth

### Concept

For each fstester test case step, capture a **screenshot of the expected
dashboard state** and store it in a `source_of_truth/` folder. This creates
a visual baseline that each new run can be compared against.

### Proposed Folder Structure

```
source_of_truth/
  TC_9448_EAPTLSPolicySANDetectionTest/
    T1316925/
      step_1_preconditions/
        expected_dashboard.png       <-- screenshot of dashboard
        expected_bundle.json         <-- expected evidence bundle
        description.md               <-- what this step tests
      step_2_san_anyvalue_match/
        expected_dashboard.png
        expected_bundle.json
        description.md
      step_3_san_invalid_no_match/
        expected_dashboard.png
        expected_bundle.json
        description.md
      step_4_san_contains_match/
        expected_dashboard.png
        expected_bundle.json
        description.md
  TC_XXXX_EAPTLSBasicAuthWiredTest/
    T1316931/
      step_1_accept_tls/
        expected_dashboard.png
        expected_bundle.json
        description.md
      step_2_reject_moved_cert/
        expected_dashboard.png
        expected_bundle.json
        description.md
```

### What the Agent Does

1. **Takes a screenshot** of the dashboard HTML after each test step completes
   (headless Chromium via Playwright)
2. **Saves the `evidence_bundle.json`** as the expected baseline
3. **Generates a `description.md`** summarizing what the step validates
4. **Compares future runs** against the baseline — visual diff + JSON diff

---

## Architecture

### Screenshot Capture Flow

```
fstester runner.py                  TestPulse Screenshot Agent
--------------------                ----------------------------
1. do_setup()
2. do_test() Step 1
   --> toggle NIC, verify auth
                                    3. Collect logs from appliance
                                    4. Run TestPulse diagnostics
                                    5. Generate dashboard HTML
                                    6. Playwright captures PNG
                                    7. Save to source_of_truth/
                                       step_1_preconditions/
3. do_test() Step 2
   --> update policy, re-auth
                                    8. Collect logs
                                    9. Run diagnostics
                                   10. Capture dashboard PNG
                                   11. Save to source_of_truth/
                                       step_2_san_anyvalue_match/
... repeat for each step ...
```

### Comparison Flow (on subsequent runs)

```
New Test Run
    |
    v
TestPulse generates new dashboard
    |
    v
compare_to_baseline tool
    |
    +---> JSON diff: evidence_bundle.json vs expected_bundle.json
    |         - Decision match?
    |         - Confidence within threshold?
    |         - Timeline event count delta?
    |         - Rule/policy match?
    |
    +---> Visual diff: new_dashboard.png vs expected_dashboard.png
    |         - Pixel-level diff (Pillow/ImageChops)
    |         - Highlight regions that changed
    |         - Generate diff overlay image
    |
    v
Comparison Report
    - MATCH / DRIFT / REGRESSION
    - JSON delta summary
    - Visual diff image (if drift detected)
```

---

## New MCP Tools

### `snapshot_baseline`

Captures the current run state as the source of truth for a test step.

```
snapshot_baseline(
    testcase_class: str,    # e.g. "TC_9448_EAPTLSPolicySANDetectionTest"
    testcase_id: str,       # e.g. "T1316925"
    step_name: str,         # e.g. "step_1_preconditions"
    run_id: str,            # e.g. "T1316925"
    description: str        # e.g. "Endpoint authenticates via EAP-TLS,
                            #        SAN populated on host properties"
)
```

**What it does:**

1. Locates `artifacts/{run_id}/` dashboard and evidence bundle
2. Uses Playwright to screenshot the dashboard HTML at 1920x1080
3. Copies `evidence_bundle.json` as `expected_bundle.json`
4. Creates `description.md` with the step description + metadata
5. Saves everything under `source_of_truth/{testcase_class}/{testcase_id}/{step_name}/`

### `compare_to_baseline`

Compares a new run against the stored source of truth.

```
compare_to_baseline(
    testcase_class: str,    # e.g. "TC_9448_EAPTLSPolicySANDetectionTest"
    testcase_id: str,       # e.g. "T1316925"
    step_name: str,         # e.g. "step_2_san_anyvalue_match"
    run_id: str             # new run to compare
)
```

**What it does:**

1. Loads `source_of_truth/{testcase_class}/{testcase_id}/{step_name}/expected_bundle.json`
2. Loads `artifacts/{run_id}/evidence_bundle.json`
3. Performs JSON diff:
   - Decision match (accept/reject)
   - Classification match (PASS_CONFIRMED, etc.)
   - Confidence delta
   - Timeline event count delta
   - Rule slot / auth method match
   - Policy match results
4. Takes screenshot of new dashboard
5. Performs visual diff against `expected_dashboard.png`
6. Returns verdict: **MATCH**, **DRIFT**, or **REGRESSION**

### `list_baselines`

Lists all stored baselines for a test case.

```
list_baselines(
    testcase_class: str = "",   # filter by class name
    testcase_id: str = ""       # filter by test case ID
)
```

---

## Implementation Plan

### Step 1: Screenshot Capture Tool

**Module:** `testpulse/tools/screenshot_capture.py`

**Dependencies:**
- `playwright` (headless Chromium)
- `Pillow` (image diffing)

```python
# Core function signature
def capture_dashboard(
    html_path: Path,
    output_png: Path,
    width: int = 1920,
    height: int = 1080,
    wait_for_mermaid: bool = True,
) -> Path:
    """
    Open dashboard HTML in headless Chromium,
    wait for Mermaid.js to render all diagrams,
    capture full-page screenshot, save as PNG.
    """
```

### Step 2: Baseline Manager

**Module:** `testpulse/core/baseline.py`

```python
def save_baseline(
    testcase_class: str,
    testcase_id: str,
    step_name: str,
    dashboard_png: Path,
    evidence_bundle: dict,
    description: str,
    source_of_truth_dir: Path,
) -> Path:
    """Save dashboard screenshot + evidence bundle as baseline."""

def load_baseline(
    testcase_class: str,
    testcase_id: str,
    step_name: str,
    source_of_truth_dir: Path,
) -> dict:
    """Load stored baseline for comparison."""

def compare_bundles(
    expected: dict,
    observed: dict,
) -> dict:
    """JSON-level comparison of two evidence bundles."""

def compare_screenshots(
    expected_png: Path,
    observed_png: Path,
    diff_output: Path,
) -> dict:
    """Pixel-level visual diff, returns similarity score and diff image."""
```

### Step 3: MCP Tool Registration

Add `snapshot_baseline`, `compare_to_baseline`, and `list_baselines` to
`testpulse/mcp/server.py` and implement handlers in `testpulse/mcp/tools.py`.

### Step 4: fstester Integration Hook

Optional: Add a post-step hook to `runner.py` that automatically calls
`snapshot_baseline` after each `do_test()` step, so baselines are captured
during the initial "golden run" without manual intervention.

---

## Comparison Report Format

When `compare_to_baseline` runs, it returns a structured report:

```
BASELINE COMPARISON: step_2_san_anyvalue_match

Verdict: MATCH

JSON Comparison:
  Decision:        accept == accept          [MATCH]
  Classification:  PASS_CONFIRMED == PASS_CONFIRMED  [MATCH]
  Confidence:      0.90 vs 0.90 (delta: 0.00)       [MATCH]
  Timeline Events: 46 vs 46 (delta: 0)              [MATCH]
  Rule Slot:       1 == 1                            [MATCH]
  Auth Method:     EAP-TLS == EAP-TLS               [MATCH]

Visual Comparison:
  Similarity: 99.7%
  Changed regions: 0
  Status: MATCH (threshold: 95%)

Baseline: source_of_truth/TC_9448_.../T1316925/step_2_.../
```

Example of a DRIFT report:

```
BASELINE COMPARISON: step_3_san_invalid_no_match

Verdict: DRIFT

JSON Comparison:
  Decision:        accept == accept          [MATCH]
  Classification:  PASS_CONFIRMED == PASS_CONFIRMED  [MATCH]
  Confidence:      0.85 vs 0.90 (delta: -0.05)      [DRIFT]
  Timeline Events: 42 vs 46 (delta: -4)             [DRIFT]
  Rule Slot:       1 == 1                            [MATCH]

Visual Comparison:
  Similarity: 87.3%
  Changed regions: 2
  Status: DRIFT (below 95% threshold)
  Diff image: artifacts/T1316925/baseline_diff.png

Action: Review timeline delta — 4 fewer events may indicate
        a parsing change or log truncation.
```

---

## Dependencies

| Package     | Purpose                          | Install                        |
|-------------|----------------------------------|--------------------------------|
| `playwright`| Headless Chromium screenshots     | `pip install playwright`       |
|             |                                  | `playwright install chromium`  |
| `Pillow`    | Image comparison / diff overlay  | `pip install Pillow`           |

Add to `pyproject.toml`:

```toml
[project.optional-dependencies]
screenshot = ["playwright>=1.40", "Pillow>=10.0"]
```

---

## CLI Usage (without MCP)

While waiting for IT to enable MCP, the screenshot agent can be used via CLI:

```bash
# Capture baseline for a test step
python -m testpulse.tools.screenshot_capture \
  --run-dir artifacts/T1316925 \
  --testcase-class TC_9448_EAPTLSPolicySANDetectionTest \
  --testcase-id T1316925 \
  --step-name step_1_preconditions \
  --description "Endpoint authenticates via EAP-TLS, SAN populated"

# Compare a new run against baseline
python -m testpulse.tools.screenshot_capture \
  --compare \
  --run-dir artifacts/T1316925_run2 \
  --testcase-class TC_9448_EAPTLSPolicySANDetectionTest \
  --testcase-id T1316925 \
  --step-name step_1_preconditions

# List all baselines
python -m testpulse.tools.screenshot_capture --list-baselines
```

---

## Integration with fstester runner.py

After each test step, the screenshot agent can be called inline:

```python
# In runner.py run_class(), after do_test() succeeds:
from testpulse.tools.screenshot_capture import capture_and_save_baseline

# After step completes successfully
capture_and_save_baseline(
    run_dir=log_dir_path,
    testcase_class=cls.__name__,
    testcase_id=instance.testCaseId,
    step_name=f"step_{step_num}_{step_label}",
    description=step_description,
)
```

---

## Summary

| Component              | Module                                  | Status      |
|------------------------|-----------------------------------------|-------------|
| Screenshot capture     | `testpulse/tools/screenshot_capture.py` | Planned     |
| Baseline manager       | `testpulse/core/baseline.py`            | Planned     |
| MCP `snapshot_baseline`| `testpulse/mcp/tools.py`                | Planned     |
| MCP `compare_to_baseline`| `testpulse/mcp/tools.py`              | Planned     |
| MCP `list_baselines`   | `testpulse/mcp/tools.py`                | Planned     |
| fstester hook          | `runner.py` integration                 | Planned     |
| Visual diff overlay    | `testpulse/core/baseline.py`            | Planned     |
| CLI interface          | `testpulse/tools/screenshot_capture.py` | Planned     |
