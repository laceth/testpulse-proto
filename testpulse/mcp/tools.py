"""MCP tool handler implementations for TestPulse.

Each function corresponds to one MCP tool registered in ``server.py``.
They orchestrate the existing TestPulse engine (parsers, correlators,
evaluator, diagram generators) and return structured text responses
that Copilot can reason about.
"""
from __future__ import annotations

import json
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from testpulse.models import (
    Decision,
    RunMetadata,
    RunType,
    TestAspect,
    TestCategory,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _category_enum(value: str) -> TestCategory:
    """Resolve a string to a TestCategory enum, with fallback."""
    try:
        return TestCategory(value)
    except ValueError:
        return TestCategory.EAP_TLS


def _decision_enum(value: str) -> Decision:
    try:
        return Decision(value)
    except ValueError:
        return Decision.UNKNOWN


def _run_diagnostics_core(
    run_dir: Path,
    testcase_id: str,
    expected_decision: Decision,
    expected_method: str,
    collect: bool,
    config_path: Path | None,
    run_metadata: RunMetadata | None = None,
) -> dict:
    """Run the TestPulse diagnostic pipeline through the shared service layer."""
    from testpulse.services.pipeline import analyze_run

    bundle = analyze_run(
        run_dir=run_dir,
        testcase_id=testcase_id,
        expected_decision=expected_decision.value,
        expected_method=expected_method,
        collect=collect,
        testbed_config=config_path if collect else None,
        write_bundle=False,
    )

    # Inject run metadata if provided
    if run_metadata and isinstance(bundle, dict):
        from dataclasses import asdict
        rm_dict = asdict(run_metadata)
        for key in ("run_type", "test_category", "test_aspect"):
            v = rm_dict.get(key)
            if hasattr(v, "value"):
                rm_dict[key] = v.value
        bundle["run_metadata"] = rm_dict

    return bundle


def _format_result(bundle: dict) -> str:
    """Format an EvidenceBundle dict into a readable MCP response."""
    classification = bundle.get("classification", "UNKNOWN")
    observed = bundle.get("observed_decision", "unknown")
    expected = bundle.get("expected_decision", "unknown")
    confidence = bundle.get("confidence", 0.0)
    functional_pass = bundle.get("functional_pass", False)
    testcase_id = bundle.get("testcase_id", "")
    run_id = bundle.get("run_id", "")
    findings = bundle.get("findings", [])
    timeline = bundle.get("timeline", [])
    artifacts = bundle.get("artifacts", [])

    # Run metadata
    rm = bundle.get("run_metadata", {})
    run_type = rm.get("run_type", "")
    category = rm.get("test_category", "")

    lines = [
        f"TEST RESULT: {classification}",
        "",
        f"Test Case:    {testcase_id}",
        f"Run ID:       {run_id}",
    ]
    if run_type:
        lines.append(f"Run Type:     {run_type}")
    if category:
        lines.append(f"Category:     {category}")

    lines += [
        "",
        "Decision Summary:",
        f"  Observed:     {observed}",
        f"  Expected:     {expected}",
        f"  Match:        {'YES' if functional_pass else 'NO'}",
        f"  Confidence:   {confidence:.2f}",
        f"  Classification: {classification}",
    ]

    # Extract key evidence from timeline
    rule_slot = None
    auth_source = None
    auth_method = None
    login_type = None
    domain_val = None
    classification_val = None
    for ev in timeline:
        if ev.get("rule_slot") and not rule_slot:
            rule_slot = ev["rule_slot"]
            auth_source = ev.get("auth_source", "")
        if ev.get("auth_method") and not auth_method:
            auth_method = ev["auth_method"]
        if ev.get("login_type") and not login_type:
            login_type = ev["login_type"]
        if ev.get("domain") and not domain_val:
            domain_val = ev["domain"]
        if ev.get("classification") and not classification_val:
            classification_val = ev["classification"]

    if rule_slot or auth_method:
        lines += ["", "Rule Engine:"]
        if rule_slot:
            lines.append(f"  Rule Matched:   Pre-Admission Rule {rule_slot}")
        if auth_source:
            lines.append(f"  Auth Source:    {auth_source}")
        if auth_method:
            lines.append(f"  Auth Method:    {auth_method}")

    if login_type or domain_val or classification_val:
        lines += ["", "Identity:"]
        if login_type:
            lines.append(f"  Login Type:     {login_type}")
        if domain_val:
            lines.append(f"  Domain:         {domain_val}")
        if classification_val:
            lines.append(f"  Classification: {classification_val}")

    if findings:
        lines += ["", "Findings:"]
        for i, f in enumerate(findings, 1):
            lines.append(f"  {i}. {f}")

    lines += [
        "",
        f"Timeline: {len(timeline)} events",
        f"Artifacts: {len(artifacts)} files",
    ]

    return "\n".join(lines)


def _format_failure_analysis(bundle: dict) -> str:
    """Add root-cause analysis for failed runs."""
    lines = [_format_result(bundle)]
    timeline = bundle.get("timeline", [])

    # Look for diagnostic clues
    clues = []
    for ev in timeline:
        kind = ev.get("kind", "")
        msg = ev.get("message", "")
        if "timeout" in msg.lower():
            clues.append(f"Timeout detected: {msg}")
        if "REJECT" in kind and "EAP" not in kind:
            clues.append(f"Policy rejection: {kind} — {msg}")
        if "FAILED" in kind:
            clues.append(f"Failure event: {kind} — {msg}")

    if clues:
        lines += ["", "Root Cause Candidates:"]
        for i, c in enumerate(clues, 1):
            lines.append(f"  {i}. {c}")

    lines += [
        "",
        "Next actions:",
        "  - Use forensic_analyze for deep pcap investigation",
        "  - Use stability_probe to check if this is intermittent",
        "  - Check appliance logs: radiusd.log, dot1x.log",
    ]

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Tool implementations
# ---------------------------------------------------------------------------

def tool_status(cfg: dict, config_path: Path, artifacts_dir: Path) -> str:
    """Show testbed status."""
    lines = ["TestPulse Testbed Status", ""]

    if not cfg:
        lines.append(f"WARNING: No testbed config found at {config_path}")
        lines.append("Create radius.yaml or set TESTPULSE_CONFIG env var.")
        return "\n".join(lines)

    # Appliance
    ca = cfg.get("ca", {})
    if ca:
        lines.append(f"Appliance:  {ca.get('ip', '???')} (v{ca.get('version', '???')})")

    # EM
    em = cfg.get("em", {})
    if em:
        lines.append(f"EM:         {em.get('ip', '???')} (v{em.get('version', '???')})")

    # Switch
    sw = cfg.get("switch", {})
    if sw:
        port1 = sw.get("port1", {})
        iface = port1.get("interface", "???")
        vlan = port1.get("vlan", "???")
        lines.append(f"Switch:     {sw.get('ip', '???')} ({iface}, VLAN {vlan})")

    # Endpoint
    pt = cfg.get("passthrough", {})
    if pt:
        lines.append(f"Endpoint:   {pt.get('ip', '???')} (MAC {pt.get('mac', '???')})")

    lines += [
        "",
        f"Config:     {config_path}",
        f"Artifacts:  {artifacts_dir}",
        "",
        "Available categories:",
    ]
    for cat in TestCategory:
        lines.append(f"  - {cat.value}")

    lines += [
        "",
        "Run types: proof_positive, negative_test, forensic,",
        "           stability_probe, eapol_probe",
    ]

    return "\n".join(lines)


def tool_list_tests(category: str = "") -> str:
    """List test cases from the registry (or show categories)."""
    lines = ["TestPulse Test Registry", ""]

    if category:
        cat = _category_enum(category)
        lines.append(f"Category: {cat.value}")
        lines.append("")
        lines.append("Test cases in this category are defined in testcases/*.yaml.")
        lines.append("Register test specs to enable automated selection.")
    else:
        lines.append("Available test categories:")
        lines.append("")
        for cat in TestCategory:
            lines.append(f"  {cat.value}")
        lines += [
            "",
            "Use list_tests(category='san_detection') to see tests in a category.",
            "",
            "Test aspects (verification depth):",
        ]
        for aspect in TestAspect:
            lines.append(f"  {aspect.value}")

    return "\n".join(lines)


def tool_proof_positive(
    testcase_id: str,
    run_id: str,
    category: str,
    method: str,
    collect: bool,
    testbed_config: dict,
    config_path: Path,
    artifacts_dir: Path,
) -> str:
    """Run proof-positive test (expect Accept)."""
    run_dir = artifacts_dir / run_id
    started = datetime.now(timezone.utc).isoformat()

    rm = RunMetadata(
        run_type=RunType.PROOF_POSITIVE,
        test_category=_category_enum(category),
        test_aspect=TestAspect.AUTH_DECISION,
        started_at=started,
        pcap_enabled=False,
    )

    bundle = _run_diagnostics_core(
        run_dir=run_dir,
        testcase_id=testcase_id,
        expected_decision=Decision.ACCEPT,
        expected_method=method,
        collect=collect,
        config_path=config_path,
        run_metadata=rm,
    )

    # Save bundle
    out_path = run_dir / "evidence_bundle.json"
    run_dir.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(bundle, indent=2, default=str), encoding="utf-8")

    if bundle.get("functional_pass"):
        return _format_result(bundle)
    else:
        return _format_failure_analysis(bundle)


def tool_negative_test(
    testcase_id: str,
    run_id: str,
    category: str,
    method: str,
    collect: bool,
    testbed_config: dict,
    config_path: Path,
    artifacts_dir: Path,
) -> str:
    """Run negative test (expect Reject)."""
    run_dir = artifacts_dir / run_id
    started = datetime.now(timezone.utc).isoformat()

    rm = RunMetadata(
        run_type=RunType.NEGATIVE_TEST,
        test_category=_category_enum(category),
        test_aspect=TestAspect.AUTH_DECISION,
        started_at=started,
    )

    bundle = _run_diagnostics_core(
        run_dir=run_dir,
        testcase_id=testcase_id,
        expected_decision=Decision.REJECT,
        expected_method=method,
        collect=collect,
        config_path=config_path,
        run_metadata=rm,
    )

    out_path = run_dir / "evidence_bundle.json"
    run_dir.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(bundle, indent=2, default=str), encoding="utf-8")

    if bundle.get("functional_pass"):
        return _format_result(bundle)
    else:
        return _format_failure_analysis(bundle)


def tool_forensic_analyze(
    run_id: str,
    testcase_id: str,
    expected_decision: str,
    method: str,
    testbed_config: dict,
    config_path: Path,
    artifacts_dir: Path,
) -> str:
    """Deep forensic analysis of an existing run directory."""
    run_dir = artifacts_dir / run_id
    if not run_dir.exists():
        return f"ERROR: Run directory not found: {run_dir}"

    rm = RunMetadata(
        run_type=RunType.FORENSIC,
        test_aspect=TestAspect.AUTH_DECISION,
        pcap_enabled=any(run_dir.rglob("*.pcap")) or any(run_dir.rglob("*.pcapng")),
    )

    bundle = _run_diagnostics_core(
        run_dir=run_dir,
        testcase_id=testcase_id,
        expected_decision=_decision_enum(expected_decision),
        expected_method=method,
        collect=False,  # forensic analyses existing data
        config_path=config_path,
        run_metadata=rm,
    )

    out_path = run_dir / "evidence_bundle.json"
    out_path.write_text(json.dumps(bundle, indent=2, default=str), encoding="utf-8")

    result = _format_result(bundle)
    timeline = bundle.get("timeline", [])

    # Add forensic-specific timeline summary
    lines = [result, "", "Key Timeline Events:"]
    shown = 0
    for ev in timeline:
        kind = ev.get("kind", "")
        ts = ev.get("ts", "")
        msg = ev.get("message", "")
        src = ev.get("source", "")
        if any(k in kind for k in (
            "RADIUS_ACCESS", "EAP_", "EAPOL_", "FRAMEWORK_TEST",
            "FRAMEWORK_AUTH", "REDIS_RULE", "IDENTITY_",
        )):
            ts_short = ts[-8:] if len(ts) >= 8 else ts
            lines.append(f"  {ts_short}  {src:16s}  {kind}")
            if msg:
                lines.append(f"  {'':8s}  {'':16s}  {msg[:80]}")
            shown += 1
            if shown >= 15:
                lines.append(f"  ... and {len(timeline) - shown} more events")
                break

    # Diagram info
    mmd_files = list(run_dir.glob("*.mmd"))
    html_files = list(run_dir.glob("*.html"))
    if mmd_files:
        lines += [
            "",
            f"Diagrams: {len(mmd_files)} generated",
        ]
        for h in html_files:
            lines.append(f"  {h.name}")

    return "\n".join(lines)


def tool_stability_probe(
    testcase_id: str,
    iterations: int,
    category: str,
    method: str,
    expected_decision: str,
    testbed_config: dict,
    config_path: Path,
    artifacts_dir: Path,
) -> str:
    """Run a test N times and report stability metrics."""
    decision = _decision_enum(expected_decision)
    results: list[dict] = []
    pass_count = 0

    for i in range(1, iterations + 1):
        run_id = f"{testcase_id}-STAB-{i:03d}"
        run_dir = artifacts_dir / run_id

        rm = RunMetadata(
            run_type=RunType.STABILITY_PROBE,
            test_category=_category_enum(category),
            test_aspect=TestAspect.STATS_AGGREGATE,
            iteration=i,
            total_iterations=iterations,
            parent_run_id=testcase_id,
            started_at=datetime.now(timezone.utc).isoformat(),
        )

        t0 = time.monotonic()
        bundle = _run_diagnostics_core(
            run_dir=run_dir,
            testcase_id=testcase_id,
            expected_decision=decision,
            expected_method=method,
            collect=True,
            config_path=config_path,
            run_metadata=rm,
        )
        elapsed = time.monotonic() - t0

        passed = bundle.get("functional_pass", False)
        if passed:
            pass_count += 1

        results.append({
            "iteration": i,
            "run_id": run_id,
            "observed": bundle.get("observed_decision", "unknown"),
            "confidence": bundle.get("confidence", 0.0),
            "elapsed": round(elapsed, 1),
            "passed": passed,
            "classification": bundle.get("classification", "UNKNOWN"),
        })

        # Save individual bundle
        run_dir.mkdir(parents=True, exist_ok=True)
        (run_dir / "evidence_bundle.json").write_text(
            json.dumps(bundle, indent=2, default=str), encoding="utf-8"
        )

    # Build summary
    pass_rate = pass_count / iterations if iterations > 0 else 0
    confidences = [r["confidence"] for r in results]
    durations = [r["elapsed"] for r in results]

    if pass_rate >= 1.0:
        verdict = "STABLE"
    elif pass_rate >= 0.8:
        verdict = "FLAKY"
    else:
        verdict = "UNSTABLE"

    lines = [
        f"STABILITY RESULT: {verdict} ({pass_count}/{iterations} passed, {pass_rate:.0%})",
        "",
        f"Test Case:  {testcase_id}",
        f"Iterations: {iterations}",
        f"Expected:   {expected_decision}",
        "",
        "Run  | Observed | Confidence | Duration | Result",
        "-----|----------|------------|----------|-------",
    ]

    for r in results:
        status = "PASS" if r["passed"] else "FAIL"
        lines.append(
            f"  {r['iteration']:2d} | {r['observed']:8s} | {r['confidence']:.2f}"
            f"       | {r['elapsed']:5.1f}s   | {status}"
        )

    lines += [
        "",
        f"Confidence range: {min(confidences):.2f} - {max(confidences):.2f}",
        f"Duration range:   {min(durations):.1f}s - {max(durations):.1f}s",
    ]

    # Identify divergence in failed runs
    failed = [r for r in results if not r["passed"]]
    if failed:
        lines += ["", "Failed iterations:"]
        for r in failed:
            lines.append(
                f"  Run {r['iteration']}: {r['observed']} "
                f"(expected {expected_decision}) — see {r['run_id']}/"
            )

    return "\n".join(lines)


def tool_cert_probe(
    radius_ip: str,
    shared_secret: str,
    testbed_config: dict,
    artifacts_dir: Path,
) -> str:
    """Run 3-certificate probe against RADIUS."""
    try:
        from testpulse.tools.eapol_test_runner import run_eapol_test, EapolTestConfig
    except ImportError:
        return "ERROR: eapol_test_runner not available."

    certs = [
        ("good", "Dot1x-CLT-Good", True),
        ("revoked", "Dot1x-CLT-Revoked", False),
        ("expired", "Dot1x-CLT-Expired", False),
    ]

    lines = [
        "3-Certificate RADIUS Probe",
        "",
        f"Target: {radius_ip}",
        "",
        "Cert      | Expected | Observed  | Result",
        "----------|----------|-----------|-------",
    ]

    all_pass = True
    ocsp_gap = False

    for name, identity, expect_success in certs:
        cfg = EapolTestConfig(
            radius_ip=radius_ip,
            shared_secret=shared_secret,
            identity=identity,
            eap_method="TLS",
        )

        try:
            result = run_eapol_test(cfg)
            actual = "Accept" if result.success else "Reject"
            expected = "Accept" if expect_success else "Reject"
            match = result.success == expect_success
            status = "PASS" if match else "FAIL"
            if not match:
                all_pass = False
                if name == "revoked" and result.success:
                    ocsp_gap = True
        except Exception as e:
            actual = f"ERROR: {e}"
            expected = "Accept" if expect_success else "Reject"
            status = "ERROR"
            all_pass = False

        lines.append(f"  {name:8s} | {expected:8s} | {actual:9s} | {status}")

    lines.append("")
    if all_pass:
        lines.append("VERDICT: Appliance healthy — all 3 probes match expectations.")
    elif ocsp_gap:
        lines += [
            "VERDICT: OCSP/CRL gap detected!",
            "",
            "The revoked certificate was ACCEPTED. This means the appliance",
            "is not checking certificate revocation status (OCSP or CRL).",
            "",
            "Action: Enable OCSP or CRL checking in the RADIUS certificate",
            "validation configuration.",
        ]
    else:
        lines.append("VERDICT: One or more probes failed — check details above.")

    return "\n".join(lines)
