"""TestPulse MCP Server — exposes diagnostic tools to Copilot via MCP.

Provides five tools that map to the five testing scenarios:

1. ``proof_positive``   — run a test, expect Accept
2. ``negative_test``    — run a test, expect Reject
3. ``forensic_analyze`` — deep analysis with pcap + 6 diagrams
4. ``stability_probe``  — run N times and report flakiness
5. ``cert_probe``       — 3-cert sweep (good/revoked/expired)

Launch::

    python -m testpulse.mcp.server

Or via VS Code MCP configuration in ``.vscode/settings.json``.
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

from mcp.server.fastmcp import FastMCP

from testpulse.mcp.tools import (
    tool_cert_probe,
    tool_forensic_analyze,
    tool_negative_test,
    tool_proof_positive,
    tool_stability_probe,
    tool_status,
    tool_list_tests,
)

# ---------------------------------------------------------------------------
# Server instance
# ---------------------------------------------------------------------------

mcp = FastMCP(
    "testpulse",
    instructions=(
        "TestPulse 802.1X diagnostic toolkit (v0.3.0) — run tests, collect "
        "evidence, generate diagrams, and analyse RADIUS/dot1x authentication flows."
    ),
)

# ---------------------------------------------------------------------------
# Configuration from environment
# ---------------------------------------------------------------------------

_CONFIG_PATH = Path(os.environ.get("TESTPULSE_CONFIG", "radius.yaml"))
_ARTIFACTS_DIR = Path(os.environ.get("TESTPULSE_ARTIFACTS", "artifacts"))


def _load_testbed_config() -> dict:
    """Load the testbed YAML configuration."""
    if not _CONFIG_PATH.exists():
        return {}
    try:
        import yaml
        with open(_CONFIG_PATH) as fh:
            return yaml.safe_load(fh) or {}
    except Exception:
        return {}


# ---------------------------------------------------------------------------
# Register tools
# ---------------------------------------------------------------------------

@mcp.tool()
def status() -> str:
    """Show testbed connection status and available test categories."""
    cfg = _load_testbed_config()
    return tool_status(cfg, _CONFIG_PATH, _ARTIFACTS_DIR)


@mcp.tool()
def list_tests(category: str = "") -> str:
    """List available test cases, optionally filtered by category.

    Args:
        category: Filter by TestCategory value (e.g. "san_detection",
                  "eap_tls", "pre_admission"). Empty = show all.
    """
    return tool_list_tests(category)


@mcp.tool()
def proof_positive(
    testcase_id: str,
    run_id: str = "",
    category: str = "eap_tls",
    method: str = "eap-tls",
    collect: bool = True,
) -> str:
    """Run a test and verify the appliance returns Access-Accept.

    This is the happy-path validation — confirm the system accepts
    what it should accept.

    Args:
        testcase_id: Test case identifier (e.g. "TP-EAPTLS-SAN-001").
        run_id: Run directory name. Defaults to testcase_id.
        category: TestCategory value (e.g. "san_detection", "eap_tls").
        method: Expected auth method (eap-tls, peap, mab).
        collect: Whether to collect logs from appliance before analysis.
    """
    cfg = _load_testbed_config()
    return tool_proof_positive(
        testcase_id=testcase_id,
        run_id=run_id or testcase_id,
        category=category,
        method=method,
        collect=collect,
        testbed_config=cfg,
        config_path=_CONFIG_PATH,
        artifacts_dir=_ARTIFACTS_DIR,
    )


@mcp.tool()
def negative_test(
    testcase_id: str,
    run_id: str = "",
    category: str = "eap_tls",
    method: str = "eap-tls",
    collect: bool = True,
) -> str:
    """Run a test and verify the appliance returns Access-Reject.

    This is the negative validation — confirm the system rejects
    what it should reject (e.g. revoked cert, expired cert, SAN mismatch).

    Args:
        testcase_id: Test case identifier (e.g. "TP-EAPTLS-SAN-004").
        run_id: Run directory name. Defaults to testcase_id.
        category: TestCategory value (e.g. "ocsp_crl", "cert_expiry").
        method: Expected auth method.
        collect: Whether to collect logs from appliance before analysis.
    """
    cfg = _load_testbed_config()
    return tool_negative_test(
        testcase_id=testcase_id,
        run_id=run_id or testcase_id,
        category=category,
        method=method,
        collect=collect,
        testbed_config=cfg,
        config_path=_CONFIG_PATH,
        artifacts_dir=_ARTIFACTS_DIR,
    )


@mcp.tool()
def forensic_analyze(
    run_id: str,
    testcase_id: str = "",
    expected_decision: str = "accept",
    method: str = "eap-tls",
) -> str:
    """Deep forensic analysis of an existing run with full evidence.

    Parses all available logs, pcap files, and artifacts in the run
    directory. Generates 6 diagrams + dashboard. Returns timeline,
    root cause candidates, and detective clues.

    Args:
        run_id: Run directory name under artifacts/ to analyse.
        testcase_id: Optional test case ID override.
        expected_decision: What the test expected (accept/reject).
        method: Expected auth method.
    """
    cfg = _load_testbed_config()
    return tool_forensic_analyze(
        run_id=run_id,
        testcase_id=testcase_id or run_id,
        expected_decision=expected_decision,
        method=method,
        testbed_config=cfg,
        config_path=_CONFIG_PATH,
        artifacts_dir=_ARTIFACTS_DIR,
    )


@mcp.tool()
def stability_probe(
    testcase_id: str,
    iterations: int = 5,
    category: str = "eap_tls",
    method: str = "eap-tls",
    expected_decision: str = "accept",
) -> str:
    """Run a test N times and report stability metrics.

    Detects flakiness by comparing results across iterations.
    Reports pass rate, confidence range, latency variance, and
    identifies the divergence point in any failing run.

    Args:
        testcase_id: Test case to repeat.
        iterations: Number of times to run (default 5).
        category: TestCategory value.
        method: Expected auth method.
        expected_decision: Expected result per iteration (accept/reject).
    """
    cfg = _load_testbed_config()
    return tool_stability_probe(
        testcase_id=testcase_id,
        iterations=iterations,
        category=category,
        method=method,
        expected_decision=expected_decision,
        testbed_config=cfg,
        config_path=_CONFIG_PATH,
        artifacts_dir=_ARTIFACTS_DIR,
    )


@mcp.tool()
def cert_probe(
    radius_ip: str = "",
    shared_secret: str = "testing123",
) -> str:
    """Run a 3-certificate probe against RADIUS (good/revoked/expired).

    No fstester or switch required — directly probes the RADIUS server
    using eapol_test with three controlled certificates to validate
    certificate acceptance and revocation enforcement.

    Args:
        radius_ip: RADIUS server IP. Defaults to testbed ca.ip.
        shared_secret: RADIUS shared secret.
    """
    cfg = _load_testbed_config()
    ip = radius_ip or cfg.get("ca", {}).get("ip", "")
    if not ip:
        return "ERROR: No RADIUS IP. Set radius_ip or configure ca.ip in radius.yaml."
    return tool_cert_probe(
        radius_ip=ip,
        shared_secret=shared_secret,
        testbed_config=cfg,
        artifacts_dir=_ARTIFACTS_DIR,
    )


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main():
    """Run the TestPulse MCP server."""
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
