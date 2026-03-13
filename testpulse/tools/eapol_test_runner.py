"""Run ``eapol_test`` against a RADIUS server and parse the results.

``eapol_test`` is a debugging utility from the hostapd project that lets
you probe a RADIUS authenticator from the command line without a real
802.1X supplicant/switch.  It is commonly used to verify FreeRADIUS
health and EAP configuration.

This module:

1. Generates a temporary ``eapol_test`` configuration file from supplied
   parameters (identity, EAP type, certificates, shared secret, etc.).
2. Invokes ``eapol_test -c <conf> -s <secret> -a <server>`` as a subprocess.
3. Parses stdout/stderr for ``SUCCESS`` / ``FAILURE`` and timing data.
4. Returns a structured :class:`EapolTestResult`.

Usage::

    from testpulse.tools.eapol_test_runner import run_eapol_test, EapolTestConfig

    cfg = EapolTestConfig(
        radius_ip="10.100.49.87",
        shared_secret="testing123",
        identity="testuser",
        eap_method="PEAP",
    )
    result = run_eapol_test(cfg)
    print(result.success, result.elapsed_sec)
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class EapolTestConfig:
    """Configuration for an ``eapol_test`` probe."""

    # RADIUS target
    radius_ip: str = "127.0.0.1"
    radius_port: int = 1812
    shared_secret: str = "testing123"

    # Identity
    identity: str = "anonymous"
    password: str = ""

    # EAP method: TLS | PEAP | TTLS | MD5 | MSCHAPV2
    eap_method: str = "PEAP"

    # Certificates (for EAP-TLS / PEAP / TTLS)
    ca_cert: str | None = None
    client_cert: str | None = None
    private_key: str | None = None
    private_key_passwd: str = ""

    # PEAP inner
    phase2: str = "auth=MSCHAPV2"

    # Misc
    timeout: int = 30  # seconds
    extra_lines: list[str] = field(default_factory=list)


@dataclass
class EapolTestResult:
    """Structured output from an ``eapol_test`` invocation."""

    success: bool
    exit_code: int
    elapsed_sec: float
    stdout: str
    stderr: str
    eap_method: str
    radius_ip: str
    # Parsed details
    eap_type_offered: str | None = None
    eap_state: str | None = None
    error_message: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# EAP method → wpa_supplicant numeric code
# ---------------------------------------------------------------------------
_EAP_METHOD_MAP = {
    "TLS": 13,
    "PEAP": 25,
    "TTLS": 21,
    "MD5": 4,
    "MSCHAPV2": 26,
    "FAST": 43,
}


def _generate_conf(cfg: EapolTestConfig) -> str:
    """Build an ``eapol_test`` configuration string."""
    eap_num = _EAP_METHOD_MAP.get(cfg.eap_method.upper(), 25)
    lines = [
        "network={",
        f'    ssid="radius-test"',
        "    key_mgmt=IEEE8021X",
        f"    eap={cfg.eap_method.upper()}",
        f'    identity="{cfg.identity}"',
    ]

    method = cfg.eap_method.upper()

    if method in ("PEAP", "TTLS"):
        lines.append(f'    password="{cfg.password}"')
        lines.append(f'    phase2="{cfg.phase2}"')
        if cfg.ca_cert:
            lines.append(f'    ca_cert="{cfg.ca_cert}"')

    elif method == "TLS":
        if cfg.ca_cert:
            lines.append(f'    ca_cert="{cfg.ca_cert}"')
        if cfg.client_cert:
            lines.append(f'    client_cert="{cfg.client_cert}"')
        if cfg.private_key:
            lines.append(f'    private_key="{cfg.private_key}"')
        if cfg.private_key_passwd:
            lines.append(f'    private_key_passwd="{cfg.private_key_passwd}"')

    elif method == "MD5":
        lines.append(f'    password="{cfg.password}"')

    elif method == "MSCHAPV2":
        lines.append(f'    password="{cfg.password}"')

    for extra in cfg.extra_lines:
        lines.append(f"    {extra}")

    lines.append("}")
    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# Output parsing
# ---------------------------------------------------------------------------
_SUCCESS_RE = re.compile(r"SUCCESS", re.IGNORECASE)
_FAILURE_RE = re.compile(r"FAILURE", re.IGNORECASE)
_EAP_TYPE_RE = re.compile(r"selectedMethod=(\d+)\s+\(EAP-([^)]+)\)", re.IGNORECASE)
_EAP_STATE_RE = re.compile(r"EAP state:\s+(\S+)", re.IGNORECASE)
_TIMEOUT_RE = re.compile(r"EAPOL test timed out|Timeout", re.IGNORECASE)


def _parse_output(stdout: str, stderr: str) -> dict[str, Any]:
    """Extract structured info from eapol_test output."""
    combined = stdout + "\n" + stderr
    info: dict[str, Any] = {}

    m = _EAP_TYPE_RE.search(combined)
    if m:
        info["eap_type_offered"] = m.group(2)

    m = _EAP_STATE_RE.search(combined)
    if m:
        info["eap_state"] = m.group(1)

    if _SUCCESS_RE.search(combined):
        info["success"] = True
    elif _FAILURE_RE.search(combined):
        info["success"] = False
        # Try to find error context
        for line in combined.splitlines():
            if "error" in line.lower() or "fail" in line.lower():
                info.setdefault("error_message", line.strip())
                break
    elif _TIMEOUT_RE.search(combined):
        info["success"] = False
        info["error_message"] = "eapol_test timed out"

    return info


# ===================================================================
# Main entry point
# ===================================================================
def run_eapol_test(cfg: EapolTestConfig) -> EapolTestResult:
    """Execute ``eapol_test`` and return structured results.

    Raises
    ------
    FileNotFoundError
        If ``eapol_test`` binary is not found on ``$PATH``.
    """
    eapol_bin = shutil.which("eapol_test")
    if eapol_bin is None:
        raise FileNotFoundError(
            "eapol_test not found. Install wpa_supplicant or build eapol_test "
            "from hostapd source: https://w1.fi/hostapd/"
        )

    conf_text = _generate_conf(cfg)

    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".conf", prefix="eapol_test_", delete=False
    ) as tmp:
        tmp.write(conf_text)
        conf_path = tmp.name

    cmd = [
        eapol_bin,
        "-c", conf_path,
        "-a", cfg.radius_ip,
        "-p", str(cfg.radius_port),
        "-s", cfg.shared_secret,
        "-t", str(cfg.timeout),
    ]

    start = time.monotonic()
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=cfg.timeout + 10,
        )
        elapsed = time.monotonic() - start
        stdout = proc.stdout
        stderr = proc.stderr
        exit_code = proc.returncode
    except subprocess.TimeoutExpired:
        elapsed = time.monotonic() - start
        stdout = ""
        stderr = "eapol_test subprocess timed out"
        exit_code = -1
    finally:
        try:
            os.unlink(conf_path)
        except OSError:
            pass

    parsed = _parse_output(stdout, stderr)

    return EapolTestResult(
        success=parsed.get("success", exit_code == 0),
        exit_code=exit_code,
        elapsed_sec=round(elapsed, 3),
        stdout=stdout,
        stderr=stderr,
        eap_method=cfg.eap_method,
        radius_ip=cfg.radius_ip,
        eap_type_offered=parsed.get("eap_type_offered"),
        eap_state=parsed.get("eap_state"),
        error_message=parsed.get("error_message"),
    )


def generate_config_only(cfg: EapolTestConfig) -> str:
    """Return the eapol_test config without running anything.

    Useful for debugging or saving the config to a file for manual testing.
    """
    return _generate_conf(cfg)
