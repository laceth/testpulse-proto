"""Parse collected Windows endpoint artifacts for auth-flow evidence.

The ``EndpointArtifactCollector`` extracts files into ``<run_dir>/endpoint/``.
This parser reads the text artifacts and produces ``AuthEvent`` objects:

Parsed files
~~~~~~~~~~~~
* ``endpoint_metadata.json``  — run context (computer name, user, timestamp)
* ``ipconfig_all.txt``        — NIC config, IP, MAC
* ``netsh_lan_show_profiles.txt`` — wired 802.1X profile list
* ``netsh_lan_profile_*.txt``     — selected profile dump (auth method)
* ``wired_autoconfig_operational.evtx``  — (binary, logged but not parsed v1)
* ``cert_store_user_my.txt``   — user cert store (EAP-TLS evidence)
* ``cert_store_machine_my.txt`` — machine cert store
* ``collector_warnings.txt``   — warnings from collection run
"""
from __future__ import annotations

import json
import re
from pathlib import Path

from testpulse.models import AuthEvent

# -- Pattern: MAC from ipconfig output  "Physical Address. . . : 28-80-23-B8-2D-59"
IPCONFIG_MAC = re.compile(
    r"Physical Address[\s.]*:\s*(?P<mac>[0-9A-Fa-f]{2}(?:-[0-9A-Fa-f]{2}){5})",
)
# IPv4 from ipconfig
IPCONFIG_IPV4 = re.compile(
    r"IPv4 Address[\s.]*:\s*(?P<ip>\d{1,3}(?:\.\d{1,3}){3})",
)
# LAN profile authentication type
LAN_AUTH_TYPE = re.compile(
    r"(?:authentication|EAP\s+Type|authMode)\s*[=:]\s*(?P<method>\S+)",
    re.IGNORECASE,
)
# Certificate subject CN
CERT_CN = re.compile(r"CN\s*=\s*(?P<cn>[^,\r\n]+)", re.IGNORECASE)
# Certificate serial
CERT_SERIAL = re.compile(r"Serial(?:\s+Number)?[\s:]*(?P<serial>[0-9a-fA-F]+)", re.IGNORECASE)

# wired autoconfig profile name in netsh output
WIRED_PROFILE = re.compile(
    r"All User Profile\s*:\s*(?P<name>.+)",
    re.IGNORECASE,
)

# wired autoconfig "authentication" lines in profile dump
WIRED_AUTH_METHOD = re.compile(
    r"(?:EAP Type|authMode|Authentication)\s*:\s*(?P<val>.+)",
    re.IGNORECASE,
)


def parse_endpoint_artifacts(endpoint_dir: str | Path) -> list[AuthEvent]:
    """Parse the endpoint artifact directory and return AuthEvents.

    Args:
        endpoint_dir: Path to ``<run_dir>/endpoint/`` directory.

    Returns:
        List of AuthEvents extracted from the endpoint artifacts.
    """
    endpoint_dir = Path(endpoint_dir)
    if not endpoint_dir.is_dir():
        return []

    events: list[AuthEvent] = []

    # -- endpoint_metadata.json
    meta_path = _find_file(endpoint_dir, "endpoint_metadata.json")
    if meta_path:
        events.extend(_parse_metadata(meta_path))

    # -- ipconfig_all.txt
    ipconfig_path = _find_file(endpoint_dir, "ipconfig_all.txt")
    if ipconfig_path:
        events.extend(_parse_ipconfig(ipconfig_path))

    # -- netsh lan show profiles
    profiles_path = _find_file(endpoint_dir, "netsh_lan_show_profiles.txt")
    if profiles_path:
        events.extend(_parse_netsh_profiles(profiles_path))

    # -- netsh lan profile detail (selected)
    for profile_file in sorted(endpoint_dir.rglob("netsh_lan_profile_*.txt")):
        if profile_file.name == "netsh_lan_profile_selected.txt":
            continue  # just contains the name
        events.extend(_parse_netsh_profile_detail(profile_file))

    # -- Certificate stores
    for cert_file in sorted(endpoint_dir.rglob("cert_store_*.txt")):
        events.extend(_parse_cert_store(cert_file))

    # -- collector_warnings.txt (informational)
    warn_path = _find_file(endpoint_dir, "collector_warnings.txt")
    if warn_path:
        events.extend(_parse_warnings(warn_path))

    return events


def _find_file(base: Path, name: str) -> Path | None:
    """Find a file by name recursively under base."""
    matches = list(base.rglob(name))
    return matches[0] if matches else None


def _parse_metadata(path: Path) -> list[AuthEvent]:
    """Parse endpoint_metadata.json."""
    try:
        data = json.loads(path.read_text(encoding="utf-8", errors="ignore"))
    except (json.JSONDecodeError, OSError):
        return []

    return [
        AuthEvent(
            ts=data.get("collected_at_local"),
            kind="ENDPOINT_METADATA",
            source="endpoint/endpoint_metadata.json",
            message=f"computer={data.get('computer')}, user={data.get('user')}, run_id={data.get('run_id')}",
            machine_name=data.get("computer"),
            run_id=data.get("run_id"),
            raw_line=json.dumps(data),
        )
    ]


def _parse_ipconfig(path: Path) -> list[AuthEvent]:
    """Parse ipconfig_all.txt for NIC MAC and IPv4 addresses."""
    text = path.read_text(encoding="utf-8", errors="ignore")
    events: list[AuthEvent] = []

    # Extract all MAC + IP pairs
    macs = IPCONFIG_MAC.findall(text)
    ips = IPCONFIG_IPV4.findall(text)

    for i, mac in enumerate(macs):
        ip_addr = ips[i] if i < len(ips) else None
        events.append(
            AuthEvent(
                ts=None,
                kind="ENDPOINT_NIC_INFO",
                source="endpoint/ipconfig_all.txt",
                message=f"NIC mac={mac}" + (f", ip={ip_addr}" if ip_addr else ""),
                endpoint_mac=mac,
                endpoint_ip=ip_addr,
                raw_line=f"MAC={mac}, IP={ip_addr}",
            )
        )

    return events


def _parse_netsh_profiles(path: Path) -> list[AuthEvent]:
    """Parse netsh lan show profiles output."""
    text = path.read_text(encoding="utf-8", errors="ignore")
    events: list[AuthEvent] = []

    for m in WIRED_PROFILE.finditer(text):
        events.append(
            AuthEvent(
                ts=None,
                kind="ENDPOINT_WIRED_PROFILE",
                source="endpoint/netsh_lan_show_profiles.txt",
                message=f"wired_profile={m.group('name').strip()}",
                raw_line=m.group(0),
            )
        )

    return events


def _parse_netsh_profile_detail(path: Path) -> list[AuthEvent]:
    """Parse a specific netsh lan profile dump for auth method."""
    text = path.read_text(encoding="utf-8", errors="ignore")
    events: list[AuthEvent] = []

    for m in WIRED_AUTH_METHOD.finditer(text):
        events.append(
            AuthEvent(
                ts=None,
                kind="ENDPOINT_WIRED_AUTH_CONFIG",
                source=f"endpoint/{path.name}",
                message=f"auth_config: {m.group(0).strip()}",
                raw_line=m.group(0),
            )
        )

    return events


def _parse_cert_store(path: Path) -> list[AuthEvent]:
    """Parse certificate store dump for CN and serial info."""
    text = path.read_text(encoding="utf-8", errors="ignore")
    events: list[AuthEvent] = []

    cns = CERT_CN.findall(text)
    serials = CERT_SERIAL.findall(text)

    for i, cn in enumerate(cns):
        serial = serials[i] if i < len(serials) else None
        events.append(
            AuthEvent(
                ts=None,
                kind="ENDPOINT_CERT_INFO",
                source=f"endpoint/{path.name}",
                message=f"cert CN={cn.strip()}" + (f", serial={serial}" if serial else ""),
                raw_line=f"CN={cn}, serial={serial}",
            )
        )

    return events


def _parse_warnings(path: Path) -> list[AuthEvent]:
    """Parse collector warnings for any collection failures."""
    text = path.read_text(encoding="utf-8", errors="ignore")
    events: list[AuthEvent] = []

    for line in text.splitlines():
        line = line.strip()
        if line.startswith("[WARN]"):
            events.append(
                AuthEvent(
                    ts=None,
                    kind="ENDPOINT_COLLECTOR_WARNING",
                    source="endpoint/collector_warnings.txt",
                    message=line,
                    raw_line=line,
                )
            )

    return events
