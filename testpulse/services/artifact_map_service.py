from __future__ import annotations

from pathlib import Path
from typing import Iterable

from testpulse.models import AuthEvent


NODE_NAMES = (
    "endpoint_supplicant",
    "dhcp",
    "dns",
    "tcpip_relay",
    "ad_ldap",
    "radius",
    "nas_authorization",
    "tomahawk",
    "coa",
    "ntp",
    "evidence_bundle",
)


def build_artifact_map(run_dir: Path, events: Iterable[AuthEvent] | None = None) -> dict[str, object]:
    rel_files = [str(p.relative_to(run_dir)) for p in run_dir.rglob("*") if p.is_file()]
    nodes: dict[str, list[str]] = {name: [] for name in NODE_NAMES}

    for rel in rel_files:
        lower = rel.lower()
        if any(k in lower for k in ("framework.log", "dot1x", "wired_autoconfig", "endpoint/")):
            _append(nodes["endpoint_supplicant"], rel)
        if any(k in lower for k in ("ipconfig", "route", "arp", "dhcp")):
            _append(nodes["dhcp"], rel)
        if any(k in lower for k in ("nslookup", "dig", "dns")):
            _append(nodes["dns"], rel)
        if any(k in lower for k in ("relay", "iphelper", "ip_helper", "helper-address", "tcpip")):
            _append(nodes["tcpip_relay"], rel)
        if any(k in lower for k in ("hostinfo", "local_properties", "ldap", "directory")):
            _append(nodes["ad_ldap"], rel)
        if any(k in lower for k in ("radiusd", "pcap", "pcapng")):
            _append(nodes["radius"], rel)
        if any(k in lower for k in ("show_auth", "auth_session", "vlan", "acl")):
            _append(nodes["nas_authorization"], rel)
        if any(k in lower for k in ("tomahawk", "fabric", "asic")):
            _append(nodes["tomahawk"], rel)
        if any(k in lower for k in ("coa", "switch_syslog", "syslog")):
            _append(nodes["coa"], rel)
        if any(k in lower for k in ("w32tm", "chrony", "ntp", "timedatectl", "show_clock")):
            _append(nodes["ntp"], rel)
        if rel.endswith("evidence_bundle.json"):
            _append(nodes["evidence_bundle"], rel)

    for ev in events or []:
        src = ev.source.lower()
        if "radius" in src:
            _append(nodes["radius"], ev.source)
        if "endpoint" in src or "framework" in src or "dot1x" in src:
            _append(nodes["endpoint_supplicant"], ev.source)
        if ev.dhcp_hostname or ev.endpoint_ip:
            _append(nodes["dhcp"], ev.source)
        if ev.dns_name:
            _append(nodes["dns"], ev.source)
        if any(term in str(ev.source).lower() or term in str(ev.message).lower() for term in ("relay", "iphelper", "helper-address", "tcpip")) or ev.metadata.get("relay"):
            _append(nodes["tcpip_relay"], ev.source)
        if ev.domain or ev.login_type or ev.kind.startswith("IDENTITY_"):
            _append(nodes["ad_ldap"], ev.source)
        if ev.nas_ip or ev.nas_port or ev.nas_port_id:
            _append(nodes["nas_authorization"], ev.source)
        if "tomahawk" in str(ev.source).lower() or "tomahawk" in str(ev.message).lower() or str(ev.metadata.get("platform", "")).lower().find("tomahawk") >= 0:
            _append(nodes["tomahawk"], ev.source)
        if "COA" in ev.kind or ev.metadata.get("coa"):
            _append(nodes["coa"], ev.source)

    return {"run_id": run_dir.name, "nodes": nodes}


def artifacts_for_node(artifact_map: dict[str, object], node_id: str) -> list[str]:
    nodes = artifact_map.get("nodes", {}) if isinstance(artifact_map, dict) else {}
    value = nodes.get(node_id, []) if isinstance(nodes, dict) else []
    return list(value) if isinstance(value, list) else []


def _append(values: list[str], value: str) -> None:
    if value and value not in values:
        values.append(value)
