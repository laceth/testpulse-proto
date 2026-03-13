"""Parse Forescout identity context artifacts.

Parses three artifact files that are already collected by
``appliance_collector.py``:

1. **fstool_hostinfo_<mac>.txt** — ``fstool hostinfo <mac>`` output::

       10.16.148.129, dot1x_auth_state, (dot1x@3922889344900135729), Access-Accept
       10.16.148.129, dot1x_NAS_addr, (dot1x@3922889344900135729), 10.16.128.15
       10.16.148.129, mac, (eps@...), 288023b82d59

   Each line:  ``<ip>, <property_name>, (<plugin>@<context>), <value>``

2. **local_properties.txt** — ``/usr/local/forescout/plugin/dot1x/local.properties``

   Key-value properties including pre-admission rule conditions::

       config.defpol.size.value=3
       config.defpol_cond1.value=[{...JSON...}]
       config.defpol_auth1.value=vlan:\\tIsCOA:false

3. **fstool_dot1x_status.txt** — ``fstool dot1x status`` output

   Shows process health (radiusd, winbindd, redis-server).
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from testpulse.models import AuthEvent


# --------------------------------------------------------------------------
# fstool hostinfo parser
# --------------------------------------------------------------------------

#  10.16.148.129, dot1x_auth_state, (dot1x@3922889344900135729), Access-Accept
_HOSTINFO_LINE_RE = re.compile(
    r"^(?P<ip>[^,]+),\s*"
    r"(?P<prop>[^,]+),\s*"
    r"\((?P<plugin>[^)]*)\),\s*"
    r"(?P<value>.*)$"
)

# Properties that directly express an auth decision
_AUTH_STATE_PROPS = {
    "dot1x_auth_state",
    "dot1x_host_auth_status",
    "dot1x_user_auth_status",
    "dot1x_mab_auth_status",
}

# Properties carrying identity context
_IDENTITY_PROPS = {
    "dot1x_user", "dot1x_tunneled_user", "dot1x_host",
    "dot1x_domain", "dot1x_rqeuested_domain",
    "dot1x_auth_source", "dot1x_login_type",
    "dot1x_fr_eap_type", "dot1x_auth_appliance",
    "dot1x_NAS_addr", "dot1x_NAS_addr6",
    "dot1x_NASPortIdStr", "dot1x_host_in_mar",
    "dot1x_auth_time",
    "mac", "dhcp_hostname", "dns_name",
    "nbthost", "nbt_domain",
    "prim_classification", "os_classification_source",
    "discovery_score",
}


def parse_hostinfo(text: str, source_file: str = "hostinfo") -> list[AuthEvent]:
    """Parse ``fstool hostinfo <mac>`` output into AuthEvents.

    Produces:
    - **IDENTITY_AUTH_STATE** for auth state properties
    - **IDENTITY_PROPERTY** for identity/classification properties
    - **IDENTITY_HOST_RECORD** summary event with all properties in metadata
    """
    events: list[AuthEvent] = []
    if not text:
        return events

    # Accumulate all properties for the summary event
    all_props: dict[str, str] = {}
    host_ip: str | None = None
    host_mac: str | None = None
    host_username: str | None = None

    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue

        m = _HOSTINFO_LINE_RE.match(line)
        if not m:
            continue

        ip = m.group("ip").strip()
        prop = m.group("prop").strip()
        plugin_ctx = m.group("plugin").strip()
        value = m.group("value").strip()

        all_props[prop] = value
        if not host_ip:
            host_ip = ip

        # Track key identity fields
        if prop == "mac":
            host_mac = value
        elif prop == "dot1x_user":
            host_username = value

        # Emit typed events for important properties
        if prop in _AUTH_STATE_PROPS:
            events.append(AuthEvent(
                ts=all_props.get("dot1x_auth_time"),
                kind="IDENTITY_AUTH_STATE",
                source=source_file,
                message=f"{prop}={value}",
                endpoint_ip=ip,
                endpoint_mac=host_mac,
                username=host_username,
                property_field=prop,
                property_value=value,
                context_id=plugin_ctx,
                metadata={"resolved_by": plugin_ctx},
                raw_line=line,
            ))
        elif prop in _IDENTITY_PROPS:
            events.append(AuthEvent(
                ts=all_props.get("dot1x_auth_time"),
                kind="IDENTITY_PROPERTY",
                source=source_file,
                message=f"{prop}={value}",
                endpoint_ip=ip,
                endpoint_mac=host_mac,
                username=host_username,
                property_field=prop,
                property_value=value,
                context_id=plugin_ctx,
                metadata={"resolved_by": plugin_ctx},
                raw_line=line,
            ))

    # Summary event with all properties in metadata
    if all_props:
        # Extract NAS info if available
        nas_ip = all_props.get("dot1x_NAS_addr") or all_props.get("dot1x_NAS_addr6")
        nas_port_id = all_props.get("dot1x_NASPortIdStr")
        auth_method = all_props.get("dot1x_fr_eap_type")
        eap_type = all_props.get("dot1x_fr_eap_type")
        login_type = all_props.get("dot1x_login_type")

        events.append(AuthEvent(
            ts=all_props.get("dot1x_auth_time"),
            kind="IDENTITY_HOST_RECORD",
            source=source_file,
            message=f"hostinfo: {len(all_props)} properties for {host_ip or 'unknown'}",
            endpoint_ip=host_ip,
            endpoint_mac=host_mac,
            username=host_username,
            nas_ip=nas_ip,
            nas_port_id=nas_port_id,
            auth_method=_normalize_auth_method(auth_method),
            eap_type=eap_type,
            metadata={
                "hostinfo_properties": all_props,
                "login_type": login_type,
                "auth_source": all_props.get("dot1x_auth_source"),
                "domain": all_props.get("dot1x_domain"),
                "requested_domain": all_props.get("dot1x_rqeuested_domain"),
                "dhcp_hostname": all_props.get("dhcp_hostname"),
                "dns_name": all_props.get("dns_name"),
                "nbt_host": all_props.get("nbthost"),
                "nbt_domain": all_props.get("nbt_domain"),
                "classification": all_props.get("prim_classification"),
                "host_in_mar": all_props.get("dot1x_host_in_mar"),
            },
        ))

    return events


def _normalize_auth_method(eap_type: str | None) -> str | None:
    """Map Forescout EAP-Type label to canonical auth_method."""
    if not eap_type:
        return None
    lower = eap_type.strip().lower()
    mapping = {
        "eap-tls": "eap-tls",
        "peap": "peap",
        "peap-eap-tls": "peap-eap-tls",
        "mab": "mab",
        "pap": "pap",
    }
    return mapping.get(lower, lower)


# --------------------------------------------------------------------------
# local.properties parser
# --------------------------------------------------------------------------

_RULE_COND_RE = re.compile(r"^config\.defpol_cond(\d+)\.value=(.+)$")
_RULE_AUTH_RE = re.compile(r"^config\.defpol_auth(\d+)\.value=(.+)$")
_RULE_SIZE_RE = re.compile(r"^config\.defpol\.size\.value=(\d+)$")
_CONFIG_KV_RE = re.compile(r"^config\.(\S+?)\.value=(.*)$")

# Important plugin settings to capture
_PLUGIN_SETTINGS_OF_INTEREST = {
    "ldap_ad_port", "ldap_use_krb5", "ldap_use_machine_account",
    "ldap_sign_and_seal", "localradiusdebug", "localradiusport",
    "localacctport", "enableradsec", "onlyradsec",
    "ocsp", "ocsp_shell", "crl",
    "cache", "enable_pap_authentication",
    "min_tls_version", "fragment_size",
}


def parse_local_properties(text: str, source_file: str = "local_properties") -> list[AuthEvent]:
    """Parse ``local.properties`` for pre-admission rules and plugin configuration.

    Produces:
    - **IDENTITY_RULE_CONDITION** — per-rule condition (parsed JSON)
    - **IDENTITY_RULE_AUTH** — per-rule auth action
    - **IDENTITY_RULE_CONFIG** — summary with rule count + all rules
    - **IDENTITY_PLUGIN_SETTING** — LDAP/TLS/OCSP config values
    """
    events: list[AuthEvent] = []
    if not text:
        return events

    rule_conditions: dict[int, str] = {}
    rule_auths: dict[int, str] = {}
    rule_count: int | None = None
    plugin_settings: dict[str, str] = {}

    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue

        # Rule count
        m = _RULE_SIZE_RE.match(line)
        if m:
            rule_count = int(m.group(1))
            continue

        # Rule conditions
        m = _RULE_COND_RE.match(line)
        if m:
            slot = int(m.group(1))
            raw_cond = m.group(2)
            rule_conditions[slot] = raw_cond

            # Try to extract criteria names from JSON
            criteria_names = _extract_criteria_names(raw_cond)
            events.append(AuthEvent(
                ts=None,
                kind="IDENTITY_RULE_CONDITION",
                source=source_file,
                message=f"rule_{slot} condition: {criteria_names or raw_cond[:120]}",
                metadata={
                    "rule_slot": slot,
                    "condition_raw": raw_cond,
                    "criteria_names": criteria_names,
                },
                raw_line=line,
            ))
            continue

        # Rule auth actions
        m = _RULE_AUTH_RE.match(line)
        if m:
            slot = int(m.group(1))
            auth_val = m.group(2)
            rule_auths[slot] = auth_val

            from testpulse.ingest.redis_parser import _interpret_auth_value
            action = _interpret_auth_value(auth_val)

            events.append(AuthEvent(
                ts=None,
                kind="IDENTITY_RULE_AUTH",
                source=source_file,
                message=f"rule_{slot} auth: {auth_val} ({action})",
                metadata={
                    "rule_slot": slot,
                    "auth_value": auth_val,
                    "auth_action": action,
                },
                raw_line=line,
            ))
            continue

        # Plugin settings
        m = _CONFIG_KV_RE.match(line)
        if m:
            key = m.group(1)
            val = m.group(2)
            if key in _PLUGIN_SETTINGS_OF_INTEREST:
                plugin_settings[key] = val
                events.append(AuthEvent(
                    ts=None,
                    kind="IDENTITY_PLUGIN_SETTING",
                    source=source_file,
                    message=f"config.{key}={val}",
                    metadata={"setting_key": key, "setting_value": val},
                    raw_line=line,
                ))

    # Summary event with full rule config
    if rule_conditions or rule_auths:
        rules_summary = []
        max_slot = max(
            max(rule_conditions.keys(), default=0),
            max(rule_auths.keys(), default=0),
        )
        for s in range(1, max_slot + 1):
            rules_summary.append({
                "slot": s,
                "condition": rule_conditions.get(s, ""),
                "auth": rule_auths.get(s, ""),
            })

        events.append(AuthEvent(
            ts=None,
            kind="IDENTITY_RULE_CONFIG",
            source=source_file,
            message=f"{rule_count or len(rules_summary)} pre-admission rules configured",
            metadata={
                "rule_count": rule_count,
                "rules": rules_summary,
                "plugin_settings": plugin_settings,
            },
        ))

    return events


def _extract_criteria_names(raw_json: str) -> list[str]:
    """Best-effort extract criterion 'field' names from condition JSON."""
    try:
        parsed = json.loads(raw_json)
        if isinstance(parsed, list):
            return [c.get("field", "?") for c in parsed if isinstance(c, dict)]
    except (json.JSONDecodeError, TypeError):
        pass
    # Fallback: regex extraction
    return re.findall(r'"field"\s*:\s*"([^"]+)"', raw_json)


# --------------------------------------------------------------------------
# fstool dot1x status parser
# --------------------------------------------------------------------------

_PROCESS_RE = re.compile(
    r"^\s*(?P<name>\S+)\s+(?:is\s+)?(?P<status>running|stopped|not running|dead)"
    r"(?:\s*\(pid\s+(?P<pid>\d+)\))?",
    re.IGNORECASE,
)


def parse_fstool_status(text: str, source_file: str = "fstool_status") -> list[AuthEvent]:
    """Parse ``fstool dot1x status`` for process health.

    Produces:
    - **IDENTITY_PROCESS_STATUS** — one per process (radiusd, winbindd, redis-server)
    - **IDENTITY_DOT1X_STATUS** — summary with all process states
    """
    events: list[AuthEvent] = []
    if not text:
        return events

    processes: dict[str, dict] = {}

    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue

        m = _PROCESS_RE.match(line)
        if m:
            name = m.group("name")
            status = m.group("status").lower()
            pid = int(m.group("pid")) if m.group("pid") else None
            is_running = status == "running"

            processes[name] = {"status": status, "pid": pid, "running": is_running}

            events.append(AuthEvent(
                ts=None,
                kind="IDENTITY_PROCESS_STATUS",
                source=source_file,
                message=f"{name}: {status}" + (f" (pid {pid})" if pid else ""),
                pid=pid,
                metadata={
                    "process_name": name,
                    "process_status": status,
                    "process_running": is_running,
                },
                raw_line=line,
            ))

    # Summary
    if processes:
        all_healthy = all(p["running"] for p in processes.values())
        events.append(AuthEvent(
            ts=None,
            kind="IDENTITY_DOT1X_STATUS",
            source=source_file,
            message=f"dot1x status: {'healthy' if all_healthy else 'DEGRADED'} "
                    f"({len(processes)} processes)",
            metadata={
                "processes": processes,
                "all_healthy": all_healthy,
            },
        ))

    return events


# =========================================================================
# Public API — parse all identity artifacts from a run directory
# =========================================================================

def parse_identity(run_dir_path: str) -> list[AuthEvent]:
    """Parse all identity-context artifacts from a run directory.

    Looks for:
    - ``fstool_hostinfo_*.txt`` (glob — may be multiple MACs)
    - ``local_properties.txt``
    - ``fstool_dot1x_status.txt``
    """
    events: list[AuthEvent] = []
    run_dir = Path(run_dir_path)

    # Hostinfo files (may have multiple MACs)
    for hi_file in sorted(run_dir.glob("fstool_hostinfo_*.txt")):
        text = hi_file.read_text(encoding="utf-8", errors="ignore")
        events.extend(parse_hostinfo(text, source_file=hi_file.name))

    # local.properties
    lp = run_dir / "local_properties.txt"
    if lp.exists():
        events.extend(
            parse_local_properties(lp.read_text(encoding="utf-8", errors="ignore"))
        )

    # fstool dot1x status
    status = run_dir / "fstool_dot1x_status.txt"
    if status.exists():
        events.extend(
            parse_fstool_status(status.read_text(encoding="utf-8", errors="ignore"))
        )

    return events
