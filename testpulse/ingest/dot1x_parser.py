"""Parse Forescout dot1x plugin log (dot1x.log) with full metadata extraction.

Real log format::

    dot1x:PID:EPOCH:Day Mon DD HH:MM:SS [TZ [-OFFSET]] YYYY: <message>

Examples::

    dot1x:6152:1773328419.574368:Thu Mar 12 10:13:39 2026: Stopping bundled Free-Radius...
    dot1x:20157:1773328433.753399:Thu Mar 12 10:13:53 CDT -0500 2026: Started: version: 4.8.6-48060050 ...
    dot1x:20157:1773328433.865199:Thu Mar 12 10:13:53 2026: ... ===== Started; Policy-Enabled=1 =====
    dot1x:20157:1773328433.869951:Thu Mar 12 10:13:53 2026: mar module has started. listening...
    dot1x:20157:1773328434.725600:Thu Mar 12 10:13:54 2026: disconnect module has started. listening...
    dot1x:20157:1773328441.499580:Thu Mar 12 10:14:01 2026: ... Loading complete (for 0 proxies)

Policy config structures appear as Perl hash dumps::

    'selected' => 'PEAP'
    'field' => 'EAP-Type'
    'restrict' => 'vlan: IsCOA:false'

Events extracted:

* Process lifecycle: start/stop/restart of radiusd and plugin
* Module starts: MAR, disconnect
* Plugin metadata: version, policy state, loading status
* Policy config: EAP-Type selection, VLAN/COA rules
* MAR device loads
* MAB rule configuration
"""
from __future__ import annotations

import re
from typing import Any
from testpulse.models import AuthEvent

# ---------------------------------------------------------------------------
# Timestamp / prefix: ``dot1x:PID:EPOCH:Day Mon DD HH:MM:SS [TZ [-OFF]] YYYY:``
# ---------------------------------------------------------------------------
PREFIX = re.compile(
    r"dot1x:(?P<pid>\d+):(?P<epoch>\d+(?:\.\d+)?):"
    r"(?P<ts>[A-Z][a-z]{2}\s+[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}"
    r"(?:\s+[A-Z]{2,5}(?:\s+[+-]\d{4})?)?\s+\d{4}):"
)

# Fallback ISO (for mixed-format files)
TS_ISO = re.compile(r"(?P<ts>\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?)")

MAC = re.compile(r"(?P<mac>(?:[0-9A-Fa-f]{2}[:.-]){5}[0-9A-Fa-f]{2})")
SESSION = re.compile(r"(?:Acct-Session-Id|session id)\s*[=:]\s*(?P<sid>[^\s,;]+)", re.IGNORECASE)

# ---------------------------------------------------------------------------
# Process lifecycle events
# ---------------------------------------------------------------------------
RADIUSD_STOP = re.compile(r"Stopping bundled Free-Radius", re.IGNORECASE)
RADIUSD_STARTED = re.compile(r"Started:\s*version:\s*(?P<version>[\d.]+(?:-\d+)?)", re.IGNORECASE)
PLUGIN_STOPPED = re.compile(r"Plugin stopped", re.IGNORECASE)
PLUGIN_STOP_MSG = re.compile(r"Handling stop message\s+(?P<msg>\S+)", re.IGNORECASE)
REDIS_FLUSH = re.compile(r"flushing Redis DB", re.IGNORECASE)
RESTART_FREERADIUS = re.compile(r"Restart(?:ing)?\s+FreeRadius", re.IGNORECASE)

# Module starts
MAR_MODULE = re.compile(r"mar module has started", re.IGNORECASE)
DISCONNECT_MODULE = re.compile(r"disconnect module has started", re.IGNORECASE)

# Loading / policy
LOADING_COMPLETE = re.compile(r"Loading complete\s*\(for\s+(?P<proxies>\d+)\s+prox", re.IGNORECASE)
POLICY_ENABLED = re.compile(r"Policy-Enabled=(?P<enabled>[01])", re.IGNORECASE)

# radiusd process status (legacy pattern)
RADIUSD_STATUS = re.compile(r"radiusd process\s*-\s*(?P<status>running|not running)", re.IGNORECASE)

# MAR device load
MAR_DEVICE = re.compile(r"Adding device\s+(?P<mac>[\w.:/-]+)", re.IGNORECASE)

# Policy file update
POLICY_FILE_UPDATE = re.compile(
    r"Updating policy file\s*\((?P<path>[^)]+)\)\s*with\s+(?P<rule_type>[^:]+):",
    re.IGNORECASE,
)

# ---------------------------------------------------------------------------
# Policy config structures (embedded Perl hash)
# ---------------------------------------------------------------------------
EAP_TYPE_SELECTED = re.compile(r"'selected'\s*=>\s*'(?P<eap_type>[^']+)'")
EAP_TYPE_FIELD = re.compile(r"'field'\s*=>\s*'EAP-Type'", re.IGNORECASE)
VLAN_RESTRICT = re.compile(r"'restrict'\s*=>\s*'(?P<restrict>[^']+)'")
MAB_VALUE = re.compile(r"'value'\s*=>\s*'MAB'", re.IGNORECASE)

# Legacy patterns (for non-Forescout environments)
EAPOL_START = re.compile(r"eapol[- ]start", re.IGNORECASE)
AUTH_SUCCESS = re.compile(r"authenticated|auth(?:entication)?\s+succeed", re.IGNORECASE)
AUTH_FAILURE = re.compile(r"auth(?:entication)?\s+fail", re.IGNORECASE)


def _extract_prefix(line: str) -> dict[str, Any]:
    """Extract PID, epoch, and timestamp from the dot1x log prefix."""
    info: dict[str, Any] = {"ts": None, "pid": None, "epoch": None}
    m = PREFIX.search(line)
    if m:
        info["pid"] = int(m.group("pid"))
        info["epoch"] = float(m.group("epoch"))
        info["ts"] = m.group("ts")
    else:
        m2 = TS_ISO.search(line)
        if m2:
            info["ts"] = m2.group("ts")
    return info


def parse_dot1x(text: str) -> list[AuthEvent]:
    """Parse dot1x.log text, extracting process, plugin, and config events."""
    events: list[AuthEvent] = []
    # Track latest plugin metadata for enrichment
    current_version: str | None = None
    current_policy_enabled: bool | None = None
    current_eap_type: str | None = None
    current_vlan_config: str | None = None

    for line in text.splitlines():
        prefix = _extract_prefix(line)
        mac_m = MAC.search(line)
        sid_m = SESSION.search(line)

        kind: str | None = None
        extra: dict[str, Any] = {}

        # -- Process lifecycle --
        if RADIUSD_STOP.search(line):
            kind = "DOT1X_RADIUSD_STOPPING"
        elif m := RADIUSD_STARTED.search(line):
            kind = "DOT1X_RADIUSD_STARTED"
            current_version = m.group("version")
            extra["plugin_version"] = current_version
        elif PLUGIN_STOPPED.search(line):
            kind = "DOT1X_PLUGIN_STOPPED"
        elif REDIS_FLUSH.search(line):
            kind = "DOT1X_REDIS_FLUSH"
        elif RESTART_FREERADIUS.search(line):
            kind = "DOT1X_RADIUSD_RESTART"

        # -- Module starts --
        elif MAR_MODULE.search(line):
            kind = "DOT1X_MAR_MODULE_STARTED"
        elif DISCONNECT_MODULE.search(line):
            kind = "DOT1X_DISCONNECT_MODULE_STARTED"

        # -- Loading / policy --
        elif m := LOADING_COMPLETE.search(line):
            kind = "DOT1X_LOADING_COMPLETE"
            extra["metadata"] = {"proxies": int(m.group("proxies"))}

        elif m := POLICY_FILE_UPDATE.search(line):
            kind = "DOT1X_POLICY_FILE_UPDATE"
            extra["metadata"] = {"policy_path": m.group("path"), "rule_type": m.group("rule_type")}

        # -- radiusd process status (legacy pattern) --
        elif m := RADIUSD_STATUS.search(line):
            status = m.group("status").lower()
            kind = "DOT1X_RADIUSD_RUNNING" if status == "running" else "DOT1X_RADIUSD_NOT_RUNNING"

        # -- MAR device load --
        elif m := MAR_DEVICE.search(line):
            kind = "DOT1X_MAR_DEVICE_LOAD"
            mac_m = m

        # -- Legacy fallback --
        elif EAPOL_START.search(line):
            kind = "EAPOL_START"
        elif AUTH_SUCCESS.search(line):
            kind = "ENDPOINT_AUTH_SUCCESS"
        elif AUTH_FAILURE.search(line):
            kind = "ENDPOINT_AUTH_FAILURE"

        # -- Config structure lines (no prefix, part of a Perl dump) --
        else:
            # These lines may not have the dot1x: prefix
            eap_m = EAP_TYPE_SELECTED.search(line)
            if eap_m and EAP_TYPE_FIELD.search(line):
                # same line has both 'selected' => 'X' AND 'field' => 'EAP-Type'
                kind = "DOT1X_EAP_TYPE_CONFIG"
                current_eap_type = eap_m.group("eap_type")
                extra["eap_type"] = current_eap_type
            elif eap_m and "'field'" not in line:
                # standalone selected line — infer from context
                kind = "DOT1X_EAP_TYPE_CONFIG"
                current_eap_type = eap_m.group("eap_type")
                extra["eap_type"] = current_eap_type
            elif MAB_VALUE.search(line):
                kind = "DOT1X_MAB_RULE_CONFIG"

            vlan_m = VLAN_RESTRICT.search(line)
            if vlan_m:
                current_vlan_config = vlan_m.group("restrict")
                if not kind:
                    kind = "DOT1X_VLAN_RESTRICT_CONFIG"
                extra["vlan_config"] = current_vlan_config

        # -- Policy-Enabled can appear on any line (e.g. "Started; Policy-Enabled=1")
        pe_m = POLICY_ENABLED.search(line)
        if pe_m:
            current_policy_enabled = pe_m.group("enabled") == "1"
            extra.setdefault("policy_enabled", current_policy_enabled)
            if not kind:
                kind = "DOT1X_POLICY_ENABLED"

        if kind:
            ev = AuthEvent(
                ts=prefix["ts"],
                kind=kind,
                source="dot1x.log",
                message=line.strip(),
                pid=prefix["pid"],
                epoch=prefix["epoch"],
                endpoint_mac=mac_m.group("mac") if mac_m else None,
                session_id=sid_m.group("sid") if sid_m else None,
                plugin_version=extra.get("plugin_version", current_version),
                policy_enabled=extra.get("policy_enabled", current_policy_enabled),
                eap_type=extra.get("eap_type", current_eap_type),
                vlan_config=extra.get("vlan_config", current_vlan_config),
                metadata=extra.get("metadata", {}),
                raw_line=line,
            )
            events.append(ev)

    return events
