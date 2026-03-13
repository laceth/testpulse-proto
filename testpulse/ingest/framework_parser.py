"""Parse Forescout framework.log for auth-flow properties, test lifecycle,
switch configuration, and operational metadata.

Real log format — structured property lines::

    2026-03-03 18:47:16 | myframework | INFO |   10.16.148.138, 1772585230,
      Tue Mar 03 18:47:10 CST 2026, dot1x_auth_state, Access-Accept,
      (? [dot1x]), 0, 1772585230

Property verification::

    Property dot1x_auth_state  : expected=Access-Accept, actual=Access-Accept, match=True
    All property checks passed

Test result banners::

    ====Test passed: EAPTLSPolicySANSubRuleStatsTest Passed====
    ====Test Failed: EAPTLSPolicySANSubRuleStatsTest Failed====

Test lifecycle::

    === Starting PEAP Test Setup ===
    === PEAP Test Teardown ===

Switch interface configuration (``show running-config``)::

    interface GigabitEthernet3/1
     description AutomationTestingPort
     switchport access vlan 1570
     switchport mode access
     authentication port-control auto
     dot1x pae authenticator
     spanning-tree portfast edge

Operational metadata::

    Configuring RADIUS plugin settings on 10.100.49.78
    Starting RADIUS Configuration steps 1/6: dot1x system-auth-control
    Successfully setup all RADIUS configuration on Cisco switch 10.16.128.15
    Starting endpoint cleanup for MAC: 288023b82d59
    Restarting 802.1X plugin on RADIUS server on 10.100.49.78
    [OK] Trusted cert thumbprint: FBB88C61B92B928E24A3BF72219574E3EF12CBE1

Metadata extracted:

* ``epoch`` — event and property epochs from structured lines
* ``context_id`` — policy context (e.g. ``dot1x@3922889344900135729``)
* ``property_field`` / ``property_value`` — field name and its value
* ``endpoint_ip`` / ``endpoint_mac`` — from structured + operational lines
* Switch interface config — interface, VLAN, auth mode, dot1x, mab
* Test lifecycle — setup/teardown/running/result with test name extraction
* RADIUS config steps — switch IP, appliance IP, auth source, plugin state
* Certificate operations — thumbprints, subjects, stores
"""
from __future__ import annotations

import re
from typing import Any
from testpulse.models import AuthEvent

# ---------------------------------------------------------------------------
# Core matchers
# ---------------------------------------------------------------------------

# Leading ISO timestamp: ``2026-03-03 18:47:16``
TS = re.compile(r"(?P<ts>\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})")

# Extract content after ``| INFO |``
INFO_CONTENT = re.compile(r"\|\s*INFO\s*\|\s*(?P<content>.*)")

# ---------------------------------------------------------------------------
# Structured property lines
# ---------------------------------------------------------------------------
PROPERTY_LINE = re.compile(
    r"\|\s*INFO\s*\|\s*"
    r"(?P<ip>\d{1,3}(?:\.\d{1,3}){3}),\s*"           # endpoint IP
    r"(?P<epoch1>\d{10,}),\s*"                         # event epoch
    r"[^,]+,\s*"                                        # human-readable date (skip)
    r"(?P<field>dot1x_\w+|macs?|online|engine_\w+|ipv4_\w+|NAS\w*),\s*"  # field name
    r"(?P<value>[^,]+?),\s*"                           # value
    r"\((?P<context>[^)]*)\),\s*"                      # context block
    r"(?P<flags>[^,]*),\s*"                            # flags
    r"(?P<epoch2>\d{10,})",                            # property epoch
)

# ---------------------------------------------------------------------------
# Property verification
# ---------------------------------------------------------------------------
PROP_CHECK = re.compile(
    r"Property\s+(?P<field>\S+)\s*:\s*expected=(?P<expected>[^,]+?)\s*,\s*actual=(?P<actual>[^,]+?)\s*,\s*match=(?P<match>\w+)",
)
ALL_CHECKS = re.compile(r"All property checks passed", re.IGNORECASE)
PROP_CHECK_START = re.compile(r"Starting property checks for ID:\s*(?P<ip>\S+)", re.IGNORECASE)
VERIFY_WIRED = re.compile(r"Verifying wired properties for host:\s*(?P<ip>\S+)", re.IGNORECASE)

# ---------------------------------------------------------------------------
# Test lifecycle
# ---------------------------------------------------------------------------

# ``====Test passed: TestName Passed====``  /  ``====Test Failed: TestName Failed====``
TEST_RESULT = re.compile(
    r"=+\s*Test\s+(?P<result>passed|failed):\s*(?P<name>\S+)\s+(?:Passed|Failed)\s*=+",
    re.IGNORECASE,
)

# ``=== Starting PEAP Test Setup ===``  /  ``=== EAP-TLS Test Teardown ===``
TEST_PHASE = re.compile(
    r"===\s*(?P<phase>Starting|Checking)\s+(?P<name>.+?)\s*===",
    re.IGNORECASE,
)
TEST_TEARDOWN = re.compile(
    r"===\s*(?P<name>.+?)\s+(?:Test\s+)?Teardown\s*===",
    re.IGNORECASE,
)

# ``====Running test: EAPTLSPolicySANDetectionTest====``
TEST_RUNNING = re.compile(
    r"=+\s*Running\s+(?:Parametrized\s+)?(?:test\s+)?(?P<name>\S+?)(?:\[(?P<param>\d+)\])?\s*(?:with\s*\((?P<args>[^)]*)\))?\s*=*",
    re.IGNORECASE,
)

# ``====Teardown complete: TestName[1] | Elapsed: 02:10====``
TEARDOWN_COMPLETE = re.compile(
    r"=+\s*Teardown complete:\s*(?P<name>\S+?)(?:\[(?P<param>\d+)\])?\s*\|\s*Ela",
    re.IGNORECASE,
)

# ---------------------------------------------------------------------------
# Switch interface configuration (show running-config)
# ---------------------------------------------------------------------------
INTERFACE_LINE = re.compile(
    r"interface\s+(?P<iface>(?:GigabitEthernet|FastEthernet|TenGigabitEthernet)\S+)",
    re.IGNORECASE,
)

# IOS sub-commands under interface
SWITCH_CONFIG_CMDS = re.compile(
    r"^\s*(?P<cmd>switchport\s+\S+(?:\s+\S+)?|"
    r"authentication\s+\S+(?:\s+\S+)?|"
    r"dot1x\s+\S+(?:\s+\S+)?|"
    r"mab(?:\s+\S+)?|"
    r"description\s+\S+|"
    r"spanning-tree\s+\S+(?:\s+\S+)?|"
    r"snmp\s+\S+(?:\s+\S+(?:\s+\S+)?)?|"
    r"shutdown|no\s+shutdown)\s*$",
)

# ---------------------------------------------------------------------------
# Operational metadata patterns
# ---------------------------------------------------------------------------

# RADIUS config on switch
RADIUS_CONFIG = re.compile(
    r"(?:Starting RADIUS [Cc]onfiguration|Successfully setup all RADIUS configuration)"
    r".*?(?P<ip>\d{1,3}(?:\.\d{1,3}){3})",
    re.IGNORECASE,
)
RADIUS_CONFIG_STEP = re.compile(
    r"Starting RADIUS Configuration steps?\s*(?P<step>\d+)/(?P<total>\d+):\s*(?P<desc>.+)",
    re.IGNORECASE,
)

# RADIUS plugin settings
RADIUS_PLUGIN_CONFIG = re.compile(
    r"Configuring RADIUS plugin settings on\s+(?P<ip>\d{1,3}(?:\.\d{1,3}){3})",
    re.IGNORECASE,
)
RADIUS_PLUGIN_OK = re.compile(
    r"RADIUS plugin settings configured successfully on\s+(?P<ip>\d{1,3}(?:\.\d{1,3}){3})",
    re.IGNORECASE,
)

# RADIUS auth source
RADIUS_AUTH_SOURCE = re.compile(
    r"Configuring RADIUS Authentication Source with domain\s+'(?P<domain>[^']+)'",
    re.IGNORECASE,
)

# Plugin restart
PLUGIN_RESTART = re.compile(
    r"Restarting 802\.1X plugin on RADIUS server on\s+(?P<ip>\d{1,3}(?:\.\d{1,3}){3})",
    re.IGNORECASE,
)

# Endpoint cleanup
ENDPOINT_CLEANUP = re.compile(
    r"Starting endpoint cleanup for MAC:\s*(?P<mac>[0-9A-Fa-f:.\-]+)",
    re.IGNORECASE,
)

# Certificate operations
CERT_THUMBPRINT = re.compile(
    r"\[OK\]\s+(?P<store>Personal|Trusted)\s+cert\s+thumbprint:\s*(?P<thumbprint>[0-9A-Fa-f]+)",
    re.IGNORECASE,
)
CERT_SUBJECT = re.compile(
    r"Subject:\s*<Name\((?P<subject>[^)]+)\)>",
)
CERT_IMPORT = re.compile(
    r"Importing\s+(?:certificate|trusted cert|PFX).*?:\s*(?P<name>\S+)",
    re.IGNORECASE,
)

# Port already configured
PORT_CONFIGURED = re.compile(
    r"Port\s+(?P<iface>\S+)\s+already configured on (?:Cisco )?switch\s+(?P<ip>\d{1,3}(?:\.\d{1,3}){3})",
    re.IGNORECASE,
)

# ---------------------------------------------------------------------------
# Utility matchers
# ---------------------------------------------------------------------------

# MAC in framework lines (colon-separated hex or plain 12-hex)
MAC = re.compile(r"(?P<mac>(?:[0-9A-Fa-f]{2}[:.\-]){5}[0-9A-Fa-f]{2}|[0-9A-Fa-f]{12})")

# IP address after ``| INFO |`` (fallback when PROPERTY_LINE doesn't match)
HOST_IP = re.compile(r"\|\s*INFO\s*\|\s*(?P<ip>\d{1,3}(?:\.\d{1,3}){3})")

# Context ID: ``dot1x@3922889344900135729`` or ``?``
CONTEXT_ID = re.compile(r"\((?P<ctx_id>dot1x@\d+|[?])\s+\[dot1x\]\)")


def _extract_info_content(line: str) -> str | None:
    """Extract the content after ``| INFO |`` from a framework log line.

    Returns None if the line is not an INFO line.
    """
    m = INFO_CONTENT.search(line)
    return m.group("content").strip() if m else None


def _parse_switch_config_block(
    lines: list[str], start_idx: int, iface: str, ts: str | None,
) -> tuple[AuthEvent | None, int]:
    """Parse an IOS interface config block starting after the ``interface`` line.

    Each sub-command is wrapped in ``... | INFO |   <cmd>`` (indented in the
    INFO content).  We consume lines as long as they are INFO lines whose
    content starts with a space (IOS config indent).

    Returns (event, last_consumed_index).  The caller should resume parsing
    from ``last_consumed_index``.
    """
    config: dict[str, Any] = {"interface": iface}
    idx = start_idx
    while idx < len(lines):
        raw = lines[idx]
        content = _extract_info_content(raw)
        if content is None:
            # Not an INFO line — stop
            break

        # IOS sub-commands are indented; the regex strips leading ``| INFO |``
        # but the content still starts with space(s) for sub-commands.
        # Re-check the raw content portion after ``| INFO |``
        m = INFO_CONTENT.search(raw)
        raw_content = m.group("content") if m else ""
        # Sub-commands start with whitespace in the original content
        if not raw_content or (not raw_content[0].isspace() and not content.lower().startswith(("description ", "switchport ", "authentication ", "dot1x ", "mab", "spanning-tree", "snmp ", "shutdown", "no shutdown"))):
            break

        # Parse known sub-commands
        low = content.lower()
        if low.startswith("description "):
            config["description"] = content.split(None, 1)[1]
        elif low.startswith("switchport access vlan"):
            try:
                config["vlan"] = int(content.rsplit(None, 1)[-1])
            except ValueError:
                config["vlan"] = content.rsplit(None, 1)[-1]
        elif low.startswith("switchport mode"):
            config["switchport_mode"] = content.split(None, 2)[-1]
        elif low.startswith("authentication port-control"):
            config["auth_port_control"] = content.split(None, 2)[-1]
        elif low.startswith("authentication periodic"):
            config["auth_periodic"] = True
        elif low.startswith("dot1x pae"):
            config["dot1x_pae"] = content.split(None, 2)[-1]
        elif low.startswith("mab"):
            config["mab"] = True
        elif low.startswith("spanning-tree"):
            config["spanning_tree"] = content.split(None, 1)[-1]
        elif low.startswith("snmp"):
            config.setdefault("snmp", []).append(content)
        elif low == "shutdown":
            config["shutdown"] = True
        elif low == "no shutdown":
            config["shutdown"] = False
        else:
            # Not a recognized sub-command — stop consuming
            break
        idx += 1

    if len(config) <= 1:
        # Only got interface name, nothing useful
        return None, idx

    ev = AuthEvent(
        ts=ts,
        kind="FRAMEWORK_SWITCH_CONFIG",
        source="framework.log",
        message=f"switch config: {iface}",
        metadata=config,
        raw_line=f"interface {iface}",
    )
    # Enrich top-level fields from config
    if "vlan" in config:
        ev.vlan_config = str(config["vlan"])
    if "dot1x_pae" in config:
        ev.metadata["dot1x_pae"] = config["dot1x_pae"]

    return ev, idx


def parse_framework(text: str) -> list[AuthEvent]:
    """Parse framework.log text and return structured AuthEvents.

    Event kinds produced:

    **Property events**

    FRAMEWORK_AUTH_STATE
        ``dot1x_auth_state`` property (Access-Accept / Access-Reject).
    FRAMEWORK_HOST_AUTH_STATUS
        ``dot1x_host_auth_status`` property.
    FRAMEWORK_PROPERTY
        Any other structured property line.
    FRAMEWORK_PROP_CHECK
        Individual property verification line.
    FRAMEWORK_ALL_CHECKS_PASSED
        Summary "All property checks passed" line.
    FRAMEWORK_VERIFY_WIRED
        "Verifying wired properties for host" line.
    FRAMEWORK_PROP_CHECK_START
        "Starting property checks for ID" line.

    **Test lifecycle**

    FRAMEWORK_TEST_PASSED / FRAMEWORK_TEST_FAILED
        Test result banner.
    FRAMEWORK_TEST_SETUP
        ``=== Starting <TestType> Test Setup ===``
    FRAMEWORK_TEST_TEARDOWN
        ``=== <TestType> Test Teardown ===``
    FRAMEWORK_RUNNING_TEST
        ``Running test:`` or ``Running Parametrized test``
    FRAMEWORK_TEARDOWN_COMPLETE
        ``Teardown complete: TestName[N] | Elapsed...``

    **Switch configuration (``show running-config``)**

    FRAMEWORK_SWITCH_CONFIG
        Interface configuration block with VLAN, auth, dot1x, mab, etc.
    FRAMEWORK_PORT_CONFIGURED
        ``Port X already configured on switch``

    **Operational events**

    FRAMEWORK_RADIUS_CONFIG_STEP
        ``Starting RADIUS Configuration steps N/M: ...``
    FRAMEWORK_RADIUS_SETUP_COMPLETE
        ``Successfully setup all RADIUS configuration``
    FRAMEWORK_PLUGIN_CONFIG
        ``Configuring RADIUS plugin settings``
    FRAMEWORK_PLUGIN_RESTART
        ``Restarting 802.1X plugin``
    FRAMEWORK_ENDPOINT_CLEANUP
        ``Starting endpoint cleanup for MAC: ...``
    FRAMEWORK_CERT_IMPORT
        Certificate import operations.
    FRAMEWORK_CERT_THUMBPRINT
        Verified thumbprint.
    FRAMEWORK_RADIUS_AUTH_SOURCE
        ``Configuring RADIUS Authentication Source with domain``
    """
    events: list[AuthEvent] = []
    all_lines = text.splitlines()
    i = 0

    while i < len(all_lines):
        line = all_lines[i]
        ts_m = TS.search(line)
        ts = ts_m.group("ts") if ts_m else None

        # ================================================================
        # Switch interface config block (inside ``| INFO |`` wrapper)
        # ================================================================
        info_content = _extract_info_content(line)
        iface_m = INTERFACE_LINE.search(line) if info_content else None
        if iface_m and info_content and info_content.lower().startswith("interface "):
            ev, end_idx = _parse_switch_config_block(
                all_lines, i + 1, iface_m.group("iface"), ts,
            )
            if ev is not None:
                events.append(ev)
            i = end_idx
            continue

        # ================================================================
        # Test result banners (====Test passed/failed====)
        # ================================================================
        tr = TEST_RESULT.search(line)
        if tr:
            result = tr.group("result").lower()
            kind = "FRAMEWORK_TEST_PASSED" if result == "passed" else "FRAMEWORK_TEST_FAILED"
            events.append(
                AuthEvent(
                    ts=ts,
                    kind=kind,
                    source="framework.log",
                    message=line.strip(),
                    testcase_id=tr.group("name"),
                    raw_line=line,
                )
            )
            i += 1
            continue

        # ================================================================
        # Test lifecycle: setup / teardown / running / complete
        # ================================================================
        tp = TEST_PHASE.search(line)
        if tp:
            name = tp.group("name").strip()
            # Determine if this is setup or checking
            phase = tp.group("phase").lower()
            kind_suffix = "SETUP" if phase == "starting" else "CHECK"
            events.append(
                AuthEvent(
                    ts=ts,
                    kind=f"FRAMEWORK_TEST_{kind_suffix}",
                    source="framework.log",
                    message=line.strip(),
                    testcase_id=name,
                    metadata={"phase": phase, "test_type": name},
                    raw_line=line,
                )
            )
            i += 1
            continue

        td = TEST_TEARDOWN.search(line)
        if td:
            events.append(
                AuthEvent(
                    ts=ts,
                    kind="FRAMEWORK_TEST_TEARDOWN",
                    source="framework.log",
                    message=line.strip(),
                    testcase_id=td.group("name").strip(),
                    metadata={"test_type": td.group("name").strip()},
                    raw_line=line,
                )
            )
            i += 1
            continue

        tdc = TEARDOWN_COMPLETE.search(line)
        if tdc:
            events.append(
                AuthEvent(
                    ts=ts,
                    kind="FRAMEWORK_TEARDOWN_COMPLETE",
                    source="framework.log",
                    message=line.strip(),
                    testcase_id=tdc.group("name"),
                    metadata={"param": tdc.group("param")},
                    raw_line=line,
                )
            )
            i += 1
            continue

        trun = TEST_RUNNING.search(line)
        if trun:
            events.append(
                AuthEvent(
                    ts=ts,
                    kind="FRAMEWORK_RUNNING_TEST",
                    source="framework.log",
                    message=line.strip(),
                    testcase_id=trun.group("name"),
                    metadata={
                        "param": trun.group("param"),
                        "args": trun.group("args"),
                    },
                    raw_line=line,
                )
            )
            i += 1
            continue

        # ================================================================
        # Operational: RADIUS config steps
        # ================================================================
        rcs = RADIUS_CONFIG_STEP.search(line)
        if rcs:
            events.append(
                AuthEvent(
                    ts=ts,
                    kind="FRAMEWORK_RADIUS_CONFIG_STEP",
                    source="framework.log",
                    message=line.strip(),
                    metadata={
                        "step": int(rcs.group("step")),
                        "total": int(rcs.group("total")),
                        "description": rcs.group("desc").strip(),
                    },
                    raw_line=line,
                )
            )
            i += 1
            continue

        # RADIUS setup complete
        rc_complete = RADIUS_CONFIG.search(line)
        if rc_complete and "successfully" in line.lower():
            events.append(
                AuthEvent(
                    ts=ts,
                    kind="FRAMEWORK_RADIUS_SETUP_COMPLETE",
                    source="framework.log",
                    message=line.strip(),
                    metadata={"switch_ip": rc_complete.group("ip")},
                    raw_line=line,
                )
            )
            i += 1
            continue

        # ================================================================
        # Operational: plugin config / restart
        # ================================================================
        rpc = RADIUS_PLUGIN_CONFIG.search(line)
        if rpc:
            events.append(
                AuthEvent(
                    ts=ts,
                    kind="FRAMEWORK_PLUGIN_CONFIG",
                    source="framework.log",
                    message=line.strip(),
                    metadata={"appliance_ip": rpc.group("ip")},
                    raw_line=line,
                )
            )
            i += 1
            continue

        rpok = RADIUS_PLUGIN_OK.search(line)
        if rpok:
            events.append(
                AuthEvent(
                    ts=ts,
                    kind="FRAMEWORK_PLUGIN_CONFIG_OK",
                    source="framework.log",
                    message=line.strip(),
                    metadata={"appliance_ip": rpok.group("ip")},
                    raw_line=line,
                )
            )
            i += 1
            continue

        pr = PLUGIN_RESTART.search(line)
        if pr:
            events.append(
                AuthEvent(
                    ts=ts,
                    kind="FRAMEWORK_PLUGIN_RESTART",
                    source="framework.log",
                    message=line.strip(),
                    metadata={"appliance_ip": pr.group("ip")},
                    raw_line=line,
                )
            )
            i += 1
            continue

        # RADIUS auth source
        ras = RADIUS_AUTH_SOURCE.search(line)
        if ras:
            events.append(
                AuthEvent(
                    ts=ts,
                    kind="FRAMEWORK_RADIUS_AUTH_SOURCE",
                    source="framework.log",
                    message=line.strip(),
                    metadata={"domain": ras.group("domain")},
                    raw_line=line,
                )
            )
            i += 1
            continue

        # ================================================================
        # Operational: endpoint cleanup
        # ================================================================
        ec = ENDPOINT_CLEANUP.search(line)
        if ec:
            events.append(
                AuthEvent(
                    ts=ts,
                    kind="FRAMEWORK_ENDPOINT_CLEANUP",
                    source="framework.log",
                    message=line.strip(),
                    endpoint_mac=ec.group("mac"),
                    raw_line=line,
                )
            )
            i += 1
            continue

        # ================================================================
        # Operational: port already configured
        # ================================================================
        pcfg = PORT_CONFIGURED.search(line)
        if pcfg:
            events.append(
                AuthEvent(
                    ts=ts,
                    kind="FRAMEWORK_PORT_CONFIGURED",
                    source="framework.log",
                    message=line.strip(),
                    metadata={
                        "interface": pcfg.group("iface"),
                        "switch_ip": pcfg.group("ip"),
                    },
                    raw_line=line,
                )
            )
            i += 1
            continue

        # ================================================================
        # Operational: certificates
        # ================================================================
        ct = CERT_THUMBPRINT.search(line)
        if ct:
            events.append(
                AuthEvent(
                    ts=ts,
                    kind="FRAMEWORK_CERT_THUMBPRINT",
                    source="framework.log",
                    message=line.strip(),
                    metadata={
                        "store": ct.group("store"),
                        "thumbprint": ct.group("thumbprint"),
                    },
                    raw_line=line,
                )
            )
            i += 1
            continue

        ci = CERT_IMPORT.search(line)
        if ci:
            events.append(
                AuthEvent(
                    ts=ts,
                    kind="FRAMEWORK_CERT_IMPORT",
                    source="framework.log",
                    message=line.strip(),
                    metadata={"cert_name": ci.group("name")},
                    raw_line=line,
                )
            )
            i += 1
            continue

        # ================================================================
        # All property checks passed
        # ================================================================
        if ALL_CHECKS.search(line):
            ip_m = HOST_IP.search(line)
            events.append(
                AuthEvent(
                    ts=ts,
                    kind="FRAMEWORK_ALL_CHECKS_PASSED",
                    source="framework.log",
                    message=line.strip(),
                    endpoint_ip=ip_m.group("ip") if ip_m else None,
                    raw_line=line,
                )
            )
            i += 1
            continue

        # ================================================================
        # Verifying wired properties
        # ================================================================
        vw = VERIFY_WIRED.search(line)
        if vw:
            events.append(
                AuthEvent(
                    ts=ts,
                    kind="FRAMEWORK_VERIFY_WIRED",
                    source="framework.log",
                    message=line.strip(),
                    endpoint_ip=vw.group("ip"),
                    raw_line=line,
                )
            )
            i += 1
            continue

        # ================================================================
        # Starting property checks
        # ================================================================
        pcs = PROP_CHECK_START.search(line)
        if pcs:
            events.append(
                AuthEvent(
                    ts=ts,
                    kind="FRAMEWORK_PROP_CHECK_START",
                    source="framework.log",
                    message=line.strip(),
                    endpoint_ip=pcs.group("ip"),
                    raw_line=line,
                )
            )
            i += 1
            continue

        # ================================================================
        # Individual property check
        # ================================================================
        pc = PROP_CHECK.search(line)
        if pc:
            ip_m = HOST_IP.search(line)
            events.append(
                AuthEvent(
                    ts=ts,
                    kind="FRAMEWORK_PROP_CHECK",
                    source="framework.log",
                    message=f"{pc.group('field')}: expected={pc.group('expected')}, actual={pc.group('actual')}, match={pc.group('match')}",
                    endpoint_ip=ip_m.group("ip") if ip_m else None,
                    property_field=pc.group("field"),
                    property_value=pc.group("actual").strip(),
                    metadata={
                        "expected": pc.group("expected").strip(),
                        "actual": pc.group("actual").strip(),
                        "match": pc.group("match").lower() == "true",
                    },
                    raw_line=line,
                )
            )
            i += 1
            continue

        # ================================================================
        # Structured property lines
        # ================================================================
        pm = PROPERTY_LINE.search(line)
        if pm:
            field = pm.group("field").strip()
            value = pm.group("value").strip()
            endpoint_ip = pm.group("ip")
            epoch1 = float(pm.group("epoch1"))
            epoch2 = float(pm.group("epoch2"))
            context_raw = pm.group("context").strip()
            flags = pm.group("flags").strip()
            mac_m = MAC.search(line)

            # Extract context ID ("?" means unknown — normalize to None)
            ctx_m = CONTEXT_ID.search(line)
            context_id = ctx_m.group("ctx_id") if ctx_m else None
            if context_id == "?":
                context_id = None

            # Determine event kind based on property field
            if field == "dot1x_auth_state":
                kind = "FRAMEWORK_AUTH_STATE"
            elif field == "dot1x_host_auth_status":
                kind = "FRAMEWORK_HOST_AUTH_STATUS"
            else:
                kind = "FRAMEWORK_PROPERTY"

            ev = AuthEvent(
                ts=ts,
                kind=kind,
                source="framework.log",
                message=f"{field}={value}",
                endpoint_ip=endpoint_ip,
                epoch=epoch1,
                context_id=context_id,
                property_field=field,
                property_value=value,
                metadata={
                    "epoch_event": epoch1,
                    "epoch_property": epoch2,
                    "flags": flags,
                    "context_raw": context_raw,
                },
                raw_line=line,
            )

            # Enrich with known fields
            if field == "dot1x_calling_sid":
                ev.calling_station_id = value
                if mac_m:
                    ev.endpoint_mac = mac_m.group("mac")
            elif field == "dot1x_called_sid":
                ev.called_station_id = value
            elif field in ("mac", "macs"):
                ev.endpoint_mac = value
            elif field == "dot1x_user":
                ev.username = value
            elif field == "dot1x_NAS_port":
                ev.nas_port = value
            elif field in ("dot1x_NAS_addr", "dot1x_NASIPAddress"):
                ev.nas_ip = value
            elif field == "dot1x_acct_sid":
                ev.acct_session_id = value
            elif field in ("dot1x_NASPortIdStr", "NASPortIdStr"):
                ev.nas_port_id = value
            elif field == "dot1x_fr_client_x509_cert_subj_alt_name":
                ev.metadata["cert_san"] = value

            events.append(ev)
            i += 1
            continue

        i += 1

    return events
