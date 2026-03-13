"""Generate a clean Mermaid sequence diagram from a TestPulse EvidenceBundle.

Produces protocol-level diagrams in the style of the reference EAP-TLS flow:
clean inter-participant arrows, descriptive labels with parenthetical detail,
dashed responses, and a final-state box.  Adapts to MAB / PEAP / EAP-TLS.

Usage (standalone)::

    python -m testpulse.tools.mermaid_timeline /tmp/bundle.json

Or programmatically::

    from testpulse.tools.mermaid_timeline import generate_mermaid
    markup = generate_mermaid(bundle_dict)
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

# ═══════════════════════════════════════════════════════════════════════════
# Helpers
# ═══════════════════════════════════════════════════════════════════════════

def _ts_short(raw: str | None) -> str:
    """Extract HH:MM:SS from any timestamp."""
    if not raw:
        return ""
    m = re.search(r"(\d{2}:\d{2}:\d{2})", raw)
    return m.group(1) if m else ""


def _san(text: str, limit: int = 80) -> str:
    """Sanitize text for Mermaid labels — preserves <br/> tags."""
    # Protect <br/> before sanitizing angle brackets
    text = text.replace("<br/>", "__BR__")
    text = text.replace('"', "'").replace("#", "Nr").replace(";", ",")
    text = text.replace("<", "(").replace(">", ")")
    text = re.sub(r"[|]", "/", text)
    text = text.replace("__BR__", "<br/>")
    return text[:limit]


# ═══════════════════════════════════════════════════════════════════════════
# Data extraction helpers
# ═══════════════════════════════════════════════════════════════════════════

def _extract_meta(timeline: list[dict]) -> dict:
    """Pull global metadata from the timeline events."""
    macs: set[str] = set()
    ips: set[str] = set()
    users: set[str] = set()
    methods: set[str] = set()
    eap_types: set[str] = set()
    nas_ips: set[str] = set()
    switch_ports: set[str] = set()
    vlans: set[str] = set()
    radius_ip: str = ""

    for ev in timeline:
        for f in ("calling_station_id", "endpoint_mac"):
            v = ev.get(f)
            if v:
                macs.add(v)
        ip = ev.get("endpoint_ip")
        if ip:
            ips.add(ip)
        u = ev.get("username")
        if u:
            users.add(u)
        m = ev.get("auth_method")
        if m:
            methods.add(m.upper())
        e = ev.get("eap_type")
        if e:
            eap_types.add(e)
        nas = ev.get("src_ip") or ev.get("nas_ip")
        if nas:
            nas_ips.add(nas)
        dst = ev.get("dst_ip")
        if dst and not radius_ip:
            kind = ev.get("kind", "")
            if "REQUEST" in kind:
                radius_ip = dst
        port = ev.get("nas_port_id")
        if port:
            switch_ports.add(port)
        vl = ev.get("vlan_config")
        if vl:
            vlans.add(vl.strip()[:30])

    # Determine primary method label
    method_label = ""
    if eap_types:
        method_label = " / ".join(sorted(eap_types))
    elif methods:
        method_label = " / ".join(sorted(methods))

    # Pick the primary MAC (prefer the framework-verified one)
    primary_mac = ""
    for ev in timeline:
        if ev.get("kind") == "FRAMEWORK_PROPERTY" and ev.get("endpoint_mac"):
            primary_mac = ev["endpoint_mac"]
            break
    if not primary_mac and macs:
        primary_mac = sorted(macs)[0]

    return {
        "macs": sorted(macs),
        "primary_mac": primary_mac,
        "ips": sorted(ips),
        "users": sorted(users),
        "methods": sorted(methods),
        "eap_types": sorted(eap_types),
        "method_label": method_label,
        "nas_ips": sorted(nas_ips),
        "radius_ip": radius_ip,
        "switch_ports": sorted(switch_ports),
        "vlans": sorted(vlans),
    }


def _pair_radius(timeline: list[dict]) -> list[dict]:
    """Group RADIUS request + response into exchange pairs, chronologically."""
    requests: list[dict] = []
    responses: list[dict] = []
    for ev in timeline:
        kind = ev.get("kind", "")
        if kind == "RADIUS_ACCESS_REQUEST":
            requests.append(ev)
        elif kind in ("RADIUS_ACCESS_ACCEPT", "RADIUS_ACCESS_REJECT"):
            responses.append(ev)

    # Pair by matching timestamp + MAC
    pairs: list[dict] = []
    used_resp: set[int] = set()
    for req in requests:
        pair: dict = {"request": req, "response": None}
        req_ts = req.get("ts", "")
        req_mac = req.get("calling_station_id", "")
        for i, resp in enumerate(responses):
            if i in used_resp:
                continue
            if resp.get("ts") == req_ts and resp.get("calling_station_id") == req_mac:
                pair["response"] = resp
                used_resp.add(i)
                break
        pairs.append(pair)

    # Add any unmatched responses
    for i, resp in enumerate(responses):
        if i not in used_resp:
            pairs.append({"request": None, "response": resp})

    return pairs


def _collect_setup(timeline: list[dict]) -> list[str]:
    """Collect setup/config events and condense into note lines."""
    lines: list[str] = []
    seen: set[str] = set()
    for ev in timeline:
        kind = ev.get("kind", "")
        if kind == "DOT1X_EAP_TYPE_CONFIG":
            eap = ev.get("eap_type", "?")
            key = f"eap:{eap}"
            if key not in seen:
                seen.add(key)
                lines.append(f"EAP type: {eap}")
        elif kind == "DOT1X_VLAN_RESTRICT_CONFIG":
            vl = ev.get("vlan_config", "")
            key = f"vlan:{vl[:20]}"
            if key not in seen:
                seen.add(key)
                short = vl.replace("\t", " ").strip()[:35] if vl else "configured"
                lines.append(f"VLAN restrict: {short}")
        elif kind == "DOT1X_POLICY_ENABLED":
            if "policy" not in seen:
                seen.add("policy")
                lines.append("802.1X policy: ENABLED")
        elif kind == "DOT1X_LOADING_COMPLETE":
            ver = ev.get("plugin_version", "")
            if "loaded" not in seen:
                seen.add("loaded")
                lines.append(f"Plugin loaded: v{ver}" if ver else "Plugin loaded")
        elif kind == "DOT1X_RADIUSD_STARTED":
            if "radiusd" not in seen:
                seen.add("radiusd")
                ts = _ts_short(ev.get("ts"))
                lines.append(f"radiusd started{f' ({ts})' if ts else ''}")
    return lines


def _collect_framework(timeline: list[dict]) -> list[dict]:
    """Collect framework verification events, deduplicated.

    Reorders so that checks/state come before the verdict.
    """
    checks: list[dict] = []
    verdicts: list[dict] = []
    seen: set[str] = set()
    verdict_kinds = {
        "FRAMEWORK_ALL_CHECKS_PASSED",
        "FRAMEWORK_TEST_PASSED",
        "FRAMEWORK_TEST_FAILED",
    }
    for ev in timeline:
        kind = ev.get("kind", "")
        if not kind.startswith("FRAMEWORK_"):
            continue
        pf = ev.get("property_field", "")
        pv = ev.get("property_value", "")
        key = f"{kind}|{pf}|{pv}"
        if key in seen:
            continue
        seen.add(key)
        if kind in verdict_kinds:
            verdicts.append(ev)
        else:
            checks.append(ev)
    return checks + verdicts


# ═══════════════════════════════════════════════════════════════════════════
# Core generator
# ═══════════════════════════════════════════════════════════════════════════

def generate_mermaid(bundle: dict) -> str:
    """Generate a clean Mermaid sequence diagram from an EvidenceBundle dict."""
    timeline = bundle.get("timeline", [])
    classification = bundle.get("classification", "UNKNOWN")
    testcase_id = bundle.get("testcase_id", "?")
    confidence = bundle.get("confidence", 0)
    run_id = bundle.get("run_id", "?")

    observed = bundle.get("observed_decision", "?")
    expected = bundle.get("expected_decision", "?")
    if hasattr(observed, "value"):
        observed = observed.value
    if hasattr(expected, "value"):
        expected = expected.value

    meta = _extract_meta(timeline)
    radius_pairs = _pair_radius(timeline)
    setup_lines = _collect_setup(timeline)
    fw_events = _collect_framework(timeline)

    # ── Derive participant labels from the data ──────────────────────────
    primary_mac = meta["primary_mac"] or (meta["macs"][0] if meta["macs"] else "Endpoint")
    primary_ip = meta["ips"][0] if meta["ips"] else ""
    method_label = meta["method_label"] or "802.1X"

    # Switch — use first NAS IP + port
    switch_ip = ""
    switch_port = ""
    if radius_pairs:
        req = radius_pairs[0].get("request")
        if req:
            switch_ip = req.get("src_ip", "")
            switch_port = req.get("nas_port_id", "")
    if not switch_ip and meta["nas_ips"]:
        switch_ip = meta["nas_ips"][0]
    if not switch_port and meta["switch_ports"]:
        switch_port = meta["switch_ports"][0]

    radius_ip = meta["radius_ip"] or "Forescout RADIUS"

    # ── Build Mermaid lines ──────────────────────────────────────────────
    L: list[str] = []
    L.append("sequenceDiagram")
    L.append("")

    # Participants — clean boxes with device + detail
    ep_detail = f"{primary_mac}"
    if primary_ip:
        ep_detail += f" / {primary_ip}"
    L.append(f"    participant EP as Endpoint<br/>{_san(ep_detail)}")

    sw_detail = switch_ip or "Switch"
    if switch_port:
        sw_detail += f" / {switch_port}"
    L.append(f"    participant SW as Cisco Switch<br/>{_san(sw_detail)}")

    L.append(f"    participant RAD as Forescout RADIUS<br/>{_san(radius_ip)}")
    L.append(f"    participant FW as Test Framework<br/>TestPulse")

    L.append("")

    # ── Title note ───────────────────────────────────────────────────────
    title_parts = [f"TestPulse {testcase_id}"]
    if method_label:
        title_parts.append(f"Method: {method_label}")
    if meta["users"]:
        title_parts.append(f"User: {', '.join(meta['users'])}")
    L.append(f"    Note over EP,FW: {_san(' | '.join(title_parts))}")
    L.append("")

    # ── Plugin Setup (condensed note on RAD) ─────────────────────────────
    if setup_lines:
        setup_text = "<br/>".join(_san(s) for s in setup_lines[:6])
        L.append(f"    Note over RAD: Plugin Configuration<br/>{setup_text}")
        L.append("")

    # ── RADIUS Authentication Exchanges ──────────────────────────────────
    for i, pair in enumerate(radius_pairs):
        req = pair.get("request")
        resp = pair.get("response")

        if req:
            ts = _ts_short(req.get("ts"))
            mac = req.get("calling_station_id", "?")
            method = (req.get("auth_method") or "").upper() or method_label
            port = req.get("nas_port_id", "")
            src = req.get("src_ip", "")
            svc = req.get("service_type", "")

            # Endpoint initiates connection (implied)
            if i == 0:
                L.append(f"    EP->>SW: Link up")

            # If this is a different switch than the participant, note it
            req_switch = src
            if req_switch and req_switch != switch_ip:
                L.append(f"    Note over SW: Switch {req_switch}")

            # Access-Request
            req_detail_parts = [method]
            if mac:
                req_detail_parts.append(f"MAC {mac}")
            if port:
                req_detail_parts.append(port)
            if svc:
                req_detail_parts.append(f"svc={svc}")
            req_label = ", ".join(req_detail_parts)
            L.append(f"    SW->>RAD: Access-Request<br/>({_san(req_label)})")

        if resp:
            ts = _ts_short(resp.get("ts"))
            kind = resp.get("kind", "")
            mac = resp.get("calling_station_id", "?")

            if kind == "RADIUS_ACCESS_ACCEPT":
                resp_label = "Access-Accept"
                resp_arrow = "RAD->>SW"
                ep_arrow = "SW->>EP"
                ep_msg = "Port Authorized"
            else:
                resp_label = "Access-Reject"
                resp_arrow = "RAD-->>SW"
                ep_arrow = "SW-->>EP"
                ep_msg = "Port Denied"

            L.append(f"    {resp_arrow}: {resp_label}")

            # Show result to endpoint
            L.append(f"    {ep_arrow}: {ep_msg}")

        L.append("")

    # ── Framework Verification ───────────────────────────────────────────
    if fw_events:
        # Start verification
        verify_ip = ""
        for ev in fw_events:
            if ev.get("endpoint_ip"):
                verify_ip = ev["endpoint_ip"]
                break

        start_label = "Verify wired auth"
        if verify_ip:
            start_label += f"<br/>(endpoint {verify_ip})"
        L.append(f"    FW->>RAD: {_san(start_label)}")

        # Property checks and state reads
        for ev in fw_events:
            kind = ev.get("kind", "")
            pf = ev.get("property_field", "")
            pv = ev.get("property_value", "")
            mac = ev.get("endpoint_mac", "")

            if kind == "FRAMEWORK_PROP_CHECK" and pf:
                L.append(f"    FW->>RAD: Check {_san(pf)}<br/>(expect: {_san(pv)})")

            elif kind == "FRAMEWORK_AUTH_STATE" and pf:
                L.append(f"    RAD-->>FW: {_san(pf)} = {_san(pv)}")

            elif kind == "FRAMEWORK_PROPERTY" and pf:
                val_display = mac if "calling" in pf.lower() else pv
                L.append(f"    RAD-->>FW: {_san(pf)} = {_san(val_display)}")

            elif kind == "FRAMEWORK_VERIFY_WIRED":
                pass  # already shown above

            elif kind == "FRAMEWORK_PROP_CHECK_START":
                pass  # already shown above

            elif kind == "FRAMEWORK_ALL_CHECKS_PASSED":
                L.append(f"    Note over FW: ALL CHECKS PASSED")

            elif kind == "FRAMEWORK_TEST_PASSED":
                L.append(f"    Note over FW: TEST PASSED")

            elif kind == "FRAMEWORK_TEST_FAILED":
                L.append(f"    Note over FW: TEST FAILED")

        L.append("")

    # ── Final State Box ──────────────────────────────────────────────────
    if classification.startswith("PASS"):
        icon = "[PASS]"
        state = "PASSED"
    elif classification.startswith("FAIL"):
        icon = "[FAIL]"
        state = "FAILED"
    else:
        icon = "[?]"
        state = "UNKNOWN"

    # Build final-state note content
    final_parts = [
        f"{icon} {classification}",
        f"observed: {observed} / expected: {expected}",
        f"confidence: {confidence}",
    ]

    # If we know the VLAN or port result, include it
    accept_found = any(
        p.get("response", {}).get("kind") == "RADIUS_ACCESS_ACCEPT"
        for p in radius_pairs if p.get("response")
    )
    if accept_found and meta["switch_ports"]:
        port_label = meta["switch_ports"][0]
        final_parts.append(f"Port {port_label} = Authorized")

    final_text = "<br/>".join(_san(p) for p in final_parts)
    L.append(f"    rect rgb({"200, 255, 200" if state == "PASSED" else "255, 200, 200" if state == "FAILED" else "255, 255, 200"})")
    L.append(f"    Note over EP,FW: {final_text}")
    L.append(f"    end")

    return "\n".join(L)


# ═══════════════════════════════════════════════════════════════════════════
# Protocol Sequence — HORIZONTAL flowchart (graph LR)
# ═══════════════════════════════════════════════════════════════════════════

def generate_mermaid_horizontal(bundle: dict) -> str:
    """Generate a horizontal ``graph LR`` version of the protocol sequence."""
    timeline = bundle.get("timeline", [])
    classification = bundle.get("classification", "UNKNOWN")
    testcase_id = bundle.get("testcase_id", "?")
    confidence = bundle.get("confidence", 0)

    observed = bundle.get("observed_decision", "?")
    expected = bundle.get("expected_decision", "?")
    if hasattr(observed, "value"):
        observed = observed.value
    if hasattr(expected, "value"):
        expected = expected.value

    meta = _extract_meta(timeline)
    setup_lines = _collect_setup(timeline)
    fw_events = _collect_framework(timeline)

    primary_mac = meta["primary_mac"] or (meta["macs"][0] if meta["macs"] else "Endpoint")
    primary_ip = meta["ips"][0] if meta["ips"] else ""
    method_label = meta["method_label"] or "802.1X"

    if classification.startswith("PASS"):
        icon = "[PASS]"
    elif classification.startswith("FAIL"):
        icon = "[FAIL]"
    else:
        icon = "[?]"

    L: list[str] = []
    L.append("graph LR")
    L.append("")

    # -- Participants as subgraphs --
    ep_detail = _san(primary_mac, 30)
    if primary_ip:
        ep_detail += f"\\n{primary_ip}"
    L.append(f'    subgraph EP["Endpoint\\n{ep_detail}"]')
    L.append(f"    end")

    L.append(f'    subgraph SW["Cisco Switch"]')
    L.append(f"    end")

    # RADIUS config note inside subgraph
    setup_summary = "\\n".join(_san(s, 40) for s in setup_lines[:3]) if setup_lines else ""
    L.append(f'    subgraph RAD["Forescout RADIUS"]')
    if setup_summary:
        L.append(f'        R_CFG["{setup_summary}"]')
    L.append(f"    end")

    # Framework subgraph with checks result
    has_passed = any(e.get("kind") == "FRAMEWORK_ALL_CHECKS_PASSED" for e in fw_events)
    L.append(f'    subgraph FW["TestPulse Framework"]')
    if has_passed:
        L.append(f'        CHK["ALL CHECKS PASSED"]')
    L.append(f"    end")
    L.append("")

    # -- Protocol arrows --
    L.append(f'    EP -- "{method_label}" --> SW')
    L.append(f'    SW -- "RADIUS" --> RAD')
    L.append("")

    # Framework verification arrows
    for ev in fw_events:
        kind = ev.get("kind", "")
        pf = ev.get("property_field", "")
        pv = ev.get("property_value", "")
        eip = ev.get("endpoint_ip", "")

        if kind == "FRAMEWORK_VERIFY_WIRED":
            label = f"Verify wired auth\\n({_san(eip, 30)})" if eip else "Verify wired auth"
            L.append(f'    FW -- "{label}" --> RAD')
        elif kind == "FRAMEWORK_PROP_CHECK" and pf:
            L.append(f'    FW -- "Check {_san(pf, 25)}\\n(expect: {_san(pv, 25)})" --> RAD')
        elif kind == "FRAMEWORK_AUTH_STATE" and pf:
            L.append(f'    RAD -. "{_san(pf, 30)} = {_san(pv, 30)}" .-> FW')
        elif kind == "FRAMEWORK_PROPERTY" and pf:
            mac = ev.get("endpoint_mac", "")
            val = mac if "calling" in pf.lower() else pv
            L.append(f'    RAD -. "{_san(pf, 30)} = {_san(val, 30)}" .-> FW')

    L.append("")

    # -- Verdict node --
    verdict_text = f"{icon} {classification}\\nobserved: {observed}\\nexpected: {expected}\\nconfidence: {confidence}"
    L.append(f'    VERDICT(["{_san(verdict_text, 120)}"])')
    L.append(f"    FW --> VERDICT")
    L.append("")

    # -- Styles --
    L.append("    style EP fill:#1565c0,stroke:#0d47a1,color:#fff")
    L.append("    style SW fill:#00695c,stroke:#004d40,color:#fff")
    L.append("    style RAD fill:#e65100,stroke:#bf360c,color:#fff")
    L.append("    style FW fill:#283593,stroke:#1a237e,color:#fff")
    if classification.startswith("PASS"):
        L.append("    style VERDICT fill:#c8e6c9,stroke:#2e7d32,color:#1b5e20,stroke-width:3px")
    elif classification.startswith("FAIL"):
        L.append("    style VERDICT fill:#ffcdd2,stroke:#c62828,color:#b71c1c,stroke-width:3px")
    else:
        L.append("    style VERDICT fill:#fff9c4,stroke:#f9a825,color:#f57f17,stroke-width:3px")
    if has_passed:
        L.append("    style CHK fill:#2e7d32,stroke:#1b5e20,color:#fff")
    if setup_summary:
        L.append("    style R_CFG fill:#bf360c,stroke:#e65100,color:#fff")

    return "\n".join(L)


# ═══════════════════════════════════════════════════════════════════════════
# Timeline Story — chronological view of all events
# ═══════════════════════════════════════════════════════════════════════════

_SOURCE_COLORS = {
    "radiusd.log":     "#4169E1",   # royal blue
    "dot1x.log":       "#FF8C00",   # dark orange
    "framework.log":   "#2E8B57",   # sea green
    "endpoint":        "#9932CC",   # dark orchid
    "redis":           "#DC143C",   # crimson
    "hostinfo":        "#708090",   # slate gray
    "local_properties": "#708090",
    "fstool_status":   "#708090",
}

_SOURCE_LABELS = {
    "radiusd.log":     "RADIUS",
    "dot1x.log":       "dot1x",
    "framework.log":   "Framework",
    "endpoint":        "Endpoint",
    "redis":           "Redis",
    "hostinfo":        "Identity",
    "local_properties": "Identity",
    "fstool_status":   "Identity",
}

_KIND_DISPLAY = {
    "RADIUS_ACCESS_REQUEST":          "Access-Request",
    "RADIUS_ACCESS_ACCEPT":           "Access-Accept [PASS]",
    "RADIUS_ACCESS_REJECT":           "Access-Reject [FAIL]",
    "RADIUS_ACCOUNTING":              "Accounting",
    "DOT1X_EAP_TYPE_CONFIG":          "EAP config",
    "DOT1X_VLAN_RESTRICT_CONFIG":     "VLAN config",
    "DOT1X_RADIUSD_STARTED":          "radiusd started",
    "DOT1X_RADIUSD_STOPPING":         "radiusd stopping",
    "DOT1X_POLICY_ENABLED":           "Policy enabled",
    "DOT1X_PLUGIN_STARTED":           "Plugin started",
    "DOT1X_PLUGIN_STOPPED":           "Plugin stopped",
    "DOT1X_LOADING_COMPLETE":         "Plugin loaded",
    "DOT1X_MAR_MODULE_STARTED":       "MAR module ready",
    "DOT1X_DISCONNECT_MODULE_STARTED": "Disconnect module ready",
    "DOT1X_REDIS_FLUSH":              "Redis FLUSH",
    "DOT1X_POLICY_FILE_UPDATE":       "Policy file updated",
    "FRAMEWORK_PROP_CHECK_START":     "Begin property check",
    "FRAMEWORK_PROP_CHECK":           "Property check",
    "FRAMEWORK_VERIFY_WIRED":         "Verify wired auth",
    "FRAMEWORK_AUTH_STATE":           "Auth state read",
    "FRAMEWORK_PROPERTY":             "Property read",
    "FRAMEWORK_ALL_CHECKS_PASSED":    "ALL CHECKS PASSED",
    "FRAMEWORK_TEST_PASSED":          "TEST PASSED",
    "FRAMEWORK_TEST_FAILED":          "TEST FAILED",
    "ENDPOINT_AUTH_SUCCESS":          "Endpoint auth OK",
    "ENDPOINT_AUTH_FAILURE":          "Endpoint auth FAIL",
    "IDENTITY_AUTH_STATE":            "Identity auth state",
    "IDENTITY_HOST_RECORD":           "Host record",
    "IDENTITY_PROPERTY":              "Identity property",
    "IDENTITY_RULE_AUTH":             "Rule auth",
    "REDIS_RULE_SET":                 "Redis rule set",
    # EAPOL / pcap kinds
    "EAPOL_START":                    "EAPOL-Start",
    "EAPOL_LOGOFF":                   "EAPOL-Logoff",
    "EAP_REQUEST_IDENTITY":           "EAP-Req/Identity",
    "EAP_RESPONSE_IDENTITY":          "EAP-Resp/Identity",
    "EAP_REQUEST_TLS":                "EAP-Req/TLS",
    "EAP_RESPONSE_TLS":               "EAP-Resp/TLS",
    "EAP_REQUEST_PEAP":               "EAP-Req/PEAP",
    "EAP_RESPONSE_PEAP":              "EAP-Resp/PEAP",
    "EAP_TLS_CLIENT_HELLO":           "TLS Client Hello",
    "EAP_TLS_SERVER_HELLO":           "TLS Server Hello",
    "EAP_TLS_CERTIFICATE":            "TLS Certificate",
    "EAP_TLS_SERVER_KEY_EXCHANGE":    "TLS Server Key Exchange",
    "EAP_TLS_CERTIFICATE_REQUEST":    "TLS Certificate Request",
    "EAP_TLS_SERVER_HELLO_DONE":      "TLS Server Hello Done",
    "EAP_TLS_CERTIFICATE_VERIFY":     "TLS Certificate Verify",
    "EAP_TLS_CLIENT_KEY_EXCHANGE":    "TLS Client Key Exchange",
    "EAP_TLS_CHANGE_CIPHER_SPEC":     "TLS Change Cipher Spec",
    "EAP_TLS_FINISHED":               "TLS Finished",
    "EAP_TLS_ALERT":                  "TLS Alert [WARN]",
    "EAP_PEAP_CLIENT_HELLO":          "PEAP Client Hello",
    "EAP_PEAP_SERVER_HELLO":          "PEAP Server Hello",
    "EAP_PEAP_CERTIFICATE":           "PEAP Certificate",
    "EAP_PEAP_CHANGE_CIPHER_SPEC":    "PEAP Change Cipher Spec",
    "EAP_PEAP_FINISHED":              "PEAP Finished",
    "EAP_SUCCESS":                    "EAP-Success [PASS]",
    "EAP_FAILURE":                    "EAP-Failure [FAIL]",
    "RADIUS_ACCESS_CHALLENGE":        "Access-Challenge",
}


def _detail_for_timeline(ev: dict) -> str:
    """Build a concise detail string for a timeline event."""
    kind = ev.get("kind", "")
    parts: list[str] = []

    mac = ev.get("calling_station_id") or ev.get("endpoint_mac")
    if mac:
        parts.append(mac)

    method = ev.get("auth_method")
    if method:
        parts.append(method.upper())

    port = ev.get("nas_port_id")
    if port:
        parts.append(port)

    eap = ev.get("eap_type")
    if eap and "EAP" in kind:
        parts.append(f"EAP={eap}")

    pf = ev.get("property_field")
    pv = ev.get("property_value")
    if pf:
        parts.append(f"{pf}={pv}" if pv else pf)

    src_ip = ev.get("src_ip")
    dst_ip = ev.get("dst_ip")
    if src_ip and dst_ip:
        parts.append(f"{src_ip} → {dst_ip}")
    elif ev.get("endpoint_ip"):
        parts.append(ev["endpoint_ip"])

    ctx = ev.get("context_id")
    if ctx:
        parts.append(f"ctx={ctx[:20]}")

    ver = ev.get("plugin_version")
    if ver and "LOADING" in kind:
        parts.append(f"v{ver}")

    svc = ev.get("service_type")
    if svc:
        parts.append(f"svc={svc}")

    return _san(", ".join(parts), 60) if parts else ""


def generate_timeline(bundle: dict) -> str:
    """Generate a horizontal chronological timeline using flowchart LR.

    Reproduces the old sequence-diagram layout (participant lanes, arrows
    between sources, inter-source messages, verdict box) but oriented
    **horizontally** — time flows left-to-right along the X axis.
    """
    timeline = bundle.get("timeline", [])
    classification = bundle.get("classification", "UNKNOWN")
    testcase_id = bundle.get("testcase_id", "?")
    confidence = bundle.get("confidence", 0)

    observed = bundle.get("observed_decision", "?")
    expected = bundle.get("expected_decision", "?")
    if hasattr(observed, "value"):
        observed = observed.value
    if hasattr(expected, "value"):
        expected = expected.value

    # ── Deduplicate ──────────────────────────────────────────────────────
    deduped: list[dict] = []
    seen: set[str] = set()
    for ev in timeline:
        key = f"{ev.get('kind')}|{ev.get('source')}|{ev.get('ts')}"
        if key not in seen:
            seen.add(key)
            deduped.append(ev)

    # ── Parse epoch helper ───────────────────────────────────────────────
    def _parse_epoch(ev: dict) -> float:
        epoch = ev.get("epoch")
        if epoch:
            return float(epoch)
        ts = ev.get("ts", "")
        m = re.match(r"(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})", ts)
        if m:
            try:
                from datetime import datetime
                return datetime.strptime(m.group(1), "%Y-%m-%d %H:%M:%S").timestamp()
            except ValueError:
                pass
        cleaned = re.sub(r"\s+[A-Z]{2,5}\s+[-+]\d{4}\s+", " ", ts)
        cleaned = re.sub(r"\s+[A-Z]{2,5}\s+", " ", cleaned)
        cleaned = re.sub(r"\s+", " ", cleaned).strip()
        for fmt in ("%a %b %d %H:%M:%S %Y",):
            try:
                from datetime import datetime
                return datetime.strptime(cleaned, fmt).timestamp()
            except ValueError:
                pass
        return 0.0

    # ── Split timed vs config ────────────────────────────────────────────
    timed: list[dict] = []
    untimed: list[dict] = []
    for ev in deduped:
        if ev.get("ts"):
            timed.append(ev)
        else:
            untimed.append(ev)

    _VERDICT_KINDS = {
        "FRAMEWORK_ALL_CHECKS_PASSED", "FRAMEWORK_TEST_PASSED",
        "FRAMEWORK_TEST_FAILED"
    }

    def _sort_key(ev: dict) -> tuple:
        epoch = _parse_epoch(ev)
        is_verdict = 1 if ev.get("kind", "") in _VERDICT_KINDS else 0
        return (epoch, is_verdict)

    timed.sort(key=_sort_key)

    # ── Group by time window ─────────────────────────────────────────────
    from collections import OrderedDict
    from datetime import datetime

    dates_seen: set[str] = set()
    for ev in timed:
        ts = ev.get("ts", "")
        m = re.match(r"(\d{4}-\d{2}-\d{2})", ts)
        if m:
            dates_seen.add(m.group(1))
        else:
            m2 = re.match(r"\w+ (\w+ \d+).+?(\d{4})$", ts.strip())
            if m2:
                dates_seen.add(f"{m2.group(2)}-{m2.group(1)}")
    multi_day = len(dates_seen) > 1

    def _ts_group_key(ev: dict) -> str:
        ts = ev.get("ts", "")
        time_part = _ts_short(ts) or "(no time)"
        if not multi_day:
            return time_part
        ep = _parse_epoch(ev)
        if ep > 0:
            try:
                return datetime.fromtimestamp(ep).strftime("%Y-%m-%d %H:%M:%S")
            except (OSError, ValueError):
                pass
        return time_part

    time_groups: OrderedDict[str, list[dict]] = OrderedDict()
    if untimed:
        time_groups["(config)"] = untimed
    for ev in timed:
        key = _ts_group_key(ev)
        if key not in time_groups:
            time_groups[key] = []
        time_groups[key].append(ev)

    # ── Detect active sources ────────────────────────────────────────────
    active_sources: set[str] = set()
    for ev in deduped:
        src = ev.get("source", "")
        label = _SOURCE_LABELS.get(src, src)
        active_sources.add(label)

    # ── Sanitize for flowchart labels (no Mermaid-breaking chars) ────────
    def _fc_san(text: str, limit: int = 70) -> str:
        text = text.replace('"', "'").replace("#", "Nr").replace(";", " ")
        text = text.replace("<", "(").replace(">", ")")
        text = text.replace("|", "/").replace("**", "")
        text = text.replace("\\", "/")
        # Collapse whitespace
        text = re.sub(r"\s+", " ", text).strip()
        text = text[:limit]
        # Balance parens/brackets after truncation
        open_p = text.count("(") - text.count(")")
        if open_p > 0:
            text = text + ")" * open_p
        open_b = text.count("[") - text.count("]")
        if open_b > 0:
            text = text + "]" * open_b
        return text

    # ── Node shape + style helpers ───────────────────────────────────────
    def _node_shape(ev: dict, nid: str, label: str) -> str:
        """Return the Mermaid node declaration with shape encoding."""
        kind = ev.get("kind", "")
        if kind in ("RADIUS_ACCESS_ACCEPT", "FRAMEWORK_ALL_CHECKS_PASSED",
                     "FRAMEWORK_TEST_PASSED", "EAP_SUCCESS"):
            # Stadium (rounded) for accept/pass
            return f'{nid}(["{label}"])'
        elif kind in ("RADIUS_ACCESS_REJECT", "FRAMEWORK_TEST_FAILED",
                       "EAP_FAILURE"):
            # Hexagon for reject/fail
            return f'{nid}{{{{"{label}"}}}}'
        elif kind == "RADIUS_ACCESS_REQUEST":
            # Parallelogram for requests
            return f'{nid}[/"{label}"/]'
        else:
            return f'{nid}["{label}"]'

    def _node_style(ev: dict, nid: str) -> str | None:
        """Return optional style line for colored nodes."""
        kind = ev.get("kind", "")
        if kind in ("RADIUS_ACCESS_ACCEPT", "FRAMEWORK_ALL_CHECKS_PASSED",
                     "FRAMEWORK_TEST_PASSED", "EAP_SUCCESS"):
            return f"style {nid} fill:#2e7d32,stroke:#1b5e20,color:#fff"
        elif kind in ("RADIUS_ACCESS_REJECT", "FRAMEWORK_TEST_FAILED",
                       "EAP_FAILURE"):
            return f"style {nid} fill:#c62828,stroke:#b71c1c,color:#fff"
        elif kind == "RADIUS_ACCESS_REQUEST":
            return f"style {nid} fill:#1565c0,stroke:#0d47a1,color:#fff"
        return None

    # ── Build display label for a node ───────────────────────────────────
    def _node_label(ev: dict) -> str:
        kind = ev.get("kind", "")
        source = ev.get("source", "")
        src_label = _SOURCE_LABELS.get(source, source)
        display = _KIND_DISPLAY.get(kind, kind.replace("_", " ").lower())
        detail = _detail_for_timeline(ev)

        label = f"{src_label}: {display}"
        if detail:
            label += f" ({detail})"
        return _fc_san(label)

    # ── Build flowchart LR ───────────────────────────────────────────────
    if classification.startswith("PASS"):
        icon = "[PASS]"
    elif classification.startswith("FAIL"):
        icon = "[FAIL]"
    else:
        icon = "[?]"

    L: list[str] = []
    L.append("graph LR")
    L.append("")

    styles: list[str] = []
    node_id = 0
    prev_nid: str | None = None
    group_idx = 0

    for ts_label, events in time_groups.items():
        group_idx += 1
        sg_id = f"T{group_idx}"
        ts_display = _fc_san(ts_label)
        L.append(f'    subgraph {sg_id}["T: {ts_display}"]')

        first_in_group: str | None = None
        for ev in events:
            node_id += 1
            nid = f"n{node_id}"
            label = _node_label(ev)
            node_decl = _node_shape(ev, nid, label)
            L.append(f"    {node_decl}")

            s = _node_style(ev, nid)
            if s:
                styles.append(s)

            if first_in_group is None:
                first_in_group = nid

        L.append(f"    end")
        L.append("")

        # Chain subgroups left-to-right
        if prev_nid and first_in_group:
            L.append(f"    {prev_nid} --> {first_in_group}")
            L.append("")

        # Track last node in this group for chaining
        prev_nid = f"n{node_id}"

    # ── Verdict node ─────────────────────────────────────────────────────
    node_id += 1
    vid = f"n{node_id}"
    verdict_lines = [
        f"{icon} {classification}",
        f"observed: {observed} / expected: {expected}",
        f"confidence: {confidence}",
    ]
    verdict_label = _fc_san(", ".join(verdict_lines))

    if classification.startswith("PASS"):
        L.append(f'{vid}(["{verdict_label}"])')
        styles.append(f"style {vid} fill:#c8e6c9,stroke:#2e7d32,color:#1b5e20,stroke-width:3px")
    elif classification.startswith("FAIL"):
        L.append(f'{vid}(["{verdict_label}"])')
        styles.append(f"style {vid} fill:#ffcdd2,stroke:#c62828,color:#b71c1c,stroke-width:3px")
    else:
        L.append(f'{vid}(["{verdict_label}"])')
        styles.append(f"style {vid} fill:#fff9c4,stroke:#f57f17,color:#e65100,stroke-width:3px")

    if prev_nid:
        L.append(f"    {prev_nid} --> {vid}")
    L.append("")

    # ── Title (as a styled node at the beginning) ────────────────────────
    title_text = _fc_san(f"{icon} {testcase_id} Chronological Timeline / {classification}")
    # Insert title node at beginning, linked to first real node
    title_nid = "TITLE"
    L.insert(2, f'    {title_nid}["{title_text}"]')
    L.insert(3, f"    {title_nid} --> n1")
    L.insert(4, "")
    styles.append(f"style {title_nid} fill:#263238,stroke:#455a64,color:#eceff1,stroke-width:2px")

    # ── Subgraph label styles ────────────────────────────────────────────
    for g in range(1, group_idx + 1):
        styles.append(f"style T{g} fill:none,stroke:#546e7a,stroke-dasharray: 5 5")

    # ── Apply styles ─────────────────────────────────────────────────────
    L.append("")
    for s in styles:
        L.append(f"    {s}")

    return "\n".join(L)


# ═══════════════════════════════════════════════════════════════════════════
# Component / Device Diagram — test topology with metadata
# ═══════════════════════════════════════════════════════════════════════════

def generate_component_diagram(bundle: dict) -> str:
    """Generate a horizontal flowchart showing devices in the test topology.

    Extracts device identities and metadata from the evidence bundle and
    renders them as a left-to-right component diagram with connection
    arrows showing the authentication flow path.
    """
    timeline = bundle.get("timeline", [])
    classification = bundle.get("classification", "UNKNOWN")
    testcase_id = bundle.get("testcase_id", "?")
    confidence = bundle.get("confidence", 0)
    artifacts = bundle.get("artifacts", [])

    observed = bundle.get("observed_decision", "?")
    expected = bundle.get("expected_decision", "?")
    if hasattr(observed, "value"):
        observed = observed.value
    if hasattr(expected, "value"):
        expected = expected.value

    meta = _extract_meta(timeline)

    # ── Collect extended metadata from timeline events ───────────────────
    plugin_versions: set[str] = set()
    plugin_settings: dict[str, str] = {}
    rule_count = 0
    rule_actions: list[str] = []
    context_ids: set[str] = set()
    property_fields: set[str] = set()
    eap_types: set[str] = set()
    policy_enabled: bool | None = None
    sources_seen: set[str] = set()
    radius_port = ""
    acct_port = ""
    min_tls = ""
    endpoint_ips: set[str] = set()
    endpoint_macs: set[str] = set()
    nas_ports: set[str] = set()
    src_ips: set[str] = set()
    dst_ips: set[str] = set()

    for ev in timeline:
        source = ev.get("source", "")
        if source:
            sources_seen.add(source)

        v = ev.get("plugin_version")
        if v:
            plugin_versions.add(v)

        pe = ev.get("policy_enabled")
        if pe is not None:
            policy_enabled = pe

        ctx = ev.get("context_id")
        if ctx:
            context_ids.add(ctx)

        pf = ev.get("property_field")
        if pf:
            property_fields.add(pf)

        et = ev.get("eap_type")
        if et:
            eap_types.add(et)

        ip = ev.get("endpoint_ip")
        if ip:
            endpoint_ips.add(ip)

        for f in ("calling_station_id", "endpoint_mac"):
            mac = ev.get(f)
            if mac:
                endpoint_macs.add(mac)

        npi = ev.get("nas_port_id")
        if npi:
            nas_ports.add(npi)

        si = ev.get("src_ip")
        if si:
            src_ips.add(si)
        di = ev.get("dst_ip")
        if di:
            dst_ips.add(di)

        md = ev.get("metadata", {})
        kind = ev.get("kind", "")

        if kind == "IDENTITY_PLUGIN_SETTING":
            sk = md.get("setting_key", "")
            sv = md.get("setting_value", "")
            if sk:
                plugin_settings[sk] = sv
                if sk == "localradiusport":
                    radius_port = sv
                elif sk == "localacctport":
                    acct_port = sv
                elif sk == "min_tls_version":
                    min_tls = sv

        if kind == "IDENTITY_RULE_CONFIG":
            rule_count = md.get("rule_count", 0)

        if kind in ("IDENTITY_RULE_AUTH", "REDIS_RULE_STATE"):
            action = md.get("auth_action", "")
            if action:
                rule_actions.append(action)

    # ── Sanitize helper ──────────────────────────────────────────────────
    def _s(text: str, limit: int = 50) -> str:
        text = text.replace('"', "'").replace("#", "Nr").replace(";", " ")
        text = text.replace("<", "(").replace(">", ")")
        text = text.replace("|", "/").replace("**", "").replace("\\", "/")
        text = re.sub(r"\s+", " ", text).strip()
        text = text[:limit]
        # Balance parens/brackets after truncation
        open_p = text.count("(") - text.count(")")
        if open_p > 0:
            text = text + ")" * open_p
        open_b = text.count("[") - text.count("]")
        if open_b > 0:
            text = text + "]" * open_b
        return text

    # ── Classification icon ──────────────────────────────────────────────
    if classification.startswith("PASS"):
        icon = "[PASS]"
        verdict_fill = "#c8e6c9"
        verdict_stroke = "#2e7d32"
        verdict_color = "#1b5e20"
    elif classification.startswith("FAIL"):
        icon = "[FAIL]"
        verdict_fill = "#ffcdd2"
        verdict_stroke = "#c62828"
        verdict_color = "#b71c1c"
    else:
        icon = "[?]"
        verdict_fill = "#fff9c4"
        verdict_stroke = "#f57f17"
        verdict_color = "#e65100"

    L: list[str] = []
    styles: list[str] = []
    L.append("graph LR")
    L.append("")

    # ── Title ────────────────────────────────────────────────────────────
    title = _s(f"{icon} {testcase_id} Component Topology / {classification}")
    L.append(f'    TITLE["{title}"]')
    styles.append("style TITLE fill:#263238,stroke:#455a64,color:#eceff1,stroke-width:2px")
    L.append("")

    # ── Endpoint device ──────────────────────────────────────────────────
    ep_lines = ["Endpoint"]
    if endpoint_macs:
        ep_lines.append(f"MAC: {', '.join(sorted(endpoint_macs)[:2])}")
    if endpoint_ips:
        ep_lines.append(f"IP: {', '.join(sorted(endpoint_ips)[:2])}")
    ep_label = _s(" / ".join(ep_lines))
    L.append(f'    EP(["{ep_label}"])')
    styles.append("style EP fill:#1565c0,stroke:#0d47a1,color:#fff")
    L.append("")

    # ── Switch / NAS ─────────────────────────────────────────────────────
    sw_lines = ["Switch / NAS"]
    if src_ips:
        sw_lines.append(f"IP: {', '.join(sorted(src_ips)[:2])}")
    if nas_ports:
        sw_lines.append(f"Port: {', '.join(sorted(nas_ports)[:2])}")
    sw_label = _s(" / ".join(sw_lines))
    L.append(f'    SW["{sw_label}"]')
    styles.append("style SW fill:#00695c,stroke:#004d40,color:#fff")
    L.append("")

    # ── Forescout Appliance (RADIUS + dot1x) ─────────────────────────────
    app_lines = ["Forescout Appliance"]
    if dst_ips:
        app_lines.append(f"RADIUS IP: {', '.join(sorted(dst_ips)[:1])}")
    elif radius_port:
        app_lines.append(f"RADIUS port: {radius_port}")
    if plugin_versions:
        app_lines.append(f"dot1x v{sorted(plugin_versions)[-1]}")
    if policy_enabled is not None:
        app_lines.append(f"Policy: {'ON' if policy_enabled else 'OFF'}")
    if min_tls:
        app_lines.append(f"TLS: {min_tls}")
    app_label = _s(" / ".join(app_lines))
    L.append(f'    APP["{app_label}"]')
    styles.append("style APP fill:#e65100,stroke:#bf360c,color:#fff")
    L.append("")

    # ── RADIUS config detail subgraph ────────────────────────────────────
    L.append('    subgraph RADCFG["RADIUS Config"]')
    rad_detail = []
    if radius_port:
        rad_detail.append(f"Auth port: {radius_port}")
    if acct_port:
        rad_detail.append(f"Acct port: {acct_port}")
    if eap_types:
        rad_detail.append(f"EAP: {', '.join(sorted(eap_types))}")
    elif meta.get("method_label"):
        rad_detail.append(f"Method: {meta['method_label']}")
    if min_tls:
        rad_detail.append(f"Min TLS: {min_tls}")
    ocsp = plugin_settings.get("ocsp", "")
    if ocsp:
        rad_detail.append(f"OCSP: {ocsp}")
    crl = plugin_settings.get("crl", "")
    if crl:
        rad_detail.append(f"CRL: {crl}")
    radsec = plugin_settings.get("enableradsec", "")
    if radsec:
        rad_detail.append(f"RadSec: {radsec}")
    frag = plugin_settings.get("fragment_size", "")
    if frag:
        rad_detail.append(f"Fragment: {frag}")

    for i, d in enumerate(rad_detail[:6]):
        L.append(f'    RC{i}["{_s(d)}"]')
    L.append('    end')
    styles.append("style RADCFG fill:none,stroke:#546e7a,stroke-dasharray: 5 5")
    L.append("")

    # ── Pre-admission rules subgraph ─────────────────────────────────────
    L.append('    subgraph RULES["Pre-Admission Rules"]')
    if rule_count:
        L.append(f'    R0["{rule_count} rules configured"]')
    unique_actions = sorted(set(rule_actions))
    for i, a in enumerate(unique_actions[:3]):
        L.append(f'    RA{i}["{_s(f"Action: {a}")}"]')
    if not rule_count and not unique_actions:
        L.append('    R0["No rules detected"]')
    L.append('    end')
    styles.append("style RULES fill:none,stroke:#546e7a,stroke-dasharray: 5 5")
    L.append("")

    # ── Data sources subgraph ────────────────────────────────────────────
    L.append('    subgraph SRCS["Data Sources"]')
    for i, src in enumerate(sorted(sources_seen)):
        label = _SOURCE_LABELS.get(src, src)
        L.append(f'    S{i}["{_s(label + ": " + src)}"]')
    # Also show artifacts not in sources
    artifact_only = [a for a in artifacts if a not in sources_seen]
    for i, a in enumerate(artifact_only[:4]):
        L.append(f'    SA{i}["{_s(a)}"]')
    L.append('    end')
    styles.append("style SRCS fill:none,stroke:#546e7a,stroke-dasharray: 5 5")
    L.append("")

    # ── Verdict node ─────────────────────────────────────────────────────
    v_text = _s(f"{icon} {classification}, {observed}/{expected}, conf={confidence}")
    L.append(f'    VERDICT(["{v_text}"])')
    styles.append(f"style VERDICT fill:{verdict_fill},stroke:{verdict_stroke},color:{verdict_color},stroke-width:3px")
    L.append("")

    # ── Connections ──────────────────────────────────────────────────────
    auth_method = meta.get("method_label") or "802.1X"
    L.append(f'    TITLE --> EP')
    L.append(f'    EP -- "{_s(auth_method)}" --> SW')
    L.append(f'    SW -- "RADIUS" --> APP')
    L.append(f'    APP --> RADCFG')
    L.append(f'    APP --> RULES')
    L.append(f'    APP --> SRCS')
    L.append(f'    APP --> VERDICT')
    L.append("")

    # ── Apply styles ─────────────────────────────────────────────────────
    for s in styles:
        L.append(f"    {s}")

    return "\n".join(L)


# ═══════════════════════════════════════════════════════════════════════════
# EAPOL Wire Diagram — from pcap-parsed AuthEvents
# ═══════════════════════════════════════════════════════════════════════════

def generate_eapol_diagram(
    events: list[dict],
    *,
    title: str = "EAPOL / EAP-TLS Wire Trace",
) -> str:
    """Generate a Mermaid sequence diagram from pcap-parsed AuthEvents.

    Participants:
        Supplicant (endpoint) ↔ Authenticator (switch) ↔ Auth Server (RADIUS)

    Parameters
    ----------
    events
        List of AuthEvent dicts (or AuthEvent objects converted via
        ``dataclasses.asdict``).  Expected to come from
        :func:`testpulse.ingest.eapol_parser.parse_pcap`.
    title
        Diagram title.
    """
    from dataclasses import asdict as _asdict

    # Normalise to dicts
    evts: list[dict] = []
    for e in events:
        if hasattr(e, "kind"):
            evts.append(_asdict(e))
        else:
            evts.append(e)

    if not evts:
        return "sequenceDiagram\n    Note over EP: No EAPOL events captured"

    # ── Discover participants ────────────────────────────────────────────
    sup_mac = ""
    auth_mac = ""
    radius_ip = ""
    sup_identity = ""

    for ev in evts:
        kind = ev.get("kind", "")
        meta = ev.get("metadata", {})

        # Supplicant is the source of EAPOL-Start or EAP-Response
        if kind in ("EAPOL_START", "EAP_RESPONSE_IDENTITY") and not sup_mac:
            sup_mac = meta.get("src_mac", "") or ev.get("endpoint_mac", "")
            auth_mac = meta.get("dst_mac", "")
        if kind == "EAP_RESPONSE_IDENTITY":
            sup_identity = meta.get("identity", "") or ev.get("username", "") or ""
        # RADIUS events have IPs
        if kind.startswith("RADIUS_") and not radius_ip:
            radius_ip = ev.get("dst_ip") or ev.get("src_ip") or ""

    sup_label = sup_mac or "Endpoint"
    if sup_identity:
        sup_label += f"<br/>{_san(sup_identity)}"
    auth_label = auth_mac or "Authenticator"
    rad_label = radius_ip or "Auth Server"

    L: list[str] = []
    L.append("sequenceDiagram")
    L.append("")
    L.append(f"    participant SUP as Supplicant<br/>{_san(sup_label)}")
    L.append(f"    participant AUTH as Authenticator<br/>{_san(auth_label)}")
    L.append(f"    participant SRV as Auth Server<br/>{_san(rad_label)}")
    L.append("")
    L.append(f"    Note over SUP,SRV: {_san(title)}")
    L.append("")

    # ── Map events to arrows ────────────────────────────────────────────
    for ev in evts:
        kind = ev.get("kind", "")
        ts = _ts_short(ev.get("ts"))
        display = _KIND_DISPLAY.get(kind, kind.replace("_", " "))
        meta = ev.get("metadata", {})
        src_mac = meta.get("src_mac", "")

        # Determine direction
        if kind == "EAPOL_START":
            L.append(f"    SUP->>AUTH: {_san(display)}")
        elif kind == "EAPOL_LOGOFF":
            L.append(f"    SUP->>AUTH: {_san(display)}")

        # EAP Request = Authenticator → Supplicant (relayed from server)
        elif kind.startswith("EAP_REQUEST"):
            L.append(f"    AUTH->>SUP: {_san(display)}")

        # EAP Response = Supplicant → Authenticator (forwarded to server)
        elif kind.startswith("EAP_RESPONSE"):
            detail = ""
            if "IDENTITY" in kind and sup_identity:
                detail = f' "{sup_identity}"'
            L.append(f"    SUP->>AUTH: {_san(display)}{_san(detail)}")

        # EAP-TLS / PEAP TLS sub-messages — direction from src MAC
        elif "TLS_CLIENT" in kind or "TLS_CERTIFICATE_VERIFY" in kind:
            # Client-originated TLS messages
            L.append(f"    SUP->>AUTH: {_san(display)}")
        elif "TLS_SERVER" in kind or "TLS_CERTIFICATE_REQUEST" in kind:
            # Server-originated TLS messages
            L.append(f"    AUTH-->>SUP: {_san(display)}")
        elif "TLS_CERTIFICATE" in kind:
            # Ambiguous — use MAC to determine direction
            if src_mac and src_mac == sup_mac:
                L.append(f"    SUP->>AUTH: {_san(display)}")
            else:
                L.append(f"    AUTH-->>SUP: {_san(display)}")
        elif "TLS_CHANGE_CIPHER_SPEC" in kind or "TLS_FINISHED" in kind:
            if src_mac and src_mac == sup_mac:
                L.append(f"    SUP->>AUTH: {_san(display)}")
            else:
                L.append(f"    AUTH-->>SUP: {_san(display)}")
        elif "TLS_ALERT" in kind:
            L.append(f"    Note over SUP,AUTH: {_san(display)}")

        # EAP Success/Failure — from server through authenticator
        elif kind == "EAP_SUCCESS":
            L.append(f"    SRV-->>AUTH: EAP-Success")
            L.append(f"    AUTH->>SUP: {_san(display)}")
        elif kind == "EAP_FAILURE":
            L.append(f"    SRV-->>AUTH: EAP-Failure")
            L.append(f"    AUTH-->>SUP: {_san(display)}")

        # RADIUS packets — between authenticator and server
        elif kind == "RADIUS_ACCESS_REQUEST":
            L.append(f"    AUTH->>SRV: {_san(display)}")
        elif kind == "RADIUS_ACCESS_ACCEPT":
            L.append(f"    SRV-->>AUTH: {_san(display)}")
        elif kind == "RADIUS_ACCESS_REJECT":
            L.append(f"    SRV-->>AUTH: {_san(display)}")
        elif kind == "RADIUS_ACCESS_CHALLENGE":
            L.append(f"    SRV-->>AUTH: {_san(display)}")
        elif kind.startswith("RADIUS_"):
            L.append(f"    AUTH->>SRV: {_san(display)}")

        # Generic EAPOL or unknown — just note it
        else:
            L.append(f"    Note over SUP,AUTH: {_san(display)}")

    L.append("")

    # ── Summary ──────────────────────────────────────────────────────────
    has_success = any(e.get("kind") == "EAP_SUCCESS" for e in evts)
    has_failure = any(e.get("kind") == "EAP_FAILURE" for e in evts)
    has_accept = any(e.get("kind") == "RADIUS_ACCESS_ACCEPT" for e in evts)
    has_reject = any(e.get("kind") == "RADIUS_ACCESS_REJECT" for e in evts)

    if has_success or has_accept:
        color = "200, 255, 200"
        verdict = "[PASS] Authentication Successful"
    elif has_failure or has_reject:
        color = "255, 200, 200"
        verdict = "[FAIL] Authentication Failed"
    else:
        color = "255, 255, 200"
        verdict = "[?] Authentication Incomplete"

    n_eapol = sum(1 for e in evts if e.get("kind", "").startswith(("EAPOL_", "EAP_")))
    n_radius = sum(1 for e in evts if e.get("kind", "").startswith("RADIUS_"))
    summary = f"{verdict}<br/>{n_eapol} EAP frames, {n_radius} RADIUS packets"

    L.append(f"    rect rgb({color})")
    L.append(f"    Note over SUP,SRV: {_san(summary)}")
    L.append(f"    end")

    return "\n".join(L)


# ═══════════════════════════════════════════════════════════════════════════
# EAPOL Wire Trace — HORIZONTAL flowchart (graph LR)
# ═══════════════════════════════════════════════════════════════════════════

def generate_eapol_horizontal(
    events: list[dict],
    *,
    title: str = "EAPOL / EAP-TLS Wire Trace (Horizontal)",
) -> str:
    """Horizontal ``graph LR`` version of the EAPOL wire trace."""
    from dataclasses import asdict as _asdict

    evts: list[dict] = []
    for e in events:
        if hasattr(e, "kind"):
            evts.append(_asdict(e))
        else:
            evts.append(e)

    if not evts:
        return "graph LR\n    NOTE[\"No EAPOL events captured\"]"

    # Discover participants
    sup_mac = ""
    auth_mac = ""
    radius_ip = ""
    sup_identity = ""
    for ev in evts:
        kind = ev.get("kind", "")
        meta = ev.get("metadata", {})
        if kind in ("EAPOL_START", "EAP_RESPONSE_IDENTITY") and not sup_mac:
            sup_mac = meta.get("src_mac", "") or ev.get("endpoint_mac", "")
            auth_mac = meta.get("dst_mac", "")
        if kind == "EAP_RESPONSE_IDENTITY":
            sup_identity = meta.get("identity", "") or ev.get("username", "") or ""
        if kind.startswith("RADIUS_") and not radius_ip:
            radius_ip = ev.get("dst_ip") or ev.get("src_ip") or ""

    sup_label = _san(sup_mac or "Endpoint", 30)
    if sup_identity:
        sup_label += f"\\n{_san(sup_identity, 30)}"
    auth_label = _san(auth_mac or "Authenticator", 30)
    rad_label = _san(radius_ip or "Auth Server", 30)

    L: list[str] = []
    styles: list[str] = []
    L.append("graph LR")
    L.append("")
    L.append(f'    SUP(["Supplicant\\n{sup_label}"])')
    L.append(f'    AUTH["Authenticator\\n{auth_label}"]')
    L.append(f'    SRV["Auth Server\\n{rad_label}"]')
    L.append("")
    L.append(f'    TITLE["{_san(title, 60)}"]')
    L.append(f"    TITLE --> SUP")
    L.append("")

    nid = 0
    prev_node = "SUP"

    for ev in evts:
        kind = ev.get("kind", "")
        display = _KIND_DISPLAY.get(kind, kind.replace("_", " "))
        nid += 1
        node = f"e{nid}"

        # Determine which participant lane
        if kind in ("EAPOL_START", "EAPOL_LOGOFF"):
            L.append(f'    {prev_node} --> {node}["{_san(display, 40)}"]')
            L.append(f"    {node} --> AUTH")
            prev_node = node
        elif kind.startswith("EAP_RESPONSE") or "TLS_CLIENT" in kind or "CERTIFICATE_VERIFY" in kind:
            L.append(f'    {prev_node} --> {node}["{_san(display, 40)}"]')
            L.append(f"    {node} --> AUTH")
            prev_node = node
        elif kind.startswith("EAP_REQUEST") or "TLS_SERVER" in kind or "CERTIFICATE_REQUEST" in kind:
            L.append(f'    AUTH --> {node}["{_san(display, 40)}"]')
            L.append(f"    {node} --> {prev_node}")
            prev_node = node
        elif kind == "EAP_SUCCESS":
            L.append(f'    SRV --> {node}(["{_san(display, 40)}"])')
            L.append(f"    {node} --> AUTH")
            prev_node = node
            styles.append(f"style {node} fill:#c8e6c9,stroke:#2e7d32,color:#1b5e20")
        elif kind == "EAP_FAILURE":
            L.append(f'    SRV --> {node}(["{_san(display, 40)}"])')
            L.append(f"    {node} --> AUTH")
            prev_node = node
            styles.append(f"style {node} fill:#ffcdd2,stroke:#c62828,color:#b71c1c")
        elif kind.startswith("RADIUS_ACCESS_REQUEST"):
            L.append(f'    AUTH --> {node}["{_san(display, 40)}"]')
            L.append(f"    {node} --> SRV")
            prev_node = node
        elif kind.startswith("RADIUS_"):
            L.append(f'    SRV --> {node}["{_san(display, 40)}"]')
            L.append(f"    {node} --> AUTH")
            prev_node = node
            if "ACCEPT" in kind:
                styles.append(f"style {node} fill:#c8e6c9,stroke:#2e7d32,color:#1b5e20")
            elif "REJECT" in kind:
                styles.append(f"style {node} fill:#ffcdd2,stroke:#c62828,color:#b71c1c")
        else:
            L.append(f'    {prev_node} --> {node}["{_san(display, 40)}"]')
            prev_node = node

    L.append("")

    # Verdict
    has_success = any(e.get("kind") == "EAP_SUCCESS" for e in evts)
    has_failure = any(e.get("kind") == "EAP_FAILURE" for e in evts)
    has_accept = any(e.get("kind") == "RADIUS_ACCESS_ACCEPT" for e in evts)

    if has_success or has_accept:
        verdict = "[PASS] Authentication Successful"
        styles.append("style VERDICT fill:#c8e6c9,stroke:#2e7d32,color:#1b5e20,stroke-width:3px")
    elif has_failure:
        verdict = "[FAIL] Authentication Failed"
        styles.append("style VERDICT fill:#ffcdd2,stroke:#c62828,color:#b71c1c,stroke-width:3px")
    else:
        verdict = "[?] Authentication Incomplete"
        styles.append("style VERDICT fill:#fff9c4,stroke:#f9a825,color:#f57f17,stroke-width:3px")

    n_eapol = sum(1 for e in evts if e.get("kind", "").startswith(("EAPOL_", "EAP_")))
    n_radius = sum(1 for e in evts if e.get("kind", "").startswith("RADIUS_"))

    L.append(f'    VERDICT(["{_san(verdict, 50)}\\n{n_eapol} EAP, {n_radius} RADIUS"])')
    L.append(f"    {prev_node} --> VERDICT")
    L.append("")

    # Styles
    L.append("    style SUP fill:#1565c0,stroke:#0d47a1,color:#fff")
    L.append("    style AUTH fill:#00695c,stroke:#004d40,color:#fff")
    L.append("    style SRV fill:#e65100,stroke:#bf360c,color:#fff")
    L.append("    style TITLE fill:#263238,stroke:#455a64,color:#eceff1,stroke-width:2px")
    for s in styles:
        L.append(f"    {s}")

    return "\n".join(L)


# ═══════════════════════════════════════════════════════════════════════════
# CLI entry point
# ═══════════════════════════════════════════════════════════════════════════

def main() -> None:
    """Read a bundle JSON and write Mermaid markup (.mmd)."""
    import argparse

    parser = argparse.ArgumentParser(
        description="Generate a Mermaid sequence diagram from a TestPulse evidence bundle."
    )
    parser.add_argument("bundle", type=Path, help="Path to evidence_bundle.json")
    parser.add_argument(
        "--out", type=Path, default=None,
        help="Output .mmd path (default: <bundle>.mmd)",
    )
    args = parser.parse_args()

    bundle = json.loads(args.bundle.read_text(encoding="utf-8"))
    markup = generate_mermaid(bundle)

    out = args.out or args.bundle.with_suffix(".mmd")
    out.write_text(markup, encoding="utf-8")
    print(markup)
    print(f"\n[OK] Wrote Mermaid diagram: {out}  ({len(markup)} chars)", file=sys.stderr)


if __name__ == "__main__":
    main()
