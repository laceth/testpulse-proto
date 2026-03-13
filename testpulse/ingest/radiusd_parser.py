"""Parse FreeRADIUS radiusd.log for RADIUS packet events with full metadata.

Real log format (Forescout FreeRADIUS debug output)::

    radiusd:PID:EPOCH:Day Mon DD HH:MM:SS YYYY: Day Mon DD HH:MM:SS YYYY : Debug: (N)
      Received Access-Request Id N from IP:port to IP:port length N
      Sent Access-Accept  Id N from IP:port to IP:port length N
      Sent Access-Reject  Id N from IP:port to IP:port length N

Attribute lines follow packet headers::

      User-Name = "98f2b301a055"
      Service-Type = Call-Check
      Framed-MTU = 1500
      Called-Station-Id = "00-6B-F1-56-66-40"
      Calling-Station-Id = "98-F2-B3-01-A0-55"
      Cisco-AVPair = "audit-session-id=0A10801100000023133B281C"
      Cisco-AVPair = "method=mab"
      NAS-IP-Address = 10.16.128.17
      NAS-Port-Id = "TenGigabitEthernet1/1"
      NAS-Port-Type = Ethernet
      NAS-Port = 50101

Accept/Reject events are correlated back to their originating Request
using the RADIUS Id, so that response events inherit the request's
attributes (MAC, username, method, NAS info, etc.).
"""
from __future__ import annotations

import re
from typing import Any
from testpulse.models import AuthEvent

# ---------------------------------------------------------------------------
# Log-prefix parsing: ``radiusd:PID:EPOCH:Day Mon DD HH:MM:SS YYYY:``
# ---------------------------------------------------------------------------
PREFIX = re.compile(
    r"radiusd:(?P<pid>\d+):(?P<epoch>\d+(?:\.\d+)?):"
    r"(?P<ts>[A-Z][a-z]{2}\s+[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+\d{4}):"
)

# Fallback: capture the timestamp that appears *before* ``Debug:``
TS_RADIUSD = re.compile(
    r"(?P<ts>[A-Z][a-z]{2}\s+[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+\d{4})\s*:\s*Debug:",
)
TS_ISO = re.compile(r"(?P<ts>\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?)")

# ---------------------------------------------------------------------------
# Packet-header regex — captures Id, src, dst, length
# ---------------------------------------------------------------------------
PACKET_LINE = re.compile(
    r"(?P<action>Sent|Received)\s+(?P<type>Access-Accept|Access-Reject|Access-Request)"
    r"\s+Id\s+(?P<id>\d+)"
    r"\s+from\s+(?P<src_ip>[\d.]+):(?P<src_port>\d+)"
    r"\s+to\s+(?P<dst_ip>[\d.]+):(?P<dst_port>\d+)"
    r"\s+length\s+(?P<length>\d+)",
    re.IGNORECASE,
)

# Simpler matchers (kept for lines that may lack the from/to/length suffix)
SENT_ACCEPT = re.compile(r"Sent\s+Access-Accept\s+Id\s+(?P<id>\d+)", re.IGNORECASE)
SENT_REJECT = re.compile(r"Sent\s+Access-Reject\s+Id\s+(?P<id>\d+)", re.IGNORECASE)
RECV_REQUEST = re.compile(r"Received\s+Access-Request\s+Id\s+(?P<id>\d+)", re.IGNORECASE)

# ---------------------------------------------------------------------------
# RADIUS attribute extraction
# ---------------------------------------------------------------------------
MAC = re.compile(r"(?P<mac>(?:[0-9A-Fa-f]{2}[:.-]){5}[0-9A-Fa-f]{2})")
USER = re.compile(r'User-Name\s*=\s*"?(?P<user>[^"\s,;]+)', re.IGNORECASE)
PORT = re.compile(r'NAS-Port\s*=\s*(?P<port>\d+)', re.IGNORECASE)
PORT_ID = re.compile(r'NAS-Port-Id\s*=\s*"?(?P<port_id>[^"\s]+)', re.IGNORECASE)
PORT_TYPE = re.compile(r'NAS-Port-Type\s*=\s*(?P<port_type>[^\s,;]+)', re.IGNORECASE)
CALLING_SID = re.compile(r'Calling-Station-Id\s*=\s*"?(?P<csid>[^"\s]+)', re.IGNORECASE)
CALLED_SID = re.compile(r'Called-Station-Id\s*=\s*"?(?P<dsid>[^"\s]+)', re.IGNORECASE)
NAS_IP = re.compile(r'NAS-IP-Address\s*=\s*(?P<nasip>[^\s,;]+)', re.IGNORECASE)
AUDIT_SID = re.compile(r'audit-session-id=(?P<asid>[^"\s,;]+)', re.IGNORECASE)
METHOD = re.compile(r'method=(?P<method>[^"\s,;]+)', re.IGNORECASE)
SERVICE_TYPE = re.compile(r'Service-Type\s*=\s*"?(?P<stype>[^"\s,;]+(?:[- ]?[^"\s,;]+)?)', re.IGNORECASE)
FRAMED_MTU = re.compile(r'Framed-MTU\s*=\s*(?P<mtu>\d+)', re.IGNORECASE)

# Kind mapping
_KIND_MAP = {
    ("Received", "Access-Request"): "RADIUS_ACCESS_REQUEST",
    ("Sent", "Access-Accept"): "RADIUS_ACCESS_ACCEPT",
    ("Sent", "Access-Reject"): "RADIUS_ACCESS_REJECT",
}


def _extract_prefix(line: str) -> dict[str, Any]:
    """Extract PID, epoch, and timestamp from the radiusd log prefix."""
    info: dict[str, Any] = {"ts": None, "pid": None, "epoch": None}
    m = PREFIX.search(line)
    if m:
        info["pid"] = int(m.group("pid"))
        info["epoch"] = float(m.group("epoch"))
        info["ts"] = m.group("ts")
    else:
        m2 = TS_RADIUSD.search(line)
        if m2:
            info["ts"] = m2.group("ts")
        else:
            m3 = TS_ISO.search(line)
            if m3:
                info["ts"] = m3.group("ts")
    return info


def _extract_attrs(lines: list[str], start: int) -> tuple[dict[str, Any], int]:
    """Scan attribute lines following a packet header.

    Returns (attrs_dict, next_line_index).
    """
    attrs: dict[str, Any] = {}
    j = start
    while j < len(lines):
        attr_line = lines[j]
        # Stop at the next packet header
        if PACKET_LINE.search(attr_line) or SENT_ACCEPT.search(attr_line) or SENT_REJECT.search(attr_line) or RECV_REQUEST.search(attr_line):
            break
        # Stop at non-attribute, non-debug lines
        if "=" not in attr_line and "Debug:" not in attr_line:
            break
        # Limit look-ahead
        if j - start > 30:
            break

        um = USER.search(attr_line)
        if um:
            attrs["username"] = um.group("user")
        cm = CALLING_SID.search(attr_line)
        if cm:
            attrs["calling_station_id"] = cm.group("csid")
            mm = MAC.search(cm.group("csid"))
            if mm:
                attrs["endpoint_mac"] = mm.group("mac")
        dm = CALLED_SID.search(attr_line)
        if dm:
            attrs["called_station_id"] = dm.group("dsid")
        pm = PORT.search(attr_line)
        if pm:
            attrs["nas_port"] = pm.group("port")
        pi = PORT_ID.search(attr_line)
        if pi:
            attrs["nas_port_id"] = pi.group("port_id")
        pt = PORT_TYPE.search(attr_line)
        if pt:
            attrs["nas_port_type"] = pt.group("port_type")
        nm = NAS_IP.search(attr_line)
        if nm:
            attrs["nas_ip"] = nm.group("nasip")
        am = AUDIT_SID.search(attr_line)
        if am:
            attrs["session_id"] = am.group("asid")
        mm2 = METHOD.search(attr_line)
        if mm2:
            attrs["auth_method"] = mm2.group("method")
        st = SERVICE_TYPE.search(attr_line)
        if st:
            attrs["service_type"] = st.group("stype")
        fm = FRAMED_MTU.search(attr_line)
        if fm:
            attrs["framed_mtu"] = int(fm.group("mtu"))

        j += 1

    return attrs, j


def parse_radiusd(text: str) -> list[AuthEvent]:
    """Parse radiusd.log text, returning RADIUS packet events with full metadata.

    Accept/Reject events are correlated back to their originating Request
    using the RADIUS Id so that response events carry forward request
    attributes (MAC, username, NAS info, auth method, etc.).
    """
    lines = text.splitlines()
    events: list[AuthEvent] = []
    # Map radius_id → request attrs for correlation
    request_attrs: dict[int, dict[str, Any]] = {}

    i = 0
    while i < len(lines):
        line = lines[i]

        # Try the full packet-header regex first
        pm = PACKET_LINE.search(line)
        if pm:
            action = pm.group("action")
            ptype = pm.group("type")
            radius_id = int(pm.group("id"))
            src_ip = pm.group("src_ip")
            src_port = int(pm.group("src_port"))
            dst_ip = pm.group("dst_ip")
            dst_port = int(pm.group("dst_port"))
            pkt_len = int(pm.group("length"))
            prefix = _extract_prefix(line)
            kind = _KIND_MAP.get((action, ptype), f"RADIUS_{action.upper()}_{ptype.upper().replace('-', '_')}")

            # Look ahead for attributes
            attrs, next_i = _extract_attrs(lines, i + 1)

            # Infer auth_method from Service-Type when method= not present
            if "auth_method" not in attrs and attrs.get("service_type", "").lower().replace("-", " ").startswith("call check"):
                attrs["auth_method"] = "mab"

            # For requests: store attrs indexed by radius_id for later
            if ptype == "Access-Request":
                request_attrs[radius_id] = attrs.copy()

            # For Accept/Reject: inherit request attrs via radius_id
            if ptype in ("Access-Accept", "Access-Reject"):
                req = request_attrs.get(radius_id, {})
                # Request attrs are base; any attrs on the response override
                merged = {**req, **attrs}
                attrs = merged

            ev = AuthEvent(
                ts=prefix["ts"],
                kind=kind,
                source="radiusd.log",
                message=line.strip(),
                radius_id=radius_id,
                src_ip=src_ip,
                src_port=src_port,
                dst_ip=dst_ip,
                dst_port=dst_port,
                packet_length=pkt_len,
                pid=prefix["pid"],
                epoch=prefix["epoch"],
                endpoint_mac=attrs.get("endpoint_mac"),
                username=attrs.get("username"),
                nas_port=attrs.get("nas_port"),
                nas_port_id=attrs.get("nas_port_id"),
                nas_port_type=attrs.get("nas_port_type"),
                nas_ip=attrs.get("nas_ip"),
                calling_station_id=attrs.get("calling_station_id"),
                called_station_id=attrs.get("called_station_id"),
                session_id=attrs.get("session_id"),
                auth_method=attrs.get("auth_method"),
                service_type=attrs.get("service_type"),
                framed_mtu=attrs.get("framed_mtu"),
                raw_line=line,
            )
            events.append(ev)
            i = next_i
            continue

        # Fallback: simpler matchers for lines without from/to/length
        for regex, kind in [
            (SENT_ACCEPT, "RADIUS_ACCESS_ACCEPT"),
            (SENT_REJECT, "RADIUS_ACCESS_REJECT"),
            (RECV_REQUEST, "RADIUS_ACCESS_REQUEST"),
        ]:
            sm = regex.search(line)
            if sm:
                prefix = _extract_prefix(line)
                radius_id = int(sm.group("id"))
                attrs, next_i = _extract_attrs(lines, i + 1)

                if kind == "RADIUS_ACCESS_REQUEST":
                    request_attrs[radius_id] = attrs.copy()
                elif kind in ("RADIUS_ACCESS_ACCEPT", "RADIUS_ACCESS_REJECT"):
                    req = request_attrs.get(radius_id, {})
                    attrs = {**req, **attrs}

                ev = AuthEvent(
                    ts=prefix["ts"],
                    kind=kind,
                    source="radiusd.log",
                    message=line.strip(),
                    radius_id=radius_id,
                    pid=prefix["pid"],
                    epoch=prefix["epoch"],
                    endpoint_mac=attrs.get("endpoint_mac"),
                    username=attrs.get("username"),
                    nas_port=attrs.get("nas_port"),
                    nas_port_id=attrs.get("nas_port_id"),
                    nas_port_type=attrs.get("nas_port_type"),
                    nas_ip=attrs.get("nas_ip"),
                    calling_station_id=attrs.get("calling_station_id"),
                    called_station_id=attrs.get("called_station_id"),
                    session_id=attrs.get("session_id"),
                    auth_method=attrs.get("auth_method"),
                    service_type=attrs.get("service_type"),
                    framed_mtu=attrs.get("framed_mtu"),
                    raw_line=line,
                )
                events.append(ev)
                i = next_i
                break
        else:
            i += 1

    return events
