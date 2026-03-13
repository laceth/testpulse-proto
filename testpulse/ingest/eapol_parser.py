"""Parse EAPOL / EAP / RADIUS frames from pcap capture files.

Uses **scapy** for deep EAP/EAPOL dissection and falls back to **dpkt**
for lightweight RADIUS or raw Ethernet parsing when scapy layers are
absent.

Supported frame types
~~~~~~~~~~~~~~~~~~~~~

* EAPOL-Start
* EAP-Request Identity / EAP-Response Identity
* EAP-Request (TLS, PEAP, MD5, etc.)  / EAP-Response
* EAP-Success / EAP-Failure
* RADIUS Access-Request / Access-Accept / Access-Reject
* TLS handshake sub-messages inside EAP-TLS (Client Hello, Server Hello,
  Certificate, Change Cipher Spec, Finished)

Each recognised frame becomes an :class:`~testpulse.models.AuthEvent` with
``source="pcap"`` and a ``kind`` string such as ``EAPOL_START``,
``EAP_REQUEST_IDENTITY``, ``EAP_TLS_CLIENT_HELLO``, ``RADIUS_ACCESS_ACCEPT``,
etc.
"""
from __future__ import annotations

import struct
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from testpulse.models import AuthEvent

# ---------------------------------------------------------------------------
# EAP / EAPOL constants (IEEE 802.1X-2004 / RFC 3748)
# ---------------------------------------------------------------------------
# EAPOL types (first byte after 802.1X header)
EAPOL_TYPE_EAP = 0
EAPOL_TYPE_START = 1
EAPOL_TYPE_LOGOFF = 2
EAPOL_TYPE_KEY = 3

# EAP codes
EAP_REQUEST = 1
EAP_RESPONSE = 2
EAP_SUCCESS = 3
EAP_FAILURE = 4

# EAP method types
EAP_TYPE_IDENTITY = 1
EAP_TYPE_NOTIFICATION = 2
EAP_TYPE_NAK = 3
EAP_TYPE_MD5 = 4
EAP_TYPE_TLS = 13
EAP_TYPE_PEAP = 25
EAP_TYPE_MSCHAP_V2 = 26
EAP_TYPE_EXPANDED = 254

EAP_TYPE_NAMES: dict[int, str] = {
    1: "IDENTITY",
    2: "NOTIFICATION",
    3: "NAK",
    4: "MD5",
    13: "TLS",
    25: "PEAP",
    26: "MSCHAP_V2",
    254: "EXPANDED",
}

# TLS content types (RFC 5246)
TLS_CHANGE_CIPHER_SPEC = 20
TLS_ALERT = 21
TLS_HANDSHAKE = 22
TLS_APPLICATION_DATA = 23

# TLS handshake message types
TLS_HELLO_REQUEST = 0
TLS_CLIENT_HELLO = 1
TLS_SERVER_HELLO = 2
TLS_CERTIFICATE = 11
TLS_SERVER_KEY_EXCHANGE = 12
TLS_CERTIFICATE_REQUEST = 13
TLS_SERVER_HELLO_DONE = 14
TLS_CERTIFICATE_VERIFY = 15
TLS_CLIENT_KEY_EXCHANGE = 16
TLS_FINISHED = 20

TLS_HS_NAMES: dict[int, str] = {
    0: "HELLO_REQUEST",
    1: "CLIENT_HELLO",
    2: "SERVER_HELLO",
    11: "CERTIFICATE",
    12: "SERVER_KEY_EXCHANGE",
    13: "CERTIFICATE_REQUEST",
    14: "SERVER_HELLO_DONE",
    15: "CERTIFICATE_VERIFY",
    16: "CLIENT_KEY_EXCHANGE",
    20: "FINISHED",
}

# RADIUS codes (RFC 2865)
RADIUS_ACCESS_REQUEST = 1
RADIUS_ACCESS_ACCEPT = 2
RADIUS_ACCESS_REJECT = 3
RADIUS_ACCOUNTING_REQUEST = 4
RADIUS_ACCOUNTING_RESPONSE = 5
RADIUS_ACCESS_CHALLENGE = 11

RADIUS_CODE_NAMES: dict[int, str] = {
    1: "ACCESS_REQUEST",
    2: "ACCESS_ACCEPT",
    3: "ACCESS_REJECT",
    4: "ACCOUNTING_REQUEST",
    5: "ACCOUNTING_RESPONSE",
    11: "ACCESS_CHALLENGE",
}


# ---------------------------------------------------------------------------
# MAC helpers
# ---------------------------------------------------------------------------
def _mac_str(raw: bytes) -> str:
    """Convert 6 raw bytes to colon-separated MAC string."""
    return ":".join(f"{b:02x}" for b in raw)


def _ts_from_epoch(epoch: float) -> str:
    """Human-readable UTC timestamp from pcap epoch."""
    return datetime.fromtimestamp(epoch, tz=timezone.utc).strftime(
        "%Y-%m-%d %H:%M:%S.%f"
    )


# ---------------------------------------------------------------------------
# TLS record inspection (for EAP-TLS payloads)
# ---------------------------------------------------------------------------
def _inspect_tls_payload(data: bytes) -> list[str]:
    """Return list of TLS event kind suffixes found in *data*.

    *data* should be the EAP-TLS payload (after the EAP-TLS flags byte and
    optional length field).  We look for TLS record headers and classify
    them.
    """
    kinds: list[str] = []
    offset = 0
    while offset + 5 <= len(data):
        content_type = data[offset]
        # TLS record: 1-byte type, 2-byte version, 2-byte length
        rec_len = struct.unpack("!H", data[offset + 3 : offset + 5])[0]
        if content_type == TLS_CHANGE_CIPHER_SPEC:
            kinds.append("CHANGE_CIPHER_SPEC")
        elif content_type == TLS_ALERT:
            kinds.append("ALERT")
        elif content_type == TLS_HANDSHAKE:
            # Parse handshake message type (first byte of payload)
            if offset + 5 < len(data):
                hs_type = data[offset + 5]
                name = TLS_HS_NAMES.get(hs_type, f"HS_{hs_type}")
                kinds.append(name)
        elif content_type == TLS_APPLICATION_DATA:
            kinds.append("APPLICATION_DATA")
        else:
            break  # not a TLS record — stop inspecting
        offset += 5 + rec_len
    return kinds


# ===================================================================
# Primary entry point — scapy-based
# ===================================================================
def parse_pcap(path: str | Path) -> list[AuthEvent]:
    """Parse a pcap/pcapng file and return AuthEvents for EAPOL/EAP/RADIUS frames.

    Requires **scapy** (≥ 2.5).  Falls back to :func:`parse_pcap_dpkt` if
    scapy is not available.
    """
    try:
        from scapy.all import rdpcap, Ether, Dot1Q, IP, UDP, Raw  # type: ignore
        from scapy.layers.eap import EAPOL as ScapyEAPOL, EAP as ScapyEAP  # type: ignore
        from scapy.layers.radius import Radius as ScapyRadius  # type: ignore
    except ImportError:
        return parse_pcap_dpkt(path)

    path = Path(path)
    if not path.exists():
        return []

    packets = rdpcap(str(path))
    events: list[AuthEvent] = []

    for pkt in packets:
        epoch = float(pkt.time)
        ts = _ts_from_epoch(epoch)
        src_mac = dst_mac = None

        if pkt.haslayer(Ether):
            src_mac = pkt[Ether].src
            dst_mac = pkt[Ether].dst

        # --- EAPOL / EAP ---------------------------------------------------
        if pkt.haslayer(ScapyEAPOL):
            eapol = pkt[ScapyEAPOL]
            eapol_type = eapol.type

            if eapol_type == EAPOL_TYPE_START:
                events.append(_make_event(
                    ts=ts, epoch=epoch, kind="EAPOL_START",
                    message=f"EAPOL-Start from {src_mac}",
                    endpoint_mac=src_mac, src_mac=src_mac, dst_mac=dst_mac,
                    raw_line=pkt.summary(),
                ))
                continue

            if eapol_type == EAPOL_TYPE_LOGOFF:
                events.append(_make_event(
                    ts=ts, epoch=epoch, kind="EAPOL_LOGOFF",
                    message=f"EAPOL-Logoff from {src_mac}",
                    endpoint_mac=src_mac, src_mac=src_mac, dst_mac=dst_mac,
                    raw_line=pkt.summary(),
                ))
                continue

            if pkt.haslayer(ScapyEAP):
                eap = pkt[ScapyEAP]
                eap_events = _classify_eap(eap, ts, epoch, src_mac, dst_mac, pkt)
                events.extend(eap_events)
                continue

            # EAPOL-Key or other — generic
            events.append(_make_event(
                ts=ts, epoch=epoch,
                kind=f"EAPOL_TYPE_{eapol_type}",
                message=f"EAPOL type {eapol_type} from {src_mac}",
                endpoint_mac=src_mac, src_mac=src_mac, dst_mac=dst_mac,
                raw_line=pkt.summary(),
            ))
            continue

        # --- RADIUS (UDP 1812/1813) ----------------------------------------
        if pkt.haslayer(ScapyRadius):
            rad = pkt[ScapyRadius]
            code_name = RADIUS_CODE_NAMES.get(rad.code, f"CODE_{rad.code}")
            kind = f"RADIUS_{code_name}"

            src_ip = dst_ip = None
            src_port = dst_port = None
            if pkt.haslayer(IP):
                src_ip = pkt[IP].src
                dst_ip = pkt[IP].dst
            if pkt.haslayer(UDP):
                src_port = pkt[UDP].sport
                dst_port = pkt[UDP].dport

            events.append(_make_event(
                ts=ts, epoch=epoch, kind=kind,
                message=f"RADIUS {code_name} id={rad.id}",
                src_ip=src_ip, dst_ip=dst_ip,
                src_port=src_port, dst_port=dst_port,
                radius_id=rad.id,
                packet_length=rad.len if hasattr(rad, "len") else None,
                raw_line=pkt.summary(),
            ))
            continue

        # --- Fallback: raw RADIUS on UDP 1812/1813 -------------------------
        if pkt.haslayer(UDP):
            udp = pkt[UDP]
            if udp.dport in (1812, 1813) or udp.sport in (1812, 1813):
                if pkt.haslayer(Raw):
                    raw_data = bytes(pkt[Raw].load)
                    rad_events = _parse_raw_radius(
                        raw_data, ts, epoch, pkt, src_mac, dst_mac
                    )
                    events.extend(rad_events)

    return events


def _classify_eap(
    eap: Any,
    ts: str,
    epoch: float,
    src_mac: str | None,
    dst_mac: str | None,
    pkt: Any,
) -> list[AuthEvent]:
    """Classify an EAP layer into one or more AuthEvents."""
    results: list[AuthEvent] = []
    code = eap.code
    eap_id = eap.id if hasattr(eap, "id") else None
    eap_type = getattr(eap, "type", None)

    code_str = {EAP_REQUEST: "REQUEST", EAP_RESPONSE: "RESPONSE"}.get(
        code, f"CODE_{code}"
    )

    # --- EAP-Success / EAP-Failure (no type field) -------------------------
    if code == EAP_SUCCESS:
        results.append(_make_event(
            ts=ts, epoch=epoch, kind="EAP_SUCCESS",
            message=f"EAP-Success id={eap_id}",
            endpoint_mac=dst_mac, src_mac=src_mac, dst_mac=dst_mac,
            raw_line=pkt.summary(),
            metadata={"eap_id": eap_id},
        ))
        return results

    if code == EAP_FAILURE:
        results.append(_make_event(
            ts=ts, epoch=epoch, kind="EAP_FAILURE",
            message=f"EAP-Failure id={eap_id}",
            endpoint_mac=dst_mac, src_mac=src_mac, dst_mac=dst_mac,
            raw_line=pkt.summary(),
            metadata={"eap_id": eap_id},
        ))
        return results

    if eap_type is None:
        results.append(_make_event(
            ts=ts, epoch=epoch,
            kind=f"EAP_{code_str}",
            message=f"EAP-{code_str} id={eap_id}",
            endpoint_mac=src_mac, src_mac=src_mac, dst_mac=dst_mac,
            raw_line=pkt.summary(),
            metadata={"eap_id": eap_id},
        ))
        return results

    type_name = EAP_TYPE_NAMES.get(eap_type, f"TYPE_{eap_type}")

    # --- Identity ----------------------------------------------------------
    if eap_type == EAP_TYPE_IDENTITY:
        identity = ""
        if hasattr(eap, "identity"):
            identity = eap.identity.decode(errors="replace") if isinstance(eap.identity, bytes) else str(eap.identity)
        elif hasattr(eap, "load"):
            identity = eap.load.decode(errors="replace") if isinstance(eap.load, bytes) else str(eap.load)
        kind = f"EAP_{code_str}_IDENTITY"
        results.append(_make_event(
            ts=ts, epoch=epoch, kind=kind,
            message=f"EAP-{code_str}/Identity \"{identity}\"",
            endpoint_mac=src_mac if code == EAP_RESPONSE else dst_mac,
            username=identity or None,
            src_mac=src_mac, dst_mac=dst_mac,
            raw_line=pkt.summary(),
            metadata={"eap_id": eap_id, "eap_type": eap_type, "identity": identity},
        ))
        return results

    # --- EAP-TLS -----------------------------------------------------------
    if eap_type == EAP_TYPE_TLS:
        # Try to inspect inner TLS records
        tls_payload = _extract_eap_tls_payload(eap)
        if tls_payload:
            tls_kinds = _inspect_tls_payload(tls_payload)
            if tls_kinds:
                for tlsk in tls_kinds:
                    kind = f"EAP_TLS_{tlsk}"
                    results.append(_make_event(
                        ts=ts, epoch=epoch, kind=kind,
                        message=f"EAP-{code_str}/TLS {tlsk}",
                        endpoint_mac=src_mac if code == EAP_RESPONSE else dst_mac,
                        src_mac=src_mac, dst_mac=dst_mac,
                        eap_type="TLS",
                        raw_line=pkt.summary(),
                        metadata={"eap_id": eap_id, "tls_event": tlsk},
                    ))
                return results

        # Generic EAP-TLS frame (fragment or start)
        kind = f"EAP_{code_str}_TLS"
        results.append(_make_event(
            ts=ts, epoch=epoch, kind=kind,
            message=f"EAP-{code_str}/TLS",
            endpoint_mac=src_mac if code == EAP_RESPONSE else dst_mac,
            src_mac=src_mac, dst_mac=dst_mac,
            eap_type="TLS",
            raw_line=pkt.summary(),
            metadata={"eap_id": eap_id, "eap_type": eap_type},
        ))
        return results

    # --- PEAP --------------------------------------------------------------
    if eap_type == EAP_TYPE_PEAP:
        tls_payload = _extract_eap_tls_payload(eap)
        if tls_payload:
            tls_kinds = _inspect_tls_payload(tls_payload)
            if tls_kinds:
                for tlsk in tls_kinds:
                    kind = f"EAP_PEAP_{tlsk}"
                    results.append(_make_event(
                        ts=ts, epoch=epoch, kind=kind,
                        message=f"EAP-{code_str}/PEAP {tlsk}",
                        endpoint_mac=src_mac if code == EAP_RESPONSE else dst_mac,
                        src_mac=src_mac, dst_mac=dst_mac,
                        eap_type="PEAP",
                        raw_line=pkt.summary(),
                        metadata={"eap_id": eap_id, "tls_event": tlsk},
                    ))
                return results

        kind = f"EAP_{code_str}_PEAP"
        results.append(_make_event(
            ts=ts, epoch=epoch, kind=kind,
            message=f"EAP-{code_str}/PEAP",
            endpoint_mac=src_mac if code == EAP_RESPONSE else dst_mac,
            src_mac=src_mac, dst_mac=dst_mac,
            eap_type="PEAP",
            raw_line=pkt.summary(),
            metadata={"eap_id": eap_id, "eap_type": eap_type},
        ))
        return results

    # --- Generic EAP method ------------------------------------------------
    kind = f"EAP_{code_str}_{type_name}"
    results.append(_make_event(
        ts=ts, epoch=epoch, kind=kind,
        message=f"EAP-{code_str}/{type_name}",
        endpoint_mac=src_mac if code == EAP_RESPONSE else dst_mac,
        src_mac=src_mac, dst_mac=dst_mac,
        raw_line=pkt.summary(),
        metadata={"eap_id": eap_id, "eap_type": eap_type},
    ))
    return results


def _extract_eap_tls_payload(eap: Any) -> bytes | None:
    """Extract the TLS record payload from an EAP-TLS or PEAP frame.

    EAP-TLS format (after EAP header):
        1 byte  — flags  (L, M, S bits + reserved)
        4 bytes — TLS message length (if L flag set)
        N bytes — TLS data
    """
    raw = None
    if hasattr(eap, "load"):
        raw = bytes(eap.load)
    elif hasattr(eap, "payload"):
        raw = bytes(eap.payload)
    if not raw or len(raw) < 2:
        return None

    flags = raw[0]
    offset = 1
    if flags & 0x80:  # L flag — length field present
        if len(raw) < 5:
            return None
        offset = 5
    return raw[offset:] if offset < len(raw) else None


# ---------------------------------------------------------------------------
# Raw RADIUS parsing (for packets not decoded by scapy Radius layer)
# ---------------------------------------------------------------------------
def _parse_raw_radius(
    data: bytes,
    ts: str,
    epoch: float,
    pkt: Any,
    src_mac: str | None,
    dst_mac: str | None,
) -> list[AuthEvent]:
    """Minimally parse RADIUS packet bytes (RFC 2865)."""
    if len(data) < 20:
        return []
    code = data[0]
    rad_id = data[1]
    length = struct.unpack("!H", data[2:4])[0]
    code_name = RADIUS_CODE_NAMES.get(code, f"CODE_{code}")

    from scapy.all import IP, UDP  # type: ignore

    src_ip = dst_ip = None
    src_port = dst_port = None
    if pkt.haslayer(IP):
        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst
    if pkt.haslayer(UDP):
        src_port = pkt[UDP].sport
        dst_port = pkt[UDP].dport

    return [_make_event(
        ts=ts, epoch=epoch,
        kind=f"RADIUS_{code_name}",
        message=f"RADIUS {code_name} id={rad_id} len={length}",
        src_ip=src_ip, dst_ip=dst_ip,
        src_port=src_port, dst_port=dst_port,
        radius_id=rad_id, packet_length=length,
        raw_line=pkt.summary() if hasattr(pkt, "summary") else "",
    )]


# ===================================================================
# Fallback — dpkt-based parser (no scapy)
# ===================================================================
def parse_pcap_dpkt(path: str | Path) -> list[AuthEvent]:
    """Lightweight pcap parser using **dpkt** when scapy is unavailable.

    Handles basic EAPOL frames and RADIUS packets.
    """
    import dpkt  # type: ignore

    path = Path(path)
    if not path.exists():
        return []

    events: list[AuthEvent] = []

    with open(path, "rb") as f:
        try:
            pcap = dpkt.pcap.Reader(f)
        except (ValueError, dpkt.dpkt.NeedData):
            try:
                f.seek(0)
                pcap = dpkt.pcapng.Reader(f)
            except Exception:
                return []

        for ts_epoch, buf in pcap:
            ts = _ts_from_epoch(ts_epoch)
            try:
                eth = dpkt.ethernet.Ethernet(buf)
            except Exception:
                continue

            src_mac = _mac_str(eth.src)
            dst_mac = _mac_str(eth.dst)

            # EAPOL ethertype = 0x888e
            if eth.type == 0x888E:
                eapol_events = _parse_dpkt_eapol(
                    bytes(eth.data), ts, ts_epoch, src_mac, dst_mac
                )
                events.extend(eapol_events)
                continue

            # 802.1Q tagged
            if eth.type == 0x8100 and hasattr(eth.data, "type") and eth.data.type == 0x888E:
                eapol_events = _parse_dpkt_eapol(
                    bytes(eth.data.data), ts, ts_epoch, src_mac, dst_mac
                )
                events.extend(eapol_events)
                continue

            # RADIUS over IP/UDP
            if isinstance(eth.data, dpkt.ip.IP):
                ip = eth.data
                if isinstance(ip.data, dpkt.udp.UDP):
                    udp = ip.data
                    if udp.dport in (1812, 1813) or udp.sport in (1812, 1813):
                        if len(udp.data) >= 20:
                            code = udp.data[0]
                            rad_id = udp.data[1]
                            length = struct.unpack("!H", udp.data[2:4])[0]
                            code_name = RADIUS_CODE_NAMES.get(code, f"CODE_{code}")
                            events.append(_make_event(
                                ts=ts, epoch=ts_epoch,
                                kind=f"RADIUS_{code_name}",
                                message=f"RADIUS {code_name} id={rad_id} len={length}",
                                src_ip=_ip_str(ip.src),
                                dst_ip=_ip_str(ip.dst),
                                src_port=udp.sport,
                                dst_port=udp.dport,
                                radius_id=rad_id,
                                packet_length=length,
                            ))

    return events


def _parse_dpkt_eapol(
    data: bytes, ts: str, epoch: float, src_mac: str, dst_mac: str
) -> list[AuthEvent]:
    """Decode EAPOL/EAP from raw bytes (dpkt fallback)."""
    results: list[AuthEvent] = []
    if len(data) < 4:
        return results

    # EAPOL header: version(1) type(1) length(2)
    eapol_type = data[1]
    eapol_length = struct.unpack("!H", data[2:4])[0]

    if eapol_type == EAPOL_TYPE_START:
        results.append(_make_event(
            ts=ts, epoch=epoch, kind="EAPOL_START",
            message=f"EAPOL-Start from {src_mac}",
            endpoint_mac=src_mac, src_mac=src_mac, dst_mac=dst_mac,
        ))
        return results

    if eapol_type == EAPOL_TYPE_LOGOFF:
        results.append(_make_event(
            ts=ts, epoch=epoch, kind="EAPOL_LOGOFF",
            message=f"EAPOL-Logoff from {src_mac}",
            endpoint_mac=src_mac, src_mac=src_mac, dst_mac=dst_mac,
        ))
        return results

    if eapol_type == EAPOL_TYPE_EAP:
        # EAP header: code(1) id(1) length(2) [type(1)]
        if len(data) < 8:
            return results
        eap_code = data[4]
        eap_id = data[5]
        eap_len = struct.unpack("!H", data[6:8])[0]

        if eap_code == EAP_SUCCESS:
            results.append(_make_event(
                ts=ts, epoch=epoch, kind="EAP_SUCCESS",
                message=f"EAP-Success id={eap_id}",
                endpoint_mac=dst_mac, src_mac=src_mac, dst_mac=dst_mac,
                metadata={"eap_id": eap_id},
            ))
            return results

        if eap_code == EAP_FAILURE:
            results.append(_make_event(
                ts=ts, epoch=epoch, kind="EAP_FAILURE",
                message=f"EAP-Failure id={eap_id}",
                endpoint_mac=dst_mac, src_mac=src_mac, dst_mac=dst_mac,
                metadata={"eap_id": eap_id},
            ))
            return results

        if eap_len > 4 and len(data) >= 9:
            eap_type = data[8]
            code_str = "REQUEST" if eap_code == EAP_REQUEST else "RESPONSE"
            type_name = EAP_TYPE_NAMES.get(eap_type, f"TYPE_{eap_type}")

            if eap_type == EAP_TYPE_IDENTITY:
                identity = data[9:4 + eap_len].decode(errors="replace") if len(data) > 9 else ""
                results.append(_make_event(
                    ts=ts, epoch=epoch,
                    kind=f"EAP_{code_str}_IDENTITY",
                    message=f"EAP-{code_str}/Identity \"{identity}\"",
                    endpoint_mac=src_mac if eap_code == EAP_RESPONSE else dst_mac,
                    username=identity or None,
                    src_mac=src_mac, dst_mac=dst_mac,
                    metadata={"eap_id": eap_id, "identity": identity},
                ))
                return results

            if eap_type in (EAP_TYPE_TLS, EAP_TYPE_PEAP):
                prefix = "TLS" if eap_type == EAP_TYPE_TLS else "PEAP"
                # Try inspecting TLS payload
                if len(data) > 9:
                    flags = data[9]
                    tls_offset = 10
                    if flags & 0x80:  # L flag
                        tls_offset = 14
                    tls_data = data[tls_offset:]
                    if tls_data:
                        tls_kinds = _inspect_tls_payload(tls_data)
                        if tls_kinds:
                            for tlsk in tls_kinds:
                                results.append(_make_event(
                                    ts=ts, epoch=epoch,
                                    kind=f"EAP_{prefix}_{tlsk}",
                                    message=f"EAP-{code_str}/{prefix} {tlsk}",
                                    endpoint_mac=src_mac if eap_code == EAP_RESPONSE else dst_mac,
                                    src_mac=src_mac, dst_mac=dst_mac,
                                    eap_type=prefix,
                                    metadata={"eap_id": eap_id, "tls_event": tlsk},
                                ))
                            return results

                results.append(_make_event(
                    ts=ts, epoch=epoch,
                    kind=f"EAP_{code_str}_{prefix}",
                    message=f"EAP-{code_str}/{prefix}",
                    endpoint_mac=src_mac if eap_code == EAP_RESPONSE else dst_mac,
                    src_mac=src_mac, dst_mac=dst_mac,
                    eap_type=prefix,
                    metadata={"eap_id": eap_id},
                ))
                return results

            # Generic EAP type
            results.append(_make_event(
                ts=ts, epoch=epoch,
                kind=f"EAP_{code_str}_{type_name}",
                message=f"EAP-{code_str}/{type_name}",
                endpoint_mac=src_mac, src_mac=src_mac, dst_mac=dst_mac,
                metadata={"eap_id": eap_id, "eap_type": eap_type},
            ))
            return results

    # Fallback for unknown EAPOL types
    results.append(_make_event(
        ts=ts, epoch=epoch,
        kind=f"EAPOL_TYPE_{eapol_type}",
        message=f"EAPOL type={eapol_type}",
        endpoint_mac=src_mac, src_mac=src_mac, dst_mac=dst_mac,
    ))
    return results


def _ip_str(raw: bytes) -> str:
    """Convert 4-byte IP to dotted-quad."""
    import socket
    return socket.inet_ntoa(raw)


# ---------------------------------------------------------------------------
# AuthEvent factory
# ---------------------------------------------------------------------------
def _make_event(
    *,
    ts: str,
    epoch: float,
    kind: str,
    message: str,
    endpoint_mac: str | None = None,
    username: str | None = None,
    src_mac: str | None = None,
    dst_mac: str | None = None,
    src_ip: str | None = None,
    dst_ip: str | None = None,
    src_port: int | None = None,
    dst_port: int | None = None,
    radius_id: int | None = None,
    packet_length: int | None = None,
    eap_type: str | None = None,
    raw_line: str | None = None,
    metadata: dict[str, Any] | None = None,
) -> AuthEvent:
    """Construct an AuthEvent with pcap-specific defaults."""
    meta = metadata or {}
    if src_mac:
        meta.setdefault("src_mac", src_mac)
    if dst_mac:
        meta.setdefault("dst_mac", dst_mac)

    return AuthEvent(
        ts=ts,
        kind=kind,
        source="pcap",
        message=message,
        endpoint_mac=endpoint_mac,
        username=username,
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=src_port,
        dst_port=dst_port,
        radius_id=radius_id,
        packet_length=packet_length,
        eap_type=eap_type,
        epoch=epoch,
        raw_line=raw_line,
        metadata=meta,
    )
