"""Deep packet analysis tool for TestPulse — pcap inspection with display filters.

Provides:
1. Pure-Python deep packet analysis using scapy (no tshark required)
2. Launch Wireshark/tshark when available with pre-built display filters
3. Comprehensive BPF capture filter and Wireshark display filter reference
4. Frame-level summary reports for AAA/802.1X protocol analysis
5. Dual-NIC aware capture support for passthrough lab topologies

Usage (CLI)::

    # Analyse a pcap and print summary
    python -m testpulse.tools.pcap_analyzer --pcap artifacts/latest/pcap/appliance.pcap

    # Open in Wireshark with AAA display filters
    python -m testpulse.tools.pcap_analyzer --pcap capture.pcap --wireshark

    # Print BPF filter reference
    python -m testpulse.tools.pcap_analyzer --filters

Usage (API)::

    from testpulse.tools.pcap_analyzer import PcapAnalyzer
    analyzer = PcapAnalyzer("capture.pcap")
    report = analyzer.analyze()
    print(report.summary())
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# ═══════════════════════════════════════════════════════════════════════════
# BPF Capture Filters — reference for tcpdump / tshark -f / dumpcap
# ═══════════════════════════════════════════════════════════════════════════

BPF_FILTERS: dict[str, dict[str, str]] = {
    # ── Layer 2 ──────────────────────────────────────────────────────────
    "EAPOL (802.1X)": {
        "filter": "ether proto 0x888e",
        "description": "All EAPOL frames: Start, Logoff, EAP-Request/Response, "
                       "Success, Failure, Key exchanges",
        "layer": "L2",
    },
    "LLDP": {
        "filter": "ether proto 0x88cc",
        "description": "Link Layer Discovery Protocol — neighbor discovery",
        "layer": "L2",
    },
    "CDP": {
        "filter": "ether dst 01:00:0c:cc:cc:cc",
        "description": "Cisco Discovery Protocol — switch identification",
        "layer": "L2",
    },
    "STP": {
        "filter": "ether dst 01:80:c2:00:00:00",
        "description": "Spanning Tree Protocol",
        "layer": "L2",
    },
    "ARP": {
        "filter": "arp",
        "description": "Address Resolution Protocol — IP-to-MAC mapping",
        "layer": "L2",
    },
    "VLAN tagged": {
        "filter": "vlan",
        "description": "802.1Q VLAN-tagged frames",
        "layer": "L2",
    },

    # ── Layer 3 ──────────────────────────────────────────────────────────
    "RADIUS Auth": {
        "filter": "udp port 1812",
        "description": "RADIUS Authentication (Access-Request/Accept/Reject/Challenge)",
        "layer": "L3",
    },
    "RADIUS Acct": {
        "filter": "udp port 1813",
        "description": "RADIUS Accounting (Start/Stop/Interim)",
        "layer": "L3",
    },
    "RADIUS (all)": {
        "filter": "udp port 1812 or udp port 1813",
        "description": "All RADIUS traffic — authentication + accounting",
        "layer": "L3",
    },
    "LDAP": {
        "filter": "tcp port 389",
        "description": "LDAP bind/search/modify — Active Directory queries",
        "layer": "L3",
    },
    "LDAPS": {
        "filter": "tcp port 636",
        "description": "LDAP over TLS — encrypted AD queries",
        "layer": "L3",
    },
    "LDAP (all)": {
        "filter": "tcp port 389 or tcp port 636",
        "description": "LDAP + LDAPS combined",
        "layer": "L3",
    },
    "Kerberos": {
        "filter": "tcp port 88 or udp port 88",
        "description": "Kerberos authentication — TGT/TGS requests",
        "layer": "L3",
    },
    "ICMP": {
        "filter": "icmp",
        "description": "Ping (echo request/reply), TTL exceeded, destination unreachable",
        "layer": "L3",
    },
    "ICMPv6": {
        "filter": "icmp6",
        "description": "IPv6 ICMP — neighbor solicitation, router advertisement",
        "layer": "L3",
    },

    # ── Layer 4 / Application ────────────────────────────────────────────
    "DHCP": {
        "filter": "udp port 67 or udp port 68",
        "description": "DHCP Discover/Offer/Request/Ack — IP address assignment",
        "layer": "L4",
    },
    "DHCPv6": {
        "filter": "udp port 546 or udp port 547",
        "description": "DHCPv6 client/server communication",
        "layer": "L4",
    },
    "DNS": {
        "filter": "udp port 53 or tcp port 53",
        "description": "DNS queries and responses — hostname resolution",
        "layer": "L4",
    },
    "HTTP": {
        "filter": "tcp port 80",
        "description": "HTTP traffic — captive portal redirects, web auth",
        "layer": "L4",
    },
    "HTTPS/TLS": {
        "filter": "tcp port 443",
        "description": "HTTPS / TLS — certificate checks, SCEP, OCSP",
        "layer": "L4",
    },
    "SNMP": {
        "filter": "udp port 161 or udp port 162",
        "description": "SNMP polls and traps — switch/device queries",
        "layer": "L4",
    },
    "Syslog": {
        "filter": "udp port 514",
        "description": "Syslog messages from network devices",
        "layer": "L4",
    },
    "NTP": {
        "filter": "udp port 123",
        "description": "Network Time Protocol — clock synchronisation verification",
        "layer": "L4",
    },
    "SSH": {
        "filter": "tcp port 22",
        "description": "SSH — remote management, SCP file transfers",
        "layer": "L4",
    },
    "TACACS+": {
        "filter": "tcp port 49",
        "description": "TACACS+ — switch/router AAA to auth server",
        "layer": "L4",
    },

    # ── Composite filters ────────────────────────────────────────────────
    "AAA Full Stack": {
        "filter": "(ether proto 0x888e) or (udp port 1812 or udp port 1813) "
                  "or (tcp port 389 or tcp port 636) or (tcp port 88 or udp port 88)",
        "description": "Complete AAA path: EAPOL + RADIUS + LDAP/S + Kerberos",
        "layer": "composite",
    },
    "802.1X Endpoint View": {
        "filter": "(ether proto 0x888e) or arp or (udp port 67 or udp port 68) "
                  "or (udp port 53) or icmp",
        "description": "Endpoint perspective: EAPOL + ARP + DHCP + DNS + ICMP "
                       "(pre-auth to post-auth lifecycle)",
        "layer": "composite",
    },
    "Appliance Inbound": {
        "filter": "(udp port 1812 or udp port 1813) or (tcp port 389 or tcp port 636) "
                  "or (tcp port 88 or udp port 88) or (udp port 53) or (udp port 161)",
        "description": "Forescout appliance: RADIUS + LDAP + Kerberos + DNS + SNMP",
        "layer": "composite",
    },
    "Switch Control Plane": {
        "filter": "(ether proto 0x888e) or (udp port 1812 or udp port 1813) "
                  "or (ether proto 0x88cc) or (ether dst 01:00:0c:cc:cc:cc) "
                  "or (udp port 161 or udp port 162) or (udp port 514)",
        "description": "Switch: EAPOL + RADIUS + LLDP + CDP + SNMP + Syslog",
        "layer": "composite",
    },
}

# ── Wireshark Display Filters (used with -Y or in the filter bar) ────────

DISPLAY_FILTERS: dict[str, dict[str, str]] = {
    "EAPOL all": {
        "filter": "eapol",
        "description": "All EAPOL frames",
    },
    "EAP negotiation": {
        "filter": "eap",
        "description": "EAP frames: Identity, TLS, PEAP, MD5, Success, Failure",
    },
    "EAP-TLS handshake": {
        "filter": "eap && tls.handshake",
        "description": "EAP-TLS certificate exchange and TLS negotiation",
    },
    "EAP failures": {
        "filter": "eap.code == 4",
        "description": "EAP-Failure frames only",
    },
    "EAP successes": {
        "filter": "eap.code == 3",
        "description": "EAP-Success frames only",
    },
    "RADIUS requests": {
        "filter": "radius.code == 1",
        "description": "RADIUS Access-Request",
    },
    "RADIUS accepts": {
        "filter": "radius.code == 2",
        "description": "RADIUS Access-Accept",
    },
    "RADIUS rejects": {
        "filter": "radius.code == 3",
        "description": "RADIUS Access-Reject",
    },
    "RADIUS challenges": {
        "filter": "radius.code == 11",
        "description": "RADIUS Access-Challenge (mid-auth exchange)",
    },
    "RADIUS all": {
        "filter": "radius",
        "description": "All RADIUS packets",
    },
    "RADIUS with EAP-Message": {
        "filter": "radius && radius.EAP-Message",
        "description": "RADIUS packets carrying EAP payloads",
    },
    "LDAP bind": {
        "filter": "ldap.protocolOp == 0",
        "description": "LDAP Bind requests — AD authentication",
    },
    "LDAP search": {
        "filter": "ldap.protocolOp == 3",
        "description": "LDAP Search requests — attribute lookups",
    },
    "TLS Client Hello": {
        "filter": "tls.handshake.type == 1",
        "description": "TLS Client Hello — cipher suite negotiation start",
    },
    "TLS Certificate": {
        "filter": "tls.handshake.type == 11",
        "description": "TLS Certificate messages — cert chain exchange",
    },
    "DHCP DORA": {
        "filter": "dhcp",
        "description": "DHCP Discover/Offer/Request/Ack lifecycle",
    },
    "AAA Full Trace": {
        "filter": "eapol || radius || ldap || kerberos",
        "description": "Complete AAA: EAPOL + RADIUS + LDAP + Kerberos",
    },
}


# ═══════════════════════════════════════════════════════════════════════════
# Packet analysis (pure Python via scapy)
# ═══════════════════════════════════════════════════════════════════════════

@dataclass
class FrameSummary:
    """One-line summary of a captured frame."""
    number: int
    timestamp: float
    time_str: str
    src: str
    dst: str
    protocol: str
    length: int
    info: str


@dataclass
class ProtocolStats:
    """Per-protocol frame count and byte total."""
    name: str
    frame_count: int = 0
    total_bytes: int = 0
    first_seen: float = 0.0
    last_seen: float = 0.0


@dataclass
class AnalysisReport:
    """Results of deep pcap analysis."""
    pcap_path: str
    total_frames: int = 0
    total_bytes: int = 0
    duration_sec: float = 0.0
    first_timestamp: str = ""
    last_timestamp: str = ""
    protocol_stats: dict[str, ProtocolStats] = field(default_factory=dict)
    eapol_frames: list[FrameSummary] = field(default_factory=list)
    radius_frames: list[FrameSummary] = field(default_factory=list)
    ldap_frames: list[FrameSummary] = field(default_factory=list)
    dhcp_frames: list[FrameSummary] = field(default_factory=list)
    other_frames: list[FrameSummary] = field(default_factory=list)
    eap_result: str = ""  # "SUCCESS", "FAILURE", or ""
    radius_result: str = ""  # "ACCEPT", "REJECT", or ""

    def summary(self) -> str:
        """Human-readable analysis summary."""
        lines = [
            "=" * 70,
            "  TestPulse Deep Packet Analysis",
            "=" * 70,
            f"  File:       {self.pcap_path}",
            f"  Frames:     {self.total_frames:,}",
            f"  Bytes:      {self.total_bytes:,}",
            f"  Duration:   {self.duration_sec:.3f} s",
            f"  Time range: {self.first_timestamp} -> {self.last_timestamp}",
            "",
            "  Protocol Breakdown:",
        ]
        for name, stats in sorted(self.protocol_stats.items(),
                                   key=lambda x: -x[1].frame_count):
            lines.append(f"    {name:<25s} {stats.frame_count:>6,} frames  "
                         f"{stats.total_bytes:>10,} bytes")

        if self.eap_result:
            lines.append(f"\n  EAP Result:    {self.eap_result}")
        if self.radius_result:
            lines.append(f"  RADIUS Result: {self.radius_result}")

        if self.eapol_frames:
            lines.append(f"\n  EAPOL/EAP Frames ({len(self.eapol_frames)}):")
            for f in self.eapol_frames:
                lines.append(f"    #{f.number:<5d} {f.time_str}  "
                             f"{f.src} -> {f.dst}  {f.info}")

        if self.radius_frames:
            lines.append(f"\n  RADIUS Frames ({len(self.radius_frames)}):")
            for f in self.radius_frames[:50]:  # limit output
                lines.append(f"    #{f.number:<5d} {f.time_str}  "
                             f"{f.src} -> {f.dst}  {f.info}")
            if len(self.radius_frames) > 50:
                lines.append(f"    ... and {len(self.radius_frames) - 50} more")

        lines.append("=" * 70)
        return "\n".join(lines)

    def to_dict(self) -> dict[str, Any]:
        """Serialisable dict for JSON output."""
        return {
            "pcap_path": self.pcap_path,
            "total_frames": self.total_frames,
            "total_bytes": self.total_bytes,
            "duration_sec": self.duration_sec,
            "first_timestamp": self.first_timestamp,
            "last_timestamp": self.last_timestamp,
            "eap_result": self.eap_result,
            "radius_result": self.radius_result,
            "protocol_stats": {
                k: {"frames": v.frame_count, "bytes": v.total_bytes}
                for k, v in self.protocol_stats.items()
            },
            "eapol_frame_count": len(self.eapol_frames),
            "radius_frame_count": len(self.radius_frames),
            "ldap_frame_count": len(self.ldap_frames),
            "dhcp_frame_count": len(self.dhcp_frames),
        }


class PcapAnalyzer:
    """Deep packet analysis engine using scapy."""

    def __init__(self, pcap_path: str | Path):
        self.pcap_path = Path(pcap_path)
        if not self.pcap_path.exists():
            raise FileNotFoundError(f"PCAP file not found: {self.pcap_path}")

    def analyze(self) -> AnalysisReport:
        """Parse the pcap and produce a detailed analysis report."""
        try:
            from scapy.all import rdpcap, EAPOL, EAP, Ether, IP, UDP, TCP, DHCP
        except ImportError:
            raise ImportError("scapy required: pip install scapy")

        report = AnalysisReport(pcap_path=str(self.pcap_path))
        packets = rdpcap(str(self.pcap_path))
        report.total_frames = len(packets)

        if not packets:
            return report

        first_ts = float(packets[0].time)
        last_ts = float(packets[-1].time)
        report.duration_sec = last_ts - first_ts
        report.first_timestamp = datetime.fromtimestamp(
            first_ts, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
        report.last_timestamp = datetime.fromtimestamp(
            last_ts, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]

        for idx, pkt in enumerate(packets, start=1):
            pkt_len = len(pkt)
            report.total_bytes += pkt_len
            ts = float(pkt.time)
            time_str = datetime.fromtimestamp(
                ts, tz=timezone.utc).strftime("%H:%M:%S.%f")[:-3]

            # Determine src/dst (MAC or IP)
            src = dst = "?"
            if pkt.haslayer(Ether):
                src = pkt[Ether].src
                dst = pkt[Ether].dst
            if pkt.haslayer(IP):
                src = pkt[IP].src
                dst = pkt[IP].dst

            # Classify protocol
            proto = "OTHER"
            info = ""

            if pkt.haslayer(EAPOL):
                proto = "EAPOL"
                eapol = pkt[EAPOL]
                info = f"EAPOL type={eapol.type}"
                if pkt.haslayer(EAP):
                    eap = pkt[EAP]
                    code_names = {1: "Request", 2: "Response",
                                  3: "Success", 4: "Failure"}
                    code_str = code_names.get(eap.code, f"code={eap.code}")
                    type_str = ""
                    if hasattr(eap, "type") and eap.code in (1, 2):
                        type_names = {1: "Identity", 4: "MD5", 13: "TLS",
                                      25: "PEAP", 26: "MSCHAPv2"}
                        type_str = type_names.get(eap.type, f"type={eap.type}")
                    info = f"EAP {code_str} {type_str}".strip()
                    if eap.code == 3:
                        report.eap_result = "SUCCESS"
                    elif eap.code == 4:
                        report.eap_result = "FAILURE"

                frame = FrameSummary(idx, ts, time_str, src, dst,
                                     proto, pkt_len, info)
                report.eapol_frames.append(frame)

            elif pkt.haslayer(UDP) and pkt.haslayer(IP):
                udp = pkt[UDP]
                if udp.dport in (1812, 1813) or udp.sport in (1812, 1813):
                    proto = "RADIUS"
                    # Try to decode RADIUS code from payload
                    raw = bytes(udp.payload)
                    if len(raw) >= 1:
                        code_map = {1: "Access-Request", 2: "Access-Accept",
                                    3: "Access-Reject", 4: "Accounting-Request",
                                    5: "Accounting-Response",
                                    11: "Access-Challenge"}
                        code = raw[0]
                        info = code_map.get(code, f"code={code}")
                        if code == 2:
                            report.radius_result = "ACCEPT"
                        elif code == 3:
                            report.radius_result = "REJECT"

                    frame = FrameSummary(idx, ts, time_str, src, dst,
                                         proto, pkt_len, info)
                    report.radius_frames.append(frame)

                elif udp.dport in (67, 68) or udp.sport in (67, 68):
                    proto = "DHCP"
                    info = "DHCP"
                    if pkt.haslayer(DHCP):
                        opts = pkt[DHCP].options
                        for opt in opts:
                            if isinstance(opt, tuple) and opt[0] == "message-type":
                                dhcp_types = {1: "Discover", 2: "Offer",
                                              3: "Request", 5: "Ack", 6: "Nak"}
                                info = f"DHCP {dhcp_types.get(opt[1], str(opt[1]))}"
                                break
                    frame = FrameSummary(idx, ts, time_str, src, dst,
                                         proto, pkt_len, info)
                    report.dhcp_frames.append(frame)

                elif udp.dport == 53 or udp.sport == 53:
                    proto = "DNS"
                    info = "DNS query/response"
                elif udp.dport == 123 or udp.sport == 123:
                    proto = "NTP"
                    info = "NTP"
                elif udp.dport in (161, 162) or udp.sport in (161, 162):
                    proto = "SNMP"
                    info = "SNMP"
                elif udp.dport == 514 or udp.sport == 514:
                    proto = "Syslog"
                    info = "Syslog"

            elif pkt.haslayer(TCP) and pkt.haslayer(IP):
                tcp = pkt[TCP]
                if tcp.dport in (389,) or tcp.sport in (389,):
                    proto = "LDAP"
                    info = "LDAP"
                    frame = FrameSummary(idx, ts, time_str, src, dst,
                                         proto, pkt_len, info)
                    report.ldap_frames.append(frame)
                elif tcp.dport in (636,) or tcp.sport in (636,):
                    proto = "LDAPS"
                    info = "LDAPS"
                    frame = FrameSummary(idx, ts, time_str, src, dst,
                                         proto, pkt_len, info)
                    report.ldap_frames.append(frame)
                elif tcp.dport in (88,) or tcp.sport in (88,):
                    proto = "Kerberos"
                    info = "Kerberos"
                elif tcp.dport == 80 or tcp.sport == 80:
                    proto = "HTTP"
                    info = "HTTP"
                elif tcp.dport == 443 or tcp.sport == 443:
                    proto = "TLS/HTTPS"
                    info = "TLS/HTTPS"

            # Update protocol stats
            if proto not in report.protocol_stats:
                report.protocol_stats[proto] = ProtocolStats(
                    name=proto, first_seen=ts)
            stats = report.protocol_stats[proto]
            stats.frame_count += 1
            stats.total_bytes += pkt_len
            stats.last_seen = ts

        return report


# ═══════════════════════════════════════════════════════════════════════════
# Wireshark / tshark launcher
# ═══════════════════════════════════════════════════════════════════════════

def find_wireshark() -> str | None:
    """Find Wireshark GUI executable on PATH or known locations."""
    # Check PATH
    ws = shutil.which("wireshark")
    if ws:
        return ws
    # WSL: check Windows-side Wireshark
    for win_path in [
        "/mnt/c/Program Files/Wireshark/Wireshark.exe",
        "/mnt/c/Program Files (x86)/Wireshark/Wireshark.exe",
    ]:
        if os.path.isfile(win_path):
            return win_path
    return None


def find_tshark() -> str | None:
    """Find tshark CLI on PATH or known locations."""
    ts = shutil.which("tshark")
    if ts:
        return ts
    # WSL: check Windows-side tshark
    for win_path in [
        "/mnt/c/Program Files/Wireshark/tshark.exe",
        "/mnt/c/Program Files (x86)/Wireshark/tshark.exe",
    ]:
        if os.path.isfile(win_path):
            return win_path
    return None


def _wsl_path(posix_path: str) -> str:
    """Convert a POSIX path to a Windows path if running under WSL."""
    try:
        result = subprocess.run(
            ["wslpath", "-w", posix_path],
            capture_output=True, text=True, timeout=5,
        )
        if result.returncode == 0 and result.stdout.strip():
            return result.stdout.strip()
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass
    return posix_path


def launch_wireshark(
    pcap_path: str | Path,
    display_filter: str = "",
    wireshark_exe: str | None = None,
) -> bool:
    """Open a pcap file in Wireshark GUI.

    Returns True if Wireshark was launched successfully.
    """
    exe = wireshark_exe or find_wireshark()
    if not exe:
        return False

    pcap_str = str(Path(pcap_path).resolve())

    # If using Windows Wireshark from WSL, convert the path
    if exe.startswith("/mnt/"):
        pcap_str = _wsl_path(pcap_str)

    cmd = [exe, "-r", pcap_str]
    if display_filter:
        cmd.extend(["-Y", display_filter])

    print(f"[INFO] Launching Wireshark: {' '.join(cmd)}")
    subprocess.Popen(cmd, start_new_session=True,
                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return True


def launch_tshark(
    pcap_path: str | Path,
    display_filter: str = "",
    tshark_exe: str | None = None,
    max_packets: int = 200,
) -> str:
    """Run tshark on a pcap and return text output."""
    exe = tshark_exe or find_tshark()
    if not exe:
        raise FileNotFoundError(
            "tshark not found. Install Wireshark:\n"
            "  Linux:   sudo apt install tshark\n"
            "  Windows: https://www.wireshark.org/download.html"
        )

    pcap_str = str(Path(pcap_path).resolve())
    if exe.startswith("/mnt/"):
        pcap_str = _wsl_path(pcap_str)

    cmd = [exe, "-r", pcap_str]
    if display_filter:
        cmd.extend(["-Y", display_filter])
    if max_packets > 0:
        cmd.extend(["-c", str(max_packets)])

    result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
    return result.stdout


# ═══════════════════════════════════════════════════════════════════════════
# Filter reference printer
# ═══════════════════════════════════════════════════════════════════════════

def print_filter_reference() -> str:
    """Format the complete BPF + display filter reference."""
    lines = [
        "=" * 78,
        "  TestPulse — Packet Capture Filter Reference",
        "=" * 78,
        "",
        "  BPF CAPTURE FILTERS (tcpdump -i <if> '<filter>', tshark -f '<filter>')",
        "  " + "-" * 74,
    ]

    current_layer = ""
    for name, info in BPF_FILTERS.items():
        layer = info["layer"]
        if layer != current_layer:
            current_layer = layer
            layer_labels = {"L2": "Layer 2 — Data Link",
                            "L3": "Layer 3 — Network / AAA",
                            "L4": "Layer 4 — Transport / Application",
                            "composite": "Composite — Multi-Protocol"}
            lines.append(f"\n  [{layer_labels.get(layer, layer)}]")

        lines.append(f"    {name}")
        lines.append(f"      BPF:  {info['filter']}")
        lines.append(f"      Desc: {info['description']}")
        lines.append("")

    lines.extend([
        "",
        "  WIRESHARK DISPLAY FILTERS (wireshark -Y '<filter>', filter bar)",
        "  " + "-" * 74,
    ])

    for name, info in DISPLAY_FILTERS.items():
        lines.append(f"    {name}")
        lines.append(f"      Filter: {info['filter']}")
        lines.append(f"      Desc:   {info['description']}")
        lines.append("")

    lines.extend([
        "  USAGE EXAMPLES",
        "  " + "-" * 74,
        "  # Capture EAPOL + RADIUS on eth0 for 60s:",
        "  tcpdump -i eth0 -w capture.pcap '(ether proto 0x888e) or (udp port 1812 or udp port 1813)'",
        "",
        "  # Capture full AAA stack on appliance:",
        "  tcpdump -i eth0 -w aaa.pcap '(ether proto 0x888e) or (udp port 1812 or udp port 1813) or (tcp port 389 or tcp port 636) or (tcp port 88 or udp port 88)'",
        "",
        "  # Capture on Windows passthrough (tshark):",
        '  tshark -i "Ethernet" -w capture.pcap -f "ether proto 0x888e or udp port 1812 or udp port 1813"',
        "",
        "  # Read pcap with RADIUS display filter:",
        "  tshark -r capture.pcap -Y 'radius.code == 2 || radius.code == 3'",
        "",
        "  # Open in Wireshark with AAA filter:",
        '  wireshark -r capture.pcap -Y "eapol || radius || ldap"',
        "",
        "  DUAL-NIC PASSTHROUGH CAPTURE",
        "  " + "-" * 74,
        "  Problem: 802.1X auth toggles the passthrough NIC, killing tshark.",
        "  Solution: Capture on the MANAGEMENT NIC (sees L3+ RADIUS/LDAP),",
        "            and use Switch SPAN for L2 EAPOL frames.",
        "",
        "  # Management NIC (survives toggle) — L3+ only:",
        '  tshark -i "Management" -w mgmt.pcap -f "udp port 1812 or udp port 1813 or tcp port 389"',
        "",
        "  # Switch SPAN (mirrors the 802.1X port) — L2 EAPOL:",
        "  # configure on switch: monitor session 1 source interface Gi3/1 both",
        "  #                      monitor session 1 destination interface Gi3/48",
        "  # then capture on host connected to SPAN dest port:",
        '  tcpdump -i eth0 -w span.pcap "ether proto 0x888e"',
        "",
        "=" * 78,
    ])
    return "\n".join(lines)


# ═══════════════════════════════════════════════════════════════════════════
# CLI
# ═══════════════════════════════════════════════════════════════════════════

def main() -> None:
    parser = argparse.ArgumentParser(
        description="TestPulse Deep Packet Analyzer — pcap inspection and Wireshark integration",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Examples:\n"
               "  %(prog)s --pcap capture.pcap\n"
               "  %(prog)s --pcap capture.pcap --wireshark\n"
               "  %(prog)s --pcap capture.pcap --wireshark --display-filter 'eapol || radius'\n"
               "  %(prog)s --filters\n",
    )
    parser.add_argument("--pcap", type=Path, nargs="+",
                        help="One or more pcap/pcapng files to analyze")
    parser.add_argument("--wireshark", action="store_true",
                        help="Launch Wireshark GUI with the pcap file(s)")
    parser.add_argument("--tshark", action="store_true",
                        help="Print tshark text decode of AAA frames")
    parser.add_argument("--display-filter", "-Y", default="",
                        help="Wireshark display filter (default: AAA Full Trace)")
    parser.add_argument("--filters", action="store_true",
                        help="Print BPF capture filter and Wireshark display filter reference")
    parser.add_argument("--json", action="store_true",
                        help="Output analysis report as JSON")
    parser.add_argument("--out", type=Path, default=None,
                        help="Write analysis report to file")

    args = parser.parse_args()

    if args.filters:
        ref = print_filter_reference()
        print(ref)
        if args.out:
            args.out.write_text(ref, encoding="utf-8")
            print(f"\n[OK] Filter reference saved to {args.out}")
        return

    if not args.pcap:
        parser.error("--pcap required (or use --filters for filter reference)")

    default_display = DISPLAY_FILTERS["AAA Full Trace"]["filter"]
    display = args.display_filter or default_display

    all_reports: list[dict] = []

    for pcap_path in args.pcap:
        if not pcap_path.exists():
            print(f"[WARN] File not found: {pcap_path}", file=sys.stderr)
            continue

        # Deep analysis (always runs)
        print(f"\n[INFO] Analyzing {pcap_path} ...")
        analyzer = PcapAnalyzer(pcap_path)
        report = analyzer.analyze()

        if args.json:
            all_reports.append(report.to_dict())
        else:
            print(report.summary())

        # Launch Wireshark if requested
        if args.wireshark:
            ws_exe = find_wireshark()
            if ws_exe:
                launch_wireshark(pcap_path, display_filter=display,
                                 wireshark_exe=ws_exe)
                print(f"[OK] Wireshark opened: {pcap_path}")
            else:
                print("[WARN] Wireshark not found. Install it:", file=sys.stderr)
                print("  Linux:   sudo apt install wireshark", file=sys.stderr)
                print("  Windows: https://www.wireshark.org/download.html",
                      file=sys.stderr)
                # Try Windows-side via explorer (WSL fallback)
                _try_wsl_open(pcap_path)

        # tshark text decode if requested
        if args.tshark:
            ts_exe = find_tshark()
            if ts_exe:
                print(f"\n[INFO] tshark decode ({display}):")
                output = launch_tshark(pcap_path, display_filter=display,
                                       tshark_exe=ts_exe)
                print(output)
            else:
                print("[WARN] tshark not found", file=sys.stderr)

    if args.json:
        output = json.dumps(all_reports, indent=2)
        if args.out:
            args.out.parent.mkdir(parents=True, exist_ok=True)
            args.out.write_text(output, encoding="utf-8")
            print(f"[OK] JSON report saved to {args.out}")
        else:
            print(output)
    elif args.out and not args.json:
        # Save text summary
        args.out.parent.mkdir(parents=True, exist_ok=True)
        texts = []
        for pcap_path in args.pcap:
            if pcap_path.exists():
                analyzer = PcapAnalyzer(pcap_path)
                report = analyzer.analyze()
                texts.append(report.summary())
        args.out.write_text("\n\n".join(texts), encoding="utf-8")
        print(f"[OK] Analysis report saved to {args.out}")


def _try_wsl_open(pcap_path: Path) -> None:
    """WSL fallback: try opening the pcap via Windows explorer."""
    try:
        win_path = _wsl_path(str(pcap_path.resolve()))
        subprocess.Popen(
            ["cmd.exe", "/c", "start", "", win_path],
            start_new_session=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        print(f"[INFO] Attempted Windows file association open: {win_path}")
    except Exception:
        pass


if __name__ == "__main__":
    main()
