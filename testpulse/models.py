from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any


class Decision(str, Enum):
    ACCEPT = "accept"
    REJECT = "reject"
    UNKNOWN = "unknown"


@dataclass
class AuthEvent:
    """Core event extracted from any log source.

    Fields fall into three tiers:

    1. **Identity** — ``ts``, ``kind``, ``source``, ``message``
    2. **Auth context** — MAC, IP, username, NAS, session IDs
    3. **Rich metadata** — RADIUS packet details, dot1x plugin state,
       network topology, epoch/PID for precise correlation
    """

    # --- Tier 1: identity ---------------------------------------------------
    ts: str | None
    kind: str
    source: str
    message: str

    # --- Tier 2: auth context ------------------------------------------------
    testcase_id: str | None = None
    run_id: str | None = None
    session_id: str | None = None
    endpoint_mac: str | None = None
    endpoint_ip: str | None = None
    username: str | None = None
    machine_name: str | None = None
    nas_ip: str | None = None
    nas_port: str | None = None
    calling_station_id: str | None = None
    called_station_id: str | None = None
    acct_session_id: str | None = None

    # --- Tier 3: rich metadata (new) -----------------------------------------
    # RADIUS packet-level
    radius_id: int | None = None          # RADIUS Id from packet line
    src_ip: str | None = None             # sender IP
    src_port: int | None = None           # sender port
    dst_ip: str | None = None             # destination IP
    dst_port: int | None = None           # destination port
    packet_length: int | None = None      # RADIUS packet length
    service_type: str | None = None       # Service-Type attribute
    nas_port_type: str | None = None      # NAS-Port-Type (Ethernet, etc.)
    nas_port_id: str | None = None        # NAS-Port-Id (interface name)
    framed_mtu: int | None = None         # Framed-MTU value
    auth_method: str | None = None        # mab / eap-tls / peap

    # Process / timing
    epoch: float | None = None            # Unix epoch from log prefix
    pid: int | None = None                # Process ID from log prefix

    # dot1x plugin state
    plugin_version: str | None = None     # e.g. "4.8.6-48060050"
    policy_enabled: bool | None = None    # Policy-Enabled flag
    eap_type: str | None = None           # EAP-Type from policy config
    vlan_config: str | None = None        # VLAN / COA restriction string

    # Framework context
    context_id: str | None = None         # e.g. "dot1x@3922889344900135729"
    property_field: str | None = None     # dot1x_auth_state, etc.
    property_value: str | None = None     # Access-Accept, etc.

    # Pre-admission / identity context (v0.2)
    rule_slot: int | None = None          # Pre-admission rule priority (1-based)
    rule_action: str | None = None        # accept / reject / unknown
    auth_source: str | None = None        # "Pre-Admission rule 1", AD name, etc.
    domain: str | None = None             # AD domain (NetBIOS or FQDN)
    login_type: str | None = None         # dot1x_user_login, dot1x_computer_login, dot1x_mac_login
    host_in_mar: bool | None = None       # MAC found in MAR
    dhcp_hostname: str | None = None      # DHCP-discovered hostname
    dns_name: str | None = None           # DNS-resolved name
    classification: str | None = None     # Forescout primary classification

    # Extensible
    metadata: dict[str, Any] = field(default_factory=dict)
    raw_line: str | None = None


@dataclass
class AssuranceExpectation:
    testcase_id: str
    expected_decision: Decision
    expected_method: str = "eap-tls"


@dataclass
class EvidenceBundle:
    testcase_id: str
    run_id: str
    observed_decision: Decision
    expected_decision: Decision
    functional_pass: bool
    classification: str
    confidence: float
    findings: list[str] = field(default_factory=list)
    timeline: list[dict[str, Any]] = field(default_factory=list)
    artifacts: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        # Ensure Decision enums are serialized as plain strings
        for key in ("observed_decision", "expected_decision"):
            v = d.get(key)
            if hasattr(v, "value"):
                d[key] = v.value
        return d
