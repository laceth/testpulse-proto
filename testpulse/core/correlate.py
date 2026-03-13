"""Correlate AuthEvents across log sources for metrics and analysis.

Correlation strategies:

1. **RADIUS Id linkage** — Request → Accept/Reject by ``radius_id``
2. **MAC grouping** — events sharing the same ``endpoint_mac``
3. **IP grouping** — events sharing the same ``endpoint_ip``
4. **Temporal ordering** — sorted by epoch (preferred) then timestamp
5. **Cross-source enrichment** — propagate metadata between sources

The ``correlate()`` function returns a time-ordered list suitable for
timeline rendering.  ``group_by_session()`` returns events clustered by
their natural session keys for metrics aggregation.
"""
from __future__ import annotations

from collections import defaultdict
from testpulse.models import AuthEvent


def correlate(events: list[AuthEvent]) -> list[AuthEvent]:
    """Sort events by epoch (preferred) then timestamp, source, kind."""

    def sort_key(event: AuthEvent) -> tuple[float, str, str, str]:
        # Prefer epoch for sub-second precision; fall back to ts string
        epoch = event.epoch if event.epoch is not None else 0.0
        ts = event.ts or ""
        return (epoch, ts, event.source, event.kind)

    return sorted(events, key=sort_key)


def group_by_mac(events: list[AuthEvent]) -> dict[str, list[AuthEvent]]:
    """Group events by endpoint MAC address.

    Events without a MAC are collected under the key ``"_unknown_"``.
    """
    groups: dict[str, list[AuthEvent]] = defaultdict(list)
    for ev in events:
        key = _normalize_mac(ev.endpoint_mac) if ev.endpoint_mac else "_unknown_"
        groups[key].append(ev)
    return dict(groups)


def group_by_ip(events: list[AuthEvent]) -> dict[str, list[AuthEvent]]:
    """Group events by endpoint IP address."""
    groups: dict[str, list[AuthEvent]] = defaultdict(list)
    for ev in events:
        key = ev.endpoint_ip or "_unknown_"
        groups[key].append(ev)
    return dict(groups)


def group_by_radius_id(events: list[AuthEvent]) -> dict[int, list[AuthEvent]]:
    """Group RADIUS events by their packet Id for request/response pairing."""
    groups: dict[int, list[AuthEvent]] = defaultdict(list)
    for ev in events:
        if ev.radius_id is not None:
            groups[ev.radius_id].append(ev)
    return dict(groups)


def group_by_session(events: list[AuthEvent]) -> dict[str, list[AuthEvent]]:
    """Group events by the best available session key.

    Priority: session_id (audit-session-id) > endpoint_mac > endpoint_ip.
    """
    groups: dict[str, list[AuthEvent]] = defaultdict(list)
    for ev in events:
        key = (
            ev.session_id
            or (_normalize_mac(ev.endpoint_mac) if ev.endpoint_mac else None)
            or ev.endpoint_ip
            or "_unknown_"
        )
        groups[key].append(ev)
    return dict(groups)


def enrich_from_peers(events: list[AuthEvent]) -> list[AuthEvent]:
    """Propagate metadata across events that share a session key.

    For example, if a RADIUS Request has a MAC but the framework event
    for the same IP doesn't, copy the MAC over.

    Also propagates identity context (hostname, domain, classification)
    from hostinfo/identity events to all events sharing the same MAC/IP.
    """
    by_ip = group_by_ip(events)

    for ip, group in by_ip.items():
        if ip == "_unknown_":
            continue
        # Collect the richest metadata from the group
        mac = next((e.endpoint_mac for e in group if e.endpoint_mac), None)
        username = next((e.username for e in group if e.username), None)
        nas_ip = next((e.nas_ip for e in group if e.nas_ip), None)
        session_id = next((e.session_id for e in group if e.session_id), None)
        auth_method = next((e.auth_method for e in group if e.auth_method), None)

        # Identity context from hostinfo events
        domain = next((e.domain for e in group if e.domain), None)
        login_type = next((e.login_type for e in group if e.login_type), None)
        auth_source = next((e.auth_source for e in group if e.auth_source), None)
        dhcp_hostname = next((e.dhcp_hostname for e in group if e.dhcp_hostname), None)
        dns_name = next((e.dns_name for e in group if e.dns_name), None)

        for ev in group:
            if not ev.endpoint_mac and mac:
                ev.endpoint_mac = mac
            if not ev.username and username:
                ev.username = username
            if not ev.nas_ip and nas_ip:
                ev.nas_ip = nas_ip
            if not ev.session_id and session_id:
                ev.session_id = session_id
            if not ev.auth_method and auth_method:
                ev.auth_method = auth_method
            if not ev.domain and domain:
                ev.domain = domain
            if not ev.login_type and login_type:
                ev.login_type = login_type
            if not ev.auth_source and auth_source:
                ev.auth_source = auth_source
            if not ev.dhcp_hostname and dhcp_hostname:
                ev.dhcp_hostname = dhcp_hostname
            if not ev.dns_name and dns_name:
                ev.dns_name = dns_name

    return events


def compute_metrics(events: list[AuthEvent]) -> dict:
    """Compute summary metrics from a correlated event list.

    Returns a dict with counts, timing, and per-method breakdowns.
    """
    total = len(events)
    by_kind: dict[str, int] = defaultdict(int)
    by_source: dict[str, int] = defaultdict(int)
    by_method: dict[str, int] = defaultdict(int)
    accept_count = 0
    reject_count = 0
    request_count = 0

    for ev in events:
        by_kind[ev.kind] += 1
        by_source[ev.source] += 1
        if ev.auth_method:
            by_method[ev.auth_method.lower()] += 1
        if ev.kind == "RADIUS_ACCESS_ACCEPT":
            accept_count += 1
        elif ev.kind == "RADIUS_ACCESS_REJECT":
            reject_count += 1
        elif ev.kind == "RADIUS_ACCESS_REQUEST":
            request_count += 1

    # Time span
    epochs = [ev.epoch for ev in events if ev.epoch is not None]
    time_span = max(epochs) - min(epochs) if len(epochs) >= 2 else 0.0

    return {
        "total_events": total,
        "by_kind": dict(by_kind),
        "by_source": dict(by_source),
        "by_method": dict(by_method),
        "radius_requests": request_count,
        "radius_accepts": accept_count,
        "radius_rejects": reject_count,
        "accept_rate": (
            accept_count / (accept_count + reject_count)
            if (accept_count + reject_count) > 0
            else 0.0
        ),
        "time_span_seconds": time_span,
        "unique_macs": len({
            _normalize_mac(ev.endpoint_mac)
            for ev in events if ev.endpoint_mac
        }),
        "unique_ips": len({ev.endpoint_ip for ev in events if ev.endpoint_ip}),
        "identity_events": sum(1 for ev in events if ev.source in ("hostinfo", "local_properties", "fstool_status") or ev.kind.startswith("IDENTITY_")),
        "redis_events": sum(1 for ev in events if ev.source == "redis" or ev.kind.startswith("REDIS_")),
    }


def _normalize_mac(mac: str) -> str:
    """Normalize a MAC address to lower-case colon-separated form."""
    clean = mac.lower().replace("-", ":").replace(".", ":")
    # Handle plain 12-hex (no separators)
    if len(clean) == 12 and ":" not in clean:
        clean = ":".join(clean[i:i+2] for i in range(0, 12, 2))
    return clean
