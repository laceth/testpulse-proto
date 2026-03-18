from __future__ import annotations

from typing import Any

from testpulse.diagnostics.common import component_result, severity_for_status
from testpulse.models import AuthEvent, Decision


RELAY_LATENCY_THRESHOLD_MS = 120.0
RELAY_HOP_THRESHOLD = 2.0


def evaluate_tcpip_relay_health(
    events: list[AuthEvent],
    *,
    expected_decision: Decision,
    service_metrics: dict[str, Any] | None = None,
    artifact_map: dict[str, list[str]] | None = None,
) -> dict[str, Any]:
    service_metrics = service_metrics or {}
    artifact_map = artifact_map or {}
    relay_latency = _extract_metric(service_metrics, 'relay_latency_ms')
    relay_hops = _extract_metric(service_metrics, 'relay_hops')
    event_hints = [
        e for e in events
        if str(e.source).lower().find('relay') >= 0
        or str(e.message).lower().find('relay') >= 0
        or bool(getattr(e, 'metadata', {}).get('relay'))
    ]
    evidence = artifact_map.get('tcpip_relay', []) or _fallback_evidence(event_hints)
    has_relay_evidence = bool(event_hints or evidence or relay_latency is not None or relay_hops is not None)

    if has_relay_evidence and (relay_latency is None or relay_latency <= RELAY_LATENCY_THRESHOLD_MS) and (relay_hops is None or relay_hops <= RELAY_HOP_THRESHOLD):
        status = 'HEALTHY'
        finding = 'TCP/IP relay path evidence is present and within expected latency/hop thresholds.'
        recommendation = 'No action.'
        confidence = 0.86 if relay_latency is not None or relay_hops is not None else 0.74
    elif has_relay_evidence and ((relay_latency is not None and relay_latency > RELAY_LATENCY_THRESHOLD_MS) or (relay_hops is not None and relay_hops > RELAY_HOP_THRESHOLD)):
        status = 'DEGRADED'
        finding = (
            f'TCP/IP relay path exceeded normal bounds '
            f'(latency={relay_latency if relay_latency is not None else "n/a"}ms, '
            f'hops={relay_hops if relay_hops is not None else "n/a"}).'
        )
        recommendation = 'Inspect DHCP relay / IP helper path, routed hops, and relay saturation or retry behavior.'
        confidence = 0.9
    elif expected_decision == Decision.ACCEPT:
        status = 'UNKNOWN'
        finding = 'No TCP/IP relay evidence was captured for a flow that may rely on routed relay/helper behavior.'
        recommendation = 'Capture relay / helper-address logs, interface counters, or relay metrics for routed auth scenarios.'
        confidence = 0.5
    else:
        status = 'UNKNOWN'
        finding = 'TCP/IP relay behavior was not confirmed for this run.'
        recommendation = 'Collect relay/helper artifacts when testing routed DHCP/DNS paths.'
        confidence = 0.4

    return component_result(
        'tcpip_relay',
        status,
        severity=severity_for_status(status),
        finding=finding,
        recommendation=recommendation,
        confidence=confidence,
        evidence=evidence,
        details={
            'relay_latency_ms': relay_latency,
            'relay_hops': relay_hops,
            'threshold_ms': RELAY_LATENCY_THRESHOLD_MS,
            'hop_threshold': RELAY_HOP_THRESHOLD,
        },
    )


def _extract_metric(service_metrics: dict[str, Any], key: str) -> float | None:
    metrics = service_metrics.get('metrics') if isinstance(service_metrics.get('metrics'), dict) else service_metrics
    value = metrics.get(key) if isinstance(metrics, dict) else None
    if isinstance(value, (int, float)):
        return float(value)
    return None


def _fallback_evidence(events: list[AuthEvent]) -> list[str]:
    evidence: list[str] = []
    if events:
        evidence.append('relay:runtime_evidence')
    return evidence
