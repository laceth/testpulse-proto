from __future__ import annotations

from typing import Any

from testpulse.diagnostics.common import component_result, severity_for_status
from testpulse.models import AuthEvent, Decision


TOMAHAWK_DROP_THRESHOLD_PCT = 1.0
TOMAHAWK_UTIL_THRESHOLD_PCT = 85.0


def evaluate_tomahawk_health(
    events: list[AuthEvent],
    *,
    expected_decision: Decision,
    service_metrics: dict[str, Any] | None = None,
    artifact_map: dict[str, list[str]] | None = None,
) -> dict[str, Any]:
    service_metrics = service_metrics or {}
    artifact_map = artifact_map or {}
    util_pct = _extract_metric(service_metrics, 'tomahawk_fabric_util_pct')
    drop_pct = _extract_metric(service_metrics, 'tomahawk_drop_pct')
    event_hints = [
        e for e in events
        if 'tomahawk' in str(e.source).lower()
        or 'tomahawk' in str(e.message).lower()
        or str(getattr(e, 'metadata', {}).get('platform', '')).lower().find('tomahawk') >= 0
    ]
    evidence = artifact_map.get('tomahawk', []) or _fallback_evidence(event_hints)
    has_tomahawk = bool(event_hints or evidence or util_pct is not None or drop_pct is not None)

    if has_tomahawk and (drop_pct is None or drop_pct <= TOMAHAWK_DROP_THRESHOLD_PCT) and (util_pct is None or util_pct <= TOMAHAWK_UTIL_THRESHOLD_PCT):
        status = 'HEALTHY'
        finding = 'Tomahawk switch/fabric evidence is present and no congestion or drop symptoms exceeded threshold.'
        recommendation = 'No action.'
        confidence = 0.84 if util_pct is not None or drop_pct is not None else 0.72
    elif has_tomahawk and ((drop_pct is not None and drop_pct > TOMAHAWK_DROP_THRESHOLD_PCT) or (util_pct is not None and util_pct > TOMAHAWK_UTIL_THRESHOLD_PCT)):
        status = 'DEGRADED'
        finding = (
            f'Tomahawk platform telemetry suggests elevated load '
            f'(util={util_pct if util_pct is not None else "n/a"}%, '
            f'drops={drop_pct if drop_pct is not None else "n/a"}%).'
        )
        recommendation = 'Review switch ASIC/fabric counters, QoS, and buffer pressure on Tomahawk-based hardware.'
        confidence = 0.91
    elif expected_decision == Decision.ACCEPT:
        status = 'UNKNOWN'
        finding = 'No Tomahawk-specific telemetry was captured for this run.'
        recommendation = 'Capture platform or ASIC counters when validating Tomahawk-based switch paths.'
        confidence = 0.45
    else:
        status = 'UNKNOWN'
        finding = 'Tomahawk platform behavior was not confirmed for this run.'
        recommendation = 'Collect switch ASIC/fabric counters for richer network-path diagnosis.'
        confidence = 0.35

    return component_result(
        'tomahawk',
        status,
        severity=severity_for_status(status),
        finding=finding,
        recommendation=recommendation,
        confidence=confidence,
        evidence=evidence,
        details={
            'tomahawk_fabric_util_pct': util_pct,
            'tomahawk_drop_pct': drop_pct,
            'util_threshold_pct': TOMAHAWK_UTIL_THRESHOLD_PCT,
            'drop_threshold_pct': TOMAHAWK_DROP_THRESHOLD_PCT,
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
        evidence.append('switch:tomahawk_platform')
    return evidence
