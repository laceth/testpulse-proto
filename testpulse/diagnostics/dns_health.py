from __future__ import annotations

from typing import Any

from testpulse.diagnostics.common import component_result, severity_for_status
from testpulse.models import AuthEvent, Decision


DNS_THRESHOLD_MS = 75.0


def evaluate_dns_health(
    events: list[AuthEvent],
    *,
    expected_decision: Decision,
    service_metrics: dict[str, Any] | None = None,
    artifact_map: dict[str, list[str]] | None = None,
) -> dict[str, Any]:
    service_metrics = service_metrics or {}
    artifact_map = artifact_map or {}
    dns_name = next((e.dns_name for e in events if e.dns_name), None)
    domains = sorted({e.domain for e in events if e.domain})
    dns_latency = _extract_metric(service_metrics, "dns_lookup_ms")
    evidence = artifact_map.get("dns", []) or _fallback_evidence(events)

    if (dns_name or dns_latency is not None) and (dns_latency is None or dns_latency <= DNS_THRESHOLD_MS):
        status = "HEALTHY"
        if dns_name:
            finding = f"DNS resolution evidence present ({dns_name})."
        else:
            finding = f"DNS lookup metric {dns_latency}ms is within threshold, but resolver artifact naming was not captured."
        recommendation = "No action."
        confidence = 0.92 if dns_latency is not None else 0.85
    elif dns_name and dns_latency is not None:
        status = "DEGRADED"
        finding = f"DNS resolution succeeded but lookup latency {dns_latency}ms exceeded {DNS_THRESHOLD_MS}ms threshold."
        recommendation = "Review resolver health, DC proximity, and suffix/search-list behavior."
        confidence = 0.89
    elif domains and expected_decision == Decision.ACCEPT:
        status = "DEGRADED"
        finding = "Enterprise auth flow has domain context but no DNS resolution evidence."
        recommendation = "Capture nslookup/dig output or resolver logs during the same run window."
        confidence = 0.8
    elif expected_decision == Decision.ACCEPT:
        status = "UNKNOWN"
        finding = "No DNS artifacts were captured for an expected successful enterprise auth flow."
        recommendation = "Add DNS evidence collection before asserting directory/auth policy behavior."
        confidence = 0.55
    else:
        status = "UNKNOWN"
        finding = "DNS was not exercised or not captured for this run."
        recommendation = "Collect DNS artifacts for richer negative-path diagnosis."
        confidence = 0.4

    return component_result(
        "dns",
        status,
        severity=severity_for_status(status),
        finding=finding,
        recommendation=recommendation,
        confidence=confidence,
        evidence=evidence,
        details={
            "dns_name": dns_name,
            "domains": domains,
            "dns_lookup_ms": dns_latency,
            "threshold_ms": DNS_THRESHOLD_MS,
        },
    )


def _extract_metric(service_metrics: dict[str, Any], key: str) -> float | None:
    metrics = service_metrics.get("metrics") if isinstance(service_metrics.get("metrics"), dict) else service_metrics
    value = metrics.get(key) if isinstance(metrics, dict) else None
    if isinstance(value, (int, float)):
        return float(value)
    return None


def _fallback_evidence(events: list[AuthEvent]) -> list[str]:
    evidence = []
    if any(e.dns_name for e in events):
        evidence.append("identity_parser:dns_name")
    if any(e.endpoint_ip for e in events):
        evidence.append("endpoint:ipconfig_all.txt")
    return evidence
