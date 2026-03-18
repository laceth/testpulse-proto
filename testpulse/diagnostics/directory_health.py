from __future__ import annotations

from typing import Any

from testpulse.diagnostics.common import component_result, severity_for_status
from testpulse.models import AuthEvent, Decision


LDAP_THRESHOLD_MS = 80.0


def evaluate_directory_health(
    events: list[AuthEvent],
    *,
    expected_decision: Decision,
    service_metrics: dict[str, Any] | None = None,
    artifact_map: dict[str, list[str]] | None = None,
) -> dict[str, Any]:
    service_metrics = service_metrics or {}
    artifact_map = artifact_map or {}
    domains = sorted({e.domain for e in events if e.domain})
    login_types = sorted({e.login_type for e in events if e.login_type})
    auth_sources = sorted({e.auth_source for e in events if e.auth_source})
    ldap_settings = {
        str(e.metadata.get("setting_key")): str(e.metadata.get("setting_value"))
        for e in events
        if e.kind == "IDENTITY_PLUGIN_SETTING" and str(e.metadata.get("setting_key", "")).startswith("ldap_")
    }
    bind_latency = _extract_metric(service_metrics, "ldap_bind_ms")
    evidence = artifact_map.get("ad_ldap", []) or _fallback_evidence(events)

    has_directory_evidence = bool(domains or login_types or auth_sources or ldap_settings)
    if has_directory_evidence and (bind_latency is None or bind_latency <= LDAP_THRESHOLD_MS):
        status = "HEALTHY"
        finding = "Directory evidence present for enterprise auth path."
        if domains:
            finding = f"Directory evidence present for domain {domains[0]}."
        recommendation = "No action."
        confidence = 0.9 if bind_latency is not None else 0.82
    elif has_directory_evidence and bind_latency is not None:
        status = "DEGRADED"
        finding = f"Directory evidence is present but LDAP bind latency {bind_latency}ms exceeded {LDAP_THRESHOLD_MS}ms."
        recommendation = "Check AD/DC reachability, referral behavior, and LDAPS/TLS overhead."
        confidence = 0.91
    elif expected_decision == Decision.ACCEPT:
        status = "FAILED"
        finding = "No AD/LDAP/domain evidence was captured for an expected enterprise auth flow."
        recommendation = "Capture hostinfo/local.properties and add LDAP bind or AD reachability checks."
        confidence = 0.8
    else:
        status = "UNKNOWN"
        finding = "Directory dependency was not confirmed for this run."
        recommendation = "Collect AD/LDAP evidence for negative-path or policy debugging."
        confidence = 0.45

    return component_result(
        "directory",
        status,
        severity=severity_for_status(status),
        finding=finding,
        recommendation=recommendation,
        confidence=confidence,
        evidence=evidence,
        details={
            "domains": domains,
            "login_types": login_types,
            "auth_sources": auth_sources,
            "ldap_settings": ldap_settings,
            "ldap_bind_ms": bind_latency,
            "threshold_ms": LDAP_THRESHOLD_MS,
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
    if any(e.domain for e in events):
        evidence.append("identity_parser:dot1x_domain")
    if any(e.login_type for e in events):
        evidence.append("identity_parser:dot1x_login_type")
    if any(e.kind == "IDENTITY_PLUGIN_SETTING" for e in events):
        evidence.append("identity_parser:local_properties")
    return evidence
