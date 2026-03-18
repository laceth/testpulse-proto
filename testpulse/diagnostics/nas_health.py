from __future__ import annotations

from typing import Any

from testpulse.diagnostics.common import component_result, severity_for_status
from testpulse.models import AuthEvent, Decision


COA_THRESHOLD_MS = 500.0


def evaluate_nas_health(
    events: list[AuthEvent],
    *,
    expected_decision: Decision,
    service_metrics: dict[str, Any] | None = None,
    artifact_map: dict[str, list[str]] | None = None,
) -> dict[str, Any]:
    service_metrics = service_metrics or {}
    artifact_map = artifact_map or {}
    nas_port = next((e.nas_port or e.nas_port_id for e in events if (e.nas_port or e.nas_port_id)), None)
    nas_ip = next((e.nas_ip for e in events if e.nas_ip), None)
    saw_accept = any(e.kind == "RADIUS_ACCESS_ACCEPT" for e in events)
    saw_reject = any(e.kind == "RADIUS_ACCESS_REJECT" for e in events)
    coa_ack_ms = _extract_metric(service_metrics, "coa_ack_ms")
    evidence = (artifact_map.get("nas_authorization", []) + artifact_map.get("coa", [])) or _fallback_evidence(events)

    if saw_accept and expected_decision == Decision.ACCEPT and (coa_ack_ms is None or coa_ack_ms <= COA_THRESHOLD_MS):
        status = "HEALTHY"
        finding = "NAS authorization evidence aligns with successful RADIUS decision."
        recommendation = "No action."
        confidence = 0.86
    elif saw_accept and coa_ack_ms is not None and coa_ack_ms > COA_THRESHOLD_MS:
        status = "DEGRADED"
        finding = f"RADIUS accepted, but CoA acknowledgement latency {coa_ack_ms}ms exceeded {COA_THRESHOLD_MS}ms."
        recommendation = "Check switch responsiveness, control-plane load, and CoA handling."
        confidence = 0.9
    elif saw_reject and expected_decision == Decision.ACCEPT:
        status = "FAILED"
        finding = "RADIUS rejected a flow expected to authorize on the NAS."
        recommendation = "Verify pre-admission rules, switch session state, VLAN/ACL enforcement, and endpoint credentials."
        confidence = 0.84
    elif nas_port or nas_ip:
        status = "DEGRADED"
        finding = "NAS context was captured, but end-to-end authorization evidence is incomplete."
        recommendation = "Collect switch show authentication sessions details and CoA/syslog evidence for the same run."
        confidence = 0.72
    else:
        status = "UNKNOWN"
        finding = "No switch/NAS authorization evidence was captured for this run."
        recommendation = "Add show authentication sessions, VLAN/ACL, and CoA artifacts to the run bundle."
        confidence = 0.4

    return component_result(
        "nas",
        status,
        severity=severity_for_status(status),
        finding=finding,
        recommendation=recommendation,
        confidence=confidence,
        evidence=evidence,
        details={
            "nas_ip": nas_ip,
            "nas_port": nas_port,
            "coa_ack_ms": coa_ack_ms,
            "threshold_ms": COA_THRESHOLD_MS,
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
    if any(e.nas_port or e.nas_port_id for e in events):
        evidence.append("identity_parser:dot1x_NASPortIdStr")
    if any(e.nas_ip for e in events):
        evidence.append("identity_parser:dot1x_NAS_addr")
    if any(e.kind.startswith("RADIUS_ACCESS_") for e in events):
        evidence.append("radius/radiusd.log")
    return evidence
