from __future__ import annotations

from typing import Any

from testpulse.diagnostics.common import component_result, severity_for_status
from testpulse.models import AuthEvent, Decision


DHCP_RETRY_THRESHOLD = 3.0


def evaluate_dhcp_health(
    events: list[AuthEvent],
    *,
    expected_decision: Decision,
    service_metrics: dict[str, Any] | None = None,
    artifact_map: dict[str, list[str]] | None = None,
) -> dict[str, Any]:
    service_metrics = service_metrics or {}
    artifact_map = artifact_map or {}
    has_ip = any(e.endpoint_ip for e in events)
    dhcp_hostname = next((e.dhcp_hostname for e in events if e.dhcp_hostname), None)
    ack_packets = _extract_metric(service_metrics, "dhcp_ack_packets")
    evidence = artifact_map.get("dhcp", []) or _fallback_evidence(events)

    if has_ip and (ack_packets is None or ack_packets <= DHCP_RETRY_THRESHOLD):
        status = "HEALTHY"
        finding = "Endpoint IP acquisition evidence is present."
        if dhcp_hostname:
            finding = f"Endpoint IP acquisition evidence is present; DHCP hostname observed ({dhcp_hostname})."
        recommendation = "No action."
        confidence = 0.88 if ack_packets is not None else 0.78
    elif has_ip and ack_packets is not None:
        status = "DEGRADED"
        finding = f"DHCP completed but required {ack_packets} Ack packets, above normal retry threshold {DHCP_RETRY_THRESHOLD}."
        recommendation = "Investigate DHCP saturation, relay health, or VLAN placement drift."
        confidence = 0.9
    elif expected_decision == Decision.ACCEPT:
        status = "FAILED"
        finding = "No endpoint IP acquisition evidence was captured for an expected successful auth flow."
        recommendation = "Verify VLAN assignment, DHCP reachability, and endpoint NIC recovery timing."
        confidence = 0.83
    else:
        status = "UNKNOWN"
        finding = "DHCP was not confirmed for this run."
        recommendation = "Collect endpoint IP and DHCP artifacts for negative-path analysis."
        confidence = 0.45

    return component_result(
        "dhcp",
        status,
        severity=severity_for_status(status),
        finding=finding,
        recommendation=recommendation,
        confidence=confidence,
        evidence=evidence,
        details={
            "has_ip": has_ip,
            "dhcp_hostname": dhcp_hostname,
            "dhcp_ack_packets": ack_packets,
            "threshold_packets": DHCP_RETRY_THRESHOLD,
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
    if any(e.endpoint_ip for e in events):
        evidence.append("endpoint:ipconfig_all.txt")
    if any(e.dhcp_hostname for e in events):
        evidence.append("identity_parser:dhcp_hostname")
    return evidence
