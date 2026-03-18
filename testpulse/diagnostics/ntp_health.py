from __future__ import annotations

from typing import Any

from testpulse.diagnostics.common import component_result, severity_for_status


SYNC_OK_MS = 50.0
SYNC_FAIL_MS = 500.0


def evaluate_ntp_health(
    events: list[Any],
    *,
    expected_decision: Any = None,
    service_metrics: dict[str, Any] | None = None,
    artifact_map: dict[str, list[str]] | None = None,
) -> dict[str, Any]:
    service_metrics = service_metrics or {}
    artifact_map = artifact_map or {}
    offset = _extract_metric(service_metrics, "ntp_offset_ms")
    evidence = artifact_map.get("ntp", [])
    if offset is None:
        status = "UNKNOWN"
        finding = "No NTP/clock integrity evidence was available for this run."
        recommendation = "Capture Windows w32tm, Linux timedatectl/chronyc, and switch show ntp status outputs."
        confidence = 0.4
    elif offset <= SYNC_OK_MS:
        status = "HEALTHY"
        finding = f"Clock offset {offset}ms is within synchronization threshold."
        recommendation = "No action."
        confidence = 0.95
    elif offset <= SYNC_FAIL_MS:
        status = "DEGRADED"
        finding = f"Clock offset {offset}ms exceeds ideal threshold and may distort timing correlation."
        recommendation = "Re-sync NTP before relying on TimingBudget or PCAP/log ordering."
        confidence = 0.93
    else:
        status = "FAILED"
        finding = f"Clock offset {offset}ms is beyond safe correlation limits."
        recommendation = "Treat this run as time-suspect and repair NTP before comparing latencies."
        confidence = 0.97

    return component_result(
        "ntp",
        status,
        severity=severity_for_status(status),
        finding=finding,
        recommendation=recommendation,
        confidence=confidence,
        evidence=evidence,
        details={"ntp_offset_ms": offset, "ok_threshold_ms": SYNC_OK_MS, "fail_threshold_ms": SYNC_FAIL_MS},
    )


def _extract_metric(service_metrics: dict[str, Any], key: str) -> float | None:
    metrics = service_metrics.get("metrics") if isinstance(service_metrics.get("metrics"), dict) else service_metrics
    value = metrics.get(key) if isinstance(metrics, dict) else None
    if isinstance(value, (int, float)):
        return float(value)
    return None
