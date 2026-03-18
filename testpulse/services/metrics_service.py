from __future__ import annotations

from typing import Any


def build_service_metrics(
    run_id: str,
    testcase_id: str,
    base_metrics: dict[str, Any],
    provided_metrics: dict[str, Any] | None = None,
) -> dict[str, Any]:
    provided_metrics = provided_metrics or {}
    metrics_block = provided_metrics.get("metrics") if isinstance(provided_metrics.get("metrics"), dict) else provided_metrics
    metrics = {
        "radius_decision_ms": _coerce(metrics_block.get("radius_decision_ms")),
        "dns_lookup_ms": _coerce(metrics_block.get("dns_lookup_ms")),
        "dhcp_ack_packets": _coerce(metrics_block.get("dhcp_ack_packets")),
        "ldap_bind_ms": _coerce(metrics_block.get("ldap_bind_ms")),
        "coa_ack_ms": _coerce(metrics_block.get("coa_ack_ms")),
        "ntp_offset_ms": _coerce(metrics_block.get("ntp_offset_ms")),
        "relay_latency_ms": _coerce(metrics_block.get("relay_latency_ms")),
        "relay_hops": _coerce(metrics_block.get("relay_hops")),
        "tomahawk_fabric_util_pct": _coerce(metrics_block.get("tomahawk_fabric_util_pct")),
        "tomahawk_drop_pct": _coerce(metrics_block.get("tomahawk_drop_pct")),
        "time_span_seconds": _coerce(base_metrics.get("time_span_seconds")),
        "radius_requests": _coerce(base_metrics.get("radius_requests")),
        "radius_accepts": _coerce(base_metrics.get("radius_accepts")),
        "radius_rejects": _coerce(base_metrics.get("radius_rejects")),
    }
    return {
        "run_id": run_id,
        "testcase_id": testcase_id,
        "metrics": {k: v for k, v in metrics.items() if v is not None},
    }


def _coerce(value: Any) -> float | int | None:
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return round(value, 3)
    return None
