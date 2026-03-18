from __future__ import annotations

from typing import Any, Iterable


def component_result(
    component: str,
    status: str = "UNKNOWN",
    *,
    severity: str = "low",
    finding: str = "No evidence evaluated.",
    recommendation: str = "Collect more evidence.",
    confidence: float = 0.3,
    evidence: Iterable[str] | None = None,
    details: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "component": component,
        "status": status,
        "severity": severity,
        "finding": finding,
        "recommendation": recommendation,
        "confidence": round(float(confidence), 2),
        "evidence": list(dict.fromkeys(evidence or [])),
        "details": details or {},
    }


def severity_for_status(status: str) -> str:
    return {
        "HEALTHY": "low",
        "DEGRADED": "medium",
        "FAILED": "high",
        "UNKNOWN": "medium",
    }.get(status, "medium")


def first_non_empty(values: Iterable[str | None]) -> str | None:
    for value in values:
        if value:
            return value
    return None
