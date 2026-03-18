from __future__ import annotations

from dataclasses import dataclass
from statistics import median
from typing import Any


DEFAULT_THRESHOLDS: dict[str, float] = {
    "service_metrics.metrics.ldap_bind_ms": 80.0,
    "service_metrics.metrics.dns_lookup_ms": 75.0,
    "service_metrics.metrics.dhcp_ack_packets": 3.0,
    "service_metrics.metrics.coa_ack_ms": 500.0,
    "service_metrics.metrics.ntp_offset_ms": 50.0,
}

DEFAULT_BASELINE_TOLERANCE: dict[str, float] = {
    "service_metrics.metrics.ldap_bind_ms": 0.25,
    "service_metrics.metrics.dns_lookup_ms": 0.30,
    "service_metrics.metrics.dhcp_ack_packets": 0.20,
    "service_metrics.metrics.coa_ack_ms": 0.35,
    "service_metrics.metrics.ntp_offset_ms": 0.30,
}


@dataclass
class TrendResult:
    metric: str
    slope: float
    current_value: float | None
    threshold: float | None
    projected_runs_to_threshold: float | None


def _nested_get(data: dict[str, Any], dotted_key: str, default: Any = None) -> Any:
    current: Any = data
    for part in dotted_key.split("."):
        if not isinstance(current, dict) or part not in current:
            return default
        current = current[part]
    return current


def _numeric_series(history: list[dict[str, Any]], key: str) -> list[float]:
    values: list[float] = []
    for item in history:
        value = _nested_get(item, key)
        if value is None and key.startswith("service_metrics.metrics."):
            legacy_key = key.replace("service_metrics.metrics.", "service_metrics.")
            value = _nested_get(item, legacy_key)
        if isinstance(value, (int, float)):
            values.append(float(value))
    return values


def _linear_regression(values: list[float]) -> float:
    n = len(values)
    if n < 2:
        return 0.0
    xs = list(range(n))
    sum_x = sum(xs)
    sum_y = sum(values)
    sum_xy = sum(x * y for x, y in zip(xs, values))
    sum_xx = sum(x * x for x in xs)
    denom = n * sum_xx - sum_x * sum_x
    if denom == 0:
        return 0.0
    return (n * sum_xy - sum_x * sum_y) / denom


def _median_abs_deviation(values: list[float]) -> float:
    if not values:
        return 0.0
    m = median(values)
    deviations = [abs(v - m) for v in values]
    return float(median(deviations))


def build_service_baselines(
    history: list[dict[str, Any]],
    metric_keys: list[str] | None = None,
) -> dict[str, dict[str, float]]:
    metric_keys = metric_keys or list(DEFAULT_THRESHOLDS)
    baselines: dict[str, dict[str, float]] = {}
    for key in metric_keys:
        values = _numeric_series(history, key)
        if not values:
            continue
        baselines[key] = {
            "median": float(median(values)),
            "mad": _median_abs_deviation(values),
            "samples": float(len(values)),
        }
    return baselines


def compare_to_baselines(
    current_run: dict[str, Any],
    baselines: dict[str, dict[str, float]],
    tolerance: dict[str, float] | None = None,
) -> list[dict[str, Any]]:
    tolerance = tolerance or DEFAULT_BASELINE_TOLERANCE
    deviations: list[dict[str, Any]] = []
    for key, baseline in baselines.items():
        current_value = _nested_get(current_run, key)
        if not isinstance(current_value, (int, float)):
            continue
        baseline_value = baseline["median"]
        if baseline_value == 0:
            deviation_pct = 0.0 if current_value == 0 else 1.0
        else:
            deviation_pct = abs(float(current_value) - baseline_value) / baseline_value
        limit = tolerance.get(key, 0.25)
        status = "NORMAL"
        if deviation_pct > limit:
            status = "DRIFTED"
        deviations.append({
            "metric": key,
            "current_value": float(current_value),
            "baseline": baseline_value,
            "deviation_pct": round(deviation_pct, 3),
            "tolerance_pct": limit,
            "status": status,
        })
    return deviations


def detect_repeated_run_anomalies(
    current_run: dict[str, Any],
    history: list[dict[str, Any]],
    metric_keys: list[str] | None = None,
) -> list[dict[str, Any]]:
    metric_keys = metric_keys or list(DEFAULT_THRESHOLDS)
    anomalies: list[dict[str, Any]] = []
    for key in metric_keys:
        series = _numeric_series(history, key)
        if len(series) < 4:
            continue
        current_value = _nested_get(current_run, key)
        if not isinstance(current_value, (int, float)):
            continue
        base = float(median(series))
        mad = _median_abs_deviation(series)
        deviation = abs(float(current_value) - base)
        threshold = max(mad * 3, abs(base) * 0.35, 1.0)
        if deviation > threshold:
            anomalies.append({
                "metric": key,
                "current_value": float(current_value),
                "baseline_median": base,
                "mad": mad,
                "severity": "high" if deviation > threshold * 1.5 else "medium",
                "message": f"{key} deviated from its normal range across repeated runs.",
            })
    return anomalies


def predictive_warnings(
    current_run: dict[str, Any],
    history: list[dict[str, Any]],
    thresholds: dict[str, float] | None = None,
) -> list[dict[str, Any]]:
    thresholds = thresholds or DEFAULT_THRESHOLDS
    warnings: list[dict[str, Any]] = []
    for key, threshold in thresholds.items():
        series = _numeric_series(history, key)
        current_value = _nested_get(current_run, key)
        if len(series) < 3 or not isinstance(current_value, (int, float)):
            continue
        slope = _linear_regression(series + [float(current_value)])
        if slope <= 0:
            continue
        projected = None
        if float(current_value) < threshold:
            projected = (threshold - float(current_value)) / slope if slope else None
        if projected is not None and projected <= 5:
            warnings.append({
                "metric": key,
                "severity": "high" if projected <= 2 else "medium",
                "slope_per_run": round(slope, 3),
                "current_value": float(current_value),
                "threshold": threshold,
                "projected_runs_to_threshold": round(projected, 2),
                "message": f"{key} is drifting upward and is projected to exceed threshold soon.",
            })
    return warnings


def forecast_flakes(
    current_run: dict[str, Any],
    history: list[dict[str, Any]],
) -> dict[str, Any]:
    testcase_id = current_run.get("testcase_id")
    relevant = [item for item in history if item.get("testcase_id") == testcase_id] if testcase_id else history
    if len(relevant) < 5:
        return {
            "status": "INSUFFICIENT_HISTORY",
            "failure_rate": 0.0,
            "retry_clear_rate": 0.0,
            "risk": 0.0,
            "message": "Need at least 5 prior runs to forecast flakes.",
        }

    failures = [item for item in relevant if item.get("functional_pass") is False]
    failure_rate = len(failures) / len(relevant)
    retry_clears = [item for item in failures if item.get("retry_cleared") is True]
    retry_clear_rate = (len(retry_clears) / len(failures)) if failures else 0.0
    risk = min(1.0, failure_rate * 0.6 + retry_clear_rate * 0.4)

    status = "LOW"
    if risk >= 0.6:
        status = "HIGH"
    elif risk >= 0.3:
        status = "MEDIUM"

    message = "Failure pattern is stable."
    if status != "LOW":
        message = "Run history suggests this testcase has a recurring retry-cleared failure pattern."

    return {
        "status": status,
        "failure_rate": round(failure_rate, 3),
        "retry_clear_rate": round(retry_clear_rate, 3),
        "risk": round(risk, 3),
        "message": message,
    }


def trend_based_health_score(
    current_run: dict[str, Any],
    history: list[dict[str, Any]],
    thresholds: dict[str, float] | None = None,
) -> dict[str, Any]:
    thresholds = thresholds or DEFAULT_THRESHOLDS
    score = 100.0
    factors: list[str] = []

    component_health = current_run.get("component_health", {})
    for name, details in component_health.items():
        if not isinstance(details, dict) or name == "prognostic_signals":
            continue
        status = details.get("status")
        if status == "DEGRADED":
            score -= 12.0
            factors.append(f"{name} health degraded")
        elif status == "UNKNOWN":
            score -= 6.0
            factors.append(f"{name} health unknown")

    for key, threshold in thresholds.items():
        series = _numeric_series(history, key)
        current_value = _nested_get(current_run, key)
        if len(series) < 3 or not isinstance(current_value, (int, float)):
            continue
        slope = _linear_regression(series + [float(current_value)])
        if slope > 0:
            proximity = min(1.0, float(current_value) / threshold) if threshold else 0.0
            penalty = min(15.0, slope * 2.0 + proximity * 8.0)
            score -= penalty
            factors.append(f"{key} drift penalty {round(penalty, 1)}")

    anomalies = detect_repeated_run_anomalies(current_run, history, list(thresholds))
    if anomalies:
        penalty = min(20.0, len(anomalies) * 5.0)
        score -= penalty
        factors.append(f"{len(anomalies)} repeated-run anomalies")

    flake = forecast_flakes(current_run, history)
    if flake["status"] == "HIGH":
        score -= 15.0
        factors.append("high flake probability")
    elif flake["status"] == "MEDIUM":
        score -= 8.0
        factors.append("medium flake probability")

    score = max(0.0, min(100.0, score))
    return {
        "score": round(score, 1),
        "factors": factors,
    }


def evaluate_prognostics(
    current_run: dict[str, Any],
    history: list[dict[str, Any]] | None = None,
    thresholds: dict[str, float] | None = None,
) -> dict[str, Any]:
    history = history or []
    thresholds = thresholds or DEFAULT_THRESHOLDS
    baselines = build_service_baselines(history, list(thresholds))
    baseline_comparison = compare_to_baselines(current_run, baselines)
    anomalies = detect_repeated_run_anomalies(current_run, history, list(thresholds))
    warnings = predictive_warnings(current_run, history, thresholds)
    flake = forecast_flakes(current_run, history)
    health = trend_based_health_score(current_run, history, thresholds)

    return {
        "trend_health": health,
        "predictive_warnings": warnings,
        "repeated_run_anomalies": anomalies,
        "flake_forecast": flake,
        "service_baselines": {
            "baseline_profile": baselines,
            "current_deviation": baseline_comparison,
        },
        "history_samples": len(history),
    }
