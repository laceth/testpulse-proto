from __future__ import annotations

from typing import Any

from testpulse.diagnostics.dhcp_health import evaluate_dhcp_health
from testpulse.diagnostics.directory_health import evaluate_directory_health
from testpulse.diagnostics.dns_health import evaluate_dns_health
from testpulse.diagnostics.nas_health import evaluate_nas_health
from testpulse.diagnostics.tcpip_relay_health import evaluate_tcpip_relay_health
from testpulse.diagnostics.tomahawk_health import evaluate_tomahawk_health
from testpulse.diagnostics.ntp_health import evaluate_ntp_health
from testpulse.models import AuthEvent, Decision


COMPONENTS = ("dns", "dhcp", "directory", "ntp", "nas", "tcpip_relay", "tomahawk")


def evaluate_component_health(
    events: list[AuthEvent],
    observed_decision: Decision,
    expected_decision: Decision,
    *,
    service_metrics: dict[str, Any] | None = None,
    artifact_map: dict[str, list[str]] | None = None,
    run_id: str | None = None,
) -> tuple[dict[str, Any], list[str]]:
    artifact_map = artifact_map or {}
    evaluators = [
        evaluate_dns_health(events, expected_decision=expected_decision, service_metrics=service_metrics, artifact_map=artifact_map),
        evaluate_dhcp_health(events, expected_decision=expected_decision, service_metrics=service_metrics, artifact_map=artifact_map),
        evaluate_directory_health(events, expected_decision=expected_decision, service_metrics=service_metrics, artifact_map=artifact_map),
        evaluate_ntp_health(events, expected_decision=expected_decision, service_metrics=service_metrics, artifact_map=artifact_map),
        evaluate_nas_health(events, expected_decision=expected_decision, service_metrics=service_metrics, artifact_map=artifact_map),
        evaluate_tcpip_relay_health(events, expected_decision=expected_decision, service_metrics=service_metrics, artifact_map=artifact_map),
        evaluate_tomahawk_health(events, expected_decision=expected_decision, service_metrics=service_metrics, artifact_map=artifact_map),
    ]

    result: dict[str, Any] = {item["component"]: item for item in evaluators}
    summary_findings = [f"{item['component'].upper()} health: {item['finding']}" for item in evaluators]

    prognostic_signals: list[dict[str, Any]] = []
    if observed_decision == Decision.REJECT and expected_decision == Decision.ACCEPT:
        for item in evaluators:
            if item["status"] in {"DEGRADED", "FAILED"}:
                prognostic_signals.append({
                    "component": item["component"],
                    "severity": item["severity"],
                    "signal": f"{item['component']}-risk",
                    "message": f"{item['component']} dependency is {item['status'].lower()} and may recur on later enterprise-auth runs.",
                })
    result["prognostic_signals"] = prognostic_signals
    result["components"] = evaluators
    result["contract"] = {
        "run_id": run_id,
        "components": evaluators,
    }
    return result, summary_findings
