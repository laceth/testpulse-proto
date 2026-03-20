from __future__ import annotations

from pathlib import Path
from typing import Any

from testpulse.core.correlate import compute_metrics
from testpulse.core.evaluate import classify_result, infer_observed_decision
from testpulse.diagnostics import evaluate_component_health, evaluate_prognostics
from testpulse.models import AssuranceExpectation, AuthEvent, EvidenceBundle
from testpulse.services.artifact_map_service import build_artifact_map
from testpulse.services.metrics_service import build_service_metrics


def build_bundle(
    run_id: str,
    expectation: AssuranceExpectation,
    events: list[AuthEvent],
    artifacts: list[str],
    history: list[dict[str, Any]] | None = None,
    service_metrics: dict[str, Any] | None = None,
    artifact_map: dict[str, Any] | None = None,
) -> EvidenceBundle:
    observed, confidence = infer_observed_decision(events)
    classification = classify_result(observed, expectation.expected_decision, confidence)
    metrics = compute_metrics(events)
    normalized_service_metrics = build_service_metrics(
        run_id=run_id,
        testcase_id=expectation.testcase_id,
        base_metrics=metrics,
        provided_metrics=service_metrics or {},
    )
    artifact_map = artifact_map or {"run_id": run_id, "nodes": {}}
    component_health, diagnostic_findings = evaluate_component_health(
        events=events,
        observed_decision=observed,
        expected_decision=expectation.expected_decision,
        service_metrics=normalized_service_metrics,
        artifact_map=artifact_map.get("nodes", {}),
        run_id=run_id,
    )

    findings = [
        f"Observed decision: {observed.value}",
        f"Expected decision: {expectation.expected_decision.value}",
        f"Functional pass: {observed == expectation.expected_decision}",
    ]

    # -- Informational policy/config signals (do not affect pass/fail)
    vlan_restrict_values = {
        (e.vlan_config or "").strip()
        for e in events
        if e.kind == "DOT1X_VLAN_RESTRICT_CONFIG" and (e.vlan_config or "").strip()
    }
    if any("reject=dummy" in v.lower() for v in vlan_restrict_values):
        findings.append("DOT1X policy present: restrict => reject=dummy (informational)")

    findings.extend(diagnostic_findings)

    timeline = [_event_to_timeline_entry(event) for event in events]
    current_run = {
        "run_id": run_id,
        "testcase_id": expectation.testcase_id,
        "functional_pass": observed == expectation.expected_decision,
        "classification": classification,
        "confidence": confidence,
        "component_health": component_health,
        "metrics": metrics,
        "service_metrics": normalized_service_metrics,
    }
    prognostics = evaluate_prognostics(current_run=current_run, history=history or [])

    if prognostics["trend_health"]["factors"]:
        findings.append(
            f"Trend health score: {prognostics['trend_health']['score']} ({'; '.join(prognostics['trend_health']['factors'][:2])})"
        )
    else:
        findings.append(f"Trend health score: {prognostics['trend_health']['score']}")

    for warning in prognostics["predictive_warnings"][:2]:
        findings.append(f"Predictive warning: {warning['message']}")
    for anomaly in prognostics["repeated_run_anomalies"][:2]:
        findings.append(f"Repeated-run anomaly: {anomaly['message']}")
    if prognostics["flake_forecast"]["status"] not in {"LOW", "INSUFFICIENT_HISTORY"}:
        findings.append(
            f"Flake forecast: {prognostics['flake_forecast']['status']} risk "
            f"(failure_rate={prognostics['flake_forecast']['failure_rate']}, retry_clear_rate={prognostics['flake_forecast']['retry_clear_rate']})"
        )

    return EvidenceBundle(
        testcase_id=expectation.testcase_id,
        run_id=run_id,
        observed_decision=observed,
        expected_decision=expectation.expected_decision,
        functional_pass=(observed == expectation.expected_decision),
        classification=classification,
        confidence=confidence,
        findings=findings,
        timeline=timeline,
        artifacts=artifacts,
        metadata={
            "component_health": component_health,
            "component_health_contract": component_health.get("contract", {"run_id": run_id, "components": []}),
            "metrics": metrics,
            "service_metrics": normalized_service_metrics,
            "artifact_map": artifact_map,
            "prognostics": prognostics,
        },
    )


def collect_artifacts(run_dir: Path) -> list[str]:
    return sorted(
        str(path.relative_to(run_dir))
        for path in run_dir.rglob("*")
        if path.is_file()
    )


def artifact_map_for_run(run_dir: Path, events: list[AuthEvent]) -> dict[str, Any]:
    return build_artifact_map(run_dir, events)


def _event_to_timeline_entry(event: AuthEvent) -> dict:
    d: dict = {
        "ts": event.ts,
        "epoch": event.epoch,
        "kind": event.kind,
        "source": event.source,
        "message": event.message,
        "endpoint_mac": event.endpoint_mac,
        "endpoint_ip": event.endpoint_ip,
        "username": event.username,
        "machine_name": event.machine_name,
        "session_id": event.session_id,
        "nas_ip": event.nas_ip,
        "nas_port": event.nas_port,
        "calling_station_id": event.calling_station_id,
        "called_station_id": event.called_station_id,
        "radius_id": event.radius_id,
        "src_ip": event.src_ip,
        "dst_ip": event.dst_ip,
        "auth_method": event.auth_method,
        "service_type": event.service_type,
        "nas_port_type": event.nas_port_type,
        "nas_port_id": event.nas_port_id,
        "framed_mtu": event.framed_mtu,
        "eap_type": event.eap_type,
        "vlan_config": event.vlan_config,
        "policy_enabled": event.policy_enabled,
        "plugin_version": event.plugin_version,
        "context_id": event.context_id,
        "property_field": event.property_field,
        "property_value": event.property_value,
        "rule_slot": event.rule_slot,
        "rule_action": event.rule_action,
        "auth_source": event.auth_source,
        "domain": event.domain,
        "login_type": event.login_type,
        "dhcp_hostname": event.dhcp_hostname,
        "dns_name": event.dns_name,
        "classification": event.classification,
    }
    if event.metadata:
        d["metadata"] = event.metadata
    return {k: v for k, v in d.items() if v is not None}
