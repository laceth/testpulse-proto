from __future__ import annotations

from pathlib import Path
from testpulse.core.evaluate import classify_result, infer_observed_decision
from testpulse.models import AssuranceExpectation, AuthEvent, EvidenceBundle


def build_bundle(
    run_id: str,
    expectation: AssuranceExpectation,
    events: list[AuthEvent],
    artifacts: list[str],
) -> EvidenceBundle:
    observed, confidence = infer_observed_decision(events)
    classification = classify_result(observed, expectation.expected_decision, confidence)

    findings = [
        f"Observed decision: {observed.value}",
        f"Expected decision: {expectation.expected_decision.value}",
        f"Functional pass: {observed == expectation.expected_decision}",
    ]

    timeline = [_event_to_timeline_entry(event) for event in events]

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
        metadata={},
    )


def collect_artifacts(run_dir: Path) -> list[str]:
    return sorted(path.name for path in run_dir.iterdir() if path.is_file())


def _event_to_timeline_entry(event: AuthEvent) -> dict:
    """Serialize an AuthEvent into a timeline dict, omitting None fields."""
    d: dict = {
        "ts": event.ts,
        "epoch": event.epoch,
        "kind": event.kind,
        "source": event.source,
        "message": event.message,
        # Tier 2 — auth context
        "endpoint_mac": event.endpoint_mac,
        "endpoint_ip": event.endpoint_ip,
        "username": event.username,
        "machine_name": event.machine_name,
        "session_id": event.session_id,
        "nas_ip": event.nas_ip,
        "nas_port": event.nas_port,
        "calling_station_id": event.calling_station_id,
        "called_station_id": event.called_station_id,
        # Tier 3 — RADIUS packet
        "radius_id": event.radius_id,
        "src_ip": event.src_ip,
        "dst_ip": event.dst_ip,
        "auth_method": event.auth_method,
        "service_type": event.service_type,
        "nas_port_type": event.nas_port_type,
        "nas_port_id": event.nas_port_id,
        "framed_mtu": event.framed_mtu,
        # dot1x plugin state
        "eap_type": event.eap_type,
        "vlan_config": event.vlan_config,
        "policy_enabled": event.policy_enabled,
        "plugin_version": event.plugin_version,
        # Framework context
        "context_id": event.context_id,
        "property_field": event.property_field,
        "property_value": event.property_value,
        # Pre-admission / identity context
        "rule_slot": event.rule_slot,
        "rule_action": event.rule_action,
        "auth_source": event.auth_source,
        "domain": event.domain,
        "login_type": event.login_type,
        "dhcp_hostname": event.dhcp_hostname,
        "dns_name": event.dns_name,
        "classification": event.classification,
    }
    # Include non-empty metadata sub-dict
    if event.metadata:
        d["metadata"] = event.metadata
    # Strip None values to keep JSON compact
    return {k: v for k, v in d.items() if v is not None}
