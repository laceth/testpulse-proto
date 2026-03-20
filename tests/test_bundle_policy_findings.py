from __future__ import annotations

from testpulse.core.bundle import build_bundle
from testpulse.models import AssuranceExpectation, AuthEvent, Decision


def test_bundle_surfaces_reject_dummy_as_informational_policy() -> None:
    expectation = AssuranceExpectation(
        testcase_id="T1316993",
        expected_decision=Decision.ACCEPT,
        expected_method="peap-eap-tls",
    )

    events = [
        # Run passes per framework evidence
        AuthEvent(ts=None, kind="FRAMEWORK_ALL_CHECKS_PASSED", source="framework.log", message="All property checks passed"),
        AuthEvent(ts=None, kind="RADIUS_ACCESS_ACCEPT", source="radiusd.log", message="Sent Access-Accept"),
        # Policy/config signal should be informational only
        AuthEvent(
            ts=None,
            kind="DOT1X_VLAN_RESTRICT_CONFIG",
            source="dot1x.log",
            message="'restrict' => 'reject=dummy'",
            vlan_config="reject=dummy",
        ),
    ]

    bundle = build_bundle(
        run_id="run1",
        expectation=expectation,
        events=events,
        artifacts=[],
        history=[],
        service_metrics={},
        artifact_map={"run_id": "run1", "nodes": {}},
    )

    assert bundle.functional_pass is True
    assert any("DOT1X policy present" in f for f in bundle.findings)
