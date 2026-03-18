from testpulse.diagnostics import evaluate_component_health
from testpulse.models import AuthEvent, Decision


def test_component_health_flags_missing_dependencies_for_expected_accept() -> None:
    events = [
        AuthEvent(
            ts=None,
            kind='ENDPOINT_NIC_INFO',
            source='endpoint/ipconfig_all.txt',
            message='NIC mac=aa-bb-cc-dd-ee-ff, ip=10.0.0.20',
            endpoint_ip='10.0.0.20',
        )
    ]

    health, findings = evaluate_component_health(
        events=events,
        observed_decision=Decision.REJECT,
        expected_decision=Decision.ACCEPT,
    )

    assert health['dns']['status'] == 'UNKNOWN'
    assert health['directory']['status'] == 'FAILED'
    assert health['prognostic_signals']
    assert any('DNS health:' in item for item in findings)
