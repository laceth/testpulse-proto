from pathlib import Path

from testpulse.core.bundle import build_bundle, collect_artifacts
from testpulse.models import AssuranceExpectation, AuthEvent, Decision


def test_collect_artifacts_is_recursive(tmp_path: Path) -> None:
    (tmp_path / 'framework.log').write_text('ok', encoding='utf-8')
    endpoint = tmp_path / 'endpoint'
    endpoint.mkdir()
    (endpoint / 'ipconfig_all.txt').write_text('ipconfig', encoding='utf-8')

    artifacts = collect_artifacts(tmp_path)

    assert artifacts == ['endpoint/ipconfig_all.txt', 'framework.log']


def test_build_bundle_includes_component_health_and_metrics() -> None:
    events = [
        AuthEvent(
            ts='2026-03-17 12:00:00',
            kind='RADIUS_ACCESS_ACCEPT',
            source='radiusd.log',
            message='Access-Accept',
            endpoint_ip='10.0.0.10',
            endpoint_mac='28-80-23-B8-2D-59',
            domain='example.local',
            dhcp_hostname='host1',
            dns_name='host1.example.local',
            login_type='dot1x_user_login',
        )
    ]

    bundle = build_bundle(
        run_id='RUN-1',
        expectation=AssuranceExpectation(
            testcase_id='TP-1',
            expected_decision=Decision.ACCEPT,
        ),
        events=events,
        artifacts=['framework.log'],
    ).to_dict()

    assert bundle['functional_pass'] is True
    assert bundle['metadata']['metrics']['radius_accepts'] == 1
    assert bundle['metadata']['component_health']['dns']['status'] == 'HEALTHY'
    assert bundle['metadata']['component_health']['dhcp']['status'] == 'HEALTHY'
    assert bundle['metadata']['component_health']['directory']['status'] == 'HEALTHY'
    assert any('DNS health:' in finding for finding in bundle['findings'])
