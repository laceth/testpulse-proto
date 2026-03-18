import json
from pathlib import Path

from testpulse.diagnostics.health import evaluate_component_health
from testpulse.models import AuthEvent, Decision
from testpulse.services.trend_service import get_prognostic_trends
from testpulse.services.history_service import record_run


def test_component_health_includes_tcpip_relay_and_tomahawk() -> None:
    events = [
        AuthEvent(
            ts='2026-03-17T12:00:00Z',
            kind='RADIUS_ACCESS_ACCEPT',
            source='relay/tomahawk.log',
            message='Tomahawk relay path healthy',
            metadata={'relay': True, 'platform': 'Tomahawk'},
            endpoint_ip='10.0.0.10',
            dns_name='host1.example.local',
            domain='example.local',
        )
    ]
    component_health, findings = evaluate_component_health(
        events,
        observed_decision=Decision.ACCEPT,
        expected_decision=Decision.ACCEPT,
        service_metrics={'metrics': {'relay_latency_ms': 55, 'relay_hops': 1, 'tomahawk_fabric_util_pct': 62, 'tomahawk_drop_pct': 0.2}},
        artifact_map={'tcpip_relay': ['switch/relay.log'], 'tomahawk': ['switch/tomahawk_counters.txt']},
        run_id='RUN-FEATURE-1',
    )
    names = {item['component'] for item in component_health['components']}
    assert 'tcpip_relay' in names
    assert 'tomahawk' in names
    assert component_health['tcpip_relay']['status'] == 'HEALTHY'
    assert component_health['tomahawk']['status'] == 'HEALTHY'
    assert len(findings) >= 2


def test_trend_service_includes_baselines(tmp_path: Path) -> None:
    artifacts_dir = tmp_path / 'artifacts'
    for idx, relay_value in enumerate([40, 55, 60], start=1):
        bundle = {
            'run_id': f'RUN-{idx}',
            'testcase_id': 'TP-TREND-1',
            'classification': 'PASS_CONFIRMED',
            'observed_decision': 'accept',
            'expected_decision': 'accept',
            'functional_pass': True,
            'confidence': 0.9,
            'metadata': {
                'component_health_contract': {
                    'components': [
                        {'component': 'tcpip_relay', 'status': 'HEALTHY', 'severity': 'low', 'confidence': 0.8, 'finding': 'ok', 'recommendation': 'none'},
                        {'component': 'tomahawk', 'status': 'HEALTHY', 'severity': 'low', 'confidence': 0.8, 'finding': 'ok', 'recommendation': 'none'},
                    ]
                },
                'service_metrics': {
                    'metrics': {
                        'relay_latency_ms': relay_value,
                        'tomahawk_fabric_util_pct': 50 + idx,
                    }
                },
            },
        }
        run_dir = artifacts_dir / bundle['run_id']
        run_dir.mkdir(parents=True, exist_ok=True)
        (run_dir / 'evidence_bundle.json').write_text(json.dumps(bundle), encoding='utf-8')
        record_run(bundle, artifacts_dir)

    trends = get_prognostic_trends('RUN-3', artifacts_dir=artifacts_dir, limit=10)
    assert 'tcpip_relay' in trends['components']
    assert 'tomahawk' in trends['components']
    assert trends['baselines']['tcpip_relay']['samples'] >= 1
    assert trends['baselines']['tomahawk']['samples'] >= 1
