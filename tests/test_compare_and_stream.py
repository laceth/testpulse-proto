import json
from pathlib import Path

from fastapi.testclient import TestClient

from testpulse.api.app import create_app
from testpulse.services import get_artifact_diff, get_recommendation_rollup


def _make_run(run_dir: Path, *, status: str, severity: str, recommendation: str, radius_message: str) -> None:
    bundle = {
        'run_id': run_dir.name,
        'testcase_id': 'TP-COMPARE-001',
        'classification': 'PASS_CONFIRMED' if status == 'HEALTHY' else 'PRODUCT_DEFECT',
        'functional_pass': status == 'HEALTHY',
        'confidence': 0.91,
        'findings': [radius_message],
        'timeline': [{'kind': 'RADIUS_ACCESS_ACCEPT' if status == 'HEALTHY' else 'RADIUS_ACCESS_REJECT', 'source': 'radiusd.log', 'message': radius_message}],
        'metadata': {
            'component_health_contract': {
                'run_id': run_dir.name,
                'components': [{'component': 'radius', 'status': status, 'severity': severity, 'confidence': 0.91, 'finding': radius_message, 'recommendation': recommendation, 'evidence': ['radiusd.log'], 'details': {}}],
            },
            'artifact_map': {'run_id': run_dir.name, 'nodes': {'radius': ['radiusd.log']}},
            'prognostics': {'predictive_warnings': [{'metric': 'radius_decision_ms', 'message': 'upward drift'}]},
        },
    }
    run_dir.mkdir(parents=True, exist_ok=True)
    (run_dir / 'evidence_bundle.json').write_text(json.dumps(bundle), encoding='utf-8')
    (run_dir / 'radiusd.log').write_text(radius_message + '\nline2', encoding='utf-8')


def test_compare_rollup_and_artifact_diff(tmp_path: Path, monkeypatch) -> None:
    artifacts_dir = tmp_path / 'artifacts'
    _make_run(artifacts_dir / 'RUN-A', status='FAILED', severity='high', recommendation='Check reject path', radius_message='Access-Reject policy miss')
    _make_run(artifacts_dir / 'RUN-B', status='HEALTHY', severity='low', recommendation='No action', radius_message='Access-Accept stable')
    monkeypatch.setenv('TESTPULSE_ARTIFACTS', str(artifacts_dir))
    rollup = get_recommendation_rollup('RUN-A', 'RUN-B')
    assert rollup['changed_nodes']
    assert rollup['rollups'][0]['recommendations'][0]['severity'] == 'high'
    diff = get_artifact_diff('RUN-A', 'RUN-B', node_id='radius')
    assert diff['content_type'] == 'text'
    assert 'Access-Reject policy miss' in diff['diff']
    assert 'Access-Accept stable' in diff['diff']


def test_compare_and_stream_routes(tmp_path: Path, monkeypatch) -> None:
    artifacts_dir = tmp_path / 'artifacts'
    _make_run(artifacts_dir / 'RUN-STREAM-A', status='FAILED', severity='high', recommendation='Check reject path', radius_message='Access-Reject policy miss')
    _make_run(artifacts_dir / 'RUN-STREAM-B', status='HEALTHY', severity='low', recommendation='No action', radius_message='Access-Accept stable')
    monkeypatch.setenv('TESTPULSE_ARTIFACTS', str(artifacts_dir))
    app = create_app(); client = TestClient(app)
    response = client.get('/runs/RUN-STREAM-A/compare/RUN-STREAM-B/recommendations'); assert response.status_code == 200; assert response.json()['rollups']
    response = client.get('/runs/RUN-STREAM-A/compare/RUN-STREAM-B/artifacts/diff?node_id=radius'); assert response.status_code == 200; assert response.json()['content_type'] == 'text'
    with client.stream('GET', '/runs/RUN-STREAM-A/stream?interval_ms=500&max_events=1') as response:
        assert response.status_code == 200
        chunks = []
        for chunk in response.iter_text():
            if chunk: chunks.append(chunk)
            if any('event: snapshot' in item for item in chunks): break
        payload = ''.join(chunks)
        assert 'event: snapshot' in payload
        assert 'RUN-STREAM-A' in payload
