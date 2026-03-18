import json
from pathlib import Path

from fastapi.testclient import TestClient

from testpulse.api.app import create_app
from testpulse.services import get_artifact_content, get_artifact_map, get_bundle, get_component_health, get_prognostics, get_prognostic_trends, get_timeline


def _write_bundle(run_dir: Path) -> None:
    bundle = {
        "run_id": run_dir.name,
        "testcase_id": "TP-API-001",
        "classification": "PASS_CONFIRMED",
        "findings": ["Observed decision: accept"],
        "timeline": [{"kind": "RADIUS_ACCESS_ACCEPT", "source": "radiusd.log"}],
        "metadata": {
            "component_health": {
                "dns": {"status": "HEALTHY", "evidence": ["endpoint/ipconfig.txt"]},
            },
            "component_health_contract": {
                "run_id": run_dir.name,
                "components": [{"component": "dns", "status": "HEALTHY", "severity": "low", "confidence": 0.9, "finding": "ok", "recommendation": "none", "evidence": ["endpoint/ipconfig.txt"], "details": {}}],
            },
            "artifact_map": {"run_id": run_dir.name, "nodes": {"radius": ["radiusd.log"]}},
            "service_metrics": {"run_id": run_dir.name, "metrics": {"dns_lookup_ms": 20}},
            "prognostics": {
                "trend_health": {"score": 90.0, "factors": []},
                "predictive_warnings": [],
                "repeated_run_anomalies": [],
                "flake_forecast": {"status": "LOW", "risk": 0.1},
                "service_baselines": {"baseline_profile": {}, "current_deviation": []},
            },
        },
        "artifacts": ["framework.log"],
    }
    run_dir.mkdir(parents=True, exist_ok=True)
    (run_dir / 'evidence_bundle.json').write_text(json.dumps(bundle), encoding='utf-8')
    (run_dir / 'radiusd.log').write_text('Access-Accept', encoding='utf-8')


def test_services_load_bundle_views(tmp_path: Path, monkeypatch) -> None:
    artifacts_dir = tmp_path / 'artifacts'
    run_dir = artifacts_dir / 'RUN-API-1'
    _write_bundle(run_dir)
    monkeypatch.setenv('TESTPULSE_ARTIFACTS', str(artifacts_dir))

    assert get_bundle('RUN-API-1')['classification'] == 'PASS_CONFIRMED'
    assert get_timeline('RUN-API-1')['timeline'][0]['kind'] == 'RADIUS_ACCESS_ACCEPT'
    assert get_component_health('RUN-API-1')['components'][0]['status'] == 'HEALTHY'
    assert get_artifact_map('RUN-API-1')['nodes']['radius'] == ['radiusd.log']
    assert get_artifact_content('RUN-API-1', 'radiusd.log')['content_type'] == 'text'
    assert get_prognostics('RUN-API-1')['prognostics']['trend_health']['score'] == 90.0
    assert get_prognostic_trends('RUN-API-1')['run_id'] == 'RUN-API-1'


def test_api_routes_expose_run_view(tmp_path: Path, monkeypatch) -> None:
    artifacts_dir = tmp_path / 'artifacts'
    run_dir = artifacts_dir / 'RUN-API-2'
    _write_bundle(run_dir)
    monkeypatch.setenv('TESTPULSE_ARTIFACTS', str(artifacts_dir))

    app = create_app()
    client = TestClient(app)

    assert client.get('/healthz').json() == {'status': 'ok'}
    runs = client.get('/runs').json()['runs']
    assert any(item['run_id'] == 'RUN-API-2' for item in runs)
    assert client.get('/runs/RUN-API-2/bundle').status_code == 200
    assert client.get('/runs/RUN-API-2/timeline').json()['timeline'][0]['kind'] == 'RADIUS_ACCESS_ACCEPT'
    assert client.get('/runs/RUN-API-2/health').json()['components'][0]['status'] == 'HEALTHY'
    assert client.get('/runs/RUN-API-2/artifacts').json()['nodes']['radius'] == ['radiusd.log']
    assert client.get('/runs/RUN-API-2/artifacts/content?path=radiusd.log').json()['content_type'] == 'text'
    assert client.get('/runs/RUN-API-2/prognostics').json()['prognostics']['trend_health']['score'] == 90.0
    assert client.get('/runs/RUN-API-2/trends').json()['run_id'] == 'RUN-API-2'


def test_api_run_filters(tmp_path: Path, monkeypatch) -> None:
    artifacts_dir = tmp_path / 'artifacts'
    run_ok = artifacts_dir / 'RUN-PASS-1'
    run_fail = artifacts_dir / 'RUN-FAIL-2'
    _write_bundle(run_ok)
    failing_bundle = json.loads((run_ok / 'evidence_bundle.json').read_text(encoding='utf-8'))
    failing_bundle.update({
        'run_id': run_fail.name,
        'classification': 'PRODUCT_DEFECT',
        'functional_pass': False,
        'observed_decision': 'reject',
        'expected_decision': 'accept',
    })
    run_fail.mkdir(parents=True, exist_ok=True)
    (run_fail / 'evidence_bundle.json').write_text(json.dumps(failing_bundle), encoding='utf-8')
    monkeypatch.setenv('TESTPULSE_ARTIFACTS', str(artifacts_dir))

    from testpulse.services.history_service import record_run
    record_run(json.loads((run_ok / 'evidence_bundle.json').read_text(encoding='utf-8')), artifacts_dir)
    record_run(failing_bundle, artifacts_dir)

    app = create_app()
    client = TestClient(app)

    filtered = client.get('/runs?outcome=fail').json()['runs']
    assert len(filtered) == 1
    assert filtered[0]['run_id'] == 'RUN-FAIL-2'
    filtered = client.get('/runs?classification=PRODUCT_DEFECT').json()['runs']
    assert len(filtered) == 1
    assert filtered[0]['run_id'] == 'RUN-FAIL-2'
