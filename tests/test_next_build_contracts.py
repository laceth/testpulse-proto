import json
from pathlib import Path

from testpulse.services.pipeline import analyze_run
from testpulse.services.history_service import list_history


RADIUS_LOG = """
Received Access-Request Id 7 from 10.0.0.20:12345 to 10.0.0.1:1812 length 120
User-Name = \"host1\"
Calling-Station-Id = \"28-80-23-B8-2D-59\"
NAS-IP-Address = 10.0.0.1
NAS-Port-Id = \"Gi1/0/1\"
Sent Access-Accept Id 7 from 10.0.0.1:1812 to 10.0.0.20:12345 length 100
""".strip()


def test_analyze_run_writes_contract_files_and_history(tmp_path: Path, monkeypatch) -> None:
    artifacts_dir = tmp_path / "artifacts"
    run_dir = artifacts_dir / "RUN-NEXT-1"
    run_dir.mkdir(parents=True)
    (run_dir / "radiusd.log").write_text(RADIUS_LOG, encoding="utf-8")
    endpoint = run_dir / "endpoint"
    endpoint.mkdir()
    (endpoint / "ipconfig_all.txt").write_text("IPv4 Address. . . . . . . . . . . : 10.0.0.20", encoding="utf-8")
    (endpoint / "nslookup_dc.txt").write_text("Server: dc1.example.local", encoding="utf-8")

    monkeypatch.setenv("TESTPULSE_ARTIFACTS", str(artifacts_dir))

    bundle = analyze_run(
        run_dir=run_dir,
        testcase_id="TP-NEXT-001",
        expected_decision="accept",
        service_metrics={"metrics": {"dns_lookup_ms": 20, "dhcp_ack_packets": 2, "ldap_bind_ms": 35, "ntp_offset_ms": 12}},
    )

    assert bundle["metadata"]["component_health"]["dns"]["status"] == "HEALTHY"
    assert (run_dir / "timeline.json").exists()
    assert (run_dir / "component_health.json").exists()
    assert (run_dir / "artifact_map.json").exists()
    assert (run_dir / "service_metrics.json").exists()

    artifact_map = json.loads((run_dir / "artifact_map.json").read_text(encoding="utf-8"))
    assert "radius" in artifact_map["nodes"]
    assert any("radiusd.log" in item for item in artifact_map["nodes"]["radius"])

    history = list_history(artifacts_dir)
    assert any(item["run_id"] == "RUN-NEXT-1" for item in history)
