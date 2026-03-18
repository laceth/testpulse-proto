from testpulse.core.bundle import build_bundle
from testpulse.diagnostics.prognostics import evaluate_prognostics
from testpulse.models import AssuranceExpectation, AuthEvent, Decision


def test_prognostics_cover_five_pillars() -> None:
    history = [
        {
            "run_id": f"RUN-{idx}",
            "testcase_id": "TP-PREADM-001",
            "functional_pass": False if idx in (1, 4) else True,
            "retry_cleared": True if idx in (1, 4) else False,
            "service_metrics": {
                "metrics": {
                    "ldap_bind_ms": value,
                    "dns_lookup_ms": 20 + idx,
                    "dhcp_ack_packets": 2,
                    "coa_ack_ms": 120 + idx * 10,
                    "ntp_offset_ms": 10 + idx,
                }
            },
        }
        for idx, value in enumerate([20, 30, 38, 46, 54, 58], start=1)
    ]
    current_run = {
        "run_id": "RUN-CURRENT",
        "testcase_id": "TP-PREADM-001",
        "functional_pass": True,
        "component_health": {
            "dns": {"status": "HEALTHY"},
            "dhcp": {"status": "DEGRADED"},
            "directory": {"status": "HEALTHY"},
            "ntp": {"status": "HEALTHY"},
            "nas": {"status": "HEALTHY"},
        },
        "service_metrics": {
            "metrics": {
                "ldap_bind_ms": 79,
                "dns_lookup_ms": 29,
                "dhcp_ack_packets": 4,
                "coa_ack_ms": 210,
                "ntp_offset_ms": 24,
            }
        },
    }

    result = evaluate_prognostics(current_run=current_run, history=history)

    assert "trend_health" in result
    assert result["trend_health"]["score"] < 100
    assert result["predictive_warnings"]
    assert any(w["metric"] == "service_metrics.metrics.ldap_bind_ms" for w in result["predictive_warnings"])
    assert result["repeated_run_anomalies"]
    assert any(a["metric"] == "service_metrics.metrics.dhcp_ack_packets" for a in result["repeated_run_anomalies"])
    assert result["flake_forecast"]["status"] in {"MEDIUM", "HIGH"}
    assert result["service_baselines"]["baseline_profile"]
    assert any(item["status"] == "DRIFTED" for item in result["service_baselines"]["current_deviation"])


def test_build_bundle_embeds_prognostics() -> None:
    events = [
        AuthEvent(
            ts="2026-03-17T12:00:00Z",
            kind="RADIUS_ACCESS_ACCEPT",
            source="radiusd.log",
            message="Access-Accept",
            endpoint_ip="10.0.0.10",
            dns_name="host1.example.local",
            dhcp_hostname="host1",
            domain="example.local",
            login_type="dot1x_user_login",
        )
    ]
    history = [
        {
            "run_id": "RUN-1",
            "testcase_id": "TP-1",
            "functional_pass": True,
            "service_metrics": {"metrics": {"ldap_bind_ms": 20, "dns_lookup_ms": 18, "dhcp_ack_packets": 2, "coa_ack_ms": 100, "ntp_offset_ms": 12}},
        },
        {
            "run_id": "RUN-2",
            "testcase_id": "TP-1",
            "functional_pass": True,
            "service_metrics": {"metrics": {"ldap_bind_ms": 25, "dns_lookup_ms": 20, "dhcp_ack_packets": 2, "coa_ack_ms": 110, "ntp_offset_ms": 11}},
        },
        {
            "run_id": "RUN-3",
            "testcase_id": "TP-1",
            "functional_pass": True,
            "service_metrics": {"metrics": {"ldap_bind_ms": 35, "dns_lookup_ms": 22, "dhcp_ack_packets": 2, "coa_ack_ms": 130, "ntp_offset_ms": 10}},
        },
    ]

    bundle = build_bundle(
        run_id="RUN-4",
        expectation=AssuranceExpectation(testcase_id="TP-1", expected_decision=Decision.ACCEPT),
        events=events,
        artifacts=["framework.log"],
        history=history,
        service_metrics={"metrics": {"ldap_bind_ms": 55, "dns_lookup_ms": 24, "dhcp_ack_packets": 2, "coa_ack_ms": 180, "ntp_offset_ms": 9}},
    ).to_dict()

    assert "prognostics" in bundle["metadata"]
    assert "trend_health" in bundle["metadata"]["prognostics"]
    assert "Predictive warning:" in " ".join(bundle["findings"])
