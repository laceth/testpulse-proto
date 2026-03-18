from testpulse.diagnostics import evaluate_component_health
from testpulse.models import AuthEvent, Decision


def test_component_health_includes_ntp_and_nas() -> None:
    events = [
        AuthEvent(ts=None, kind='RADIUS_ACCESS_ACCEPT', source='radiusd.log', message='accept', nas_ip='10.0.0.1', nas_port='Gi1/0/1', domain='example.local', dns_name='host1.example.local', endpoint_ip='10.0.0.20')
    ]
    health, _ = evaluate_component_health(
        events,
        observed_decision=Decision.ACCEPT,
        expected_decision=Decision.ACCEPT,
        service_metrics={"metrics": {"ntp_offset_ms": 9, "coa_ack_ms": 120, "dns_lookup_ms": 20, "dhcp_ack_packets": 2, "ldap_bind_ms": 30}},
        artifact_map={"dns": ["endpoint/nslookup_dc.txt"], "dhcp": ["endpoint/ipconfig_all.txt"], "ad_ldap": ["identity/local_properties.txt"], "nas_authorization": ["switch/show_auth_session_detail.txt"], "coa": ["switch/switch_syslog.txt"], "ntp": ["time/show_ntp_status.txt"]},
        run_id='RUN-HEALTH-1',
    )

    assert health['ntp']['status'] == 'HEALTHY'
    assert health['nas']['status'] == 'HEALTHY'
    assert len(health['contract']['components']) >= 7
