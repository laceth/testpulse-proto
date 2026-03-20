from testpulse.core.evaluate import infer_observed_decision
from testpulse.models import AuthEvent, Decision


def test_infer_observed_decision_prefers_radius_accept() -> None:
    events = [
        AuthEvent(ts=None, kind='FRAMEWORK_TEST_FAILED', source='framework.log', message='fail'),
        AuthEvent(ts=None, kind='RADIUS_ACCESS_ACCEPT', source='radiusd.log', message='accept'),
    ]

    decision, confidence = infer_observed_decision(events)

    assert decision == Decision.ACCEPT
    assert confidence >= 0.85


def test_infer_observed_decision_identity_only_reject() -> None:
    events = [
        AuthEvent(
            ts=None,
            kind='IDENTITY_AUTH_STATE',
            source='hostinfo.txt',
            message='auth',
            property_value='Access-Reject',
        )
    ]

    decision, confidence = infer_observed_decision(events)

    assert decision == Decision.REJECT
    assert confidence == 0.70


def test_infer_observed_decision_mixed_radius_prefers_framework_accept() -> None:
    events = [
        # Mixed packet evidence
        AuthEvent(ts=None, kind='RADIUS_ACCESS_REJECT', source='radiusd.log', message='reject'),
        AuthEvent(ts=None, kind='RADIUS_ACCESS_ACCEPT', source='radiusd.log', message='accept'),
        # Strong framework corroboration
        AuthEvent(ts=None, kind='FRAMEWORK_PROP_CHECK', source='framework.log', message='dot1x_auth_state: expected=Access-Accept, actual=Access-Accept, match=True'),
        AuthEvent(ts=None, kind='FRAMEWORK_ALL_CHECKS_PASSED', source='framework.log', message='All property checks passed'),
        # Weak failure signal (should not win)
        AuthEvent(ts=None, kind='ENDPOINT_AUTH_FAILURE', source='dot1x.log', message='reauth failed'),
    ]

    decision, confidence = infer_observed_decision(events)

    assert decision == Decision.ACCEPT
    assert confidence >= 0.90
