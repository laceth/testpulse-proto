from __future__ import annotations

from testpulse.models import AuthEvent, Decision


def infer_observed_decision(events: list[AuthEvent]) -> tuple[Decision, float]:
    """Infer the observed RADIUS decision from parsed events.

    Evidence sources (strongest → weakest):
      1. ``RADIUS_ACCESS_ACCEPT`` / ``RADIUS_ACCESS_REJECT`` — packet-level
      2. ``FRAMEWORK_AUTH_STATE`` — Forescout property ``dot1x_auth_state``
      3. ``FRAMEWORK_HOST_AUTH_STATUS`` — ``dot1x_host_auth_status``
      4. ``FRAMEWORK_TEST_PASSED`` / ``FRAMEWORK_TEST_FAILED``
      5. ``FRAMEWORK_ALL_CHECKS_PASSED`` — property verification summary
      6. ``ENDPOINT_AUTH_SUCCESS`` / ``ENDPOINT_AUTH_FAILURE`` (legacy dot1x)
      7. ``ENDPOINT_WIRED_AUTOCONFIG`` — endpoint-side wired auth events
    """
    # -- RADIUS packet evidence
    saw_accept = any(e.kind == "RADIUS_ACCESS_ACCEPT" for e in events)
    saw_reject = any(e.kind == "RADIUS_ACCESS_REJECT" for e in events)

    # -- Framework property evidence
    saw_fw_accept = any(
        e.kind in ("FRAMEWORK_AUTH_STATE", "FRAMEWORK_HOST_AUTH_STATUS")
        and "Access-Accept" in (e.message or "")
        for e in events
    )
    saw_fw_reject = any(
        e.kind in ("FRAMEWORK_AUTH_STATE", "FRAMEWORK_HOST_AUTH_STATUS")
        and "Access-Reject" in (e.message or "")
        for e in events
    )

    # -- Framework test result evidence
    saw_test_passed = any(e.kind == "FRAMEWORK_TEST_PASSED" for e in events)
    saw_test_failed = any(e.kind == "FRAMEWORK_TEST_FAILED" for e in events)
    saw_all_checks = any(e.kind == "FRAMEWORK_ALL_CHECKS_PASSED" for e in events)

    # -- Endpoint-side evidence (legacy dot1x or wired autoconfig parser)
    saw_endpoint_success = any(
        e.kind in ("ENDPOINT_AUTH_SUCCESS", "ENDPOINT_WIRED_AUTH_SUCCESS")
        for e in events
    )
    saw_endpoint_failure = any(
        e.kind in ("ENDPOINT_AUTH_FAILURE", "ENDPOINT_WIRED_AUTH_FAILURE")
        for e in events
    )

    # -- Identity context evidence (from fstool hostinfo)
    saw_identity_accept = any(
        e.kind == "IDENTITY_AUTH_STATE"
        and "Accept" in (e.property_value or "")
        for e in events
    )
    saw_identity_reject = any(
        e.kind == "IDENTITY_AUTH_STATE"
        and "Reject" in (e.property_value or "")
        for e in events
    )
    has_identity_context = any(
        e.kind in ("IDENTITY_HOST_RECORD", "IDENTITY_PROPERTY")
        for e in events
    )
    has_redis_rules = any(
        e.kind in ("REDIS_RULE_STATE", "REDIS_RULE_SET")
        for e in events
    )

    # -- Decision logic: RADIUS packets are most authoritative
    if saw_accept and not saw_reject:
        # RADIUS Accept confirmed; boost confidence with corroboration
        if saw_fw_accept or saw_test_passed or saw_all_checks:
            conf = 0.98
            if saw_identity_accept:
                conf = 0.99  # triple-source confirmed
            return Decision.ACCEPT, conf
        if saw_identity_accept:
            return Decision.ACCEPT, 0.96
        if saw_endpoint_success:
            return Decision.ACCEPT, 0.95
        return Decision.ACCEPT, 0.85

    if saw_reject and not saw_accept:
        if saw_fw_reject or saw_test_failed:
            conf = 0.98
            if saw_identity_reject:
                conf = 0.99
            return Decision.REJECT, conf
        if saw_identity_reject:
            return Decision.REJECT, 0.96
        if saw_endpoint_failure:
            return Decision.REJECT, 0.95
        return Decision.REJECT, 0.85

    # No RADIUS packets — fall back to framework properties
    if saw_fw_accept and not saw_fw_reject:
        conf = 0.90 if (saw_all_checks or saw_test_passed) else 0.75
        if saw_identity_accept:
            conf = min(conf + 0.05, 0.98)
        return Decision.ACCEPT, conf

    if saw_fw_reject and not saw_fw_accept:
        conf = 0.90 if saw_test_failed else 0.75
        if saw_identity_reject:
            conf = min(conf + 0.05, 0.98)
        return Decision.REJECT, conf

    # Identity-only evidence (from hostinfo)
    if saw_identity_accept and not saw_identity_reject:
        return Decision.ACCEPT, 0.70
    if saw_identity_reject and not saw_identity_accept:
        return Decision.REJECT, 0.70

    # Framework test results only
    if saw_test_passed and not saw_test_failed:
        return Decision.ACCEPT, 0.60
    if saw_test_failed and not saw_test_passed:
        return Decision.REJECT, 0.60

    # Endpoint-only evidence (lowest confidence)
    if saw_endpoint_success and not saw_endpoint_failure:
        return Decision.ACCEPT, 0.55
    if saw_endpoint_failure and not saw_endpoint_success:
        return Decision.REJECT, 0.55

    return Decision.UNKNOWN, 0.4


def classify_result(observed: Decision, expected: Decision, confidence: float) -> str:
    if observed == Decision.UNKNOWN:
        return "INSUFFICIENT_EVIDENCE"
    if observed == expected:
        return "PASS_CONFIRMED" if confidence >= 0.9 else "PASS_LOW_CONFIDENCE"
    return "MISMATCH"
