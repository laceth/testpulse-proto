import pytest

from testpulse.ingest.radiusd_parser import parse_radiusd


def test_parse_radiusd_captures_request_ctx_and_access_challenge_and_cleanup():
    text = "\n".join(
        [
            # Packet with request context number
            "radiusd:13099:1773958823.864853:Thu Mar 19 17:20:23 2026: Thu Mar 19 17:20:23 2026 : Debug: (8) Sent Access-Challenge Id 41 from 10.16.177.66:1812 to 10.16.128.18:58444 length 1546",
            "radiusd:13099:1773958828.859817:Thu Mar 19 17:20:28 2026: Thu Mar 19 17:20:28 2026 : Debug: (8) Cleaning up request packet ID 41 with timestamp +116 due to cleanup_delay was reached",
        ]
    )

    events = parse_radiusd(text)
    kinds = [e.kind for e in events]

    # We should parse Access-Challenge and cleanup.
    assert "RADIUS_ACCESS_CHALLENGE" in kinds
    assert "RADIUSD_REQUEST_CLEANUP" in kinds

    challenge = next(e for e in events if e.kind == "RADIUS_ACCESS_CHALLENGE")
    assert challenge.radius_id == 41
    assert challenge.src_ip == "10.16.177.66"
    assert challenge.dst_ip == "10.16.128.18"
    assert challenge.packet_length == 1546
    assert challenge.metadata.get("request_ctx") == 8

    cleanup = next(e for e in events if e.kind == "RADIUSD_REQUEST_CLEANUP")
    assert cleanup.radius_id == 41
    assert cleanup.metadata.get("age") == 116
    assert cleanup.metadata.get("reason") == "cleanup_delay"
