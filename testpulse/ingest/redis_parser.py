"""Parse Redis artifacts for pre-admission rule state.

Two artifact types:

1. **redis_monitor.log** — ``redis-cli monitor`` capture::

       1773367843.809836 [0 127.0.0.1:55100] "DEL" "default"
       1773367843.809981 [0 127.0.0.1:55100] "HSET" "default" "rule_2" "vlan:\\tIsCOA:false"
       1773367843.810246 [0 127.0.0.1:55100] "HSET" "default" "rule_3" "reject=dummy"

2. **redis_hash_dump.txt** — ``redis-cli HGETALL "default"``::

       rule_1
       vlan:\\tIsCOA:false
       rule_2
       vlan:\\tIsCOA:false
       rule_3
       reject=dummy

Both produce ``AuthEvent`` objects with ``source="redis"`` that capture the
pre-admission rule configuration seen at evidence-collection time.
"""
from __future__ import annotations

import re
from testpulse.models import AuthEvent


# --------------------------------------------------------------------------
# MONITOR format patterns
# --------------------------------------------------------------------------
#   1773367843.809981 [0 127.0.0.1:55100] "HSET" "default" "rule_2" "vlan:\tIsCOA:false"
_MONITOR_RE = re.compile(
    r"^(?P<epoch>\d+\.\d+)\s+"
    r"\[(?P<db>\d+)\s+(?P<client>[^\]]+)\]\s+"
    r'"(?P<cmd>[A-Z]+)"'
    r"(?:\s+(?P<rest>.+))?$"
)

# Parse quoted arguments from the rest of a MONITOR line
_QUOTED_ARG_RE = re.compile(r'"([^"]*)"')


# --------------------------------------------------------------------------
# Pre-admission rule auth value interpretation
# --------------------------------------------------------------------------
_REJECT_PATTERN = re.compile(r"reject", re.IGNORECASE)


def _interpret_auth_value(value: str) -> str:
    """Map a redis pre-admission auth value to accept/reject/unknown."""
    if _REJECT_PATTERN.search(value):
        return "reject"
    if "vlan:" in value.lower() or "iscoa" in value.lower():
        return "accept"
    return "unknown"


# =========================================================================
# Public API
# =========================================================================

def parse_redis_monitor(text: str) -> list[AuthEvent]:
    """Parse ``redis-cli monitor`` output.

    Emits events for:
    - **REDIS_RULE_SET** — HSET on the pre-admission hash
    - **REDIS_RULE_DEL** — DEL of the pre-admission hash (rule reload)
    """
    events: list[AuthEvent] = []
    if not text:
        return events

    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue

        m = _MONITOR_RE.match(line)
        if not m:
            continue

        epoch = float(m.group("epoch"))
        cmd = m.group("cmd").upper()
        rest = m.group("rest") or ""
        args = _QUOTED_ARG_RE.findall(rest)

        if cmd == "HSET" and len(args) >= 3:
            hash_key, field, value = args[0], args[1], args[2]
            auth_action = _interpret_auth_value(value)
            events.append(AuthEvent(
                ts=None,
                kind="REDIS_RULE_SET",
                source="redis",
                message=f"{field}={value}",
                epoch=epoch,
                metadata={
                    "redis_cmd": cmd,
                    "hash_key": hash_key,
                    "rule_field": field,
                    "rule_value": value,
                    "auth_action": auth_action,
                },
                raw_line=line,
            ))

        elif cmd == "DEL" and args:
            events.append(AuthEvent(
                ts=None,
                kind="REDIS_RULE_DEL",
                source="redis",
                message=f"DEL {args[0]}",
                epoch=epoch,
                metadata={
                    "redis_cmd": cmd,
                    "hash_key": args[0],
                },
                raw_line=line,
            ))

        elif cmd == "HGET" and len(args) >= 2:
            events.append(AuthEvent(
                ts=None,
                kind="REDIS_RULE_READ",
                source="redis",
                message=f"HGET {args[0]} {args[1]}",
                epoch=epoch,
                metadata={
                    "redis_cmd": cmd,
                    "hash_key": args[0],
                    "rule_field": args[1],
                },
                raw_line=line,
            ))

    return events


def parse_redis_hash_dump(text: str) -> list[AuthEvent]:
    """Parse ``redis-cli HGETALL`` output.

    HGETALL returns alternating key/value lines::

        rule_1
        vlan:\\tIsCOA:false
        rule_2
        reject=dummy

    Produces one ``REDIS_RULE_STATE`` event per rule describing the
    snapshot state at collection time.
    """
    events: list[AuthEvent] = []
    if not text:
        return events

    lines = [l.strip() for l in text.splitlines() if l.strip()]

    # HGETALL produces key/value pairs
    i = 0
    while i + 1 < len(lines):
        field = lines[i]
        value = lines[i + 1]
        i += 2

        # Skip non-rule lines (e.g. redis-cli header noise)
        if not field.startswith("rule_") and not re.match(r"^\d+\)$", field):
            continue

        # Handle redis-cli numbered output: "1) rule_1" / "2) vlan:..."
        if re.match(r"^\d+\)$", field):
            # numbered output — the key is the value, next line is the real value
            # e.g.: "1)" / "rule_1" / "2)" / "vlan:..."
            # skip, handled by paired iteration
            continue

        auth_action = _interpret_auth_value(value)
        events.append(AuthEvent(
            ts=None,
            kind="REDIS_RULE_STATE",
            source="redis",
            message=f"{field}={value}",
            metadata={
                "rule_field": field,
                "rule_value": value,
                "auth_action": auth_action,
            },
        ))

    return events


def parse_redis(run_dir_path: str) -> list[AuthEvent]:
    """Convenience: parse all redis artifacts from a run directory.

    Looks for ``redis_monitor.log`` and ``redis_hash_dump.txt``.
    """
    from pathlib import Path
    events: list[AuthEvent] = []
    run_dir = Path(run_dir_path)

    monitor = run_dir / "redis_monitor.log"
    if monitor.exists():
        events.extend(parse_redis_monitor(monitor.read_text(encoding="utf-8", errors="ignore")))

    dump = run_dir / "redis_hash_dump.txt"
    if dump.exists():
        events.extend(parse_redis_hash_dump(dump.read_text(encoding="utf-8", errors="ignore")))

    return events
