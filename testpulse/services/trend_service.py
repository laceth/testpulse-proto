from __future__ import annotations

from datetime import datetime
from pathlib import Path
from statistics import median
from typing import Any

from .history_service import resolve_history_db
from .pipeline import load_bundle_from_dir, resolve_run_dir
from testpulse.storage.sqlite import fetch_metric_history, fetch_run_created_at

COMPONENT_METRIC_MAP = {
    'dns': 'dns_lookup_ms',
    'dhcp': 'dhcp_ack_packets',
    'tcpip_relay': 'relay_latency_ms',
    'directory': 'ldap_bind_ms',
    'nas': 'coa_ack_ms',
    'tomahawk': 'tomahawk_fabric_util_pct',
    'ntp': 'ntp_offset_ms',
}


def get_prognostic_trends(
    run_id: str,
    artifacts_dir: Path | None = None,
    limit: int = 25,
    baseline_mode: str = 'testcase_weekday_hour',
    window_hours: int = 2,
) -> dict[str, Any]:
    run_dir = resolve_run_dir(run_id, artifacts_dir)
    bundle = load_bundle_from_dir(run_dir)
    testcase_id = bundle.get('testcase_id')
    rows = fetch_metric_history(resolve_history_db(artifacts_dir), testcase_id=testcase_id, limit=max(limit, 200))
    components: dict[str, list[dict[str, Any]]] = {name: [] for name in COMPONENT_METRIC_MAP}
    history_db = resolve_history_db(artifacts_dir)
    current_run_created_at = _parse_dt(bundle.get('created_at') or fetch_run_created_at(history_db, run_id))

    for row in reversed(rows):
        metric_key = row.get('metric_key')
        if not metric_key:
            continue
        component = next((name for name, key in COMPONENT_METRIC_MAP.items() if key == metric_key), None)
        if not component:
            continue
        components.setdefault(component, []).append({
            'run_id': row.get('run_id'),
            'created_at': row.get('created_at'),
            'metric_key': metric_key,
            'metric_value': row.get('metric_value'),
            'status': row.get('status') or 'UNKNOWN',
            'severity': row.get('severity') or 'low',
        })

    baselines = {
        component: _build_component_baseline(points, current_run_created_at, baseline_mode=baseline_mode, window_hours=window_hours)
        for component, points in components.items()
        if points
    }

    return {
        'run_id': run_id,
        'testcase_id': testcase_id,
        'components': components,
        'metric_map': COMPONENT_METRIC_MAP,
        'baselines': baselines,
        'baseline_mode': baseline_mode,
        'window_hours': window_hours,
    }


def _parse_dt(value: Any) -> datetime | None:
    if not value or not isinstance(value, str):
        return None
    raw = value.replace('Z', '+00:00')
    for candidate in (raw, raw.replace(' ', 'T')):
        try:
            return datetime.fromisoformat(candidate)
        except ValueError:
            continue
    return None


def _build_component_baseline(
    points: list[dict[str, Any]],
    current_run_created_at: datetime | None,
    *,
    baseline_mode: str,
    window_hours: int,
) -> dict[str, Any]:
    eligible: list[dict[str, Any]] = []
    for point in points:
        ts = _parse_dt(point.get('created_at'))
        if ts is None or point.get('metric_value') is None:
            continue
        if baseline_mode == 'testcase_weekday_hour' and current_run_created_at is not None:
            if ts.weekday() != current_run_created_at.weekday():
                continue
            if abs(ts.hour - current_run_created_at.hour) > window_hours:
                continue
        eligible.append(point)

    values = [float(p['metric_value']) for p in eligible if isinstance(p.get('metric_value'), (int, float))]
    if not values:
        return {
            'samples': 0,
            'median': None,
            'min': None,
            'max': None,
            'window': _window_label(current_run_created_at, window_hours),
            'mode': baseline_mode,
        }
    return {
        'samples': len(values),
        'median': round(float(median(values)), 3),
        'min': round(float(min(values)), 3),
        'max': round(float(max(values)), 3),
        'window': _window_label(current_run_created_at, window_hours),
        'mode': baseline_mode,
    }


def _window_label(current_run_created_at: datetime | None, window_hours: int) -> str:
    if current_run_created_at is None:
        return 'all-history'
    return f"weekday={current_run_created_at.strftime('%A')} hour≈{current_run_created_at.hour}±{window_hours}"
