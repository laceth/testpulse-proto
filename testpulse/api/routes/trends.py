from __future__ import annotations

from fastapi import APIRouter, HTTPException, Query

from testpulse.services import get_prognostic_trends

router = APIRouter(prefix='/runs', tags=['trends'])


@router.get('/{run_id}/trends')
def read_trends(
    run_id: str,
    limit: int = Query(default=25, ge=1, le=100),
    baseline_mode: str = Query(default='testcase_weekday_hour'),
    window_hours: int = Query(default=2, ge=0, le=12),
) -> dict:
    try:
        return get_prognostic_trends(run_id, limit=limit, baseline_mode=baseline_mode, window_hours=window_hours)
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
