from __future__ import annotations

from fastapi import APIRouter, HTTPException

from testpulse.services import get_timeline

router = APIRouter(prefix="/runs", tags=["timeline"])


@router.get("/{run_id}/timeline")
def read_timeline(run_id: str) -> dict:
    try:
        return get_timeline(run_id)
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
