from __future__ import annotations

from fastapi import APIRouter, HTTPException

from testpulse.services import get_prognostics

router = APIRouter(prefix="/runs", tags=["prognostics"])


@router.get("/{run_id}/prognostics")
def read_prognostics(run_id: str) -> dict:
    try:
        return get_prognostics(run_id)
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
