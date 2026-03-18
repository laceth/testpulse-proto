from __future__ import annotations

from fastapi import APIRouter, HTTPException

from testpulse.services import get_component_health

router = APIRouter(prefix="/runs", tags=["health"])


@router.get("/{run_id}/health")
def read_health(run_id: str) -> dict:
    try:
        return get_component_health(run_id)
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
