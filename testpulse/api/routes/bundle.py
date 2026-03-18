from __future__ import annotations

from fastapi import APIRouter, HTTPException

from testpulse.services import get_bundle

router = APIRouter(prefix="/runs", tags=["bundle"])


@router.get("/{run_id}/bundle")
def read_bundle(run_id: str) -> dict:
    try:
        return get_bundle(run_id)
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
