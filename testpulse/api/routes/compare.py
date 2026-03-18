from __future__ import annotations

from fastapi import APIRouter, HTTPException, Query

from testpulse.services import get_artifact_diff, get_recommendation_rollup

router = APIRouter(prefix='/runs', tags=['compare'])


@router.get('/{run_id}/compare/{compare_run_id}/recommendations')
def read_recommendation_rollup(run_id: str, compare_run_id: str) -> dict:
    try:
        return get_recommendation_rollup(run_id, compare_run_id)
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.get('/{run_id}/compare/{compare_run_id}/artifacts/diff')
def read_artifact_diff(
    run_id: str,
    compare_run_id: str,
    node_id: str = Query(..., alias='node_id'),
    path: str | None = Query(default=None, alias='path'),
) -> dict:
    try:
        return get_artifact_diff(run_id, compare_run_id, node_id=node_id, path=path)
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
