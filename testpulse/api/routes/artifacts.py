from __future__ import annotations

from urllib.parse import quote

from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import FileResponse, JSONResponse

from testpulse.services import get_artifact_content, get_artifact_map, resolve_run_dir

router = APIRouter(prefix='/runs', tags=['artifacts'])


@router.get('/{run_id}/artifacts')
def read_artifacts(run_id: str) -> dict:
    try:
        return get_artifact_map(run_id)
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.get('/{run_id}/artifacts/content')
def read_artifact_content(run_id: str, path: str = Query(..., alias='path')):
    try:
        preview = get_artifact_content(run_id, path)
        candidate = resolve_run_dir(run_id) / path
        if preview.get('content_type') == 'binary':
            return FileResponse(candidate)
        preview['download_path'] = f"/runs/{run_id}/artifacts/content?path={quote(path)}"
        return JSONResponse(preview)
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
