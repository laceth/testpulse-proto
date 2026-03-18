from __future__ import annotations

import os
from pathlib import Path

from fastapi import APIRouter, HTTPException, Query

from testpulse.services import list_history
from testpulse.services.pipeline import resolve_run_dir

router = APIRouter(prefix="/runs", tags=["runs"])


@router.get("")
def list_runs(
    q: str | None = Query(default=None),
    classification: str | None = Query(default=None),
    outcome: str | None = Query(default=None, pattern="^(pass|fail)?$"),
    limit: int = Query(default=100, ge=1, le=500),
) -> dict:
    artifacts_dir = Path(os.environ.get("TESTPULSE_ARTIFACTS", "artifacts"))
    history = list_history(artifacts_dir, limit=limit, search=q, classification=classification, outcome=outcome)
    if history:
        return {"runs": history, "source": "sqlite", "filters": {"q": q, "classification": classification, "outcome": outcome, "limit": limit}}
    if not artifacts_dir.exists():
        return {"runs": [], "source": "filesystem", "filters": {"q": q, "classification": classification, "outcome": outcome, "limit": limit}}
    runs = []
    q_lower = q.lower() if q else None
    for path in sorted((p for p in artifacts_dir.iterdir() if p.is_dir()), reverse=True):
        if q_lower and q_lower not in path.name.lower():
            continue
        bundle = path / "evidence_bundle.json"
        runs.append({
            "run_id": path.name,
            "has_bundle": bundle.exists(),
        })
        if len(runs) >= limit:
            break
    return {"runs": runs, "source": "filesystem", "filters": {"q": q, "classification": classification, "outcome": outcome, "limit": limit}}


@router.get("/{run_id}")
def get_run(run_id: str) -> dict:
    run_dir = resolve_run_dir(run_id)
    if not run_dir.exists():
        raise HTTPException(status_code=404, detail=f"Run not found: {run_id}")
    bundle = run_dir / "evidence_bundle.json"
    return {
        "run_id": run_id,
        "path": str(run_dir),
        "has_bundle": bundle.exists(),
    }
