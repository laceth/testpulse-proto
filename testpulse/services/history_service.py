from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from testpulse.storage.sqlite import DEFAULT_DB_NAME, fetch_bundle, fetch_runs, upsert_bundle


def resolve_history_db(artifacts_dir: Path | None = None) -> Path:
    configured = os.environ.get("TESTPULSE_HISTORY_DB")
    if configured:
        return Path(configured)
    base = artifacts_dir or Path(os.environ.get("TESTPULSE_ARTIFACTS", "artifacts"))
    return base / DEFAULT_DB_NAME


def record_run(bundle: dict[str, Any], artifacts_dir: Path | None = None) -> Path:
    db_path = resolve_history_db(artifacts_dir)
    upsert_bundle(db_path, bundle)
    return db_path


def list_history(
    artifacts_dir: Path | None = None,
    limit: int = 100,
    search: str | None = None,
    classification: str | None = None,
    outcome: str | None = None,
) -> list[dict[str, Any]]:
    return fetch_runs(
        resolve_history_db(artifacts_dir),
        limit=limit,
        search=search,
        classification=classification,
        outcome=outcome,
    )


def load_historical_bundle(run_id: str, artifacts_dir: Path | None = None) -> dict[str, Any] | None:
    return fetch_bundle(resolve_history_db(artifacts_dir), run_id)
