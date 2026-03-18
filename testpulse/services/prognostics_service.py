from __future__ import annotations

from pathlib import Path
from typing import Any

from .pipeline import load_bundle_from_dir, resolve_run_dir


def get_prognostics(run_id: str, artifacts_dir: Path | None = None) -> dict[str, Any]:
    run_dir = resolve_run_dir(run_id, artifacts_dir)
    bundle = load_bundle_from_dir(run_dir)
    metadata = bundle.get("metadata", {})
    return {
        "run_id": bundle.get("run_id", run_id),
        "testcase_id": bundle.get("testcase_id"),
        "prognostics": metadata.get("prognostics", {}),
    }
