from __future__ import annotations

from pathlib import Path
from typing import Any

from .pipeline import load_bundle_from_dir, resolve_run_dir, load_json_if_exists


def get_timeline(run_id: str, artifacts_dir: Path | None = None) -> dict[str, Any]:
    run_dir = resolve_run_dir(run_id, artifacts_dir)
    bundle = load_bundle_from_dir(run_dir)
    timeline_contract = load_json_if_exists(run_dir / "timeline.json") or {}
    artifact_map = load_json_if_exists(run_dir / "artifact_map.json") or bundle.get("metadata", {}).get("artifact_map", {})
    return {
        "run_id": bundle.get("run_id", run_id),
        "testcase_id": bundle.get("testcase_id"),
        "timeline": timeline_contract.get("timeline", bundle.get("timeline", [])),
        "artifact_map": artifact_map,
        "findings": bundle.get("findings", []),
    }
