from __future__ import annotations

from pathlib import Path
from typing import Any

from .pipeline import load_bundle_from_dir, resolve_run_dir, load_json_if_exists


def get_bundle(run_id: str, artifacts_dir: Path | None = None) -> dict[str, Any]:
    run_dir = resolve_run_dir(run_id, artifacts_dir)
    return load_bundle_from_dir(run_dir)


def get_component_health(run_id: str, artifacts_dir: Path | None = None) -> dict[str, Any]:
    run_dir = resolve_run_dir(run_id, artifacts_dir)
    contract = load_json_if_exists(run_dir / "component_health.json")
    if contract:
        return contract
    bundle = load_bundle_from_dir(run_dir)
    metadata = bundle.get("metadata", {})
    return {
        "run_id": bundle.get("run_id", run_id),
        "testcase_id": bundle.get("testcase_id"),
        "components": metadata.get("component_health_contract", {}).get("components", []),
        "component_health": metadata.get("component_health", {}),
        "findings": bundle.get("findings", []),
    }


def get_artifact_map(run_id: str, artifacts_dir: Path | None = None) -> dict[str, Any]:
    run_dir = resolve_run_dir(run_id, artifacts_dir)
    artifact_map = load_json_if_exists(run_dir / "artifact_map.json")
    if artifact_map:
        return artifact_map
    bundle = load_bundle_from_dir(run_dir)
    return bundle.get("metadata", {}).get("artifact_map", {"run_id": run_id, "nodes": {}})
