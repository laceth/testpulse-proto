from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from testpulse.models import AssuranceExpectation, Decision
from testpulse.services.history_service import record_run
from testpulse.tools.run_diagnostics import run_diagnostics


CONTRACT_FILES = {
    "timeline": "timeline.json",
    "component_health": "component_health.json",
    "artifact_map": "artifact_map.json",
    "service_metrics": "service_metrics.json",
}


def resolve_run_dir(run_id: str, artifacts_dir: Path | None = None) -> Path:
    base = artifacts_dir or Path(os.environ.get("TESTPULSE_ARTIFACTS", "artifacts"))
    return base / run_id


def load_json(path: Path) -> dict[str, Any]:
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def load_json_if_exists(path: Path) -> dict[str, Any]:
    return load_json(path) if path.exists() else {}


def load_bundle_from_dir(run_dir: Path) -> dict[str, Any]:
    bundle_path = run_dir / "evidence_bundle.json"
    if not bundle_path.exists():
        raise FileNotFoundError(f"Evidence bundle not found: {bundle_path}")
    return load_json(bundle_path)


def analyze_run(
    run_dir: Path,
    testcase_id: str,
    expected_decision: str,
    expected_method: str = "eap-tls",
    collect: bool = False,
    testbed_config: Path | None = None,
    history: list[dict[str, Any]] | None = None,
    service_metrics: dict[str, Any] | None = None,
    write_bundle: bool = True,
) -> dict[str, Any]:
    expectation = AssuranceExpectation(
        testcase_id=testcase_id,
        expected_decision=Decision(expected_decision),
        expected_method=expected_method,
    )
    bundle = run_diagnostics(
        run_dir=run_dir,
        expectation=expectation,
        collect=collect,
        testbed_config=testbed_config,
        history=history,
        service_metrics=service_metrics,
    )
    if write_bundle:
        _write_contracts(run_dir, bundle)
        record_run(bundle, run_dir.parent)
    return bundle


def _write_contracts(run_dir: Path, bundle: dict[str, Any]) -> None:
    run_dir.mkdir(parents=True, exist_ok=True)
    (run_dir / "evidence_bundle.json").write_text(json.dumps(bundle, indent=2), encoding="utf-8")
    (run_dir / CONTRACT_FILES["timeline"]).write_text(
        json.dumps({
            "run_id": bundle.get("run_id"),
            "testcase_id": bundle.get("testcase_id"),
            "timeline": bundle.get("timeline", []),
        }, indent=2),
        encoding="utf-8",
    )
    metadata = bundle.get("metadata", {})
    (run_dir / CONTRACT_FILES["component_health"]).write_text(
        json.dumps(metadata.get("component_health_contract", {"run_id": bundle.get("run_id"), "components": []}), indent=2),
        encoding="utf-8",
    )
    (run_dir / CONTRACT_FILES["artifact_map"]).write_text(
        json.dumps(metadata.get("artifact_map", {"run_id": bundle.get("run_id"), "nodes": {}}), indent=2),
        encoding="utf-8",
    )
    (run_dir / CONTRACT_FILES["service_metrics"]).write_text(
        json.dumps(metadata.get("service_metrics", {"run_id": bundle.get("run_id"), "metrics": {}}), indent=2),
        encoding="utf-8",
    )
