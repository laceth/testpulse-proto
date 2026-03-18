from __future__ import annotations

import difflib
import hashlib
from pathlib import Path
from typing import Any

from .artifact_content_service import get_artifact_content
from .diagnostics_service import get_artifact_map, get_component_health
from .pipeline import load_bundle_from_dir, resolve_run_dir
from .prognostics_service import get_prognostics
from .timeline_service import get_timeline

SEVERITY_WEIGHT = {"high": 3, "medium": 2, "low": 1}
NODE_COMPONENT_MAP = {
    "endpoint_supplicant": None,
    "dhcp": "dhcp",
    "tcpip_relay": "tcpip_relay",
    "dns": "dns",
    "ad_ldap": "directory",
    "radius": "radius",
    "nas_authorization": "nas",
    "tomahawk": "tomahawk",
    "coa": "nas",
    "ntp": "ntp",
    "evidence_bundle": None,
}


def _component_by_node(components: list[dict[str, Any]], node_id: str) -> dict[str, Any] | None:
    component_key = NODE_COMPONENT_MAP.get(node_id)
    if not component_key:
        return None
    return next((item for item in components if item.get("component") == component_key), None)


def _status_of(component: dict[str, Any] | None) -> str:
    return str((component or {}).get("status") or "UNKNOWN")


def _severity_of(component: dict[str, Any] | None) -> str:
    return str((component or {}).get("severity") or "low")


def _recommendations_for(component: dict[str, Any] | None, source: str) -> list[dict[str, Any]]:
    if not component or not component.get("recommendation"):
        return []
    return [{
        "source": source,
        "component": component.get("component"),
        "status": component.get("status"),
        "severity": component.get("severity") or "low",
        "confidence": component.get("confidence"),
        "finding": component.get("finding"),
        "recommendation": component.get("recommendation"),
    }]


def _score(item: dict[str, Any]) -> tuple[int, float]:
    sev = SEVERITY_WEIGHT.get(str(item.get("severity") or "").lower(), 0)
    conf = float(item.get("confidence") or 0.0)
    return sev, conf


def get_recommendation_rollup(run_id: str, compare_run_id: str, artifacts_dir: Path | None = None) -> dict[str, Any]:
    primary = get_component_health(run_id, artifacts_dir)
    compare = get_component_health(compare_run_id, artifacts_dir)
    primary_components = primary.get("components", [])
    compare_components = compare.get("components", [])

    changed_nodes: list[dict[str, Any]] = []
    rollups: list[dict[str, Any]] = []
    for node_id in NODE_COMPONENT_MAP:
        primary_component = _component_by_node(primary_components, node_id)
        compare_component = _component_by_node(compare_components, node_id)
        primary_status = _status_of(primary_component)
        compare_status = _status_of(compare_component)
        primary_severity = _severity_of(primary_component)
        compare_severity = _severity_of(compare_component)
        changed = (primary_status != compare_status) or (primary_severity != compare_severity)
        if not changed:
            continue
        changed_nodes.append({
            "node_id": node_id,
            "component": NODE_COMPONENT_MAP.get(node_id),
            "primary_status": primary_status,
            "compare_status": compare_status,
            "primary_severity": primary_severity,
            "compare_severity": compare_severity,
        })
        recommendations = _recommendations_for(primary_component, "primary") + _recommendations_for(compare_component, "compare")
        recommendations.sort(key=_score, reverse=True)
        rollups.append({
            "node_id": node_id,
            "component": NODE_COMPONENT_MAP.get(node_id),
            "primary_finding": (primary_component or {}).get("finding"),
            "compare_finding": (compare_component or {}).get("finding"),
            "recommendations": recommendations,
        })
    rollups.sort(key=lambda item: max((_score(rec) for rec in item.get("recommendations", [])), default=(0, 0.0)), reverse=True)
    return {
        "run_id": run_id,
        "compare_run_id": compare_run_id,
        "changed_nodes": changed_nodes,
        "rollups": rollups,
    }


def _choose_artifact_pair(run_id: str, compare_run_id: str, node_id: str, path: str | None, artifacts_dir: Path | None = None) -> tuple[str | None, str | None]:
    if path:
        return path, path
    primary_map = get_artifact_map(run_id, artifacts_dir).get("nodes", {})
    compare_map = get_artifact_map(compare_run_id, artifacts_dir).get("nodes", {})
    primary_paths = [str(p) for p in primary_map.get(node_id, [])]
    compare_paths = [str(p) for p in compare_map.get(node_id, [])]
    if not primary_paths or not compare_paths:
        return (primary_paths[0] if primary_paths else None, compare_paths[0] if compare_paths else None)
    compare_by_name = {Path(item).name: item for item in compare_paths}
    for candidate in primary_paths:
        name = Path(candidate).name
        if name in compare_by_name:
            return candidate, compare_by_name[name]
    return primary_paths[0], compare_paths[0]


def get_artifact_diff(run_id: str, compare_run_id: str, node_id: str, path: str | None = None, artifacts_dir: Path | None = None) -> dict[str, Any]:
    primary_path, compare_path = _choose_artifact_pair(run_id, compare_run_id, node_id, path, artifacts_dir)
    if not primary_path and not compare_path:
        raise FileNotFoundError(f"No artifacts mapped for node {node_id}")
    primary_content = get_artifact_content(run_id, primary_path, artifacts_dir) if primary_path else None
    compare_content = get_artifact_content(compare_run_id, compare_path, artifacts_dir) if compare_path else None
    if primary_content and primary_content.get("content_type") != "text":
        return {
            "run_id": run_id,
            "compare_run_id": compare_run_id,
            "node_id": node_id,
            "artifact_path": primary_path,
            "compare_artifact_path": compare_path,
            "content_type": "binary",
            "diff": "Binary artifact cannot be diffed inline.",
        }
    primary_text = (primary_content or {}).get("preview", "")
    compare_text = (compare_content or {}).get("preview", "")
    diff_lines = list(
        difflib.unified_diff(
            compare_text.splitlines(),
            primary_text.splitlines(),
            fromfile=f"{compare_run_id}:{compare_path or 'missing'}",
            tofile=f"{run_id}:{primary_path or 'missing'}",
            lineterm="",
            n=2,
        )
    )
    return {
        "run_id": run_id,
        "compare_run_id": compare_run_id,
        "node_id": node_id,
        "artifact_path": primary_path,
        "compare_artifact_path": compare_path,
        "content_type": "text",
        "diff": "\n".join(diff_lines[:400]) if diff_lines else "No textual differences detected.",
    }


def _contract_fingerprint(run_dir: Path) -> str:
    watched = [
        run_dir / "evidence_bundle.json",
        run_dir / "timeline.json",
        run_dir / "component_health.json",
        run_dir / "artifact_map.json",
        run_dir / "service_metrics.json",
    ]
    parts: list[str] = []
    for path in watched:
        if path.exists():
            stat = path.stat()
            parts.append(f"{path.name}:{stat.st_mtime_ns}:{stat.st_size}")
        else:
            parts.append(f"{path.name}:missing")
    return hashlib.sha1("|".join(parts).encode("utf-8")).hexdigest()


def get_stream_snapshot(run_id: str, artifacts_dir: Path | None = None) -> dict[str, Any]:
    run_dir = resolve_run_dir(run_id, artifacts_dir)
    bundle = load_bundle_from_dir(run_dir)
    timeline = get_timeline(run_id, artifacts_dir)
    health = get_component_health(run_id, artifacts_dir)
    prognostics = get_prognostics(run_id, artifacts_dir)
    return {
        "run_id": run_id,
        "fingerprint": _contract_fingerprint(run_dir),
        "bundle_summary": {
            "classification": bundle.get("classification"),
            "functional_pass": bundle.get("functional_pass"),
            "confidence": bundle.get("confidence"),
            "findings": bundle.get("findings", [])[:5],
        },
        "timeline_count": len(timeline.get("timeline", [])),
        "components": [
            {
                "component": item.get("component"),
                "status": item.get("status"),
                "severity": item.get("severity"),
                "confidence": item.get("confidence"),
            }
            for item in health.get("components", [])
        ],
        "predictive_warnings": prognostics.get("prognostics", {}).get("predictive_warnings", []),
    }
