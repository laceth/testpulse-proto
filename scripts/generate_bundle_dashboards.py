#!/usr/bin/env python3
"""Batch-generate Mermaid diagrams + HTML dashboards from EvidenceBundle JSONs.

This is useful when bundles were uploaded/checked-in and you want per-run
"breakout" dashboards without re-running collection.

Default behavior writes outputs next to each evidence_bundle.json:
  <run_dir>/<run_id>.mmd
  <run_dir>/<run_id>_protocol_h.mmd
  <run_dir>/<run_id>_timeline.mmd
  <run_dir>/<run_id>_components.mmd
  <run_dir>/<run_id>_eapol.mmd (if events exist)
  <run_dir>/<run_id>_eapol_h.mmd (if events exist)
  <run_dir>/<run_id>_dashboard.html
  <run_dir>/<run_id>*.html (per-diagram)

Usage:
  python scripts/generate_bundle_dashboards.py bundles/eap_tls_suite_20260318
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from testpulse.tools.mermaid_timeline import (
    generate_component_diagram,
    generate_eapol_diagram,
    generate_eapol_horizontal,
    generate_mermaid,
    generate_mermaid_horizontal,
    generate_timeline,
)
from testpulse.tools.run_diagnostics import _export_dashboard, _export_html


_EAPOL_PREFIXES = ("EAPOL_", "EAP_", "RADIUS_")


def _iter_bundle_paths(root: Path) -> list[Path]:
    if root.is_file() and root.name.endswith(".json"):
        return [root]

    bundle_paths: list[Path] = []
    if root.is_dir():
        for p in sorted(root.rglob("evidence_bundle.json")):
            bundle_paths.append(p)
    return bundle_paths


def _write_if_needed(path: Path, content: str, force: bool) -> None:
    if path.exists() and not force:
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def generate_for_bundle(bundle_path: Path, force: bool) -> Path:
    bundle = json.loads(bundle_path.read_text(encoding="utf-8"))
    run_id = str(bundle.get("run_id") or bundle_path.parent.name)

    out_dir = bundle_path.parent
    base = out_dir / run_id

    mmd_paths: list[Path] = []

    # 1) Protocol sequence (vertical)
    mmd = base.with_suffix(".mmd")
    _write_if_needed(mmd, generate_mermaid(bundle), force)
    mmd_paths.append(mmd)

    # 2) Protocol sequence (horizontal)
    mmd_h = base.with_name(base.name + "_protocol_h.mmd")
    _write_if_needed(mmd_h, generate_mermaid_horizontal(bundle), force)
    mmd_paths.append(mmd_h)

    # 3) Timeline (horizontal)
    mmd_tl = base.with_name(base.name + "_timeline.mmd")
    _write_if_needed(mmd_tl, generate_timeline(bundle), force)
    mmd_paths.append(mmd_tl)

    # 4) Component topology (horizontal)
    mmd_comp = base.with_name(base.name + "_components.mmd")
    _write_if_needed(mmd_comp, generate_component_diagram(bundle), force)
    mmd_paths.append(mmd_comp)

    # 5/6) EAPOL diagrams (if EAP/RADIUS timeline events exist)
    timeline = bundle.get("timeline", []) or []
    eapol_events = [
        e
        for e in timeline
        if isinstance(e, dict) and str(e.get("kind", "")).startswith(_EAPOL_PREFIXES)
    ]
    if eapol_events:
        mmd_eap = base.with_name(base.name + "_eapol.mmd")
        _write_if_needed(mmd_eap, generate_eapol_diagram(eapol_events), force)
        mmd_paths.append(mmd_eap)

        mmd_eap_h = base.with_name(base.name + "_eapol_h.mmd")
        _write_if_needed(mmd_eap_h, generate_eapol_horizontal(eapol_events), force)
        mmd_paths.append(mmd_eap_h)

    # HTML exports
    # (These functions overwrite; keep that behavior consistent with run_diagnostics.)
    html_paths = _export_html(mmd_paths)
    dashboard = _export_dashboard(mmd_paths, bundle)

    # Return dashboard path if created
    return dashboard or (html_paths[0] if html_paths else base.with_suffix(".html"))


def main() -> int:
    ap = argparse.ArgumentParser(description="Generate per-run HTML dashboards from EvidenceBundle JSON")
    ap.add_argument(
        "path",
        help="Path to a bundle directory (containing evidence_bundle.json files) or a single evidence_bundle.json",
    )
    ap.add_argument(
        "--force",
        action="store_true",
        help="Overwrite existing .mmd files (HTML exports are always overwritten)",
    )
    args = ap.parse_args()

    root = Path(args.path)
    bundle_paths = _iter_bundle_paths(root)
    if not bundle_paths:
        raise SystemExit(f"No evidence_bundle.json found under: {root}")

    dashboards: list[Path] = []
    for bp in bundle_paths:
        dash = generate_for_bundle(bp, force=args.force)
        dashboards.append(dash)

    print("\n[OK] Dashboards generated:")
    for d in dashboards:
        print(f" - {d}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
