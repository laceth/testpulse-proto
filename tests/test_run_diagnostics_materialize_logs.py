from __future__ import annotations

from pathlib import Path

from testpulse.tools.run_diagnostics import materialize_common_logs
from testpulse.tools.run_diagnostics import _tab_for_stem


def test_materialize_common_logs_creates_standard_files(tmp_path: Path):
    # Simulate a fstester per-testcase folder naming convention. The run folder name
    # contains the token; materialization should prefer files that match it.
    run_dir = tmp_path / "fstester_log_20260319_173643"
    run_dir.mkdir(parents=True)

    (run_dir / "RadiusFragmentSizeDefaultWired_radiusd_20260319_173643.log").write_text(
        "preferred-radiusd\n",
        encoding="utf-8",
    )
    (run_dir / "RadiusFragmentSizeDefaultWired_radiusd_20260319_173924.log").write_text(
        "other-radiusd\n",
        encoding="utf-8",
    )
    (run_dir / "RadiusFragmentSizeDefaultWired_dot1x_20260319_173643.log").write_text(
        "preferred-dot1x\n",
        encoding="utf-8",
    )
    (run_dir / "RadiusFragmentSizeDefaultWired_dot1x_20260319_173924.log").write_text(
        "other-dot1x\n",
        encoding="utf-8",
    )
    (run_dir / "fstester_peap_eap_tls.log").write_text(
        "verification completed successfully\n",
        encoding="utf-8",
    )

    materialize_common_logs(run_dir)

    assert (run_dir / "radiusd.log").exists()
    assert (run_dir / "dot1x.log").exists()
    assert (run_dir / "framework.log").exists()

    # Token preference should avoid mixing other subruns
    assert (run_dir / "radiusd.log").read_text(encoding="utf-8") == "preferred-radiusd\n"
    assert (run_dir / "dot1x.log").read_text(encoding="utf-8") == "preferred-dot1x\n"
    assert "verification completed" in (run_dir / "framework.log").read_text(encoding="utf-8")


def test_tab_for_stem_labels_split_timeline_parts() -> None:
    label, desc = _tab_for_stem("evidence_bundle_timeline_01")
    assert label.startswith("Timeline Story")
    assert "(1)" in label
    assert "Chronological" in desc
