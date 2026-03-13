from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from testpulse.core.bundle import build_bundle, collect_artifacts
from testpulse.core.correlate import correlate
from testpulse.ingest.dot1x_parser import parse_dot1x
from testpulse.ingest.endpoint_parser import parse_endpoint_artifacts
from testpulse.ingest.framework_parser import parse_framework
from testpulse.ingest.identity_parser import parse_identity
from testpulse.ingest.radiusd_parser import parse_radiusd
from testpulse.ingest.redis_parser import parse_redis
from testpulse.ingest.eapol_parser import parse_pcap
from testpulse.models import AssuranceExpectation, AuthEvent, Decision


def derive_run_id(run_dir: Path) -> str:
    return run_dir.name or "RUN-UNKNOWN"


def read_text_if_exists(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="ignore") if path.exists() else ""


def maybe_collect_appliance(
    run_dir: Path,
    testbed_config: Path | None = None,
    appliance_ip: str | None = None,
    appliance_user: str = "root",
    appliance_pass: str = "aristo1",
    mac: str = "",
) -> None:
    """Collect logs from the Forescout appliance into run_dir.

    Connection info is resolved in priority order:
    1. Explicit --appliance-ip / --appliance-user / --appliance-pass CLI args
    2. ``ca:`` section in --testbed-config YAML
    """
    try:
        from testpulse.collect.appliance_collector import ApplianceCollector
    except ImportError:
        print("[WARN] paramiko not installed — skipping appliance collection.", file=sys.stderr)
        return

    # Resolve connection from testbed YAML if not given explicitly
    ip = appliance_ip
    user = appliance_user
    password = appliance_pass
    ep_mac = mac

    if testbed_config and testbed_config.exists() and not ip:
        try:
            import yaml
            with open(testbed_config) as fh:
                cfg = yaml.safe_load(fh)
            ca = cfg.get("ca", {})
            ip = ca.get("ip", ip)
            user = ca.get("user_name", user)
            password = ca.get("password", password)
            pt = cfg.get("passthrough", {})
            if not ep_mac:
                ep_mac = pt.get("mac", "")
        except Exception as e:
            print(f"[WARN] Failed to read testbed config: {e}", file=sys.stderr)

    if not ip:
        print("[WARN] No appliance IP configured — skipping log collection.", file=sys.stderr)
        print("       Use --appliance-ip or --testbed-config with a ca: section.", file=sys.stderr)
        return

    print(f"[INFO] Collecting appliance logs from {ip} → {run_dir} ...")
    collector = ApplianceCollector(ip=ip, user=user, password=password)
    try:
        results = collector.collect_all(run_dir=str(run_dir), mac=ep_mac)
        collected = [k for k, v in results.items() if v]
        print(f"[OK] Collected from appliance: {', '.join(collected)}")
    except Exception as e:
        print(f"[WARN] Appliance collection error: {e}", file=sys.stderr)
    finally:
        collector.close()


def maybe_collect_endpoint(
    run_dir: Path,
    ip: str,
    username: str,
    password: str,
    run_id: str,
) -> None:
    """Optionally run the endpoint collector and extract into run_dir/endpoint/."""
    try:
        from testpulse.collect import EndpointArtifactCollector
    except ImportError:
        print("[WARN] pywinrm not installed — skipping endpoint collection.", file=sys.stderr)
        print("       Install with: pip install testpulse-proto[endpoint]", file=sys.stderr)
        return

    print(f"[INFO] Collecting endpoint artifacts from {ip} ...")
    collector = EndpointArtifactCollector(ip=ip, username=username, password=password)
    zip_path = collector.collect(run_id=run_id, run_dir=str(run_dir))
    print(f"[OK] Endpoint artifacts saved to {run_dir / 'endpoint'}")
    try:
        collector.cleanup_remote(run_id)
    except Exception:
        pass  # best-effort cleanup


def run_diagnostics(
    run_dir: Path,
    expectation: AssuranceExpectation,
    collect: bool = False,
    testbed_config: Path | None = None,
    appliance_ip: str | None = None,
    appliance_user: str = "root",
    appliance_pass: str = "aristo1",
    mac: str = "",
    framework_log: Path | None = None,
    collect_endpoint: bool = False,
    endpoint_ip: str | None = None,
    endpoint_user: str | None = None,
    endpoint_pass: str | None = None,
    pcap_files: list[Path] | None = None,
) -> dict:
    events: list[AuthEvent] = []

    # -- Ensure run_dir exists
    run_dir.mkdir(parents=True, exist_ok=True)

    # -- Optional: copy local framework.log (fstester) into run_dir
    if framework_log and framework_log.exists():
        import shutil
        dest = run_dir / "framework.log"
        shutil.copy2(str(framework_log), str(dest))
        print(f"[OK] Copied framework log: {framework_log} → {dest}")

    # -- Optional: collect logs from appliance into run_dir
    if collect:
        maybe_collect_appliance(
            run_dir=run_dir,
            testbed_config=testbed_config,
            appliance_ip=appliance_ip,
            appliance_user=appliance_user,
            appliance_pass=appliance_pass,
            mac=mac,
        )

    # -- Optional: collect endpoint artifacts into run_dir/endpoint/
    if collect_endpoint and endpoint_ip:
        run_id = derive_run_id(run_dir)
        maybe_collect_endpoint(
            run_dir=run_dir,
            ip=endpoint_ip,
            username=endpoint_user or "Administrator",
            password=endpoint_pass or "",
            run_id=run_id,
        )

    # -- Server-side log parsing
    radiusd = run_dir / "radiusd.log"
    dot1x = run_dir / "dot1x.log"
    framework = run_dir / "framework.log"

    if radiusd.exists():
        events.extend(parse_radiusd(read_text_if_exists(radiusd)))
    if dot1x.exists():
        events.extend(parse_dot1x(read_text_if_exists(dot1x)))
    if framework.exists():
        events.extend(parse_framework(read_text_if_exists(framework)))

    # -- Endpoint artifact parsing (from <run_dir>/endpoint/)
    endpoint_dir = run_dir / "endpoint"
    if endpoint_dir.is_dir():
        events.extend(parse_endpoint_artifacts(endpoint_dir))

    # -- Redis & identity artifact parsing
    events.extend(parse_redis(str(run_dir)))
    events.extend(parse_identity(str(run_dir)))

    # -- PCAP parsing (EAPOL / RADIUS frames from wire captures)
    pcap_paths = list(pcap_files or [])
    # Also auto-discover any .pcap / .pcapng files in run_dir
    for suffix in ("*.pcap", "*.pcapng"):
        for p in run_dir.glob(suffix):
            if p not in pcap_paths:
                pcap_paths.append(p)
    for pcap_path in pcap_paths:
        print(f"[INFO] Parsing pcap: {pcap_path}")
        events.extend(parse_pcap(pcap_path))

    correlated = correlate(events)
    artifacts = collect_artifacts(run_dir)
    # Also enumerate endpoint artifacts
    if endpoint_dir.is_dir():
        for ep_file in sorted(endpoint_dir.rglob("*")):
            if ep_file.is_file():
                artifacts.append(f"endpoint/{ep_file.relative_to(endpoint_dir)}")

    bundle = build_bundle(
        run_id=derive_run_id(run_dir),
        expectation=expectation,
        events=correlated,
        artifacts=artifacts,
    )
    return bundle.to_dict()


def main() -> None:
    parser = argparse.ArgumentParser(description="Run TestPulse diagnostics on a run folder.")
    parser.add_argument("--run-dir", type=Path, default=None)
    parser.add_argument("--testcase-id", default=None)
    parser.add_argument(
        "--expected-decision",
        choices=[decision.value for decision in Decision],
        default=None,
    )
    parser.add_argument("--expected-method", default="eap-tls")
    parser.add_argument("--out", type=Path, default=Path("evidence_bundle.json"))
    parser.add_argument("--pretty", action="store_true")
    parser.add_argument(
        "--mermaid",
        nargs="?",
        const="auto",
        default="auto",
        metavar="PATH",
        help="Generate Mermaid protocol sequence diagram (.mmd). "
             "Always on by default; use --no-mermaid to disable. "
             "Optionally specify output path; defaults to <out>.mmd",
    )
    parser.add_argument(
        "--no-mermaid",
        action="store_true",
        default=False,
        help="Disable protocol sequence diagram generation.",
    )
    parser.add_argument(
        "--timeline",
        nargs="?",
        const="auto",
        default="auto",
        metavar="PATH",
        help="Generate Mermaid chronological timeline diagram. "
             "Always on by default; use --no-timeline to disable. "
             "Optionally specify output path; defaults to <out>_timeline.mmd",
    )
    parser.add_argument(
        "--no-timeline",
        action="store_true",
        default=False,
        help="Disable chronological timeline diagram generation.",
    )

    # Endpoint collection options
    parser.add_argument(
        "--collect-endpoint",
        action="store_true",
        help="Collect artifacts from Windows endpoint before analysis",
    )
    parser.add_argument("--endpoint-ip", help="Windows endpoint IP address")
    parser.add_argument("--endpoint-user", default="Administrator", help="WinRM username")
    parser.add_argument("--endpoint-pass", default="", help="WinRM password")

    # Appliance collection + testbed config
    parser.add_argument(
        "--collect",
        action="store_true",
        help="Collect logs from the Forescout appliance (radiusd.log, dot1x.log, "
             "redis, fstool) via SSH before analysis. "
             "Uses --testbed-config or --appliance-* flags for connection info.",
    )
    parser.add_argument("--appliance-ip", help="Appliance IP (overrides testbed YAML ca.ip)")
    parser.add_argument("--appliance-user", default="root", help="Appliance SSH user")
    parser.add_argument("--appliance-pass", default="aristo1", help="Appliance SSH password")
    parser.add_argument("--mac", default="", help="Endpoint MAC for fstool hostinfo lookup")
    parser.add_argument(
        "--framework-log",
        type=Path, default=None,
        help="Path to local fstester framework log (fstester.log). "
             "This log is produced locally by fstester, not on the appliance. "
             "Will be copied into --run-dir as framework.log for analysis.",
    )

    # PCAP parsing
    parser.add_argument(
        "--pcap",
        type=Path, nargs="+", default=None,
        help="One or more .pcap/.pcapng files to parse for EAPOL/RADIUS frames. "
             "Any pcap files found in --run-dir are also auto-discovered.",
    )
    parser.add_argument(
        "--analyze-pcap",
        action="store_true",
        help="Run deep packet analysis on discovered pcap files and print summary.",
    )
    parser.add_argument(
        "--wireshark",
        action="store_true",
        help="Open discovered pcap files in Wireshark with AAA display filters.",
    )
    parser.add_argument(
        "--pcap-filters",
        action="store_true",
        help="Print BPF capture filter and Wireshark display filter reference.",
    )

    # PCAP + NTP options
    parser.add_argument(
        "--ntp-check",
        action="store_true",
        help="Check NTP clock sync across testbed devices before analysis",
    )
    parser.add_argument(
        "--testbed-config",
        type=Path, default=None,
        help="Path to testbed YAML (radius.yml) — provides appliance/switch/endpoint "
             "connection info for --collect, --ntp-check, and PCAP",
    )

    args = parser.parse_args()

    # ── Filter reference (standalone, no run_dir needed) ────────────────
    if args.pcap_filters:
        from testpulse.tools.pcap_analyzer import print_filter_reference
        print(print_filter_reference())
        return

    if not args.run_dir:
        parser.error("the following arguments are required: --run-dir")
    if not args.testcase_id:
        parser.error("the following arguments are required: --testcase-id")
    if not args.expected_decision:
        parser.error("the following arguments are required: --expected-decision")

    if not args.collect and (not args.run_dir.exists() or not args.run_dir.is_dir()):
        raise SystemExit(f"Run directory not found: {args.run_dir}  (use --collect to pull logs first)")

    if args.collect_endpoint and not args.endpoint_ip:
        raise SystemExit("--endpoint-ip is required when using --collect-endpoint")

    # ── NTP sync preflight ───────────────────────────────────────────────
    if args.ntp_check:
        from testpulse.collect.ntp_sync import NtpSyncChecker, NtpConfig

        if args.testbed_config and args.testbed_config.exists():
            ntp_cfg = NtpConfig.from_yaml(str(args.testbed_config))
        else:
            # Minimal config from CLI args
            devices: dict[str, dict] = {}
            if args.endpoint_ip:
                devices["endpoint"] = {
                    "ip": args.endpoint_ip,
                    "user": args.endpoint_user,
                    "password": args.endpoint_pass,
                    "transport": "winrm",
                }
            ntp_cfg = NtpConfig(devices=devices)

        if ntp_cfg.devices:
            checker = NtpSyncChecker(ntp_cfg)
            report = checker.check_all()
            print(report.summary())
            if not report.ready_for_capture:
                print("[WARN] NTP clocks not synchronised — timestamps may drift")
        else:
            print("[WARN] No devices configured for NTP check")

    expectation = AssuranceExpectation(
        testcase_id=args.testcase_id,
        expected_decision=Decision(args.expected_decision),
        expected_method=args.expected_method,
    )

    bundle = run_diagnostics(
        run_dir=args.run_dir,
        expectation=expectation,
        collect=args.collect,
        testbed_config=args.testbed_config,
        appliance_ip=args.appliance_ip,
        appliance_user=args.appliance_user,
        appliance_pass=args.appliance_pass,
        mac=args.mac,
        framework_log=args.framework_log,
        collect_endpoint=args.collect_endpoint,
        endpoint_ip=args.endpoint_ip,
        endpoint_user=args.endpoint_user,
        endpoint_pass=args.endpoint_pass,
        pcap_files=args.pcap,
    )

    args.out.parent.mkdir(parents=True, exist_ok=True)
    with args.out.open("w", encoding="utf-8") as handle:
        json.dump(bundle, handle, indent=2 if args.pretty else None)

    print(f"[OK] Wrote EvidenceBundle: {args.out}")
    print(f"     testcase_id={bundle['testcase_id']}")
    observed = bundle['observed_decision']
    expected = bundle['expected_decision']
    if hasattr(observed, 'value'):
        observed = observed.value
    if hasattr(expected, 'value'):
        expected = expected.value
    print(f"     observed_decision={observed}")
    print(f"     expected_decision={expected}")
    print(f"     classification={bundle['classification']}")
    print(f"     confidence={bundle['confidence']}")
    print(f"     events_parsed={len(bundle.get('timeline', []))}")
    print(f"     artifacts_found={len(bundle.get('artifacts', []))}")

    # ── Mermaid diagram generation (ON by default) ──────────────────────
    mmd_paths: list[Path] = []

    if args.mermaid is not None and not args.no_mermaid:
        from testpulse.tools.mermaid_timeline import generate_mermaid

        # 1. Protocol sequence — vertical (sequenceDiagram)
        mmd_path = (
            Path(args.mermaid)
            if args.mermaid != "auto"
            else args.out.with_suffix(".mmd")
        )
        markup = generate_mermaid(bundle)
        mmd_path.parent.mkdir(parents=True, exist_ok=True)
        mmd_path.write_text(markup, encoding="utf-8")
        mmd_paths.append(mmd_path)
        print(f"[OK] Wrote protocol diagram (vertical): {mmd_path}  ({len(markup)} chars)")
        print(markup)

        # 2. Protocol sequence — horizontal (graph LR)
        from testpulse.tools.mermaid_timeline import generate_mermaid_horizontal

        h_path = args.out.with_name(args.out.stem + "_protocol_h.mmd")
        h_markup = generate_mermaid_horizontal(bundle)
        h_path.parent.mkdir(parents=True, exist_ok=True)
        h_path.write_text(h_markup, encoding="utf-8")
        mmd_paths.append(h_path)
        print(f"[OK] Wrote protocol diagram (horizontal): {h_path}  ({len(h_markup)} chars)")
        print(h_markup)

    # ── Timeline diagram generation (ON by default) ─────────────────────
    if args.timeline is not None and not args.no_timeline:
        from testpulse.tools.mermaid_timeline import generate_timeline

        # 3. Chronological timeline (graph LR)
        tl_path = (
            Path(args.timeline)
            if args.timeline != "auto"
            else args.out.with_name(args.out.stem + "_timeline.mmd")
        )
        tl_markup = generate_timeline(bundle)
        tl_path.parent.mkdir(parents=True, exist_ok=True)
        tl_path.write_text(tl_markup, encoding="utf-8")
        mmd_paths.append(tl_path)
        print(f"[OK] Wrote timeline diagram (horizontal): {tl_path}  ({len(tl_markup)} chars)")
        print(tl_markup)

    # ── Component topology diagram (ON by default) ──────────────────────
    if not args.no_mermaid:
        from testpulse.tools.mermaid_timeline import generate_component_diagram

        # 4. Component topology (graph LR)
        comp_path = args.out.with_name(args.out.stem + "_components.mmd")
        comp_markup = generate_component_diagram(bundle)
        comp_path.parent.mkdir(parents=True, exist_ok=True)
        comp_path.write_text(comp_markup, encoding="utf-8")
        mmd_paths.append(comp_path)
        print(f"[OK] Wrote component topology (horizontal): {comp_path}  ({len(comp_markup)} chars)")
        print(comp_markup)

    # ── EAPOL wire diagrams (auto when EAP/RADIUS events exist) ────────
    _EAPOL_PREFIXES = ("EAPOL_", "EAP_", "RADIUS_")
    eapol_events = [
        e for e in bundle.get("timeline", [])
        if e.get("kind", "").startswith(_EAPOL_PREFIXES)
    ]
    if eapol_events and not args.no_mermaid:
        from testpulse.tools.mermaid_timeline import generate_eapol_diagram, generate_eapol_horizontal

        # 5. EAPOL wire trace — vertical (sequenceDiagram)
        eapol_path = args.out.with_name(args.out.stem + "_eapol.mmd")
        eapol_markup = generate_eapol_diagram(eapol_events)
        eapol_path.parent.mkdir(parents=True, exist_ok=True)
        eapol_path.write_text(eapol_markup, encoding="utf-8")
        mmd_paths.append(eapol_path)
        print(f"[OK] Wrote EAPOL wire diagram (vertical): {eapol_path}  ({len(eapol_markup)} chars)")
        print(eapol_markup)

        # 6. EAPOL wire trace — horizontal (graph LR)
        eapol_h_path = args.out.with_name(args.out.stem + "_eapol_h.mmd")
        eapol_h_markup = generate_eapol_horizontal(eapol_events)
        eapol_h_path.parent.mkdir(parents=True, exist_ok=True)
        eapol_h_path.write_text(eapol_h_markup, encoding="utf-8")
        mmd_paths.append(eapol_h_path)
        print(f"[OK] Wrote EAPOL wire diagram (horizontal): {eapol_h_path}  ({len(eapol_h_markup)} chars)")
        print(eapol_h_markup)

    # ── HTML export (self-contained Mermaid.js) ──────────────────────────
    if mmd_paths:
        html_paths = _export_html(mmd_paths)
        # Also generate a combined tabbed dashboard
        dashboard_path = _export_dashboard(mmd_paths, bundle)
        if dashboard_path:
            html_paths.insert(0, dashboard_path)
        _serve_diagrams(html_paths)

    # ── Deep packet analysis / Wireshark integration ─────────────────────
    if args.analyze_pcap or args.wireshark:
        # Discover pcap files in run_dir
        pcap_files_found: list[Path] = list(args.pcap or [])
        for suffix in ("*.pcap", "*.pcapng"):
            for p in args.run_dir.rglob(suffix):
                if p not in pcap_files_found:
                    pcap_files_found.append(p)

        if pcap_files_found:
            if args.analyze_pcap:
                from testpulse.tools.pcap_analyzer import PcapAnalyzer
                for pf in pcap_files_found:
                    analyzer = PcapAnalyzer(pf)
                    report = analyzer.analyze()
                    print(report.summary())

            if args.wireshark:
                from testpulse.tools.pcap_analyzer import (
                    launch_wireshark, find_wireshark, DISPLAY_FILTERS,
                )
                ws = find_wireshark()
                aaa_filter = DISPLAY_FILTERS["AAA Full Trace"]["filter"]
                if ws:
                    for pf in pcap_files_found:
                        launch_wireshark(pf, display_filter=aaa_filter,
                                         wireshark_exe=ws)
                        print(f"[OK] Wireshark opened: {pf}")
                else:
                    print("[WARN] Wireshark not found on PATH or standard locations",
                          file=sys.stderr)
                    print("  Linux:   sudo apt install wireshark", file=sys.stderr)
                    print("  Windows: https://www.wireshark.org/download.html",
                          file=sys.stderr)
        else:
            print("[INFO] No pcap files found for analysis")


# ═══════════════════════════════════════════════════════════════════════════
# Dashboard tab labels — mapped from .mmd filename stems
# ═══════════════════════════════════════════════════════════════════════════

_TAB_LABELS = {
    "components":   ("Component Topology", "Devices and data sources in the test topology"),
    "eapol":        ("EAPOL Wire Trace", "EAP-TLS / PEAP authentication sequence diagram"),
    "eapol_h":      ("EAPOL Horizontal", "Horizontal EAPOL wire trace flowchart"),
    "protocol_h":   ("Protocol Flow", "Left-to-right protocol flow diagram"),
    "timeline":     ("Timeline Story", "Chronological event timeline"),
}


def _tab_for_stem(stem: str) -> tuple[str, str]:
    """Derive a tab label + description from an .mmd file stem."""
    for key, (label, desc) in _TAB_LABELS.items():
        if stem.endswith(key):
            return label, desc
    # Fallback: if the stem ends with _bundle or is the base bundle name,
    # it's the main vertical protocol sequence diagram.
    return "Protocol Sequence", "Vertical protocol sequence diagram"


_DASHBOARD_TEMPLATE = """\
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>TestPulse Evidence Dashboard — {testcase_id}</title>
<script src="https://cdn.jsdelivr.net/npm/mermaid@10/dist/mermaid.min.js"></script>
<style>
  * {{ margin: 0; padding: 0; box-sizing: border-box; }}
  body {{ font-family: 'Segoe UI', system-ui, sans-serif; background: #1a1a2e; color: #e0e0e0; }}
  .header {{ background: linear-gradient(135deg, #0f3460, #16213e); padding: 20px 30px;
             border-bottom: 3px solid #e94560; }}
  .header h1 {{ font-size: 1.6em; color: #fff; }}
  .header .sub {{ color: #a0a0c0; margin-top: 4px; font-size: 0.9em; }}
  .meta {{ background: #16213e; padding: 12px 30px; border-bottom: 1px solid #333;
           display: flex; flex-wrap: wrap; gap: 20px; font-size: 0.85em; }}
  .meta .chip {{ background: #0f3460; padding: 4px 12px; border-radius: 14px; }}
  .finding {{ background: rgba(233,69,96,0.15); border-left: 3px solid #e94560;
              padding: 6px 12px; margin: 3px 30px; font-size: 0.85em; border-radius: 2px; }}
  .tabs {{ display: flex; flex-wrap: wrap; background: #16213e; padding: 0 20px;
           border-bottom: 2px solid #333; align-items: center; }}
  .tab {{ padding: 10px 18px; cursor: pointer; color: #888; font-size: 0.9em;
          border-bottom: 3px solid transparent; transition: all 0.2s; }}
  .tab:hover {{ color: #e94560; }}
  .tab.active {{ color: #fff; border-bottom-color: #e94560; background: rgba(233,69,96,0.1); }}
  .diagrams {{ padding: 20px; min-height: 400px; }}
  /* All panes start visible so Mermaid can render; JS hides inactive after init */
  .pane {{ background: #fff; border-radius: 8px; padding: 20px; margin: 10px;
           overflow-x: auto; }}
  .pane.hidden {{ display: none; }}
  .pane-hdr {{ display: flex; align-items: center; justify-content: space-between;
               padding: 5px 10px; }}
  .pane-hdr .desc {{ color: #a0a0c0; font-size: 0.85em; }}
  .pane-hdr .open-link {{ color: #e94560; font-size: 0.8em; text-decoration: none;
                          border: 1px solid #e94560; padding: 3px 10px; border-radius: 4px;
                          transition: all 0.2s; }}
  .pane-hdr .open-link:hover {{ background: #e94560; color: #fff; }}
  .pane-hdr.hidden {{ display: none; }}
</style>
</head>
<body>
<div class="header">
  <h1>TestPulse Evidence Dashboard</h1>
  <div class="sub">{subtitle}</div>
</div>
<div class="meta">
  <span class="chip">Test: {testcase_id}</span>
  <span class="chip">Run: {run_id}</span>
  <span class="chip">Result: {classification}</span>
  <span class="chip">Observed: {observed}</span>
  <span class="chip">Expected: {expected}</span>
  <span class="chip">Confidence: {confidence}</span>
</div>
{findings_html}
<div class="tabs">
{tabs_html}
</div>
<div class="diagrams">
{panes_html}
</div>
<script>
mermaid.initialize({{ startOnLoad: true, theme: 'default', securityLevel: 'loose' }});

// After Mermaid finishes rendering ALL panes, hide the inactive ones.
mermaid.run().then(function() {{
  document.querySelectorAll('.pane').forEach(function(d, i) {{
    if (i !== 0) d.classList.add('hidden');
  }});
  document.querySelectorAll('.pane-hdr').forEach(function(d, i) {{
    if (i !== 0) d.classList.add('hidden');
  }});
}});

function showTab(idx) {{
  document.querySelectorAll('.tab').forEach(function(t, i) {{
    t.classList.toggle('active', i === idx);
  }});
  document.querySelectorAll('.pane').forEach(function(d, i) {{
    d.classList.toggle('hidden', i !== idx);
  }});
  document.querySelectorAll('.pane-hdr').forEach(function(d, i) {{
    d.classList.toggle('hidden', i !== idx);
  }});
}}
</script>
</body>
</html>"""


def _export_dashboard(mmd_paths: list[Path], bundle: dict) -> Path | None:
    """Generate a single tabbed HTML dashboard containing all diagrams."""
    if not mmd_paths:
        return None

    testcase_id = bundle.get("testcase_id", "?")
    run_id = bundle.get("run_id", "?")
    classification = bundle.get("classification", "?")
    observed = bundle.get("observed_decision", "?")
    expected = bundle.get("expected_decision", "?")
    if hasattr(observed, "value"):
        observed = observed.value
    if hasattr(expected, "value"):
        expected = expected.value
    confidence = bundle.get("confidence", 0)

    findings = bundle.get("findings", [])
    findings_html = "\n".join(
        f'<div class="finding">{f}</div>' for f in findings
    ) if findings else ""

    tabs_parts: list[str] = []
    panes_parts: list[str] = []

    for i, mmd in enumerate(mmd_paths):
        code = mmd.read_text(encoding="utf-8")
        label, desc = _tab_for_stem(mmd.stem)
        html_name = mmd.with_suffix(".html").name
        active = " active" if i == 0 else ""
        tabs_parts.append(
            f'  <div class="tab{active}" onclick="showTab({i})">{label}</div>'
        )
        panes_parts.append(
            f'  <div class="pane-hdr" id="hdr-{i}">\n'
            f'    <span class="desc">{desc}</span>\n'
            f'    <a class="open-link" href="{html_name}" target="_blank">'
            f'Open full size &#x2197;</a>\n'
            f'  </div>\n'
            f'  <div class="pane" id="pane-{i}">\n'
            f'    <pre class="mermaid">\n{code}\n    </pre>\n'
            f'  </div>'
        )

    subtitle = f"{testcase_id} / {run_id} — {classification}"

    html = _DASHBOARD_TEMPLATE.format(
        testcase_id=testcase_id,
        run_id=run_id,
        classification=classification,
        observed=observed,
        expected=expected,
        confidence=confidence,
        subtitle=subtitle,
        findings_html=findings_html,
        tabs_html="\n".join(tabs_parts),
        panes_html="\n".join(panes_parts),
    )

    out = mmd_paths[0].parent / f"{run_id}_dashboard.html"
    out.write_text(html, encoding="utf-8")
    print(f"[OK] Wrote combined dashboard: {out}")
    return out


_HTML_TEMPLATE = """\
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>{title}</title>
<style>
  body {{ font-family: sans-serif; background: #1e1e1e; color: #ddd; margin: 2em; }}
  h1 {{ color: #fff; }}
  .mermaid {{ background: #fff; padding: 1em; border-radius: 8px; }}
</style>
</head>
<body>
<h1>{title}</h1>
<div class="mermaid">
{mermaid_code}
</div>
<script src="https://cdn.jsdelivr.net/npm/mermaid@11/dist/mermaid.min.js"></script>
<script>mermaid.initialize({{startOnLoad:true, theme:'default'}});</script>
</body>
</html>"""


def _export_html(mmd_paths: list[Path]) -> list[Path]:
    """Convert each .mmd file to a self-contained .html with embedded Mermaid.js."""
    html_paths: list[Path] = []
    for mmd in mmd_paths:
        code = mmd.read_text(encoding="utf-8")
        html = _HTML_TEMPLATE.format(title=mmd.stem, mermaid_code=code)
        out = mmd.with_suffix(".html")
        out.write_text(html, encoding="utf-8")
        html_paths.append(out)
        print(f"[OK] Wrote HTML diagram: {out}")
    return html_paths


_SERVE_PORT = 8765


def _serve_diagrams(html_paths: list[Path]) -> None:
    """Start an HTTP server in a background process and print URLs."""
    import socket
    import subprocess

    if not html_paths:
        return

    serve_dir = html_paths[0].parent.resolve()
    port = _SERVE_PORT

    # Check if server is already running on this port
    already_running = False
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        already_running = sock.connect_ex(("127.0.0.1", port)) == 0

    if not already_running:
        # Start a background HTTP server (detached from this process)
        subprocess.Popen(
            [sys.executable, "-m", "http.server", str(port)],
            cwd=str(serve_dir),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
        print(f"[OK] Started HTTP server on port {port} (serving {serve_dir})")
    else:
        print(f"[OK] HTTP server already running on port {port}")

    print()
    print("=" * 60)
    print("  Diagram URLs (open in browser or VS Code Simple Browser)")
    print("  Ctrl+Shift+P -> 'Simple Browser: Show' -> paste URL")
    print("=" * 60)
    for hp in html_paths:
        print(f"  http://localhost:{port}/{hp.name}")
    print(f"  http://localhost:{port}/          (directory listing)")
    print("=" * 60)


if __name__ == "__main__":
    main()
