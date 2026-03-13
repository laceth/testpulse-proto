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
    parser.add_argument("--run-dir", type=Path, required=True)
    parser.add_argument("--testcase-id", required=True)
    parser.add_argument(
        "--expected-decision",
        choices=[decision.value for decision in Decision],
        required=True,
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
    if args.mermaid is not None and not args.no_mermaid:
        from testpulse.tools.mermaid_timeline import generate_mermaid

        mmd_path = (
            Path(args.mermaid)
            if args.mermaid != "auto"
            else args.out.with_suffix(".mmd")
        )
        markup = generate_mermaid(bundle)
        mmd_path.parent.mkdir(parents=True, exist_ok=True)
        mmd_path.write_text(markup, encoding="utf-8")
        print(f"[OK] Wrote Mermaid protocol diagram: {mmd_path}  ({len(markup)} chars)")
        print(markup)

    # ── Timeline diagram generation (ON by default) ─────────────────────
    if args.timeline is not None and not args.no_timeline:
        from testpulse.tools.mermaid_timeline import generate_timeline

        tl_path = (
            Path(args.timeline)
            if args.timeline != "auto"
            else args.out.with_name(args.out.stem + "_timeline.mmd")
        )
        tl_markup = generate_timeline(bundle)
        tl_path.parent.mkdir(parents=True, exist_ok=True)
        tl_path.write_text(tl_markup, encoding="utf-8")
        print(f"[OK] Wrote Mermaid timeline diagram: {tl_path}  ({len(tl_markup)} chars)")
        print(tl_markup)

    # ── EAPOL wire diagram (auto when pcap events exist) ─────────────────
    pcap_events = [e for e in bundle.get("timeline", []) if e.get("source") == "pcap"]
    if pcap_events and not args.no_mermaid:
        from testpulse.tools.mermaid_timeline import generate_eapol_diagram

        eapol_path = args.out.with_name(args.out.stem + "_eapol.mmd")
        eapol_markup = generate_eapol_diagram(pcap_events)
        eapol_path.parent.mkdir(parents=True, exist_ok=True)
        eapol_path.write_text(eapol_markup, encoding="utf-8")
        print(f"[OK] Wrote EAPOL wire diagram: {eapol_path}  ({len(eapol_markup)} chars)")
        print(eapol_markup)


if __name__ == "__main__":
    main()
