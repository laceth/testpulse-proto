"""NTP clock synchronisation checker for TestPulse.

Before starting PCAP captures across multiple devices, every device's
clock MUST be synchronised to the same NTP source so that packet
timestamps can be correlated with log timestamps and the Mermaid
timeline.

This module queries each device for its NTP offset and reports whether
the testbed is ready for time-sensitive capture.

Decision thresholds::

    offset < 50 ms    → SYNC_OK        (proceed)
    50 ms ≤ offset    → SYNC_WARNING   (capture but warn)
    no NTP / error    → SYNC_UNKNOWN   (device may not have ntpd)

Usage::

    from testpulse.collect.ntp_sync import NtpSyncChecker, NtpConfig

    ntp = NtpSyncChecker(NtpConfig(
        devices={
            "appliance": {"ip": "10.16.177.66", "user": "root", "password": "aristo1"},
            "endpoint":  {"ip": "10.16.133.143", "user": "Administrator",
                          "password": "aristo", "transport": "winrm"},
            "switch":    {"ip": "10.16.128.21", "user": "admin",
                          "password": "aristo", "transport": "switch"},
            "ad":        {"ip": "10.100.49.30", "user": "root", "password": "aristo1"},
        }
    ))

    report = ntp.check_all()
    if not report.all_synced:
        print("WARNING: clocks are not synchronised!")
        for d in report.devices:
            print(f"  {d.name}: offset={d.offset_ms}ms  status={d.status}")

    # Or as a pre-flight check for PCAP
    ntp.assert_synced()  # raises if any device fails
"""
from __future__ import annotations

import logging
import re
import time
from dataclasses import dataclass, field
from typing import Optional

log = logging.getLogger("testpulse")

try:
    import paramiko
except ImportError:
    paramiko = None  # type: ignore[assignment]

try:
    import winrm
except ImportError:
    winrm = None  # type: ignore[assignment]


# ═══════════════════════════════════════════════════════════════════════════
# Data models
# ═══════════════════════════════════════════════════════════════════════════

THRESHOLD_OK_MS = 50.0         # ≤50ms = good
THRESHOLD_WARN_MS = 500.0      # ≤500ms = warning (still usable)


@dataclass
class DeviceSync:
    """NTP sync status for one device."""
    name: str
    ip: str
    offset_ms: float | None = None   # NTP offset in milliseconds
    stratum: int | None = None       # NTP stratum (1-15; 16 = unsync)
    ntp_source: str = ""             # upstream NTP server
    status: str = "UNKNOWN"          # SYNC_OK | SYNC_WARNING | SYNC_FAIL | SYNC_UNKNOWN
    raw_output: str = ""             # raw ntpq / w32tm output
    error: str = ""                  # error message if check failed
    local_time: str = ""             # device's current time string
    transport: str = "ssh"


@dataclass
class SyncReport:
    """Aggregate NTP sync report across all devices."""
    devices: list[DeviceSync] = field(default_factory=list)
    checked_at: str = ""             # ISO timestamp of the check
    max_offset_ms: float = 0.0
    all_synced: bool = False
    ready_for_capture: bool = False

    def summary(self) -> str:
        """Human-readable summary."""
        lines = [
            f"NTP Sync Report — {self.checked_at}",
            f"Max offset: {self.max_offset_ms:.1f} ms",
            f"All synced: {self.all_synced}",
            f"Ready for capture: {self.ready_for_capture}",
            "",
        ]
        for d in self.devices:
            offset_str = f"{d.offset_ms:.1f} ms" if d.offset_ms is not None else "N/A"
            lines.append(f"  {d.name:15s}  {d.ip:18s}  offset={offset_str:>10s}  "
                         f"stratum={d.stratum or '?':>2}  {d.status:15s}  "
                         f"time={d.local_time}")
        return "\n".join(lines)


@dataclass
class NtpDeviceConfig:
    """Connection params for a single device."""
    ip: str
    user: str = "root"
    password: str = ""
    transport: str = "ssh"     # ssh | winrm | switch


@dataclass
class NtpConfig:
    """Multi-device NTP check configuration."""
    devices: dict[str, dict] = field(default_factory=dict)
    # devices = {"appliance": {"ip": ..., "user": ..., ...}, ...}

    @classmethod
    def from_pcap_config(cls, pcap_cfg) -> NtpConfig:
        """Build from a PcapConfig instance — check every capture target."""
        devices: dict[str, dict] = {}
        for target in pcap_cfg.build_targets():
            transport = target.transport
            if transport == "switch_span":
                transport = "switch"
            devices[target.name] = {
                "ip": target.ip,
                "user": target.user,
                "password": target.password,
                "transport": transport,
            }
        return cls(devices=devices)

    @classmethod
    def from_yaml(cls, path: str) -> NtpConfig:
        """Load from radius.yml / testbed YAML."""
        try:
            import yaml
        except ImportError:
            raise ImportError("PyYAML required")

        with open(path) as fh:
            data = yaml.safe_load(fh)

        devices: dict[str, dict] = {}
        if "ca" in data:
            ca = data["ca"]
            devices["appliance"] = {
                "ip": ca.get("ip", ""), "user": ca.get("user_name", "root"),
                "password": ca.get("password", ""), "transport": "ssh",
            }
        if "em" in data and data["em"].get("ip"):
            em = data["em"]
            devices["em"] = {
                "ip": em.get("ip", ""), "user": em.get("user_name", "root"),
                "password": em.get("password", ""), "transport": "ssh",
            }
        if "switch" in data and data["switch"].get("ip"):
            sw = data["switch"]
            devices["switch"] = {
                "ip": sw.get("ip", ""), "user": sw.get("user_name", "admin"),
                "password": sw.get("password", ""), "transport": "switch",
            }
        if "passthrough" in data and data["passthrough"].get("ip"):
            pt = data["passthrough"]
            devices["endpoint"] = {
                "ip": pt.get("ip", ""), "user": pt.get("user_name", "Administrator"),
                "password": pt.get("password", ""), "transport": "winrm",
            }
        if "ad" in data and data["ad"].get("ip"):
            ad = data["ad"]
            devices["ad"] = {
                "ip": ad.get("ip", ""), "user": ad.get("user_name", "root"),
                "password": ad.get("password", ""), "transport": ad.get("transport", "ssh"),
            }
        return cls(devices=devices)


# ═══════════════════════════════════════════════════════════════════════════
# Per-transport NTP query strategies
# ═══════════════════════════════════════════════════════════════════════════

def _check_linux_ntp(ip: str, user: str, password: str) -> DeviceSync:
    """Check NTP sync on a Linux host (ntpq, chronyc, or timedatectl)."""
    if paramiko is None:
        raise ImportError("paramiko required")

    ds = DeviceSync(name="", ip=ip, transport="ssh")
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        # Try password first, fall back to key-based auth
        try:
            client.connect(ip, username=user, password=password, timeout=15)
        except paramiko.ssh_exception.BadAuthenticationType:
            # Server only allows publickey — try default keys
            client.connect(ip, username=user, timeout=15,
                           look_for_keys=True, allow_agent=True)

        # Get current time
        _, stdout, _ = client.exec_command("date '+%Y-%m-%d %H:%M:%S %Z'")
        ds.local_time = stdout.read().decode().strip()

        # Try ntpq first (classic ntpd)
        _, stdout, stderr = client.exec_command("ntpq -pn 2>/dev/null")
        ntpq_out = stdout.read().decode().strip()

        if ntpq_out and "offset" not in stderr.read().decode().lower():
            ds.raw_output = ntpq_out
            _parse_ntpq(ds, ntpq_out)
            return ds

        # Try chronyc (RHEL 8+, CentOS 8+)
        _, stdout, _ = client.exec_command("chronyc tracking 2>/dev/null")
        chrony_out = stdout.read().decode().strip()
        if chrony_out and "System time" in chrony_out:
            ds.raw_output = chrony_out
            _parse_chronyc(ds, chrony_out)
            return ds

        # Fallback: timedatectl
        _, stdout, _ = client.exec_command("timedatectl status 2>/dev/null")
        tdc_out = stdout.read().decode().strip()
        if tdc_out:
            ds.raw_output = tdc_out
            if "synchronized: yes" in tdc_out.lower() or "NTP synchronized: yes" in tdc_out:
                ds.status = "SYNC_OK"
                ds.offset_ms = 0.0  # timedatectl doesn't give offset
            else:
                ds.status = "SYNC_WARNING"

        return ds
    except Exception as e:
        ds.error = str(e)
        ds.status = "SYNC_UNKNOWN"
        return ds
    finally:
        client.close()


def _parse_ntpq(ds: DeviceSync, output: str) -> None:
    """Parse ntpq -pn output to extract offset and stratum."""
    # Lines look like:
    # *10.0.0.1   .GPS.  1 u  64  128  377  0.123  -0.456  0.789
    # The * prefix means the active peer
    for line in output.splitlines():
        line = line.strip()
        if not line or line.startswith("=") or "remote" in line.lower():
            continue
        # Active peer starts with * , selected peer with +
        if line.startswith("*") or (ds.ntp_source == "" and line[0] in "+#o"):
            parts = line[1:].split()
            if len(parts) >= 9:
                ds.ntp_source = parts[0]
                try:
                    ds.stratum = int(parts[2])
                except ValueError:
                    pass
                try:
                    ds.offset_ms = abs(float(parts[8]))
                except (ValueError, IndexError):
                    pass
    if ds.offset_ms is not None:
        ds.status = (
            "SYNC_OK" if ds.offset_ms <= THRESHOLD_OK_MS
            else "SYNC_WARNING" if ds.offset_ms <= THRESHOLD_WARN_MS
            else "SYNC_FAIL"
        )
    else:
        ds.status = "SYNC_UNKNOWN"


def _parse_chronyc(ds: DeviceSync, output: str) -> None:
    """Parse chronyc tracking output."""
    for line in output.splitlines():
        if "Reference ID" in line:
            m = re.search(r"\((.+?)\)", line)
            if m:
                ds.ntp_source = m.group(1)
        if "Stratum" in line:
            m = re.search(r"(\d+)", line.split(":")[-1])
            if m:
                ds.stratum = int(m.group(1))
        if "System time" in line:
            # "System time     : 0.000002345 seconds fast of NTP time"
            m = re.search(r"([\d.]+)\s+seconds", line)
            if m:
                ds.offset_ms = float(m.group(1)) * 1000.0
        if "Last offset" in line:
            m = re.search(r"([+-]?[\d.]+)\s+seconds", line)
            if m:
                ds.offset_ms = abs(float(m.group(1))) * 1000.0

    if ds.offset_ms is not None:
        ds.status = (
            "SYNC_OK" if ds.offset_ms <= THRESHOLD_OK_MS
            else "SYNC_WARNING" if ds.offset_ms <= THRESHOLD_WARN_MS
            else "SYNC_FAIL"
        )
    else:
        ds.status = "SYNC_UNKNOWN"


def _check_windows_ntp(ip: str, user: str, password: str) -> DeviceSync:
    """Check NTP sync on a Windows host (w32tm)."""
    if winrm is None:
        raise ImportError("pywinrm required")

    ds = DeviceSync(name="", ip=ip, transport="winrm")
    try:
        session = winrm.Session(ip, auth=(user, password), transport="ntlm")

        # Current time
        r = session.run_ps("Get-Date -Format 'yyyy-MM-dd HH:mm:ss K'")
        ds.local_time = r.std_out.decode().strip()

        # w32tm /query /status
        r = session.run_ps("w32tm /query /status")
        status_out = r.std_out.decode().strip()
        ds.raw_output = status_out

        if status_out:
            for line in status_out.splitlines():
                if "Source:" in line:
                    ds.ntp_source = line.split(":", 1)[1].strip()
                if "Stratum:" in line:
                    m = re.search(r"(\d+)", line.split(":", 1)[1])
                    if m:
                        ds.stratum = int(m.group(1))

        # w32tm /stripchart for recent offset
        r = session.run_ps(
            f"w32tm /stripchart /computer:{ds.ntp_source or 'localhost'} "
            f"/dataonly /samples:1 2>$null"
        )
        strip_out = r.std_out.decode().strip()
        if strip_out:
            # Line: "13:45:23, +00.0012345s"
            m = re.search(r"([+-]?\d+\.\d+)s", strip_out)
            if m:
                ds.offset_ms = abs(float(m.group(1))) * 1000.0

        if ds.offset_ms is not None:
            ds.status = (
                "SYNC_OK" if ds.offset_ms <= THRESHOLD_OK_MS
                else "SYNC_WARNING" if ds.offset_ms <= THRESHOLD_WARN_MS
                else "SYNC_FAIL"
            )
        else:
            ds.status = "SYNC_UNKNOWN"

    except Exception as e:
        ds.error = str(e)
        ds.status = "SYNC_UNKNOWN"

    return ds


def _check_switch_ntp(ip: str, user: str, password: str) -> DeviceSync:
    """Check NTP sync on a Cisco IOS switch (show ntp status)."""
    if paramiko is None:
        raise ImportError("paramiko required")

    ds = DeviceSync(name="", ip=ip, transport="switch")
    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(ip, username=user, password=password, timeout=15,
                       look_for_keys=False, allow_agent=False)
        shell = client.invoke_shell()
        time.sleep(2)

        # Send commands
        shell.send("terminal length 0\n")
        time.sleep(0.5)
        shell.send("show ntp status\n")
        time.sleep(2)
        shell.send("show clock\n")
        time.sleep(1)

        output = shell.recv(8192).decode("utf-8", errors="replace")
        ds.raw_output = output
        client.close()

        # Parse NTP status
        # "Clock is synchronized, stratum 3, reference is 10.0.0.1"
        if "synchronized" in output.lower():
            m = re.search(r"stratum\s+(\d+)", output, re.IGNORECASE)
            if m:
                ds.stratum = int(m.group(1))
            m = re.search(r"reference is\s+(\S+)", output, re.IGNORECASE)
            if m:
                ds.ntp_source = m.group(1)
            # Parse 'clock offset is 44.2129 msec' or 'offset is X msec'
            m = re.search(r"(?:clock\s+)?offset\s+is\s+([+-]?[\d.]+)\s*m?sec",
                          output, re.IGNORECASE)
            if m:
                ds.offset_ms = abs(float(m.group(1)))
            else:
                ds.offset_ms = 0.0  # synchronised but offset not shown

            if ds.offset_ms <= THRESHOLD_OK_MS:
                ds.status = "SYNC_OK"
            elif ds.offset_ms <= THRESHOLD_WARN_MS:
                ds.status = "SYNC_WARNING"
            else:
                ds.status = "SYNC_FAIL"
        elif "unsynchronized" in output.lower():
            ds.status = "SYNC_FAIL"
        else:
            ds.status = "SYNC_UNKNOWN"

        # Parse clock
        m = re.search(r"(\d{2}:\d{2}:\d{2}\.\d+\s+\S+\s+\w+\s+\w+\s+\d+\s+\d{4})", output)
        if m:
            ds.local_time = m.group(1)

    except Exception as e:
        ds.error = str(e)
        ds.status = "SYNC_UNKNOWN"

    return ds


# ═══════════════════════════════════════════════════════════════════════════
# Orchestrator
# ═══════════════════════════════════════════════════════════════════════════

class NtpSyncChecker:
    """Check NTP clock sync across all testbed devices."""

    def __init__(self, config: NtpConfig | None = None):
        self.config = config or NtpConfig()

    def check_device(self, name: str, dev: dict) -> DeviceSync:
        """Check NTP sync on a single device."""
        transport = dev.get("transport", "ssh")
        ip = dev.get("ip", "")
        user = dev.get("user", "root")
        password = dev.get("password", "")

        if not ip:
            return DeviceSync(name=name, ip="", status="SYNC_UNKNOWN",
                              error="No IP configured")

        log.info(f"Checking NTP sync on {name} ({ip}, {transport}) ...")

        if transport == "ssh":
            ds = _check_linux_ntp(ip, user, password)
        elif transport == "winrm":
            ds = _check_windows_ntp(ip, user, password)
        elif transport == "switch":
            ds = _check_switch_ntp(ip, user, password)
        else:
            ds = DeviceSync(name=name, ip=ip, status="SYNC_UNKNOWN",
                            error=f"Unknown transport: {transport}")

        ds.name = name
        log.info(f"  {name}: offset={ds.offset_ms}ms  stratum={ds.stratum}  "
                 f"status={ds.status}  source={ds.ntp_source}")
        return ds

    def check_all(self) -> SyncReport:
        """Check NTP sync on all configured devices and return a report."""
        from datetime import datetime

        report = SyncReport(checked_at=datetime.now().isoformat())
        offsets: list[float] = []

        for name, dev_cfg in self.config.devices.items():
            ds = self.check_device(name, dev_cfg)
            report.devices.append(ds)
            if ds.offset_ms is not None:
                offsets.append(ds.offset_ms)

        if offsets:
            report.max_offset_ms = max(offsets)
        report.all_synced = all(d.status == "SYNC_OK" for d in report.devices)
        # SYNC_UNKNOWN means we couldn't reach the device — still allow capture
        # but warn.  Only SYNC_FAIL blocks readiness.
        report.ready_for_capture = all(
            d.status in ("SYNC_OK", "SYNC_WARNING", "SYNC_UNKNOWN")
            for d in report.devices
        )

        log.info(f"NTP report: max_offset={report.max_offset_ms:.1f}ms  "
                 f"all_synced={report.all_synced}  "
                 f"ready={report.ready_for_capture}")
        return report

    def assert_synced(self, strict: bool = False) -> SyncReport:
        """Check all devices and raise if not ready for capture.

        Args:
            strict: If True, require SYNC_OK on ALL devices.
                    If False (default), allow SYNC_WARNING.
        """
        report = self.check_all()
        if strict and not report.all_synced:
            raise RuntimeError(
                f"NTP sync FAILED (strict mode): max offset = "
                f"{report.max_offset_ms:.1f} ms\n{report.summary()}"
            )
        if not report.ready_for_capture:
            raise RuntimeError(
                f"NTP sync FAILED: not all devices are synchronised.\n"
                f"{report.summary()}"
            )
        return report
