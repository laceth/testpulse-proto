"""PCAP trace collector for TestPulse — multi-device packet capture.

Starts and stops tcpdump / tshark PCAPs on every device in the testbed
**before** the test round begins and pulls the captures after the test
completes.  Produces one ``.pcap`` file per device so the timeline and
protocol diagrams can correlate log events with actual wire packets.

Capture points::

    ┌─────────────┐   ┌───────────┐   ┌──────────────┐   ┌────────────┐
    │  Passthru   │   │  Cisco    │   │  Forescout   │   │  LDAP / AD │
    │   VM (EP)   │   │  Switch   │   │  Appliance   │   │    VM      │
    │  tshark.exe │   │  monitor  │   │  tcpdump     │   │  tcpdump   │
    └──────┬──────┘   └─────┬─────┘   └──────┬───────┘   └─────┬──────┘
           │                │                │                  │
           └────────────────┴────────────────┴──────────────────┘
                        NTP-synchronised clocks

**NTP requirement**: every device MUST report an NTP offset < 50 ms
before captures start.  The ``NtpSyncChecker`` (ntp_sync.py) verifies
this.  If any device is out of sync, the test round should be delayed
until clocks converge or the user is warned.

Usage::

    from testpulse.collect.pcap_collector import PcapCollector, PcapConfig

    cfg = PcapConfig(
        appliance_ip="10.16.177.66",
        switch_ip="10.16.128.21",
        endpoint_ip="10.16.133.143",
        ad_ip="10.100.49.30",
    )
    pcap = PcapCollector(cfg)

    # 1. Start captures (BEFORE the test round)
    pcap.start_all()

    # ... run the test ...

    # 2. Stop and pull captures (AFTER the test round)
    artifacts = pcap.stop_and_collect(run_dir="/path/to/artifacts/latest")
    # artifacts = {"appliance": "/path/.../appliance.pcap", ...}
"""
from __future__ import annotations

import logging
import os
import time
from dataclasses import dataclass, field
from pathlib import Path
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
# Configuration
# ═══════════════════════════════════════════════════════════════════════════

@dataclass
class PcapTarget:
    """A single device where PCAP will be captured."""
    name: str                       # logical name: appliance, switch, endpoint, ad, em
    ip: str                         # reachable IP
    user: str = "root"
    password: str = ""
    transport: str = "ssh"          # ssh | winrm | switch_span
    interface: str = ""             # capture interface (empty = auto)
    capture_filter: str = ""        # BPF filter (optional)
    remote_pcap_path: str = ""      # where the pcap lands on the device
    enabled: bool = True


@dataclass
class PcapConfig:
    """Multi-device PCAP capture configuration."""

    # --- Forescout appliance (Linux, tcpdump via SSH) ---
    appliance_ip: str = "10.16.177.66"
    appliance_user: str = "root"
    appliance_pass: str = "aristo1"
    appliance_interface: str = "eth0"
    appliance_filter: str = "port 1812 or port 1813 or port 389 or port 636"

    # --- Enterprise Manager (Linux, tcpdump via SSH) ---
    em_ip: str = ""
    em_user: str = "root"
    em_pass: str = "aristo1"
    em_interface: str = "eth0"
    em_filter: str = ""

    # --- Cisco switch (SPAN mirror or EPC) ---
    switch_ip: str = ""
    switch_user: str = "admin"
    switch_pass: str = "aristo"
    switch_monitor_session: int = 1
    switch_source_interface: str = ""   # e.g. "GigabitEthernet3/1"
    switch_dest_interface: str = ""     # SPAN destination port

    # --- Windows passthrough VM (tshark via WinRM) ---
    endpoint_ip: str = ""
    endpoint_user: str = "Administrator"
    endpoint_pass: str = "aristo"
    endpoint_interface: str = ""        # tshark interface name or index
    endpoint_filter: str = "eapol or (udp port 1812) or (udp port 1813)"

    # --- Dual-NIC passthrough support ---
    # When the passthrough VM has two NICs:
    #   - Management NIC (10.16.133.143) — survives 802.1X toggle
    #   - 802.1X passthrough NIC — toggles during auth (kills tshark)
    # Set endpoint_mgmt_interface to capture L3+ (RADIUS/LDAP) on
    # the management NIC while SPAN captures L2 EAPOL on the switch.
    endpoint_dual_nic: bool = False
    endpoint_mgmt_interface: str = ""       # management NIC name (survives toggle)
    endpoint_mgmt_filter: str = (
        "(udp port 1812 or udp port 1813) or "  # RADIUS
        "(tcp port 389 or tcp port 636) or "     # LDAP/S
        "(udp port 67 or udp port 68) or "       # DHCP
        "icmp"                                   # ping
    )

    # --- LDAP / AD VM (Linux or Windows) ---
    ad_ip: str = ""
    ad_user: str = "root"
    ad_pass: str = ""
    ad_transport: str = "ssh"           # ssh or winrm
    ad_interface: str = ""
    ad_filter: str = "port 389 or port 636 or port 88"

    # Global settings
    snap_len: int = 0                   # 0 = no truncation
    max_packets: int = 0               # 0 = unlimited
    ring_buffer_mb: int = 50           # max pcap file size

    def build_targets(self) -> list[PcapTarget]:
        """Build list of enabled PcapTarget objects from config."""
        targets: list[PcapTarget] = []

        if self.appliance_ip:
            targets.append(PcapTarget(
                name="appliance", ip=self.appliance_ip,
                user=self.appliance_user, password=self.appliance_pass,
                transport="ssh", interface=self.appliance_interface,
                capture_filter=self.appliance_filter,
                remote_pcap_path="/tmp/testpulse_capture_appliance.pcap",
            ))
        if self.em_ip:
            targets.append(PcapTarget(
                name="em", ip=self.em_ip,
                user=self.em_user, password=self.em_pass,
                transport="ssh", interface=self.em_interface,
                capture_filter=self.em_filter,
                remote_pcap_path="/tmp/testpulse_capture_em.pcap",
            ))
        if self.endpoint_ip:
            if self.endpoint_dual_nic and self.endpoint_mgmt_interface:
                # Dual-NIC mode: capture on management NIC (survives 802.1X toggle)
                targets.append(PcapTarget(
                    name="endpoint_mgmt", ip=self.endpoint_ip,
                    user=self.endpoint_user, password=self.endpoint_pass,
                    transport="winrm", interface=self.endpoint_mgmt_interface,
                    capture_filter=self.endpoint_mgmt_filter,
                    remote_pcap_path=r"C:\TestPulse\captures\testpulse_capture_endpoint_mgmt.pcap",
                ))
                # Also capture on 802.1X NIC if interface is set (may be killed by toggle)
                if self.endpoint_interface:
                    targets.append(PcapTarget(
                        name="endpoint_dot1x", ip=self.endpoint_ip,
                        user=self.endpoint_user, password=self.endpoint_pass,
                        transport="winrm", interface=self.endpoint_interface,
                        capture_filter="ether proto 0x888e",  # L2-only on passthrough NIC
                        remote_pcap_path=r"C:\TestPulse\captures\testpulse_capture_endpoint_dot1x.pcap",
                    ))
            else:
                targets.append(PcapTarget(
                    name="endpoint", ip=self.endpoint_ip,
                    user=self.endpoint_user, password=self.endpoint_pass,
                    transport="winrm", interface=self.endpoint_interface,
                    capture_filter=self.endpoint_filter,
                    remote_pcap_path=r"C:\TestPulse\captures\testpulse_capture_endpoint.pcap",
                ))
        if self.ad_ip:
            targets.append(PcapTarget(
                name="ad", ip=self.ad_ip,
                user=self.ad_user, password=self.ad_pass,
                transport=self.ad_transport, interface=self.ad_interface,
                capture_filter=self.ad_filter,
                remote_pcap_path="/tmp/testpulse_capture_ad.pcap"
                    if self.ad_transport == "ssh"
                    else r"C:\TestPulse\captures\testpulse_capture_ad.pcap",
            ))
        if self.switch_ip and self.switch_source_interface:
            targets.append(PcapTarget(
                name="switch", ip=self.switch_ip,
                user=self.switch_user, password=self.switch_pass,
                transport="switch_span",
                interface=self.switch_source_interface,
            ))
        return targets

    @classmethod
    def from_yaml(cls, path: str) -> PcapConfig:
        """Load from a radius.yml / testbed YAML file."""
        try:
            import yaml
        except ImportError:
            raise ImportError("PyYAML required: pip install pyyaml")

        with open(path) as fh:
            data = yaml.safe_load(fh)

        cfg = cls()
        if "ca" in data:
            cfg.appliance_ip = data["ca"].get("ip", cfg.appliance_ip)
            cfg.appliance_user = data["ca"].get("user_name", cfg.appliance_user)
            cfg.appliance_pass = data["ca"].get("password", cfg.appliance_pass)
        if "em" in data:
            cfg.em_ip = data["em"].get("ip", "")
            cfg.em_user = data["em"].get("user_name", cfg.em_user)
            cfg.em_pass = data["em"].get("password", cfg.em_pass)
        if "switch" in data:
            sw = data["switch"]
            cfg.switch_ip = sw.get("ip", "")
            cfg.switch_user = sw.get("user_name", cfg.switch_user)
            cfg.switch_pass = sw.get("password", cfg.switch_pass)
            p1 = sw.get("port1", {})
            cfg.switch_source_interface = p1.get("interface", "")
        if "passthrough" in data:
            pt = data["passthrough"]
            cfg.endpoint_ip = pt.get("ip", "")
            cfg.endpoint_user = pt.get("user_name", cfg.endpoint_user)
            cfg.endpoint_pass = pt.get("password", cfg.endpoint_pass)
            cfg.endpoint_dual_nic = pt.get("dual_nic", False)
            cfg.endpoint_mgmt_interface = pt.get("mgmt_interface", "")
            cfg.endpoint_interface = pt.get("dot1x_interface",
                                            pt.get("interface", ""))
        if "ad" in data:
            ad = data["ad"]
            cfg.ad_ip = ad.get("ip", "")
            cfg.ad_user = ad.get("user_name", "root")
            cfg.ad_pass = ad.get("password", "")
            cfg.ad_transport = ad.get("transport", "ssh")
        if "pcap" in data:
            pc = data["pcap"]
            cfg.snap_len = pc.get("snap_len", 0)
            cfg.max_packets = pc.get("max_packets", 0)
            cfg.ring_buffer_mb = pc.get("ring_buffer_mb", 50)
        return cfg


# ═══════════════════════════════════════════════════════════════════════════
# SSH / WinRM execution helpers
# ═══════════════════════════════════════════════════════════════════════════

def _ssh_exec(ip: str, user: str, password: str, cmd: str,
              timeout: int = 30) -> str:
    """Execute a command over SSH and return stdout."""
    if paramiko is None:
        raise ImportError("paramiko required: pip install paramiko")
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(ip, username=user, password=password, timeout=15)
        _, stdout, stderr = client.exec_command(cmd, timeout=timeout)
        return stdout.read().decode("utf-8", errors="replace").strip()
    finally:
        client.close()


def _ssh_exec_background(ip: str, user: str, password: str, cmd: str) -> None:
    """Start a command in the background via SSH (nohup + &)."""
    if paramiko is None:
        raise ImportError("paramiko required: pip install paramiko")
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(ip, username=user, password=password, timeout=15)
    # Use nohup to detach; don't wait for output
    bg_cmd = f"nohup {cmd} > /dev/null 2>&1 &"
    client.exec_command(bg_cmd)
    log.info(f"[{ip}] Background started: {cmd[:100]}")
    # Don't close immediately — give the process time to fork
    time.sleep(1)
    client.close()


def _ssh_download(ip: str, user: str, password: str,
                  remote_path: str, local_path: str) -> str:
    """Download a file via SFTP."""
    if paramiko is None:
        raise ImportError("paramiko required: pip install paramiko")
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(ip, username=user, password=password, timeout=15)
        sftp = client.open_sftp()
        sftp.get(remote_path, local_path)
        sftp.close()
        size = os.path.getsize(local_path)
        log.info(f"SFTP {ip}:{remote_path} → {local_path} ({size:,} bytes)")
    finally:
        client.close()
    return local_path


def _winrm_exec(ip: str, user: str, password: str, cmd: str) -> str:
    """Execute a PowerShell command on Windows via WinRM."""
    if winrm is None:
        raise ImportError("pywinrm required: pip install pywinrm")
    session = winrm.Session(ip, auth=(user, password), transport="ntlm")
    r = session.run_ps(f"$ProgressPreference = 'SilentlyContinue'; {cmd}")
    stdout = r.std_out.decode("utf-8", errors="replace").strip()
    if r.status_code != 0:
        stderr = r.std_err.decode("utf-8", errors="replace").strip()
        raise RuntimeError(f"WinRM command failed ({r.status_code}): {stderr}")
    return stdout


def _winrm_download(ip: str, user: str, password: str,
                    remote_path: str, local_path: str) -> str:
    """Download a file from Windows via pypsrp."""
    from pypsrp.client import Client
    os.makedirs(os.path.dirname(local_path) or ".", exist_ok=True)
    client = Client(ip, username=user, password=password, ssl=False, auth="ntlm")
    client.fetch(remote_path, local_path)
    log.info(f"WinRM download {ip}:{remote_path} → {local_path}")
    return local_path


# ═══════════════════════════════════════════════════════════════════════════
# Per-device capture strategies
# ═══════════════════════════════════════════════════════════════════════════

class _CaptureStrategy:
    """Base class for per-device PCAP capture."""

    def __init__(self, target: PcapTarget, config: PcapConfig):
        self.target = target
        self.config = config

    def start(self) -> None:
        raise NotImplementedError

    def stop(self) -> None:
        raise NotImplementedError

    def collect(self, run_dir: str) -> str | None:
        raise NotImplementedError


class _LinuxTcpdumpStrategy(_CaptureStrategy):
    """tcpdump on a Linux host (appliance, EM, AD)."""

    def _build_cmd(self) -> str:
        t = self.target
        parts = ["tcpdump", "-i", t.interface or "any"]
        if self.config.snap_len:
            parts.extend(["-s", str(self.config.snap_len)])
        if self.config.max_packets:
            parts.extend(["-c", str(self.config.max_packets)])
        parts.extend(["-w", t.remote_pcap_path])
        if t.capture_filter:
            parts.append(t.capture_filter)
        return " ".join(parts)

    def start(self) -> None:
        t = self.target
        log.info(f"[{t.name}] Starting tcpdump on {t.ip} ({t.interface or 'any'}) ...")
        # Kill any leftover capture
        try:
            _ssh_exec(t.ip, t.user, t.password,
                      f"pkill -f 'tcpdump.*{t.remote_pcap_path}' 2>/dev/null; "
                      f"rm -f {t.remote_pcap_path}")
        except Exception:
            pass
        cmd = self._build_cmd()
        _ssh_exec_background(t.ip, t.user, t.password, cmd)
        log.info(f"[{t.name}] tcpdump started → {t.remote_pcap_path}")

    def stop(self) -> None:
        t = self.target
        log.info(f"[{t.name}] Stopping tcpdump on {t.ip} ...")
        try:
            _ssh_exec(t.ip, t.user, t.password,
                      f"pkill -f 'tcpdump.*{t.remote_pcap_path}' 2>/dev/null || true")
        except Exception as e:
            log.warning(f"[{t.name}] stop tcpdump: {e}")
        # Give tcpdump time to flush
        time.sleep(1)

    def collect(self, run_dir: str) -> str | None:
        t = self.target
        local_path = os.path.join(run_dir, "pcap", f"{t.name}.pcap")
        try:
            os.makedirs(os.path.dirname(local_path), exist_ok=True)
            _ssh_download(t.ip, t.user, t.password, t.remote_pcap_path, local_path)
            return local_path
        except Exception as e:
            log.warning(f"[{t.name}] Failed to collect pcap: {e}")
            return None


class _WindowsTsharkStrategy(_CaptureStrategy):
    """tshark on a Windows host (passthrough VM, AD if Windows)."""

    def _build_cmd(self) -> str:
        t = self.target
        parts = ["tshark"]
        if t.interface:
            parts.extend(["-i", t.interface])
        if self.config.snap_len:
            parts.extend(["-s", str(self.config.snap_len)])
        if self.config.max_packets:
            parts.extend(["-c", str(self.config.max_packets)])
        parts.extend(["-w", t.remote_pcap_path])
        if t.capture_filter:
            parts.extend(["-f", f'"{t.capture_filter}"'])
        return " ".join(parts)

    def start(self) -> None:
        t = self.target
        log.info(f"[{t.name}] Starting tshark on {t.ip} ...")
        remote_dir = t.remote_pcap_path.rsplit("\\", 1)[0]
        _winrm_exec(t.ip, t.user, t.password,
                     f"New-Item -Path '{remote_dir}' -ItemType Directory -Force | Out-Null")
        # Kill any leftover tshark
        try:
            _winrm_exec(t.ip, t.user, t.password,
                         "Get-Process tshark -ErrorAction SilentlyContinue | Stop-Process -Force")
        except Exception:
            pass
        # Start tshark as background job
        cmd = self._build_cmd()
        _winrm_exec(t.ip, t.user, t.password,
                     f"Start-Job -ScriptBlock {{ & {cmd} }}")
        log.info(f"[{t.name}] tshark started → {t.remote_pcap_path}")

    def stop(self) -> None:
        t = self.target
        log.info(f"[{t.name}] Stopping tshark on {t.ip} ...")
        try:
            _winrm_exec(t.ip, t.user, t.password,
                         "Get-Process tshark -ErrorAction SilentlyContinue | Stop-Process -Force")
        except Exception as e:
            log.warning(f"[{t.name}] stop tshark: {e}")
        time.sleep(2)

    def collect(self, run_dir: str) -> str | None:
        t = self.target
        local_path = os.path.join(run_dir, "pcap", f"{t.name}.pcap")
        try:
            os.makedirs(os.path.dirname(local_path), exist_ok=True)
            _winrm_download(t.ip, t.user, t.password, t.remote_pcap_path, local_path)
            return local_path
        except Exception as e:
            log.warning(f"[{t.name}] Failed to collect pcap: {e}")
            return None


class _SwitchSpanStrategy(_CaptureStrategy):
    """Configure SPAN on Cisco IOS and capture on the mirror port.

    Note: actual pcap capture happens on the device connected to the
    SPAN destination port.  This strategy configures/tears down the
    SPAN session only.  The capture file comes from the appliance or
    a dedicated capture host.
    """

    def start(self) -> None:
        t = self.target
        cfg = self.config
        log.info(f"[{t.name}] Configuring SPAN session {cfg.switch_monitor_session} "
                 f"on {t.ip} ...")
        if not cfg.switch_dest_interface:
            log.warning(f"[{t.name}] No SPAN dest interface configured — skipping")
            return

        cmds = [
            f"monitor session {cfg.switch_monitor_session} source interface "
            f"{cfg.switch_source_interface} both",
            f"monitor session {cfg.switch_monitor_session} destination interface "
            f"{cfg.switch_dest_interface}",
        ]
        try:
            if paramiko is None:
                raise ImportError("paramiko required")
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(t.ip, username=t.user, password=t.password, timeout=15)
            shell = client.invoke_shell()
            time.sleep(1)
            shell.send("enable\n")
            time.sleep(1)
            shell.send("configure terminal\n")
            time.sleep(1)
            for cmd in cmds:
                shell.send(cmd + "\n")
                time.sleep(0.5)
            shell.send("end\n")
            time.sleep(1)
            output = shell.recv(4096).decode("utf-8", errors="replace")
            log.debug(f"[{t.name}] SPAN config output: {output[:300]}")
            client.close()
            log.info(f"[{t.name}] SPAN session configured")
        except Exception as e:
            log.warning(f"[{t.name}] SPAN setup failed: {e}")

    def stop(self) -> None:
        t = self.target
        cfg = self.config
        log.info(f"[{t.name}] Tearing down SPAN session {cfg.switch_monitor_session} ...")
        try:
            if paramiko is None:
                return
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(t.ip, username=t.user, password=t.password, timeout=15)
            shell = client.invoke_shell()
            time.sleep(1)
            shell.send("enable\n")
            time.sleep(1)
            shell.send("configure terminal\n")
            time.sleep(1)
            shell.send(f"no monitor session {cfg.switch_monitor_session}\n")
            time.sleep(1)
            shell.send("end\n")
            time.sleep(1)
            client.close()
            log.info(f"[{t.name}] SPAN session removed")
        except Exception as e:
            log.warning(f"[{t.name}] SPAN teardown: {e}")

    def collect(self, run_dir: str) -> str | None:
        # SPAN doesn't produce a pcap on the switch itself
        # The pcap lives on the device connected to the mirror port
        log.info(f"[{self.target.name}] SPAN — pcap from mirror port device (not switch)")
        return None


# ═══════════════════════════════════════════════════════════════════════════
# Strategy factory
# ═══════════════════════════════════════════════════════════════════════════

def _make_strategy(target: PcapTarget, config: PcapConfig) -> _CaptureStrategy:
    if target.transport == "ssh":
        return _LinuxTcpdumpStrategy(target, config)
    elif target.transport == "winrm":
        return _WindowsTsharkStrategy(target, config)
    elif target.transport == "switch_span":
        return _SwitchSpanStrategy(target, config)
    else:
        raise ValueError(f"Unknown transport for {target.name}: {target.transport}")


# ═══════════════════════════════════════════════════════════════════════════
# Orchestrator
# ═══════════════════════════════════════════════════════════════════════════

class PcapCollector:
    """Orchestrate PCAP captures across all testbed devices.

    Lifecycle::

        pcap = PcapCollector(config)

        # BEFORE the test round
        pcap.start_all()

        # ... test runs ...

        # AFTER the test round
        artifacts = pcap.stop_and_collect(run_dir)
    """

    def __init__(self, config: PcapConfig | None = None):
        self.config = config or PcapConfig()
        self.targets = self.config.build_targets()
        self._strategies: list[_CaptureStrategy] = [
            _make_strategy(t, self.config) for t in self.targets if t.enabled
        ]
        self._running = False

    def start_all(self) -> None:
        """Start PCAP captures on all enabled devices.

        Call this BEFORE the test round begins.
        """
        log.info("=== Starting PCAP captures across all devices ===")
        for strat in self._strategies:
            try:
                strat.start()
            except Exception as e:
                log.error(f"[{strat.target.name}] Failed to start capture: {e}")
        self._running = True
        log.info(f"=== PCAP captures running on {len(self._strategies)} devices ===")

    def stop_all(self) -> None:
        """Stop all PCAP captures."""
        log.info("=== Stopping PCAP captures ===")
        for strat in self._strategies:
            try:
                strat.stop()
            except Exception as e:
                log.error(f"[{strat.target.name}] Failed to stop capture: {e}")
        self._running = False

    def stop_and_collect(self, run_dir: str) -> dict[str, str | None]:
        """Stop all captures and pull pcap files into run_dir/pcap/.

        Returns:
            Dict mapping device name to local pcap path (or None if failed).
        """
        self.stop_all()
        log.info("=== Collecting PCAP files ===")
        results: dict[str, str | None] = {}
        for strat in self._strategies:
            try:
                path = strat.collect(run_dir)
                results[strat.target.name] = path
                if path:
                    size = os.path.getsize(path)
                    log.info(f"[{strat.target.name}] pcap: {path} ({size:,} bytes)")
            except Exception as e:
                log.error(f"[{strat.target.name}] Failed to collect: {e}")
                results[strat.target.name] = None
        return results

    @property
    def device_names(self) -> list[str]:
        """Names of all configured capture targets."""
        return [t.name for t in self.targets if t.enabled]
