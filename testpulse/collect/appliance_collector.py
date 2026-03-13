"""Appliance log collector for TestPulse.

Pulls log files from the Forescout appliance (CounterACT / eyeSight)
using direct SSH/SFTP or reverse tunnel connectivity.

Collected logs::

    /usr/local/forescout/log/plugin/dot1x/radiusd.log
    /usr/local/forescout/log/plugin/dot1x/dot1x.log
    /usr/local/forescout/log/framework.log
    Redis MONITOR snapshot (pre-admission rule state)
    fstool dot1x status
    fstool hostinfo <mac>

Usage::

    from testpulse.collect.appliance_collector import ApplianceCollector

    collector = ApplianceCollector(ip="10.16.177.66", user="root", password="aristo1")
    collector.collect_all(run_dir="/path/to/artifacts/latest", mac="288023b82d59")
"""
from __future__ import annotations

import logging
import os
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

log = logging.getLogger("testpulse")


# Forescout standard log paths (appliance-side only)
DOT1X_LOG_PATH = "/usr/local/forescout/log/plugin/dot1x/dot1x.log"
RADIUSD_LOG_PATH = "/usr/local/forescout/log/plugin/dot1x/radiusd.log"
LOCAL_PROPERTIES_PATH = "/usr/local/forescout/plugin/dot1x/local.properties"
# NOTE: framework.log is generated locally by fstester, NOT on the appliance.
# Use --framework-log to supply it from the local fstester log output.

# Rotated log glob patterns
DOT1X_LOG_ROTATED = "/usr/local/forescout/log/plugin/dot1x/dot1x.log.*"
RADIUSD_LOG_ROTATED = "/usr/local/forescout/log/plugin/dot1x/radiusd.log.*"


@dataclass
class ApplianceCollectorConfig:
    """What to collect from the appliance."""
    collect_radiusd: bool = True
    collect_dot1x: bool = True
    collect_framework: bool = False   # framework.log is LOCAL (fstester), not on appliance
    collect_redis_snapshot: bool = True
    collect_fstool_status: bool = True
    collect_hostinfo: bool = True
    collect_local_properties: bool = True
    collect_rotated_logs: bool = False
    redis_monitor_seconds: int = 10
    tail_lines: int = 0  # 0 = full file; >0 = last N lines


class ApplianceCollector:
    """Collect evidence from the Forescout appliance via SSH.

    Supports both direct paramiko SSH and the TunnelManager reverse
    tunnel approach.
    """

    def __init__(
        self,
        ip: str,
        user: str = "root",
        password: str = "aristo1",
        tunnel_manager=None,
        config: ApplianceCollectorConfig | None = None,
    ):
        self.ip = ip
        self.user = user
        self.password = password
        self.tunnel = tunnel_manager  # Optional TunnelManager instance
        self.cfg = config or ApplianceCollectorConfig()
        self._ssh = None

    def _get_ssh(self):
        """Get or create a paramiko SSH client."""
        if self.tunnel:
            return self.tunnel._get_ssh_client("appliance")

        try:
            import paramiko
        except ImportError:
            raise ImportError("paramiko required: pip install paramiko")

        if self._ssh is not None:
            transport = self._ssh.get_transport()
            if transport and transport.is_active():
                return self._ssh

        self._ssh = paramiko.SSHClient()
        self._ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        self._ssh.connect(self.ip, username=self.user, password=self.password, timeout=15)
        log.info(f"SSH connected to appliance {self.ip}")
        return self._ssh

    def _exec(self, cmd: str, timeout: int = 30) -> str:
        """Execute a command on the appliance."""
        client = self._get_ssh()
        _, stdout, stderr = client.exec_command(cmd, timeout=timeout)
        return stdout.read().decode("utf-8", errors="replace").strip()

    def _download(self, remote_path: str, local_path: str) -> str:
        """Download a file from the appliance via SFTP."""
        os.makedirs(os.path.dirname(local_path) or ".", exist_ok=True)
        client = self._get_ssh()
        sftp = client.open_sftp()
        try:
            sftp.get(remote_path, local_path)
            size = os.path.getsize(local_path)
            log.info(f"Downloaded {remote_path} → {local_path} ({size:,} bytes)")
        finally:
            sftp.close()
        return local_path

    def _download_or_tail(self, remote_path: str, local_path: str) -> str:
        """Download full file or tail last N lines."""
        if self.cfg.tail_lines > 0:
            content = self._exec(f"tail -n {self.cfg.tail_lines} {remote_path}")
            os.makedirs(os.path.dirname(local_path) or ".", exist_ok=True)
            Path(local_path).write_text(content, encoding="utf-8")
            log.info(f"Tailed {self.cfg.tail_lines} lines from {remote_path} → {local_path}")
            return local_path
        else:
            return self._download(remote_path, local_path)

    # ------------------------------------------------------------------
    # Individual collectors
    # ------------------------------------------------------------------

    def collect_radiusd(self, run_dir: str) -> str | None:
        """Collect radiusd.log."""
        if not self.cfg.collect_radiusd:
            return None
        local = os.path.join(run_dir, "radiusd.log")
        try:
            return self._download_or_tail(RADIUSD_LOG_PATH, local)
        except Exception as e:
            log.warning(f"Failed to collect radiusd.log: {e}")
            return None

    def collect_dot1x(self, run_dir: str) -> str | None:
        """Collect dot1x.log."""
        if not self.cfg.collect_dot1x:
            return None
        local = os.path.join(run_dir, "dot1x.log")
        try:
            return self._download_or_tail(DOT1X_LOG_PATH, local)
        except Exception as e:
            log.warning(f"Failed to collect dot1x.log: {e}")
            return None

    def collect_framework(self, run_dir: str) -> str | None:
        """Collect framework.log — DISABLED by default.

        framework.log is produced locally by the fstester test runner,
        NOT on the Forescout appliance.  Use --framework-log to copy
        the local fstester log into the run directory.
        """
        if not self.cfg.collect_framework:
            return None
        log.warning("framework.log is a local fstester log, not on the appliance — skipping")
        return None

    def collect_redis_snapshot(self, run_dir: str) -> str | None:
        """Capture Redis MONITOR output for pre-admission rule state."""
        if not self.cfg.collect_redis_snapshot:
            return None
        local = os.path.join(run_dir, "redis_monitor.log")
        try:
            dur = self.cfg.redis_monitor_seconds
            log.info(f"Capturing Redis MONITOR for {dur}s ...")
            output = self._exec(
                f"timeout {dur} redis-cli monitor 2>/dev/null || true",
                timeout=dur + 15,
            )
            Path(local).write_text(output, encoding="utf-8")
            log.info(f"Redis snapshot: {len(output)} bytes → {local}")
            return local
        except Exception as e:
            log.warning(f"Failed to capture Redis monitor: {e}")
            return None

    def collect_redis_hash_dump(self, run_dir: str, hash_key: str = "default") -> str | None:
        """Dump a Redis hash (e.g. 'default' for pre-admission rules) via HGETALL."""
        local = os.path.join(run_dir, "redis_hash_dump.txt")
        try:
            output = self._exec(f"redis-cli hgetall {hash_key}")
            Path(local).write_text(output, encoding="utf-8")
            log.info(f"Redis HGETALL '{hash_key}': {len(output)} bytes → {local}")
            return local
        except Exception as e:
            log.warning(f"Failed to dump Redis hash '{hash_key}': {e}")
            return None

    def collect_fstool_status(self, run_dir: str) -> str | None:
        """Collect 'fstool dot1x status' output."""
        if not self.cfg.collect_fstool_status:
            return None
        local = os.path.join(run_dir, "fstool_dot1x_status.txt")
        try:
            output = self._exec("fstool dot1x status")
            Path(local).write_text(output, encoding="utf-8")
            log.info(f"fstool dot1x status: {len(output)} bytes")
            return local
        except Exception as e:
            log.warning(f"Failed to collect fstool status: {e}")
            return None

    def collect_hostinfo(self, run_dir: str, mac: str) -> str | None:
        """Collect 'fstool hostinfo <mac>' output."""
        if not self.cfg.collect_hostinfo or not mac:
            return None
        local = os.path.join(run_dir, f"fstool_hostinfo_{mac}.txt")
        try:
            output = self._exec(f"fstool hostinfo {mac}")
            Path(local).write_text(output, encoding="utf-8")
            log.info(f"fstool hostinfo {mac}: {len(output.splitlines())} properties")
            return local
        except Exception as e:
            log.warning(f"Failed to collect hostinfo for {mac}: {e}")
            return None

    def collect_local_properties(self, run_dir: str) -> str | None:
        """Collect the dot1x local.properties file (plugin config including pre-admission rules)."""
        if not self.cfg.collect_local_properties:
            return None
        local = os.path.join(run_dir, "local_properties.txt")
        try:
            return self._download(LOCAL_PROPERTIES_PATH, local)
        except Exception as e:
            log.warning(f"Failed to collect local.properties: {e}")
            return None

    def collect_rotated_logs(self, run_dir: str) -> list[str]:
        """Collect rotated log files (radiusd.log.1, framework.log.1, etc.)."""
        if not self.cfg.collect_rotated_logs:
            return []

        collected = []
        for pattern, prefix in [
            (RADIUSD_LOG_ROTATED, "radiusd.log"),
            (DOT1X_LOG_ROTATED, "dot1x.log"),
        ]:
            try:
                listing = self._exec(f"ls -1 {pattern} 2>/dev/null || true")
                for remote_path in listing.splitlines():
                    remote_path = remote_path.strip()
                    if not remote_path:
                        continue
                    fname = os.path.basename(remote_path)
                    local = os.path.join(run_dir, fname)
                    try:
                        self._download(remote_path, local)
                        collected.append(local)
                    except Exception as e:
                        log.warning(f"Failed to collect {remote_path}: {e}")
            except Exception as e:
                log.debug(f"No rotated logs for {pattern}: {e}")

        return collected

    # ------------------------------------------------------------------
    # Orchestrator
    # ------------------------------------------------------------------

    def collect_all(self, run_dir: str, mac: str = "") -> dict[str, str | list | None]:
        """Collect all configured artifacts from the appliance.

        Args:
            run_dir: Local directory to store collected artifacts.
            mac: Endpoint MAC address for hostinfo lookup.

        Returns:
            Dict mapping artifact names to local file paths.
        """
        os.makedirs(run_dir, exist_ok=True)
        log.info(f"=== Collecting appliance artifacts → {run_dir} ===")

        results: dict[str, str | list | None] = {}
        results["radiusd"] = self.collect_radiusd(run_dir)
        results["dot1x"] = self.collect_dot1x(run_dir)
        results["framework"] = self.collect_framework(run_dir)
        results["redis_monitor"] = self.collect_redis_snapshot(run_dir)
        results["redis_hash"] = self.collect_redis_hash_dump(run_dir)
        results["fstool_status"] = self.collect_fstool_status(run_dir)
        results["hostinfo"] = self.collect_hostinfo(run_dir, mac)
        results["local_properties"] = self.collect_local_properties(run_dir)
        results["rotated"] = self.collect_rotated_logs(run_dir)

        collected = sum(1 for v in results.values() if v)
        log.info(f"=== Collected {collected}/{len(results)} artifact groups ===")
        return results

    def close(self):
        """Close any direct SSH connections."""
        if self._ssh:
            try:
                self._ssh.close()
            except Exception:
                pass
            self._ssh = None
