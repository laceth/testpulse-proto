"""Reverse SSH tunnel manager for TestPulse evidence collection.

Provides connectivity between the VM, Forescout appliance, and EM
using reverse SSH tunnels when direct connectivity is not available.

Architecture::

    ┌──────────┐  ssh -R 22022  ┌─────────────┐
    │  Dev VM  │◄───────────────│  Appliance   │
    │ (triley) │                │ 10.16.177.66 │
    └──────────┘                └──────────────┘

    From VM  → appliance:  ssh root@10.16.177.66
    From appliance → VM:   ssh -i /root/.ssh/vm_from_appliance_ed25519 -p 22022 triley@127.0.0.1
    SCP appliance → VM:    scp -i /root/.ssh/vm_from_appliance_ed25519 -P 22022 <file> triley@127.0.0.1:/tmp/

Usage::

    from testpulse.collect.tunnel_manager import TunnelManager, TunnelConfig

    cfg = TunnelConfig.from_yaml("config/testbed_conf.yml")
    mgr = TunnelManager(cfg)

    # Establish reverse tunnel so appliance can SCP files to VM
    mgr.start_reverse_tunnel()

    # Collect a file from the appliance
    mgr.pull_file_from_appliance("/usr/local/forescout/log/plugin/dot1x/radiusd.log",
                                  "/tmp/radiusd.log")
    mgr.stop()
"""
from __future__ import annotations

import logging
import os
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

try:
    import paramiko
except ImportError:
    paramiko = None  # type: ignore[assignment]

log = logging.getLogger("testpulse")


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
@dataclass
class TunnelConfig:
    """Connection parameters for all infrastructure nodes."""

    # Forescout appliance (CA / CounterACT)
    appliance_ip: str = "10.16.177.66"
    appliance_user: str = "root"
    appliance_pass: str = "aristo1"

    # Enterprise Manager
    em_ip: str = ""
    em_user: str = "root"
    em_pass: str = "aristo1"

    # Dev VM (local side of the tunnel)
    vm_user: str = "triley"
    vm_tunnel_port: int = 22022
    vm_ssh_key_on_appliance: str = "/root/.ssh/vm_from_appliance_ed25519"

    # Cisco switch
    switch_ip: str = "10.16.128.15"
    switch_user: str = "admin"
    switch_pass: str = "aristo"

    # Windows endpoint (WinRM)
    endpoint_ip: str = "10.16.148.129"
    endpoint_user: str = "Administrator"
    endpoint_pass: str = "aristo"
    endpoint_mac: str = "288023b82d59"

    # SSH host alias for the appliance in ~/.ssh/config
    appliance_ssh_alias: str = "appliance-66"

    @classmethod
    def from_yaml(cls, path: str) -> TunnelConfig:
        """Load tunnel config from a YAML file (radius.yml-compatible layout)."""
        try:
            import yaml
        except ImportError:
            raise ImportError("PyYAML required: pip install pyyaml")

        with open(path) as fh:
            data = yaml.safe_load(fh)

        cfg = cls()
        # Map fstester radius.yml keys
        if "ca" in data:
            ca = data["ca"]
            cfg.appliance_ip = ca.get("ip", cfg.appliance_ip)
            cfg.appliance_user = ca.get("user_name", cfg.appliance_user)
            cfg.appliance_pass = ca.get("password", cfg.appliance_pass)
        if "em" in data:
            em = data["em"]
            cfg.em_ip = em.get("ip", cfg.em_ip)
            cfg.em_user = em.get("user_name", cfg.em_user)
            cfg.em_pass = em.get("password", cfg.em_pass)
        if "switch" in data:
            sw = data["switch"]
            cfg.switch_ip = sw.get("ip", cfg.switch_ip)
            cfg.switch_user = sw.get("user_name", cfg.switch_user)
            cfg.switch_pass = sw.get("password", cfg.switch_pass)
        if "passthrough" in data:
            pt = data["passthrough"]
            cfg.endpoint_ip = pt.get("ip", cfg.endpoint_ip)
            cfg.endpoint_user = pt.get("user_name", cfg.endpoint_user)
            cfg.endpoint_pass = pt.get("password", cfg.endpoint_pass)
            cfg.endpoint_mac = pt.get("mac", cfg.endpoint_mac)
        if "tunnel" in data:
            t = data["tunnel"]
            cfg.vm_user = t.get("vm_user", cfg.vm_user)
            cfg.vm_tunnel_port = t.get("vm_tunnel_port", cfg.vm_tunnel_port)
            cfg.vm_ssh_key_on_appliance = t.get("vm_ssh_key", cfg.vm_ssh_key_on_appliance)
            cfg.appliance_ssh_alias = t.get("appliance_ssh_alias", cfg.appliance_ssh_alias)

        return cfg


class TunnelManager:
    """Manage SSH connections and reverse tunnels to lab infrastructure.

    Supports two connectivity modes:

    1. **Direct SSH** — paramiko connection from VM to appliance/EM
       (default, works when VM has direct IP reachability)
    2. **Reverse tunnel** — VM opens ``ssh -R`` to appliance so the
       appliance can SCP files *back* to the VM through ``127.0.0.1:22022``
    """

    def __init__(self, config: TunnelConfig | None = None):
        self.cfg = config or TunnelConfig()
        self._tunnel_proc: subprocess.Popen | None = None
        self._ssh_clients: dict[str, paramiko.SSHClient] = {}

    # ------------------------------------------------------------------
    # Reverse tunnel lifecycle
    # ------------------------------------------------------------------

    def start_reverse_tunnel(self, background: bool = True) -> None:
        """Open a reverse SSH tunnel from VM → appliance.

        Runs: ``ssh -f -N -R 127.0.0.1:<port>:localhost:22 <alias>``

        After this, the appliance can reach the VM at
        ``127.0.0.1:<port>`` using the ed25519 key.
        """
        if self._tunnel_proc is not None:
            log.info("Reverse tunnel already active, skipping")
            return

        cmd = [
            "ssh", "-f", "-N",
            "-R", f"127.0.0.1:{self.cfg.vm_tunnel_port}:localhost:22",
            "-o", "StrictHostKeyChecking=no",
            "-o", "ServerAliveInterval=30",
            "-o", "ServerAliveCountMax=3",
            self.cfg.appliance_ssh_alias,
        ]
        log.info(f"Starting reverse tunnel: {' '.join(cmd)}")

        if background:
            # ssh -f will fork to background itself
            subprocess.run(cmd, check=True, timeout=15)
            log.info(f"Reverse tunnel established (appliance → VM via 127.0.0.1:{self.cfg.vm_tunnel_port})")
        else:
            self._tunnel_proc = subprocess.Popen(cmd)
            time.sleep(2)
            if self._tunnel_proc.poll() is not None:
                raise RuntimeError("Reverse tunnel process exited immediately")
            log.info(f"Reverse tunnel process started (PID {self._tunnel_proc.pid})")

    def verify_reverse_tunnel(self) -> bool:
        """Check if the reverse tunnel listener is active on the appliance."""
        try:
            client = self._get_ssh_client("appliance")
            _, stdout, _ = client.exec_command(
                f"ss -lntp | grep {self.cfg.vm_tunnel_port}"
            )
            output = stdout.read().decode().strip()
            active = bool(output)
            log.info(f"Reverse tunnel verify: {'ACTIVE' if active else 'NOT FOUND'}")
            return active
        except Exception as e:
            log.warning(f"Could not verify tunnel: {e}")
            return False

    def stop(self) -> None:
        """Tear down tunnels and close SSH connections."""
        if self._tunnel_proc and self._tunnel_proc.poll() is None:
            self._tunnel_proc.terminate()
            self._tunnel_proc.wait(timeout=5)
            log.info("Reverse tunnel process terminated")
        self._tunnel_proc = None

        for name, client in self._ssh_clients.items():
            try:
                client.close()
                log.debug(f"Closed SSH connection to {name}")
            except Exception:
                pass
        self._ssh_clients.clear()

    # ------------------------------------------------------------------
    # Direct SSH helpers
    # ------------------------------------------------------------------

    def _get_ssh_client(self, target: str) -> paramiko.SSHClient:
        """Get or create an SSH client connection to a named target."""
        if paramiko is None:
            raise ImportError("paramiko required: pip install paramiko")

        if target in self._ssh_clients:
            # Check if still alive
            transport = self._ssh_clients[target].get_transport()
            if transport and transport.is_active():
                return self._ssh_clients[target]
            else:
                try:
                    self._ssh_clients[target].close()
                except Exception:
                    pass

        if target == "appliance":
            ip, user, pw = self.cfg.appliance_ip, self.cfg.appliance_user, self.cfg.appliance_pass
        elif target == "em":
            ip, user, pw = self.cfg.em_ip, self.cfg.em_user, self.cfg.em_pass
        elif target == "switch":
            ip, user, pw = self.cfg.switch_ip, self.cfg.switch_user, self.cfg.switch_pass
        else:
            raise ValueError(f"Unknown target: {target}")

        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(ip, username=user, password=pw, timeout=15)
        self._ssh_clients[target] = client
        log.info(f"SSH connection established to {target} ({ip})")
        return client

    def exec_on(self, target: str, command: str, timeout: int = 30) -> str:
        """Execute a command on a remote target and return stdout."""
        client = self._get_ssh_client(target)
        _, stdout, stderr = client.exec_command(command, timeout=timeout)
        out = stdout.read().decode("utf-8", errors="replace").strip()
        err = stderr.read().decode("utf-8", errors="replace").strip()
        if err:
            log.debug(f"[{target}] stderr: {err[:200]}")
        return out

    # ------------------------------------------------------------------
    # File transfer helpers
    # ------------------------------------------------------------------

    def pull_file_from_appliance(
        self, remote_path: str, local_path: str, via_tunnel: bool = False,
    ) -> str:
        """Download a file from the appliance to the VM.

        Args:
            remote_path: Absolute path on the appliance (e.g.
                ``/usr/local/forescout/log/plugin/dot1x/radiusd.log``).
            local_path: Destination on the VM.
            via_tunnel: If True, use reverse tunnel SCP from the
                appliance side.  If False (default), use direct
                paramiko SFTP from the VM.

        Returns:
            The local path written to.
        """
        os.makedirs(os.path.dirname(local_path) or ".", exist_ok=True)

        if via_tunnel:
            return self._pull_via_tunnel(remote_path, local_path)
        else:
            return self._pull_direct(remote_path, local_path)

    def _pull_direct(self, remote_path: str, local_path: str) -> str:
        """SFTP download from appliance (VM → appliance)."""
        client = self._get_ssh_client("appliance")
        sftp = client.open_sftp()
        try:
            log.info(f"SFTP download: {remote_path} → {local_path}")
            sftp.get(remote_path, local_path)
            size = os.path.getsize(local_path)
            log.info(f"Downloaded {size:,} bytes")
        finally:
            sftp.close()
        return local_path

    def _pull_via_tunnel(self, remote_path: str, local_path: str) -> str:
        """Use reverse tunnel: ask appliance to SCP file to VM."""
        scp_cmd = (
            f"scp -i {self.cfg.vm_ssh_key_on_appliance} "
            f"-P {self.cfg.vm_tunnel_port} "
            f"-o StrictHostKeyChecking=no "
            f"{remote_path} "
            f"{self.cfg.vm_user}@127.0.0.1:{local_path}"
        )
        log.info(f"Tunnel SCP: {scp_cmd}")
        result = self.exec_on("appliance", scp_cmd, timeout=60)
        log.info(f"Tunnel SCP result: {result or '(ok)'}")
        return local_path

    def push_file_to_appliance(self, local_path: str, remote_path: str) -> str:
        """Upload a file from the VM to the appliance via SFTP."""
        client = self._get_ssh_client("appliance")
        sftp = client.open_sftp()
        try:
            log.info(f"SFTP upload: {local_path} → {remote_path}")
            sftp.put(local_path, remote_path)
        finally:
            sftp.close()
        return remote_path

    def tail_remote_log(
        self, remote_path: str, lines: int = 500, target: str = "appliance",
    ) -> str:
        """Grab the last N lines of a remote log file."""
        return self.exec_on(target, f"tail -n {lines} {remote_path}")

    def stream_redis_monitor(
        self, duration: int = 10, target: str = "appliance",
    ) -> str:
        """Capture Redis MONITOR output for a fixed duration.

        Runs ``timeout <dur> redis-cli monitor`` on the appliance.
        Returns the raw monitor output.
        """
        cmd = f"timeout {duration} redis-cli monitor 2>/dev/null || true"
        return self.exec_on(target, cmd, timeout=duration + 10)
