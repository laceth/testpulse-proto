"""Endpoint artifact collector for TestPulse.

Collects diagnostic evidence from a remote Windows endpoint over WinRM,
saves artifacts into the run folder for end-to-end analysis.

The collector gathers:
  - Wired-AutoConfig Operational log (EVTX)
  - EapHost Operational log (EVTX)
  - System log (EVTX, optional)
  - ``netsh lan`` profile dumps
  - ``ipconfig /all``
  - Certificate store dumps (optional)
  - EAPOL PCAP capture (optional, requires tshark)

Quick start::

    from testpulse.collect import EndpointArtifactCollector

    collector = EndpointArtifactCollector(
        ip="10.16.133.143",
        username="Administrator",
        password="aristo",
    )
    zip_path = collector.collect(run_id="latest", run_dir="/path/to/artifacts/latest")
    collector.cleanup_remote("latest")
"""

import logging
import os
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

try:
    import winrm
except ImportError:
    winrm = None  # type: ignore[assignment]

log = logging.getLogger("testpulse")


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
@dataclass
class ArtifactCollectorConfig:
    """Parameters forwarded to collect_endpoint_artifacts.ps1."""

    out_root: str = r"C:\TestPulse\runs"
    lan_profile_name: str = ""
    include_system_log: bool = False
    include_certs: bool = False
    capture_eapol: bool = False
    capture_seconds: int = 90
    capture_interface: str = ""


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
_REMOTE_SCRIPT_DIR = r"C:\TestPulse\scripts"
_REMOTE_SCRIPT_NAME = "collect_endpoint_artifacts.ps1"
# Resolve the local PS1 relative to this file's parent (project root)
_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
_LOCAL_SCRIPT_PATH = os.path.join(_PROJECT_ROOT, "scripts", _REMOTE_SCRIPT_NAME)


class EndpointArtifactCollector:
    """Collect diagnostic artifacts from a remote Windows endpoint.

    Args:
        ip:       Windows endpoint IP address.
        username: WinRM username (e.g. ``Administrator``).
        password: WinRM password.
        config:   Optional ``ArtifactCollectorConfig`` overrides.
    """

    def __init__(
        self,
        ip: str,
        username: str,
        password: str,
        config: Optional[ArtifactCollectorConfig] = None,
    ):
        if winrm is None:
            raise ImportError(
                "pywinrm is required for endpoint collection. "
                "Install with: pip install pywinrm pypsrp"
            )
        self.ip = ip
        self.username = username
        self.password = password
        self.cfg = config or ArtifactCollectorConfig()
        self._session = winrm.Session(
            self.ip,
            auth=(self.username, self.password),
            transport="ntlm",
        )

    # ------------------------------------------------------------------
    # Remote command execution
    # ------------------------------------------------------------------

    def execute_command(self, command: str, is_ps: bool = True) -> str:
        """Execute a command on the remote Windows endpoint via WinRM."""
        log.info(f"Remote exec: {command[:120]}{'…' if len(command) > 120 else ''}")

        if is_ps:
            command = f"$ProgressPreference = 'SilentlyContinue'; {command}"

        out = self._session.run_ps(command) if is_ps else self._session.run_cmd(command)

        stdout = out.std_out.decode("utf-8", errors="replace").strip()
        stderr = out.std_err.decode("utf-8", errors="replace").strip()

        # Filter CLIXML noise from stderr
        if stderr and ("#< CLIXML" in stderr or "Preparing modules" in stderr):
            stderr_lines = stderr.split("\n")
            stderr = "\n".join(
                line
                for line in stderr_lines
                if not line.strip().startswith("<")
                and "#< CLIXML" not in line
                and "Preparing modules" not in line
            ).strip()

        if out.status_code != 0:
            parts = [f"Command failed (code={out.status_code})"]
            if stdout:
                parts.append(f"STDOUT:\n{stdout}")
            if stderr:
                parts.append(f"STDERR:\n{stderr}")
            cmd_display = command if len(command) < 200 else command[:200] + "..."
            parts.append(f"COMMAND:\n{cmd_display}")
            raise RuntimeError("\n".join(parts))

        return stdout

    # ------------------------------------------------------------------
    # File operations
    # ------------------------------------------------------------------

    def _check_remote_exists(self, path: str) -> bool:
        try:
            return self.execute_command(f"Test-Path '{path}'").strip().lower() == "true"
        except RuntimeError:
            return False

    def _create_remote_dir(self, path: str):
        self.execute_command(f"New-Item -Path '{path}' -ItemType Directory -Force | Out-Null")
        log.debug(f"Created remote directory: {path}")

    def _upload_file(self, local_path: str, remote_path: str):
        """Copy a local file to the endpoint using pypsrp."""
        from pypsrp.client import Client

        if not os.path.isfile(local_path):
            raise FileNotFoundError(f"Local file not found: {local_path}")

        remote_dir = remote_path.rsplit("\\", 1)[0]
        self._create_remote_dir(remote_dir)

        log.info(f"Uploading {local_path} → {remote_path} ({os.path.getsize(local_path)} bytes)")
        client = Client(
            self.ip,
            username=self.username,
            password=self.password,
            ssl=False,
            auth="ntlm",
        )
        client.copy(local_path, remote_path)
        log.info("[OK] Uploaded")

    def _download_file(self, remote_path: str, local_path: str):
        """Pull a file from the endpoint to the local machine via pypsrp."""
        from pypsrp.client import Client

        log.info(f"Downloading {remote_path} → {local_path}")
        client = Client(
            self.ip,
            username=self.username,
            password=self.password,
            ssl=False,
            auth="ntlm",
        )
        client.fetch(remote_path, local_path)
        size = os.path.getsize(local_path)
        log.info(f"[OK] Downloaded {size:,} bytes")

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def collect(self, run_id: str, run_dir: str = "") -> str:
        """Run the collector on the endpoint and pull the ZIP into the run folder.

        The ZIP is extracted into ``<run_dir>/endpoint/`` so that the
        endpoint parser can read the text artifacts during analysis.

        Args:
            run_id:  Unique run identifier (e.g. ``"latest"``).
            run_dir: Local run folder (e.g. ``artifacts/latest``).
                     Defaults to ``<cwd>/artifacts/<run_id>/``.

        Returns:
            Absolute path to the ``endpoint/`` subdirectory.
        """
        log.info(f"=== Collecting endpoint artifacts for RunId={run_id} ===")

        # 1. Upload the PS1 if needed
        self._ensure_script_uploaded()

        # 2. Run the collector on the endpoint
        remote_zip = self._run_collector(run_id)

        # 3. Download the ZIP into the run folder
        if not run_dir:
            run_dir = os.path.join(os.getcwd(), "artifacts", run_id)
        os.makedirs(run_dir, exist_ok=True)

        local_zip = os.path.join(run_dir, f"endpoint_windows_{run_id}.zip")
        self._download_file(remote_zip, local_zip)

        # 4. Extract into <run_dir>/endpoint/ for end-to-end analysis
        endpoint_dir = os.path.join(run_dir, "endpoint")
        os.makedirs(endpoint_dir, exist_ok=True)
        with zipfile.ZipFile(local_zip, "r") as zf:
            zf.extractall(endpoint_dir)
        log.info(f"[OK] Extracted endpoint artifacts to: {endpoint_dir}")

        # List what we got
        extracted = sorted(
            str(p.relative_to(endpoint_dir))
            for p in Path(endpoint_dir).rglob("*")
            if p.is_file()
        )
        for f in extracted:
            log.info(f"  -> {f}")

        return endpoint_dir

    def cleanup_remote(self, run_id: str):
        """Remove the remote run directory (best-effort)."""
        run_dir = f"{self.cfg.out_root}\\{run_id}"
        cmd = (
            f"if (Test-Path '{run_dir}') {{ "
            f"Remove-Item -Path '{run_dir}' -Recurse -Force "
            f"}}"
        )
        try:
            self.execute_command(cmd)
            log.info(f"Cleaned up remote directory: {run_dir}")
        except RuntimeError as e:
            log.warning(f"Remote cleanup failed (non-fatal): {e}")

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _ensure_script_uploaded(self):
        """Upload the PS1 collector if it doesn't already exist on the endpoint."""
        remote_path = f"{_REMOTE_SCRIPT_DIR}\\{_REMOTE_SCRIPT_NAME}"

        if not os.path.isfile(_LOCAL_SCRIPT_PATH):
            raise FileNotFoundError(f"Collector script not found: {_LOCAL_SCRIPT_PATH}")

        if self._check_remote_exists(remote_path):
            log.debug(f"Collector script already on endpoint: {remote_path}")
            return

        self._upload_file(_LOCAL_SCRIPT_PATH, remote_path)

    def _run_collector(self, run_id: str) -> str:
        """Invoke the collector and return the remote ZIP path."""
        remote_script = f"{_REMOTE_SCRIPT_DIR}\\{_REMOTE_SCRIPT_NAME}"

        parts = [
            f"& '{remote_script}'",
            f"-RunId '{run_id}'",
            f"-OutRoot '{self.cfg.out_root}'",
        ]
        if self.cfg.lan_profile_name:
            parts.append(f"-LanProfileName '{self.cfg.lan_profile_name}'")
        if self.cfg.include_system_log:
            parts.append("-IncludeSystemLog")
        if self.cfg.include_certs:
            parts.append("-IncludeCerts")
        if self.cfg.capture_eapol:
            parts.append("-CaptureEapol")
            parts.append(f"-CaptureSeconds {self.cfg.capture_seconds}")
            if self.cfg.capture_interface:
                parts.append(f"-CaptureInterface '{self.cfg.capture_interface}'")

        cmd = " ".join(parts)
        log.info(f"Running collector: {cmd}")
        self.execute_command(cmd)

        remote_zip = f"{self.cfg.out_root}\\{run_id}\\endpoint_windows_{run_id}.zip"
        if not self._check_remote_exists(remote_zip):
            raise RuntimeError(f"Collector ZIP not found on endpoint: {remote_zip}")

        log.info(f"Collector ZIP created: {remote_zip}")
        return remote_zip
