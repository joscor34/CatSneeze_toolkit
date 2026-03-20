"""
Firmware management — delegates to the `catnip` CLI.

Discovery order for the catnip entry-point:
  1. CATNIP_PATH env var (absolute path to catnip.py or installed binary)
  2. `catnip`  installed globally via pip
  3. Common repo locations relative to this toolkit
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path
from typing import Optional

from config import CATNIP_PATH

# Typical clone locations users might have
_CANDIDATE_SCRIPTS = [
    Path.home() / "CatSniffer-Tools" / "catnip" / "catnip.py",
    Path("/opt/CatSniffer-Tools/catnip/catnip.py"),
    Path.cwd() / "CatSniffer-Tools" / "catnip" / "catnip.py",
]


def _find_catnip() -> list[str]:
    """Return the command prefix to invoke catnip (e.g. ['catnip'] or ['python', 'catnip.py'])."""
    # Try the configured / env binary first
    try:
        subprocess.run(
            [CATNIP_PATH, "--help"],
            capture_output=True,
            timeout=5,
        )
        return [CATNIP_PATH]
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass

    # Fallback: look for catnip.py script
    for candidate in _CANDIDATE_SCRIPTS:
        if candidate.exists():
            return [sys.executable, str(candidate)]

    return []


def flash_firmware(alias: str, device_id: Optional[int] = None) -> bool:
    """
    Flash *alias* firmware onto the CatSniffer.

    Returns True on success, False otherwise.
    """
    cmd_prefix = _find_catnip()
    if not cmd_prefix:
        return False

    cmd = cmd_prefix + ["flash", alias]
    if device_id is not None:
        cmd += ["--device", str(device_id)]

    result = subprocess.run(cmd, timeout=180)
    return result.returncode == 0


def list_firmware() -> bool:
    """Print available firmware (delegates to catnip flash --list)."""
    cmd_prefix = _find_catnip()
    if not cmd_prefix:
        return False
    subprocess.run(cmd_prefix + ["flash", "--list"])
    return True


def catnip_available() -> bool:
    """Return True if the catnip CLI can be found."""
    return bool(_find_catnip())
