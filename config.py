"""
CatSniffer Toolkit — Global Configuration
"""
import os
from pathlib import Path

# ─── Toolkit info ────────────────────────────────────────────────────────────
TOOLKIT_NAME = "CatSniffer Toolkit"
TOOLKIT_VERSION = "0.1.0"
TOOLKIT_AUTHOR = "Your Lab"

# ─── Paths ───────────────────────────────────────────────────────────────────
BASE_DIR = Path(__file__).parent

# Path to catnip CLI. Override with CATNIP_PATH env var, or it will be
# auto-discovered later in core/firmware.py
CATNIP_PATH = os.environ.get("CATNIP_PATH", "catnip")

# ─── USB identifiers (Raspberry Pi RP2040 — used by CatSniffer v3) ───────────
CATSNIFFER_VID = 0x2E8A
CATSNIFFER_PID = 0x00C0

# ─── Serial defaults ─────────────────────────────────────────────────────────
# Most CC1352 firmwares (scanner, spoofer, justworks) output at 9600 baud
DEFAULT_BAUD = 9600
# Shell / config port baud
SHELL_BAUD = 115_200
# Bootloader / flash baud
BRIDGE_BAUD = 500_000
