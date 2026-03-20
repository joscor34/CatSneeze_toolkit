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

# ─── USB identifiers ─────────────────────────────────────────────────────────
# Firmware mode (bridge running) — Electronic Cats / pid.codes VID
CATSNIFFER_VID = 0x1209
CATSNIFFER_PID = 0xBABB

# RP2040 bootloader / UF2 mass-storage mode ("RP2 Boot")
CATSNIFFER_BOOT_VID = 0x2E8A
CATSNIFFER_BOOT_PID = 0x0003

# ─── Serial defaults ─────────────────────────────────────────────────────────
# Most CC1352 firmwares (scanner, spoofer, justworks) output at 9600 baud
DEFAULT_BAUD = 9600
# Shell / config port baud
SHELL_BAUD = 115_200
# Bootloader / flash baud
BRIDGE_BAUD = 500_000
