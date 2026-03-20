"""
CatSniffer device detection and management.

Each CatSniffer v3 exposes 3 serial ports (RP2040 VID 0x2E8A):
  Port 0 — Cat-Bridge (CC1352) : firmware flashing + protocol data
  Port 1 — Cat-LoRa  (SX1262) : LoRa radio data
  Port 2 — Cat-Shell (Config)  : interactive shell / bootloader trigger
"""
from __future__ import annotations

import platform
import subprocess
from dataclasses import dataclass
from typing import List, Optional

import serial.tools.list_ports

from config import CATSNIFFER_VID, CATSNIFFER_BOOT_VID, CATSNIFFER_BOOT_PID


@dataclass
class CatSnifferDevice:
    device_id: int
    bridge_port: Optional[str] = None
    lora_port: Optional[str] = None
    shell_port: Optional[str] = None

    # ── helpers ──────────────────────────────────────────────────────────────

    def is_valid(self) -> bool:
        """True if at least the bridge port was detected."""
        return bool(self.bridge_port)

    def __str__(self) -> str:
        return f"CatSniffer #{self.device_id}"

    def summary(self) -> str:
        b = self.bridge_port or "—"
        l = self.lora_port or "—"
        s = self.shell_port or "—"
        return f"Bridge:{b}  LoRa:{l}  Shell:{s}"


# ── Public API ────────────────────────────────────────────────────────────────


def detect_devices() -> List[CatSnifferDevice]:
    """Return all connected CatSniffer devices grouped into sets of 3 ports."""
    all_ports = list(serial.tools.list_ports.comports())

    cat_ports = sorted(
        [p for p in all_ports if p.vid == CATSNIFFER_VID],
        key=lambda p: p.device,
    )

    devices: List[CatSnifferDevice] = []
    for i in range(0, len(cat_ports), 3):
        group = cat_ports[i : i + 3]
        dev = CatSnifferDevice(
            device_id=len(devices) + 1,
            bridge_port=group[0].device if len(group) > 0 else None,
            lora_port=group[1].device if len(group) > 1 else None,
            shell_port=group[2].device if len(group) > 2 else None,
        )
        devices.append(dev)

    return devices


def get_device(device_id: Optional[int] = None) -> Optional[CatSnifferDevice]:
    """Return a specific device by ID, or the first detected one."""
    devices = detect_devices()
    if not devices:
        return None
    if device_id is None:
        return devices[0]
    for dev in devices:
        if dev.device_id == device_id:
            return dev
    return None


def is_in_bootloader_mode() -> bool:
    """
    Return True if a CatSniffer RP2040 is detected in USB bootloader /
    UF2 mass-storage mode (VID=0x2E8A, PID=0x0003 — "RP2 Boot").
    """
    vid_dec = int(CATSNIFFER_BOOT_VID)   # 11914  (0x2E8A)
    pid_dec = int(CATSNIFFER_BOOT_PID)   # 3      (0x0003)
    try:
        if platform.system() == "Darwin":
            out = subprocess.run(
                ["ioreg", "-p", "IOUSB", "-l", "-w", "0"],
                capture_output=True, text=True, timeout=5,
            ).stdout
            return (
                f'"idVendor" = {vid_dec}' in out
                and f'"idProduct" = {pid_dec}' in out
            )
        elif platform.system() == "Linux":
            out = subprocess.run(
                ["lsusb"], capture_output=True, text=True, timeout=5,
            ).stdout
            return "2e8a:0003" in out.lower()
    except Exception:
        pass
    return False
