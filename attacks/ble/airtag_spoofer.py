"""
BLE — AirTag Spoofer
════════════════════
Flashes the `airtag_spoofer` firmware and broadcasts fake Apple
AirTag / FindMy advertisements from the CatSniffer CC1352 radio.

How it works
────────────
The CC1352 firmware transmits two concurrent BLE advertising sets:
  1. Legacy (BLE 4.x compatible) — Apple FindMy payload
  2. Long Range (BLE 5 Coded PHY) — extended range

The FindMy payload is formatted as an Apple Manufacturer Specific
Data AD record (company ID 0x004C), subtype 0x12 with status byte
0x10 ("separated from owner"). This triggers iOS/macOS notifications
about an unknown tracker moving with the user.

Advertising parameters (from firmware source):
  • Interval : 0x80–0x100 units × 0.625 ms = 80–160 ms
  • TX Power  : 0 dBm
  • Channels  : 37, 38, 39 (all primary channels)
  • Addr mode : CC1352 default (random)

Why might nearby Apple devices NOT react immediately?
  • iOS 16.2+ suppresses the "AirTag detected" banner until the
    device has been moving with you for several hours.
  • macOS shows alerts faster. Open "Find My" → Items tab.
  • Use nRF Connect (Android/iOS) to verify the BLE packet is on air:
    filter by "Name starts with / Manufacturer: Apple".
  • The raw payload should show:  FF 4C 00 12 19 ...

The firmware does NOT output anything over serial — the CC1352 radio
is a pure BLE transmitter. This attack simply keeps the board running
until the user presses Ctrl-C.

Useful for
──────────
  • Testing Apple FindMy detection tools / privacy scanners
  • Research into the Find My network protocol
  • Demonstrating BLE spoofing to an audience
"""
from __future__ import annotations

import time

from rich.console import Console
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from attacks.base import BaseAttack, AttackOption
from attacks.registry import AttackRegistry
from core import ui as UI
from core.firmware import flash_firmware

console = Console()

# ── FindMy payload (hardcoded in firmware source: airtag_spoofer.c) ─────────
_ADV_PAYLOAD_HEX = (
    "1E FF 4C 00 12 19 "
    "10 62 99 96 85 AB 4C 0A B4 A1 "
    "D6 A4 13 A1 9B 30 84 4D "
    "60 70 59 CF A2 01 45"
)
# Decoded fields:
#   0x1E       = AD record length (30 bytes)
#   0xFF       = AD type: Manufacturer Specific Data
#   0x4C 0x00  = Apple Inc. company ID (little-endian)
#   0x12       = FindMy subtype: "Offline" / AirTag
#   0x19       = FindMy payload length (25 bytes)
#   0x10       = Status byte: "Separated from owner" (triggers iOS alerts)
#   [22 bytes] = Partial public key used for location encryption
#   0x01       = Hint byte (last byte of public key)
#   0x45       = Reserved


@AttackRegistry.register
class AirTagSpoofer(BaseAttack):
    # ── Metadata ──────────────────────────────────────────────────────────────
    name = "airtag_spoofer"
    description = "Broadcast fake Apple AirTag / FindMy BLE advertisements"
    firmware_alias = "airtag-spoofer"
    category = "BLE"

    options = [
        AttackOption(
            name="flash",
            description="Flash firmware before running? (yes/no)",
            default="yes",
            type=str,
            choices=["yes", "no"],
        ),
    ]

    # ── Run ────────────────────────────────────────────────────────────────────

    def run(self, device) -> None:
        """Flash firmware (optional) and show live status panel."""
        if self.get_option("flash") == "yes":
            UI.info(f"Flashing [bold]{self.firmware_alias}[/bold] onto {device}…")
            if not flash_firmware(self.firmware_alias, device.device_id):
                UI.error(
                    "Firmware flash failed.\n"
                    "  • Make sure [bold]catnip[/bold] is installed and on PATH.\n"
                    "  • Alternatively set the [bold]flash[/bold] option to "
                    "[bold]no[/bold] if the firmware is already loaded."
                )
                return
            UI.success("Firmware flashed successfully.")
            time.sleep(1)

        self._show_status(device)

    # ── Private helpers ────────────────────────────────────────────────────────

    def _show_status(self, device) -> None:
        """Display a live status panel while the firmware runs."""
        start = time.time()

        def _panel(elapsed: float) -> Panel:
            mins, secs = divmod(int(elapsed), 60)

            # ── Radio parameters ──
            radio = Table(box=None, show_header=False, padding=(0, 2))
            radio.add_column(style="dim cyan", no_wrap=True)
            radio.add_column(style="white")
            radio.add_row("Device port", str(device.bridge_port))
            radio.add_row("Firmware", self.firmware_alias)
            radio.add_row("Uptime", f"[bold green]{mins:02d}:{secs:02d}[/bold green]")
            radio.add_row("TX Power", "0 dBm")
            radio.add_row("Adv interval", "80 – 160 ms  (0x80–0x100 × 0.625 ms)")
            radio.add_row("Adv channels", "37 / 38 / 39  (all)")
            radio.add_row("Adv sets", "Legacy (BLE 4)  +  Long Range (BLE 5 Coded PHY)")
            radio.add_row("MAC type", "CC1352 default random address")

            # ── Payload breakdown ──
            payload = Table(box=None, show_header=False, padding=(0, 2))
            payload.add_column(style="dim cyan", no_wrap=True)
            payload.add_column(style="white")
            payload.add_row("Company ID", "0x004C  →  [bold]Apple Inc.[/bold]")
            payload.add_row("FindMy subtype", "0x12  →  Offline / AirTag")
            payload.add_row("Status byte", "0x10  →  [yellow]Separated from owner[/yellow]  ⚠ triggers iOS alert")
            payload.add_row("Public key", "22-byte partial key (hardcoded in firmware)")
            payload.add_row("Raw payload", Text(_ADV_PAYLOAD_HEX, style="dim white"))

            # ── Detection tips ──
            tips = Table(box=None, show_header=False, padding=(0, 1))
            tips.add_column(style="dim yellow", no_wrap=True)
            tips.add_column(style="dim white")
            tips.add_row("iOS 16.2+", "Alert only after hours of movement with device")
            tips.add_row("macOS", "Open Find My → Items tab to see faster")
            tips.add_row("Verify OTA", "Use nRF Connect · filter Manufacturer = Apple")
            tips.add_row("Serial", "No output expected — radio transmits silently")

            from rich.columns import Columns
            from rich import box as rbox
            from rich.rule import Rule

            body = Table(box=None, show_header=False, padding=(0, 0))
            body.add_column()
            body.add_row("[bold]Radio config[/bold]")
            body.add_row(radio)
            body.add_row(Rule(style="dim"))
            body.add_row("[bold]BLE FindMy payload[/bold]")
            body.add_row(payload)
            body.add_row(Rule(style="dim"))
            body.add_row("[bold]Detection notes[/bold]")
            body.add_row(tips)

            return Panel(
                body,
                title="[bold green]● AirTag Spoofer — BROADCASTING[/bold green]",
                subtitle="[dim]Ctrl-C to stop[/dim]",
                border_style="green",
                padding=(1, 2),
            )

        try:
            with Live(_panel(0), console=console, refresh_per_second=1) as live:
                while True:
                    time.sleep(1)
                    live.update(_panel(time.time() - start))
        except KeyboardInterrupt:
            pass

        UI.info("AirTag Spoofer stopped.")
