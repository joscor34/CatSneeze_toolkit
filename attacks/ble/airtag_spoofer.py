"""
BLE — AirTag Spoofer
════════════════════
Flashes the `airtag_spoofer` firmware and broadcasts fake Apple
AirTag / FindMy advertisements from the CatSniffer CC1352 radio.

How it works
────────────
The CC1352 firmware continuously transmits BLE advertising packets
formatted as Apple FindMy "offline" device advertisements. Nearby
Apple devices see these as a real AirTag and can report their location
back to Apple's Find My network.

Useful for
──────────
  • Testing Apple FindMy detection tools / privacy scanners
  • Research into the Find My network protocol
  • Demonstrating BLE spoofing to an audience

Serial output
─────────────
The firmware prints status lines at 9600 baud on the bridge port.
Lines arriving over serial are shown in real-time on screen.
"""
from __future__ import annotations

import threading
import time
from pathlib import Path

import serial
from rich.console import Console
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich import box

from attacks.base import BaseAttack, AttackOption
from attacks.registry import AttackRegistry
from core import ui as UI
from core.firmware import flash_firmware

console = Console()


@AttackRegistry.register
class AirTagSpoofer(BaseAttack):
    # ── Metadata ──────────────────────────────────────────────────────────────
    name = "airtag_spoofer"
    description = "Broadcast fake Apple AirTag / FindMy BLE advertisements"
    firmware_alias = "airtag-spoofer"   # maps to airtag_spoofer_CC1352P_7_v1.0.hex
    category = "BLE"

    options = [
        AttackOption(
            name="baud",
            description="Bridge port baud rate (9600 for most CC1352 firmwares)",
            default=9600,
            type=int,
        ),
        AttackOption(
            name="log_file",
            description="Path to save serial output (leave empty to skip)",
            default="",
            type=str,
        ),
        AttackOption(
            name="flash",
            description="Flash firmware before running? (yes/no)",
            default="yes",
            type=str,
            choices=["yes", "no"],
        ),
    ]

    # ── Internal state ─────────────────────────────────────────────────────────

    def __init__(self) -> None:
        super().__init__()
        self._lines: list[str] = []
        self._lock = threading.Lock()

    # ── Run ────────────────────────────────────────────────────────────────────

    def run(self, device) -> None:  # noqa: C901
        """Flash firmware (optional) and stream serial output."""
        # ── 1. Optionally flash ───────────────────────────────────────────────
        if self.get_option("flash") == "yes":
            UI.info(f"Flashing [bold]{self.firmware_alias}[/bold] onto {device}…")
            if not flash_firmware(self.firmware_alias, device.device_id):
                UI.error(
                    "Firmware flash failed.\n"
                    "  • Make sure [bold]catnip[/bold] is installed and on PATH, or set "
                    "the CATNIP_PATH environment variable.\n"
                    "  • Alternatively set the [bold]flash[/bold] option to [bold]no[/bold] "
                    "if the firmware is already loaded."
                )
                return
            UI.success("Firmware flashed successfully.")
            time.sleep(1)  # let the device re-enumerate

        # ── 2. Open serial port ───────────────────────────────────────────────
        port = device.bridge_port
        baud = self.get_option("baud")

        if not port:
            UI.error("Bridge port not found for this device!")
            return

        log_path = self.get_option("log_file") or None
        log_fh = open(log_path, "a", encoding="utf-8") if log_path else None

        UI.info(f"Opening serial connection  →  [bold]{port}[/bold]  @  {baud} baud")

        self._running = True
        self._lines.clear()

        # ── 3. Stream output ──────────────────────────────────────────────────
        try:
            with serial.Serial(port, baud, timeout=0.5) as ser:
                self._stream(ser, log_fh)
        except serial.SerialException as exc:
            UI.error(f"Serial error: {exc}")
        except KeyboardInterrupt:
            pass
        finally:
            self._running = False
            if log_fh:
                log_fh.close()
            UI.info("AirTag Spoofer stopped.")

    # ── Private helpers ────────────────────────────────────────────────────────

    def _stream(self, ser: serial.Serial, log_fh) -> None:
        """Display a live panel and read serial lines until stopped."""
        header = (
            "[bold green]● AirTag Spoofer — ACTIVE[/]\n\n"
            f"  Device port : [cyan]{ser.port}[/cyan]\n"
            f"  Baud rate   : [cyan]{ser.baudrate}[/cyan]\n"
            f"  Firmware    : [cyan]{self.firmware_alias}[/cyan]\n\n"
            "  The CC1352 is now broadcasting fake Apple FindMy\n"
            "  advertisements. Nearby Apple devices will see this\n"
            "  as an AirTag and relay its location.\n\n"
            "  [dim]Press  Ctrl-C  to stop.[/dim]"
        )

        console.print(
            Panel(header, title="[bold]CatSniffer Toolkit[/bold]", border_style="green")
        )
        console.print()

        # Live table of received serial lines
        with Live(self._build_table(), console=console, refresh_per_second=4) as live:
            while self._running:
                try:
                    raw = ser.readline()
                    if raw:
                        line = raw.decode("utf-8", errors="replace").rstrip()
                        if line:
                            with self._lock:
                                self._lines.append(line)
                                # Keep only last 30 lines
                                if len(self._lines) > 30:
                                    self._lines.pop(0)
                            if log_fh:
                                log_fh.write(line + "\n")
                                log_fh.flush()
                            live.update(self._build_table())
                except serial.SerialException:
                    break

    def _build_table(self) -> Table:
        t = Table(
            title="Serial Output",
            box=box.SIMPLE_HEAVY,
            show_lines=False,
            expand=True,
        )
        t.add_column("Line", style="dim cyan")
        with self._lock:
            for line in self._lines[-20:]:
                t.add_row(line)
        return t
