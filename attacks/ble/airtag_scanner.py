"""
BLE — AirTag Scanner
════════════════════
Flashes the `airtag_scanner` firmware and passively listens for Apple AirTag /
FindMy BLE advertisements near you.

How it works
────────────
The CC1352 firmware acts as a BLE Central scanner. It scans all three primary
channels (37/38/39) continuously and filters packets by Apple's Manufacturer
Specific Data signature (0x4C 0x00). When a matching packet is found, it prints
the tracker MAC and status over UART.

Detection logic (from firmware source `airtag_scanner.c`):
  • pData[0] == 0x1E      → AD length = 30
  • pData[2..3] == 4C 00  → Apple Inc. company ID
  • pData[4] == 0x12 AND pData[6] == 0x10  → "Registered and active"
  • pData[4] == 0x07 AND pData[6] == 0x05  → "Unregistered" (unclaimed AirTag)

Serial output format (UART via RP2040 bridge):
  Airtag detected! -> AA:BB:CC:DD:EE:FF Status: Registered and active
  Airtag detected! -> AA:BB:CC:DD:EE:FF Status: Unregistered

Use cases
─────────
  • Counter-surveillance / anti-tracking audit
  • See who might be tracking you in your environment
  • Research into Apple's FindMy network presence
"""
from __future__ import annotations

import re
import threading
import time
from collections import OrderedDict
from datetime import datetime

import serial
from rich.console import Console
from rich.live import Live
from rich.panel import Panel
from rich.rule import Rule
from rich.table import Table
from rich.text import Text

from attacks.base import BaseAttack, AttackOption
from attacks.registry import AttackRegistry
from core import ui as UI
from core.firmware import flash_firmware

console = Console()

# ── Serial parsing ─────────────────────────────────────────────────────────────
_AIRTAG_RE = re.compile(
    r"Airtag detected! -> (\S+)\s+Status:\s+(.+)", re.IGNORECASE
)

# Status → (color, emoji)
_STATUS_STYLE = {
    "registered and active": ("green", "●"),
    "unregistered": ("yellow", "○"),
}


def _parse_line(line: str) -> tuple[str, str] | None:
    """Parse a firmware UART line. Returns (mac, status) or None."""
    m = _AIRTAG_RE.search(line)
    if m:
        return m.group(1).strip(), m.group(2).strip()
    return None


# ── Attack ─────────────────────────────────────────────────────────────────────


@AttackRegistry.register
class AirTagScanner(BaseAttack):
    # ── Metadata ──────────────────────────────────────────────────────────────
    name = "airtag_scanner"
    description = "Detect Apple AirTag / FindMy trackers broadcasting nearby"
    firmware_alias = "airtag-scanner"
    category = "BLE"

    options = [
        AttackOption(
            name="flash",
            description="Flash firmware before running? (yes/no)",
            default="yes",
            type=str,
            choices=["yes", "no"],
        ),
        AttackOption(
            name="baud",
            description="Serial baud rate for UART output",
            default="115200",
            type=str,
            choices=["9600", "115200", "500000"],
        ),
    ]

    # ── Run ────────────────────────────────────────────────────────────────────

    def run(self, device) -> None:
        if self.get_option("flash") == "yes":
            UI.info(f"Flashing [bold]{self.firmware_alias}[/bold] onto {device}…")
            if not flash_firmware(self.firmware_alias, device.device_id):
                UI.error(
                    "Firmware flash failed.\n"
                    "  • Make sure [bold]catnip[/bold] is installed and on PATH.\n"
                    "  • Set [bold]flash=no[/bold] if firmware is already loaded."
                )
                return
            UI.success("Firmware flashed successfully.")
            time.sleep(2)  # wait for CC1352 to boot

        baud = int(self.get_option("baud"))
        self._scan(device, baud)

    # ── Private ────────────────────────────────────────────────────────────────

    def _scan(self, device, baud: int) -> None:
        """Open serial, read UART lines, display live tracker table."""
        port = device.bridge_port
        # tracker records: {mac: {status, count, first_seen, last_seen}}
        trackers: "OrderedDict[str, dict]" = OrderedDict()
        raw_log: list[str] = []  # last 8 raw firmware lines
        lock = threading.Lock()
        start = time.time()
        _running = [True]

        def _reader():
            try:
                with serial.Serial(port, baud, timeout=1) as ser:
                    while _running[0]:
                        raw = ser.readline()
                        if not raw:
                            continue
                        try:
                            line = raw.decode("utf-8", errors="replace").strip()
                        except Exception:
                            continue
                        if not line:
                            continue

                        with lock:
                            if len(raw_log) >= 8:
                                raw_log.pop(0)
                            raw_log.append(line)

                        result = _parse_line(line)
                        if result:
                            mac, status = result
                            now = datetime.now().strftime("%H:%M:%S")
                            with lock:
                                if mac not in trackers:
                                    trackers[mac] = {
                                        "status": status,
                                        "count": 1,
                                        "first_seen": now,
                                        "last_seen": now,
                                    }
                                else:
                                    trackers[mac]["count"] += 1
                                    trackers[mac]["last_seen"] = now
                                    trackers[mac]["status"] = status
            except serial.SerialException as e:
                with lock:
                    raw_log.append(f"[red]Serial error: {e}[/red]")

        t = threading.Thread(target=_reader, daemon=True)
        t.start()

        def _build_panel(elapsed: float) -> Panel:
            mins, secs = divmod(int(elapsed), 60)
            with lock:
                current_trackers = dict(trackers)
                current_log = list(raw_log)

            # ── Header row ──
            hdr = Table(box=None, show_header=False, padding=(0, 2))
            hdr.add_column(style="dim cyan", no_wrap=True)
            hdr.add_column(style="white")
            hdr.add_row("Port", str(port))
            hdr.add_row("Firmware", self.firmware_alias)
            hdr.add_row("Uptime", f"[bold green]{mins:02d}:{secs:02d}[/bold green]")
            hdr.add_row("Baud", str(baud))
            hdr.add_row("Trackers detected", f"[bold yellow]{len(current_trackers)}[/bold yellow]")

            # ── Tracker table ──
            tbl = Table(
                "MAC",
                "Status",
                "Count",
                "First Seen",
                "Last Seen",
                box=None,
                show_header=True,
                header_style="bold dim",
                padding=(0, 1),
            )
            if current_trackers:
                for mac, info in current_trackers.items():
                    s = info["status"].lower()
                    color, dot = _STATUS_STYLE.get(s, ("white", "?"))
                    tbl.add_row(
                        f"[bold]{mac}[/bold]",
                        Text(f"{dot} {info['status']}", style=color),
                        str(info["count"]),
                        info["first_seen"],
                        info["last_seen"],
                    )
            else:
                tbl.add_row(
                    "[dim]Waiting for trackers…[/dim]", "", "", "", ""
                )

            # ── Raw log ──
            log_lines = "\n".join(current_log) if current_log else "[dim](no output yet)[/dim]"

            body = Table(box=None, show_header=False, padding=(0, 0))
            body.add_column()
            body.add_row(hdr)
            body.add_row(Rule(style="dim"))
            body.add_row("[bold]Detected Apple Trackers[/bold]")
            body.add_row(tbl)
            body.add_row(Rule(style="dim"))
            body.add_row("[bold]Firmware UART output[/bold]")
            body.add_row(Text(log_lines, style="dim white"))

            return Panel(
                body,
                title="[bold green]● AirTag Scanner — ACTIVE[/bold green]",
                subtitle="[dim]Ctrl-C to stop[/dim]",
                border_style="green",
                padding=(1, 2),
            )

        try:
            with Live(_build_panel(0), console=console, refresh_per_second=2) as live:
                while True:
                    time.sleep(0.5)
                    live.update(_build_panel(time.time() - start))
        except KeyboardInterrupt:
            pass
        finally:
            _running[0] = False
            t.join(timeout=2)

        UI.info(f"AirTag Scanner stopped. Detected [bold]{len(trackers)}[/bold] tracker(s).")
        if trackers:
            for mac, info in trackers.items():
                UI.info(f"  {mac} → {info['status']} (seen {info['count']}×)")
