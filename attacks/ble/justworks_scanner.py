"""
BLE — JustWorks Vulnerability Scanner
═══════════════════════════════════════
Flashes the `justworks` firmware and finds BLE devices that accept insecure
"Just Works" pairing without any user interaction or PIN.

What is JustWorks?
──────────────────
BLE has four pairing methods (from the spec):
  1. Just Works         — No interaction. Zero MITM protection.
  2. Passkey Entry      — 6-digit PIN. Weak but better than nothing.
  3. Numeric Comparison — LE Secure Connections. Good.
  4. Out-of-Band (OOB)  — External channel (NFC, QR, etc.). Good.

Devices that use Just Works (IO_CAP_NO_INPUT_NO_OUTPUT) accept any pairing
request without confirming it. An attacker within BLE range can pair, read
sensitive GATT attributes, impersonate, or deny service.

What the firmware does
──────────────────────
  1. Scans for ALL connectable BLE advertisers (channels 37/38/39).
  2. Attempts to connect (max 3 tries per MAC, 8 s cooldown).
  3. Initiates pairing with IO_CAP_NO_INPUT_NO_OUTPUT + MITM=FALSE.
  4. If the peer accepts → it logs [INSECURE].
  5. After connect it discovers the GAP service (UUID 0x1800), reads the
     Device Name characteristic (UUID 0x2A00), and writes "Secure your device".
  6. Disconnects, re-scans every 30 s.

Serial output format (UART via RP2040 bridge at 115200 baud):
  ===== JustWorks Scanner (UART) =====
  Auto scan + 30s relaunch...
  [INIT] Done. DevAddr: AA:BB:CC:DD:EE:FF
  [SCAN] ADV from AA:BB | name:Lock | RSSI:-67 dBm | addrType:RANDOM | ...
  [CONN] Initiating to AA:BB:CC:DD:EE:FF ...
  [CONN] Connected: AA:BB:CC:DD:EE:FF | name:Lock | RSSI:-55
  [PAIR] started (conn=0x0040)
  [PAIR] success (conn=0x0040)
  [INSECURE] Just Works accepted by peer: addr=AA:BB name=Lock no user interaction during pairing
  [INFO] Device Name: "SmartLock Pro"
  [INFO] Name write OK: "SmartLock Pro" -> "Secure your device"

Legal notice
────────────
This tool is for authorized security auditing and research ONLY. Connecting
to and pairing with devices you do not own or have explicit written permission
to test may violate computer fraud laws in your jurisdiction. Use responsibly.
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

# ── Regex patterns for each log prefix ────────────────────────────────────────
_SCAN_ADV = re.compile(
    r"\[SCAN\] ADV from (\S+)\s*\|\s*name:(\S*)\s*\|\s*RSSI:(-?\d+) dBm"
)
_CONN_INIT = re.compile(r"\[CONN\] Initiating to (\S+)")
_CONN_ESTAB = re.compile(
    r"\[CONN\] Connected:\s*(\S+)\s*\|\s*name:(\S*)\s*\|\s*RSSI:(-?\d+)"
)
_CONN_DISC = re.compile(r"\[CONN\] Disconnected:\s*(\S+)")
_PAIR_STATE = re.compile(r"\[PAIR\]\s*(started|success|failed\S*)\s*\(conn=0x([0-9A-Fa-f]+)\)")
_INSECURE = re.compile(
    r"\[INSECURE\] Just Works accepted by peer:\s+addr=(\S+)\s+name=(\S*)\s+(.*)"
)
_INFO_NAME = re.compile(r'\[INFO\] Device Name:\s*"(.+)"')
_INFO_WRITE = re.compile(r'\[INFO\] Name write OK:\s*"(.+)"\s*->\s*"(.+)"')


def _ts() -> str:
    return datetime.now().strftime("%H:%M:%S")


# ── Data models (lightweight dicts) ───────────────────────────────────────────

class _DeviceRecord:
    """Mutable record for a discovered BLE device."""

    def __init__(self, mac: str, name: str, rssi: int):
        self.mac = mac
        self.name = name
        self.rssi = rssi
        self.status = "Seen"       # Seen | Connecting | Connected | Disconnected
        self.pair_state = ""       # started | success | failed…
        self.insecure = False
        self.device_name = ""
        self.name_written = False
        self.first_seen = _ts()
        self.last_seen = _ts()


# ── Attack ─────────────────────────────────────────────────────────────────────


@AttackRegistry.register
class JustWorksScanner(BaseAttack):
    # ── Metadata ──────────────────────────────────────────────────────────────
    name = "justworks_scanner"
    description = "Find BLE devices that accept insecure Just Works pairing"
    firmware_alias = "justworks"
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
            time.sleep(2)

        baud = int(self.get_option("baud"))
        self._scan(device, baud)

    # ── Private ────────────────────────────────────────────────────────────────

    def _scan(self, device, baud: int) -> None:
        port = device.bridge_port
        devices: "OrderedDict[str, _DeviceRecord]" = OrderedDict()
        vuln_list: list[dict] = []          # [INSECURE] entries
        event_log: list[str] = []           # last 12 raw tagged lines
        lock = threading.Lock()
        start = time.time()
        _running = [True]

        def _add_event(line: str):
            with lock:
                if len(event_log) >= 12:
                    event_log.pop(0)
                event_log.append(f"[{_ts()}] {line.strip()}")

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

                        _add_event(line)
                        _process_line(line)
            except serial.SerialException as e:
                _add_event(f"[red]Serial error: {e}[/red]")

        def _process_line(line: str):
            with lock:
                # [SCAN] device spotted
                m = _SCAN_ADV.search(line)
                if m:
                    mac, name, rssi = m.group(1), m.group(2) or "", int(m.group(3))
                    if mac not in devices:
                        devices[mac] = _DeviceRecord(mac, name, rssi)
                    else:
                        devices[mac].rssi = rssi
                        devices[mac].last_seen = _ts()
                    return

                # [CONN] initiating
                m = _CONN_INIT.search(line)
                if m:
                    mac = m.group(1)
                    if mac in devices:
                        devices[mac].status = "Connecting"
                    return

                # [CONN] established
                m = _CONN_ESTAB.search(line)
                if m:
                    mac, name, rssi = m.group(1), m.group(2) or "", int(m.group(3))
                    if mac not in devices:
                        devices[mac] = _DeviceRecord(mac, name, rssi)
                    devices[mac].status = "Connected"
                    devices[mac].rssi = rssi
                    devices[mac].last_seen = _ts()
                    return

                # [CONN] disconnected
                m = _CONN_DISC.search(line)
                if m:
                    mac = m.group(1)
                    if mac in devices:
                        devices[mac].status = "Disconnected"
                    return

                # [PAIR] state change
                m = _PAIR_STATE.search(line)
                if m:
                    state = m.group(1)
                    # find most recently connecting/connected MAC
                    for rec in reversed(list(devices.values())):
                        if rec.status in ("Connecting", "Connected"):
                            rec.pair_state = state
                            break
                    return

                # [INSECURE] — vulnerable device
                m = _INSECURE.search(line)
                if m:
                    mac, name, reason = m.group(1), m.group(2) or "", m.group(3)
                    if mac in devices:
                        devices[mac].insecure = True
                        devices[mac].status = "Connected"
                    vuln_list.append({
                        "mac": mac,
                        "name": name or "?",
                        "reason": reason.strip(),
                        "ts": _ts(),
                    })
                    return

                # [INFO] Device Name
                m = _INFO_NAME.search(line)
                if m:
                    name = m.group(1)
                    for rec in reversed(list(devices.values())):
                        if rec.status == "Connected":
                            rec.device_name = name
                            break
                    return

                # [INFO] Name write OK
                m = _INFO_WRITE.search(line)
                if m:
                    for rec in reversed(list(devices.values())):
                        if rec.status == "Connected":
                            rec.name_written = True
                            break

        t = threading.Thread(target=_reader, daemon=True)
        t.start()

        def _build_panel(elapsed: float) -> Panel:
            mins, secs = divmod(int(elapsed), 60)
            with lock:
                snap_devices = list(devices.values())
                snap_vulns = list(vuln_list)
                snap_log = list(event_log)

            vuln_count = len(snap_vulns)
            device_count = len(snap_devices)

            # ── Header ──
            hdr = Table(box=None, show_header=False, padding=(0, 2))
            hdr.add_column(style="dim cyan", no_wrap=True)
            hdr.add_column(style="white")
            hdr.add_row("Port", str(port))
            hdr.add_row("Firmware", self.firmware_alias)
            hdr.add_row("Uptime", f"[bold green]{mins:02d}:{secs:02d}[/bold green]")
            hdr.add_row("Devices seen", str(device_count))
            hdr.add_row(
                "Vulnerable (JustWorks)",
                f"[bold {'red' if vuln_count else 'dim'}]{vuln_count}[/bold {'red' if vuln_count else 'dim'}]",
            )

            # ── Vulnerable devices table ──
            vuln_tbl = Table(
                "MAC", "Name", "Reason", "Time",
                box=None, show_header=True,
                header_style="bold red",
                padding=(0, 1),
            )
            if snap_vulns:
                for v in snap_vulns:
                    vuln_tbl.add_row(
                        f"[bold red]{v['mac']}[/bold red]",
                        f"[yellow]{v['name']}[/yellow]",
                        Text(v["reason"], style="dim"),
                        v["ts"],
                    )
            else:
                vuln_tbl.add_row("[dim](none found yet)[/dim]", "", "", "")

            # ── Devices in range table ──
            dev_tbl = Table(
                "MAC", "Name", "RSSI", "Status", "Pair",
                box=None, show_header=True,
                header_style="bold dim",
                padding=(0, 1),
            )
            for rec in snap_devices[-20:]:  # show last 20
                status_style = {
                    "Seen": "dim",
                    "Connecting": "yellow",
                    "Connected": "green",
                    "Disconnected": "dim",
                }.get(rec.status, "white")
                vuln_marker = " [red]![/red]" if rec.insecure else ""
                dev_tbl.add_row(
                    f"[bold]{rec.mac}[/bold]{vuln_marker}",
                    rec.name or "[dim]—[/dim]",
                    f"{rec.rssi} dBm",
                    Text(rec.status, style=status_style),
                    rec.pair_state or "[dim]—[/dim]",
                )

            # ── Event log ──
            log_text = "\n".join(snap_log) if snap_log else "[dim](no output yet)[/dim]"

            body = Table(box=None, show_header=False, padding=(0, 0))
            body.add_column()
            body.add_row(hdr)
            body.add_row(Rule(style="dim"))
            body.add_row(
                Text(
                    f"🚨 VULNERABLE DEVICES (JustWorks pairing accepted) — {vuln_count}",
                    style="bold red" if vuln_count else "bold dim",
                )
            )
            body.add_row(vuln_tbl)
            body.add_row(Rule(style="dim"))
            body.add_row(Text(f"📡 ALL DEVICES IN RANGE — {device_count}", style="bold"))
            body.add_row(dev_tbl)
            body.add_row(Rule(style="dim"))
            body.add_row(Text("📋 EVENT LOG", style="bold"))
            body.add_row(Text(log_text, style="dim white"))

            title_style = "bold red" if vuln_count else "bold yellow"
            return Panel(
                body,
                title=f"[{title_style}]● JustWorks BLE Scanner — ACTIVE[/{title_style}]",
                subtitle="[dim]Ctrl-C to stop[/dim]",
                border_style="red" if vuln_count else "yellow",
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

        total_vuln = len(vuln_list)
        UI.info(
            f"JustWorks Scanner stopped. "
            f"Scanned [bold]{len(devices)}[/bold] device(s), "
            f"[bold red]{total_vuln}[/bold red] vulnerable."
        )
        if vuln_list:
            UI.warning("Vulnerable devices found:")
            for v in vuln_list:
                UI.warning(f"  [bold]{v['mac']}[/bold]  name={v['name']}  reason={v['reason']}")
