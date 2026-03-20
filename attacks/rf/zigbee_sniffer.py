"""
RF — Zigbee / Thread / 802.15.4 Sniffer
════════════════════════════════════════
Flashes the `ti_sniffer` MultiProtocol firmware and captures 802.15.4 traffic
(Zigbee, Thread/Matter, 6LoWPAN, IEEE 802.15.4 MAC) over the air.

Supported protocols
───────────────────
  • Zigbee (channels 11–26, 2.4 GHz)
  • Thread / Matter (channels 11–26, 2.4 GHz)
  • IEEE 802.15.4 MAC — general sniffer for sub-GHz and 2.4 GHz
  • 6LoWPAN (on top of 802.15.4)
  • Amazon Sidewalk (sub-GHz, experimental)

Firmware: TI SmartRF Packet Sniffer 2 (sniffer_fw_Catsniffer_v3.x.hex)
Alias   : ti | zigbee | thread | 15.4 | multiprotocol

How it works
────────────
The CC1352P7 exposes a radio sniffer that captures 802.15.4 frames and sends
them over serial in TI's proprietary PCAP framing. Three integration modes:

  1. Wireshark  — Pipe frames directly into Wireshark for real-time analysis.
                  Requires Wireshark ≥ 3.0 with the TI SmartRF extcap plugin,
                  OR the `wireshark` binary in PATH (uses stdin PCAP pipe).
  2. PCAP file  — Write a standard PCAP / PCAPNG file for offline analysis.
  3. Info only  — Just flash + show serial port info; user connects manually.

Channel map (2.4 GHz 802.15.4):
  Ch 11 (2405 MHz)  Ch 17 (2435 MHz)  Ch 22 (2460 MHz)
  Ch 12 (2410 MHz)  Ch 18 (2440 MHz)  Ch 23 (2465 MHz)
  Ch 13 (2415 MHz)  Ch 19 (2445 MHz)  Ch 24 (2470 MHz)
  Ch 14 (2420 MHz)  Ch 20 (2450 MHz)  Ch 25 (2475 MHz)
  Ch 15 (2425 MHz)  Ch 21 (2455 MHz)  Ch 26 (2480 MHz)
  Ch 16 (2430 MHz)

Attack use cases
────────────────
  • Capture Zigbee home-automation traffic (lights, locks, sensors)
  • Capture Thread/Matter mesh network joins / key exchanges
  • Replay attacks on unencrypted 802.15.4 devices
  • Network mapping: PAN ID, coordinator, router, end-device discovery
  • Find devices with encryption disabled ("Wireshark → Edit → Preferences →
    Protocols → Zigbee → Add pre-shared key" to decrypt if known)
"""
from __future__ import annotations

import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.syntax import Syntax
from rich.table import Table
from rich.text import Text

from attacks.base import BaseAttack, AttackOption
from attacks.registry import AttackRegistry
from core import ui as UI
from core.firmware import flash_firmware

console = Console()

# 2.4 GHz 802.15.4 channel → centre frequency (MHz)
_CHANNEL_FREQ = {i: 2405 + 5 * (i - 11) for i in range(11, 27)}


@AttackRegistry.register
class ZigbeeSniffer(BaseAttack):
    # ── Metadata ──────────────────────────────────────────────────────────────
    name = "zigbee_sniffer"
    description = "Capture Zigbee / Thread / 802.15.4 traffic (Real-time or PCAP)"
    firmware_alias = "ti"
    category = "RF"

    options = [
        AttackOption(
            name="flash",
            description="Flash firmware before running? (yes/no)",
            default="yes",
            type=str,
            choices=["yes", "no"],
        ),
        AttackOption(
            name="channel",
            description="802.15.4 channel (11–26 for 2.4 GHz)",
            default="11",
            type=str,
        ),
        AttackOption(
            name="mode",
            description="Integration mode: info / wireshark / pcap",
            default="info",
            type=str,
            choices=["info", "wireshark", "pcap"],
        ),
        AttackOption(
            name="output",
            description="Output PCAP file path (for mode=pcap)",
            default="capture.pcap",
            type=str,
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

        try:
            channel = int(self.get_option("channel"))
        except ValueError:
            UI.error("Invalid channel. Use an integer 11–26.")
            return

        if channel not in range(11, 27):
            UI.warning(f"Channel {channel} is outside the 2.4 GHz range (11–26). Continuing anyway.")

        freq = _CHANNEL_FREQ.get(channel, "?")
        mode = self.get_option("mode")
        port = device.bridge_port

        if mode == "info":
            self._show_info(device, port, channel, freq)
        elif mode == "wireshark":
            self._launch_wireshark(device, port, channel, freq)
        elif mode == "pcap":
            self._capture_pcap(device, port, channel, freq)

    # ── Private ────────────────────────────────────────────────────────────────

    def _show_info(self, device, port, channel: int, freq) -> None:
        """Display setup instructions and serial port info."""
        hdr = Table(box=None, show_header=False, padding=(0, 2))
        hdr.add_column(style="dim cyan", no_wrap=True)
        hdr.add_column(style="white")
        hdr.add_row("Firmware", self.firmware_alias)
        hdr.add_row("Bridge port", str(port))
        hdr.add_row("Channel", f"{channel}  ({freq} MHz)")
        hdr.add_row("Protocol", "IEEE 802.15.4 / Zigbee / Thread")

        wireshark_ok = shutil.which("wireshark") is not None
        hdr.add_row("Wireshark", "[green]found[/green]" if wireshark_ok else "[red]not found[/red]")

        # Hint tables
        tool_tbl = Table("Method", "Command", box=None, header_style="bold dim", padding=(0, 1))
        tool_tbl.add_row(
            "[bold]TI SmartRF extcap[/bold]",
            f"Open Wireshark → Capture → Interfaces → CatSniffer",
        )
        tool_tbl.add_row(
            "[bold]PCAP pipe[/bold]",
            f"Set mode=wireshark in this tool  (requires wireshark in PATH)",
        )
        tool_tbl.add_row(
            "[bold]PCAP file[/bold]",
            f"Set mode=pcap  output=my_capture.pcap",
        )
        tool_tbl.add_row(
            "[bold]catnip sniffer[/bold]",
            f"catnip sniffer --channel {channel} --interface {port}",
        )

        # Wireshark key tip
        decrypt_code = (
            "# In Wireshark: Edit → Preferences → Protocols → Zigbee\n"
            "# Add pre-shared key (PSK) if known:\n"
            "# Key: 5A6967426565416C6C69616E636530 (default Zigbee Well-Known key)\n"
            "# Type: NWK"
        )
        syntax = Syntax(decrypt_code, "bash", theme="monokai", line_numbers=False)

        body = Table(box=None, show_header=False, padding=(0, 0))
        body.add_column()
        body.add_row(hdr)
        from rich.rule import Rule
        body.add_row(Rule(style="dim"))
        body.add_row(Text("📡 Integration options", style="bold"))
        body.add_row(tool_tbl)
        body.add_row(Rule(style="dim"))
        body.add_row(Text("🔑 Decryption tip (Zigbee)", style="bold dim"))
        body.add_row(syntax)

        console.print(
            Panel(
                body,
                title="[bold cyan]Zigbee / 802.15.4 Sniffer — Info[/bold cyan]",
                subtitle=f"[dim]Firmware flashed. Set mode=wireshark or mode=pcap to capture.[/dim]",
                border_style="cyan",
                padding=(1, 2),
            )
        )

        UI.info(
            "Firmware is running on the device. "
            "Use [bold]mode=wireshark[/bold] or [bold]mode=pcap[/bold] to start capturing."
        )

    def _launch_wireshark(self, device, port, channel: int, freq) -> None:
        """Pipe PCAP output directly to Wireshark via stdin."""
        if not shutil.which("wireshark"):
            UI.error(
                "Wireshark not found in PATH.\n"
                "  • Install with: [bold]brew install --cask wireshark[/bold]\n"
                "  • Or use [bold]mode=pcap[/bold] to save a capture file instead."
            )
            return

        UI.info(
            f"Launching Wireshark with 802.15.4 capture on channel [bold]{channel}[/bold] "
            f"({freq} MHz)…\n"
            "Wireshark will open. Close it or press Ctrl-C here to stop."
        )

        # catnip sniffer → stdout PCAP → wireshark stdin
        # Try catnip sniffer subcommand first, fall back to raw serial pipe
        catnip = shutil.which("catnip")
        if catnip:
            cmd_capture = [catnip, "sniffer", "--channel", str(channel), "--interface", str(port)]
        else:
            # Minimal fallback: raw serial bytes piped to Wireshark
            # (TI sniffer sends PCAP-formatted data on the serial port)
            cmd_capture = [
                sys.executable, "-c",
                (
                    "import sys, serial\n"
                    f"s = serial.Serial('{port}', 3000000, timeout=1)\n"
                    "while True:\n"
                    "    d = s.read(4096)\n"
                    "    if d: sys.stdout.buffer.write(d); sys.stdout.buffer.flush()\n"
                ),
            ]

        cmd_ws = ["wireshark", "-k", "-i", "-"]

        try:
            proc_cap = subprocess.Popen(cmd_capture, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
            proc_ws = subprocess.Popen(cmd_ws, stdin=proc_cap.stdout)
            proc_cap.stdout.close()  # allow proc_cap to receive SIGPIPE if ws dies
            proc_ws.wait()
        except KeyboardInterrupt:
            pass
        except FileNotFoundError as e:
            UI.error(f"Failed to launch process: {e}")
        finally:
            try:
                proc_cap.terminate()
            except Exception:
                pass

        UI.info("Wireshark session ended.")

    def _capture_pcap(self, device, port, channel: int, freq) -> None:
        """Capture to a PCAP file using catnip or raw serial."""
        output = self.get_option("output")
        out_path = Path(output).expanduser().resolve()

        UI.info(
            f"Capturing 802.15.4 traffic on channel [bold]{channel}[/bold] "
            f"({freq} MHz) → [bold]{out_path}[/bold]\n"
            "Press Ctrl-C to stop."
        )

        catnip = shutil.which("catnip")
        if catnip:
            cmd = [
                catnip, "sniffer",
                "--channel", str(channel),
                "--interface", str(port),
                "--output", str(out_path),
            ]
        else:
            # Fallback: raw serial → file (TI framing kept intact for Wireshark)
            cmd = [
                sys.executable, "-c",
                (
                    "import sys, serial\n"
                    f"s = serial.Serial('{port}', 3000000, timeout=1)\n"
                    f"with open('{out_path}', 'wb') as f:\n"
                    "    while True:\n"
                    "        d = s.read(4096)\n"
                    "        if d: f.write(d); f.flush()\n"
                ),
            ]

        try:
            proc = subprocess.Popen(cmd)
            proc.wait()
        except KeyboardInterrupt:
            pass
        except FileNotFoundError as e:
            UI.error(f"Failed to launch capture process: {e}")
        finally:
            try:
                proc.terminate()
            except Exception:
                pass

        if out_path.exists() and out_path.stat().st_size > 0:
            UI.success(
                f"Capture saved: [bold]{out_path}[/bold] ({out_path.stat().st_size} bytes)\n"
                "Open with Wireshark to analyse."
            )
        else:
            UI.warning("No data captured or file is empty.")
