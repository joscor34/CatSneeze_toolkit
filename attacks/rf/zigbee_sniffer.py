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

import os
import shutil
import subprocess
import sys
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

# Named pipe catnip creates on macOS/Linux for PCAP output
_CATNIP_PIPE = "/tmp/fcatnip"


def _find_catnip() -> str | None:
    return shutil.which("catnip")


def _catnip_sniff_cmd(channel: int, ws: bool = False) -> list[str]:
    """Build the correct catnip sniff zigbee command."""
    catnip = _find_catnip()
    if not catnip:
        return []
    cmd = [catnip, "sniff", "zigbee", "-c", str(channel)]
    if ws:
        cmd.append("-ws")
    return cmd


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
            description="Integration mode: info / wireshark / pcap / scan",
            default="info",
            type=str,
            choices=["info", "wireshark", "pcap", "scan"],
        ),
        AttackOption(
            name="scan_dwell",
            description="Seconds per channel during scan mode (0.5–10)",
            default="2",
            type=str,
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
            if self.get_option("mode") != "scan":
                UI.error("Invalid channel. Use an integer 11–26.")
                return
            channel = 11  # scan ignores the channel option

        if channel not in range(11, 27):
            UI.warn(f"Channel {channel} is outside the 2.4 GHz range (11–26). Continuing anyway.")

        freq = _CHANNEL_FREQ.get(channel, "?")
        mode = self.get_option("mode")
        port = device.bridge_port

        if mode == "info":
            self._show_info(device, port, channel, freq)
        elif mode == "wireshark":
            self._launch_wireshark(device, port, channel, freq)
        elif mode == "pcap":
            self._capture_pcap(device, port, channel, freq)
        elif mode == "scan":
            try:
                dwell = float(self.get_option("scan_dwell"))
            except ValueError:
                dwell = 2.0
            self._scan_channels(device, port, dwell)

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
        """Capture via catnip FIFO and feed Wireshark with tail -f (no profile needed)."""
        catnip = _find_catnip()
        if not catnip:
            UI.error(
                "[bold]catnip[/bold] not found in PATH.\n"
                "  Install: [bold]pip install catnip[/bold]\n"
                "  Or use [bold]mode=pcap[/bold] once catnip is available."
            )
            return

        ws_bin = (
            shutil.which("wireshark")
            or "/Applications/Wireshark.app/Contents/MacOS/Wireshark"
        )
        if not Path(ws_bin).exists() and not shutil.which("wireshark"):
            UI.error(
                "Wireshark not found.\n"
                "  Install: [bold]brew install --cask wireshark[/bold]\n"
                "  Or use [bold]mode=pcap[/bold]."
            )
            return

        # Always save to a timestamped PCAP file so data is not lost.
        ts = time.strftime("%Y%m%d_%H%M%S")
        pcap_path = Path.cwd() / f"zigbee_capture_{ts}.pcap"

        UI.info(
            f"Launching Wireshark — channel [bold]{channel}[/bold] ({freq} MHz)\n"
            f"Saving to [bold]{pcap_path.name}[/bold] — Close Wireshark or Ctrl-C to stop."
        )

        # Clean stale FIFO
        if os.path.exists(_CATNIP_PIPE):
            try:
                os.remove(_CATNIP_PIPE)
            except OSError:
                pass

        # catnip without -ws: writes PCAP to /tmp/fcatnip without launching Wireshark
        cmd = _catnip_sniff_cmd(channel, ws=False)
        proc_cap = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        # Wait for catnip to create the FIFO
        deadline = time.time() + 6.0
        while not os.path.exists(_CATNIP_PIPE) and time.time() < deadline:
            time.sleep(0.05)

        if not os.path.exists(_CATNIP_PIPE):
            UI.error("catnip did not create its pipe — check device connection and firmware.")
            proc_cap.terminate()
            return

        p_reader = None
        p_tail = None
        p_ws = None
        try:
            # Thread: read from FIFO and tee to real PCAP file
            import threading

            stop_event = threading.Event()

            def _tee_to_file():
                with open(_CATNIP_PIPE, "rb") as pipe_r, open(pcap_path, "wb") as f:
                    while not stop_event.is_set():
                        chunk = pipe_r.read(4096)
                        if chunk:
                            f.write(chunk)
                            f.flush()

            p_reader = threading.Thread(target=_tee_to_file, daemon=True)
            p_reader.start()

            # Wait for PCAP global header (24 bytes) to land on disk
            deadline = time.time() + 8.0
            while time.time() < deadline:
                if pcap_path.exists() and pcap_path.stat().st_size >= 24:
                    break
                time.sleep(0.1)
            else:
                UI.warn("Timeout waiting for capture to start — check device connection.")
                stop_event.set()
                proc_cap.terminate()
                return

            # tail → Wireshark: stream the real file from byte 1 (no Zigbee profile)
            p_tail = subprocess.Popen(
                ["tail", "-c", "+1", "-f", str(pcap_path)],
                stdout=subprocess.PIPE,
            )
            p_ws = subprocess.Popen(
                [ws_bin, "-k", "-i", "-"],
                stdin=p_tail.stdout,
                stderr=subprocess.DEVNULL,
            )
            p_tail.stdout.close()
            p_ws.wait()

        except KeyboardInterrupt:
            pass
        finally:
            if "stop_event" in dir():
                stop_event.set()
            for proc in (proc_cap, p_tail, p_ws):
                if proc is not None:
                    try:
                        proc.terminate()
                    except Exception:
                        pass

        if pcap_path.exists() and pcap_path.stat().st_size > 24:
            UI.success(
                f"Capture saved: [bold]{pcap_path}[/bold] "
                f"({pcap_path.stat().st_size} bytes)"
            )
        else:
            UI.warn(f"Capture file empty or missing: {pcap_path}")

    def _capture_pcap(self, device, port, channel: int, freq) -> None:
        """Capture to PCAP by intercepting catnip's /tmp/fcatnip FIFO."""
        catnip = _find_catnip()
        if not catnip:
            UI.error(
                "[bold]catnip[/bold] not found in PATH.\n"
                "  Install: [bold]pip install catnip[/bold]"
            )
            return

        output = self.get_option("output")
        ts = time.strftime("%Y%m%d_%H%M%S")
        out_path = Path(output).expanduser().resolve()
        # Add timestamp to avoid overwriting previous captures
        out_path = out_path.parent / f"{out_path.stem}_{ts}{out_path.suffix}"

        UI.info(
            f"Capturing 802.15.4 on channel [bold]{channel}[/bold] ({freq} MHz)\n"
            f"→ [bold]{out_path}[/bold]\nPress Ctrl-C to stop."
        )

        # catnip always creates /tmp/fcatnip FIFO and writes PCAP to it.
        # We intercept by opening the read side — this unblocks catnip's writer.
        # Clean up stale FIFO from a previous run.
        if os.path.exists(_CATNIP_PIPE):
            try:
                os.remove(_CATNIP_PIPE)
            except OSError:
                pass

        cmd = _catnip_sniff_cmd(channel, ws=False)
        proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        # Wait for catnip to create the FIFO (typically < 1 s)
        deadline = time.time() + 6.0
        while not os.path.exists(_CATNIP_PIPE) and time.time() < deadline:
            time.sleep(0.05)

        if not os.path.exists(_CATNIP_PIPE):
            UI.error(
                "catnip did not create its pipe — check device connection and firmware."
            )
            proc.terminate()
            return

        bytes_written = 0
        try:
            # Opening the read side unblocks catnip's opening_worker write side.
            with open(_CATNIP_PIPE, "rb") as pipe_r, open(out_path, "wb") as f:
                while True:
                    chunk = pipe_r.read(4096)
                    if not chunk:
                        break
                    f.write(chunk)
                    f.flush()
                    bytes_written += len(chunk)
        except KeyboardInterrupt:
            pass
        finally:
            proc.terminate()

        if out_path.exists() and out_path.stat().st_size > 24:
            UI.success(
                f"Capture saved: [bold]{out_path}[/bold] "
                f"({out_path.stat().st_size} bytes)\n"
                "Open with Wireshark to analyse."
            )
        else:
            UI.warn(f"No data captured or file is empty: {out_path}")

    def _scan_channels(self, device, port, dwell: float) -> None:
        """Scan all 802.15.4 channels (11–26) and report activity."""
        catnip = _find_catnip()
        if not catnip:
            UI.error(
                "[bold]catnip[/bold] not found in PATH.\n"
                "  Install: [bold]pip install catnip[/bold]"
            )
            return

        from rich.live import Live
        from rich.table import Table as RTable

        UI.info(
            f"Scanning channels 11\u201326 ({dwell}s each) \u2014 Press Ctrl-C to stop.\n"
            "Activity = frames captured on that channel."
        )

        results: dict[int, int] = {ch: 0 for ch in range(11, 27)}

        def _make_table() -> RTable:
            tbl = RTable(title="802.15.4 Channel Scan", header_style="bold cyan")
            tbl.add_column("CH", justify="center", style="bold")
            tbl.add_column("Freq (MHz)", justify="center")
            tbl.add_column("Frames", justify="right")
            tbl.add_column("Activity", justify="left")
            for ch in range(11, 27):
                count = results[ch]
                bar = "\u2588" * min(count, 30) if count else "[dim]\u2014[/dim]"
                style = "green" if count > 5 else ("yellow" if count > 0 else "")
                tbl.add_row(
                    f"[{style}]{ch}[/{style}]" if style else str(ch),
                    str(_CHANNEL_FREQ[ch]),
                    f"[{style}]{count}[/{style}]" if style else str(count),
                    bar,
                )
            return tbl

        try:
            with Live(_make_table(), refresh_per_second=4) as live:
                for ch in range(11, 27):
                    # Clean up stale FIFO
                    if os.path.exists(_CATNIP_PIPE):
                        try:
                            os.remove(_CATNIP_PIPE)
                        except OSError:
                            pass

                    cmd = _catnip_sniff_cmd(ch, ws=False)
                    proc = subprocess.Popen(
                        cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
                    )

                    # Wait for catnip to create the FIFO
                    deadline = time.time() + 4.0
                    while not os.path.exists(_CATNIP_PIPE) and time.time() < deadline:
                        time.sleep(0.05)

                    if os.path.exists(_CATNIP_PIPE):
                        frame_count = 0
                        t_end = time.time() + dwell
                        try:
                            with open(_CATNIP_PIPE, "rb") as pipe_r:
                                pipe_r.read(24)  # consume PCAP global header
                                while time.time() < t_end:
                                    # Each PCAP record starts with a 16-byte header
                                    hdr = pipe_r.read(16)
                                    if not hdr or len(hdr) < 16:
                                        time.sleep(0.02)
                                        continue
                                    import struct
                                    pkt_len = struct.unpack_from("<I", hdr, 8)[0]
                                    pipe_r.read(pkt_len)  # discard payload
                                    frame_count += 1
                        except (OSError, struct.error):
                            pass

                        results[ch] = frame_count
                    else:
                        results[ch] = 0

                    proc.terminate()
                    proc.wait(timeout=2)
                    live.update(_make_table())

        except KeyboardInterrupt:
            pass

        # Final report
        active = [(ch, results[ch]) for ch in range(11, 27) if results[ch] > 0]
        if active:
            UI.success(
                "Channels with activity: "
                + ", ".join(f"[bold]{ch}[/bold] ({n} frames)" for ch, n in sorted(active, key=lambda x: -x[1]))
            )
        else:
            UI.warn("No 802.15.4 activity detected on any channel.")
