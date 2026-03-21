"""
BLE — Sniffle Active Sniffer
══════════════════════════════
Flashes the `sniffle` firmware and listens to BLE advertisements and
connections using NCC Group's Sniffle sniffer.

What is Sniffle?
────────────────
Sniffle (https://github.com/nccgroup/Sniffle) is an open-source BLE sniffer
specifically designed for the TI CC1352 family. Unlike passive scanners it can:
  • Follow BLE connections from initiation through termination
  • Hop with the connection onto data channels (channel-hopping)
  • Capture extended advertising (BLE 5.x, Coded PHY, extended)
  • Capture AUX_ADV packets (secondary advertising channel)
  • Decode and dissect DLE, LE Credit-Based Flow Control, etc.
  • Export standard PCAP/PCAPNG consumed by any BLE Wireshark build

Firmware: sniffle_cc1352p7_1M.hex (SnifferFirmware)
Alias   : ble | sniffle

Python host tool
────────────────
Sniffle requires its Python host package:
  # Sniffle has no pip package — clone and install deps manually:
  git clone https://github.com/nccgroup/Sniffle
  pip install pyserial numpy scipy
  # Then place the Sniffle/ folder next to CatSniffer_my_tool/ (auto-discovered).

Usage (from Sniffle Python host):
  python3 -m sniffle.sniff_receiver -s /dev/tty.usbmodem31101
  python3 -m sniffle.sniff_receiver -s /dev/tty.usbmodem31101 -o capture.pcap

Integration modes
─────────────────
  auto       — detect sniffle installation, launch automatically
  wireshark  — pipe PCAP to Wireshark stdin for live display
  pcap       — save to PCAP file
  info       — show setup instructions and exit

Attack use cases
────────────────
  • Capture BLE connection establishment (find shared link key exchange)
  • Follow a specific device connection end-to-end
  • Capture GATT attribute reads that may leak sensitive data
  • Debug custom BLE firmware
  • Capture and replay BLE sequences
  • Passive reconnaisance of BLE environment

Legal notice
────────────────
Capturing BLE traffic from devices you do not own or have explicit written
permission to test is likely illegal in most jurisdictions. Use responsibly.
"""
from __future__ import annotations

import importlib.util
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.rule import Rule
from rich.syntax import Syntax
from rich.table import Table
from rich.text import Text

from attacks.base import BaseAttack, AttackOption
from attacks.registry import AttackRegistry
from core import ui as UI
from core.firmware import flash_firmware

console = Console()


_SNIFFLE_CLI_PATH: Path | None = None


def _inject_sniffle_path() -> None:
    """Add Sniffle's python_cli directory to sys.path if found locally."""
    global _SNIFFLE_CLI_PATH
    if importlib.util.find_spec("sniffle") is not None:
        return  # already importable

    # Search for a local Sniffle clone.
    candidates = [
        Path(__file__).resolve().parents[2] / "Sniffle" / "python_cli",
        Path(__file__).resolve().parents[1] / "Sniffle" / "python_cli",
        Path.home() / "Sniffle" / "python_cli",
    ]
    for candidate in candidates:
        if (candidate / "sniffle" / "__init__.py").exists():
            sys.path.insert(0, str(candidate))
            _SNIFFLE_CLI_PATH = candidate
            return


def _sniffle_env() -> dict:
    """Return environ with PYTHONPATH set so subprocesses can import sniffle."""
    _inject_sniffle_path()  # ensure _SNIFFLE_CLI_PATH is populated
    env = os.environ.copy()
    cli_path = _SNIFFLE_CLI_PATH
    if cli_path is None:
        # Try to derive it from sys.path (installed package)
        try:
            import sniffle as _s
            cli_path = Path(_s.__file__).parent.parent
        except Exception:
            pass
    if cli_path is not None:
        existing = env.get("PYTHONPATH", "")
        env["PYTHONPATH"] = str(cli_path) + (os.pathsep + existing if existing else "")
    return env


def _sniffle_available() -> bool:
    """Return True if the sniffle Python package is importable (auto-discovers local clone)."""
    _inject_sniffle_path()
    return importlib.util.find_spec("sniffle") is not None


@AttackRegistry.register
class BleSniffer(BaseAttack):
    # ── Metadata ──────────────────────────────────────────────────────────────
    name = "ble_sniffer"
    description = "Active BLE sniffer with connection following (Sniffle firmware)"
    firmware_alias = "ble"
    category = "BLE"

    options = [
        AttackOption(
            name="flash",
            description="Flash Sniffle firmware before running? (yes/no)",
            default="yes",
            type=str,
            choices=["yes", "no"],
        ),
        AttackOption(
            name="mode",
            description="Launch mode: auto / wireshark / pcap / info",
            default="auto",
            type=str,
            choices=["auto", "wireshark", "pcap", "info"],
        ),
        AttackOption(
            name="output",
            description="Output PCAP file (mode=pcap)",
            default="ble_capture.pcap",
            type=str,
        ),
        AttackOption(
            name="follow",
            description="Follow BLE connections (yes/no)",
            default="yes",
            type=str,
            choices=["yes", "no"],
        ),
        AttackOption(
            name="channel",
            description="Primary advertising channel (37, 38, 39, or all)",
            default="all",
            type=str,
            choices=["37", "38", "39", "all"],
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
            UI.success("Firmware flashed. Waiting for device to boot…")
            time.sleep(2)

        port = device.bridge_port
        mode = self.get_option("mode")
        follow = self.get_option("follow") == "yes"
        channel = self.get_option("channel")
        output = self.get_option("output")

        if mode == "info":
            self._show_info(port)
            return

        # Check sniffle installed
        if not _sniffle_available():
            UI.warn(
                "The [bold]sniffle[/bold] Python package is not installed.\n"
                "  Install with:  [bold]pip install sniffle[/bold]\n"
                "  Or:            [bold]pip install git+https://github.com/nccgroup/Sniffle[/bold]\n\n"
                "Showing info mode instead."
            )
            self._show_info(port)
            return

        if mode == "auto":
            ws_found = shutil.which("wireshark") or os.path.exists(
                "/Applications/Wireshark.app/Contents/MacOS/Wireshark"
            )
            if ws_found:
                mode = "wireshark"
            else:
                mode = "pcap"
            UI.info(f"Auto-selected mode: [bold]{mode}[/bold]")

        if mode == "wireshark":
            self._launch_wireshark(port, follow, channel)
        elif mode == "pcap":
            self._capture_pcap(port, follow, channel, output)

    # ── Private ────────────────────────────────────────────────────────────────

    def _show_info(self, port) -> None:
        """Display setup instructions."""
        sniffle_ok = _sniffle_available()
        ws_ok = bool(
            shutil.which("wireshark") or
            os.path.exists("/Applications/Wireshark.app/Contents/MacOS/Wireshark")
        )

        hdr = Table(box=None, show_header=False, padding=(0, 2))
        hdr.add_column(style="dim cyan", no_wrap=True)
        hdr.add_column(style="white")
        hdr.add_row("Firmware", self.firmware_alias)
        hdr.add_row("Bridge port", str(port))
        hdr.add_row("sniffle package", "[green]installed[/green]" if sniffle_ok else "[red]not installed[/red]")
        hdr.add_row("Wireshark", "[green]found[/green]" if ws_ok else "[dim]not found[/dim]")

        install_code = (
            "# Install sniffle Python host tools:\n"
            "pip install sniffle\n\n"
            "# Or from source (latest):\n"
            "git clone https://github.com/nccgroup/Sniffle\n"
            "cd Sniffle && pip install -e ."
        )

        usage_code = (
            f"# Basic capture (console output):\n"
            f"python3 -m sniffle.sniff_receiver -s {port}\n\n"
            f"# Save to PCAP file:\n"
            f"python3 -m sniffle.sniff_receiver -s {port} -o ble.pcap\n\n"
            f"# Pipe to Wireshark:\n"
            f"python3 -m sniffle.sniff_receiver -s {port} | wireshark -k -i -\n\n"
            f"# Follow connections on channel 37 only:\n"
            f"python3 -m sniffle.sniff_receiver -s {port} -c 37"
        )

        body = Table(box=None, show_header=False, padding=(0, 0))
        body.add_column()
        body.add_row(hdr)
        body.add_row(Rule(style="dim"))
        body.add_row(Text("Installation", style="bold"))
        body.add_row(Syntax(install_code, "bash", theme="monokai"))
        body.add_row(Rule(style="dim"))
        body.add_row(Text("Manual usage", style="bold"))
        body.add_row(Syntax(usage_code, "bash", theme="monokai"))

        body.add_row(Rule(style="dim"))
        body.add_row(Text("Available options in this tool", style="bold dim"))
        opt_tbl = Table("Option", "Value", "Description", box=None, header_style="bold dim", padding=(0, 1))
        opt_tbl.add_row("mode", "wireshark | pcap | auto", "How to output captured data")
        opt_tbl.add_row("output", "ble_capture.pcap", "PCAP output file (mode=pcap)")
        opt_tbl.add_row("follow", "yes | no", "Follow BLE connections end-to-end")
        opt_tbl.add_row("channel", "37 | 38 | 39 | all", "Primary advertising channel to monitor")
        body.add_row(opt_tbl)

        console.print(
            Panel(
                body,
                title="[bold blue]Sniffle BLE Sniffer — Setup[/bold blue]",
                subtitle="[dim]Set mode=wireshark or mode=pcap after installing sniffle[/dim]",
                border_style="blue",
                padding=(1, 2),
            )
        )

    def _build_sniffle_cmd(self, port, follow: bool, channel: str) -> list[str]:
        """Return the base sniffle command."""
        # sniff_receiver.py lives in python_cli/ (not inside the sniffle package)
        _inject_sniffle_path()
        if _SNIFFLE_CLI_PATH is not None:
            script = str(_SNIFFLE_CLI_PATH / "sniff_receiver.py")
        else:
            # Fallback: hope it's on PATH
            script = "sniff_receiver.py"
        cmd = [sys.executable, script, "-s", str(port)]
        if not follow:
            cmd.append("-a")  # --advonly: passive scan, don't follow connections
        if channel != "all":
            cmd += ["-c", channel]
        return cmd

    def _launch_wireshark(self, port, follow: bool, channel: str) -> None:
        ws_bin = shutil.which("wireshark") or "/Applications/Wireshark.app/Contents/MacOS/Wireshark"
        if not os.path.exists(ws_bin) and not shutil.which("wireshark"):
            UI.error(
                "Wireshark not found in PATH.\n"
                "  Install: [bold]brew install --cask wireshark[/bold]\n"
                "  Or switch to mode=pcap."
            )
            return

        # Always save to a real timestamped PCAP file so data is not lost.
        # Then tail the file into Wireshark stdin for live display.
        ts = time.strftime("%Y%m%d_%H%M%S")
        pcap_path = Path.cwd() / f"ble_capture_{ts}.pcap"

        UI.info(
            f"Launching Wireshark — saving to [bold]{pcap_path.name}[/bold]\n"
            "Close Wireshark or press Ctrl-C here to stop."
        )

        sniffle_env = _sniffle_env()
        cmd_sniffle = self._build_sniffle_cmd(port, follow, channel) + ["-o", str(pcap_path)]

        p_sniffle = None
        p_tail = None
        p_ws = None

        try:
            p_sniffle = subprocess.Popen(cmd_sniffle, env=sniffle_env)

            # Wait until sniff_receiver writes the 24-byte PCAP global header
            deadline = time.time() + 8.0
            while time.time() < deadline:
                if pcap_path.exists() and pcap_path.stat().st_size >= 24:
                    break
                time.sleep(0.1)
            else:
                UI.warn("Timeout waiting for capture to start — check device connection.")
                return

            # tail -c +1 -f: stream the real PCAP file (from byte 1) to Wireshark stdin
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
        except FileNotFoundError as e:
            UI.error(f"Failed to launch process: {e}")
        finally:
            for proc in (p_sniffle, p_tail, p_ws):
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

    def _capture_pcap(self, port, follow: bool, channel: str, output: str) -> None:
        out_path = Path(output).expanduser().resolve()
        UI.info(
            f"Capturing BLE traffic → [bold]{out_path}[/bold]\n"
            "Press Ctrl-C to stop."
        )
        cmd = self._build_sniffle_cmd(port, follow, channel) + ["-o", str(out_path)]

        try:
            proc = subprocess.Popen(cmd, env=_sniffle_env())
            proc.wait()
        except KeyboardInterrupt:
            pass
        except FileNotFoundError as e:
            UI.error(f"Failed to launch sniffle: {e}")
        finally:
            try:
                proc.terminate()
            except Exception:
                pass

        if out_path.exists() and out_path.stat().st_size > 0:
            UI.success(
                f"Capture saved: [bold]{out_path}[/bold] ({out_path.stat().st_size} bytes)\n"
                "Open with Wireshark (BLE PCAP dissector required)."
            )
        else:
            UI.warn("No data captured or file is empty.")
