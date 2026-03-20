"""
Shared Rich UI helpers — used by the menu and attacks.
"""
from __future__ import annotations

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich import box
from rich.style import Style
from rich.text import Text

from config import TOOLKIT_NAME, TOOLKIT_VERSION

console = Console()

# ── Styles ────────────────────────────────────────────────────────────────────

STYLE_SUCCESS = Style(color="green", bold=True)
STYLE_WARNING = Style(color="yellow", bold=True)
STYLE_ERROR   = Style(color="red",   bold=True)
STYLE_INFO    = Style(color="cyan")
STYLE_DIM     = Style(dim=True)

# ── Convenience printers ──────────────────────────────────────────────────────


def success(msg: str) -> None:
    console.print(f"[green]✓[/green]  {msg}")


def warn(msg: str) -> None:
    console.print(f"[yellow]⚠[/yellow]  {msg}")


def error(msg: str) -> None:
    console.print(f"[red]✗[/red]  {msg}")


def info(msg: str) -> None:
    console.print(f"[cyan]ℹ[/cyan]  {msg}")


def separator() -> None:
    console.print("[dim]" + "─" * 60 + "[/dim]")


# ── Header ────────────────────────────────────────────────────────────────────

_ASCII = r"""
   /\_____/\
  /  o   o  \    CatSniffer Toolkit
 ( ==  ^  == )
  )         (
 (           )
( (  )   (  ) )
(__(__)___(__)__)"""


def print_banner() -> None:
    console.print(
        Panel(
            f"[cyan bold]{_ASCII}[/cyan bold]\n"
            f"\n  [bold white]{TOOLKIT_NAME}[/bold white]  "
            f"[dim]v{TOOLKIT_VERSION}[/dim]\n"
            f"  [dim]Modular IoT attack toolkit for CatSniffer hardware[/dim]",
            border_style="cyan",
            padding=(0, 2),
        )
    )


# ── Device table ──────────────────────────────────────────────────────────────


def print_devices(devices: list) -> None:
    if not devices:
        from core.device import is_in_bootloader_mode
        if is_in_bootloader_mode():
            warn(
                "CatSniffer detected in [bold]RP2040 bootloader / UF2 mode[/bold] — "
                "no serial ports are exposed in this state."
            )
            console.print(
                "  [dim]Press the [white]Reset[/white] button (or re-plug without "
                "holding BOOT) so the bridge firmware starts, then retry.[/dim]"
            )
        else:
            warn("No CatSniffer devices detected. Connect your device and retry.")
        return

    t = Table(title=f"Found {len(devices)} CatSniffer device(s)", box=box.ROUNDED)
    t.add_column("ID", style="cyan bold", justify="center")
    t.add_column("Bridge (CC1352)", style="white")
    t.add_column("LoRa (SX1262)", style="white")
    t.add_column("Shell (Config)", style="white")

    for dev in devices:
        t.add_row(
            str(dev.device_id),
            dev.bridge_port or "[dim]—[/dim]",
            dev.lora_port or "[dim]—[/dim]",
            dev.shell_port or "[dim]—[/dim]",
        )
    console.print(t)
