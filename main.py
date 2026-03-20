#!/usr/bin/env python3
"""
CatSneeze_toolkit — entry point.  *ACHOO!*

Usage
─────
  python main.py            # interactive menu
  python main.py run airtag_spoofer          [--device 1]
  python main.py list
  python main.py devices
"""
from __future__ import annotations

import sys
from pathlib import Path

import click

# ── Make the repo root importable regardless of cwd ──────────────────────────
sys.path.insert(0, str(Path(__file__).parent))


# ── CLI ───────────────────────────────────────────────────────────────────────


@click.group(invoke_without_command=True, context_settings={"help_option_names": ["-h", "--help"]})
@click.pass_context
def cli(ctx: click.Context) -> None:
    """CatSneeze_toolkit — modular IoT sniffing framework. *achoo!*"""
    if ctx.invoked_subcommand is None:
        # No sub-command → launch interactive menu
        from shell import run_menu
        run_menu()


@cli.command("list")
def cmd_list() -> None:
    """List all available attacks."""
    import attacks  # noqa: F401 — trigger registrations

    from attacks.registry import AttackRegistry
    from rich.console import Console
    from rich.table import Table
    from rich import box

    console = Console()
    by_cat = AttackRegistry.by_category()

    for cat, atks in sorted(by_cat.items()):
        t = Table(title=f"[bold]{cat}[/bold]", box=box.ROUNDED, show_lines=False)
        t.add_column("Name", style="green bold")
        t.add_column("Firmware", style="cyan")
        t.add_column("Description", style="dim")
        for atk in atks:
            t.add_row(atk.name, atk.firmware_alias or "—", atk.description)
        console.print(t)
        console.print()


@cli.command("devices")
def cmd_devices() -> None:
    """Scan for connected CatSniffer devices."""
    from core.device import detect_devices
    from core.ui import print_devices
    print_devices(detect_devices())


@cli.command("run")
@click.argument("attack_name")
@click.option("--device", "-d", default=None, type=int, help="Device ID (default: first found)")
@click.option("--set", "-s", "opts", multiple=True, metavar="KEY=VALUE",
              help="Set attack option, e.g. --set baud=9600")
def cmd_run(attack_name: str, device: int | None, opts: tuple[str, ...]) -> None:
    """Run an attack directly (non-interactive)."""
    import attacks  # noqa: F401

    from attacks.registry import AttackRegistry
    from core.device import get_device
    from core import ui as UI

    atk_cls = AttackRegistry.get(attack_name)
    if atk_cls is None:
        UI.error(f"Attack '{attack_name}' not found. Run 'list' to see available attacks.")
        sys.exit(1)

    dev = get_device(device)
    if dev is None:
        UI.error("No CatSniffer device found!")
        sys.exit(1)

    instance = atk_cls()

    for kv in opts:
        if "=" not in kv:
            UI.warn(f"Skipping malformed option: {kv}")
            continue
        key, _, val = kv.partition("=")
        if not instance.set_option(key.strip(), val.strip()):
            UI.warn(f"Unknown or invalid option: {key}")

    try:
        instance.run(dev)
    except KeyboardInterrupt:
        instance.stop()


def main() -> None:
    cli()


if __name__ == "__main__":
    main()
