"""
Interactive menu shell.

Navigation model
────────────────
  Main menu
    └─ Category (BLE / Zigbee / LoRa / …)
         └─ Attack detail  →  configure options  →  run
"""
from __future__ import annotations

from typing import Optional, Type

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich import box
from rich.prompt import Prompt, Confirm

import attacks  # noqa: F401 — triggers all @register decorators
from attacks.base import BaseAttack
from attacks.registry import AttackRegistry
from core.device import CatSnifferDevice, detect_devices
from core import ui as UI

console = Console()


# ─────────────────────────────────────────────────────────────────────────────
# Helper printers
# ─────────────────────────────────────────────────────────────────────────────


def _prompt(label: str = "> ") -> str:
    return Prompt.ask(f"[bold magenta]{label}[/bold magenta]").strip()


def _back_or_quit(choice: str) -> bool:
    return choice.lower() in ("b", "q", "back", "quit", "exit")


def _section(title: str) -> None:
    console.print()
    console.print(f"[bold cyan]{'─' * 4} {title} {'─' * 4}[/bold cyan]")
    console.print()


# ─────────────────────────────────────────────────────────────────────────────
# Device selection
# ─────────────────────────────────────────────────────────────────────────────


def _select_device() -> Optional[CatSnifferDevice]:
    devices = detect_devices()
    if not devices:
        UI.warn("No CatSniffer detected. Plug it in and try again.")
        return None
    if len(devices) == 1:
        UI.success(f"Using {devices[0]}  ({devices[0].summary()})")
        return devices[0]

    UI.print_devices(devices)
    choice = _prompt("Select device ID")
    try:
        idx = int(choice)
        for d in devices:
            if d.device_id == idx:
                return d
    except ValueError:
        pass
    UI.warn("Invalid selection.")
    return None


# ─────────────────────────────────────────────────────────────────────────────
# Options screen
# ─────────────────────────────────────────────────────────────────────────────


def _configure_options(instance: BaseAttack) -> None:
    """Interactive option editor for a running attack instance."""
    opts = instance.__class__.options
    if not opts:
        UI.info("This attack has no configurable options.")
        return

    while True:
        _section("Configure Options")

        t = Table(box=box.SIMPLE, show_header=True)
        t.add_column("#", style="dim", justify="right", width=3)
        t.add_column("Option", style="cyan bold")
        t.add_column("Current value", style="green")
        t.add_column("Description", style="dim")

        for i, opt in enumerate(opts, 1):
            val = instance.get_option(opt.name)
            display_val = str(val) if val is not None and val != "" else "[dim]—[/dim]"
            choices_hint = ""
            if opt.choices:
                choices_hint = f"  [dim]({' / '.join(str(c) for c in opt.choices)})[/dim]"
            t.add_row(str(i), opt.name, display_val, opt.description + choices_hint)

        console.print(t)
        console.print("  [dim]\\[b]  back / save[/dim]")
        console.print()

        choice = _prompt("Edit option #")
        if _back_or_quit(choice):
            break

        try:
            idx = int(choice) - 1
            opt = opts[idx]
        except (ValueError, IndexError):
            UI.warn("Invalid selection.")
            continue

        new_val = Prompt.ask(
            f"  [cyan]{opt.name}[/cyan]",
            default=str(instance.get_option(opt.name) or ""),
        )
        if instance.set_option(opt.name, new_val):
            UI.success(f"Set {opt.name} = {new_val}")
        else:
            UI.error(f"Invalid value for {opt.name}")


# ─────────────────────────────────────────────────────────────────────────────
# Attack detail screen
# ─────────────────────────────────────────────────────────────────────────────


def _attack_screen(attack_cls: Type[BaseAttack], device: CatSnifferDevice) -> None:
    instance = attack_cls()

    while True:
        _section(f"Attack: {attack_cls.name}")
        console.print(f"  [white]{attack_cls.description}[/white]")
        console.print(f"  Firmware : [cyan]{attack_cls.firmware_alias or '—'}[/cyan]")
        console.print(f"  Category : [cyan]{attack_cls.category}[/cyan]")
        console.print()
        console.print("  [bold cyan]\\[r][/bold cyan]  run attack")
        console.print("  [bold cyan]\\[o][/bold cyan]  options")
        console.print("  [bold cyan]\\[b][/bold cyan]  back")
        console.print()

        choice = _prompt()

        if choice.lower() == "r":
            console.print()
            try:
                instance.run(device)
            except KeyboardInterrupt:
                instance.stop()
            break

        elif choice.lower() == "o":
            _configure_options(instance)

        elif _back_or_quit(choice):
            break
        else:
            UI.warn("Unknown command.")


# ─────────────────────────────────────────────────────────────────────────────
# Category screen
# ─────────────────────────────────────────────────────────────────────────────


def _category_screen(category: str, device: CatSnifferDevice) -> None:
    attacks_in_cat = AttackRegistry.by_category().get(category, [])

    while True:
        _section(f"Category: {category}")

        t = Table(box=box.SIMPLE, show_header=True)
        t.add_column("#", style="dim", justify="right", width=3)
        t.add_column("Attack", style="bold green")
        t.add_column("Description", style="dim")

        for i, atk in enumerate(attacks_in_cat, 1):
            t.add_row(str(i), atk.name, atk.description)

        console.print(t)
        console.print("  [dim]\\[b]  back[/dim]")
        console.print()

        choice = _prompt()
        if _back_or_quit(choice):
            break

        try:
            idx = int(choice) - 1
            atk_cls = attacks_in_cat[idx]
        except (ValueError, IndexError):
            UI.warn("Invalid selection.")
            continue

        _attack_screen(atk_cls, device)


# ─────────────────────────────────────────────────────────────────────────────
# Main menu
# ─────────────────────────────────────────────────────────────────────────────


def run_menu() -> None:
    UI.print_banner()

    # Device selection at startup (non-blocking — show status either way)
    console.print()
    devices = detect_devices()
    UI.print_devices(devices)
    console.print()

    device: Optional[CatSnifferDevice] = devices[0] if devices else None

    while True:
        _section("Main Menu")

        by_cat = AttackRegistry.by_category()
        categories = sorted(by_cat.keys())

        t = Table(box=box.SIMPLE, show_header=False, show_edge=False)
        t.add_column("key", style="bold cyan", width=5)
        t.add_column("label", style="white")

        for i, cat in enumerate(categories, 1):
            count = len(by_cat[cat])
            t.add_row(f"\\[{i}]", f"{cat}  [dim]({count} attack{'s' if count != 1 else ''})[/dim]")

        t.add_row("\\[d]", "Devices — rescan / select")
        t.add_row("\\[q]", "Quit")

        console.print(t)
        console.print()

        if device:
            console.print(f"  Active device: [cyan]{device}[/cyan]  [dim]{device.summary()}[/dim]")
        else:
            console.print("  [yellow]No device selected — connect your CatSniffer.[/yellow]")
        console.print()

        choice = _prompt()

        if choice.lower() in ("q", "quit", "exit"):
            console.print("\n[dim]Goodbye.[/dim]\n")
            break

        elif choice.lower() in ("d", "devices"):
            devices = detect_devices()
            UI.print_devices(devices)
            device = _select_device()

        else:
            try:
                idx = int(choice) - 1
                cat = categories[idx]
            except (ValueError, IndexError):
                UI.warn("Unknown command — type a number or a key.")
                continue

            if device is None:
                device = _select_device()
                if device is None:
                    continue

            _category_screen(cat, device)
