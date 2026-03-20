"""
BaseAttack — abstract base class every attack must inherit from.

Minimal contract to implement a new attack
──────────────────────────────────────────
1. Subclass BaseAttack
2. Set class attributes: name, description, firmware_alias, category
3. Optionally define options = [AttackOption(...), ...]
4. Implement run(device) — your attack logic
5. Register with @AttackRegistry.register  (or place in attacks/<category>/)

Example
───────
from attacks.base import BaseAttack, AttackOption
from attacks.registry import AttackRegistry

@AttackRegistry.register
class MyAttack(BaseAttack):
    name            = "my_attack"
    description     = "Does something cool"
    firmware_alias  = "sniffle"          # catnip firmware alias
    category        = "BLE"
    options = [
        AttackOption("channel", "BLE channel (37-39)", default=37, type=int),
    ]

    def run(self, device) -> None:
        ch = self.get_option("channel")
        # ... attack logic ...
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, List, Optional


@dataclass
class AttackOption:
    """Describes a user-configurable parameter for an attack."""

    name: str
    description: str
    default: Any
    type: type = str
    required: bool = False
    choices: Optional[List[Any]] = None

    def validate(self, value: Any) -> bool:
        if self.choices is not None and value not in self.choices:
            return False
        try:
            self.type(value)
        except (ValueError, TypeError):
            return False
        return True


class BaseAttack(ABC):
    """Abstract base-class for all CatSniffer attacks."""

    # ── Class-level metadata (override in subclasses) ─────────────────────────
    name: str = ""
    description: str = ""
    firmware_alias: str = ""   # catnip alias, e.g. "airtag-spoofer"
    category: str = "generic"  # shown in the menu hierarchy
    options: List[AttackOption] = []

    # ── Instance state ────────────────────────────────────────────────────────

    def __init__(self) -> None:
        self._running = False
        # Build a fresh values dict with defaults
        self._values: dict[str, Any] = {
            opt.name: opt.default for opt in self.__class__.options
        }

    # ── Option management ─────────────────────────────────────────────────────

    def set_option(self, name: str, value: Any) -> bool:
        """Set option *name* to *value*. Returns False if name unknown."""
        opts = {o.name: o for o in self.__class__.options}
        if name not in opts:
            return False
        # Cast to the declared type
        try:
            self._values[name] = opts[name].type(value)
        except (ValueError, TypeError):
            return False
        return True

    def get_option(self, name: str) -> Any:
        return self._values.get(name)

    # ── Info helpers ──────────────────────────────────────────────────────────

    @classmethod
    def info(cls) -> dict[str, Any]:
        return {
            "name": cls.name,
            "description": cls.description,
            "firmware": cls.firmware_alias,
            "category": cls.category,
            "options": cls.options,
        }

    # ── Lifecycle ─────────────────────────────────────────────────────────────

    @abstractmethod
    def run(self, device) -> None:
        """Execute the attack against *device* (a CatSnifferDevice)."""

    def stop(self) -> None:
        """Signal the attack to stop gracefully."""
        self._running = False
