"""
Attack registry — decoupled from the attacks themselves.

Usage
─────
    from attacks.registry import AttackRegistry

    @AttackRegistry.register
    class MyAttack(BaseAttack):
        ...
"""
from __future__ import annotations

from typing import Dict, List, Optional, Type

from attacks.base import BaseAttack


class AttackRegistry:
    _attacks: Dict[str, Type[BaseAttack]] = {}

    # ── Registration ──────────────────────────────────────────────────────────

    @classmethod
    def register(cls, attack_cls: Type[BaseAttack]) -> Type[BaseAttack]:
        """Register *attack_cls*.  Can be used as a class decorator."""
        if not attack_cls.name:
            raise ValueError(f"{attack_cls.__name__} must define 'name'")
        cls._attacks[attack_cls.name] = attack_cls
        return attack_cls

    # ── Retrieval ─────────────────────────────────────────────────────────────

    @classmethod
    def get(cls, name: str) -> Optional[Type[BaseAttack]]:
        return cls._attacks.get(name)

    @classmethod
    def all(cls) -> List[Type[BaseAttack]]:
        return list(cls._attacks.values())

    @classmethod
    def by_category(cls) -> Dict[str, List[Type[BaseAttack]]]:
        """Return attacks grouped by category."""
        cats: Dict[str, List[Type[BaseAttack]]] = {}
        for atk in cls._attacks.values():
            cats.setdefault(atk.category, []).append(atk)
        return cats
