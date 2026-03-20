"""attacks/ble package — imports all BLE attacks so they self-register."""
from importlib import import_module
from pathlib import Path

_pkg = Path(__file__).parent
for _mod in sorted(_pkg.glob("*.py")):
    if _mod.name not in ("__init__.py",):
        import_module(f"attacks.ble.{_mod.stem}")
