"""attacks package — auto-imports all sub-packages to trigger @register decorators."""

from importlib import import_module
from pathlib import Path

# Walk sub-packages and import them so every @register fires
_pkg_dir = Path(__file__).parent
for _sub in sorted(_pkg_dir.iterdir()):
    if _sub.is_dir() and (_sub / "__init__.py").exists() and _sub.name != "__pycache__":
        import_module(f"attacks.{_sub.name}")
