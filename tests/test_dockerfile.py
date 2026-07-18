"""Guard the Dockerfile against missing local modules.

The Dockerfile copies an explicit file list. When a new top-level module is
added and imported by the app but not copied, the image builds green and then
crash-loops at startup (ModuleNotFoundError) — exactly what happened with
pagination.py in the apiv1-083f171 image. This test fails the build instead.
"""

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def _local_top_level_modules() -> set:
    return {p.stem for p in ROOT.glob("*.py") if p.stem not in {"conftest"}}


def _imported_local_modules() -> set:
    local = _local_top_level_modules()
    sources = [
        ROOT / "main.py",
        ROOT / "dependencies.py",
        *(ROOT / "routers").glob("*.py"),
    ]
    imported = set()
    pattern = re.compile(
        r"^\s*(?:from|import)\s+([A-Za-z_][A-Za-z0-9_]*)", re.MULTILINE
    )
    for src in sources:
        for name in pattern.findall(src.read_text()):
            if name in local:
                imported.add(name)
    return imported


def test_every_imported_local_module_is_copied_into_the_image():
    dockerfile = (ROOT / "Dockerfile").read_text()
    copied = set(
        re.findall(r"^COPY\s+([A-Za-z_][A-Za-z0-9_]*)\.py\b", dockerfile, re.MULTILINE)
    )
    missing = _imported_local_modules() - copied
    assert not missing, (
        f"Modules imported by the app but not copied into the image: {sorted(missing)}. "
        "Add COPY lines to the Dockerfile."
    )
