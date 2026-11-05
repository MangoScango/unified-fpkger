#!/usr/bin/env python3
"""Stage a self-contained, non-Docker release directory from this checkout."""

import argparse
import ast
import re
import shutil
import tempfile
from pathlib import Path

from fetch_dependencies import fetch_all


ROOT = Path(__file__).resolve().parent.parent
RUNTIME_FILES = (
    "RUN.sh",
    "RUN.bat",
    "README.md",
    "LICENSE",
    ".env.example",
    "requirements.txt",
    "build-pkg.py",
    "pfsdump.py",
    "psn_entitlements.py",
)
RUNTIME_DIRECTORIES = ("tools", "web", "another-backporter")
DRAKMOR_SOURCE_FILES = ("scripts/create-gp5-from-folder.py",)


def copy_runtime(staging):
    for name in RUNTIME_FILES:
        shutil.copy2(ROOT / name, staging / name)
    for name in RUNTIME_DIRECTORIES:
        shutil.copytree(
            ROOT / name,
            staging / name,
            ignore=shutil.ignore_patterns(".git", "__pycache__", "*.pyc"),
        )


def copy_drakmor_sources(staging):
    for name in DRAKMOR_SOURCE_FILES:
        target = staging / "drakmor" / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(ROOT / "drakmor" / name, target)


def validate_runtime(staging):
    required = [
        *RUNTIME_FILES,
        "another-backporter/backport-ps5.py",
        "tools/sfo.py",
        "web/server.py",
        "ps_pkg_info/pkg.py",
        "PS4_Fake_PKG_Tools_3/orbis-pub-cmd.exe",
        "drakmor/scripts/create-gp5-from-folder.py",
        "drakmor/prospero-dds2png.exe",
        "drakmor/toolchain/prospero-pub-cmd.exe",
        "entitlements.elf",
    ]
    missing = [name for name in required if not (staging / name).is_file()]
    if missing:
        raise RuntimeError("release is missing required files: " + ", ".join(missing))

    for path in staging.rglob("*.py"):
        with path.open("rb") as handle:
            ast.parse(handle.read(), filename=str(path))
    forbidden = [
        path for path in staging.rglob("*")
        if path.name == "__pycache__" or path.suffix == ".pyc"
    ]
    if forbidden:
        raise RuntimeError(f"release contains cache files: {forbidden[0]}")


def build(version, output_dir):
    """Return the staged release directory named unified-fpkger-<version>."""
    if not re.fullmatch(r"[0-9A-Za-z][0-9A-Za-z._-]*", version):
        raise ValueError(f"invalid release version: {version!r}")
    output_dir.mkdir(parents=True, exist_ok=True)
    name = f"unified-fpkger-{version}"
    target = output_dir / name

    # Build beside the final location so a failed build never replaces a good one.
    with tempfile.TemporaryDirectory(prefix=f".{name}-", dir=output_dir) as temp:
        staging = Path(temp) / name
        staging.mkdir()
        copy_runtime(staging)
        fetch_all(staging)
        # The toolchain archive ships its own GP5 script; the repository copy wins.
        copy_drakmor_sources(staging)
        validate_runtime(staging)

        if target.exists():
            shutil.rmtree(target)
        shutil.move(str(staging), str(target))

    print(f"Release directory: {target}")
    return target


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", default="dev")
    parser.add_argument("--output", type=Path, default=ROOT / "dist")
    args = parser.parse_args()
    build(args.version, args.output.resolve())


if __name__ == "__main__":
    main()
