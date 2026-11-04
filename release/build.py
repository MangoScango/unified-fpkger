#!/usr/bin/env python3
"""Build a self-contained, non-Docker release ZIP from this checkout."""

import argparse
import ast
import json
import os
import re
import shutil
import stat
import tempfile
import zipfile
from pathlib import Path

from fetch_dependencies import CONFIG_PATH, fetch_all, file_hash


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
RUNTIME_DIRECTORIES = ("tools", "web", "another-backporter", "drakmor")
ZIP_TIMESTAMP = (1980, 1, 1, 0, 0, 0)


def copy_runtime(staging):
    for name in RUNTIME_FILES:
        shutil.copy2(ROOT / name, staging / name)
    for name in RUNTIME_DIRECTORIES:
        shutil.copytree(
            ROOT / name,
            staging / name,
            ignore=shutil.ignore_patterns(".git", "__pycache__", "*.pyc"),
        )


def validate_runtime(staging):
    required = [
        *RUNTIME_FILES,
        "another-backporter/backport-ps5.py",
        "tools/sfo.py",
        "web/server.py",
        "ps_pkg_info/pkg.py",
        "PS4_Fake_PKG_Tools_3/orbis-pub-cmd.exe",
        "drakmor/scripts/create-gp5-from-folder.py",
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


def write_manifest(staging, version):
    manifest = {
        "version": version,
        "source_revision": os.environ.get("GITHUB_SHA", "unknown"),
        "dependencies": json.loads(CONFIG_PATH.read_text(encoding="utf-8")),
    }
    (staging / "RELEASE.json").write_text(
        json.dumps(manifest, indent=2) + "\n", encoding="utf-8"
    )


def zip_tree(staging, output):
    """Write a deterministic ZIP while preserving executable permission bits."""
    with zipfile.ZipFile(output, "w") as archive:
        files = sorted(path for path in staging.rglob("*") if path.is_file())
        for path in files:
            name = path.relative_to(staging.parent).as_posix()
            info = zipfile.ZipInfo(name, ZIP_TIMESTAMP)
            info.create_system = 3
            info.external_attr = stat.S_IMODE(path.stat().st_mode) << 16
            info.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(
                info, path.read_bytes(), compress_type=zipfile.ZIP_DEFLATED,
                compresslevel=9,
            )


def build(version, output_dir):
    if not re.fullmatch(r"[0-9A-Za-z][0-9A-Za-z._-]*", version):
        raise ValueError(f"invalid release version: {version!r}")
    output_dir.mkdir(parents=True, exist_ok=True)

    with tempfile.TemporaryDirectory(prefix="fpkger-release-") as temp:
        staging = Path(temp) / f"unified-fpkger-{version}"
        staging.mkdir()
        copy_runtime(staging)
        fetch_all(staging)
        write_manifest(staging, version)
        validate_runtime(staging)

        output = output_dir / f"unified-fpkger-{version}.zip"
        zip_tree(staging, output)

    checksum = file_hash(output)
    checksum_path = output.with_suffix(output.suffix + ".sha256")
    checksum_path.write_text(f"{checksum}  {output.name}\n", encoding="ascii")
    print(f"Release: {output}")
    print(f"SHA-256: {checksum}")
    return output


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", default="dev")
    parser.add_argument("--output", type=Path, default=ROOT / "dist")
    args = parser.parse_args()
    build(args.version, args.output.resolve())


if __name__ == "__main__":
    main()
