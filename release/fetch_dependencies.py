#!/usr/bin/env python3
"""Fetch and verify the external runtime dependencies shared by Docker/releases."""

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import tarfile
import tempfile
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path


CONFIG_PATH = Path(__file__).with_name("dependencies.json")
PKGTOOLS_PATCH_OFFSET = 0x3681B


class _DropAuthOnRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        redirected = super().redirect_request(req, fp, code, msg, headers, newurl)
        if redirected is not None:
            old = urllib.parse.urlsplit(req.full_url)
            new = urllib.parse.urlsplit(newurl)
            if (old.scheme, old.netloc) != (new.scheme, new.netloc):
                redirected.remove_header("Authorization")
        return redirected


OPENER = urllib.request.build_opener(_DropAuthOnRedirect)


def file_hash(path):
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _open(url, accept=None):
    headers = {"User-Agent": "unified-fpkger-release"}
    if accept:
        headers["Accept"] = accept
    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    if token and urllib.parse.urlsplit(url).hostname in {"github.com", "api.github.com"}:
        headers["Authorization"] = f"Bearer {token}"
    return OPENER.open(urllib.request.Request(url, headers=headers), timeout=120)


def download(url, destination, expected_sha256, accept=None):
    with _open(url, accept) as response:
        with destination.open("wb") as output:
            shutil.copyfileobj(response, output)
    actual = file_hash(destination)
    if actual != expected_sha256:
        raise RuntimeError(
            f"SHA-256 mismatch for {url}: expected {expected_sha256}, got {actual}"
        )


def download_github_asset(spec, destination):
    """Download a release asset, using the API so private repositories honor the token."""
    repository = spec["repository"]
    tag = urllib.parse.quote(spec["tag"], safe="")
    name = spec["asset"]
    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")

    if not token:
        try:
            download(
                f"https://github.com/{repository}/releases/download/{tag}/"
                f"{urllib.parse.quote(name, safe='')}",
                destination,
                spec["sha256"],
            )
        except urllib.error.HTTPError as error:
            if error.code == 404:
                raise RuntimeError(
                    f"{name} is not publicly downloadable; set GITHUB_TOKEN"
                ) from error
            raise
        return

    try:
        with _open(
            f"https://api.github.com/repos/{repository}/releases/tags/{tag}",
            accept="application/vnd.github+json",
        ) as response:
            release = json.load(response)
    except urllib.error.HTTPError as error:
        raise RuntimeError(
            f"cannot read release {spec['tag']}: HTTP {error.code}"
        ) from error

    asset = next((item for item in release["assets"] if item["name"] == name), None)
    if asset is None:
        available = ", ".join(item["name"] for item in release["assets"]) or "none"
        raise RuntimeError(
            f"{name} is not attached to release {spec['tag']}; available: {available}"
        )
    download(
        f"https://api.github.com/repos/{repository}/releases/assets/{asset['id']}",
        destination,
        spec["sha256"],
        accept="application/octet-stream",
    )


def extract_archive(archive, destination):
    """Extract a pinned GitHub archive without allowing paths outside destination."""
    base = destination.resolve()
    with tarfile.open(archive, "r:gz") as package:
        for member in package.getmembers():
            target = (base / member.name).resolve()
            try:
                target.relative_to(base)
            except ValueError:
                raise RuntimeError(f"unsafe archive path: {member.name}") from None
        package.extractall(destination)
    roots = [path for path in destination.iterdir() if path.is_dir()]
    if len(roots) != 1:
        raise RuntimeError(f"unexpected GitHub archive layout in {archive}")
    return roots[0]


def extract_7z(archive, destination):
    """Extract with the 7-Zip CLI, which handles the archive's BCJ2 filter."""
    executable = next(
        (found for name in ("7zz", "7z", "7za") if (found := shutil.which(name))),
        None,
    )
    if executable is None:
        raise RuntimeError("7-Zip is required to extract the Drakmor toolchain")
    destination.mkdir(parents=True, exist_ok=True)
    subprocess.run(
        [executable, "x", "-y", f"-o{destination}", str(archive)],
        check=True,
        stdout=subprocess.DEVNULL,
    )


def fetch_github(spec, work):
    work.mkdir(parents=True, exist_ok=True)
    archive = work / "source.tar.gz"
    url = f"https://github.com/{spec['repository']}/archive/{spec['ref']}.tar.gz"
    download(url, archive, spec["archive_sha256"])
    source_dir = work / "source"
    source_dir.mkdir()
    return extract_archive(archive, source_dir)


def fetch_drakmor(spec, destination, work):
    archive = work / "drakmor-toolchain.7z"
    download_github_asset(spec, archive)
    extract_7z(archive, destination / "drakmor")
    print(f"drakmor toolchain: {spec['sha256'][:12]}")


def copy_tree(source, destination):
    shutil.copytree(
        source,
        destination,
        ignore=shutil.ignore_patterns(".git", "__pycache__", "*.pyc"),
        dirs_exist_ok=True,
    )


def copy_upstream_licenses(source, destination, name):
    license_dir = destination / "licenses" / name
    for pattern in ("LICENSE*", "COPYING*"):
        for path in source.glob(pattern):
            if path.is_file():
                license_dir.mkdir(parents=True, exist_ok=True)
                shutil.copy2(path, license_dir / path.name)


def patch_orbis(pkgtools_dir, spec):
    """Apply Docker's APP_VER guard patch, verifying input and output hashes."""
    path = pkgtools_dir / "orbis-pub-cmd.exe"
    original = path.read_bytes()
    digest = hashlib.sha256(original).hexdigest()

    if digest == spec["orbis_patched_sha256"]:
        patched = original
    elif digest == spec["orbis_original_sha256"]:
        if original[PKGTOOLS_PATCH_OFFSET:PKGTOOLS_PATCH_OFFSET + 2] != b"\x74\x07":
            raise RuntimeError("orbis-pub-cmd.exe patch guard bytes are not 74 07")
        patched = original[:PKGTOOLS_PATCH_OFFSET] + b"\xEB" + original[
            PKGTOOLS_PATCH_OFFSET + 1:
        ]
    else:
        raise RuntimeError(f"unexpected orbis-pub-cmd.exe SHA-256: {digest}")

    if patched[PKGTOOLS_PATCH_OFFSET:PKGTOOLS_PATCH_OFFSET + 2] != b"\xEB\x07":
        raise RuntimeError("orbis-pub-cmd.exe patch did not produce EB 07")
    actual = hashlib.sha256(patched).hexdigest()
    if actual != spec["orbis_patched_sha256"]:
        raise RuntimeError(f"patched orbis-pub-cmd.exe SHA-256 mismatch: {actual}")
    if patched != original:
        path.write_bytes(patched)


def fetch_all(destination):
    """Populate destination with the pinned runtime dependencies."""
    destination = Path(destination)
    destination.mkdir(parents=True, exist_ok=True)
    config = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))

    with tempfile.TemporaryDirectory(prefix="fpkger-dependencies-") as temp:
        work = Path(temp)

        pkgtools = fetch_github(config["pkgtools"], work / "pkgtools")
        # The dependency archive contains the tools at its root, whereas the
        # runtime expects them beneath PS4_Fake_PKG_Tools_3.
        target = destination / "PS4_Fake_PKG_Tools_3"
        # Materialize first so hashing and patching operate on the final copy.
        copy_tree(pkgtools, target)
        patch_orbis(target, config["pkgtools"])
        copy_upstream_licenses(pkgtools, destination, "PS4-Fake-PKG-Tools")
        print(f"PS4 tools: {config['pkgtools']['ref']} (patched)")

        ps_pkg_info = fetch_github(config["ps_pkg_info"], work / "ps-pkg-info")
        copy_tree(ps_pkg_info / "ps_pkg_info", destination / "ps_pkg_info")
        copy_upstream_licenses(ps_pkg_info, destination, "ps-pkg-info")
        print(f"ps-pkg-info: {config['ps_pkg_info']['ref']}")

        download(
            config["entitlements"]["url"],
            destination / "entitlements.elf",
            config["entitlements"]["sha256"],
        )
        print("entitlements.elf: verified")

        fetch_drakmor(config["drakmor"], destination, work)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("destination", type=Path)
    args = parser.parse_args()
    fetch_all(args.destination)


if __name__ == "__main__":
    main()
