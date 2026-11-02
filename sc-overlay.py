#!/usr/bin/env python3
"""Overlay a retail SC package's metadata onto a PS5 dump's sce_sys.

  sc-overlay.py SC_PKG DUMP_DIR
  sc-overlay.py URL DUMP_DIR
  sc-overlay.py --resolve DUMP_DIR

An SC package is the small metadata-only container retail content ships
besides the game image. Its named entries are the sce_sys files (param.json,
icon0.png, playgo-chunk.dat, ...); restoring them fixes dumps that came
without them. Only unencrypted entries are extracted, and the NP-bound files
(npbind.dat, *.ucp, license.dat, license.info) are excluded: they are tied to
the retail package and cannot be reused.

With --resolve, no package is given: the dump's own sce_sys/param.json points
the way. Its versionFileUri's version.xml lists the app's packages by
content_ver; the one matching the dump's contentVersion has a manifest whose
pieces include the SC package, and its URL is printed. build-pkg.py uses this
to find the SC package itself instead of asking for one.

Existing dump files are replaced; the SC is the retail source of truth.
"""

import json
import os
import shutil
import sys
import tempfile
import urllib.request
from urllib.parse import urlparse
import ssl
import xml.etree.ElementTree

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from ps_pkg_info import pkg as pkgmod  # noqa: E402

EXCLUDED_BASENAMES = {"npbind.dat", "license.dat", "license.info"}
EXCLUDED_SUFFIX = ".ucp"


def die(message):
    sys.exit(f"error: {message}")


def ssl_context(url):
    """playstation.net's chain does not verify everywhere; it is Sony's CDN."""
    if urlparse(url).hostname.endswith("playstation.net"):
        return ssl._create_unverified_context()
    return ssl.create_default_context()


def fetch(url):
    """One URL's body, or raise."""
    with urllib.request.urlopen(url, context=ssl_context(url),
                                timeout=30) as response:
        return response.read()


def resolve_param(param):
    """(sc_url, reason) for the SC package matching a param.json's version.

    The app_tag packages in the version.xml versionFileUri points to are keyed
    by content_ver; only the one equal to the dump's contentVersion describes
    this build, so anything else is no match. reason explains a None return.
    """
    uri = (param.get("versionFileUri") or "").strip()
    if not uri:
        return None, "param.json has no versionFileUri"
    version = param.get("contentVersion") or ""
    if not version:
        return None, "param.json has no contentVersion"
    try:
        root = xml.etree.ElementTree.fromstring(fetch(uri))
    except Exception as err:
        return None, f"could not fetch version.xml: {err}"
    manifests = [package.get("manifest_url")
                 for package in root.findall("app_tag/package")
                 if package.get("content_ver") == version
                 and package.get("manifest_url")]
    if not manifests:
        return None, f"version.xml has no app package at version {version}"
    try:
        manifest = json.loads(fetch(manifests[0]).decode("utf-8"))
    except Exception as err:
        return None, f"could not fetch the package manifest: {err}"
    for piece in manifest.get("pieces") or []:
        url = piece.get("url") or ""
        if url.endswith("_sc.pkg"):
            return url, None
    return None, "the package manifest has no _sc.pkg piece"


def resolve(param_json_path):
    """resolve_param for a param.json on disk."""
    try:
        with open(param_json_path, encoding="utf-8-sig") as fh:
            param = json.load(fh)
    except (OSError, ValueError):
        return None, "no readable param.json"
    return resolve_param(param)


def materialize(source):
    """(local path, is_temp) for a path or http(s) URL."""
    if source.startswith(("http://", "https://")):
        tmp = tempfile.NamedTemporaryFile(prefix="sc-overlay-", suffix=".pkg",
                                          delete=False)
        try:
            with urllib.request.urlopen(source,
                                        context=ssl_context(source)) as response:
                shutil.copyfileobj(response, tmp)
        except Exception:
            os.unlink(tmp.name)
            raise
        tmp.close()
        return tmp.name, True
    return source, False


def entry_names(pkg):
    """entry id -> name from the entry-names table (0x200)."""
    names_entry = pkg.entries.get(pkgmod.ENTRY_ENTRY_NAMES)
    if names_entry is None:
        return {}
    blob = pkg._source.read(names_entry.offset, names_entry.size)
    table = {}
    for entry_id, entry in pkg.entries.items():
        end = blob.find(b"\x00", entry.name_offset)
        if end != -1 and end > entry.name_offset:
            table[entry_id] = blob[entry.name_offset:end].decode("utf-8", "replace")
    return table


def check_title(pkg, sce_sys):
    """Warn when the SC package is for a different title than the dump."""
    try:
        with open(os.path.join(sce_sys, "param.json"), encoding="utf-8-sig") as fh:
            dump_id = json.load(fh).get("contentId", "")
    except (OSError, ValueError):
        return
    dump_title = pkgmod.title_id_from_content_id(dump_id)
    if dump_title and pkg.title_id and dump_title != pkg.title_id:
        print(f"warning: SC package is for {pkg.title_id} but the dump is "
              f"{dump_title}; overlaying anyway")


def overlay(pkg, sce_sys):
    names = entry_names(pkg)
    written = skipped = 0
    for entry_id, entry in sorted(pkg.entries.items(), key=lambda kv: kv[1].index):
        name = names.get(entry_id)
        if not name:
            continue  # digests, keys and other unnamed housekeeping entries
        parts = name.split("/")
        if name.startswith("/") or ".." in parts or any(not p for p in parts):
            die(f"refusing unsafe entry name: {name!r}")
        base = parts[-1]
        if base in EXCLUDED_BASENAMES or base.lower().endswith(EXCLUDED_SUFFIX):
            skipped += 1
            continue
        if entry.encrypted:
            print(f"warning: skipping encrypted entry: {name}")
            skipped += 1
            continue
        dest = os.path.join(sce_sys, *parts)
        os.makedirs(os.path.dirname(dest), exist_ok=True)
        data = pkg.read_entry(entry_id)
        verb = "overwrote" if os.path.exists(dest) else "wrote"
        with open(dest, "wb") as fh:
            fh.write(data)
        print(f"{verb} sce_sys/{name} ({len(data)} bytes)")
        written += 1
    return written, skipped


def main():
    if len(sys.argv) == 3 and sys.argv[1] == "--resolve":
        param_path = os.path.join(sys.argv[2], "sce_sys", "param.json")
        url, reason = resolve(param_path)
        if url is None:
            die(f"no SC package match for {sys.argv[2]}: {reason}")
        print(url)
        return
    if len(sys.argv) != 3:
        die(f"usage: {os.path.basename(sys.argv[0])} SC_PKG_OR_URL DUMP_DIR\n"
            f"       {os.path.basename(sys.argv[0])} --resolve DUMP_DIR")
    source, dump_dir = sys.argv[1], sys.argv[2]
    sce_sys = os.path.join(dump_dir, "sce_sys")
    if not os.path.isdir(sce_sys):
        die(f"not a dump tree, no sce_sys: {dump_dir}")
    try:
        path, is_temp = materialize(source)
    except OSError as err:
        die(f"could not fetch {source}: {err}")
    try:
        try:
            pkg = pkgmod.Pkg.open(path)
        except pkgmod.PkgError as err:
            die(f"could not parse {source}: {err}")
        with pkg:
            if pkg.container != "CNT":
                print(f"warning: {os.path.basename(source)} is a full {pkg.container} "
                      "image, not an SC package; only its unencrypted named "
                      "entries can be restored")
            check_title(pkg, sce_sys)
            written, skipped = overlay(pkg, sce_sys)
    finally:
        if is_temp:
            os.unlink(path)
    if not written:
        die("the SC package had nothing usable to restore")
    print(f"restored {written} file(s) into {sce_sys} ({skipped} excluded)")


if __name__ == "__main__":
    main()
