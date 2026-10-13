"""Split a dlc_emu-based PS5 dump into a clean base plus per-DLC add-on trees.

drakmor's dlc_emu replacement modules serve DLC to a game from a dlc_emu.ini
in the app tree: each [PSAC] section names a content_id, an entitlement_key
and a mount_point (such as /app0/dlc00) whose folder inside the app tree
holds the DLC payload. A rebuild undoes that layout: each mounted folder
becomes its own add-on tree <content-id>-ac under the sibling <title>-dlc
folder pfsdump also writes, with its sce_sys restored from the DLC's retail
SC package (sc-overlay.py) and the ini's entitlement key saved as
entitlement_key.dat. The base tree loses the DLC folders, the dlc_emu
fakelibs and the ini itself, so a rescan sees a normal base plus add-ons.
"""

import os
import re
import shutil
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
SC_OVERLAY = os.path.join(os.path.dirname(HERE), "sc-overlay.py")

INI_NAME = "dlc_emu.ini"
INI_MAX_BYTES = 64 << 10  # the modules read at most 32 KiB; allow for edits
CONTENT_ID_LEN = 36
KEY_RE = re.compile(r"[0-9A-Fa-f]{32}")
# The modules dlc_emu replaces.
FAKELIBS = {"libsce" + name + "." + ext
            for name in ("appcontent", "npentitlementaccess", "gameupdate")
            for ext in ("prx", "sprx")}


class SplitError(Exception):
    """A split step failed in a way worth reporting to the user."""


def parse_ini(text):
    """[(section, {key: value})] keeping repeated sections.

    configparser merges duplicate [PSAC] sections, and a multi-DLC ini is
    nothing but, so this walks the lines itself. Keys fold to lowercase.
    """
    sections = []
    values = None
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith(("#", ";")):
            continue
        if line.startswith("[") and line.endswith("]"):
            values = {}
            sections.append((line[1:-1].strip(), values))
        elif values is not None and "=" in line:
            key, _, value = line.partition("=")
            values[key.strip().lower()] = value.strip()
    return sections


def mount_relative(mount_point):
    """A mount point as a path inside the tree, or None when it leaves /app0."""
    rel = mount_point.lstrip("/")
    head, sep, rest = rel.partition("/")
    if head.lower() != "app0" or not sep:
        return None
    parts = rest.split("/")
    if any(part in ("", ".", "..") for part in parts):
        return None
    return os.path.join(*parts)


def read_entries(tree):
    """The PSAC entries of a tree's dlc_emu.ini; [] when there is none.

    Splittable entries carry files, so they need a mount_point landing inside
    the tree; anything else (a license-only PSAC, a bad key) still shows up,
    with its problems listed, so the caller can show rather than silently drop.
    """
    try:
        with open(os.path.join(tree, INI_NAME), "rb") as handle:
            text = handle.read(INI_MAX_BYTES).decode("utf-8", "replace")
    except OSError:
        return []
    entries = []
    for section, values in parse_ini(text):
        if section.upper() != "PSAC":
            continue
        content_id = values.get("content_id", "")
        mount_point = values.get("mount_point", "")
        key = values.get("entitlement_key", "")
        entry = {
            "content_id": content_id,
            # dlc_emu's own default label: the content ID's final 16 chars.
            "label": (values.get("label") or values.get("entitlement_label")
                      or content_id[-16:]),
            "mount_point": mount_point,
            "mount_rel": mount_relative(mount_point),
            "entitlement_key": key.upper() if KEY_RE.fullmatch(key) else None,
            "problems": [],
        }
        if len(content_id) != CONTENT_ID_LEN:
            entry["problems"].append("content_id must be 36 characters")
        if not mount_point:
            entry["problems"].append("no mount_point, so there is nothing to split")
        elif entry["mount_rel"] is None:
            entry["problems"].append("mount_point is not a folder under /app0")
        elif not os.path.isdir(os.path.join(tree, entry["mount_rel"])):
            entry["problems"].append(f"{entry['mount_rel']} is missing from the dump")
        if key and not entry["entitlement_key"]:
            entry["problems"].append("entitlement_key is not 32 hex digits")
        entries.append(entry)
    return entries


def overlay_default(sc_pkg, ac_dir):
    proc = subprocess.run([sys.executable, SC_OVERLAY, sc_pkg, ac_dir])
    if proc.returncode != 0:
        raise SplitError(f"sc-overlay failed for {sc_pkg} (exit {proc.returncode})")


def clean_base(tree, dlc_root, log):
    """Drop the dlc_emu fakelibs from the base tree and file the ini away."""
    for root, _dirs, files in os.walk(tree):
        for name in files:
            if name.lower() in FAKELIBS:
                path = os.path.join(root, name)
                os.unlink(path)
                log(f"removed dlc_emu fakelib: {path}")
    ini = os.path.join(tree, INI_NAME)
    if os.path.isfile(ini):
        kept = os.path.join(dlc_root, INI_NAME)
        shutil.move(ini, kept)
        log(f"moved {INI_NAME} to {kept}")


def split(tree, title_id, entries, overlay=None, log=print):
    """Move each entry's mount folder into a sibling -dlc tree and restore sce_sys.

    entries are read_entries() dicts narrowed to the ones to split, each with
    its SC package (path or URL) in "sc_pkg". overlay(sc_pkg, ac_dir) defaults
    to running sc-overlay.py; the web server passes one that streams into the
    job log. Returns the new add-on trees.
    """
    overlay = overlay or overlay_default
    parent = os.path.dirname(tree.rstrip(os.sep))
    dlc_root = os.path.join(parent, f"{title_id}-dlc")
    built = []
    for entry in entries:
        src = os.path.join(tree, entry["mount_rel"])
        dest = os.path.join(dlc_root, entry["content_id"] + "-ac")
        if os.path.exists(dest):
            raise SplitError(f"{dest} already exists; move it away or finish it by hand")
        if not os.path.isdir(src):
            raise SplitError(f"the mount folder is missing: {src}")
        os.makedirs(dlc_root, exist_ok=True)
        log(f"moving {src} -> {dest}")
        try:
            os.rename(src, dest)
        except OSError:  # across filesystems
            shutil.move(src, dest)
        os.makedirs(os.path.join(dest, "sce_sys"), exist_ok=True)
        overlay(entry["sc_pkg"], dest)
        key = entry.get("entitlement_key")
        if key:
            with open(os.path.join(dest, "entitlement_key.dat"), "wb") as handle:
                handle.write(bytes.fromhex(key))
            log(f"entitlement key for {entry['content_id']}: {key}")
        built.append(dest)
    clean_base(tree, dlc_root, log)
    return built
