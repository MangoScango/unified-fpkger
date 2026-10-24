"""Split a dlc_emu-based PS5 dump into a clean base plus per-DLC add-on trees.

drakmor's dlc_emu replacement modules serve DLC to a game from a dlc_emu.ini
in the app tree. Each [PSAC] section names a content_id, an entitlement_key
and a mount_point (such as /app0/dlc00) whose folder inside the app tree
holds the DLC payload; each [PSAL] section names only a content_id (and maybe
an entitlement_key), serving a license with no files at all.

A rebuild undoes that layout: each PSAC mount folder becomes its own add-on
tree <content-id>-ac under the sibling <title>-dlc folder pfsdump also writes,
with its sce_sys restored from the DLC's retail SC package (sc-overlay.py).
Each PSAL section becomes a metadata-only <content-id>-al tree, its metadata
taken from the first source that works: a supplied SC package, the SC package
the base param.json's version.xml points to (an AL listing whose content is
really AC), or the PSN store's name and icon (psn_entitlements.py), queried in
the region the content ID's prefix belongs to. Entitlements no store carries
still get a bare unlocker named after their ini label. Either way the ini's
entitlement key is saved as entitlement_key.dat. The base tree loses the DLC
folders, the dlc_emu fakelibs and the ini itself, so a rescan sees a normal
base plus add-ons.
"""

import os
import re
import shutil
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import psn_entitlements  # noqa: E402

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
    """The PSAC and PSAL entries of a tree's dlc_emu.ini; [] when there is none.

    Splittable PSAC entries carry files, so they need a mount_point landing
    inside the tree; anything else (a bad key, a missing folder) still shows
    up, with its problems listed, so the caller can show rather than silently
    drop. PSAL entries are license-only: no mount_point, no files to check.
    """
    try:
        with open(os.path.join(tree, INI_NAME), "rb") as handle:
            text = handle.read(INI_MAX_BYTES).decode("utf-8", "replace")
    except OSError:
        return []
    entries = []
    for section, values in parse_ini(text):
        kind = {"PSAC": "ac", "PSAL": "al"}.get(section.upper())
        if kind is None:
            continue
        content_id = values.get("content_id", "")
        mount_point = values.get("mount_point", "") if kind == "ac" else ""
        key = values.get("entitlement_key", "")
        entry = {
            "content_id": content_id,
            "kind": kind,
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
        if kind == "ac":
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


def al_metadata(tree, title_id, entry, dest, cache, overlay, log):
    """Write an AL entry's metadata into dest's sce_sys.

    AL entries ship no files, so the metadata comes from the first source that
    works: a caller-supplied SC package, the SC package the base param.json's
    version.xml links through its ac_tag manifests (an AL listing whose
    content is really AC), or the PSN store's name and icon. Entitlements that
    were never sold (pre-order and edition bonuses) are in no store catalog;
    those still get an unlocker, named after the ini label, just without a
    store title or icon. cache carries the version.xml map and the store
    pages (keyed by region) across a split's entries.
    """
    content_id = entry["content_id"]
    sc_pkg = entry.get("sc_pkg") or ""
    if sc_pkg:
        log(f"{content_id}: restoring sce_sys from the supplied SC package")
        overlay(sc_pkg, dest)
        return
    if "manifests" not in cache:
        manifests = {}
        uri = psn_entitlements.version_file_uri(
            os.path.join(tree, "sce_sys", "param.json"))
        if uri:
            try:
                manifests = psn_entitlements.fetch_ac_manifests(uri)
            except RuntimeError as err:
                log(f"warning: {err}")
        cache["manifests"] = manifests
    manifest = cache["manifests"].get(content_id)
    if manifest:
        try:
            url = psn_entitlements.sc_pkg_url(manifest)
        except RuntimeError as err:
            log(f"warning: {err}")
        else:
            log(f"{content_id}: restoring sce_sys from the version.xml SC package")
            overlay(url, dest)
            return
    store = cache.setdefault("store", {})
    region, language = psn_entitlements.region_for_content_id(content_id)
    if region not in store:
        try:
            store[region] = {row[0]: row for row in
                             psn_entitlements.fetch_addons(title_id, region,
                                                           language)}
        except RuntimeError as err:
            log(f"warning: {err}")
            store[region] = {}
    found = store[region].get(content_id)
    if found:
        _cid, title, icon_url, store_title_id = found
        log(f"{content_id}: metadata from the PSN store ({title})")
        try:
            psn_entitlements.write_unlocker(dest, content_id, store_title_id,
                                            title, icon_url, log)
        except RuntimeError as err:
            raise SplitError(str(err)) from None
        return
    log(f"{content_id}: no metadata found; writing a bare unlocker")
    try:
        psn_entitlements.write_unlocker(dest, content_id, title_id,
                                        entry["label"], "", log)
    except RuntimeError as err:
        raise SplitError(str(err)) from None


def split(tree, title_id, entries, overlay=None, log=print):
    """Move/create each entry's add-on tree in a sibling -dlc folder.

    entries are read_entries() dicts narrowed to the ones to split. PSAC
    entries move their mount folder into <content-id>-ac; PSAL entries create
    a metadata-only <content-id>-al (see al_metadata). Either way "sc_pkg"
    (path or URL) is overlaid when given, with overlay(sc_pkg, dir) defaulting
    to running sc-overlay.py; the web server passes one that streams into the
    job log. Returns the new add-on trees.
    """
    overlay = overlay or overlay_default
    parent = os.path.dirname(tree.rstrip(os.sep))
    dlc_root = os.path.join(parent, f"{title_id}-dlc")
    cache = {}
    built = []
    for entry in entries:
        dest = os.path.join(dlc_root, entry["content_id"] + "-" + entry["kind"])
        if os.path.exists(dest):
            raise SplitError(f"{dest} already exists; move it away or finish it by hand")
        os.makedirs(dlc_root, exist_ok=True)
        if entry["kind"] == "al":
            os.makedirs(os.path.join(dest, "sce_sys"), exist_ok=True)
            al_metadata(tree, title_id, entry, dest, cache, overlay, log)
        else:
            src = os.path.join(tree, entry["mount_rel"])
            if not os.path.isdir(src):
                raise SplitError(f"the mount folder is missing: {src}")
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
