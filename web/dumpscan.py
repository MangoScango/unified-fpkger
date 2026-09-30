"""Finds title dumps under a folder by their param.sfo / param.json.

Every sce_sys/param.sfo (PS4) or sce_sys/param.json (PS5) found is one piece of
content, and what it declares decides what it is: CATEGORY gd* is a base app,
gp* an update, ac an add-on. Pieces are then grouped by the title ID they
declare, so a base, its update and its add-ons come together wherever they sit
and whatever their folders are called.

The param.sfo and param.json readings follow MangoScango/ps-pkg-server
(pkgtool/pkg.py), which in turn mirrors LibOrbisPkg's SFO/ParamSfo.cs.
"""

import json
import os
import re
import struct

SCEC_MAGIC = 0x53434543
SFO_MAGIC = 0x00505346
SFO_UTF8_SPECIAL, SFO_UTF8, SFO_INTEGER = 0x0004, 0x0204, 0x0404
MAX_META_BYTES = 1 << 20


# --- metadata ------------------------------------------------------------------

def parse_sfo(data):
    """A param.sfo blob as {key: value}; ints stay ints. {} when it is not one."""
    start = 0x800 if len(data) >= 4 and struct.unpack_from(">I", data)[0] == SCEC_MAGIC else 0
    if len(data) < start + 0x14 or struct.unpack_from(">I", data, start)[0] != SFO_MAGIC:
        return {}
    key_table, data_table, count = struct.unpack_from("<IIi", data, start + 0x08)
    out = {}
    try:
        for i in range(max(count, 0)):
            key_off, fmt, length, _max, data_off = struct.unpack_from(
                "<HHiII", data, start + 0x14 + i * 0x10)
            kpos = start + key_table + key_off
            end = data.find(b"\0", kpos, kpos + 256)
            name = data[kpos:end if end >= 0 else kpos + 256].decode("utf-8", "replace")
            vpos = start + data_table + data_off
            if fmt == SFO_INTEGER:
                out[name] = struct.unpack_from("<I", data, vpos)[0]
            elif fmt in (SFO_UTF8, SFO_UTF8_SPECIAL):
                raw = data[vpos:vpos + max(length, 0)]
                out[name] = raw.split(b"\0", 1)[0].decode("utf-8", "replace")
    except struct.error:
        pass  # a truncated table: keep what was read
    return out


def read_small(path):
    with open(path, "rb") as handle:
        return handle.read(MAX_META_BYTES)


def read_sfo(path):
    try:
        return parse_sfo(read_small(path))
    except OSError:
        return {}


def read_param_json(path):
    try:
        value = json.loads(read_small(path).decode("utf-8-sig"))
    except (OSError, ValueError):
        return {}
    return value if isinstance(value, dict) else {}


def bcd(major, minor):
    return "%x.%02x" % (major, minor)


def fw_from_u32(value):
    """PS4 SYSTEM_VER, BCD major.minor in the top two bytes (0x09008001 -> 9.00)."""
    if not isinstance(value, int) or not value:
        return None
    return bcd((value >> 24) & 0xFF, (value >> 16) & 0xFF)


def fw_from_hex(value):
    """PS5 requiredSystemSoftwareVersion/sdkVersion ("0x0403000000000000" -> 4.03)."""
    if not isinstance(value, str) or not value:
        return None
    try:
        v = int(value, 16)
    except ValueError:
        return None
    return bcd((v >> 56) & 0xFF, (v >> 48) & 0xFF) if v else None


def ps5_title(param):
    """The default language's titleName, else any language's, else a top-level one."""
    loc = param.get("localizedParameters")
    if isinstance(loc, dict):
        default = loc.get("defaultLanguage")
        entry = loc.get(default) if isinstance(default, str) else None
        if isinstance(entry, dict) and entry.get("titleName"):
            return str(entry["titleName"])
        for entry in loc.values():
            if isinstance(entry, dict) and entry.get("titleName"):
                return str(entry["titleName"])
    return str(param["titleName"]) if param.get("titleName") else None


def title_id_from_content_id(content_id):
    """UP4433-PPSA19639_00-... -> PPSA19639."""
    _head, dash, rest = (content_id or "").partition("-")
    return rest.split("_", 1)[0] if dash else ""


def ps4_role(category):
    """What a PS4 CATEGORY makes a tree: "base", "update" or "addon"."""
    c = (category or "").lower()
    if c.startswith("gp"):
        return "update"
    if c == "ac":
        return "addon"
    return "base"


def ps4_kind(category):
    """PS4 CATEGORY as a label (LibOrbisPkg SfoData types)."""
    c = (category or "").lower()
    if c.startswith("gp"):
        return "Update"
    if c == "ac":
        return "Add-on"
    if c == "gdo":
        return "PS2 Classic"
    if c in ("gd", "gc", "bd"):
        return "Game"
    if c.startswith("gd"):
        return "App"
    return "Unknown"


def version_key(version):
    return tuple(int(n) for n in re.findall(r"\d+", version or ""))


def platform_of(folder):
    """"ps4", "ps5" or None, from which param file sce_sys holds.

    param.sfo wins: PS4 titles can carry a param.json too (a stub holding only
    gameIntent, for instance), while PS5 titles carry no param.sfo.
    """
    sce = os.path.join(folder, "sce_sys")
    if os.path.isfile(os.path.join(sce, "param.sfo")):
        return "ps4"
    if os.path.isfile(os.path.join(sce, "param.json")):
        return "ps5"
    return None


def read_meta(folder):
    """One tree's identity from its sce_sys/param.sfo or param.json, else None."""
    sce = os.path.join(folder, "sce_sys")
    json_path, sfo_path = os.path.join(sce, "param.json"), os.path.join(sce, "param.sfo")
    meta = {"path": folder, "icon": os.path.isfile(os.path.join(sce, "icon0.png")),
            "sdk": None, "notes": []}
    platform = platform_of(folder)
    if platform == "ps5":
        param = read_param_json(json_path)
        content_id = param.get("contentId") or None
        category = param.get("applicationCategoryType")
        meta.update(
            platform="ps5", role="base", title=ps5_title(param), content_id=content_id,
            title_id=param.get("titleId") or title_id_from_content_id(content_id) or None,
            version=param.get("contentVersion") or param.get("masterVersion") or None,
            category=category,
            kind="Game" if category == 0 else ("App" if category is not None else "Unknown"),
            fw=fw_from_hex(param.get("requiredSystemSoftwareVersion")),
            sdk=fw_from_hex(param.get("sdkVersion")))
        if not param:
            meta["notes"].append("param.json could not be read")
    elif platform == "ps4":
        sfo = read_sfo(sfo_path)
        content_id = sfo.get("CONTENT_ID") or None
        category = sfo.get("CATEGORY") or None
        meta.update(
            platform="ps4", role=ps4_role(category), title=sfo.get("TITLE") or None,
            content_id=content_id,
            title_id=sfo.get("TITLE_ID") or title_id_from_content_id(content_id) or None,
            version=sfo.get("APP_VER") or sfo.get("VERSION") or None,
            category=category, kind=ps4_kind(category),
            fw=fw_from_u32(sfo.get("SYSTEM_VER")))
        if not sfo:
            meta["notes"].append("param.sfo could not be read")
        if meta["role"] == "base" and not os.path.isfile(os.path.join(folder, "eboot.bin")):
            meta["notes"].append("no eboot.bin")
        # backport-sdk.py's <TITLE>-bp output carries the dump's param.sfo
        # unmodified next to only the executables it restamped, so its sfo reads
        # as a base. A dump's sce_sys always holds more than param.sfo.
        # build-fpkg has no way to build from such a folder yet (--base-pkg
        # regenerates it from the -app dump), so it is marked and left out.
        if meta["role"] == "base":
            try:
                only_sfo = os.listdir(sce) == ["param.sfo"]
            except OSError:
                only_sfo = False
            if only_sfo:
                meta["role"] = "backport"
    else:
        return None
    return meta


# --- scanning ------------------------------------------------------------------

def find_trees(root, depth, limit):
    """Metadata of every tree at or under root that has a sce_sys param file.

    depth is how many folders below root a tree may sit. A tree is not searched
    inside, and symlinked folders are not followed, so the walk stays in root.
    Returns (trees, truncated).
    """
    trees = []

    def visit(folder, level):
        if len(trees) >= limit:
            return
        meta = read_meta(folder)
        if meta:
            trees.append(meta)
            return
        # sce_sys without a param file is nothing buildable; a title's own
        # folders are not searched for more titles either way.
        if level >= depth or os.path.isdir(os.path.join(folder, "sce_sys")):
            return
        try:
            children = sorted((e for e in os.scandir(folder)
                               if not e.name.startswith(".") and e.is_dir(follow_symlinks=False)),
                              key=lambda e: e.name.lower())
        except OSError:
            return
        for child in children:
            visit(child.path, level + 1)

    visit(root, 0)
    return trees, len(trees) >= limit


def group(trees):
    """Buildable units from the trees found.

    PS4: each base collects the updates and add-ons declaring its title ID.
    Add-ons with no base found form an add-on only unit, which build-fpkg can
    build alone; updates with no base are listed but cannot be built. PS5: each
    tree is its own unit, since build-ps5 builds one folder.
    """
    units = []
    by_title = {}
    for tree in trees:
        if tree["role"] == "backport":
            continue
        if tree["platform"] == "ps5":
            units.append(unit(tree, [], []))
        else:
            by_title.setdefault(tree["title_id"] or tree["path"], []).append(tree)
    for title_id, members in by_title.items():
        bases = [t for t in members if t["role"] == "base"]
        updates = sorted((t for t in members if t["role"] == "update"),
                         key=lambda t: version_key(t["version"]), reverse=True)
        addons = sorted((t for t in members if t["role"] == "addon"),
                        key=lambda t: (t["title"] or t["content_id"] or t["path"]).lower())
        for base in bases:
            u = unit(base, updates, addons)
            if len(bases) > 1:
                u["notes"].append(f"{len(bases)} base dumps declare {title_id}; "
                                  "its update and add-ons are offered to each")
            units.append(u)
        if not bases and addons:
            units.append(unit(None, updates, addons))
        elif not bases:
            units.append(unit(None, updates, []))
    units.sort(key=lambda u: ((u["title"] or u["title_id"] or u["id"]).lower(), u["id"]))
    return units


def unit(base, updates, addons):
    lead = base or (addons or updates)[0]
    notes = list(base["notes"]) if base else []
    buildable = not base or "no eboot.bin" not in notes
    if base is None and not addons:
        buildable = False
        notes.append("an update needs its base dump to build")
    elif base is None:
        notes.append("no base dump declares this title ID; only the add-ons build")
    icon_from = next((t for t in [base, *updates, *addons] if t and t["icon"]), None)
    return {
        "id": base["path"] if base else "title:" + (lead["title_id"] or lead["path"]),
        "platform": lead["platform"],
        "title": lead["title"] or next((t["title"] for t in updates + addons if t["title"]), None),
        "title_id": lead["title_id"], "content_id": base["content_id"] if base else None,
        "kind": base["kind"] if base else ("Add-ons" if addons else "Update"),
        "version": base["version"] if base else None,
        "fw": base["fw"] if base else None, "sdk": base["sdk"] if base else None,
        "icon": icon_from["path"] if icon_from else None,
        "base": base, "updates": updates, "addons": addons,
        "buildable": buildable, "notes": notes,
    }


def scan(root, depth=4, limit=2000):
    """(units, trees_found, truncated) for everything at or under root."""
    trees, truncated = find_trees(root, depth, limit)
    return group(trees), len(trees), truncated
