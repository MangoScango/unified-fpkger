#!/usr/bin/env python3
# ----------------------------------------------------------------------------
# backport-sdk.py
# Collect a dump's executables and param.sfo into <TITLEID>-bp, rewriting the
# SDK version stamp in each executable so an older firmware's loader accepts it.
#
# USAGE
#   backport-sdk.py [options] DUMP_DIR
#     -s, --sdk VER     target SDK version, or "auto" (default 0x10790001)
#     -o, --out DIR     where to create <TITLEID>-bp (default: cwd)
#     -n, --dry-run     report what would happen, write nothing
#     -f, --force       restamp even when that would raise the SDK version
#         --keep-version-records
#                       leave PT_SCE_VERSION alone, restamping only the param
#                       segment. The records drive the SYSTEM_VER img_create
#                       writes, so a package built this way still asks for the
#                       firmware the title was built against.
#     -r, --resolve     print the "auto" target for one or more dumps and exit,
#                       so a caller restamping several trees resolves once and
#                       applies the same stamp to each
#         --observed    print the highest SDK stamp the dumps' executables carry
#                       and exit, which is what their param.sfo should ask for
#         --libs        report which system libraries a PS5 title would need
#                       injected to run below its floor, and exit (see below)
#     -v, --verbose     with --libs, list every missing symbol
#         --target VER[,VER...]
#                       with --libs, report these firmware levels instead of
#                       the defaults; repeatable
#         --json FILE   with --libs, also write the full report as JSON
#     -h, --help        this text
#
#   A stamp already at or below the target is left as it is, so a mixed tree can
#   be run through repeatedly without pushing old modules forward.
#
#   "auto" reads the dump's imports and picks the oldest firmware that exports
#   all of them, which is the most portable target the title can take. Imports a
#   module in the dump satisfies itself are not counted; a game bundles its own
#   libc and friends under sce_module.
#
#   It reads the tables build-export-db.py writes, by default from ./docs beside
#   this file and otherwise from $FW_EXPORT_DB. An import no sampled firmware
#   exports is an error rather than a lower floor, because lowering the stamp
#   does not conjure the symbol and the result would not load. Adding a newer
#   firmware dump or naming an explicit --sdk are the ways past it.
#
#   The stamp it emits is the floor's compat level with the point-release digit
#   dropped, so 07.590 becomes 07.500. An explicit --sdk is used exactly as
#   given.
#
# EXIT STATUS
#   0  at least one executable was restamped
#   3  nothing needed lowering
#   1  error
#
#   Executables are eboot.bin and any .elf/.self/.prx/.sprx. Only the ones this
#   actually restamps are written, with their relative paths intact so the result
#   can be dropped back over a staged tree; an executable with no param segment,
#   or already at or below the target, is reported and left out. param.sfo comes
#   along unmodified, for the title id and as a record of what the dump asked
#   for.
#
#   The stamp lives at offset 0x10 of PT_SCE_PROCPARAM (executables) and
#   PT_SCE_MODULE_PARAM (libraries). PT_SCE_VERSION holds a second copy per
#   linked object, and orbis-pub-cmd reads THAT to decide the SYSTEM_VER it
#   writes into the package's param.sfo, so both are lowered or the package ends
#   up demanding the firmware the title was originally built for. Neither edit
#   changes a file's size.
#
#   Imports the target firmware does not export are left alone; --sdk auto
#   refuses a target that would need any.
#
# LIBRARY REQUIREMENTS
#   backport-sdk.py --libs [-v] [--target VER[,VER...]]... [--json FILE] DIR...
#
#   Each DIR is a title if it holds eboot.bin, otherwise a folder of titles one
#   level down. For every target below the title's floor, it lists the firmware
#   imports that target cannot bind, grouped by the sprx file that carries the
#   library and then by library, with who imports them. A library the target
#   lacks entirely has to be supplied whole; one it has only needs its newer
#   exports. Bundled modules are scanned like the eboot, so a sce_module prx
#   that needs a newer libkernel shows up under its own name.
#
#   The default targets are the first release of each major version from 4.00,
#   the lowest the community backports to. The sprx mapping comes from
#   fw-modules.csv beside the other tables.
# ----------------------------------------------------------------------------
import csv
import json
import os
import re
import shutil
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import ps4elf

PT_LOAD = 1
PT_SCE_PROCPARAM = 0x61000001
PT_SCE_MODULE_PARAM = 0x61000002
PT_SCE_VERSION = 0x6FFFFF01

PARAM_NAMES = {PT_SCE_PROCPARAM: 'PT_SCE_PROCPARAM', PT_SCE_MODULE_PARAM: 'PT_SCE_MODULE_PARAM'}
SDK_OFFSET = 0x10
DEFAULT_SDK = 0x10790001
EXEC_SUFFIXES = ('.elf', '.self', '.prx', '.sprx')
SFO_MAGIC = b'\x00PSF'
DB_DIR = os.environ.get('FW_EXPORT_DB',
                        os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                     'docs'))


# libkernel's table of modules a game supplies from /app0/sce_module rather
# than the firmware, each with the first PS5 firmware whose libkernel lists it.
# Read from libkernel.sprx in every dumped firmware, 1.00 through 12.70; the
# table has only grown once. No firmware exports these libraries, so a title
# that imports one without shipping it is not asking the firmware for anything:
# Astro (PPSA01325) needs libSceJobManager, ships no copy, and runs, its seven
# imports left unbound. Re-check the table when adding a firmware dump.
APP_SUPPLIED_MODULES = {
    'libSceFios2': '1.00',
    'libc': '1.00',
    'libSceFace': '1.00',
    'libSceHand': '1.00',
    'libSceSmart': '1.00',
    'libSceS3DConversion': '1.00',
    'libSceHeadTracker': '1.00',
    'libSceFaceTracker': '1.00',
    'libSceHandTracker': '1.00',
    'libSceAudioLatencyEstimation': '1.00',
    'libSceNpToolkit': '1.00',
    'libSceJobManager': '1.00',
    'libSceNpToolkit2': '1.00',
    'libSceNpCppWebApi': '1.00',
    'libScePfs': '1.00',
    'libSceFontGsm': '6.00',
}


def die(msg):
    sys.exit('error: %s' % msg)


def read_sfo(path):
    """param.sfo -> {key: value}. Ints come back as ints, strings as str."""
    d = open(path, 'rb').read()
    if d[:4] != SFO_MAGIC:
        return {}
    key_off, data_off, count = struct.unpack_from('<III', d, 8)
    out = {}
    for i in range(count):
        ko, fmt, length, _, do = struct.unpack_from('<HHIII', d, 0x14 + i * 0x10)
        key = d[key_off + ko:d.index(b'\0', key_off + ko)].decode()
        raw = d[data_off + do:data_off + do + length]
        if fmt == 0x0404:
            out[key] = struct.unpack_from('<I', raw)[0]
        else:
            out[key] = raw.rstrip(b'\0').decode('utf8', 'replace')
    return out


def segments(data):
    phoff, = struct.unpack_from('<Q', data, 32)
    _, phentsize, phnum = struct.unpack_from('<3H', data, 52)
    for i in range(phnum):
        yield struct.unpack_from('<IIQQQQQQ', data, phoff + i * phentsize)


def version_records(data, seg, sdk=None):
    """Per-object SDK versions recorded in PT_SCE_VERSION.

    Each record is a length byte, a "name:" string, then a big-endian u32. The
    length counts the name and the version but not itself.

    Given sdk, lower any record above it in place and return how many moved;
    otherwise return the (name, version) pairs. orbis-pub-cmd reads these rather
    than the param segment to decide the SYSTEM_VER it writes into param.sfo, so
    leaving them behind makes a package demand the firmware the title was built
    for no matter what the param segment says.
    """
    out, lowered = [], 0
    off, end = seg[2], seg[2] + seg[5]
    while off < end:
        length = data[off]
        if length == 0 or off + 1 + length > end:
            break
        at = off + length - 3
        name = data[off + 1:off + length].split(b':')[0].decode('utf8', 'replace')
        ver, = struct.unpack_from('>I', data, at)
        if sdk is None:
            out.append((name, ver))
        elif version_field(ver) > version_field(sdk):
            struct.pack_into('>I', data, at, retarget(ver, sdk))
            lowered += 1
        off += length + 1
    return lowered if sdk is not None else out


def find_content(dump):
    """-> (executables relative to dump, param.sfo path or None)"""
    execs, sfo = [], None
    for root, dirs, files in os.walk(dump):
        dirs.sort()
        for name in sorted(files):
            full = os.path.join(root, name)
            rel = os.path.relpath(full, dump)
            low = name.lower()
            if low == 'param.sfo' and os.path.basename(root) == 'sce_sys':
                sfo = full
            elif low == 'eboot.bin' or low.endswith(EXEC_SUFFIXES):
                execs.append(rel)
    return execs, sfo


def fw_key(name):
    return tuple(int(part) for part in name.split('.'))


def version_field(stamp):
    """The BCD major.minor an SDK stamp names, e.g. 0x08508001 -> 0x0850."""
    return stamp >> 16


def retarget(old, sdk):
    """Give old the version sdk names, keeping its own revision half-word."""
    return (sdk & 0xFFFF0000) | (old & 0x0000FFFF)


def relax_point_release(stamp):
    """Drop the point-release digit from a compat level: 7.59 -> 7.50.

    A PS5's compatibility layer advertises a PS4 system software level set just
    above the newest PS4 release of its era, so the levels are versions PS4
    hardware never shipped: 07.590, 08.540, 10.790. Stamping one verbatim
    demands a PS4 point release that does not exist and gates the title to the
    next minor version for nothing, since the ABI does not move within one.
    Rounding down to the x.x0 boundary lands on a release that shipped and stays
    within the same compat band.
    """
    return stamp & ~0x000F0000


def load_export_db():
    """-> (levels oldest-first, stamp by level, ranges, names, holes)

    ranges maps (library, nid) to (min_fw, max_fw), the oldest and newest
    firmware seen exporting it. Every library a title can link is described, so
    an import absent from ranges is exported by no firmware in the collection.
    """
    levels, stamps = [], {}
    with open(os.path.join(DB_DIR, 'fw-levels.csv')) as fh:
        for row in csv.DictReader(fh):
            levels.append(row['ps5_system_software'])
            stamps[row['ps5_system_software']] = int(row['ps4_stamp'], 16)

    ranges, names = {}, {}
    with open(os.path.join(DB_DIR, 'fw-exports.csv')) as fh:
        for row in csv.DictReader(fh):
            key = (row['library'], row['nid'])
            ranges[key] = (row['min_fw'], row['max_fw'])
            if row['name']:
                names[key] = row['name']


    holes = {}
    path = os.path.join(DB_DIR, 'fw-export-gaps.csv')
    if os.path.exists(path):
        with open(path) as fh:
            for row in csv.DictReader(fh):
                holes[(row['library'], row['nid'])] = row['missing_fw'].split(';')
    return levels, stamps, ranges, names, holes


def observed_sdk(dumps):
    """The highest SDK stamp any executable in the dumps carries.

    This is what the package genuinely requires, as opposed to the SYSTEM_VER its
    param.sfo asks for, which Sony sets from release policy.
    """
    highest = 0
    for dump in dumps:
        execs, _ = find_content(dump)
        for rel in execs:
            data = open(os.path.join(dump, rel), 'rb').read(4)
            if data != b'\x7fELF':
                continue
            module = ps4elf.read(os.path.join(dump, rel))
            if module is None:
                continue
            for stamp in (module.ps4_sdk, module.ps5_sdk):
                if stamp and stamp > highest:
                    highest = stamp
    return highest


def collect_modules(dumps):
    """Parse every executable across the given dumps.

    -> (modules, library names carried as empty files)
    """
    modules, blanked = [], set()
    for dump in dumps:
        execs, _ = find_content(dump)
        for rel in execs:
            full = os.path.join(dump, rel)
            module = ps4elf.read(full)
            if module is not None:
                modules.append(module)
            elif os.path.getsize(full) == 0:
                blanked.add(os.path.basename(rel).rsplit('.', 1)[0])
    return modules, blanked


def choose_sdk(dumps):
    """Pick the oldest firmware that exports everything the dumps import.

    Resolve over every dump at once: a title's base and its update share one
    process, so a symbol the update bundles satisfies the base's import of it.

    -> (stamp, list of report lines)
    """
    levels, stamps, ranges, names, holes = load_export_db()
    rank = {name: i for i, name in enumerate(levels)}
    modules, blanked = collect_modules(dumps)
    if not modules:
        die('no readable executables in %s' % ', '.join(dumps))

    provided, imported = set(), set()
    for module in modules:
        imported |= set(module.imports)
        for library, nids in module.exports.items():
            provided |= {(library, nid) for nid in nids}
    wanted = imported - provided
    # An update can supersede a bundled library and blank the original rather
    # than delete it, leaving the old importer in the tree with nothing to bind
    # to. The console never loads it, and no firmware exports the library, so
    # those imports are not a firmware requirement.
    superseded = sorted({pair for pair in wanted if pair[0] in blanked})
    wanted -= set(superseded)

    def label(pair):
        return names.get(pair) or '%s / %s' % pair

    floor, floor_for = levels[0], None
    ceiling, ceiling_for = levels[-1], None
    beyond, gated = [], []
    for pair in sorted(wanted):
        if pair not in ranges:
            beyond.append(pair)
            continue
        low, high = ranges[pair]
        if rank[low] > rank[floor]:
            floor, floor_for = low, pair
        if rank[high] < rank[ceiling]:
            ceiling, ceiling_for = high, pair
        if pair in holes:
            gated.append((pair, holes[pair]))

    # Only libkernel's own list of game-supplied modules is excused, and a member
    # the list gained later still needs the firmware that added it.
    unshipped = sorted(pair for pair in beyond if pair[0] in APP_SUPPLIED_MODULES)
    beyond = [pair for pair in beyond if pair[0] not in APP_SUPPLIED_MODULES]
    for library in sorted({lib for lib, _ in unshipped}):
        since = APP_SUPPLIED_MODULES[library]
        if rank.get(since, 0) > rank[floor]:
            floor, floor_for = since, (library, '(listed from %s)' % since)

    if beyond:
        known = {library for library, _ in ranges}
        foreign = sorted({library for library, _ in beyond
                          if library not in known})
        if foreign:
            die('%d import(s) come from libraries no firmware provides: %s.\n'
                'A title bundles these under sce_module, so resolve over the '
                'dump that carries them as well.'
                % (len(beyond), ', '.join(foreign[:6])))
        detail = ['  %s / %s' % pair for pair in beyond[:12]]
        if len(beyond) > 12:
            detail.append('  ... and %d more' % (len(beyond) - 12))
        die('%d import(s) are exported by no firmware in the tables, so no '
            'target satisfies this title. The newest sampled is PS5 %s:\n%s\n'
            'Add a newer firmware dump and rerun build-export-db.py, or pass an '
            'explicit --sdk to stamp it anyway.'
            % (len(beyond), levels[-1], '\n'.join(detail)))

    lines = ['%d imports: %d satisfied within the dump, %d from firmware'
             % (len(imported), len(imported) - len(wanted), len(wanted))]
    if unshipped:
        lines.append('%d import(s) of %s ignored: a game-supplied module the '
                     'dump does not ship, so they stay unbound'
                     % (len(unshipped),
                        ', '.join(sorted({lib for lib, _ in unshipped}))))
    if superseded:
        lines.append('%d import(s) of %s ignored: carried as an empty file, so '
                     'an update superseded it'
                     % (len(superseded),
                        ', '.join(sorted({lib for lib, _ in superseded}))))
    lines.append('floor: PS5 %s%s' % (
        floor, '  (%s)' % label(floor_for) if floor_for
        else '  (no import raises it)'))
    if rank[ceiling] < rank[levels[-1]]:
        lines.append('ceiling: PS5 %s  (%s is gone after it)'
                     % (ceiling, label(ceiling_for)))
    if rank[ceiling] < rank[floor]:
        die('no sampled firmware exports every import: floor is %s but %s '
            'is gone after %s' % (floor, label(ceiling_for), ceiling))
    for pair, missing in gated:
        above = [fw for fw in missing if rank.get(fw, -1) >= rank[floor]]
        if above:
            lines.append('%s is missing at %s inside its own range'
                         % (label(pair), ', '.join(above)))

    stamp = relax_point_release(stamps[floor])
    if stamp != stamps[floor]:
        lines.append('stamp 0x%08x relaxed to 0x%08x, a PS4 release that exists'
                     % (stamps[floor], stamp))
    return stamp, lines


def load_module_table():
    """-> {library: [(sprx filename, min_fw, max_fw)]} from fw-modules.csv."""
    path = os.path.join(DB_DIR, 'fw-modules.csv')
    if not os.path.exists(path):
        die('%s is missing; run build-export-db.py' % path)
    table = {}
    with open(path) as fh:
        for row in csv.DictReader(fh):
            table.setdefault(row['library'], []).append(
                (row['module'], row['min_fw'], row['max_fw']))
    return table


# The community has settled on 4.00 as the lowest firmware worth backporting to.
BACKPORT_FLOOR = '4.00'

SELF_MAGICS = {b'\x4f\x15\x3d\x1d': 'PS4 SELF', b'\x54\x14\xf5\xee': 'PS5 SELF'}


def default_targets(levels):
    """The first level of each major version from BACKPORT_FLOOR upward."""
    targets, majors = [], set()
    for level in levels:
        major = fw_key(level)[0]
        if fw_key(level) >= fw_key(BACKPORT_FLOOR) and major not in majors:
            majors.add(major)
            targets.append(level)
    return targets


def index_db(db, module_table):
    """Precompute, per library and per sprx file, the level indices it exists at."""
    levels, _, ranges, _, _ = db
    rank = {name: i for i, name in enumerate(levels)}
    spans = {}
    for (library, _), (low, high) in ranges.items():
        spans.setdefault(library, set()).add((rank[low], rank[high]))
    library_levels = {library: {i for low, high in pairs
                                for i in range(low, high + 1)}
                      for library, pairs in spans.items()}
    module_levels = {}
    for rows in module_table.values():
        for module, low, high in rows:
            module_levels.setdefault(module, set()).update(
                range(rank[low], rank[high] + 1))
    return {'rank': rank, 'library_levels': library_levels,
            'module_levels': module_levels}


def title_imports(title_dir, ranges):
    """Parse a title and sort the imports nothing inside it satisfies.

    -> (modules, importers, unshipped, superseded, unreadable)

    importers and unshipped map (library, nid) to the set of title-relative
    files importing it: unshipped holds game-supplied libraries no firmware
    exports and the title does not carry, importers everything else.
    superseded is the set of libraries carried as empty files, and unreadable
    lists (file, reason) for executables that could not be parsed.
    """
    modules, blanked = collect_modules([title_dir])
    parsed = {module.path for module in modules}
    execs, _ = find_content(title_dir)
    unreadable = []
    for rel in execs:
        full = os.path.join(title_dir, rel)
        if full in parsed or os.path.getsize(full) == 0:
            continue
        with open(full, 'rb') as fh:
            magic = fh.read(4)
        unreadable.append((rel, SELF_MAGICS.get(
            magic, 'unparsable ELF' if magic == b'\x7fELF' else 'not an ELF')))

    provided = set()
    for module in modules:
        for library, nids in module.exports.items():
            provided |= {(library, nid) for nid in nids}
    importers, unshipped, superseded = {}, {}, set()
    for module in modules:
        rel = os.path.relpath(module.path, title_dir)
        for pair in module.imports:
            if pair in provided:
                continue
            if pair[0] in blanked:
                superseded.add(pair[0])
                continue
            bucket = (unshipped if pair not in ranges
                      and pair[0] in APP_SUPPLIED_MODULES else importers)
            bucket.setdefault(pair, set()).add(rel)
    return modules, importers, unshipped, superseded, unreadable


def title_floor(importers, unshipped, db, index=None):
    """The oldest firmware exporting every import, as choose_sdk finds it.

    -> (floor, (library, nid) that set it or None, unresolvable). floor is None
    when some import is exported by no sampled firmware; unresolvable lists
    those. A floor set by the game-supplied list has nid None.
    """
    levels, _, ranges, names, _ = db
    index = index or index_db(db, {})
    rank = index['rank']
    floor, floor_pair, unresolvable = levels[0], None, []
    for pair in sorted(importers):
        if pair not in ranges:
            unresolvable.append({
                'library': pair[0], 'nid': pair[1], 'name': names.get(pair),
                'kind': ('unknown_nid' if pair[0] in index['library_levels']
                         else 'unknown_library'),
                'importers': sorted(importers[pair])})
            continue
        low = ranges[pair][0]
        if rank[low] > rank[floor]:
            floor, floor_pair = low, pair
    for library in sorted({lib for lib, _ in unshipped}):
        since = APP_SUPPLIED_MODULES[library]
        if rank.get(since, 0) > rank[floor]:
            floor, floor_pair = since, (library, None)
    if unresolvable:
        floor = floor_pair = None
    return floor, floor_pair, unresolvable


def _module_key(name):
    return name.lower().replace('.', '_')


def carrier(library, target, module_table, rank):
    """-> (sprx filename a library at target comes from, alternatives)."""
    rows = module_table.get(library)
    if not rows:
        return '?', []
    at = rank[target]
    found = [r for r in rows if rank[r[1]] <= at <= rank[r[2]]]
    if not found:
        later = [r for r in rows if rank[r[1]] > at]
        if later:
            first = min(rank[r[1]] for r in later)
            found = [r for r in later if rank[r[1]] == first]
        else:
            last = max(rank[r[2]] for r in rows)
            found = [r for r in rows if rank[r[2]] == last]
    files = sorted({r[0] for r in found})
    exact = [f for f in files
             if _module_key(f.rsplit('.', 1)[0]) == _module_key(library)]
    primary = exact[0] if exact else min(files, key=lambda f: (len(f), f))
    return primary, [f for f in files if f != primary]


def requirements_at(target, importers, db, module_table, unshipped,
                    index=None, shipped=()):
    """What a title would need injected to run on firmware target.

    shipped names game-supplied libraries the title carries itself.

    -> {"target", "resolved", "missing_symbols", "app_supplied_unlisted",
    "modules": [{"module", "alternatives", "present", "module_since",
    "libraries": [{"library", "status", "library_since", "missing",
    "importers", "symbols": [...]}]}]}
    """
    levels, _, ranges, names, holes = db
    index = index or index_db(db, module_table)
    rank = index['rank']
    at = rank[target]

    libraries = {}
    for pair in sorted(importers):
        if pair not in ranges:
            continue
        low, high = ranges[pair]
        if at < rank[low]:
            reason = 'newer'
        elif at > rank[high]:
            reason = 'removed'
        elif target in holes.get(pair, ()):
            reason = 'gap'
        else:
            continue
        libraries.setdefault(pair[0], []).append({
            'nid': pair[1], 'name': names.get(pair), 'min_fw': low,
            'max_fw': high, 'reason': reason,
            'importers': sorted(importers[pair])})

    modules = {}
    for library, symbols in libraries.items():
        present_at = index['library_levels'].get(library, set())
        symbols.sort(key=lambda s: (s['name'] is None, s['name'] or s['nid']))
        module, alternatives = carrier(library, target, module_table, rank)
        entry = modules.setdefault(module, {
            'module': module, 'alternatives': set(), 'libraries': []})
        entry['alternatives'].update(alternatives)
        entry['libraries'].append({
            'library': library,
            'status': ('missing_exports' if at in present_at
                       else 'missing_library'),
            'library_since': levels[min(present_at)] if present_at else None,
            'missing': len(symbols),
            'importers': sorted(set().union(*(s['importers'] for s in symbols))),
            'symbols': symbols})

    for entry in modules.values():
        held = index['module_levels'].get(entry['module'], set())
        entry['alternatives'] = sorted(entry['alternatives'])
        entry['present'] = at in held
        entry['module_since'] = levels[min(held)] if held else None
        entry['libraries'].sort(key=lambda lib: lib['library'])

    unlisted = sorted(lib for lib in {lib for lib, _ in unshipped} | set(shipped)
                      if rank.get(APP_SUPPLIED_MODULES[lib], 0) > at)
    missing = sum(len(s) for s in libraries.values())
    return {
        'target': target,
        'resolved': not missing and not unlisted
                    and all(pair in ranges for pair in importers),
        'missing_symbols': missing,
        'app_supplied_unlisted': [
            {'library': lib, 'since': APP_SUPPLIED_MODULES[lib],
             'shipped': lib in shipped}
            for lib in unlisted],
        'modules': [modules[m] for m in sorted(modules)],
    }


def bcd_word(word):
    """An SDK word's major.minor, e.g. 0x13000035 -> '13.00'."""
    if word is None:
        return '?'
    return '%x.%02x' % (word >> 24, (word >> 16) & 0xFF)


def param_version(value):
    """A param.json version string such as '0x0602000000000000' -> '6.02'."""
    try:
        top = int(value, 16) >> 48
    except (TypeError, ValueError):
        return '?'
    return '%x.%02x' % (top >> 8, top & 0xFF)


def title_meta(title_dir, modules):
    """Title id, name, param.json versions and the top-level eboot's SDK words."""
    param = {}
    path = os.path.join(title_dir, 'sce_sys', 'param.json')
    if os.path.exists(path):
        try:
            with open(path, encoding='utf-8-sig') as fh:
                param = json.load(fh)
        except (OSError, ValueError):
            param = {}
    sfo_path = os.path.join(title_dir, 'sce_sys', 'param.sfo')
    sfo = read_sfo(sfo_path) if os.path.exists(sfo_path) else {}

    title_id = param.get('titleId') or sfo.get('TITLE_ID')
    if not title_id:
        found = re.search(r'[A-Z]{4}\d{5}', os.path.basename(title_dir))
        title_id = found.group(0) if found else None
    local = param.get('localizedParameters') or {}
    name = (local.get(local.get('defaultLanguage'), {}).get('titleName')
            or sfo.get('TITLE'))

    eboot = os.path.join(title_dir, 'eboot.bin')
    eboot_sdk = None
    for module in modules:
        if module.path == eboot:
            eboot_sdk = {'ps5': None if module.ps5_sdk is None
                         else '0x%08x' % module.ps5_sdk,
                         'ps4': None if module.ps4_sdk is None
                         else '0x%08x' % module.ps4_sdk}
    return {
        'title_id': title_id, 'name': name, 'eboot_sdk': eboot_sdk,
        'param_sdk': (param_version(param['sdkVersion'])
                      if 'sdkVersion' in param else None),
        'param_required': (param_version(param['requiredSystemSoftwareVersion'])
                           if 'requiredSystemSoftwareVersion' in param else None),
    }


def library_report(title_dir, db, module_table, index, targets=None):
    """Everything --libs says about one title, in the shape --json writes."""
    levels, _, ranges, names, _ = db
    rank = index['rank']
    modules, importers, unshipped, superseded, unreadable = title_imports(
        title_dir, ranges)
    meta = title_meta(title_dir, modules)
    shipped = {library for module in modules for library in module.exports
               if library in APP_SUPPLIED_MODULES}
    del modules
    floor, floor_pair, unresolvable = title_floor(
        importers, unshipped, db, index)

    if targets is None:
        targets = [t for t in default_targets(levels)
                   if floor is None or rank[t] < rank[floor]]
    floor_set_by = None
    if floor_pair:
        floor_set_by = {'library': floor_pair[0], 'nid': floor_pair[1],
                        'name': (names.get(floor_pair) if floor_pair[1]
                                 else 'game-supplied list from %s' % floor)}
    report = {'dir': os.path.basename(title_dir),
              'path': os.path.abspath(title_dir)}
    report.update(meta)
    report.update({
        'floor': floor,
        'floor_set_by': floor_set_by,
        'needs_injection': (floor is None
                            or fw_key(floor) > fw_key(BACKPORT_FLOOR)),
        'ignored': {
            'app_supplied_unshipped': sorted({lib for lib, _ in unshipped}),
            'superseded': sorted(superseded)},
        'unreadable': [{'file': f, 'reason': r} for f, r in unreadable],
        'unresolvable': unresolvable,
        'targets': [requirements_at(t, importers, db, module_table, unshipped,
                                    index, shipped) for t in targets],
    })
    return report


def _plural(count, one, many):
    return '%d %s' % (count, one if count == 1 else many)


def render_library_report(title, verbose, rank):
    """Text lines for one title from library_report."""
    lines = ['%s  %s' % (title['dir'], title['name'] or '?')]
    sdk = title['eboot_sdk']
    if sdk:
        ps5 = int(sdk['ps5'], 16) if sdk['ps5'] else None
        eboot = 'eboot SDK PS5 %s (%s), PS4 compat %s' % (
            bcd_word(ps5), sdk['ps5'] or '?', sdk['ps4'] or '?')
    else:
        eboot = 'eboot SDK ?'
    lines.append('  %s; param.json sdk %s, requires %s' % (
        eboot, title['param_sdk'] or '?', title['param_required'] or '?'))

    floor = title['floor']
    by = title['floor_set_by']
    if floor is None:
        lines.append('  floor: none')
    elif not title['targets'] and not title['needs_injection']:
        lines.append('  floor PS5 %s: no injection needed (backport floor %s)'
                     % (floor, BACKPORT_FLOOR))
    else:
        lines.append('  floor PS5 %s%s' % (floor, '  (%s / %s)' % (
            by['library'], by['name'] or by['nid']) if by
            else '  (no import raises it)'))

    ignored = title['ignored']
    if ignored['app_supplied_unshipped']:
        lines.append('  ignored: %s (game-supplied, not shipped)'
                     % ', '.join(ignored['app_supplied_unshipped']))
    if ignored['superseded']:
        lines.append('  ignored: %s (empty file, superseded)'
                     % ', '.join(ignored['superseded']))
    for item in title['unreadable']:
        lines.append('  unreadable: %s (%s)' % (item['file'], item['reason']))
    if title['unresolvable']:
        lines.append('  UNRESOLVED at every firmware (%d):'
                     % len(title['unresolvable']))
        for item in title['unresolvable'][:12]:
            lines.append('    %s / %s [%s] %s <%s>' % (
                item['library'], item['nid'], item['name'] or '?',
                item['kind'].replace('_', ' '), ', '.join(item['importers'])))
        if len(title['unresolvable']) > 12:
            lines.append('    ... and %d more' % (len(title['unresolvable']) - 12))

    for target in title['targets']:
        t = target['target']
        if target['resolved']:
            lines.append('  target %s: resolves, no injection needed' % t)
            continue
        libraries = sum(len(m['libraries']) for m in target['modules'])
        lines.append('  target %s: %s in %s across %s' % (
            t, _plural(target['missing_symbols'], 'symbol', 'symbols'),
            _plural(libraries, 'library', 'libraries'),
            _plural(len(target['modules']), 'module', 'modules')))
        for note in target['app_supplied_unlisted']:
            lines.append('    note: %s is game-supplied only from %s; libkernel '
                         'at %s will not load it from sce_module%s'
                         % (note['library'], note['since'], t,
                            '' if note['shipped'] else ' (not shipped)'))
        for module in target['modules']:
            since = module['module_since']
            if module['module'] == '?':
                state = 'no firmware file known'
            elif module['present']:
                state = 'present, replace'
            elif since and rank[since] > rank[t]:
                state = 'absent before %s, supply whole' % since
            else:
                state = 'absent at %s, supply whole' % t
            name = module['module']
            if module['alternatives']:
                name += ' (also %s)' % ', '.join(module['alternatives'])
            lines.append('    %-38s  %s' % (name, state))
            for lib in module['libraries']:
                status = ('whole library, first in %s' % lib['library_since']
                          if lib['status'] == 'missing_library'
                          else '%d of its exports missing' % lib['missing'])
                lines.append('      %-28s %4d  %s  <%s>' % (
                    lib['library'], lib['missing'], status,
                    ', '.join(lib['importers'])))
                if not verbose:
                    continue
                for sym in lib['symbols']:
                    lines.append('        %-12s %s  %s..%s %s  <%s>' % (
                        sym['nid'], sym['name'] or '?', sym['min_fw'],
                        sym['max_fw'], sym['reason'],
                        ', '.join(sym['importers'])))
    return lines


def library_titles(dirs):
    """Expand --libs arguments. -> (title dirs, [(dir, reason)] skipped)"""
    titles, skipped = [], []
    for d in dirs:
        if os.path.isfile(os.path.join(d, 'eboot.bin')):
            titles.append(d)
            continue
        for name in sorted(os.listdir(d)):
            sub = os.path.join(d, name)
            if not os.path.isdir(sub):
                continue
            if os.path.isfile(os.path.join(sub, 'eboot.bin')):
                titles.append(sub)
            else:
                skipped.append((sub, 'no eboot.bin'))
    return titles, skipped


def library_requirements(dirs, verbose, targets, json_path):
    """The --libs mode: print, and optionally write as JSON, what each title
    needs injected at each target."""
    db = load_export_db()
    levels = db[0]
    for t in targets or ():
        if t not in levels:
            die('unknown firmware level %s; known: %s' % (t, ', '.join(levels)))
        if fw_key(t) < fw_key(BACKPORT_FLOOR):
            die('%s is below the backport floor %s' % (t, BACKPORT_FLOOR))
    if targets:
        targets = sorted(set(targets), key=fw_key)
    titles, skipped = library_titles(dirs)
    if not titles:
        die('no title folder (one holding eboot.bin) in %s' % ', '.join(dirs))
    module_table = load_module_table()
    index = index_db(db, module_table)

    report = {'backport_floor': BACKPORT_FLOOR, 'levels': levels,
              'titles': [], 'skipped': []}
    first = True
    for title_dir in titles:
        title = library_report(title_dir, db, module_table, index, targets)
        report['titles'].append(title)
        if not first:
            print()
        first = False
        print('\n'.join(render_library_report(title, verbose, index['rank'])),
              flush=True)
    for path, reason in skipped:
        report['skipped'].append({'path': os.path.abspath(path),
                                  'reason': reason})
        print('\n%s  skipped: %s' % (os.path.basename(path), reason))
    if json_path:
        with open(json_path, 'w') as fh:
            json.dump(report, fh, indent=1)
            fh.write('\n')
    return 0


def patch(data, sdk, force, label, keep_versions=False):
    """Rewrite the stamp in place. -> (list of report lines, changed?)"""
    lines, changed = [], False
    version_seg = None
    for seg in segments(data):
        if seg[0] in PARAM_NAMES and seg[5] >= SDK_OFFSET + 4:
            at = seg[2] + SDK_OFFSET
            old, = struct.unpack_from('<I', data, at)
            kind = PARAM_NAMES[seg[0]]
            if version_field(old) == version_field(sdk):
                lines.append('%-20s already 0x%04x0000' % (kind, version_field(sdk)))
            elif version_field(old) < version_field(sdk) and not force:
                # backporting only ever lowers the stamp
                lines.append('%-20s 0x%08x is already below the target, left alone' % (kind, old))
            else:
                new = retarget(old, sdk)
                struct.pack_into('<I', data, at, new)
                lines.append('%-20s 0x%08x -> 0x%08x  @0x%x' % (kind, old, new, at))
                changed = True
        elif seg[0] == PT_SCE_VERSION and seg[5]:
            version_seg = seg

    if not lines:
        lines.append('no param segment')
    if version_seg is not None and keep_versions:
        before = version_records(data, version_seg)
        stale = sorted({v for _, v in before
                        if version_field(v) > version_field(sdk)})
        lines.append('%-20s %d records left alone%s'
                     % ('PT_SCE_VERSION', len(before),
                        ', naming ' + ', '.join('0x%08x' % v for v in stale)
                        if stale else ''))
    elif version_seg is not None:
        before = version_records(data, version_seg)
        lowered = version_records(data, version_seg, sdk)
        if lowered:
            changed = True
        stale = sorted({v for _, v in before
                        if version_field(v) > version_field(sdk)})
        lines.append('%-20s %d of %d records lowered%s'
                     % ('PT_SCE_VERSION', lowered, len(before),
                        ' from ' + ', '.join('0x%08x' % v for v in stale)
                        if stale else ''))
    return lines, changed


def main(argv):
    sdk, out_base, dry_run, force = DEFAULT_SDK, '.', False, False
    resolve_only = observed_only = keep_versions = False
    libs = verbose = False
    targets, json_path = [], None
    dumps = []
    i = 0
    while i < len(argv):
        a = argv[i]
        if a in ('-h', '--help'):
            for line in open(__file__):
                if line.startswith('# ---'):
                    continue
                if not line.startswith('#'):
                    break
                print(line[2:].rstrip())
            return 0
        elif a in ('-s', '--sdk'):
            i += 1
            sdk = 'auto' if argv[i].lower() == 'auto' else int(argv[i], 0)
        elif a in ('-o', '--out'):
            i += 1
            out_base = argv[i]
        elif a in ('-r', '--resolve'):
            resolve_only = True
        elif a == '--observed':
            observed_only = True
        elif a == '--keep-version-records':
            keep_versions = True
        elif a == '--libs':
            libs = True
        elif a in ('-v', '--verbose'):
            verbose = True
        elif a == '--target':
            i += 1
            targets += [t.strip() for t in argv[i].split(',') if t.strip()]
        elif a == '--json':
            i += 1
            json_path = argv[i]
        elif a in ('-n', '--dry-run'):
            dry_run = True
        elif a in ('-f', '--force'):
            force = True
        elif a.startswith('-'):
            die('unknown option: %s' % a)
        else:
            dumps.append(a)
        i += 1

    dumps = [d.rstrip('/') for d in dumps]
    for d in dumps:
        if not os.path.isdir(d):
            die('not a directory: %s' % d)

    if libs:
        if not dumps:
            die('give at least one title or parent directory (see --help)')
        return library_requirements(dumps, verbose, targets or None, json_path)
    if verbose or targets or json_path:
        die('-v, --target and --json go with --libs')

    if observed_only:
        if not dumps:
            die('give at least one dump directory (see --help)')
        print('0x%08x' % observed_sdk(dumps))
        return 0

    if resolve_only:
        if not dumps:
            die('give at least one dump directory (see --help)')
        stamp, why = choose_sdk(dumps)
        for line in why:
            print(line, file=sys.stderr)
        print('0x%08x' % stamp)
        return 0

    if len(dumps) != 1:
        die('give exactly one dump directory, or --resolve for several')
    dump = dumps[0]
    if sdk != 'auto' and not 0 <= sdk <= 0xFFFFFFFF:
        die('SDK version must fit in 32 bits')

    execs, sfo = find_content(dump)
    if not execs:
        die('no executables found under %s' % dump)

    sfo_values = read_sfo(sfo) if sfo else {}
    title = sfo_values.get('TITLE_ID')
    if not title:
        base = os.path.basename(dump)
        for i in range(len(base) - 8):
            chunk = base[i:i + 9]
            if chunk[:4].isalpha() and chunk[:4].isupper() and chunk[4:].isdigit():
                title = chunk
                break
    if not title:
        die('could not determine the title id from param.sfo or %r' % os.path.basename(dump))

    out = os.path.join(out_base, '%s-bp' % title)
    print('%s  ->  %s' % (dump, out))
    if sfo_values:
        print('%s %s, app %s, needs %s, built with SDK %s'
              % (title, sfo_values.get('CATEGORY', '?'), sfo_values.get('APP_VER', '?'),
                 '0x%08x' % sfo_values['SYSTEM_VER'] if 'SYSTEM_VER' in sfo_values else '?',
                 dict(p.split('=', 1) for p in sfo_values.get('PUBTOOLINFO', '').split(',')
                      if '=' in p).get('sdk_ver', '?')))
    if sdk == 'auto':
        sdk, why = choose_sdk([dump])
        for line in why:
            print(line)
    print('target SDK 0x%08x%s\n' % (sdk, '  (dry run)' if dry_run else ''))

    if not dry_run:
        os.makedirs(out, exist_ok=True)

    patched = 0
    for rel in execs:
        data = bytearray(open(os.path.join(dump, rel), 'rb').read())
        if data[:4] != b'\x7fELF':
            print('%-34s not an ELF, skipped' % rel)
            continue
        lines, changed = patch(data, sdk, force, rel, keep_versions)
        print('%-34s %s' % (rel, lines[0]))
        for extra in lines[1:]:
            print('%-34s %s' % ('', extra))
        patched += changed
        # Only restamped files belong in the tree. Carrying an executable this
        # did not touch would put a byte-identical copy in the patch package and
        # have it replace the base's.
        if changed and not dry_run:
            dst = os.path.join(out, rel)
            os.makedirs(os.path.dirname(dst) or '.', exist_ok=True)
            with open(dst, 'wb') as fh:
                fh.write(data)

    if sfo:
        rel = os.path.relpath(sfo, dump)
        print('%-34s copied unmodified' % rel)
        if not dry_run:
            dst = os.path.join(out, rel)
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            shutil.copy2(sfo, dst)
    else:
        print('no sce_sys/param.sfo found')

    print('\n%d of %d executables restamped' % (patched, len(execs)))
    return 0 if patched else 3


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
