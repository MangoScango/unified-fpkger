#!/usr/bin/env python3
# ----------------------------------------------------------------------------
# build-export-db.py
# Scan a collection of PS5 firmware library dumps and write the tables that
# backport-sdk.py --sdk auto uses to pick a target.
#
# USAGE
#   build-export-db.py [options] PS5_LIBS_DIR
#     -o, --out DIR     where to write the tables (default: ./docs)
#     -n, --names FILE  a source of symbol names; repeatable, earlier files win
#     -h, --help        this text
#
#   Names only label the tables; nothing matches on them. A NID is the first
#   eight bytes of SHA-1(name + salt), so any list of names is a lookup table
#   once hashed. Each FILE may be a GhidraOrbis nid_db.xml, "NID name" pairs
#   (aerolib.csv), or one name per line; every name is hashed and kept only
#   for the NID it produces, so a wrong or stale pair cannot mislabel a row.
#   Strings inside the newest firmware's own libraries are tried last.
#
#   PS5_LIBS_DIR holds one directory per firmware, named for its version
#   ("7.61"), each containing that firmware's extracted libraries. The firmware
#   binaries are large and are not in this repo; the tables are, so this only
#   needs re-running when a firmware is added.
#
# OUTPUT
#   fw-levels.csv       one row per firmware: the PS4 system software level its
#                       compatibility layer presents, read from the modules.
#   fw-exports.csv      library,nid,name,min_fw,max_fw - the oldest and newest
#                       firmware seen exporting a symbol.
#   fw-export-gaps.csv  symbols absent from a firmware inside their own range
#                       even though the library was there, which min_fw and
#                       max_fw alone would claim are present throughout.
#   fw-modules.csv      library,module,min_fw,max_fw - which sprx files carry
#                       a library, since a library is often exported from a
#                       file of another name (libScePosix from libkernel.sprx).
#
# WHICH LIBRARIES
#   A dump is surveyed through the directory holding libkernel, since that is
#   the set a PS4 title resolves against and no dump can omit it. Dumps disagree
#   on where that lands - system/common/lib usually, a flat lib/ sometimes - and
#   they also carry system_ex, priv and vsh libraries a title cannot link, so
#   anchoring on libkernel is what makes them comparable.
#
#   min_fw and max_fw are the first and last firmware seen exporting a symbol,
#   so a dump that simply missed a module does not turn into a removal. Only a
#   symbol missing from a module that WAS read is recorded as a gap. Where a
#   dump is wrong the tables will be wrong with it; the fix for that is a better
#   dump, not more inference here.
# ----------------------------------------------------------------------------
import base64
import csv
import hashlib
import os
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import ps4elf


def die(msg):
    sys.exit(f'error: {msg}')


def fw_key(name):
    return tuple(int(part) for part in name.split('.'))


NID_SALT = bytes.fromhex('518D64A635DED8C1E6B039B1C3E55230')
# Long enough to skip most noise, short enough to keep C++ manglings.
STRING_TOKEN = re.compile(rb'[A-Za-z_][A-Za-z0-9_@$.]{3,399}')


def nid_of(name):
    digest = hashlib.sha1(name.encode('utf-8', 'surrogateescape') + NID_SALT).digest()
    return base64.b64encode(digest[:8][::-1]).decode().rstrip('=').replace('/', '-')


def candidate_names(path):
    """Every string in a names file that might be a symbol name."""
    with open(path, encoding='utf-8', errors='surrogateescape') as fh:
        text = fh.read()
    if 'obf="' in text:
        return [sym for _, sym in re.findall(r'obf="([^"]+)"\s+sym="([^"]+)"', text)]
    names = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        names.append(line)
        # "NID name" pairs: the name is the second field.
        first, _, rest = line.partition(' ')
        if rest:
            names.append(rest.strip())
    return names


def add_names(table, wanted, names):
    """Hash names into table for the NIDs in wanted. -> how many were new."""
    added = 0
    for name in names:
        if len(name) > 400:
            continue
        nid = nid_of(name)
        if nid in wanted and nid not in table:
            table[nid] = name
            added += 1
    return added


def library_strings(directory):
    tokens = set()
    for path in sorted(directory.rglob('*.sprx')):
        tokens.update(STRING_TOKEN.findall(path.read_bytes()))
    return [t.decode('ascii') for t in tokens]


def anchor_dir(firmware):
    """The directory holding libkernel, which is the linkable library set."""
    candidates = []
    for path in sorted(firmware.rglob('libkernel.sprx')):
        module = ps4elf.read(path)
        if module and 'libkernel' in module.exports:
            candidates.append(path.parent)
    if not candidates:
        return None
    return max(candidates, key=lambda d: sum(1 for _ in d.glob('*.sprx')))


def scan(directory):
    """-> (exports by library, module count, PS4 stamp, files by library)."""
    exports = defaultdict(set)
    files = defaultdict(set)
    stamps = Counter()
    modules = 0
    for path in sorted(directory.glob('*.sprx')):
        module = ps4elf.read(path)
        if module is None:
            continue
        modules += 1
        if module.ps4_sdk:
            stamps[module.ps4_sdk] += 1
        for library, nids in module.exports.items():
            exports[library] |= nids
            files[library].add(path.name)
    return (exports, modules, (stamps.most_common(1)[0][0] if stamps else 0),
            files)


def main(argv):
    out_dir, name_paths, roots = Path('docs'), [], []
    i = 0
    while i < len(argv):
        arg = argv[i]
        if arg in ('-h', '--help'):
            for line in open(__file__):
                if line.startswith(('# ---', '#!')):
                    continue
                if not line.startswith('#'):
                    break
                print(line[2:].rstrip())
            return 0
        elif arg in ('-o', '--out'):
            i += 1
            out_dir = Path(argv[i])
        elif arg in ('-n', '--names', '--nids'):
            i += 1
            name_paths.append(argv[i])
        elif arg.startswith('-'):
            die(f'unknown option: {arg}')
        else:
            roots.append(arg)
        i += 1

    if len(roots) != 1:
        die('give exactly one library collection directory (see --help)')
    root = Path(roots[0])
    if not root.is_dir():
        die(f'not a directory: {root}')
    for path in name_paths:
        if not os.path.isfile(path):
            die(f'names file not found: {path}')
    if not name_paths:
        print('warning: no -n names files given; only strings inside the '
              'libraries will name symbols', file=sys.stderr)

    levels = []
    carriers = defaultdict(list)
    newest_dir = None
    for firmware in sorted((d for d in root.iterdir()
                            if d.is_dir() and d.name[0].isdigit()),
                           key=lambda d: fw_key(d.name)):
        directory = anchor_dir(firmware)
        if directory is None:
            print(f'{firmware.name:>6}  no libkernel, skipped')
            continue
        exports, modules, stamp, files = scan(directory)
        for library, filenames in files.items():
            for filename in filenames:
                carriers[(library, filename)].append(len(levels))
        levels.append((firmware.name, exports, modules, stamp))
        newest_dir = firmware
        print(f'{firmware.name:>6}  {modules:4d} modules  {len(exports):4d} '
              f'libraries  ps4 0x{stamp:08x}  {directory.relative_to(firmware)}',
              flush=True)
    if not levels:
        die(f'no usable firmware dumps under {root}')

    order = [name for name, *_ in levels]
    has_library = [set(exports) for _, exports, _, _ in levels]
    seen = defaultdict(list)
    for index, (_, exports, _, _) in enumerate(levels):
        for library, nids in exports.items():
            for nid in nids:
                seen[(library, nid)].append(index)

    wanted = {nid for _, nid in seen}
    names = {}
    print()
    for path in name_paths:
        added = add_names(names, wanted, candidate_names(path))
        print(f'names: {added:6d} from {path}')
    added = add_names(names, wanted, library_strings(newest_dir))
    print(f'names: {added:6d} from strings in {newest_dir}')
    print(f'names: {len(names)} of {len(wanted)} NIDs '
          f'({100 * len(names) / len(wanted):.1f}%)')

    rows, gaps = [], []
    for (library, nid), indices in sorted(seen.items()):
        low, high = indices[0], indices[-1]
        name = names.get(nid, '')
        rows.append((library, nid, name, order[low], order[high]))
        if high - low + 1 == len(indices):
            continue
        present = set(indices)
        # A firmware whose dump lacks the library says nothing about the symbol;
        # one that has the library and not the symbol does.
        holes = [order[i] for i in range(low, high + 1)
                 if i not in present and library in has_library[i]]
        if holes:
            gaps.append((library, nid, name, ';'.join(holes)))

    rows.sort(key=lambda r: (r[0], r[2], r[1]))
    gaps.sort(key=lambda r: (r[0], r[2], r[1]))
    out_dir.mkdir(parents=True, exist_ok=True)

    with open(out_dir / 'fw-levels.csv', 'w', newline='') as fh:
        writer = csv.writer(fh)
        writer.writerow(['ps5_system_software', 'ps4_stamp', 'modules'])
        for name, _, modules, stamp in levels:
            writer.writerow([name, f'0x{stamp:08x}', modules])
    with open(out_dir / 'fw-exports.csv', 'w', newline='') as fh:
        writer = csv.writer(fh)
        writer.writerow(['library', 'nid', 'name', 'min_fw', 'max_fw'])
        writer.writerows(rows)
    with open(out_dir / 'fw-export-gaps.csv', 'w', newline='') as fh:
        writer = csv.writer(fh)
        writer.writerow(['library', 'nid', 'name', 'missing_fw'])
        writer.writerows(gaps)
    with open(out_dir / 'fw-modules.csv', 'w', newline='') as fh:
        writer = csv.writer(fh)
        writer.writerow(['library', 'module', 'min_fw', 'max_fw'])
        for (library, module), indices in sorted(carriers.items()):
            writer.writerow([library, module, order[indices[0]],
                             order[indices[-1]]])

    added = sum(1 for r in rows if r[3] != order[0])
    removed = sum(1 for r in rows if r[4] != order[-1])
    print(f'\n{len(levels)} firmware levels, {order[0]} .. {order[-1]}')
    print(f'{len({r[0] for r in rows})} libraries, {len(rows)} symbols')
    print(f'{added} appear after {order[0]}, {removed} gone before '
          f'{order[-1]}, {len(gaps)} with gaps')
    print(f'wrote {out_dir}/fw-levels.csv, fw-exports.csv, fw-export-gaps.csv, '
          f'fw-modules.csv')
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
