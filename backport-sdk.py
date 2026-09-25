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
# ----------------------------------------------------------------------------
import csv
import os
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
        elif ver > sdk:
            struct.pack_into('>I', data, at, sdk)
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
    """Parse every executable across the given dumps."""
    modules = []
    for dump in dumps:
        execs, _ = find_content(dump)
        for rel in execs:
            module = ps4elf.read(os.path.join(dump, rel))
            if module is not None:
                modules.append(module)
    return modules


def choose_sdk(dumps):
    """Pick the oldest firmware that exports everything the dumps import.

    Resolve over every dump at once: a title's base and its update share one
    process, so a symbol the update bundles satisfies the base's import of it.

    -> (stamp, list of report lines)
    """
    levels, stamps, ranges, names, holes = load_export_db()
    rank = {name: i for i, name in enumerate(levels)}
    modules = collect_modules(dumps)
    if not modules:
        die('no readable executables in %s' % ', '.join(dumps))

    provided, imported = set(), set()
    for module in modules:
        imported |= set(module.imports)
        for library, nids in module.exports.items():
            provided |= {(library, nid) for nid in nids}
    wanted = imported - provided

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


def patch(data, sdk, force, label, keep_versions=False):
    """Rewrite the stamp in place. -> (list of report lines, changed?)"""
    lines, changed = [], False
    version_seg = None
    for seg in segments(data):
        if seg[0] in PARAM_NAMES and seg[5] >= SDK_OFFSET + 4:
            at = seg[2] + SDK_OFFSET
            old, = struct.unpack_from('<I', data, at)
            kind = PARAM_NAMES[seg[0]]
            if old == sdk:
                lines.append('%-20s already 0x%08x' % (kind, sdk))
            elif old < sdk and not force:
                # backporting only ever lowers the stamp
                lines.append('%-20s 0x%08x is already below the target, left alone' % (kind, old))
            else:
                struct.pack_into('<I', data, at, sdk)
                lines.append('%-20s 0x%08x -> 0x%08x  @0x%x' % (kind, old, sdk, at))
                changed = True
        elif seg[0] == PT_SCE_VERSION and seg[5]:
            version_seg = seg

    if not lines:
        lines.append('no param segment')
    if version_seg is not None and keep_versions:
        before = version_records(data, version_seg)
        stale = sorted({v for _, v in before if v > sdk})
        lines.append('%-20s %d records left alone%s'
                     % ('PT_SCE_VERSION', len(before),
                        ', naming ' + ', '.join('0x%08x' % v for v in stale)
                        if stale else ''))
    elif version_seg is not None:
        before = version_records(data, version_seg)
        lowered = version_records(data, version_seg, sdk)
        if lowered:
            changed = True
        stale = sorted({v for _, v in before if v > sdk})
        lines.append('%-20s %d of %d records lowered%s'
                     % ('PT_SCE_VERSION', lowered, len(before),
                        ' from ' + ', '.join('0x%08x' % v for v in stale)
                        if stale else ''))
    return lines, changed


def main(argv):
    sdk, out_base, dry_run, force = DEFAULT_SDK, '.', False, False
    resolve_only = observed_only = keep_versions = False
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
