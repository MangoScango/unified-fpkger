#!/usr/bin/env python3
# ----------------------------------------------------------------------------
# backport-sdk.py
# Collect a dump's executables and param.sfo into <TITLEID>-bp, rewriting the
# SDK version stamp in each executable so an older firmware's loader accepts it.
#
# USAGE
#   backport-sdk.py [options] DUMP_DIR
#     -s, --sdk VER     target SDK version (default 0x10790001)
#     -o, --out DIR     where to create <TITLEID>-bp (default: cwd)
#     -n, --dry-run     report what would happen, write nothing
#     -f, --force       restamp even when that would raise the SDK version
#     -h, --help        this text
#
#   A stamp already at or below the target is left as it is, so a mixed tree can
#   be run through repeatedly without pushing old modules forward.
#
# EXIT STATUS
#   0  at least one executable was restamped
#   3  nothing needed lowering
#   1  error
#
#   Executables are eboot.bin and any .elf/.self/.prx/.sprx, copied with their
#   relative paths intact so the result can be dropped back over a staged tree.
#   param.sfo comes along unmodified, for the title id and as a record of what
#   the dump asked for.
#
#   The stamp lives at offset 0x10 of PT_SCE_PROCPARAM (executables) and
#   PT_SCE_MODULE_PARAM (libraries), and patching it does not change any file's
#   size. Nothing else is touched: the per-object records in PT_SCE_VERSION
#   still name the original SDK, and imports the target firmware does not
#   export are left alone. Both are reported.
# ----------------------------------------------------------------------------
import os
import shutil
import struct
import sys

PT_LOAD = 1
PT_SCE_PROCPARAM = 0x61000001
PT_SCE_MODULE_PARAM = 0x61000002
PT_SCE_VERSION = 0x6FFFFF01

PARAM_NAMES = {PT_SCE_PROCPARAM: 'PT_SCE_PROCPARAM', PT_SCE_MODULE_PARAM: 'PT_SCE_MODULE_PARAM'}
SDK_OFFSET = 0x10
DEFAULT_SDK = 0x10790001
EXEC_SUFFIXES = ('.elf', '.self', '.prx', '.sprx')
SFO_MAGIC = b'\x00PSF'


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


def version_records(data, seg):
    """Names recorded in PT_SCE_VERSION, which this tool leaves untouched. Each
    record is a length byte, a "name:" string, then a big-endian u32."""
    out = []
    off, end = seg[2], seg[2] + seg[5]
    while off < end:
        length = data[off]
        if length == 0 or off + 1 + length > end:
            break
        name = data[off + 1:off + length].split(b':')[0].decode('utf8', 'replace')
        ver, = struct.unpack_from('>I', data, off + length - 3)
        out.append((name, ver))
        off += length + 1
    return out


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


def patch(data, sdk, force, label):
    """Rewrite the stamp in place. -> (list of report lines, changed?)"""
    lines, changed = [], False
    leftovers = []
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
            leftovers = version_records(data, seg)

    if not lines:
        lines.append('no param segment')
    if leftovers:
        stale = sorted({v for _, v in leftovers if v != sdk})
        lines.append('%-20s %d records kept%s'
                     % ('PT_SCE_VERSION', len(leftovers),
                        ', naming ' + ', '.join('0x%08x' % v for v in stale) if stale else ''))
    return lines, changed


def main(argv):
    sdk, out_base, dry_run, force = DEFAULT_SDK, '.', False, False
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
            sdk = int(argv[i], 0)
        elif a in ('-o', '--out'):
            i += 1
            out_base = argv[i]
        elif a in ('-n', '--dry-run'):
            dry_run = True
        elif a in ('-f', '--force'):
            force = True
        elif a.startswith('-'):
            die('unknown option: %s' % a)
        else:
            dumps.append(a)
        i += 1

    if len(dumps) != 1:
        die('give exactly one dump directory (see --help)')
    dump = dumps[0].rstrip('/')
    if not os.path.isdir(dump):
        die('not a directory: %s' % dump)
    if not 0 <= sdk <= 0xFFFFFFFF:
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
    print('target SDK 0x%08x%s\n' % (sdk, '  (dry run)' if dry_run else ''))

    if not dry_run:
        os.makedirs(out, exist_ok=True)

    patched = 0
    for rel in execs:
        data = bytearray(open(os.path.join(dump, rel), 'rb').read())
        if data[:4] != b'\x7fELF':
            print('%-34s not an ELF, skipped' % rel)
            continue
        lines, changed = patch(data, sdk, force, rel)
        print('%-34s %s' % (rel, lines[0]))
        for extra in lines[1:]:
            print('%-34s %s' % ('', extra))
        patched += changed
        if not dry_run:
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
