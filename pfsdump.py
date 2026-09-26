#!/usr/bin/env python3
"""Dumps a PS4 title's app+patch tree by streaming the console's PFS images.

The console exposes each layer's decrypted inner PFS image at
/mnt/sandbox/pfsmnt/<title>-{app0,patch0}-nest/pfs_image.dat. Rather than
mirroring the loose files, this reads each image's metadata, works out one
merged write plan, and demultiplexes the file data out of a single sequential
transfer per image.

Layering: the patch's files win, but the base game's capitalisation wins. Each
layer stores exactly one spelling of a path while the console's PFS resolves
lookups case-insensitively, so a patch that recapitalises a directory would
otherwise land a second copy of it next to the base game's.

Executables are a special case: the PFS image holds the signed, encrypted SELF,
so each one is re-fetched afterwards through the console's PFS mount, which
decrypts on the fly.

Not yet handled, and still ftpdump.sh's job: sce_sys, which lives in the PKG
entries rather than in the PFS image.
"""

import argparse
import ftplib
import os
import re
import struct
import sys
import time

BLOCK_SIG_SIZE = 40
DINODE_D32_SIZE = 0xA8
DIRENT_FILE, DIRENT_DIR = 2, 3
PFS_MAGIC = 20130315

MODE_SIGNED = 0x1
MODE_ENCRYPTED = 0x4
INODE_COMPRESSED = 0x1
INODE_MODE_DIR = 0x4000

ELF_MAGIC = b"\x7fELF"
TRP_MAGIC = b"\xdc\xa2\x4d"
# npbind.dat holds these in a tag/length table; scanning for them is enough to
# recover the order, which is what maps a set onto trophy<NN>.trp.
NPWR_ID = re.compile(rb"NPWR[0-9]{5}_[0-9]{2}")
# Names the console decrypts on the way out of a PFS mount. Matching on the name
# rather than sniffing every file's magic keeps this off the data path.
EXECUTABLE_SUFFIXES = (".self", ".elf", ".sprx", ".prx")
EXECUTABLE_NAMES = ("eboot.bin",)

# Splitting a transfer costs a round trip, so a short run of unwanted data is
# cheaper to read and discard than to seek past.
RESEEK_THRESHOLD = 8 << 20
CHUNK = 1 << 20


class Unsupported(Exception):
    """The image uses a PFS feature this reader deliberately does not handle."""


def is_executable(path):
    name = path.rsplit("/", 1)[-1].lower()
    return name in EXECUTABLE_NAMES or name.endswith(EXECUTABLE_SUFFIXES)


def elf_truncated(path):
    """Whether an ELF's program headers reach past the end of the file.

    The mount advertises the encrypted size for the files it decrypts, so a
    short download cannot be caught by comparing sizes.
    """
    size = os.path.getsize(path)
    with open(path, "rb") as handle:
        head = handle.read(0x40)
        if head[:4] != ELF_MAGIC:
            return True
        ph_offset = struct.unpack_from("<Q", head, 0x20)[0]
        ph_size, ph_count = struct.unpack_from("<HH", head, 0x36)
        if ph_offset + ph_size * ph_count > size:
            return True
        handle.seek(ph_offset)
        table = handle.read(ph_size * ph_count)
        for i in range(ph_count):
            at = i * ph_size
            offset = struct.unpack_from("<Q", table, at + 0x08)[0]
            length = struct.unpack_from("<Q", table, at + 0x20)[0]
            if offset + length > size:
                return True
    return False


def reachable(offset):
    """Whether the server will accept offset in a REST command.

    Its bounds check reads the low 32 bits as a signed int, so any offset whose
    low word has the top bit set is refused even though the seek itself is
    64-bit correct.
    """
    return (offset & 0xFFFFFFFF) < 0x80000000


def transfer_start(offset):
    """The highest acceptable REST offset from which offset can be reached."""
    if reachable(offset):
        return offset
    return (offset >> 32 << 32) + 0x7FFFFFFF


class FtpFile:
    """Random and sequential reads of one remote file.

    Deliberately avoids SIZE, which the console truncates modulo 2**32 and
    which makes clients refuse offsets past the wrap.
    """

    def __init__(self, host, port, path, timeout=60):
        self.host, self.port, self.path = host, port, path
        self.timeout = timeout
        self.ftp = None
        self.metadata_bytes = 0
        self._connect()

    def _connect(self):
        self.close()
        self.ftp = ftplib.FTP()
        self.ftp.connect(self.host, self.port, timeout=self.timeout)
        self.ftp.login("anonymous", "")
        self.ftp.voidcmd("TYPE I")

    def open_at(self, offset):
        return self.ftp.transfercmd(f"RETR {self.path}", rest=offset)

    def finish(self, conn):
        # Transfers are abandoned partway through, which leaves the control
        # connection out of step; reconnecting beats negotiating an abort.
        conn.close()
        self._connect()

    def read(self, offset, length):
        conn = self.open_at(offset)
        buf = bytearray()
        try:
            while len(buf) < length:
                chunk = conn.recv(min(CHUNK, length - len(buf)))
                if not chunk:
                    break
                buf += chunk
        finally:
            self.finish(conn)
        if len(buf) != length:
            raise IOError(f"{self.path}: short read at {offset}, "
                          f"{len(buf)} of {length} bytes")
        self.metadata_bytes += len(buf)
        return bytes(buf)

    def close(self):
        if self.ftp is not None:
            try:
                self.ftp.close()
            except ftplib.all_errors:
                pass
            self.ftp = None


class FtpMount:
    """Whole-file reads from the console's PFS mounts, which decrypt SELFs."""

    def __init__(self, host, port, timeout=60):
        self.ftp = ftplib.FTP()
        self.ftp.connect(host, port, timeout=timeout)
        self.ftp.login("anonymous", "")
        self.ftp.voidcmd("TYPE I")

    def enable_decryption(self):
        """Turns server-side SELF decryption on. DECRYPT toggles, so this reads
        the state back and sends it again if the first reply reported it off.

        Returns False when the server has no DECRYPT command, which may mean it
        always decrypts or that it never does.
        """
        for _attempt in (1, 2):
            try:
                reply = self.ftp.sendcmd("DECRYPT")
            except ftplib.all_errors:
                return False
            if "decryption enabled" in reply:
                return True
            if "decryption disabled" not in reply:
                return False
        return False

    def size(self, remote):
        """The size MLST reports, or None. SIZE is not used because the console
        truncates it modulo 2**32.
        """
        try:
            reply = self.ftp.sendcmd(f"MLST {remote}")
        except ftplib.all_errors:
            return None
        found = re.search(r"size=(\d+)", reply)
        return int(found.group(1)) if found else None

    def try_download(self, remote, dest):
        """Downloads remote, returning the byte count, or None if absent."""
        try:
            return self.download(remote, dest)
        except ftplib.all_errors:
            return None

    def download(self, remote, dest):
        """Reads remote to EOF. Its length is not known ahead of time, because
        the mount reports the encrypted size for files it decrypts.
        """
        conn = self.ftp.transfercmd(f"RETR {remote}")
        written = 0
        try:
            with open(dest, "wb") as out:
                while True:
                    chunk = conn.recv(CHUNK)
                    if not chunk:
                        break
                    out.write(chunk)
                    written += len(chunk)
        finally:
            conn.close()
            self.ftp.voidresp()
        return written

    def close(self):
        try:
            self.ftp.close()
        except ftplib.all_errors:
            pass


class PfsImage:
    """The directory tree and data extents of an unsigned, decrypted PFS image."""

    def __init__(self, remote):
        self.remote = remote
        self._read_superblock()
        self._read_inodes()
        self._read_directory_blocks()

    def _read_superblock(self):
        hdr = self.remote.read(0, 0x400)
        version, magic = struct.unpack_from("<qq", hdr, 0)
        if version != 1 or magic != PFS_MAGIC:
            raise Unsupported(f"not a PFS superblock (version {version}, magic {magic})")
        self.mode = struct.unpack_from("<H", hdr, 0x1C)[0]
        if self.mode & MODE_ENCRYPTED:
            raise Unsupported("image is encrypted; this reader has no key handling")
        if self.mode & MODE_SIGNED:
            raise Unsupported("image uses signed inodes; only unsigned are handled")
        self.block_size = struct.unpack_from("<I", hdr, 0x20)[0]
        self.inode_count, _ndblock, self.inode_block_count = \
            struct.unpack_from("<qqq", hdr, 0x30)

        # The inode table follows the superblock, past whatever indirect blocks
        # the header's own inode claims.
        ib_base = 0x50 + 0x68 + 12 * BLOCK_SIG_SIZE
        indirect = sum(
            1 for i in range(5)
            if struct.unpack_from("<q", hdr, ib_base + i * BLOCK_SIG_SIZE + 32)[0] > 0)
        self.inode_table_offset = self.block_size * (1 + indirect)

    def _read_inodes(self):
        table = self.remote.read(self.inode_table_offset,
                                 self.block_size * self.inode_block_count)
        per_block = self.block_size // DINODE_D32_SIZE
        self.inodes = []
        for block in range(self.inode_block_count):
            for slot in range(per_block):
                if len(self.inodes) >= self.inode_count:
                    break
                off = block * self.block_size + slot * DINODE_D32_SIZE
                mode = struct.unpack_from("<H", table, off)[0]
                flags = struct.unpack_from("<I", table, off + 0x04)[0]
                size = struct.unpack_from("<q", table, off + 0x08)[0]
                blocks = struct.unpack_from("<I", table, off + 0x60)[0]
                direct = struct.unpack_from("<12i", table, off + 0x64)
                index = len(self.inodes)
                if flags & INODE_COMPRESSED:
                    raise Unsupported(f"inode {index} is PFSC-compressed")
                if not mode & INODE_MODE_DIR and blocks > 1 and direct[1] != -1:
                    raise Unsupported(f"inode {index} has a non-contiguous block list")
                self.inodes.append((mode, size, blocks, direct[0]))

    def _read_directory_blocks(self):
        extents = [(start, start + max(blocks, 1))
                   for mode, _size, blocks, start in self.inodes
                   if mode & INODE_MODE_DIR]
        self.dir_first = min(start for start, _end in extents)
        last = max(end for _start, end in extents)
        self.dir_blocks = self.remote.read(
            self.dir_first * self.block_size,
            (last - self.dir_first) * self.block_size)

    def dirents(self, index):
        _mode, _size, blocks, start = self.inodes[index]
        for block in range(start, start + max(blocks, 1)):
            base = (block - self.dir_first) * self.block_size
            pos = 0
            while pos < self.block_size:
                inode, kind, name_len, ent_size = struct.unpack_from(
                    "<IiiI", self.dir_blocks, base + pos)
                if ent_size == 0:
                    break
                raw = self.dir_blocks[base + pos + 16:base + pos + 16 + name_len]
                yield kind, raw.split(b"\0")[0].decode("ascii"), inode
                pos += ent_size

    def manifest(self):
        """Returns [(path, offset, size)] for every file below uroot."""
        try:
            uroot = next(i for kind, name, i in self.dirents(0)
                         if kind == DIRENT_DIR and name == "uroot")
        except StopIteration:
            raise Unsupported("image has no uroot directory") from None

        entries = []

        def walk(index, prefix):
            for kind, name, child in self.dirents(index):
                if kind == DIRENT_DIR:
                    walk(child, prefix + name + "/")
                elif kind == DIRENT_FILE:
                    _mode, size, _blocks, start = self.inodes[child]
                    entries.append((prefix + name, start * self.block_size, size))

        walk(uroot, "")
        return entries


def directory_spellings(manifest):
    """Maps each lowercased directory path to the spelling the image stores."""
    spellings = {}
    for path, _offset, _size in manifest:
        parts = path.split("/")[:-1]
        for depth in range(1, len(parts) + 1):
            prefix = "/".join(parts[:depth])
            spellings.setdefault(prefix.lower(), prefix)
    return spellings


def canonicalise(path, base_files, base_dirs):
    """Rewrites a patch path into the spelling the base game uses."""
    parts = path.split("/")
    resolved = []
    for part in parts[:-1]:
        probe = "/".join(resolved + [part]).lower()
        existing = base_dirs.get(probe)
        resolved.append(existing.rsplit("/", 1)[-1] if existing else part)
    candidate = "/".join(resolved + [parts[-1]])
    return base_files.get(candidate.lower(), candidate)


def build_plan(app_manifest, patch_manifest):
    """Merges both manifests into per-image write plans.

    Returns (patch_plan, app_plan, superseded), each plan being
    [(destination path, offset, size)].
    """
    base_files = {path.lower(): path for path, _o, _s in app_manifest}
    base_dirs = directory_spellings(app_manifest)

    patch_plan = [(canonicalise(path, base_files, base_dirs), offset, size)
                  for path, offset, size in patch_manifest]
    # A patch supersedes a path even when it blanks the file to zero bytes.
    taken = {dest for dest, _o, _s in patch_plan}
    app_plan = [(path, offset, size) for path, offset, size in app_manifest
                if path not in taken]
    recased = sum(1 for (dest, _o, _s), (src, _o2, _s2)
                  in zip(patch_plan, patch_manifest) if dest != src)
    return patch_plan, app_plan, len(app_manifest) - len(app_plan), recased


def group_runs(plan):
    """Groups an offset-ordered plan into one entry per worthwhile transfer."""
    runs, current = [], []
    for entry in plan:
        if current and entry[1] - (current[-1][1] + current[-1][2]) > RESEEK_THRESHOLD:
            runs.append(current)
            current = []
        current.append(entry)
    if current:
        runs.append(current)
    return runs


class Progress:
    def __init__(self, total, label, enabled):
        self.total, self.label = total, label
        self.enabled = enabled and sys.stderr.isatty()
        self.done = 0
        self.started = self.last = time.monotonic()

    def advance(self, count):
        self.done += count
        now = time.monotonic()
        if self.enabled and now - self.last >= 0.5:
            self.last = now
            rate = self.done / max(now - self.started, 1e-9) / (1 << 20)
            pct = 100 * self.done / self.total if self.total else 100
            print(f"\r  {self.label}: {pct:5.1f}%  {self.done >> 20:,} MiB  "
                  f"{rate:6.1f} MiB/s", end="", file=sys.stderr, flush=True)

    def finish(self):
        if self.enabled:
            elapsed = time.monotonic() - self.started
            rate = self.done / max(elapsed, 1e-9) / (1 << 20)
            print(f"\r  {self.label}: {self.done >> 20:,} MiB in {elapsed:.0f}s "
                  f"({rate:.0f} MiB/s){' ' * 12}", file=sys.stderr)


def extract(remote, dest_root, plan, label, verbose=False, progress=True):
    """Writes every entry in plan, demultiplexing sequential transfers."""
    # Blanked files carry no extent, so they are created rather than streamed.
    for rel, _offset, size in plan:
        if size == 0:
            path = os.path.join(dest_root, rel)
            os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
            open(path, "wb").close()

    ordered = sorted((e for e in plan if e[2] > 0), key=lambda entry: entry[1])
    if not ordered:
        return 0, 0
    runs = group_runs(ordered)
    bar = Progress(sum(size for _d, _o, size in ordered), label, progress)
    discarded = 0

    for run in runs:
        pos = transfer_start(run[0][1])
        conn = remote.open_at(pos)
        try:
            for rel, offset, size in run:
                while pos < offset:
                    chunk = conn.recv(min(CHUNK, offset - pos))
                    if not chunk:
                        raise IOError(f"transfer ended at {pos}, expected {offset}")
                    pos += len(chunk)
                    discarded += len(chunk)
                path = os.path.join(dest_root, rel)
                os.makedirs(os.path.dirname(path), exist_ok=True)
                if verbose:
                    print(f"  {rel}", file=sys.stderr)
                with open(path, "wb") as out:
                    remaining = size
                    while remaining:
                        chunk = conn.recv(min(CHUNK, remaining))
                        if not chunk:
                            raise IOError(f"transfer ended inside {rel}")
                        out.write(chunk)
                        remaining -= len(chunk)
                        pos += len(chunk)
                        bar.advance(len(chunk))
        finally:
            remote.finish(conn)

    bar.finish()
    return len(runs), discarded


def replace_executables(mount, title, dest_root, layers, verbose=False):
    """Overwrites the extracted SELFs with the mount's decrypted copies.

    layers maps a layer name onto its plan, so each executable is re-fetched
    from the layer it actually came from. Returns (replaced, [(path, reason)]).
    """
    replaced = 0
    problems = []
    for layer, plan in layers.items():
        for rel, _offset, size in plan:
            if size == 0 or not is_executable(rel):
                continue
            local = os.path.join(dest_root, rel)
            remote = f"/mnt/sandbox/pfsmnt/{title}-{layer}/{rel}"
            if verbose:
                print(f"  {layer}: {rel}", file=sys.stderr)
            staged = local + ".decrypted"
            try:
                written = mount.download(remote, staged)
            except (ftplib.all_errors, OSError) as err:
                problems.append((rel, f"could not fetch from {layer}: {err}"))
                if os.path.exists(staged):
                    os.unlink(staged)
                continue
            if written == 0:
                os.unlink(staged)
                problems.append((rel, f"{layer} served an empty file"))
                continue
            if elf_truncated(staged):
                os.unlink(staged)
                problems.append((rel, "decrypted copy is not a complete ELF"))
                continue
            os.replace(staged, local)
            replaced += 1
    return replaced, problems


def dump_np_files(mount, title, dest_root):
    """Takes npbind.dat and nptitle.dat from the console's appmeta.

    The PKG's own copies are bound to the account that installed it. Returns
    npbind.dat's contents, which name the title's trophy sets, or None.
    """
    sce_sys = os.path.join(dest_root, "sce_sys")
    os.makedirs(sce_sys, exist_ok=True)
    appmeta = f"/system_data/priv/appmeta/{title}"
    npbind = None
    for name in ("npbind.dat", "nptitle.dat"):
        dest = os.path.join(sce_sys, name)
        if mount.try_download(f"{appmeta}/{name}", dest) is None:
            continue
        if name == "npbind.dat":
            with open(dest, "rb") as handle:
                npbind = handle.read()
    return npbind


def trophy_set_ids(npbind):
    """The NPWR ids in npbind.dat, in order and without repeats."""
    seen, ordered = set(), []
    for match in NPWR_ID.finditer(npbind or b""):
        value = match.group().decode("ascii")
        if value not in seen:
            seen.add(value)
            ordered.append(value)
    return ordered


def dump_trophies(mount, dest_root, npbind, verbose=False):
    """Writes each trophy set as sce_sys/trophy/trophy<NN>.trp.

    The console keeps a decrypted TRP per set under /user/trophy/conf, so these
    are taken from there rather than decrypted from the PKG's encrypted copies.
    Returns (written, [(name, reason)]).
    """
    ids = trophy_set_ids(npbind)
    if not ids:
        return 0, []

    trophy_dir = os.path.join(dest_root, "sce_sys", "trophy")
    os.makedirs(trophy_dir, exist_ok=True)
    written = 0
    problems = []
    for index, npwr in enumerate(ids):
        name = f"trophy{index:02d}.trp"
        remote = f"/user/trophy/conf/{npwr}/TROPHY.TRP"
        dest = os.path.join(trophy_dir, name)
        if verbose:
            print(f"  {npwr} -> sce_sys/trophy/{name}", file=sys.stderr)
        expected = mount.size(remote)
        got = mount.try_download(remote, dest)
        if got is None:
            problems.append((name, f"{npwr} has no TROPHY.TRP on the console"))
            continue
        if expected is not None and got != expected:
            problems.append((name, f"got {got} of {expected} bytes"))
            continue
        with open(dest, "rb") as handle:
            header = handle.read(0x18)
        if header[:3] != TRP_MAGIC:
            problems.append((name, f"{npwr}'s TROPHY.TRP is not a plain TRP"))
            continue
        # A TRP records its own length, which catches a short read without
        # having to trust the server's listing.
        declared = struct.unpack_from(">Q", header, 0x08)[0]
        if declared != got:
            problems.append((name, f"TRP declares {declared} bytes, got {got}"))
            continue
        written += 1
    return written, problems


def verify(dest_root, plan):
    """Returns the plan entries whose file is missing or the wrong size."""
    bad = []
    for rel, _offset, size in plan:
        path = os.path.join(dest_root, rel)
        try:
            if os.path.getsize(path) != size:
                bad.append((rel, size, os.path.getsize(path)))
        except OSError:
            bad.append((rel, size, None))
    return bad


def nest_path(title, layer):
    return f"/mnt/sandbox/pfsmnt/{title}-{layer}-nest/pfs_image.dat"


def main():
    parser = argparse.ArgumentParser(
        description="Dump a PS4 title's app+patch tree by streaming its PFS images.")
    parser.add_argument("host", help="console address, optionally HOST:PORT")
    parser.add_argument("title", help="title ID, e.g. CUSA01760")
    parser.add_argument("-o", "--output-dir", default=".",
                        help="directory to create <TITLE>-app in (default: .)")
    parser.add_argument("-p", "--port", type=int, default=2121)
    parser.add_argument("--no-patch", action="store_true",
                        help="dump the base game only")
    parser.add_argument("--no-decrypt", action="store_true",
                        help="leave the executables as the encrypted SELFs the "
                             "image stores")
    parser.add_argument("--manifest", action="store_true",
                        help="print the merged write plan and exit")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="name every file as it is written")
    args = parser.parse_args()

    host, port = args.host, args.port
    if ":" in host:
        host, _, spec = host.partition(":")
        port = int(spec)

    app = FtpFile(host, port, nest_path(args.title, "app0"))
    patch = None
    try:
        app_image = PfsImage(app)
        app_manifest = app_image.manifest()

        patch_manifest = []
        if not args.no_patch:
            try:
                patch = FtpFile(host, port, nest_path(args.title, "patch0"))
                patch_manifest = PfsImage(patch).manifest()
            except ftplib.all_errors:
                print(f"No patch image for {args.title}; dumping the base game only.")
                if patch is not None:
                    patch.close()
                    patch = None

        patch_plan, app_plan, superseded, recased = build_plan(
            app_manifest, patch_manifest)
        metadata = app.metadata_bytes + (patch.metadata_bytes if patch else 0)
        total = sum(size for _d, _o, size in patch_plan + app_plan)

        print(f"{args.title}: {len(app_manifest)} base file(s), "
              f"{len(patch_manifest)} patch file(s), {superseded} superseded")
        print(f"  merged tree: {len(patch_plan) + len(app_plan)} file(s), "
              f"{total:,} bytes; metadata cost {metadata / 1048576:.1f} MiB")
        if recased:
            print(f"  {recased} patch path(s) recased to the base game's spelling")

        if args.manifest:
            for rel, offset, size in sorted(patch_plan):
                print(f"patch\t{offset}\t{size}\t{rel}")
            for rel, offset, size in sorted(app_plan):
                print(f"app\t{offset}\t{size}\t{rel}")
            return 0

        dest = os.path.join(args.output_dir, f"{args.title}-app")
        os.makedirs(dest, exist_ok=True)

        # The patch goes first so that nothing the base game writes can land on
        # top of a patched file.
        if patch_plan:
            runs, discarded = extract(patch, dest, patch_plan, "patch",
                                      args.verbose)
            print(f"  patch: {len(patch_plan)} file(s), {runs} run(s), "
                  f"{discarded:,} bytes discarded")
        runs, discarded = extract(app, dest, app_plan, "app", args.verbose)
        print(f"  app:   {len(app_plan)} file(s), {runs} run(s), "
              f"{discarded:,} bytes discarded")

        # Checked before the executables are swapped, since the decrypted copies
        # deliberately no longer match the sizes the image recorded.
        bad = verify(dest, patch_plan + app_plan)
        if bad:
            print(f"{len(bad)} file(s) did not match the plan:", file=sys.stderr)
            for rel, expected, actual in bad[:20]:
                got = "missing" if actual is None else f"{actual} bytes"
                print(f"  {rel}: expected {expected} bytes, got {got}",
                      file=sys.stderr)
            return 1
        print(f"  verified {len(patch_plan) + len(app_plan)} file(s) against the plan")

        if args.no_decrypt:
            print("  executables left encrypted (--no-decrypt)")
            return 0

        mount = FtpMount(host, port)
        try:
            if not mount.enable_decryption():
                print("  warning: the server did not confirm SELF decryption; "
                      "check the executables before building", file=sys.stderr)
            replaced, problems = replace_executables(
                mount, args.title, dest,
                {"patch0": patch_plan, "app0": app_plan}, args.verbose)
            print(f"  decrypted {replaced} executable(s) via the PFS mounts")

            npbind = dump_np_files(mount, args.title, dest)
            sets = trophy_set_ids(npbind)
            if sets:
                written, trophy_problems = dump_trophies(
                    mount, dest, npbind, args.verbose)
                print(f"  wrote {written} of {len(sets)} trophy set(s) "
                      f"from /user/trophy/conf")
                problems += trophy_problems
            elif npbind is None:
                print("  no appmeta for this title; no np files or trophies")
            else:
                print("  npbind.dat names no trophy sets")
        finally:
            mount.close()

        if problems:
            print(f"{len(problems)} item(s) could not be resolved:",
                  file=sys.stderr)
            for rel, reason in problems:
                print(f"  {rel}: {reason}", file=sys.stderr)
            return 1
        return 0
    except Unsupported as err:
        print(f"Unsupported PFS image: {err}", file=sys.stderr)
        return 2
    finally:
        app.close()
        if patch is not None:
            patch.close()


if __name__ == "__main__":
    sys.exit(main())
