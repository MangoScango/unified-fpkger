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
import shutil
import struct
import subprocess
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
PKG_MAGIC = 0x7F434E54
PKG_ENTRY_SIZE = 32
PKG_ENTRY_NAMES = 0x200
PKG_ENTRY_ENCRYPTED = 0x80000000
# Entries below 0x1000 are absent from the name table and carry these names by
# convention. Everything above it names itself.
PKG_NAMELESS = {
    0x400: "license.dat",
    0x401: "license.info",
    0x402: "nptitle.dat",
    0x403: "npbind.dat",
    0x404: "selfinfo.dat",
    0x406: "imageinfo.dat",
    0x407: "target-deltainfo.dat",
    0x408: "origin-deltainfo.dat",
    0x409: "psreserved.dat",
}
# npbind.dat holds these in a tag/length table; scanning for them is enough to
# recover the order, which is what maps a set onto trophy<NN>.trp.
NPWR_ID = re.compile(rb"NPWR[0-9]{5}_[0-9]{2}")

PFSMNT = "/mnt/sandbox/pfsmnt"
TITLE_MOUNT = re.compile(r"^([A-Z]{4}[0-9]{5})-app0$")
# What ks_create produces from an all-zero passcode, so not the retail keystone.
GENERATED_KEYSTONE = ("294a5ed06db170618f2eed8c424b9d82"
                      "8879c080cc66fbc4864f69e974deb856")
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


def close_session(ftp):
    """Ends an FTP session, asking the server to release it.

    A bare socket close leaves the console holding the session, and reconnecting
    often enough during a long dump is a good way to run it out of them.
    """
    try:
        ftp.quit()
        return
    except ftplib.all_errors:
        pass
    try:
        ftp.close()
    except ftplib.all_errors:
        pass


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
        # One layer's control connection sits idle for as long as another layer
        # takes to stream, which on a large patch is long enough for the console
        # to drop it. A refused path is a different matter and is not retried.
        try:
            return self.ftp.transfercmd(f"RETR {self.path}", rest=offset)
        except ftplib.error_perm:
            raise
        except ftplib.all_errors:
            self._connect()
            return self.ftp.transfercmd(f"RETR {self.path}", rest=offset)

    def renew(self):
        """Starts a fresh session, for when this one has been idle a long time."""
        self._connect()

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
            close_session(self.ftp)
            self.ftp = None


class FtpMount:
    """Whole-file reads from the console's PFS mounts, which decrypt SELFs."""

    def __init__(self, host, port, timeout=60):
        self.host, self.port, self.timeout = host, port, timeout
        self.ftp = None
        self._connect()

    def _connect(self):
        self.close()
        self.ftp = ftplib.FTP()
        self.ftp.connect(self.host, self.port, timeout=self.timeout)
        self.ftp.login("anonymous", "")
        self.ftp.voidcmd("TYPE I")

    def _retry(self, action):
        """Runs action, once more on a fresh connection if the old one died.

        This connection idles while whole images stream on another one, which is
        long enough for the console to hang up.
        """
        try:
            return action()
        except ftplib.error_perm:
            raise
        except ftplib.all_errors:
            self._connect()
            return action()

    def listdir(self, path):
        """Base names of the entries in a remote directory."""
        try:
            names = self._retry(lambda: self.ftp.nlst(path))
        except ftplib.all_errors:
            return []
        return sorted(name.rsplit("/", 1)[-1].rstrip("/")
                      for name in names if name.rstrip("/"))

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
            reply = self._retry(lambda: self.ftp.sendcmd(f"MLST {remote}"))
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
        conn = self._retry(lambda: self.ftp.transfercmd(f"RETR {remote}"))
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
        if self.ftp is None:
            return
        close_session(self.ftp)
        self.ftp = None


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
    """Groups an offset-ordered plan into one entry per worthwhile transfer.

    A split is only taken where the next transfer can actually begin. Splitting
    at an offset REST refuses would force transfer_start to rewind to the last
    acceptable one, and that rewind averages a gigabyte, which costs far more
    than reading through the gap the split was meant to avoid.
    """
    runs, current = [], []
    for entry in plan:
        if current:
            gap = entry[1] - (current[-1][1] + current[-1][2])
            if gap > RESEEK_THRESHOLD and reachable(entry[1]):
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
        return 0, 0, 0
    runs = group_runs(ordered)
    bar = Progress(sum(size for _d, _o, size in ordered), label, progress)
    discarded = rewound = 0
    # This layer's session has been idle since its metadata was read, which for
    # the app means however long the patch took to stream.
    remote.renew()

    for run in runs:
        pos = transfer_start(run[0][1])
        rewound += run[0][1] - pos
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
    return len(runs), discarded, rewound


def replace_executables(mount, dest_root, layers, verbose=False):
    """Overwrites the extracted SELFs with the mount's decrypted copies.

    layers maps a pfsmnt directory name onto the plan taken from it, so each
    executable is re-fetched from the layer it actually came from. Returns
    (replaced, [(path, reason)]).
    """
    replaced = 0
    problems = []
    for layer, plan in layers.items():
        for rel, _offset, size in plan:
            if size == 0 or not is_executable(rel):
                continue
            local = os.path.join(dest_root, rel)
            remote = f"{PFSMNT}/{layer}/{rel}"
            if verbose:
                print(f"  {layer}: {rel}", file=sys.stderr)
            staged = local + ".decrypted"
            try:
                written = mount.download(remote, staged)
            except ftplib.all_errors as err:
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


class PkgEntries:
    """The named entries of a remote PKG, which is where sce_sys lives.

    Only the entry table and the region it points at are read; the PFS image
    making up the rest of the package is left alone.
    """

    def __init__(self, remote):
        header = remote.read(0, 0x40)
        magic = struct.unpack_from(">I", header, 0)[0]
        if magic != PKG_MAGIC:
            raise Unsupported(f"not a PS4 package (magic 0x{magic:08x})")
        count = struct.unpack_from(">I", header, 0x10)[0]
        table_offset = struct.unpack_from(">I", header, 0x18)[0]

        table = remote.read(table_offset, count * PKG_ENTRY_SIZE)
        raw = []
        for index in range(count):
            at = index * PKG_ENTRY_SIZE
            raw.append(struct.unpack_from(">IIIIII", table, at))

        # One read covering every entry beats a round trip each, and the table
        # gives its exact extent.
        span_start = min(row[4] for row in raw if row[5])
        span_end = max(row[4] + row[5] for row in raw if row[5])
        blob = remote.read(span_start, span_end - span_start)

        names = b""
        for entry_id, _name_offset, _f1, _f2, data_offset, size in raw:
            if entry_id == PKG_ENTRY_NAMES:
                at = data_offset - span_start
                names = blob[at:at + size]

        self.files = {}
        self.unnamed = []
        self.encrypted = {}
        for entry_id, name_offset, flags1, flags2, data_offset, size in raw:
            if entry_id < 0x400:
                continue
            if entry_id in PKG_NAMELESS:
                name = PKG_NAMELESS[entry_id]
            elif entry_id >= 0x1000 and names:
                end = names.find(b"\0", name_offset)
                name = names[name_offset:end].decode("ascii", "replace")
            else:
                self.unnamed.append(entry_id)
                continue
            at = data_offset - span_start
            self.files[name] = blob[at:at + size]
            # Written out as-is, ciphertext and all. The np files get replaced
            # from appmeta afterwards; the licence entries are account-bound and
            # nothing downstream reads them, which is also true of the dumps
            # ftpdump.sh produces.
            if flags1 & PKG_ENTRY_ENCRYPTED:
                self.encrypted[name] = (flags2 & 0xF000) >> 12


def write_pkg_sce_sys(entries, dest_root, verbose=False):
    """Writes a PKG's entries into sce_sys, overwriting what is already there."""
    sce_sys = os.path.join(dest_root, "sce_sys")
    for name, data in entries.files.items():
        path = os.path.join(sce_sys, name)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        if verbose:
            print(f"  sce_sys/{name}", file=sys.stderr)
        with open(path, "wb") as out:
            out.write(data)
    return len(entries.files)


def open_first(host, port, paths):
    """Opens the first of paths that can actually be read.

    Opening a connection proves nothing about the path, so each candidate is
    probed before being accepted.
    """
    for path in paths:
        remote = FtpFile(host, port, path)
        try:
            remote.read(0, 4)
        except ftplib.all_errors:
            remote.close()
            continue
        return remote, path
    return None, None


def find_pkg(host, port, title, kind):
    """Opens the app or patch package. External installs live under /mnt/ext0."""
    return open_first(host, port, [f"{base}/{kind}/{title}/{kind}.pkg"
                                   for base in ("/user", "/mnt/ext0/user")])


def find_ac_pkg(host, port, title, label):
    """Opens an add-on package by its entitlement label."""
    return open_first(host, port, [f"{base}/addcont/{title}/{label}/ac.pkg"
                                   for base in ("/user", "/mnt/ext0/user")])


def discover_title(mount):
    """The title ID of the running game, per its app0 mount."""
    found = [match.group(1) for match in
             (TITLE_MOUNT.match(name) for name in mount.listdir(PFSMNT)) if match]
    if not found:
        return None, []
    return found[0], found


def find_dlc_mounts(mount, title):
    """The add-on content mounts belonging to a title.

    Their directory name is the add-on's content ID, whose last 16 characters
    are the entitlement label the package is filed under.
    """
    return [name for name in mount.listdir(PFSMNT)
            if name.endswith("-ac") and title in name]


def entitlement_label(ac_mount):
    return ac_mount[:-len("-ac")][-16:]


def keystone_is_generated(path):
    """Whether a keystone is the one ks_create derives from an empty passcode."""
    try:
        with open(path, "rb") as handle:
            handle.seek(0x20)
            return handle.read(0x20).hex() == GENERATED_KEYSTONE
    except OSError:
        return False


def sfo_tool():
    """Locates hippie68's sfo tool"""
    override = os.environ.get("SFO_PATH")
    if override and os.access(override, os.X_OK):
        return override
    beside = os.path.join(os.path.dirname(os.path.abspath(__file__)), "sfo")
    if os.access(beside, os.X_OK):
        return beside
    found = shutil.which("sfo")
    return found


def fix_merged_sfo(path, category):
    """Turns a patch's param.sfo into one an app package will accept.

    A merged tree advertises the game's real version, so the patch's
    TARGET_APP_VER has to go, and its category has to revert to the base
    game's. Returns None on success or a reason why not.
    """
    tool = sfo_tool()
    if tool is None:
        return "sfo not found; set SFO_PATH"
    backup = path + ".orig"
    shutil.copyfile(path, backup)
    # Deleting exits non-zero when the key is absent, which is not an error.
    subprocess.run([tool, path, "-d", "TARGET_APP_VER"],
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                   check=False)
    done = subprocess.run([tool, path, "-e", "category", category],
                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                          check=False)
    if done.returncode != 0:
        shutil.copyfile(backup, path)
        os.unlink(backup)
        return f"sfo could not set category to {category}"
    os.unlink(backup)
    return None


def sfo_query(path, key):
    tool = sfo_tool()
    if tool is None:
        return None
    done = subprocess.run([tool, path, "-q", key], capture_output=True,
                          text=True, check=False)
    return done.stdout.strip() if done.returncode == 0 else None


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
    """Returns the plan entries whose file is missing or the wrong size.

    Executables are exempt: their decrypted form is a different length than the
    image records, so a re-run over a finished dump would otherwise flag every
    one. elf_truncated covers them instead.
    """
    bad = []
    for rel, _offset, size in plan:
        if is_executable(rel):
            continue
        path = os.path.join(dest_root, rel)
        try:
            if os.path.getsize(path) != size:
                bad.append((rel, size, os.path.getsize(path)))
        except OSError:
            bad.append((rel, size, None))
    return bad


def nest_path(title, layer):
    return f"{PFSMNT}/{title}-{layer}-nest/pfs_image.dat"


def ac_nest_path(ac_mount):
    return f"{PFSMNT}/{ac_mount}-nest/pfs_image.dat"


def dump_dlc(host, port, mount, title, out_dir, ac_mounts, decrypt=True,
             verbose=False):
    """Streams each add-on's image into <title>-dlc/<content-id>-ac.

    Add-ons sit on nothing, so unlike the app tree there is no layer to merge
    and no spelling to reconcile.
    """
    root = os.path.join(out_dir, f"{title}-dlc")
    problems = []
    done = 0
    for ac in ac_mounts:
        dest = os.path.join(root, ac)
        remote = FtpFile(host, port, ac_nest_path(ac))
        try:
            plan = PfsImage(remote).manifest()
            os.makedirs(dest, exist_ok=True)
            runs, discarded, rewound = extract(remote, dest, plan, ac, verbose)
        except Unsupported as err:
            problems.append((ac, f"unsupported image: {err}"))
            remote.close()
            continue
        except ftplib.all_errors as err:
            problems.append((ac, f"could not read {ac_nest_path(ac)}: {err}"))
            remote.close()
            continue
        finally:
            remote.close()

        note = f", {rewound:,} rewound" if rewound else ""
        print(f"  dlc {ac}: {len(plan)} file(s), {runs} run(s), "
              f"{discarded:,} bytes discarded{note}")

        bad = verify(dest, plan)
        if bad:
            problems.append((ac, f"{len(bad)} file(s) did not match the plan"))
            continue

        if decrypt:
            replaced, issues = replace_executables(mount, dest, {ac: plan}, verbose)
            problems += issues
            if replaced:
                print(f"    decrypted {replaced} executable(s)")

        label = entitlement_label(ac)
        pkg, pkg_path = find_ac_pkg(host, port, title, label)
        if pkg is None:
            problems.append((ac, f"no ac.pkg for label {label}; "
                                 "sce_sys metadata will be missing"))
            continue
        try:
            entries = PkgEntries(pkg)
        finally:
            pkg.close()
        written = write_pkg_sce_sys(entries, dest, verbose)
        print(f"    sce_sys: {written} entries from {pkg_path}")
        done += 1
    return done, problems


def main():
    parser = argparse.ArgumentParser(
        description="Dump a PS4 title's app+patch tree by streaming its PFS images.")
    parser.add_argument("host", help="console address, optionally HOST:PORT")
    parser.add_argument("title", nargs="?",
                        help="title ID; defaults to the running game")
    parser.add_argument("-o", "--output-dir", default=".",
                        help="directory to create <TITLE>-app in (default: .)")
    parser.add_argument("-p", "--port", type=int, default=2121)
    parser.add_argument("--no-patch", action="store_true",
                        help="dump the base game only")
    parser.add_argument("--no-decrypt", action="store_true",
                        help="leave the executables as the encrypted SELFs the "
                             "image stores")
    parser.add_argument("--no-dlc", action="store_true",
                        help="skip installed add-on content")
    parser.add_argument("--manifest", action="store_true",
                        help="print the merged write plan and exit")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="name every file as it is written")
    args = parser.parse_args()

    host, port = args.host, args.port
    if ":" in host:
        host, _, spec = host.partition(":")
        port = int(spec)

    probe = FtpMount(host, port)
    try:
        title = args.title
        if not title:
            title, candidates = discover_title(probe)
            if not title:
                print("Could not find a mounted app0; is the game running?",
                      file=sys.stderr)
                return 1
            if len(candidates) > 1:
                print(f"Several titles are mounted ({', '.join(candidates)}); "
                      f"using {title}.", file=sys.stderr)
            print(f"Running game: {title}")
        ac_mounts = [] if args.no_dlc else find_dlc_mounts(probe, title)
    finally:
        probe.close()

    app = FtpFile(host, port, nest_path(title, "app0"))
    patch = None
    try:
        app_image = PfsImage(app)
        app_manifest = app_image.manifest()

        patch_manifest = []
        if not args.no_patch:
            try:
                patch = FtpFile(host, port, nest_path(title, "patch0"))
                patch_manifest = PfsImage(patch).manifest()
            except ftplib.all_errors:
                print(f"No patch image for {title}; dumping the base game only.")
                if patch is not None:
                    patch.close()
                    patch = None

        patch_plan, app_plan, superseded, recased = build_plan(
            app_manifest, patch_manifest)
        metadata = app.metadata_bytes + (patch.metadata_bytes if patch else 0)
        total = sum(size for _d, _o, size in patch_plan + app_plan)

        # Phrased the way ftpdump.sh phrases it, because dump-build.sh reads the
        # title back out of this line.
        print(f"Dumping {title} app data ({total // 1000000} MB):")
        print(f"  {len(app_manifest)} base file(s), "
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

        dest = os.path.join(args.output_dir, f"{title}-app")
        os.makedirs(dest, exist_ok=True)

        # The patch goes first so that nothing the base game writes can land on
        # top of a patched file.
        for label, remote, layer_plan in (("patch", patch, patch_plan),
                                          ("app", app, app_plan)):
            if not layer_plan:
                continue
            runs, discarded, rewound = extract(remote, dest, layer_plan, label,
                                               args.verbose)
            note = f", {rewound:,} rewound" if rewound else ""
            print(f"  {label}: {len(layer_plan)} file(s), {runs} run(s), "
                  f"{discarded:,} bytes discarded{note}")

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

        problems = []
        mount = FtpMount(host, port)
        try:
            if args.no_decrypt:
                print("  executables left encrypted (--no-decrypt)")
            else:
                if not mount.enable_decryption():
                    print("  warning: the server did not confirm SELF "
                          "decryption; check the executables before building",
                          file=sys.stderr)
                replaced, problems = replace_executables(
                    mount, dest, {f"{title}-patch0": patch_plan,
                                  f"{title}-app0": app_plan}, args.verbose)
                print(f"  decrypted {replaced} executable(s) via the PFS mounts")
                if replaced:
                    damaged = [rel for rel, _o, _s in patch_plan + app_plan
                               if _s > 0 and is_executable(rel)
                               and elf_truncated(os.path.join(dest, rel))]
                    keystone = os.path.join(dest, "sce_sys", "keystone")
                    if keystone_is_generated(keystone):
                        print("  warning: keystone is not the retail one",
                              file=sys.stderr)
                    problems += [(rel, "decrypted executable is truncated")
                                 for rel in damaged]

            # sce_sys comes from the package entries, not the PFS image. The app
            # goes down first and the patch over it, matching how the layers
            # supersede each other everywhere else.
            base_category = None
            ciphertext = {}
            for kind in ("app", "patch"):
                if kind == "patch" and not patch_manifest:
                    continue
                pkg, pkg_path = find_pkg(host, port, title, kind)
                if pkg is None:
                    problems.append((f"{kind}.pkg", "not found on the console"))
                    continue
                try:
                    entries = PkgEntries(pkg)
                finally:
                    pkg.close()
                written = write_pkg_sce_sys(entries, dest, args.verbose)
                ciphertext.update(entries.encrypted)
                print(f"  sce_sys: {written} entr{'y' if written == 1 else 'ies'} "
                      f"from {pkg_path}")
                if entries.encrypted:
                    listed = ", ".join(
                        f"{n} (key{k})" for n, k in sorted(entries.encrypted.items()))
                    print(f"    encrypted entries written as-is: {listed}")
                if entries.unnamed:
                    problems.append((
                        f"{kind}.pkg",
                        "unnamed entries skipped: "
                        + ", ".join(f"0x{i:x}" for i in entries.unnamed)))
                if kind == "app":
                    base_category = sfo_query(
                        os.path.join(dest, "sce_sys", "param.sfo"), "category")

            if patch_manifest:
                sfo_path = os.path.join(dest, "sce_sys", "param.sfo")
                reason = fix_merged_sfo(sfo_path, base_category or "gd")
                if reason:
                    problems.append(("sce_sys/param.sfo", reason))
                else:
                    print(f"  param.sfo: merged, category {base_category or 'gd'}")

            npbind = dump_np_files(mount, title, dest)
            # These are encrypted in the package, so the appmeta copies are the
            # only usable ones rather than merely the preferred ones.
            for name in ("npbind.dat", "nptitle.dat"):
                if name not in ciphertext:
                    continue
                staged = os.path.join(dest, "sce_sys", name)
                if name == "npbind.dat" and npbind is None:
                    problems.append((f"sce_sys/{name}",
                                     "encrypted in the package and absent from "
                                     "appmeta, so it is still ciphertext"))
                elif not os.path.exists(staged):
                    problems.append((f"sce_sys/{name}", "missing"))
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

            if ac_mounts:
                print(f"Dumping {title} DLC data ({len(ac_mounts)} add-on(s)):")
                done, dlc_problems = dump_dlc(
                    host, port, mount, title, args.output_dir, ac_mounts,
                    decrypt=not args.no_decrypt, verbose=args.verbose)
                print(f"  {done} of {len(ac_mounts)} add-on(s) dumped")
                problems += dlc_problems
            elif not args.no_dlc:
                print(f"No DLC data found for {title}.")
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
