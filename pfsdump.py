#!/usr/bin/env python3
"""Dumps a PS4 or PS5 title's tree by streaming the console's PFS images.

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

PS5 titles are detected from the image itself. They have no patch layer, so
only the app image is streamed; sce_sys is then completed from app.pkg's entry
container, the console's appmeta and its trophy and UDS conf directories.
"""

import argparse
import collections
import ftplib
import json
import os
import re
import shutil
import socket
import sqlite3
import struct
import sys
import tempfile
import time
import urllib.request

from tools import playgo_state
from tools.sfo import SFO, SFOError, load_sfo

BLOCK_SIG_SIZE = 40
DINODE_D32_SIZE = 0xA8
DIRENT_FILE, DIRENT_DIR = 2, 3
PFS_MAGIC = 20130315

MODE_SIGNED = 0x1
MODE_ENCRYPTED = 0x4
INODE_COMPRESSED = 0x1
INODE_MODE_DIR = 0x4000

ELF_MAGIC = b"\x7fELF"
SELF_MAGIC = b"\x4f\x15\x3d\x1d"
PS5_SELF_MAGIC = b"\x54\x14\xf5\xee"
SELF_MAGICS = (SELF_MAGIC, PS5_SELF_MAGIC)
TRP_MAGIC = b"\xdc\xa2\x4d"
PKG_MAGIC = 0x7F434E54
FIH_MAGIC = b"\x7fFIH"
FIH_CNT_OFFSET = 0x58
# TROPHY.UCP and uds.ucp share this header, with the file's length as a
# big-endian u64 at 0x08.
UCP_MAGIC = b"\xb2\x28\xc6\x0a"
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
# Internal storage first, then extended storage.
PKG_ROOTS = ("/user", "/mnt/ext0/user", "/mnt/ext1/user")
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
STREAM_RETRIES = 2

# How far back from the end of a PS5 image to look for its superblock. The
# metadata after it is the inode table plus directories, a few MiB on the titles
# seen so far; this leaves room for titles with millions of files.
V2_SUPERBLOCK_SCAN_LIMIT = 2 << 30
V2_SCAN_CHUNK = 8 << 20
V2_HOLE_STEP = 1 << 16
# Directories spread wider than this are fetched one by one instead of in a
# single read covering all of them.
DIRECTORY_SPAN_LIMIT = 256 << 20


class Unsupported(Exception):
    """The image uses a PFS feature this reader deliberately does not handle."""


# The console returns this in a 550 reply when a path exists in the PFS tree but
# has no backing data, i.e. content the user chose not to install. It is ENOTSUP
# (95), distinct from a missing path or a transfer error, and reproducibly so.
NOT_INSTALLED_CODE = "0x0000005f"


def is_not_installed_error(err):
    """Whether a 550 reply means the file's data was never downloaded."""
    return isinstance(err, ftplib.error_perm) and NOT_INSTALLED_CODE in str(err)


def is_executable(path):
    name = path.rsplit("/", 1)[-1].lower()
    return name in EXECUTABLE_NAMES or name.endswith(EXECUTABLE_SUFFIXES)


def elf_truncated(path):
    """Whether an ELF's program headers reach past the end of the file.

    The mount advertises the encrypted size for the files it decrypts, so a
    short download cannot be caught by comparing sizes.
    """
    size = os.path.getsize(path)
    if size < 0x40:
        return True
    with open(path, "rb") as handle:
        head = handle.read(0x40)
        if head[:4] != ELF_MAGIC:
            return True
        ph_offset = struct.unpack_from("<Q", head, 0x20)[0]
        ph_size, ph_count = struct.unpack_from("<HH", head, 0x36)
        if ph_size < 0x38 or ph_offset + ph_size * ph_count > size:
            return True
        handle.seek(ph_offset)
        table = handle.read(ph_size * ph_count)
        if len(table) != ph_size * ph_count:
            return True
        for i in range(ph_count):
            at = i * ph_size
            offset = struct.unpack_from("<Q", table, at + 0x08)[0]
            length = struct.unpack_from("<Q", table, at + 0x20)[0]
            if offset + length > size:
                return True
    return False


def reachable(offset):
    """Whether the server will accept this offset in a REST command.

    A buggy FTP server reads the low 32 bits as a signed int and refuses any
    offset whose low word has its top bit set. detect_rest_bug() detects this.
    """
    return (offset & 0xFFFFFFFF) < 0x80000000


def transfer_start(offset, rest_workaround):
    """The highest REST offset from which a transfer will actually reach offset.

    On a buggy server, snap back to the last acceptable offset in the window.
    On a fixed server, start exactly where we want to.
    """
    if not rest_workaround or reachable(offset):
        return offset
    return (offset >> 32 << 32) + 0x7FFFFFFF


def detect_rest_bug(host, port, path, image_extent):
    """Detects servers that reject REST offsets with the int32 sign bit set.

    Returns None when the image is too small to probe or the probe could not
    establish an answer. The workaround is only enabled after a definite 550 at
    an offset known to be inside the image.
    """
    probe_offset = 0x80000000
    if image_extent <= probe_offset:
        return None
    ftp = ftplib.FTP()
    try:
        ftp.connect(host, port, timeout=20)
        ftp.login("anonymous", "")
        ftp.voidcmd("TYPE I")
        conn = ftp.transfercmd(f"RETR {path}", rest=probe_offset)
        data = conn.recv(4)
        conn.close()
        return False if data else None
    except ftplib.error_perm:
        return True
    except ftplib.all_errors:
        return None
    finally:
        close_session(ftp)


def close_session(ftp):
    """Ends an FTP session, asking the server to release it.

    A bare socket close leaves the console holding the session, and reconnecting
    often enough during a long dump is a good way to run it out of them.
    """
    if getattr(ftp, "sock", None) is None:
        ftp.close()
        return
    try:
        ftp.quit()
        return
    except ftplib.all_errors:
        pass
    ftp.close()


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

    def size(self):
        """The file's size from a listing of its directory, or None.

        MLSD is the one source every server tested gets right; SIZE wraps on
        PS4 and MLST reports the wrong entry on PS5.
        """
        parent, _, name = self.path.rpartition("/")
        try:
            for entry, facts in self.ftp.mlsd(parent or "/"):
                if entry == name and "size" in facts:
                    return int(facts["size"])
        except ftplib.all_errors:
            return None
        return None

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
        self.decrypting = False
        self._connect()

    def _connect(self):
        self.close()
        self.ftp = ftplib.FTP()
        self.ftp.connect(self.host, self.port, timeout=self.timeout)
        self.ftp.login("anonymous", "")
        self.ftp.voidcmd("TYPE I")
        # The PS5 server keeps SELF mode per session, so a reconnect would
        # otherwise quietly start handing out encrypted executables.
        if self.decrypting:
            self._drive_toggle(self.decrypt_verb)

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

    def walk(self, path, prefix=""):
        """Yields (relative path, size) for every file below a remote directory.

        Unreadable directories yield nothing.
        """
        try:
            entries = self._retry(lambda: list(self.ftp.mlsd(path)))
        except ftplib.all_errors:
            return
        for name, facts in sorted(entries):
            kind = facts.get("type")
            if kind == "dir":
                yield from self.walk(f"{path}/{name}", f"{prefix}{name}/")
            elif kind == "file":
                yield prefix + name, int(facts.get("size", 0))

    def enable_decryption(self):
        """Turns server-side SELF decryption on.

        The PS4 server calls this DECRYPT and the PS5 one SELF; both toggle, so
        the reply is read back and the command sent again if it reported off.
        Returns False when neither command confirms decryption, which may mean
        the server always decrypts or that it never does.
        """
        for verb in ("DECRYPT", "SELF"):
            state = self._drive_toggle(verb)
            if state is None:
                continue
            if state:
                self.decrypt_verb = verb
                self.decrypting = True
            return state
        return False

    def _drive_toggle(self, verb):
        """Sends verb until its reply reports enabled. None if unrecognised."""
        for _attempt in (1, 2):
            try:
                reply = self.ftp.sendcmd(verb).lower()
            except ftplib.all_errors:
                return None
            if "enabled" in reply:
                return True
            if "disabled" not in reply:
                return None
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
    """The directory tree and data extents of an unsigned, decrypted PFS image.

    Handles both layouts the consoles mount. PS4 images (version 1) start with
    the superblock and address data through per-inode block lists. PS5 images
    (version 2) put file data first and the superblock near the end, and each
    inode gives its data as one contiguous byte range.

    self.inodes holds (mode, size, offset, span, flags), with offset and span in
    bytes; span is how much of the image the inode's data occupies.
    """

    def __init__(self, remote):
        self.remote = remote
        self._dir_cache = {}
        hdr = remote.read(0, 0x400)
        version, magic = struct.unpack_from("<qq", hdr, 0)
        if version == 1 and magic == PFS_MAGIC:
            self.version = 1
            self.image_size = None
            self._load(hdr, 0)
        else:
            self.version = 2
            self.image_size = remote.size()
            if self.image_size is None:
                raise Unsupported("no PFS superblock at offset 0 and the "
                                  "image size is unknown, so the tail cannot "
                                  "be searched")
            self._load_from_tail()

    def _read_tolerant(self, start, stop):
        """Bytes of start..stop, with an unreadable lead-in zeroed.

        Chunks the console never downloaded leave holes in the image, and a
        read that starts inside one returns nothing. The tail we scan for the
        superblock is readable from the hole's end onward.
        """
        try:
            return self.remote.read(start, stop - start)
        except IOError:
            pass
        low, high = start, stop
        while high - low > V2_HOLE_STEP:
            middle = low + (high - low) // 2
            try:
                self.remote.read(middle, 1)
                high = middle
            except IOError:
                low = middle
        try:
            return bytes(high - start) + self.remote.read(high, stop - high)
        except IOError:
            return bytes(stop - start)

    def _load_from_tail(self):
        """Finds the version 2 superblock by searching back from the end.

        Candidates are tried highest first and must survive a full metadata
        load, which rejects a chance match inside file data.
        """
        needle = struct.pack("<qq", 2, PFS_MAGIC)
        end = self.image_size
        floor = max(0, end - V2_SUPERBLOCK_SCAN_LIMIT)
        reasons = []
        while end > floor:
            start = max(floor, end - V2_SCAN_CHUNK)
            # Overlap so a needle straddling two chunks is still seen.
            chunk = self._read_tolerant(
                start, min(end + len(needle), self.image_size))
            # Matches starting at or past end were tried with the previous chunk.
            hit = min(len(chunk), end - start + len(needle) - 1)
            while True:
                hit = chunk.rfind(needle, 0, hit)
                if hit < 0:
                    break
                at = start + hit
                if at + 0x400 > self.image_size:
                    continue
                try:
                    self._load(self.remote.read(at, 0x400), at)
                    return
                except Unsupported as err:
                    reasons.append(f"{at:,}: {err}")
            end = start
        detail = f"; rejected {'; '.join(reasons[:3])}" if reasons else ""
        raise Unsupported(f"no version 2 superblock in the last "
                          f"{(self.image_size - floor) >> 20:,} MiB{detail}")

    def _load(self, hdr, base):
        self._dir_cache = {}
        self.superblock_offset = base
        self.mode = struct.unpack_from("<H", hdr, 0x1C)[0]
        if self.mode & MODE_ENCRYPTED:
            raise Unsupported("image is encrypted; this reader has no key handling")
        if self.mode & MODE_SIGNED:
            raise Unsupported("image uses signed inodes; only unsigned are handled")
        self.block_size = struct.unpack_from("<I", hdr, 0x20)[0]
        bs = self.block_size
        if bs < 0x1000 or bs > 1 << 20 or bs & (bs - 1):
            raise Unsupported(f"implausible block size {bs}")
        self.inode_count, _ndblock, self.inode_block_count = \
            struct.unpack_from("<qqq", hdr, 0x30)
        per_block = bs // DINODE_D32_SIZE
        if not 0 < self.inode_count <= self.inode_block_count * per_block:
            raise Unsupported(f"{self.inode_count} inodes do not fit in "
                              f"{self.inode_block_count} block(s)")

        # The inode table follows the superblock, past whatever indirect blocks
        # the header's own inode claims.
        ib_base = 0x50 + 0x68 + 12 * BLOCK_SIG_SIZE
        indirect = sum(
            1 for i in range(5)
            if struct.unpack_from("<q", hdr, ib_base + i * BLOCK_SIG_SIZE + 32)[0] > 0)
        self.inode_table_offset = base + bs * (1 + indirect)
        table_end = self.inode_table_offset + bs * self.inode_block_count
        if self.image_size is not None and table_end > self.image_size:
            raise Unsupported("inode table runs past the end of the image")

        self._read_inodes()
        if not self.inodes[0][0] & INODE_MODE_DIR:
            raise Unsupported("inode 0 is not a directory")
        self._read_directory_blocks()
        self.uroot = next((i for kind, name, i in self.dirents(0)
                           if kind == DIRENT_DIR and name == "uroot"), None)
        if self.uroot is None:
            raise Unsupported("image has no uroot directory")

    def _read_inodes(self):
        bs = self.block_size
        table = self.remote.read(self.inode_table_offset,
                                 bs * self.inode_block_count)
        per_block = bs // DINODE_D32_SIZE
        self.inodes = []
        for block in range(self.inode_block_count):
            for slot in range(per_block):
                if len(self.inodes) >= self.inode_count:
                    break
                off = block * bs + slot * DINODE_D32_SIZE
                mode = struct.unpack_from("<H", table, off)[0]
                flags = struct.unpack_from("<I", table, off + 0x04)[0]
                size = struct.unpack_from("<q", table, off + 0x08)[0]
                index = len(self.inodes)
                if self.version == 2:
                    offset = struct.unpack_from("<Q", table, off + 0x60)[0]
                    self.inodes.append((mode, size, offset, size, flags))
                    continue
                blocks = struct.unpack_from("<I", table, off + 0x60)[0]
                direct = struct.unpack_from("<12i", table, off + 0x64)
                if flags & INODE_COMPRESSED:
                    raise Unsupported(f"inode {index} is PFSC-compressed")
                if not mode & INODE_MODE_DIR and blocks > 1 and direct[1] != -1:
                    raise Unsupported(f"inode {index} has a non-contiguous block list")
                self.inodes.append((mode, size, direct[0] * bs,
                                    max(blocks, 1) * bs, flags))

    def _read_directory_blocks(self):
        """Reads every directory's data in one transfer when that is cheap.

        The directories normally sit together, but nothing requires it; a
        spread-out image is read one directory at a time instead.
        """
        extents = [(offset, offset + span)
                   for mode, _size, offset, span, _flags in self.inodes
                   if mode & INODE_MODE_DIR and span > 0]
        if self.image_size is not None:
            extents = [(lo, hi) for lo, hi in extents if hi <= self.image_size]
        if not extents:
            raise Unsupported("image has no readable directories")
        self.dir_first = min(lo for lo, _hi in extents)
        last = max(hi for _lo, hi in extents)
        if last - self.dir_first <= DIRECTORY_SPAN_LIMIT:
            self.dir_blocks = self.remote.read(self.dir_first, last - self.dir_first)
        else:
            self.dir_blocks = None

    def _directory_data(self, index):
        mode, _size, offset, span, _flags = self.inodes[index]
        if not mode & INODE_MODE_DIR:
            raise Unsupported(f"inode {index} is listed as a directory but is not one")
        if self.image_size is not None and offset + span > self.image_size:
            raise Unsupported(f"directory inode {index} lies outside the image")
        if self.dir_blocks is not None:
            at = offset - self.dir_first
            if 0 <= at and at + span <= len(self.dir_blocks):
                return self.dir_blocks[at:at + span]
        if index not in self._dir_cache:
            self._dir_cache[index] = self.remote.read(offset, span)
        return self._dir_cache[index]

    def dirents(self, index):
        data = self._directory_data(index)
        bs = self.block_size
        for base in range(0, len(data), bs):
            end = min(base + bs, len(data))
            pos = base
            while pos + 16 <= end:
                inode, kind, name_len, ent_size = struct.unpack_from(
                    "<IiiI", data, pos)
                if ent_size == 0:
                    break
                raw = data[pos + 16:pos + 16 + name_len]
                yield kind, raw.split(b"\0")[0].decode("utf-8"), inode
                pos += ent_size

    def manifest(self):
        """Returns [(path, offset, size)] for every file below uroot."""
        entries = []

        def walk(index, prefix):
            for kind, name, child in self.dirents(index):
                if kind == DIRENT_DIR:
                    walk(child, prefix + name + "/")
                elif kind == DIRENT_FILE:
                    _mode, size, offset, _span, flags = self.inodes[child]
                    if flags & INODE_COMPRESSED:
                        raise Unsupported(f"{prefix + name} is PFSC-compressed")
                    if (self.image_size is not None
                            and offset + size > self.image_size):
                        raise Unsupported(f"{prefix + name} lies outside the image")
                    entries.append((prefix + name, offset, size))

        walk(self.uroot, "")
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


def group_runs(plan, rest_workaround=False):
    """Groups an offset-ordered plan into one entry per worthwhile transfer.

    A split is only taken where the next transfer can actually begin. On a
    buggy server, splitting at a forbidden offset forces transfer_start to
    rewind; streaming through the gap is cheaper than the rewind.
    """
    runs, current = [], []
    for entry in plan:
        if current:
            gap = entry[1] - (current[-1][1] + current[-1][2])
            start_ok = not rest_workaround or reachable(entry[1])
            if gap > RESEEK_THRESHOLD and start_ok:
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


def recover_from_loose(host, port, loose_root, rel, dest, expected_size,
                       allow_decrypted=True):
    """Fetches one file through its mounted path into dest.

    Returns (success, reason). Regular files must match the PFS manifest size;
    executables may differ only when decrypted output is allowed and complete.
    """
    directory = os.path.dirname(dest) or "."
    fd, staged = tempfile.mkstemp(
        prefix=f".{os.path.basename(dest)}.", suffix=".loose", dir=directory)
    os.close(fd)
    mount = None
    try:
        mount = FtpMount(host, port)
        written = mount.download(f"{loose_root}/{rel}", staged)
        if is_executable(rel):
            with open(staged, "rb") as handle:
                magic = handle.read(4)
            if magic == ELF_MAGIC:
                complete_elf = not elf_truncated(staged)
                valid = allow_decrypted and complete_elf
                if not allow_decrypted:
                    invalid_reason = "loose mount returned a decrypted ELF"
                else:
                    invalid_reason = "loose mount returned an incomplete ELF"
            else:
                valid = magic in SELF_MAGICS and written == expected_size
                invalid_reason = (
                    f"loose mount returned executable magic {magic.hex()} "
                    f"and {written} of {expected_size} bytes")
        else:
            valid = written == expected_size
            invalid_reason = f"loose mount returned {written} of {expected_size} bytes"
        if not valid:
            os.unlink(staged)
            return False, invalid_reason
        os.replace(staged, dest)
        return True, ""
    except (OSError, EOFError, ftplib.Error) as err:
        if os.path.exists(staged):
            os.unlink(staged)
        return False, str(err)
    finally:
        if mount is not None:
            mount.close()


def resume_from_loose(host, port, loose_root, rel, dest, have, size,
                      rest_workaround):
    """Appends the rest of a file, from byte `have`, read through its mount.

    For when the image stream gave out partway through a file. Only for files
    the mount serves unchanged; a decrypted executable would differ from the
    bytes already written. Returns (success, reason).
    """
    remote = FtpFile(host, port, f"{loose_root}/{rel}")
    try:
        conn, _skipped = open_stream_at(remote, have, rest_workaround)
        try:
            with open(dest, "ab") as out:
                while have < size:
                    chunk = conn.recv(min(CHUNK, size - have))
                    if not chunk:
                        break
                    out.write(chunk)
                    have += len(chunk)
        finally:
            remote.finish(conn)
    except (OSError, EOFError, ftplib.Error) as err:
        return False, str(err)
    finally:
        remote.close()
    if os.path.getsize(dest) != size:
        return False, f"mount returned {os.path.getsize(dest)} of {size} bytes"
    return True, ""


def open_stream_at(remote, target, rest_workaround):
    """Opens the image stream positioned at target.

    A server with the REST sign-bit bug may require starting earlier and
    discarding up to target. Returns (socket, bytes_discarded).
    """
    start = transfer_start(target, rest_workaround)
    remote.renew()
    conn = remote.open_at(start)
    discarded = 0
    try:
        while start < target:
            chunk = conn.recv(min(CHUNK, target - start))
            if not chunk:
                raise OSError(f"transfer ended while seeking to {target}")
            start += len(chunk)
            discarded += len(chunk)
    except (OSError, EOFError, ftplib.Error):
        conn.close()
        raise
    return conn, discarded


def summarize_skips(skipped, plan):
    """Collapses skipped paths, folding fully-skipped directories.

    A directory is reported as one line when every planned file under it (at any
    depth) was skipped; otherwise its skipped files are listed individually.
    Returns a sorted list of display strings.
    """
    skipped = set(skipped)
    if not skipped:
        return []
    planned_in = collections.defaultdict(int)
    skipped_in = collections.defaultdict(int)
    for rel, _offset, _size in plan:
        for parent in _ancestors(rel):
            planned_in[parent] += 1
    for rel in skipped:
        for parent in _ancestors(rel):
            skipped_in[parent] += 1

    # A directory fully collapses when none of its planned files survived. Take
    # the highest such directory so nested fully-skipped trees fold into one.
    collapsed = set()
    for directory, planned in planned_in.items():
        if skipped_in.get(directory) == planned:
            collapsed.add(directory)
    roots = {d for d in collapsed
             if not any(parent in collapsed for parent in _ancestors(d))}

    lines = [f"{directory}/ (entire directory, "
             f"{planned_in[directory]} file(s))" for directory in roots]
    for rel in skipped:
        if not any(parent in roots for parent in _ancestors(rel)):
            lines.append(rel)
    return sorted(lines)


def _ancestors(rel):
    """Yields each directory prefix of a relative path, deepest last."""
    parts = rel.split("/")[:-1]
    for depth in range(1, len(parts) + 1):
        yield "/".join(parts[:depth])


def extract(remote, dest_root, plan, label, verbose=False, progress=True,
            rest_workaround=False, loose_source=None,
            allow_decrypted_fallback=True, known_missing=frozenset()):
    """Writes every entry in plan, resuming short image transfers as needed.

    loose_source is (host, port, mount root). If the image cannot finish a file
    after STREAM_RETRIES resumptions, that file is fetched through the loose
    mount. Failure of both sources is returned as a warning, not raised.
    Paths in known_missing are not requested and are reported as not installed.
    """
    for rel, _offset, size in plan:
        if size == 0:
            path = os.path.join(dest_root, rel)
            os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
            open(path, "wb").close()

    skipped_not_installed = sorted(
        rel for rel, _offset, size in plan if size > 0 and rel in known_missing)
    ordered = sorted((entry for entry in plan
                      if entry[2] > 0 and entry[0] not in known_missing),
                     key=lambda entry: entry[1])
    if not ordered:
        return 0, 0, 0, 0, [], skipped_not_installed

    runs = group_runs(ordered, rest_workaround)
    bar = Progress(sum(size for _rel, _offset, size in ordered), label, progress)
    discarded = rewound = recovered = 0
    unresolved = []

    for run in runs:
        conn = None
        pos = None
        try:
            for rel, offset, size in run:
                path = os.path.join(dest_root, rel)
                os.makedirs(os.path.dirname(path), exist_ok=True)
                if verbose:
                    print(f"  {rel}", file=sys.stderr)

                # Preserve the sequential stream between files. If it ended in
                # alignment slack, reopen directly at this file instead.
                if conn is not None:
                    try:
                        while pos < offset:
                            chunk = conn.recv(min(CHUNK, offset - pos))
                            if not chunk:
                                raise OSError("image stream ended between files")
                            pos += len(chunk)
                            discarded += len(chunk)
                    except (OSError, EOFError, ftplib.Error):
                        conn.close()
                        conn = None

                written = 0
                failures = 0
                not_installed = False
                with open(path, "wb") as out:
                    while written < size:
                        if conn is None:
                            target = offset + written
                            try:
                                conn, skipped = open_stream_at(
                                    remote, target, rest_workaround)
                                pos = target
                                discarded += skipped
                                rewound += skipped
                            except ftplib.error_perm as err:
                                # Content the console never downloaded reports
                                # this at the file's own start. Retrying and the
                                # loose fallback would only repeat it, so skip.
                                if written == 0 and is_not_installed_error(err):
                                    not_installed = True
                                    break
                                failure_reason = str(err)
                                failures += 1
                                if failures <= STREAM_RETRIES:
                                    print(f"  warning: {label} could not resume "
                                          f"{rel} at {target:,}; retry "
                                          f"{failures}/{STREAM_RETRIES}: {err}",
                                          file=sys.stderr)
                                    continue
                                break
                            except (OSError, EOFError, ftplib.Error) as err:
                                failure_reason = str(err)
                                failures += 1
                                if failures <= STREAM_RETRIES:
                                    print(f"  warning: {label} could not resume "
                                          f"{rel} at {target:,}; retry "
                                          f"{failures}/{STREAM_RETRIES}: {err}",
                                          file=sys.stderr)
                                    continue
                                break

                        try:
                            chunk = conn.recv(min(CHUNK, size - written))
                        except (OSError, EOFError) as err:
                            chunk = b""
                            failure_reason = str(err)
                        else:
                            failure_reason = "unexpected end of stream"
                        if not chunk:
                            conn.close()
                            conn = None
                            failures += 1
                            if failures <= STREAM_RETRIES:
                                print(f"  warning: {label} stream ended inside "
                                      f"{rel} at {written:,}/{size:,}; retry "
                                      f"{failures}/{STREAM_RETRIES}",
                                      file=sys.stderr)
                                continue
                            break

                        out.write(chunk)
                        written += len(chunk)
                        pos += len(chunk)
                        bar.advance(len(chunk))

                if written == size:
                    continue

                if conn is not None:
                    conn.close()
                    conn = None
                # A file the stream gave out on partway keeps what it has, so
                # the mount only supplies the rest.
                if (loose_source is not None and 0 < written < size
                        and not not_installed and not is_executable(rel)):
                    host, port, loose_root = loose_source
                    print(f"  warning: {label} image stopped in {rel} at "
                          f"{written:,}/{size:,}; reading the rest from "
                          f"{loose_root}", file=sys.stderr)
                    ok, reason = resume_from_loose(
                        host, port, loose_root, rel, path, written, size,
                        rest_workaround)
                    if ok:
                        recovered += 1
                        bar.advance(size - written)
                        print(f"  recovered the rest of {rel} from the loose "
                              f"mount", file=sys.stderr)
                        continue
                # An omitted file must be absent, not truncated, so verify and
                # any later build never see a fragment.
                if os.path.exists(path):
                    os.unlink(path)
                if not_installed:
                    skipped_not_installed.append(rel)
                    continue

                if loose_source is not None:
                    host, port, loose_root = loose_source
                    print(f"  warning: {label} image could not finish {rel}; "
                          f"trying {loose_root}/{rel}", file=sys.stderr)
                    ok, reason = recover_from_loose(
                        host, port, loose_root, rel, path, size,
                        allow_decrypted=allow_decrypted_fallback)
                    if ok:
                        recovered += 1
                        bar.advance(size - written)
                        print(f"  recovered {rel} from the loose mount",
                              file=sys.stderr)
                        continue
                else:
                    reason = failure_reason

                unresolved.append((rel, reason or failure_reason))
                print(f"  warning: could not recover {rel}: "
                      f"{reason or failure_reason}; file omitted", file=sys.stderr)
        finally:
            if conn is not None:
                remote.finish(conn)

    bar.finish()
    return len(runs), discarded, rewound, recovered, unresolved, skipped_not_installed


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
            if os.path.isfile(local) and not elf_truncated(local):
                continue
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
        header = remote.read(0, 0x60)
        # A PS5 package wraps the same entry container in a FIH header, and
        # every offset inside the container is relative to where it starts.
        base = 0
        if header[:4] == FIH_MAGIC:
            base = struct.unpack_from("<Q", header, FIH_CNT_OFFSET)[0]
            header = remote.read(base, 0x40)
        magic = struct.unpack_from(">I", header, 0)[0]
        if magic != PKG_MAGIC:
            raise Unsupported(f"not a PS4 or PS5 package (magic 0x{magic:08x})")
        count = struct.unpack_from(">I", header, 0x10)[0]
        table_offset = base + struct.unpack_from(">I", header, 0x18)[0]

        table = remote.read(table_offset, count * PKG_ENTRY_SIZE)
        raw = []
        for index in range(count):
            at = index * PKG_ENTRY_SIZE
            raw.append(struct.unpack_from(">IIIIII", table, at))

        # One read covering every entry beats a round trip each, and the table
        # gives its exact extent.
        span_start = min(row[4] for row in raw if row[5])
        span_end = max(row[4] + row[5] for row in raw if row[5])
        blob = remote.read(base + span_start, span_end - span_start)

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
    """Opens the app or patch package, wherever the title is installed."""
    return open_first(host, port, [f"{base}/{kind}/{title}/{kind}.pkg"
                                   for base in PKG_ROOTS])


def find_ac_pkg(host, port, title, label):
    """Opens an add-on package by its entitlement label."""
    return open_first(host, port, [f"{base}/addcont/{title}/{label}/ac.pkg"
                                   for base in PKG_ROOTS])


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


def relist_dlc_mounts(host, port, title, known):
    """The title's add-on mounts as they are now, and those not in known.

    The entitlement injector mounts every add-on to read its key, so the
    listing taken before it ran can be short.
    """
    mount = FtpMount(host, port)
    try:
        current = find_dlc_mounts(mount, title)
    finally:
        mount.close()
    return current, [name for name in current if name not in known]


def entitlement_label(name):
    """The 16-character label from an add-on's content ID or -ac/-al folder."""
    return re.sub(r"-a[cl]$", "", name)[-16:]


# The payload loader's port. ps5-entitlement-dumper's injector finds the
# running game, asks libSceNpEntitlementAccess for every add-on's key and
# reports back on the same socket.
ELF_LOADER_PORT = 9021
ENTITLEMENT_TIMEOUT = 60
ENTITLEMENTS_FILE = "entitlements.txt"
ENTITLEMENT_KEY_FILE = "entitlement_key.dat"
ENTITLEMENT_LABEL_LINE = re.compile(r"entitlements: \[(\d+)\] label=(\S+)")
ENTITLEMENT_KEY_LINE = re.compile(r"entitlements: \[(\d+)\] key=([0-9A-Fa-f]{32})\b")
ENTITLEMENT_DONE = b"entitlements: done"


def default_injector():
    return os.environ.get("ENTITLEMENT_INJECTOR") or os.path.join(
        os.path.dirname(os.path.realpath(__file__)), "entitlements.elf")


def dump_entitlements(host, injector, port=ELF_LOADER_PORT,
                      timeout=ENTITLEMENT_TIMEOUT):
    """[(label, key hex)] for the running game's add-ons, in report order.

    Add-ons whose key lookup failed are left out. Raises OSError when the
    loader cannot be reached and RuntimeError when the run does not finish.
    """
    with open(injector, "rb") as handle:
        payload = handle.read()
    deadline = time.monotonic() + timeout
    output = bytearray()
    with socket.create_connection((host, port), timeout=30) as sock:
        sock.sendall(payload)
        # The loader reads the payload until EOF.
        sock.shutdown(socket.SHUT_WR)
        while ENTITLEMENT_DONE not in output:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            sock.settimeout(remaining)
            try:
                data = sock.recv(65536)
            except TimeoutError:
                break
            if not data:
                break
            output += data
    text = output.decode("utf-8", "replace")
    if b"no add-on entitlements" in output:
        return []
    if ENTITLEMENT_DONE not in output:
        last = next((line.strip() for line in reversed(text.splitlines())
                     if line.strip()), "no output")
        raise RuntimeError(f"the injector did not finish: {last}")
    labels = {int(m.group(1)): m.group(2)
              for m in ENTITLEMENT_LABEL_LINE.finditer(text)}
    keys = {int(m.group(1)): m.group(2).upper()
            for m in ENTITLEMENT_KEY_LINE.finditer(text)}
    return [(labels[i], keys[i]) for i in sorted(labels) if i in keys]


def running_game_entitlements(host, title, running, injector):
    """{label: key hex}, or None when the keys could not be read."""
    # The injector picks the game process itself, so the keys are only
    # known to be this title's when nothing else is running.
    if running != [title]:
        others = ", ".join(running) or "none"
        print(f"  warning: not reading entitlement keys: {title} is not the "
              f"only running title (running: {others})", file=sys.stderr)
        return None
    if not os.path.isfile(injector):
        print(f"  warning: not reading entitlement keys: no injector at "
              f"{injector}", file=sys.stderr)
        return None
    try:
        print("Injecting ps5-entitlement-dumper")
        found = dump_entitlements(host, injector)
    except (OSError, RuntimeError) as err:
        print(f"  warning: could not read entitlement keys via "
              f"{host}:{ELF_LOADER_PORT}: {err}", file=sys.stderr)
        return None
    print(f"  entitlement keys: {len(found)} add-on(s)")
    return dict(found)


def write_entitlements(dest, keys):
    with open(os.path.join(dest, ENTITLEMENTS_FILE), "w") as handle:
        for label, key in keys.items():
            handle.write(f"{label} {key}\n")


def write_entitlement_key(dest, key):
    with open(os.path.join(dest, ENTITLEMENT_KEY_FILE), "wb") as handle:
        handle.write(bytes.fromhex(key))


def keystone_is_generated(path):
    """Whether a keystone is the one ks_create derives from an empty passcode."""
    try:
        with open(path, "rb") as handle:
            handle.seek(0x20)
            return handle.read(0x20).hex() == GENERATED_KEYSTONE
    except OSError:
        return False


def fix_merged_sfo(path, category):
    """Turns a patch's param.sfo into one an app package will accept.

    A merged tree advertises the game's real version, so the patch's
    TARGET_APP_VER has to go, and its category has to revert to the base
    game's. Returns None on success or a reason why not.
    """
    backup = path + ".orig"
    shutil.copyfile(path, backup)
    try:
        data, _magic = load_sfo(path)
        data.delete("TARGET_APP_VER", ignore_missing=True)
        data.edit("CATEGORY", category)
        data.write(path)
    except (OSError, SFOError, ValueError, struct.error):
        shutil.copyfile(backup, path)
        return f"sfo could not set category to {category}"
    finally:
        os.unlink(backup)
    return None


def sfo_query(path, key):
    try:
        data, _magic = load_sfo(path)
        return data.query(key.upper())
    except (OSError, SFOError, ValueError, struct.error):
        return None


def sfo_delete(path, key):
    try:
        data, _magic = load_sfo(path)
        data.delete(key.upper())
        data.write(path)
        return ""
    except (OSError, SFOError, ValueError, struct.error):
        return None

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


def replace_encrypted_trophies(mount, dest_root, npbind, verbose=False):
    """Swaps any encrypted TRP the package shipped for the console's plain copy.

    The trophy files already exist, written from the package's sce_sys. A TRP
    that is not plaintext gets replaced from /user/trophy/conf, where the nth
    trophy file maps to the nth trophy set named in npbind.dat. Returns
    (replaced, [(name, reason)]).
    """
    trophy_dir = os.path.join(dest_root, "sce_sys", "trophy")
    files = sorted(name for name in os.listdir(trophy_dir)
                   if re.fullmatch(r"trophy\d\d\.trp", name)) \
        if os.path.isdir(trophy_dir) else []
    if not files:
        return 0, []

    ids = trophy_set_ids(npbind)
    replaced = 0
    problems = []
    for index, name in enumerate(files):
        path = os.path.join(trophy_dir, name)
        with open(path, "rb") as handle:
            if handle.read(3) == TRP_MAGIC:
                continue

        if index >= len(ids):
            problems.append((name, "is encrypted and npbind.dat names no set "
                                   "for it"))
            continue
        npwr = ids[index]
        remote = f"/user/trophy/conf/{npwr}/TROPHY.TRP"
        if verbose:
            print(f"  {name} encrypted, replacing from {npwr}", file=sys.stderr)
        got = mount.try_download(remote, path)
        if got is None:
            problems.append((name, f"{npwr} has no TROPHY.TRP on the console"))
            continue
        with open(path, "rb") as handle:
            header = handle.read(0x18)
        if header[:3] != TRP_MAGIC:
            problems.append((name, f"{npwr}'s TROPHY.TRP is not a plain TRP"))
            continue
        # A TRP records its own length, which catches a short read without
        # trusting the server's listing.
        declared = struct.unpack_from(">Q", header, 0x08)[0]
        if declared != got:
            problems.append((name, f"TRP declares {declared} bytes, got {got}"))
            continue
        replaced += 1
    return replaced, problems


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
             verbose=False, rest_workaround=False, sce_sys_from_pkg=True,
             keys=None):
    """Streams each add-on's image into <title>-dlc/<content-id>-ac.

    Add-ons sit on nothing, so unlike the app tree there is no layer to merge
    and no spelling to reconcile. sce_sys_from_pkg=False skips the ac.pkg
    step, which has not been worked out for PS5 add-ons. keys maps entitlement
    labels to keys; each add-on found in it gets an entitlement_key.dat.
    """
    root = os.path.join(out_dir, f"{title}-dlc")
    problems = []
    all_skipped = []
    skip_total = 0
    done = 0
    for ac in ac_mounts:
        dest = os.path.join(root, ac)
        remote = FtpFile(host, port, ac_nest_path(ac))
        try:
            plan = PfsImage(remote).manifest()
            layer_rest_workaround = rest_workaround
            if layer_rest_workaround is None:
                extent = max((offset + size for _rel, offset, size in plan),
                             default=0)
                layer_rest_workaround = detect_rest_bug(
                    host, port, ac_nest_path(ac), extent)
                if layer_rest_workaround:
                    print("    FTP server has the REST sign-bit bug; "
                          "applying workaround")
                if layer_rest_workaround is not None:
                    rest_workaround = layer_rest_workaround
            os.makedirs(dest, exist_ok=True)
            (runs, discarded, rewound, recovered, unresolved,
             skipped) = extract(
                remote, dest, plan, ac, verbose,
                rest_workaround=bool(layer_rest_workaround),
                loose_source=(host, port, f"{PFSMNT}/{ac}"),
                allow_decrypted_fallback=decrypt)
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
        if recovered:
            note += f", {recovered} recovered from loose mount"
        if skipped:
            note += f", {len(skipped)} not installed"
            skip_total += len(skipped)
        print(f"  dlc {ac}: {len(plan)} file(s), {runs} run(s), "
              f"{discarded:,} bytes discarded{note}")
        for line in summarize_skips(skipped, plan):
            all_skipped.append(f"{ac}/{line}")

        skipped_paths = set(skipped)
        unresolved_paths = {rel for rel, _reason in unresolved} | skipped_paths
        bad = verify(dest, plan)
        unexpected = [item for item in bad if item[0] not in unresolved_paths]
        if unexpected:
            problems.append((ac, f"{len(unexpected)} file(s) did not match the plan"))
            continue
        if unresolved:
            print(f"    warning: {len(unresolved)} file(s) omitted after both "
                  f"image and loose extraction failed", file=sys.stderr)

        if decrypt:
            available = [entry for entry in plan
                         if entry[0] not in unresolved_paths]
            replaced, issues = replace_executables(
                mount, dest, {ac: available}, verbose)
            problems += issues
            if replaced:
                print(f"    decrypted {replaced} executable(s)")

        label = entitlement_label(ac)
        if keys is not None:
            if label in keys:
                write_entitlement_key(dest, keys[label])
                print(f"    entitlement key: {keys[label]}")
            else:
                print(f"    warning: the game reported no entitlement key for "
                      f"{label}", file=sys.stderr)

        if not sce_sys_from_pkg:
            done += 1
            continue
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
    return done, problems, all_skipped, skip_total


AL_CONTENT_ID = re.compile(
    r"[A-Z]{2}[0-9]{4}-([A-Z]{4}[0-9]{5})_00-.{16}")
ENTITLEMENT_DBS = (
    "/system_data/priv/license/entitlement4.db",
    "/system_data/priv/license/entitlement.db",
)


def write_ps4_al_param(path, content_id, title_id, title):
    """Write the minimal SFO shared by console- and PSN-derived unlockers."""
    param = SFO()
    for param_type, key, value in (
            ("int", "ATTRIBUTE", "0"),
            ("str", "CATEGORY", "ac"),
            ("str", "CONTENT_ID", content_id),
            ("str", "FORMAT", "obs"),
            ("str", "TITLE", title),
            ("str", "TITLE_ID", title_id),
            ("str", "VERSION", "01.00")):
        param.set(param_type, key, value)
    param.write(path)


def write_ps5_al_param(path, content_id, title_id, title, concept_id):
    param = {
        "conceptId": concept_id,
        "contentId": content_id,
        "contentVersion": "01.000.000",
        "localizedParameters": {
            "defaultLanguage": "en-US",
            "en-US": {"titleName": title},
        },
        "masterVersion": "01.00",
        "requiredSystemSoftwareVersion": "0x0100000000000000",
        "titleId": title_id,
    }
    with open(path, "w", encoding="utf-8") as out:
        json.dump(param, out, ensure_ascii=False, indent=2)
        out.write("\n")


PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"


def to_png(data):
    """Return icon0 as an 8-bit RGB PNG, the only form Publishing Tools accepts."""
    # IHDR holds bit depth at byte 24 and color type at byte 25; type 2 is RGB.
    if data.startswith(PNG_SIGNATURE) and data[24:26] == b"\x08\x02":
        return data
    from PIL import Image
    import io
    out = io.BytesIO()
    Image.open(io.BytesIO(data)).convert("RGB").save(out, "PNG", optimize=True)
    return out.getvalue()


def dump_dlc_entitlements(host, port, out_dir, filter_title=None,
                          required=False, verbose=False, keys=None):
    """Builds unlocker directories for additional-content licenses.

    Missing prerequisites skip an automatic dump with a warning, but fail an
    explicitly requested one. keys maps entitlement labels to keys, and each
    unlocker found in it gets an entitlement_key.dat. Returns the number of
    licenses written.
    """
    def missing_prereq(message):
        if required:
            raise RuntimeError(message)
        print(f"  warning: {message} Skipping DLC entitlement unlockers.",
              file=sys.stderr)
        return 0

    try:
        os.makedirs(out_dir, exist_ok=True)
    except OSError as err:
        raise RuntimeError(f"could not create output directory {out_dir}: {err}") from err

    print("Downloading entitlement database ...")
    data = None
    error = None
    for path in ENTITLEMENT_DBS:
        try:
            data = fetch_whole(host, port, path)
            error = None
        except (OSError, EOFError, ftplib.Error) as err:
            error = err
            continue
        if data:
            break
    if not data:
        if error is not None:
            raise RuntimeError(
                f"could not download entitlement database: {error}") from error
        return missing_prereq(
            "No entitlement data found at entitlement4.db or entitlement.db.")

    with tempfile.TemporaryDirectory(prefix="pfsdump-entitlements-") as tmp:
        db_path = os.path.join(tmp, "entitlement.db")
        try:
            with open(db_path, "wb") as out:
                out.write(data)
            db = sqlite3.connect(db_path)
        except (OSError, sqlite3.Error) as err:
            return missing_prereq(f"Could not read entitlement.db: {err}.")
        try:
            try:
                tables = [row[0] for row in db.execute(
                    "SELECT name FROM sqlite_master WHERE type='table' "
                    "AND name LIKE 'entitlement_%';")]
            except sqlite3.Error as err:
                return missing_prereq(
                    f"Could not read tables from entitlement.db: {err} "
                    "(corrupt download?).")
            if not tables:
                print("No entitlement tables found in entitlement.db.")
                return 0

            licenses = []
            for table in tables:
                if verbose:
                    print(f"  entitlement table: {table}", file=sys.stderr)
                quoted_table = table.replace('"', '""')
                try:
                    rows = db.execute(
                        f'''SELECT json_extract(JSON, '$.id'),
                                   coalesce(json_extract(JSON, '$.gameMeta.name'),
                                            json_extract(JSON, '$.game_meta.name'),
                                            json_extract(JSON, '$.name'), ''),
                                   coalesce(json_extract(JSON, '$.gameMeta.iconUrl'),
                                            json_extract(JSON, '$.game_meta.icon_url'), ''),
                                   coalesce(json_extract(JSON, '$.conceptMeta.conceptId'),
                                            json_extract(JSON, '$.titleMeta.conceptId'), '')
                            FROM "{quoted_table}" WHERE Package_type LIKE 'PS%AL';''').fetchall()
                except sqlite3.Error as err:
                    return missing_prereq(
                        f"Could not read DLC entitlements from table {table}: {err}.")

                for content_id, title, icon_url, concept_id in rows:
                    if not content_id:
                        continue
                    match = AL_CONTENT_ID.fullmatch(content_id)
                    if match is None:
                        if verbose:
                            print(f"  skipping entitlement with unexpected content ID "
                                  f"{content_id}", file=sys.stderr)
                        continue
                    title_id = match.group(1)
                    if filter_title and title_id != filter_title:
                        continue
                    licenses.append((content_id, title or content_id,
                                     icon_url, title_id, str(concept_id)))
        finally:
            db.close()

    for content_id, title, icon_url, title_id, concept_id in licenses:
        dlc_dir = os.path.join(
            out_dir, f"{title_id}-dlc", f"{content_id}-al")
        sce_sys = os.path.join(dlc_dir, "sce_sys")
        try:
            os.makedirs(sce_sys, exist_ok=True)
        except OSError as err:
            raise RuntimeError(
                f"could not create unlocker directory for {content_id}: {err}"
            ) from err

        if title_id.startswith("PPSA"):
            try:
                write_ps5_al_param(
                    os.path.join(sce_sys, "param.json"),
                    content_id, title_id, title, concept_id)
            except OSError as err:
                raise RuntimeError(
                    f"could not build param.json for {content_id}: {err}") from err
            try:
                os.unlink(os.path.join(sce_sys, "param.sfo"))
            except FileNotFoundError:
                pass
            except OSError as err:
                raise RuntimeError(
                    f"could not remove stale param.sfo for {content_id}: {err}"
                ) from err
        else:
            try:
                write_ps4_al_param(
                    os.path.join(sce_sys, "param.sfo"),
                    content_id, title_id, title)
            except (OSError, SFOError, ValueError) as err:
                raise RuntimeError(
                    f"could not build param.sfo for {content_id}: {err}") from err

        if icon_url:
            icon_path = os.path.join(sce_sys, "icon0.png")
            try:
                with urllib.request.urlopen(icon_url, timeout=30) as response:
                    icon = to_png(response.read())
                with open(icon_path, "wb") as out:
                    out.write(icon)
            except Exception as err:
                try:
                    os.unlink(icon_path)
                except FileNotFoundError:
                    pass
                print(f"  warning: could not download icon0.png for "
                      f"{content_id}: {err}", file=sys.stderr)

        print(f"{content_id}  ({title_id})  {title}")
        if keys is not None:
            label = entitlement_label(content_id)
            if label in keys:
                write_entitlement_key(dlc_dir, keys[label])
                print(f"    entitlement key: {keys[label]}")
            else:
                print(f"    warning: the game reported no entitlement key for "
                      f"{label}", file=sys.stderr)

    count = len(licenses)
    if count == 0:
        if filter_title:
            print(f"No DLC entitlements found for {filter_title}.")
        else:
            print("No DLC entitlements found in entitlement.db.")
    else:
        print(f"Created {count} DLC unlocker template(s) under "
              f"\"{out_dir}/<title_id>-dlc/\".")
    return count


def dump_ps4_metadata(host, port, mount, title, dest, has_patch,
                      verbose=False, patch_only=False):
    """Writes sce_sys from PKGs and fixes up the result.

    Covers the merged param.sfo, the np files and the trophy files. patch_only
    selects just patch.pkg and leaves its patch metadata unmerged. Returns
    [(item, reason)] for whatever could not be resolved.
    """
    problems = []
    # sce_sys comes from the package entries, not the PFS image. The app
    # goes down first and the patch over it, matching how the layers
    # supersede each other everywhere else.
    base_category = None
    ciphertext = {}
    kinds = ("patch",) if patch_only else ("app", "patch")
    for kind in kinds:
        if kind == "patch" and not has_patch:
            continue
        pkg, pkg_path = find_pkg(host, port, title, kind)
        if pkg is None:
            problems.append((f"{kind}.pkg", "not found on the console"))
            continue
        try:
            entries = PkgEntries(pkg)
        finally:
            pkg.close()
        written = write_pkg_sce_sys(entries, dest, verbose)
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
        sfo_path = os.path.join(dest, "sce_sys", "param.sfo")
        if kind == "app":
            base_category = sfo_query(sfo_path, "category")
            remaster_type = sfo_query(sfo_path, "remaster_type")
            if remaster_type:
                print(f"  param.sfo: clearing remaster flag {remaster_type}")
                sfo_delete(sfo_path, "remaster_type")

    if has_patch and not patch_only:
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
    replaced, trophy_problems = replace_encrypted_trophies(
        mount, dest, npbind, verbose)
    problems += trophy_problems
    if replaced:
        print(f"  replaced {replaced} encrypted trophy file(s) "
              f"from /user/trophy/conf")
    return problems


def ucp_complete(path):
    """Whether a file is a plaintext UCP as long as its header says."""
    try:
        with open(path, "rb") as handle:
            header = handle.read(0x10)
        size = os.path.getsize(path)
    except OSError:
        return False
    return (header[:4] == UCP_MAGIC
            and struct.unpack_from(">Q", header, 0x08)[0] == size)


def dump_ps5_metadata(host, port, mount, title, dest, verbose=False):
    """Fills in the parts of sce_sys a PS5 image leaves out.

    The image carries only a few sce_sys files; param.json, the artwork and
    the np and trophy files live in app.pkg's entry container. Those entries
    fill whatever the image lacks, then the console's appmeta overwrites them
    because several are encrypted in the package. Trophy and UDS files come
    from the console's conf directories, the nth set named in npbind.dat
    becoming trophy<NN>.ucp and uds<NN>.ucp. Returns [(item, reason)].
    """
    problems = []
    sce_sys = os.path.join(dest, "sce_sys")
    os.makedirs(sce_sys, exist_ok=True)
    plaintext = set()

    ciphertext = {}
    pkg, pkg_path = find_pkg(host, port, title, "app")
    if pkg is None:
        problems.append(("app.pkg", "not found on the console"))
    else:
        try:
            entries = PkgEntries(pkg)
        finally:
            pkg.close()
        ciphertext = entries.encrypted
        written = 0
        for name, data in entries.files.items():
            path = os.path.join(sce_sys, name)
            if os.path.exists(path):
                continue
            os.makedirs(os.path.dirname(path), exist_ok=True)
            if verbose:
                print(f"  sce_sys/{name}", file=sys.stderr)
            with open(path, "wb") as out:
                out.write(data)
            written += 1
        print(f"  sce_sys: {written} entr{'y' if written == 1 else 'ies'} "
              f"from {pkg_path}")
        if entries.unnamed:
            # Neither the name table nor the id convention names these, so
            # there is no sce_sys path to give them.
            print("    unnamed entries skipped: "
                  + ", ".join(f"0x{i:x}" for i in entries.unnamed))

    copied = 0
    for root in (f"/user/appmeta/{title}", f"/system_data/priv/appmeta/{title}"):
        for rel, _size in mount.walk(root):
            path = os.path.join(sce_sys, rel)
            os.makedirs(os.path.dirname(path), exist_ok=True)
            if mount.try_download(f"{root}/{rel}", path) is None:
                problems.append((f"sce_sys/{rel}", f"could not copy from {root}"))
                continue
            if verbose:
                print(f"  sce_sys/{rel} from {root}", file=sys.stderr)
            plaintext.add(rel)
            copied += 1
    print(f"  sce_sys: {copied} file(s) from appmeta")

    def npbind(kind):
        for sub in (kind, "trophy2" if kind == "uds" else "uds"):
            path = os.path.join(sce_sys, sub, "npbind.dat")
            if sub + "/npbind.dat" in plaintext:
                with open(path, "rb") as handle:
                    return handle.read()
        return None

    fetched = 0
    for kind, conf, remote_name, local_fmt in (
            ("trophy2", "/user/trophy2/nobackup/conf", "TROPHY.UCP",
             "trophy2/trophy{:02d}.ucp"),
            ("uds", "/user/np_uds/nobackup/conf", "uds.ucp", "uds/uds{:02d}.ucp")):
        for index, npwr in enumerate(trophy_set_ids(npbind(kind))):
            rel = local_fmt.format(index)
            path = os.path.join(sce_sys, rel)
            os.makedirs(os.path.dirname(path), exist_ok=True)
            got = mount.try_download(f"{conf}/{npwr}/{remote_name}", path)
            if got is None:
                if rel in ciphertext:
                    problems.append((f"sce_sys/{rel}",
                                     f"{npwr} has no {remote_name} on the console"))
                continue
            if not ucp_complete(path):
                problems.append((f"sce_sys/{rel}",
                                 f"{npwr}'s {remote_name} is not a complete UCP"))
                continue
            if verbose:
                print(f"  sce_sys/{rel} from {npwr}", file=sys.stderr)
            plaintext.add(rel)
            fetched += 1
    if fetched:
        print(f"  sce_sys: {fetched} trophy/UDS file(s) from the console's conf")

    for name in sorted(set(ciphertext) - plaintext):
        if name not in ['license.dat', 'license.info']:
            problems.append((f"sce_sys/{name}",
                             "encrypted in the package and no plaintext copy was "
                             "found on the console"))
    return problems


class RemotePackage:
    """Package bytes read over FTP, in the shape ps_pkg_info reads from."""

    def __init__(self, remote):
        self.remote = remote

    def read(self, offset, size):
        return self.remote.read(offset, size)

    def close(self):
        self.remote.close()


def fetch_whole(host, port, path):
    """The full contents of a small remote file, or None if it is not there."""
    remote = FtpFile(host, port, path)
    try:
        size = remote.size()
        return None if size is None else remote.read(0, size)
    finally:
        remote.close()


def install_state(host, port, title):
    """(InstallState, status, detail) for a title's package on the console.

    status is "ok" or "unavailable"; detail says why when it is not "ok".
    """
    try:
        from ps_pkg_info import Pkg, PkgError
        from ps_pkg_info.pkg import (
            ENTRY_PLAYGO_CHUNK_DAT, ENTRY_PLAYGO_FICM_DAT,
            ENTRY_PLAYGO_HASH_TABLE_DAT, ENTRY_PLAYGO_SCENARIO_JSON,
            parse_scenario_names)
    except ImportError:
        return None, "unavailable", "ps_pkg_info is not installed"
    try:
        for root in playgo_state.APP_ROOTS:
            base = f"{root}/{title}"
            bitmap_bytes = fetch_whole(host, port, f"{base}/app.pbm")
            if bitmap_bytes is not None:
                break
        else:
            return None, "unavailable", ""
        bitmap = playgo_state.Bitmap(bitmap_bytes)
        package = FtpFile(host, port, f"{base}/app.pkg")
        try:
            pkg = Pkg.from_source(RemotePackage(package))
            entries = [pkg.read_entry(entry) for entry in (
                ENTRY_PLAYGO_CHUNK_DAT, ENTRY_PLAYGO_HASH_TABLE_DAT,
                ENTRY_PLAYGO_FICM_DAT)]
            scenario_json = pkg.read_entry(ENTRY_PLAYGO_SCENARIO_JSON)
        finally:
            package.close()
        if entries[0] is None:
            return None, "unavailable", ""
        # PS4 packages have no file-to-chunk map, so only whole chunks are known.
        files = (playgo_state.FileChunks(entries[1], entries[2])
                 if entries[1] is not None and entries[2] is not None else None)
        state = playgo_state.InstallState(
            playgo_state.chunk_extents(entries[0]), bitmap, files)
        state.layout = playgo_state.read_layout(entries[0])
        if scenario_json:
            try:
                state.scenario_titles = {
                    index: info["title"] for index, info
                    in parse_scenario_names(scenario_json).items()
                    if info.get("title")}
            except ValueError:
                pass
        wanted = fetch_whole(host, port, f"{base}/app.xml")
        state.wanted = playgo_state.wanted_chunks(
            wanted.decode("utf-8", "replace")) if wanted else None
        return state, "ok", ""
    except (OSError, EOFError, ftplib.Error, ValueError, PkgError) as err:
        return None, "unavailable", f"could not read the install state: {err}"


def pfs_bitmap(host, port, title, layer="app"):
    """The PS4 title's image bitmap for a layer ("app" or "patch"), or None.

    pfs.pbm records the block count of the package each layer came from, and
    the bitmap is used only if that matches the package's own bitmap file.
    """
    roots, name = ((playgo_state.APP_ROOTS, "app.pbm") if layer == "app"
                   else (playgo_state.PATCH_ROOTS, "patch.pbm"))
    try:
        data = fetch_whole(host, port, f"/system_data/playgo/{title}/pfs.pbm")
        if data is None:
            return None
        bitmap = playgo_state.PfsBitmap(data, layer)
        for root in roots:
            record = fetch_whole(host, port, f"{root}/{title}/{name}")
            if record is not None:
                same = playgo_state.Bitmap(record).blocks == bitmap.pkg_blocks
                return bitmap if same else None
        return None
    except (OSError, EOFError, ftplib.Error, ValueError):
        return None


def ps4_missing(host, port, title, state, plan, patch_plan=None):
    """(unreadable paths, per-chunk counts, exact, patch checked) for PS4, or None.

    Uses the console's image bitmaps (pfs.pbm), so a file is unreadable exactly
    when one of its blocks is not set; nothing needs probing. The per-chunk
    counts, for the base package, are None when the holes cannot be matched to
    the missing chunks. patch_plan files are checked against the update's
    bitmap; patch checked says whether that was possible.
    """
    bitmap = pfs_bitmap(host, port, title, "app")
    if bitmap is None:
        return None
    gone = bitmap.unreadable(plan)
    split = playgo_state.attribute_files(state, bitmap, plan, gone)
    counts, exact = split if split else (None, True)
    patch_checked = True
    if patch_plan:
        patch_bitmap = pfs_bitmap(host, port, title, "patch")
        patch_checked = patch_bitmap is not None
        if patch_checked:
            gone = gone | patch_bitmap.unreadable(patch_plan)
    return gone, counts, exact, patch_checked


def install_report(host, port, title):
    """install_state as a JSON-ready dict: status, detail and, if ok, chunks."""
    state, status, detail = install_state(host, port, title)
    report = {"status": status, "detail": detail}
    if state is None:
        return report
    counts, exact = None, True
    if state.files is None and state.incomplete:
        # Counting files needs the image's manifest, which exists only while
        # the title is mounted.
        image = FtpFile(host, port, nest_path(title, "app0"), timeout=15)
        try:
            found = ps4_missing(host, port, title, state,
                                PfsImage(image).manifest())
            if found:
                counts, exact = found[1], found[2]
        except (OSError, EOFError, ftplib.Error, Unsupported):
            pass
        finally:
            image.close()
    report.update(playgo_state.describe(state, counts, exact))
    return report


def read_install_state(host, port, title):
    """The InstallState, or None (with a note) when it cannot be told."""
    state, _status, detail = install_state(host, port, title)
    if state is None and detail:
        print(f"  note: {detail}")
    return state


def describe_chunk(entry, approximate=False):
    """One line naming a missing chunk, its languages and why it is missing."""
    name = entry["label"] or f"chunk {entry['id']}"
    languages = ", ".join(entry["languages"][:6])
    if len(entry["languages"]) > 6:
        languages += f" and {len(entry['languages']) - 6} more"
    asked = {None: "", True: ", requested by the console",
             False: ", not requested by the console"}[entry["requested"]]
    files = ("" if entry["files"] is None
             else f"{'~' if approximate else ''}{entry['files']} file(s) ")
    return (f"chunk {entry['id']} {name}"
            + (f" [{languages}]" if languages else "")
            + f" ({entry['size'] / 2 ** 30:.2f} GiB): {files}"
              f"never downloaded{asked}")


def predict_missing(host, port, title, paths, plan=None, patch_plan=None):
    """Paths whose chunk never reached the console, from its own records.

    Without a file-to-chunk map (PS4), plan and patch_plan are checked against
    the console's image bitmaps instead.
    """
    state = read_install_state(host, port, title)
    if state is None:
        return set()
    found, counts, exact, unknown, patch_unknown = set(), None, True, False, False
    if state.files is not None:
        # Empty files hold no data, so they are never missing.
        if plan is not None:
            paths = [rel for rel, _offset, size in plan if size > 0]
        by_chunk = state.missing_files(paths)
        found = {path for paths_ in by_chunk.values() for path in paths_}
        counts = {chunk: len(files) for chunk, files in by_chunk.items()}
    elif state.incomplete and plan is not None:
        result = ps4_missing(host, port, title, state, plan, patch_plan)
        if result is None:
            unknown = True
        else:
            found, counts, exact, patch_checked = result
            patch_unknown = not patch_checked
    report = playgo_state.describe(state, counts, exact)
    for entry in report["chunks"]:
        print("  " + describe_chunk(entry, report["files_approximate"]))
    for scenario in report["scenarios"]:
        label = scenario["title"] or scenario["name"] or f"#{scenario['id']}"
        launch = " (needed to launch)" if scenario["needed_for_launch"] else ""
        print(f"  scenario {label} lacks chunk(s) "
              f"{', '.join(map(str, scenario['missing']))}{launch}")
    if report["partial"]:
        print(f"  chunk(s) {', '.join(map(str, report['partial']))} only partly "
              f"downloaded; their files are requested as usual")
    if unknown:
        print("  could not tell which files the missing chunks hold; "
              "each unreadable file will be retried")
    elif state.files is None and found:
        print(f"  {len(found)} file(s) have blocks missing from the image "
              f"and will be left out")
    if patch_unknown:
        print("  could not check the update's files against the console's "
              "bitmap; any unreadable ones will be retried")
    return found


def main():
    parser = argparse.ArgumentParser(
        description="Dump a PS4 or PS5 title's tree by streaming its PFS images.")
    parser.add_argument("host", help="console address, optionally HOST:PORT")
    parser.add_argument("title", nargs="?",
                        help="title ID; defaults to the running game, or no "
                             "filter with --dlc-entitlements")
    parser.add_argument("-o", "--output-dir", default=".",
                        help="root directory for dump output (default: .)")
    parser.add_argument("-p", "--port", type=int, default=2121)
    parser.add_argument("--no-game", action="store_true",
                        help="dump only the selected add-on content")
    parser.add_argument("--patch-mode",
                        choices=("combined", "separate", "skip"), default="combined",
                        help="combine the PS4 patch into the app, dump it separately, "
                             "or skip it (default: combined)")
    parser.add_argument("--no-patch", action="store_true",
                        help="alias for --patch-mode skip")
    parser.add_argument("--addon-mode", choices=("all", "ac", "al", "skip"),
                        default="all",
                        help="dump installed AC content, AL licenses, both, or neither "
                             "(default: all)")
    parser.add_argument("--no-decrypt", action="store_true",
                        help="leave the executables as the encrypted SELFs the "
                             "image stores")
    parser.add_argument("--no-install-check", action="store_true",
                        help="request every file instead of skipping those in "
                             "chunks the console never downloaded (PS5), and do "
                             "not report missing chunks")
    parser.add_argument("--dlc-entitlements", action="store_true",
                        help="build DLC unlocker templates from entitlement.db "
                             "and exit; TITLE restricts output to one game")
    parser.add_argument("--no-dlc", action="store_true",
                        help="alias for --addon-mode skip")
    parser.add_argument("--no-entitlements", action="store_true",
                        help="do not read add-on entitlement keys from "
                             "the running game")
    parser.add_argument("--injector", default=default_injector(),
                        help="ps5-entitlement-dumper's entitlements.elf "
                             "(default: $ENTITLEMENT_INJECTOR, else beside this "
                             "script)")
    parser.add_argument("--manifest", action="store_true",
                        help="print the game write plan and exit")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="name every file as it is written")
    args = parser.parse_args()

    host, port = args.host, args.port
    if ":" in host:
        host, _, spec = host.partition(":")
        port = int(spec)

    if args.dlc_entitlements:
        try:
            dump_dlc_entitlements(
                host, port, args.output_dir, filter_title=args.title,
                required=True, verbose=args.verbose)
        except RuntimeError as err:
            print(f"Could not dump DLC entitlements: {err}", file=sys.stderr)
            return 1
        return 0

    dump_game = not args.no_game
    patch_mode = "skip" if args.no_patch else args.patch_mode
    addon_mode = "skip" if args.no_dlc else args.addon_mode
    dump_ac = addon_mode in ("all", "ac")
    dump_al = addon_mode in ("all", "al")
    if not dump_game and addon_mode == "skip":
        parser.error("--no-game requires an add-on mode other than skip")
    if not dump_game and args.manifest:
        parser.error("--manifest requires game dumping")

    probe = FtpMount(host, port)
    try:
        title = args.title
        running_title, candidates = discover_title(probe)
        if not title:
            title = running_title
            if not title:
                print("Could not find a mounted app0; is the game running?",
                      file=sys.stderr)
                return 1
            if len(candidates) > 1:
                print(f"Several titles are mounted ({', '.join(candidates)}); "
                      f"using {title}.", file=sys.stderr)
            print(f"Running game: {title}")
        ac_mounts = find_dlc_mounts(probe, title) if dump_ac else []
    finally:
        probe.close()

    app = None
    patch = None
    try:
        app_manifest = []
        patch_manifest = []
        ps5 = False
        if dump_game:
            app = FtpFile(host, port, nest_path(title, "app0"))
            app_image = PfsImage(app)
            app_manifest = app_image.manifest()
            # A PS5 update replaces the whole image, so there is no patch layer.
            ps5 = app_image.version == 2
            if ps5:
                print(f"  PS5 image: superblock at {app_image.superblock_offset:,}")
        elif dump_ac:
            app = FtpFile(host, port, nest_path(title, "app0"))
            header = app.read(0, 16)
            version, magic = struct.unpack("<qq", header)
            ps5 = not (version == 1 and magic == PFS_MAGIC)
            app.close()
            app = None

        separate = dump_game and patch_mode == "separate" and not ps5
        if dump_game:
            if patch_mode != "skip" and not ps5:
                try:
                    patch = FtpFile(host, port, nest_path(title, "patch0"))
                    patch_manifest = PfsImage(patch).manifest()
                except ftplib.all_errors:
                    print(f"No patch image for {title}; dumping the base game only.")
                    if patch is not None:
                        patch.close()
                        patch = None

            if separate:
                patch_plan, app_plan = patch_manifest, app_manifest
                superseded = recased = 0
            else:
                patch_plan, app_plan, superseded, recased = build_plan(
                    app_manifest, patch_manifest)
            known_missing = set()
            if not args.no_install_check and not args.manifest:
                known_missing = predict_missing(
                    host, port, title, [rel for rel, _o, _s in app_plan],
                    plan=app_plan, patch_plan=patch_plan)
            metadata = app.metadata_bytes + (patch.metadata_bytes if patch else 0)
            total = sum(size for _d, _o, size in patch_plan + app_plan)

            print(f"Dumping {title} app data ({total // 1000000} MB):")
            print(f"  {len(app_manifest)} base file(s), "
                  f"{len(patch_manifest)} patch file(s), {superseded} superseded")
            layout = "separate layers" if separate else "merged tree"
            print(f"  {layout}: {len(patch_plan) + len(app_plan)} file(s), "
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
            patch_dest = (os.path.join(args.output_dir, f"{title}-patch")
                          if separate else dest)
            os.makedirs(dest, exist_ok=True)
            if separate and patch_manifest:
                os.makedirs(patch_dest, exist_ok=True)
        else:
            patch_plan = app_plan = []
            known_missing = set()
            dest = os.path.join(args.output_dir, f"{title}-dlc")
            patch_dest = dest

        entitlement_keys = None
        if not args.no_entitlements and (dump_game or dump_ac or dump_al):
            entitlement_keys = running_game_entitlements(
                host, title, candidates, args.injector)
            if entitlement_keys:
                os.makedirs(dest, exist_ok=True)
                write_entitlements(dest, entitlement_keys)
            if dump_ac:
                ac_mounts, added = relist_dlc_mounts(host, port, title, ac_mounts)
                if added:
                    print(f"  the injector mounted {len(added)} more add-on(s): "
                          f"{', '.join(added)}")

        rest_bug = None
        if dump_game:
            # Probe whichever image reaches furthest into its PFS. A small patch
            # is not evidence either way because the failing 2 GiB offset lies
            # outside it. One conclusive probe covers all layers.
            probes = [(nest_path(title, "app0"), app_manifest)]
            if patch_manifest:
                probes.append((nest_path(title, "patch0"), patch_manifest))
            probe_path, probe_manifest = max(
                probes, key=lambda item: max(
                    (offset + size for _rel, offset, size in item[1]), default=0))
            probe_extent = max(
                (offset + size for _rel, offset, size in probe_manifest), default=0)
            rest_bug = detect_rest_bug(host, port, probe_path, probe_extent)
            if rest_bug:
                print("  note: FTP server has the REST sign-bit bug; "
                      "applying workaround")

        problems = []
        stream_unresolved = []
        skip_summary = []
        skip_count = 0
        skipped_paths = set()
        layer_results = []
        layers = (
            ("patch", patch, patch_plan, patch_dest, f"{title}-patch0"),
            ("app", app, app_plan, dest, f"{title}-app0"),
        ) if dump_game else ()
        for label, remote, layer_plan, layer_dest, mount_name in layers:
            if not layer_plan:
                continue
            (runs, discarded, rewound, recovered, unresolved,
             skipped) = extract(
                remote, layer_dest, layer_plan, label, args.verbose,
                rest_workaround=rest_bug,
                loose_source=(host, port, f"{PFSMNT}/{mount_name}"),
                allow_decrypted_fallback=not args.no_decrypt,
                known_missing=known_missing)
            stream_unresolved.extend(unresolved)
            skipped_paths.update(skipped)
            skip_count += len(skipped)
            note = f", {rewound:,} rewound" if rewound else ""
            if recovered:
                note += f", {recovered} recovered from loose mount"
            if skipped:
                note += f", {len(skipped)} not installed"
            print(f"  {label}: {len(layer_plan)} file(s), {runs} run(s), "
                  f"{discarded:,} bytes discarded{note}")

            unresolved_paths = {rel for rel, _reason in unresolved} | set(skipped)
            bad = verify(layer_dest, layer_plan)
            unexpected = [item for item in bad if item[0] not in unresolved_paths]
            if unexpected:
                print(f"{len(unexpected)} {label} file(s) did not match the plan:",
                      file=sys.stderr)
                for rel, expected, actual in unexpected[:20]:
                    got = "missing" if actual is None else f"{actual} bytes"
                    print(f"  {rel}: expected {expected} bytes, got {got}",
                          file=sys.stderr)
                return 1
            planned = len(layer_plan)
            verified = planned - len(
                {rel for rel, _expected, _actual in bad} | unresolved_paths)
            print(f"  verified {verified} of {planned} {label} file(s) against the plan"
                  if verified != planned else
                  f"  verified {planned} {label} file(s) against the plan")
            available = [entry for entry in layer_plan
                         if entry[0] not in unresolved_paths]
            layer_results.append((layer_dest, mount_name, available))
            if separate:
                for line in summarize_skips(skipped, layer_plan):
                    skip_summary.append(f"{label}: {line}")

        if dump_game and not separate:
            skip_summary.extend(summarize_skips(
                skipped_paths, patch_plan + app_plan))
        if stream_unresolved:
            print(f"  warning: {len(stream_unresolved)} file(s) omitted after "
                  f"both image and loose extraction failed", file=sys.stderr)

        mount = FtpMount(host, port) if dump_game or dump_ac else None
        try:
            if mount is not None:
                if args.no_decrypt:
                    print("  executables left encrypted (--no-decrypt)")
                else:
                    if not mount.enable_decryption():
                        print("  warning: the server did not confirm SELF "
                              "decryption; check the executables before building",
                              file=sys.stderr)
                    replaced_total = 0
                    for layer_dest, mount_name, available in layer_results:
                        replaced, issues = replace_executables(
                            mount, layer_dest, {mount_name: available}, args.verbose)
                        replaced_total += replaced
                        problems += issues
                        if replaced:
                            damaged = [
                                rel for rel, _offset, size in available
                                if size > 0 and is_executable(rel)
                                and elf_truncated(os.path.join(layer_dest, rel))]
                            problems += [
                                (rel, "decrypted executable is truncated")
                                for rel in damaged]
                    if dump_game:
                        print(f"  decrypted {replaced_total} executable(s) via the PFS mounts")
                        if replaced_total:
                            keystone = os.path.join(dest, "sce_sys", "keystone")
                            if keystone_is_generated(keystone):
                                print("  warning: keystone is not the retail one",
                                      file=sys.stderr)

                if dump_game:
                    if ps5:
                        problems += dump_ps5_metadata(
                            host, port, mount, title, dest, args.verbose)
                    elif separate:
                        problems += dump_ps4_metadata(
                            host, port, mount, title, dest, False, args.verbose)
                        if patch_manifest:
                            problems += dump_ps4_metadata(
                                host, port, mount, title, patch_dest, True,
                                args.verbose, patch_only=True)
                    else:
                        problems += dump_ps4_metadata(
                            host, port, mount, title, dest, bool(patch_manifest),
                            args.verbose)

                if dump_ac:
                    if ac_mounts:
                        print(f"Dumping {title} DLC data ({len(ac_mounts)} add-on(s)):")
                        done, dlc_problems, dlc_skipped, dlc_skip_count = dump_dlc(
                            host, port, mount, title, args.output_dir, ac_mounts,
                            decrypt=not args.no_decrypt, verbose=args.verbose,
                            rest_workaround=rest_bug, sce_sys_from_pkg=not ps5,
                            keys=entitlement_keys)
                        print(f"  {done} of {len(ac_mounts)} add-on(s) dumped")
                        problems += dlc_problems
                        skip_summary.extend(dlc_skipped)
                        skip_count += dlc_skip_count
                    else:
                        print(f"No DLC data found for {title}.")
        finally:
            if mount is not None:
                mount.close()

        if dump_al:
            try:
                dump_dlc_entitlements(
                    host, port, args.output_dir, filter_title=title,
                    verbose=args.verbose, keys=entitlement_keys)
            except RuntimeError as err:
                problems.append(("DLC entitlement unlockers", str(err)))

        if skip_summary:
            print(f"\n{skip_count} uninstalled file(s) skipped "
                  f"(content not present on the console):")
            for line in skip_summary:
                print(f"  {line}")

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
        if app is not None:
            app.close()
        if patch is not None:
            patch.close()


if __name__ == "__main__":
    sys.exit(main())
