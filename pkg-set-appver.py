#!/usr/bin/env python3
"""Rewrite APP_VER in a built PS4 PKG's param.sfo and repair dependent digests.

APP_VER is a fixed-width sfo field, so the edit is length-preserving and no
offset moves. The digests covering it form a chain that must be rewritten in
order:

  param.sfo (entry 0x1000)
    -> general digests (0x0080) ParamDigest slot at +0xc0
    -> entry digest table (0x0001) slots for 0x1000 and 0x0080
      -> header 0x100  sc_entries1_hash  SHA256(keys|imgkey|gendigests|metas|digests)
      -> header 0x120  sc_entries2_hash  as above minus digests, metas truncated
      -> header 0x140  digest_table_hash SHA256(entry 0x0001)
      -> header 0x160  body_digest       SHA256(body_offset, body_size)
        -> header 0xfe0   SHA256(header[0:0xfe0])
          -> header 0x1000 signature over SHA256(header[0:0x1000])

SYSTEM_VER is an int field of the same fixed width, so it rides the same chain.
img_create derives it from the executables' version records rather than from the
param.sfo handed to it, so a package whose stamps were lowered still ships asking
for the firmware they were built against; setting it here is after the fact.

Usage: pkg-set-appver.py <pkg> <new_app_ver> [system_ver]   e.g. 01.23 0x08500000
"""
import hashlib
import mmap
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from pkgsig import sign  # noqa: E402

PKG_MAGIC = 0x7F434E54
SFO_MAGIC = 0x46535000

ENTRY_DIGESTS = 0x0001
ENTRY_KEYS = 0x0010
IMAGE_KEY = 0x0020
GENERAL_DIGESTS = 0x0080
METAS = 0x0100
PARAM_SFO = 0x1000

# 8-byte preamble, then fixed 32-byte slots; ParamDigest is the sixth.
GEN_SLOT_PARAM_DIGEST = 0xC0

HDR_SC_ENTRIES1 = 0x100
HDR_SC_ENTRIES2 = 0x120
HDR_DIGEST_TABLE = 0x140
HDR_BODY_DIGEST = 0x160
HDR_SELF_DIGEST = 0xFE0
HDR_SIGNATURE = 0x1000

SC_ENTRIES1 = (ENTRY_KEYS, IMAGE_KEY, GENERAL_DIGESTS, METAS, ENTRY_DIGESTS)
SC_ENTRIES2 = (ENTRY_KEYS, IMAGE_KEY, GENERAL_DIGESTS, METAS)

# Public modulus, LibOrbisPkg Keys.PkgPublicKeys[3].
PKG_SIGN_KEY = bytes.fromhex(
    "d212fc335f6ddb831609628b0356273782d477853529392d526b8c4c8cfb06c1"
    "845be7d4f7bcd24e6245cd2abbd77776453655273fb3f5f98eda4befaa59aeb3"
    "9bea5498d206326a58312ae0d44f90b50a7decf43a9c52672d99318e0c43e682"
    "fe0746e12e50d41f2d2f7ed908ba06b3bf2e203f4e3ffe44ffaa504357916994"
    "49158282e40f4c8d9d2cc95b1d64bf888bd4c594e76547841ee57910fb989347"
    "b97d8512a640982cf792bc951932ede890560d65c1aa78c62e54fd5f54a1f67e"
    "e5e05f61c120b4b9b4330870e4df8956ed012946775f8cb8a9f51e2eb3b9bfe0"
    "09b78d28d4a6c3b81e1f07ebb4120b95b88530fddc3913d07cdc8fedf9c9a3c1")


HASH_CHUNK = 1 << 24


class Pkg:
    """A package opened in place.

    Mapped rather than read: an app package runs to tens of gigabytes and the
    body digest covers all of it, so holding either the file or that slice in
    memory is not an option.
    """

    def __init__(self, path):
        self.path = path
        self.file = open(path, "r+b")
        self.blob = mmap.mmap(self.file.fileno(), 0)
        if struct.unpack_from(">I", self.blob, 0)[0] != PKG_MAGIC:
            raise SystemExit("not a PS4 pkg")
        self.entry_count, = struct.unpack_from(">I", self.blob, 0x10)
        self.sc_entry_count, = struct.unpack_from(">H", self.blob, 0x14)
        self.table_off, = struct.unpack_from(">I", self.blob, 0x18)
        self.main_ent_data_size, = struct.unpack_from(">I", self.blob, 0x1C)
        self.body_off, = struct.unpack_from(">Q", self.blob, 0x20)
        self.body_size, = struct.unpack_from(">Q", self.blob, 0x28)
        self.entries = {}
        for i in range(self.entry_count):
            eid, _, _, _, off, size = struct.unpack_from(
                ">IIIIII", self.blob, self.table_off + i * 32)
            self.entries[eid] = (i, off, size)

    def data(self, eid):
        _, off, size = self.entries[eid]
        return self.blob[off:off + size]

    def sha_entry(self, eid):
        return hashlib.sha256(self.data(eid)).digest()

    def put(self, at, value):
        self.blob[at:at + len(value)] = value

    def sha_range(self, off, size):
        """SHA256 over a span of the file, read in chunks so nothing is copied
        whole. The body digest covers the entire package."""
        digest = hashlib.sha256()
        view = memoryview(self.blob)
        end = off + size
        while off < end:
            step = min(HASH_CHUNK, end - off)
            digest.update(view[off:off + step])
            off += step
        view.release()
        return digest.digest()

    def save(self):
        self.blob.flush()
        self.blob.close()
        self.file.close()


def sfo_field(blob, key):
    if struct.unpack_from("<I", blob, 0)[0] != SFO_MAGIC:
        raise SystemExit("param.sfo magic mismatch")
    key_tab, data_tab, count = struct.unpack_from("<III", blob, 0x08)
    for i in range(count):
        e = 0x14 + i * 0x10
        key_off, _, length, max_len, data_off = struct.unpack_from("<HHIII", blob, e)
        start = key_tab + key_off
        if blob[start:blob.index(b"\0", start)].decode() == key:
            return data_tab + data_off, length, max_len
    raise SystemExit(f"{key} not present in param.sfo")


def main() -> int:
    path, new_ver = sys.argv[1], sys.argv[2]
    pkg = Pkg(path)

    sfo_idx, sfo_off, sfo_size = pkg.entries[PARAM_SFO]
    rel, length, max_len = sfo_field(pkg.data(PARAM_SFO), "APP_VER")
    old = bytes(pkg.blob[sfo_off + rel:sfo_off + rel + length - 1]).decode()
    encoded = new_ver.encode() + b"\0"
    if len(encoded) > max_len:
        raise SystemExit(f"{new_ver!r} exceeds field width {max_len}")
    pkg.put(sfo_off + rel, encoded.ljust(length, b"\0"))
    print(f"param.sfo APP_VER {old} -> {new_ver}")

    if len(sys.argv) > 3:
        want = int(sys.argv[3], 0)
        rel, length, _ = sfo_field(pkg.data(PARAM_SFO), "SYSTEM_VER")
        if length != 4:
            raise SystemExit(f"SYSTEM_VER is {length} bytes, expected 4")
        was, = struct.unpack_from("<I", pkg.blob, sfo_off + rel)
        pkg.put(sfo_off + rel, struct.pack("<I", want))
        print(f"param.sfo SYSTEM_VER {was:#010x} -> {want:#010x}")

    gen_idx, gen_off, _ = pkg.entries[GENERAL_DIGESTS]
    pkg.put(gen_off + GEN_SLOT_PARAM_DIGEST, pkg.sha_entry(PARAM_SFO))

    _, dig_off, dig_size = pkg.entries[ENTRY_DIGESTS]
    for eid in (PARAM_SFO, GENERAL_DIGESTS):
        idx = pkg.entries[eid][0]
        pkg.put(dig_off + idx * 32, pkg.sha_entry(eid))

    concat1 = b"".join(bytes(pkg.data(e)) for e in SC_ENTRIES1)
    if len(concat1) != pkg.main_ent_data_size:
        raise SystemExit(f"sc entries 1 size {len(concat1):#x} != "
                         f"main_ent_data_size {pkg.main_ent_data_size:#x}")
    pkg.put(HDR_SC_ENTRIES1, hashlib.sha256(concat1).digest())

    parts = []
    for eid in SC_ENTRIES2:
        _, off, size = pkg.entries[eid]
        if eid == METAS:
            size = pkg.sc_entry_count * 0x20
        parts.append(bytes(pkg.blob[off:off + size]))
    pkg.put(HDR_SC_ENTRIES2, hashlib.sha256(b"".join(parts)).digest())

    pkg.put(HDR_DIGEST_TABLE, pkg.sha_range(dig_off, dig_size))
    pkg.put(HDR_BODY_DIGEST, pkg.sha_range(pkg.body_off, pkg.body_size))
    pkg.put(HDR_SELF_DIGEST, pkg.sha_range(0, HDR_SELF_DIGEST))
    pkg.put(HDR_SIGNATURE, sign(PKG_SIGN_KEY, pkg.sha_range(0, HDR_SIGNATURE)))
    print("repaired: gen +0xc0, digest slots, header 0x100/0x120/0x140/0x160/"
          "0xfe0, signature 0x1000")

    pkg.save()
    return 0


if __name__ == "__main__":
    sys.exit(main())
