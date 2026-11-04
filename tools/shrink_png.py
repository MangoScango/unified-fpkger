#!/usr/bin/env python3
"""Shrink oversized sce_sys icon PNGs in place without changing their pixels.

usage: shrink_png.py SCE_SYS_DIR [--limit BYTES]

Publishing Tools rejects icon0*.png larger than 1 MiB. Dumps sometimes carry
icons padded with editor metadata (multi-MB iTXt/XMP chunks), so this drops
ancillary chunks and, if that is not enough, recompresses the image data.
Files at or under the limit are left untouched. Files are replaced rather
than rewritten, so a hardlinked copy of a dump is never written through.
"""
import argparse
import os
import re
import struct
import sys
import tempfile
import zlib
from pathlib import Path

SIGNATURE = b"\x89PNG\r\n\x1a\n"
DEFAULT_LIMIT = 1024 * 1024
# Chunks that affect how pixels decode; everything else is metadata.
KEEP = {b"IHDR", b"PLTE", b"tRNS", b"IDAT", b"IEND", b"gAMA", b"sRGB", b"cHRM", b"sBIT"}
ICON = re.compile(r"icon0(_\d\d)?\.png", re.IGNORECASE)


def chunks(data):
    if data[:8] != SIGNATURE:
        raise ValueError("not a PNG")
    at = 8
    while at < len(data):
        length, kind = struct.unpack_from(">I4s", data, at)
        yield kind, data[at + 8:at + 8 + length]
        at += 12 + length


def chunk(kind, body):
    return struct.pack(">I", len(body)) + kind + body + struct.pack(">I", zlib.crc32(kind + body))


def build(parts, recompress):
    image = b"".join(body for kind, body in parts if kind == b"IDAT")
    if recompress:
        image = zlib.compress(zlib.decompress(image), 9)
    out = [SIGNATURE]
    wrote_idat = False
    for kind, body in parts:
        if kind == b"IDAT":
            if not wrote_idat:
                out.append(chunk(b"IDAT", image))
                wrote_idat = True
        else:
            out.append(chunk(kind, body))
    return b"".join(out)


def shrink(path, limit):
    data = path.read_bytes()
    if len(data) <= limit:
        return None
    parts = [(kind, body) for kind, body in chunks(data) if kind in KEEP]
    result = build(parts, recompress=False)
    if len(result) > limit:
        result = build(parts, recompress=True)
    if len(result) > limit:
        raise ValueError(f"{path.name}: still {len(result)} bytes after stripping metadata "
                         f"and recompressing (limit {limit}); replace the image by hand")
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=path.name, suffix=".tmp")
    with os.fdopen(fd, "wb") as fh:
        fh.write(result)
    os.chmod(tmp, path.stat().st_mode & 0o7777)
    os.replace(tmp, path)
    return len(data), len(result)


def shrink_icons(sce_sys, limit=DEFAULT_LIMIT, log=None):
    """Shrink every eligible icon, reporting all failures after processing them."""
    failures = []
    for path in sorted(Path(sce_sys).iterdir()):
        if not path.is_file() or not ICON.fullmatch(path.name):
            continue
        try:
            done = shrink(path, limit)
        except ValueError as error:
            failures.append(str(error))
            continue
        if done and log:
            log(f"{path.name}: {done[0]} -> {done[1]} bytes "
                "(metadata stripped, pixels unchanged)")
    if failures:
        raise ValueError("; ".join(failures))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("sce_sys", type=Path)
    ap.add_argument("--limit", type=int, default=DEFAULT_LIMIT)
    args = ap.parse_args()
    try:
        shrink_icons(
            args.sce_sys, args.limit,
            log=lambda message: print(f">> {message}", file=sys.stderr),
        )
    except (OSError, ValueError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
