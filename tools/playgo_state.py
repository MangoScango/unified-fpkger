"""Which PlayGo chunks of an installed title are on the console.

The console tracks app.pkg in 64 KiB blocks (app.pbm). playgo-chunk.dat gives
each chunk's byte range in the package, and playgo-hash-table.dat with
playgo-ficm.dat give the chunk of every file path.
"""

import re
import struct

BLOCK = 1 << 16
PBM_HEADER = 256
PFS_PBM_HEADER = 0x100
APP_ROOTS = ("/user/app", "/mnt/ext0/user/app", "/mnt/ext1/user/app")
PATCH_ROOTS = ("/user/patch", "/mnt/ext0/user/patch", "/mnt/ext1/user/patch")

# Bit 63 of a chunk's language mask is the first of these, then downward.
PLAYGO_LANGUAGES = (
    "ja-JP", "en-US", "fr-FR", "es-ES", "de-DE", "it-IT", "nl-NL", "pt-PT",
    "ru-RU", "ko-KR", "zh-Hant", "zh-Hans", "fi-FI", "sv-SE", "da-DK", "no-NO",
    "pl-PL", "pt-BR", "en-GB", "tr-TR", "es-419", "ar-AE", "fr-CA", "cs-CZ",
    "hu-HU", "el-GR", "ro-RO", "th-TH", "vi-VN", "id-ID", "uk-UA",
)

_PLGX_SECTION_TABLE = 0xC0
_PLGX_ATTRIBUTES, _PLGX_EXTENT_ORDER, _PLGX_LABELS, _PLGX_EXTENTS = 0, 1, 2, 3
_PLGX_SCENARIOS, _PLGX_SCENARIO_LISTS, _PLGX_SCENARIO_NAMES = 4, 5, 6
_PLGX_ATTRIBUTE_SIZE = 0x20
# PS4 packages use the same tables under the magic "plgo", but keep each
# chunk's range count in a u16 at +0x0E where PS5 keeps a u32 at +4.
_PLAYGO_MAGICS = (b"plgx", b"plgo")
_PLGX_SCENARIO_SIZE = 0x20
_MASK64 = (1 << 64) - 1
_HASH_MIX = 0x8000000080008081
_FLT_MAGIC = b"\x7fFLT"
_POPCOUNT = bytes(bin(value).count("1") for value in range(256))


def _rol64(value, count):
    return ((value << count) | (value >> (64 - count))) & _MASK64


def _mix(a, b, c):
    x = _rol64(_rol64(c ^ b, 5) ^ a, 53)
    y = _rol64(_rol64(c ^ a, 17) ^ b, 11)
    z = _rol64(_rol64(b ^ a, 1) ^ c, 59)
    return (((~y & z) ^ x ^ _HASH_MIX) & _MASK64,
            ((~z & x) ^ y) & _MASK64, ((~x & y) ^ z) & _MASK64)


def path_hash(path, seed, key):
    """Hash of an image-relative path, without a leading slash."""
    data = path.encode("utf-8").upper()
    a, b, c = seed, _rol64(seed, 11), _rol64(seed, 23)
    tail = 0
    if data:
        blocks, rest = divmod(len(data) - 1, 8)
        for index in range(blocks):
            a ^= struct.unpack_from("<Q", data, index * 8)[0]
            a, b, c = _mix(a, b, c)
        tail = int.from_bytes(data[blocks * 8:blocks * 8 + rest + 1], "little")
    return _mix(tail ^ a ^ key, b, c)[0]


class _Blocks:
    """Bits over 64 KiB blocks; the first block is the top bit of byte 0."""

    def _set(self, block):
        return self.bits[block >> 3] & (0x80 >> (block & 7))

    def count(self, first, last):
        """Blocks set in first..last, inclusive."""
        first, last = max(first, 0), min(last, self.blocks - 1)
        if last < first:
            return 0
        total = 0
        block = first
        while block <= last and block & 7:
            total += 1 if self._set(block) else 0
            block += 1
        whole = (last + 1 - block) >> 3
        total += sum(_POPCOUNT[value] for value in
                     self.bits[block >> 3:(block >> 3) + whole])
        block += whole << 3
        while block <= last:
            total += 1 if self._set(block) else 0
            block += 1
        return total


class Bitmap(_Blocks):
    """The package block bitmap from app.pbm."""

    def __init__(self, data):
        if len(data) < PBM_HEADER or data[:4] != b"pdbm":
            raise ValueError("not an app.pbm")
        self.blocks = struct.unpack_from("<I", data, 0x22)[0]
        end = PBM_HEADER + (self.blocks + 7) // 8
        if not self.blocks or len(data) < end:
            raise ValueError("app.pbm is shorter than its block count")
        self.bits = data[PBM_HEADER:end]


class PfsBitmap(_Blocks):
    """The block bitmap of a PFS image, from a PS4 title's pfs.pbm.

    app.pbm and patch.pbm track the compressed packages; this tracks the
    decompressed images the console serves, so a file's blocks can be checked
    directly. The header holds block counts for the base package then the
    update, and a table at 0xC0 lists a package bitmap and an image bitmap for
    each. pkg_blocks is the package's block count, to compare with its own
    app.pbm or patch.pbm.
    """

    # (offset of pkg_blocks, offset of image blocks, table slot of image bitmap)
    _LAYERS = {"app": (0x22, 0x3A, 1), "patch": (0x42, 0x5A, 3)}

    def __init__(self, data, layer="app"):
        if len(data) < PFS_PBM_HEADER or data[:4] != b"ppbm":
            raise ValueError("not a pfs.pbm")
        pkg_at, image_at, slot = self._LAYERS[layer]
        self.pkg_blocks = struct.unpack_from("<Q", data, pkg_at)[0]
        # The update's image count is followed directly by a timestamp, so it
        # is a u32 rather than the u64 the earlier fields use.
        self.blocks = struct.unpack_from("<I", data, image_at)[0]
        _kind, _pad, at, size = struct.unpack_from(
            "<IIII", data, 0xC0 + slot * 16)
        if (not self.blocks or size != (self.blocks + 7) // 8
                or at + size > len(data)):
            raise ValueError(f"pfs.pbm has no {layer} image bitmap")
        self.bits = data[at:at + size]

    def unset_runs(self):
        """The unset stretches of the image as [(first block, last block)]."""
        runs, start = [], None
        for index, value in enumerate(self.bits):
            if value == 0xFF:
                if start is not None:
                    runs.append((start, index * 8 - 1))
                    start = None
                continue
            for bit in range(8):
                block = index * 8 + bit
                if block >= self.blocks:
                    break
                if value & (0x80 >> bit):
                    if start is not None:
                        runs.append((start, block - 1))
                        start = None
                elif start is None:
                    start = block
        if start is not None:
            runs.append((start, self.blocks - 1))
        return runs

    def unreadable(self, plan):
        """Paths in plan, as (path, offset, size), with a block not on the console."""
        gone = set()
        for path, offset, size in plan:
            if size <= 0:
                continue
            first, last = offset // BLOCK, (offset + size - 1) // BLOCK
            if self.count(first, last) < last - first + 1:
                gone.add(path)
        return gone


def _section(data, index):
    at, size = struct.unpack_from("<II", data, _PLGX_SECTION_TABLE + index * 8)
    if at + size > len(data):
        raise ValueError("playgo-chunk.dat section runs past the end")
    return at, size


def _range_count(playgo_chunk, entry):
    if playgo_chunk[:4] == b"plgo":
        return struct.unpack_from("<H", playgo_chunk, entry + 0x0E)[0]
    return struct.unpack_from("<I", playgo_chunk, entry + 4)[0]


def chunk_extents(playgo_chunk):
    """Per chunk, its [(offset, size)] byte ranges in app.pkg.

    A chunk can hold several ranges, or none. Each chunk's attributes give how
    many, and the order table lists their indexes chunk by chunk.
    """
    if playgo_chunk[:4] not in _PLAYGO_MAGICS or len(playgo_chunk) < 0x100:
        raise ValueError("not a playgo-chunk.dat")
    count = struct.unpack_from("<H", playgo_chunk, 0x0A)[0]
    attrs_at, attrs_size = _section(playgo_chunk, _PLGX_ATTRIBUTES)
    order_at, order_size = _section(playgo_chunk, _PLGX_EXTENT_ORDER)
    extents_at, extents_size = _section(playgo_chunk, _PLGX_EXTENTS)
    if attrs_size != count * _PLGX_ATTRIBUTE_SIZE:
        raise ValueError("chunk attributes do not match the chunk count")
    ranges = [struct.unpack_from("<QQ", playgo_chunk, extents_at + i * 16)
              for i in range(extents_size // 16)]
    width, code = (2, "H") if playgo_chunk[:4] == b"plgo" else (4, "I")
    order = struct.unpack_from(f"<{order_size // width}{code}", playgo_chunk, order_at)
    lengths = [_range_count(playgo_chunk, attrs_at + chunk * _PLGX_ATTRIBUTE_SIZE)
               for chunk in range(count)]
    if sum(lengths) != len(order) or any(i >= len(ranges) for i in order):
        raise ValueError("chunk extents do not match the chunk attributes")
    chunks, cursor = [], 0
    for length in lengths:
        chunks.append([ranges[i] for i in order[cursor:cursor + length]])
        cursor += length
    return chunks


class Layout:
    """Chunk labels and languages, and the scenarios that group chunks."""

    def __init__(self, chunks, scenarios):
        self.chunks = chunks        # [(label, [language])]
        self.scenarios = scenarios  # [(name, initial count, [chunk id])]


def read_layout(playgo_chunk):
    """Labels, languages and scenarios from a playgo-chunk.dat."""
    if playgo_chunk[:4] not in _PLAYGO_MAGICS or len(playgo_chunk) < 0x100:
        raise ValueError("not a playgo-chunk.dat")
    count = struct.unpack_from("<H", playgo_chunk, 0x0A)[0]
    attrs_at, attrs_size = _section(playgo_chunk, _PLGX_ATTRIBUTES)
    labels_at, labels_size = _section(playgo_chunk, _PLGX_LABELS)
    if attrs_size != count * _PLGX_ATTRIBUTE_SIZE:
        raise ValueError("chunk attributes do not match the chunk count")
    labels = playgo_chunk[labels_at:labels_at + labels_size]
    chunks = []
    for chunk in range(count):
        entry = attrs_at + chunk * _PLGX_ATTRIBUTE_SIZE
        mask = struct.unpack_from("<Q", playgo_chunk, entry + 0x10)[0]
        label_at = struct.unpack_from("<I", playgo_chunk, entry + 0x1C)[0]
        end = labels.find(b"\0", label_at)
        label = labels[label_at:end].decode("utf-8", "replace") if end >= 0 else ""
        languages = [language for bit, language in enumerate(PLAYGO_LANGUAGES)
                     if mask >> (63 - bit) & 1]
        chunks.append((label, languages))
    return Layout(chunks, _read_scenarios(playgo_chunk, count))


def _read_scenarios(data, chunk_count):
    """[(name, initial, [chunk id])], or [] if the scenario tables look wrong."""
    try:
        scenario_count = struct.unpack_from("<H", data, 0x0E)[0]
        table_at, table_size = _section(data, _PLGX_SCENARIOS)
        lists_at, lists_size = _section(data, _PLGX_SCENARIO_LISTS)
        names_at, names_size = _section(data, _PLGX_SCENARIO_NAMES)
        if table_size != scenario_count * _PLGX_SCENARIO_SIZE:
            return []
        names = data[names_at:names_at + names_size]
        scenarios = []
        for index in range(scenario_count):
            entry = table_at + index * _PLGX_SCENARIO_SIZE
            initial, total = struct.unpack_from("<HH", data, entry + 0x14)
            list_at, name_at = struct.unpack_from("<II", data, entry + 0x18)
            if list_at + total * 2 > lists_size or initial > total:
                return []
            ids = list(struct.unpack_from(
                f"<{total}H", data, lists_at + list_at))
            end = names.find(b"\0", name_at)
            if end < 0 or any(chunk >= chunk_count for chunk in ids):
                return []
            scenarios.append(
                (names[name_at:end].decode("utf-8", "replace"), initial, ids))
        return scenarios
    except (struct.error, ValueError):
        return []


class FileChunks:
    """Chunk of each file, looked up by path."""

    def __init__(self, hash_table, ficm):
        if (len(hash_table) < 0x38 or hash_table[0x18:0x1C] != _FLT_MAGIC or
                struct.unpack_from("<I", hash_table, 0x08)[0] != 0x38):
            raise ValueError("unrecognized playgo-hash-table.dat")
        count = struct.unpack_from("<I", hash_table, 0x24)[0]
        self.seed, self.key = struct.unpack_from("<QQ", hash_table, 0x28)
        if (len(hash_table) != 0x38 + count * 8 or len(ficm) != 0x10 + count * 2):
            raise ValueError("playgo-ficm.dat does not match the hash table")
        hashes = struct.unpack_from(f"<{count}Q", hash_table, 0x38)
        chunks = struct.unpack_from(f"<{count}H", ficm, 0x10)
        self._chunks = dict(zip(hashes, chunks))

    def chunk_of(self, path):
        return self._chunks.get(path_hash(path, self.seed, self.key))

    def counts(self):
        """{chunk index: number of files in it}."""
        found = {}
        for chunk in self._chunks.values():
            found[chunk] = found.get(chunk, 0) + 1
        return found


class ChunkState:
    def __init__(self, index, ranges, present, total):
        self.index, self.ranges = index, ranges
        self.size = sum(size for _offset, size in ranges)
        self.present, self.total = present, total

    @property
    def absent(self):
        """True when the chunk has data and no block of it is on the console."""
        return self.total > 0 and self.present == 0

    @property
    def complete(self):
        return self.present == self.total


class InstallState:
    def __init__(self, extents, bitmap, files):
        self.files = files
        self.wanted = None  # chunk ids the console asked for, if it says
        self.layout = None  # Layout, for labels, languages and scenarios
        self.scenario_titles = {}  # {scenario id: display title}
        self.chunks = []
        for index, ranges in enumerate(extents):
            present = total = 0
            for offset, size in ranges:
                first = offset // BLOCK
                last = (offset + size - 1) // BLOCK
                # Neighbouring ranges can share an edge block, so only the
                # interior says whether this range's own data arrived.
                if last - first >= 2:
                    first, last = first + 1, last - 1
                present += bitmap.count(first, last)
                total += last - first + 1
            self.chunks.append(ChunkState(index, ranges, present, total))

    @property
    def absent_chunks(self):
        return [chunk for chunk in self.chunks if chunk.absent]

    def absent_runs(self):
        """Absent ranges of the package in order, as [[(offset, size, chunk)]].

        Ranges that touch are grouped, since they form one hole.
        """
        segments = sorted((offset, size, chunk.index)
                          for chunk in self.absent_chunks
                          for offset, size in chunk.ranges)
        runs = []
        for segment in segments:
            last = runs[-1][-1] if runs else None
            if last and segment[0] <= last[0] + last[1] + BLOCK:
                runs[-1].append(segment)
            else:
                runs.append([segment])
        return runs

    @property
    def incomplete(self):
        return [chunk for chunk in self.chunks if not chunk.complete]

    def missing_files(self, paths):
        """{chunk index: [path]} for files in chunks that never arrived.

        Empty when the package carries no file-to-chunk map, as on PS4.
        """
        absent = {chunk.index for chunk in self.absent_chunks}
        found = {}
        if not absent or self.files is None:
            return found
        for path in paths:
            chunk = self.files.chunk_of(path)
            if chunk in absent:
                found.setdefault(chunk, []).append(path)
        return found


def wanted_chunks(app_xml):
    """Chunk ids the console asked for in app.xml, or None without a status."""
    if "playgo-status" not in app_xml:
        return None
    return {int(m.group(1)) for m in
            re.finditer(r'<chunk id="(\d+)"[^>]*req_locus="3"', app_xml)}


def attribute_files(state, pfs_bitmap, plan, unreadable):
    """Splits the unreadable files over the absent chunks.

    Returns ({chunk: file count}, exact), or None when the package's absent
    runs and the image's holes do not pair up. Each hole belongs to one absent
    run, in order. Where a run holds several chunks, the hole's files are
    divided in proportion to the chunks' sizes in the package, which is exact
    only if all of them compress alike.
    """
    runs, holes = state.absent_runs(), pfs_bitmap.unset_runs()
    if len(runs) != len(holes):
        return None
    files = sorted((offset, size) for path, offset, size in plan
                   if path in unreadable)
    counts = {segment[2]: 0 for run in runs for segment in run}
    exact = True
    for run, (first, last) in zip(runs, holes):
        inside = [(offset, size) for offset, size in files
                  if first <= offset // BLOCK <= last]
        if len({segment[2] for segment in run}) == 1:
            counts[run[0][2]] += len(inside)
            continue
        exact = False
        weight = sum(segment[1] for segment in run)
        total = sum(size for _offset, size in inside) or 1
        edges, taken = [], 0
        for _offset, size, _chunk in run:
            taken += size
            edges.append(taken / weight)
        done = 0
        for _offset, size in inside:
            middle = (done + size / 2) / total
            done += size
            index = next((i for i, edge in enumerate(edges) if middle <= edge),
                         len(run) - 1)
            counts[run[index][2]] += 1
    return counts, exact


def describe(state, counts=None, exact=True):
    """The missing chunks of an InstallState, with languages and scenarios.

    counts overrides the per-chunk file counts; exact says whether they are.
    """
    if counts is None and state.files:
        counts = state.files.counts()
    labels = state.layout.chunks if state.layout else []
    absent = {chunk.index for chunk in state.absent_chunks}
    chunks = []
    for chunk in state.absent_chunks:
        label, languages = labels[chunk.index] if chunk.index < len(labels) else ("", [])
        chunks.append({
            "id": chunk.index, "label": label, "languages": languages,
            "size": chunk.size,
            "files": None if counts is None else counts.get(chunk.index, 0),
            "requested": None if state.wanted is None else chunk.index in state.wanted,
        })
    scenarios = []
    for index, (name, initial, ids) in enumerate(
            state.layout.scenarios if state.layout else []):
        missing = [chunk for chunk in ids if chunk in absent]
        if missing:
            scenarios.append({
                "id": index, "name": name,
                "title": state.scenario_titles.get(index, ""),
                "initial": initial, "total": len(ids), "missing": missing,
                # Language chunks the console never asked for are in the
                # scenario's list but do not hold up a launch.
                "needed_for_launch": any(
                    chunk in absent and (state.wanted is None or chunk in state.wanted)
                    for chunk in ids[:initial]),
            })
    return {
        "chunk_count": len(state.chunks), "chunks": chunks,
        "partial": [chunk.index for chunk in state.incomplete if not chunk.absent],
        "scenarios": scenarios,
        "files_approximate": not exact,
        "bytes": sum(entry["size"] for entry in chunks),
        "files": None if counts is None else sum(entry["files"] for entry in chunks),
    }
