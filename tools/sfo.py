#!/usr/bin/env python3
"""Read, print, and modify PlayStation 4 param.sfo files.

Supports regular PS4 param.sfo files, disc param.sfo files, and PS4 PKG files.
Only regular param.sfo files can be modified. No third-party packages are needed.

Drop in replacement for hippie68's tool
"""

import argparse
import struct
import sys
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import BinaryIO, Dict, Iterator, List, Optional, Union


PROGRAM_VERSION = "1.02 (January 4, 2022)"
PROGRAM_URL = "https://github.com/hippie68/sfo"

SFO_MAGIC = 0x46535000
DISC_SFO_MAGIC = 0x43454353
PKG_MAGIC = 0x544E437F
PKG_SFO_ENTRY_ID = 0x1000

HEADER = struct.Struct("<5I")
ENTRY = struct.Struct("<2H3I")
PKG_ENTRY = struct.Struct(">6IQ")
UINT32 = struct.Struct("<I")
BIG_ENDIAN_UINT32 = struct.Struct(">I")

UTF8_STRING = 516
UTF8_SPECIAL_STRING = 1024
UTF8_FORMATS = {UTF8_STRING, UTF8_SPECIAL_STRING}
UNSIGNED_INTEGER = 1028

RESERVED_STRING_SIZES = {
    "CATEGORY": 4,
    "FORMAT": 4,
    "APP_VER": 8,
    "CONTENT_VER": 8,
    "VERSION": 8,
    "INSTALL_DIR_SAVEDATA": 12,
    "TITLE_ID": 12,
    "CONTENT_ID": 48,
    "PUBTOOLINFO": 512,
    "PS3_TITLE_ID_LIST_FOR_BOOT": 512,
    "PROVIDER": 128,
    "TITLE": 128,
}
for _number in range(1, 8):
    RESERVED_STRING_SIZES[f"SERVICE_ID_ADDCONT_ADD_{_number}"] = 20
    RESERVED_STRING_SIZES[f"SAVE_DATA_TRANSFER_TITLE_ID_LIST_{_number}"] = 512
for _number in range(21):
    RESERVED_STRING_SIZES[f"PROVIDER_{_number:02d}"] = 128
    RESERVED_STRING_SIZES[f"TITLE_{_number:02d}"] = 128
for _number in range(21, 30):
    RESERVED_STRING_SIZES[f"TITLE_{_number:02d}"] = 128


class SFOError(Exception):
    """An invalid or unsupported SFO operation."""


@dataclass
class Header:
    magic: int = SFO_MAGIC
    version: int = 0x101
    key_table_offset: int = HEADER.size
    data_table_offset: int = HEADER.size
    entries_count: int = 0

    @classmethod
    def unpack(cls, data: bytes) -> "Header":
        return cls(*HEADER.unpack(data))

    def pack(self) -> bytes:
        return HEADER.pack(
            self.magic,
            self.version,
            self.key_table_offset,
            self.data_table_offset,
            self.entries_count,
        )


@dataclass
class Entry:
    key_offset: int = 0
    param_fmt: int = 0
    param_len: int = 0
    param_max_len: int = 0
    data_offset: int = 0

    @classmethod
    def unpack(cls, data: bytes) -> "Entry":
        return cls(*ENTRY.unpack(data))

    def pack(self) -> bytes:
        return ENTRY.pack(
            self.key_offset,
            self.param_fmt,
            self.param_len,
            self.param_max_len,
            self.data_offset,
        )


@dataclass(frozen=True)
class Command:
    operation: str
    key: str
    value: Optional[str] = None
    param_type: Optional[str] = None


class CommandAction(argparse.Action):
    """Collect different modification options in their command-line order."""

    def __init__(self, *args, operation: str = "", **kwargs) -> None:
        self.operation = operation
        super().__init__(*args, **kwargs)

    def __call__(self, parser, namespace, values, option_string=None) -> None:
        commands = getattr(namespace, self.dest, None) or []

        if self.operation in {"add", "set"}:
            param_type, key, value = values
            if param_type not in {"int", "str"}:
                parser.error(f'{option_string}: TYPE must be "int" or "str"')
            command = Command(self.operation, key.upper(), value, param_type)
        elif self.operation == "edit":
            key, value = values
            command = Command(self.operation, key.upper(), value)
        else:
            command = Command(self.operation, values.upper())

        commands.append(command)
        setattr(namespace, self.dest, commands)


def read_exact(file: BinaryIO, size: int, section: str) -> bytes:
    data = file.read(size)
    if len(data) != size:
        raise SFOError(f"could not read {section}")
    return data


def c_string(table: bytearray, offset: int) -> bytes:
    end = table.find(b"\0", offset)
    if end == -1:
        end = len(table)
    return bytes(table[offset:end])


def align4(value: int) -> int:
    return (value + 3) & ~3


def hexdump(data: bytearray) -> Iterator[str]:
    heading = "      0  1  2  3  4  5  6  7  8  9  a  b  c  d  e  f"
    yield heading
    for offset in range(0, len(data), 16):
        row = data[offset:offset + 16]
        hexadecimal = " ".join(f"{byte:02x}" for byte in row)
        characters = "".join(
            chr(byte) if 32 <= byte <= 126 else "." for byte in row
        )
        yield f"{offset:04x} {hexadecimal:<47}  {characters}"
    if len(data) > 64:
        yield heading


@dataclass
class SFO:
    header: Header = field(default_factory=Header)
    entries: List[Entry] = field(default_factory=list)
    key_table: bytearray = field(default_factory=bytearray)
    data_table: bytearray = field(default_factory=bytearray)

    @classmethod
    def read(cls, file: BinaryIO) -> "SFO":
        header = Header.unpack(read_exact(file, HEADER.size, "header"))
        entry_data = read_exact(
            file, ENTRY.size * header.entries_count, "index table"
        )
        entries = [
            Entry.unpack(entry_data[offset:offset + ENTRY.size])
            for offset in range(0, len(entry_data), ENTRY.size)
        ]

        key_size = header.data_table_offset - header.key_table_offset
        if key_size < 0:
            raise SFOError("invalid key table offsets")
        key_table = bytearray(read_exact(file, key_size, "key table"))

        data_size = (
            entries[-1].data_offset + entries[-1].param_max_len if entries else 0
        )
        data_table = bytearray(read_exact(file, data_size, "data table"))
        return cls(header, entries, key_table, data_table)

    def __bytes__(self) -> bytes:
        key_offset = HEADER.size + ENTRY.size * len(self.entries)
        header = replace(
            self.header,
            key_table_offset=key_offset,
            data_table_offset=key_offset + len(self.key_table),
            entries_count=len(self.entries),
        )
        return b"".join([
            header.pack(),
            *(entry.pack() for entry in self.entries),
            bytes(self.key_table),
            bytes(self.data_table),
        ])

    def write(self, path: Union[str, Path]) -> None:
        Path(path).write_bytes(bytes(self))

    def key(self, entry: Entry) -> str:
        return c_string(self.key_table, entry.key_offset).decode("utf-8")

    def string_value(self, entry: Entry) -> str:
        return c_string(self.data_table, entry.data_offset).decode("utf-8")

    def integer_value(self, entry: Entry) -> int:
        return UINT32.unpack_from(self.data_table, entry.data_offset)[0]

    def value(self, entry: Entry, decimal: bool = False) -> str:
        if entry.param_fmt in UTF8_FORMATS:
            return self.string_value(entry)
        if entry.param_fmt == UNSIGNED_INTEGER:
            value = self.integer_value(entry)
            return str(value) if decimal else f"0x{value:08x}"
        raise SFOError(f"unsupported parameter format {entry.param_fmt}")

    def as_dict(self) -> Dict[str, object]:
        """Return parameter values with unsigned integers kept as integers."""
        values: Dict[str, object] = {}
        for entry in self.entries:
            if entry.param_fmt in UTF8_FORMATS:
                value = self.string_value(entry)
            elif entry.param_fmt == UNSIGNED_INTEGER:
                value = self.integer_value(entry)
            else:
                raise SFOError(f"unsupported parameter format {entry.param_fmt}")
            values[self.key(entry)] = value
        return values

    def query(self, key: str, decimal: bool = False) -> Optional[str]:
        index = self._find(key)
        return None if index is None else self.value(self.entries[index], decimal)

    def format(self, verbose: bool = False, decimal: bool = False) -> str:
        lines = []
        if verbose:
            major = self.header.version >> 8
            minor = self.header.version & 0xFF
            lines.extend([
                f"Param.sfo version: {major:x}.{minor:02x}",
                f"Number of parameters: {len(self.entries)}",
            ])

        for index, entry in enumerate(self.entries):
            key = self.key(entry)
            value = self.value(entry, decimal)
            if not verbose:
                lines.append(f"{key}={value}")
                continue

            if entry.param_fmt == UTF8_STRING:
                description = "UTF-8 string"
                value = f'"{value}"'
            elif entry.param_fmt == UTF8_SPECIAL_STRING:
                description = "UTF-8 special mode string"
                value = f'"{value}"'
            else:
                description = "unsigned integer"
            lines.append(
                f"[{index}] {key}={value} "
                f"({entry.param_len}/{entry.param_max_len} bytes {description})"
            )

        return "\n".join(lines) + ("\n" if lines else "")

    def debug(self) -> str:
        lines = [
            "Header:",
            f"Size: {HEADER.size}",
            f".magic: {self.header.magic}",
            f".version: {self.header.version}",
            f".key_table_offset: {self.header.key_table_offset}",
            f".data_table_offset: {self.header.data_table_offset}",
            f".entries_count: {len(self.entries)}",
            "",
            "Index table:",
            f"Size: {ENTRY.size * len(self.entries)}",
        ]
        for index, entry in enumerate(self.entries):
            lines.extend([
                f"Entry {index}:",
                f'  .key_offset: {entry.key_offset} -> "{self.key(entry)}"',
                f"  .param_fmt: {entry.param_fmt}",
                f"  .param_len: {entry.param_len}",
                f"  .param_max_len: {entry.param_max_len}",
            ])
            value = ""
            if entry.param_fmt in UTF8_FORMATS:
                value = f'"{self.string_value(entry)}"'
            elif entry.param_fmt == UNSIGNED_INTEGER:
                value = f"0x{self.integer_value(entry):08x}"
            lines.append(
                f"  .data_offset: {entry.data_offset} "
                f"(0x{entry.data_offset:x})-> {value}"
            )

        key_content = "".join(
            chr(byte) if 32 <= byte <= 126 else f"'\\{byte}'"
            for byte in self.key_table
        )
        lines.extend([
            "",
            "Key table:",
            f"Size: {len(self.key_table)}",
        ])
        if self.key_table:
            lines.extend(["Content:", key_content])
        lines.extend([
            "",
            "Data table:",
            f"Size: {len(self.data_table)} (0x{len(self.data_table):x})",
        ])
        if self.data_table:
            lines.append("Content:")
            lines.extend(hexdump(self.data_table))
        lines.append("")
        return "\n".join(lines) + "\n"

    def _find(self, key: str) -> Optional[int]:
        encoded_key = key.encode("utf-8")
        for index, entry in enumerate(self.entries):
            if c_string(self.key_table, entry.key_offset) == encoded_key:
                return index
        return None

    def _pad_keys(self) -> None:
        self.key_table = self.key_table.rstrip(b"\0")
        if self.key_table:
            self.key_table.append(0)
        self.key_table.extend(b"\0" * (-len(self.key_table) % 4))

    def edit(self, key: str, value: str, ignore_missing: bool = False) -> None:
        index = self._find(key)
        if index is None:
            if ignore_missing:
                return
            raise SFOError(f'could not edit "{key}": parameter not found')

        entry = self.entries[index]
        if entry.param_fmt in UTF8_FORMATS:
            encoded = value.encode("utf-8") + b"\0"
            entry.param_len = len(encoded)

            if len(encoded) > entry.param_max_len:
                old_max_len = entry.param_max_len
                expansion_offset = entry.data_offset + old_max_len
                entry.param_max_len = align4(len(encoded))
                growth = entry.param_max_len - old_max_len
                self.data_table[expansion_offset:expansion_offset] = b"\0" * growth
                for following in self.entries[index + 1:]:
                    following.data_offset += growth

            start = entry.data_offset
            end = start + entry.param_max_len
            self.data_table[start:end] = encoded.ljust(entry.param_max_len, b"\0")
        elif entry.param_fmt == UNSIGNED_INTEGER:
            UINT32.pack_into(self.data_table, entry.data_offset, int(value, 0))

    def delete(self, key: str, ignore_missing: bool = False) -> None:
        index = self._find(key)
        if index is None:
            if ignore_missing:
                return
            raise SFOError(f'could not delete "{key}": parameter not found')

        entry = self.entries[index]
        key_size = len(key.encode("utf-8")) + 1
        data_size = entry.param_max_len
        del self.key_table[entry.key_offset:entry.key_offset + key_size]
        del self.data_table[entry.data_offset:entry.data_offset + data_size]
        del self.entries[index]
        self._pad_keys()

        for following in self.entries[index:]:
            following.key_offset -= key_size
            following.data_offset -= data_size
        self.header.entries_count = len(self.entries)

    def add(
        self, param_type: str, key: str, value: str, ignore_existing: bool = False
    ) -> None:
        encoded_key = key.encode("utf-8")
        encoded_value = value.encode("utf-8")

        if param_type == "str":
            param_len = len(encoded_value) + 1
            max_len = RESERVED_STRING_SIZES.get(key, 0)
            if max_len < param_len:
                max_len = align4(param_len)
            entry = Entry(param_fmt=UTF8_STRING, param_len=param_len,
                          param_max_len=max_len)
        else:
            entry = Entry(param_fmt=UNSIGNED_INTEGER, param_len=4, param_max_len=4)

        new_index = len(self.entries)
        if self.entries:
            last = self.entries[-1]
            entry.key_offset = last.key_offset + len(self.key(last).encode()) + 1
            entry.data_offset = last.data_offset + last.param_max_len

        for index, existing in enumerate(self.entries):
            existing_key = c_string(self.key_table, existing.key_offset)
            if encoded_key == existing_key:
                if ignore_existing:
                    return
                raise SFOError(f'could not add "{key}": parameter already exists')
            if encoded_key < existing_key:
                new_index = index
                entry.key_offset = existing.key_offset
                entry.data_offset = existing.data_offset
                break

        self.entries.insert(new_index, entry)
        for following in self.entries[new_index + 1:]:
            following.key_offset += len(encoded_key) + 1
            following.data_offset += entry.param_max_len
        self.header.entries_count = len(self.entries)

        self.key_table[entry.key_offset:entry.key_offset] = encoded_key + b"\0"
        self._pad_keys()
        start = entry.data_offset
        self.data_table[start:start] = b"\0" * entry.param_max_len

        if param_type == "str":
            self.data_table[start:start + entry.param_len] = encoded_value + b"\0"
        else:
            UINT32.pack_into(self.data_table, start, int(value, 0))

    def set(self, param_type: str, key: str, value: str) -> None:
        self.delete(key, ignore_missing=True)
        self.add(param_type, key, value, ignore_existing=True)

    def apply(self, command: Command, force: bool = False) -> None:
        if command.operation == "add":
            self.add(command.param_type or "", command.key,
                     command.value or "", force)
        elif command.operation == "delete":
            self.delete(command.key, force)
        elif command.operation == "edit":
            self.edit(command.key, command.value or "", force)
        else:
            self.set(command.param_type or "", command.key, command.value or "")


def pkg_sfo_offset(file: BinaryIO) -> int:
    file.seek(0x0C)
    count = BIG_ENDIAN_UINT32.unpack(read_exact(file, 4, "PKG header"))[0]
    file.seek(0x18)
    table_offset = BIG_ENDIAN_UINT32.unpack(read_exact(file, 4, "PKG header"))[0]
    file.seek(table_offset)

    for _ in range(count):
        data = read_exact(file, PKG_ENTRY.size, "PKG table")
        entry = PKG_ENTRY.unpack(data)
        if entry[0] == PKG_SFO_ENTRY_ID:
            return entry[4]
    raise SFOError("could not find a param.sfo file inside the PS4 PKG")


def load_sfo(path: Union[str, Path]) -> tuple:
    path = Path(path)
    with path.open("rb") as file:
        magic = UINT32.unpack(read_exact(file, 4, "file header"))[0]
        if magic == PKG_MAGIC:
            offset = pkg_sfo_offset(file)
        elif magic == DISC_SFO_MAGIC:
            offset = 0x800
        elif magic == SFO_MAGIC:
            offset = 0
        else:
            raise SFOError("param.sfo magic number not found")
        file.seek(offset)
        return SFO.read(file), magic


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Read, print, or modify SFO parameters.",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog=(
            "Supported input: PS4 param.sfo, PS4 disc param.sfo, and PS4 PKG.\n"
            "Modification options may be repeated and are applied in order."
        ),
    )
    parser.add_argument("file", type=Path, help="input SFO, disc SFO, or PKG file")
    parser.add_argument("-a", "--add", dest="commands", action=CommandAction,
                        operation="add", nargs=3,
                        metavar=("TYPE", "PARAMETER", "VALUE"),
                        help="add a new string or integer parameter")
    parser.add_argument("-d", "--delete", dest="commands", action=CommandAction,
                        operation="delete", metavar="PARAMETER",
                        help="delete a parameter")
    parser.add_argument("-e", "--edit", dest="commands", action=CommandAction,
                        operation="edit", nargs=2, metavar=("PARAMETER", "VALUE"),
                        help="change a parameter's value")
    parser.add_argument("-s", "--set", dest="commands", action=CommandAction,
                        operation="set", nargs=3,
                        metavar=("TYPE", "PARAMETER", "VALUE"),
                        help="set a parameter, creating it if necessary")
    parser.add_argument("--debug", action="store_true", help="print debug information")
    parser.add_argument("--decimal", action="store_true",
                        help="display integers as decimal numerals")
    parser.add_argument("-f", "--force", action="store_true",
                        help="ignore failed modifications and overwrite with --new-file")
    parser.add_argument("--new-file", action="store_true",
                        help="create FILE if it does not exist")
    parser.add_argument("-o", "--output-file", type=Path,
                        help="write the resulting param.sfo to another file")
    parser.add_argument("-q", "--query", action="append", metavar="PARAMETER",
                        help="print one parameter's value and quit")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="include parameter metadata")
    parser.add_argument("--version", action="version",
                        version=f"SFO v{PROGRAM_VERSION}\n{PROGRAM_URL}")
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.query and len(args.query) > 1:
        parser.error("only one query is allowed")

    try:
        if args.new_file:
            if args.file.exists() and not args.force:
                raise SFOError(f'file "{args.file}" already exists')
            SFO().write(args.file)

        sfo, source_magic = load_sfo(args.file)
        if args.debug:
            print(f"Arguments: {args}\n", file=sys.stderr)
            print(f"Memory before running commands:\n\n{sfo.debug()}", file=sys.stderr)

        if args.commands:
            if source_magic == PKG_MAGIC:
                raise SFOError("cannot edit PKG files")
            if source_magic == DISC_SFO_MAGIC:
                raise SFOError("cannot edit disc param.sfo files")
            for command in args.commands:
                sfo.apply(command, args.force)
            if args.debug:
                print(f"Memory after running commands:\n\n{sfo.debug()}", file=sys.stderr)
            sfo.write(args.output_file if args.output_file is not None else args.file)
        elif args.output_file is not None:
            sfo.write(args.output_file)

        if args.query:
            value = sfo.query(args.query[0].upper(), args.decimal)
            if value is None:
                return 1
            print(value)
        elif not args.commands:
            print(sfo.format(args.verbose, args.decimal), end="")
        return 0
    except (OSError, SFOError, ValueError) as error:
        print(f"{parser.prog}: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
