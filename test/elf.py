# SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
# SPDX-License-Identifier: MIT
"""Load static RV32 executables into the verification platform."""

from dataclasses import dataclass
from pathlib import Path
import struct


@dataclass(frozen=True)
class Region:
    name: str
    address: int
    size: int
    flags: int


REGIONS = (Region("rom", 0, 0x10000, 5), Region("sram", 0x20000000, 0x10000, 7))


@dataclass(frozen=True)
class Segment:
    address: int
    data: bytes
    memory_size: int
    flags: int


@dataclass
class ElfImage:
    entry: int
    segments: tuple[Segment, ...]
    symbols: dict[str, int]
    memory: dict[int, int]
    flags: int = 0

    def words(self):
        result = {}
        for address, value in self.memory.items():
            aligned = address & ~3
            result[aligned] = result.get(aligned, 0) | value << (8 * (address & 3))
        return result


def _extent(data, offset, size, label):
    if offset > len(data) or size > len(data) - offset:
        raise ValueError(f"Truncated {label}")
    return data[offset:offset + size]


def _symbols(data, offset, count, entry_size):
    if not count:
        if offset or entry_size not in (0, 40):
            raise ValueError("Invalid absent section table")
        return {}
    if entry_size != 40 or offset < 52:
        raise ValueError("Invalid section table")
    table = _extent(data, offset, count * entry_size, "section table")
    sections = [struct.unpack_from("<10I", table, index * 40) for index in range(count)]
    symbols = {}
    for section in sections:
        _, kind, _, _, start, size, link, _, _, stride = section
        if kind in (6, 11):
            raise ValueError("Dynamic linking is unsupported")
        if kind != 8:
            _extent(data, start, size, "section")
        if kind != 2:
            continue
        if stride != 16 or size % stride or link >= count or sections[link][1] != 3:
            raise ValueError("Invalid symbol table")
        strings = _extent(data, sections[link][4], sections[link][5], "symbol strings")
        for at in range(start, start + size, stride):
            name, value, _, info, _, index = struct.unpack_from("<IIIBBH", data, at)
            if name >= len(strings):
                raise ValueError("Invalid symbol name")
            end = strings.find(b"\0", name)
            if end < 0:
                raise ValueError("Unterminated symbol name")
            if not index or info >> 4 not in (1, 2):
                continue
            if index >= count and index != 0xFFF1:
                raise ValueError("Invalid symbol section")
            try:
                key = strings[name:end].decode("ascii")
            except UnicodeDecodeError as error:
                raise ValueError("Invalid symbol name") from error
            if key in symbols and symbols[key] != value:
                raise ValueError("Conflicting symbol definitions")
            if key:
                symbols[key] = value
    return symbols


def load_elf(path, *, reset_vector=0, regions=REGIONS, enable_c=False):
    if type(enable_c) is not bool:
        raise ValueError("enable_c must be a Boolean")
    data = Path(path).read_bytes()
    header = _extent(data, 0, 52, "ELF header")
    if header[:7] != b"\x7fELF\x01\x01\x01":
        raise ValueError("Expected little-endian ELF32")
    if header[7] or header[8] or any(header[9:16]):
        raise ValueError("Unsupported ELF identification")
    (kind, machine, version, entry, phoff, shoff, flags, header_size,
     phsize, phnum, shsize, shnum, shstrings) = struct.unpack_from("<HHIIIIIHHHHHH", header, 16)
    if kind != 2 or machine != 243 or version != 1 or flags & ~(1 if enable_c else 0):
        raise ValueError("Expected a static RV32 executable with compatible flags and the soft-float ABI")
    if header_size != 52 or phsize != 32 or not 0 < phnum < 0xFFFF or phoff < 52:
        raise ValueError("Invalid ELF program table")
    if type(reset_vector) is not int or not 0 <= reset_vector <= 0xFFFFFFFF or reset_vector % (2 if enable_c else 4):
        raise ValueError("Invalid reset vector")
    if entry != reset_vector:
        raise ValueError("ELF entry does not match the reset vector")
    if (shnum and shstrings >= shnum) or (not shnum and shstrings):
        raise ValueError("Invalid section name table")
    for index, region in enumerate(regions):
        if (not 0 <= region.address < 1 << 32 or region.size <= 0 or
                region.address + region.size > 1 << 32 or region.flags & ~7):
            raise ValueError("Invalid memory region")
        for earlier in regions[:index]:
            if region.address < earlier.address + earlier.size and earlier.address < region.address + region.size:
                raise ValueError("Overlapping memory regions")
    table = _extent(data, phoff, phnum * phsize, "program table")
    segments = []
    for index in range(phnum):
        kind, offset, virtual, address, file_size, memory_size, access, align = struct.unpack_from(
            "<8I", table, index * phsize)
        if kind in (2, 3):
            raise ValueError("Dynamic linking is unsupported")
        if kind != 1:
            continue
        if not memory_size or file_size > memory_size:
            raise ValueError("Invalid load segment size")
        if virtual != address or address + memory_size > 1 << 32:
            raise ValueError("Invalid load segment address")
        if align > 1 and (align & (align - 1) or (virtual - offset) % align):
            raise ValueError("Invalid load segment alignment")
        if access & ~7 or not access & 4:
            raise ValueError("Invalid load segment permissions")
        if not any(region.address <= address and address + memory_size <= region.address + region.size
                   and access & ~region.flags == 0 for region in regions):
            raise ValueError("Load segment exceeds platform permissions or bounds")
        if any(address < earlier.address + earlier.memory_size and earlier.address < address + memory_size
               for earlier in segments):
            raise ValueError("Overlapping load segments")
        if segments and address < segments[-1].address:
            raise ValueError("Load segments are not in address order")
        contents = _extent(data, offset, file_size, "load segment")
        segments.append(Segment(address, contents, memory_size, access))
    entry_segment = next((segment for segment in segments if segment.flags & 1 and
                          segment.address <= entry and entry + 2 <= segment.address + len(segment.data)), None)
    if entry_segment is None:
        raise ValueError("ELF entry is outside executable file data")
    offset = entry - entry_segment.address
    halfword = int.from_bytes(entry_segment.data[offset:offset + 2], "little")
    if halfword & 3 != 3 and not enable_c:
        raise ValueError("Compressed ELF entry requires C")
    if halfword & 31 == 31:
        raise ValueError("Unsupported instruction width at ELF entry")
    length = 2 if halfword & 3 != 3 else 4
    if offset + length > len(entry_segment.data):
        raise ValueError("ELF entry is outside executable file data")
    symbols = _symbols(data, shoff, shnum, shsize)
    memory = {}
    for segment in segments:
        memory.update((segment.address + index, value) for index, value in enumerate(segment.data))
        memory.update((address, 0) for address in range(segment.address + len(segment.data),
                                                      segment.address + segment.memory_size))
    return ElfImage(entry, tuple(segments), symbols, memory, flags)
