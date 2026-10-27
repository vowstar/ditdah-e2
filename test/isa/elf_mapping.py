# SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
# SPDX-License-Identifier: MIT
"""Check instruction ranges declared by RISC-V ELF mapping symbols."""

from collections import defaultdict
import re
import struct


def extent(data, start, size):
    if start < 0 or size < 0 or start + size > len(data):
        raise ValueError('ELF mapping extent exceeds the file')
    return data[start:start + size]


def instruction_ranges(data, *, enable_c=False):
    if type(enable_c) is not bool:
        raise ValueError('C selection must be Boolean')
    header = extent(data, 0, 52)
    if header[:7] != b'\x7fELF\x01\x01\x01':
        raise ValueError('ELF mapping requires little-endian ELF32')
    entry, phoff, shoff = struct.unpack_from('<III', header, 24)
    phsize, phnum, shsize, shnum = struct.unpack_from('<HHHH', header, 42)
    if phsize != 32 or shsize != 40 or not 0 < phnum < 0xffff or not 0 < shnum < 0xff00:
        raise ValueError('Invalid ELF mapping tables')
    program_table = extent(data, phoff, phsize * phnum)
    section_table = extent(data, shoff, shsize * shnum)
    programs = [struct.unpack_from('<8I', program_table, index * 32) for index in range(phnum)]
    sections = [struct.unpack_from('<10I', section_table, index * 40) for index in range(shnum)]
    executable = {index: section for index, section in enumerate(sections) if section[2] & 4 and section[5]}
    mappings = defaultdict(dict)
    for section in sections:
        _, kind, _, _, offset, size, link, _, _, stride = section
        if kind != 2:
            continue
        if stride != 16 or size % stride or link >= shnum or sections[link][1] != 3:
            raise ValueError('Invalid ELF mapping symbol table')
        symbols = extent(data, offset, size)
        strings = extent(data, sections[link][4], sections[link][5])
        for at in range(0, size, stride):
            name, address, length, info, other, index = struct.unpack_from('<IIIBBH', symbols, at)
            if name >= len(strings) or strings.find(b'\0', name) < 0:
                raise ValueError('Invalid ELF mapping symbol name')
            symbol = strings[name:strings.find(b'\0', name)]
            if not symbol.startswith((b'$x', b'$d')):
                continue
            if re.fullmatch(rb'\$d(?:\..*)?', symbol):
                mapping = 'data'
            elif re.fullmatch(rb'\$x(?:rv32i2p1(?:_zicsr2p0|_c2p0_zicsr2p0_zca1p0)?)?(?:\..*)?', symbol):
                mapping = 'code'
            else:
                raise ValueError('Unsupported ELF mapping symbol')
            if info or other or length or not 0 < index < shnum:
                raise ValueError('Invalid ELF mapping symbol attributes')
            target = sections[index]
            if not target[3] <= address <= target[3] + target[5]:
                raise ValueError('ELF mapping symbol exceeds its section')
            if index in executable:
                if address in mappings[index] and mappings[index][address] != mapping:
                    raise ValueError('Conflicting ELF mapping symbols')
                mappings[index][address] = mapping
    covered = set()
    for kind, offset, address, _, size, memory, flags, _ in programs:
        if kind != 1 or not flags & 1:
            continue
        if size != memory or not size:
            raise ValueError('Executable memory must have complete file data')
        extent(data, offset, size)
        cursor = address
        members = sorted((section[3], index, section) for index, section in executable.items()
                         if address <= section[3] < address + size)
        for start, index, section in members:
            if (index in covered or section[1] != 1 or section[2] & 2 == 0 or start != cursor or
                    section[4] != offset + start - address or start + section[5] > address + size):
                raise ValueError('Executable section coverage is incomplete')
            cursor = start + section[5]
            covered.add(index)
        if cursor != address + size:
            raise ValueError('Executable section coverage is incomplete')
    if not executable or covered != executable.keys():
        raise ValueError('Executable sections lack matching load segments')
    ranges = []
    for index, section in executable.items():
        start, offset, size = section[3:6]
        if start + size > 1 << 32 or start not in mappings[index]:
            raise ValueError('Executable section lacks an initial mapping')
        boundaries = sorted(mappings[index])
        for at, end in zip(boundaries, boundaries[1:] + [start + size]):
            if mappings[index][at] != 'code' or at == end:
                continue
            if at % 2 or end % 2:
                raise ValueError('Mapped code has an odd byte boundary')
            while at < end:
                file_offset = offset + at - start
                halfword = int.from_bytes(extent(data, file_offset, 2), 'little')
                # The fixed LA macro emits C.NOP to reach a word boundary.
                if not enable_c and halfword == 1 and at % 4 == 2:
                    at += 2
                    continue
                width = 2 if enable_c and halfword & 3 != 3 else 4
                if at + width > end or (not enable_c and halfword & 3 != 3) or halfword & 31 == 31:
                    raise ValueError('Mapped code contains an unsupported instruction width')
                if not enable_c and ranges and ranges[-1][1] == at:
                    ranges[-1] = (ranges[-1][0], at + width)
                else:
                    ranges.append((at, at + width))
                at += width
    if not instruction_pc(ranges, entry, enable_c=enable_c):
        raise ValueError('ELF entry is outside mapped instructions')
    return tuple(sorted(ranges))


def instruction_pc(ranges, address, *, enable_c=False):
    if enable_c:
        return address % 2 == 0 and any(start == address for start, _ in ranges)
    return address % 4 == 0 and any(start <= address and address + 4 <= end and
                                  (address - start) % 4 == 0 for start, end in ranges)
