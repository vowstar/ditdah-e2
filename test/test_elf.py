# SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
# SPDX-License-Identifier: MIT
"""Check ELF boundaries independently of the cross compiler."""

import os
from pathlib import Path
import shutil
import struct
import sys
import tempfile
import unittest
from unittest.mock import patch

from elf import Region, load_elf

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import build_software


def executable():
    data = bytearray(0x108)
    data[:16] = b"\x7fELF\x01\x01\x01" + bytes(9)
    struct.pack_into("<HHIIIIIHHHHHH", data, 16, 2, 243, 1, 0, 52, 0, 0, 52, 32, 2, 0, 0, 0)
    struct.pack_into("<8I", data, 52, 1, 0x100, 0, 0, 4, 4, 5, 4)
    struct.pack_into("<8I", data, 84, 1, 0x104, 0x20000000, 0x20000000, 4, 8, 6, 4)
    struct.pack_into("<II", data, 0x100, 0x13, 0x12345678)
    return data


def with_symbols(data):
    names = b"\0software_done\0"
    names_at = len(data)
    data.extend(names)
    symbols_at = len(data)
    data.extend(bytes(16))
    data.extend(struct.pack("<IIIBBH", 1, 0, 4, 0x12, 0, 0xFFF1))
    sections_at = len(data)
    data.extend(bytes(40))
    data.extend(struct.pack("<10I", 0, 3, 0, 0, names_at, len(names), 0, 0, 1, 0))
    data.extend(struct.pack("<10I", 0, 2, 0, 0, symbols_at, 32, 1, 1, 4, 16))
    struct.pack_into("<I", data, 32, sections_at)
    struct.pack_into("<HHH", data, 46, 40, 3, 0)
    return data, names_at, symbols_at, sections_at


class ElfTests(unittest.TestCase):
    def setUp(self):
        scratch = "/data/tmp" if os.access("/data/tmp", os.W_OK) else None
        self.directory = tempfile.TemporaryDirectory(prefix="ditdah-e2-elf-", dir=scratch)
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name) / "program.elf"

    def load(self, data, **arguments):
        self.path.write_bytes(data)
        return load_elf(self.path, **arguments)

    def reject(self, data, message, **arguments):
        with self.assertRaisesRegex(ValueError, message):
            self.load(data, **arguments)

    def test_load_and_zero_fill(self):
        image = self.load(executable())
        self.assertEqual(image.entry, 0)
        self.assertEqual(image.words(), {0: 0x13, 0x20000000: 0x12345678, 0x20000004: 0})
        self.assertEqual(image.memory[0x20000000], 0x78)
        self.assertEqual(len(image.memory), 12)
        self.assertEqual(image.segments[1].data, b"\x78\x56\x34\x12")

    def test_pure_bss_segment(self):
        data = executable()
        struct.pack_into("<I", data, 84 + 16, 0)
        image = self.load(data)
        self.assertTrue(all(image.memory[address] == 0 for address in range(0x20000000, 0x20000008)))

    def test_nonzero_reset(self):
        data = executable()
        struct.pack_into("<I", data, 24, 0x40)
        struct.pack_into("<II", data, 52 + 8, 0x40, 0x40)
        self.assertEqual(self.load(data, reset_vector=0x40).words()[0x40], 0x13)
        self.reject(data, "entry does not match")

    def test_identification_and_machine(self):
        for offset, width, value in ((0, "I", 0), (4, "B", 2), (5, "B", 2), (6, "B", 2),
                                     (7, "B", 3), (8, "B", 1), (9, "B", 1),
                                     (16, "H", 3), (18, "H", 62), (20, "I", 2),
                                     (36, "I", 1), (36, "I", 2), (36, "I", 4), (36, "I", 8)):
            with self.subTest(offset=offset, value=value):
                data = executable()
                struct.pack_into("<" + width, data, offset, value)
                self.reject(data, "Expected|Unsupported")

    def test_invalid_program_table(self):
        for offset, width, value in ((28, "I", 0), (40, "H", 51), (42, "H", 31),
                                     (44, "H", 0), (44, "H", 0xFFFF)):
            with self.subTest(offset=offset):
                data = executable()
                struct.pack_into("<" + width, data, offset, value)
                self.reject(data, "program table")

    def test_truncated_inputs(self):
        for length in (0, 51, 83, 115, 0x103, 0x107):
            with self.subTest(length=length):
                self.reject(executable()[:length], "Truncated")

    def test_dynamic_linking(self):
        for kind in (2, 3):
            with self.subTest(kind=kind):
                data = executable()
                struct.pack_into("<I", data, 84, kind)
                self.reject(data, "Dynamic linking")

    def test_segment_size_and_address(self):
        for offset, value, message in ((20, 0, "size"), (16, 9, "size"),
                                       (8, 0x20000004, "address"), (24, 2, "permissions"),
                                       (24, 14, "permissions"), (28, 3, "alignment"),
                                       (28, 8, "alignment"), (4, 0xFFFFFFFC, "Truncated")):
            with self.subTest(offset=offset, value=value):
                data = executable()
                struct.pack_into("<I", data, 84 + offset, value)
                self.reject(data, message)

    def test_valid_segment_alignment(self):
        for align in (0, 1, 4):
            with self.subTest(align=align):
                data = executable()
                struct.pack_into("<I", data, 84 + 28, align)
                self.assertEqual(self.load(data).memory[0x20000000], 0x78)

    def test_wrap_and_platform_bounds(self):
        for address, message in ((0xFFFFFFFC, "address"), (0x2000FFFC, "bounds"),
                                 (0x10000000, "bounds"), (0x10000, "bounds")):
            with self.subTest(address=address):
                data = executable()
                struct.pack_into("<II", data, 84 + 8, address, address)
                self.reject(data, message)

    def test_rom_write_permission(self):
        data = executable()
        struct.pack_into("<I", data, 52 + 24, 7)
        self.reject(data, "permissions or bounds")

    def test_overlap(self):
        for address in (0, 2):
            with self.subTest(address=address):
                data = executable()
                struct.pack_into("<8I", data, 84, 1, 0x104, address, address, 4, 4, 5, 1)
                self.reject(data, "Overlapping load")

    def test_load_segment_order(self):
        data = executable()
        data[52:84], data[84:116] = data[84:116], data[52:84]
        self.reject(data, "not in address order")

    def test_entry_requires_executable_file_bytes(self):
        for flags, file_size in ((4, 4), (5, 0), (5, 3)):
            with self.subTest(flags=flags, file_size=file_size):
                data = executable()
                struct.pack_into("<I", data, 52 + 16, file_size)
                struct.pack_into("<I", data, 52 + 24, flags)
                self.reject(data, "entry is outside")

    def test_reset_alignment_and_range(self):
        for reset in (-1, 2, 1 << 32, True):
            with self.subTest(reset=reset):
                self.reject(executable(), "Invalid reset", reset_vector=reset)

    def test_region_validation(self):
        for regions in ((Region("invalid", 0, 0, 7),), (Region("invalid", 0xFFFFFFFF, 2, 7),),
                        (Region("invalid", 0, 4, 8),),
                        (Region("first", 0, 8, 7), Region("second", 4, 8, 7))):
            with self.subTest(regions=regions):
                self.reject(executable(), "memory region", regions=regions)

    def test_defined_symbol(self):
        data, _, _, _ = with_symbols(executable())
        self.assertEqual(self.load(data).symbols, {"software_done": 0})

    def test_section_table_bounds(self):
        data, _, _, _ = with_symbols(executable())
        self.reject(data[:-1], "Truncated section table")
        struct.pack_into("<H", data, 46, 39)
        self.reject(data, "Invalid section table")
        data = executable()
        struct.pack_into("<I", data, 32, 0x200)
        self.reject(data, "Invalid absent section")

    def test_symbol_table_bounds(self):
        for field, value in ((4, 0xFFFFFFFF), (5, 31), (6, 3), (9, 15)):
            with self.subTest(field=field):
                data, _, _, sections = with_symbols(executable())
                struct.pack_into("<I", data, sections + 80 + field * 4, value)
                self.reject(data, "Truncated section|Invalid symbol table")

    def test_symbol_name_bounds(self):
        data, _, symbols, _ = with_symbols(executable())
        struct.pack_into("<I", data, symbols + 16, 0xFFFFFFFF)
        self.reject(data, "Invalid symbol name")
        data, names, symbols, _ = with_symbols(executable())
        data[symbols - 1] = 0x20
        self.reject(data, "Unterminated symbol name")
        data, names, _, _ = with_symbols(executable())
        data[names + 1] = 0xFF
        self.reject(data, "Invalid symbol name")

    def test_dynamic_sections(self):
        for kind in (6, 11):
            with self.subTest(kind=kind):
                data, _, _, sections = with_symbols(executable())
                struct.pack_into("<I", data, sections + 80 + 4, kind)
                self.reject(data, "Dynamic linking")


@unittest.skipUnless(shutil.which("riscv32-none-elf-gcc") and shutil.which("riscv32-none-elf-objdump"),
                     "RISC-V compiler and objdump are required")
class SoftwareBuildTests(unittest.TestCase):
    def setUp(self):
        scratch = "/data/tmp" if os.access("/data/tmp", os.W_OK) else None
        self.directory = tempfile.TemporaryDirectory(prefix="ditdah-e2-software-test-", dir=scratch)
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name)

    def test_reproducible_executable(self):
        first = build_software.build(self.path / "first")
        second = build_software.build(self.path / "second")
        self.assertEqual(first, second)
        image = load_elf(self.path / "first/program.elf")
        self.assertEqual(image.words()[image.symbols["software_done"]], 0x6F)
        self.assertEqual(image.words()[image.symbols["software_seed"]], 0x13579BDF)
        self.assertEqual(image.words()[image.symbols["software_signature"]], 0)

    def test_relocated_executable(self):
        report = build_software.build(self.path / "relocated", reset_vector=0x40)
        image = load_elf(self.path / "relocated/program.elf", reset_vector=0x40)
        self.assertEqual(image.entry, 0x40)
        self.assertEqual(image.symbols["_start"], 0x40)
        self.assertEqual(report["resetVector"], 0x40)

    def test_changed_input_rejected(self):
        original = build_software.sources()
        with patch.object(build_software, "sources", side_effect=[original, {}]):
            with self.assertRaisesRegex(RuntimeError, "inputs changed"):
                build_software.build(self.path / "changed")
        self.assertFalse((self.path / "changed/manifest.json").exists())


if __name__ == "__main__":
    unittest.main()
