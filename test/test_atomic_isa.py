# SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
# SPDX-License-Identifier: MIT
"""Check the atomic ELF initialization contract."""

from pathlib import Path
import sys
import unittest
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).parent / "isa"))
from atomic_run import init_pairs, mutable_bytes, check_initialization, atomic_specification, selected_tests


class AtomicInitializationTests(unittest.TestCase):
    def test_test_selection_keeps_the_rtl_control_reachable(self):
        self.assertEqual(selected_tests(["amoxor.w", "amoadd.w"]), ["amoadd.w", "amoxor.w"])

    def test_selection_without_the_rtl_control_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "including amoadd.w"):
            selected_tests(["amoxor.w"])

    def test_isa_and_misa_enable_the_same_extensions(self):
        text = atomic_specification({"enableM": True, "enableC": True})
        self.assertIn("ISA: RV32IMACZicsr", text)
        self.assertIn("reset-val: 0x40001105", text)

    def test_little_endian_words(self):
        data = {8: 0x78, 9: 0x56, 10: 0x34, 11: 0x12, 16: 1, 17: 0, 18: 0, 19: 0}
        self.assertEqual(init_pairs(data), [(8, 0x12345678), (16, 1)])

    def test_missing_lane_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "Incomplete initialization word"):
            init_pairs({8: 1, 9: 2, 11: 4})

    def test_writable_rom_is_rejected(self):
        image = SimpleNamespace(segments=[SimpleNamespace(flags=6, address=0, memory_size=4)], memory={})
        with self.assertRaisesRegex(ValueError, "exceeds SRAM"):
            mutable_bytes(image, {"sram": {"base": 8, "size": 4}})

    def test_final_link_cannot_change_initial_values(self):
        segment = SimpleNamespace(flags=6, address=8, memory_size=4)
        old = SimpleNamespace(segments=[segment], memory={8: 1, 9: 0, 10: 0, 11: 0})
        new = SimpleNamespace(segments=[segment], memory={8: 2, 9: 0, 10: 0, 11: 0})
        with self.assertRaisesRegex(ValueError, "Final link changed"):
            check_initialization(old, new, {"sram": {"base": 8, "size": 4}}, [(8, 1)])


if __name__ == "__main__":
    unittest.main()
