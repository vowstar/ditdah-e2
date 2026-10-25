# SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
# SPDX-License-Identifier: MIT

import unittest

from pmp import ADDRESS_MASK, LIMIT, Reference, check, partial_match_mutant


class PmpTests(unittest.TestCase):
    def test_csr_decode_and_unknown_writes(self):
        model = Reference()
        addresses = set(range(0x3A0, 0x3A4)) | set(range(0x3B0, 0x3C0))
        for address in range(4096):
            self.assertEqual(model.read(address), (address in addresses, 0))
        for address in (0x39F, 0x3A4, 0x3AF, 0x3C0, 0xFFF):
            model.write(address, 0xFFFFFFFF)
            self.assertEqual(model.read(address), (False, 0))
        self.assertEqual(model.configs, [0] * 16)

    def test_configuration_warl_and_packed_locks(self):
        for raw, expected in ((0xFF, 0x9F), (0xFE, 0x9C), (0x60, 0),
                              (0x02, 0), (0x16, 0x14), (0x9E, 0x9C)):
            model = Reference()
            model.write(0x3A0, raw)
            self.assertEqual(model.read(0x3A0), (True, expected))
        model = Reference()
        model.write(0x3A0, 0x01020380)
        self.assertEqual(model.read(0x3A0), (True, 0x01000380))
        model.write(0x3A0, 0x07070700)
        self.assertEqual(model.read(0x3A0), (True, 0x07070780))
        model.write(0x3B0, 7)
        self.assertEqual(model.read(0x3B0), (True, 0))

    def test_address_width(self):
        model = Reference()
        for index in range(16):
            model.write(0x3B0 + index, 0xFFFFFFFF)
            self.assertEqual(model.read(0x3B0 + index), (True, ADDRESS_MASK))

    def test_tor_lock_includes_previous_address_only(self):
        for index in range(1, 16):
            model = Reference()
            model.write(0x3AF + index, 11)
            model.write(0x3B0 + index, 22)
            group, lane = divmod(index, 4)
            model.write(0x3A0 + group, 0x88 << (lane * 8))
            model.write(0x3AF + index, 33)
            model.write(0x3B0 + index, 44)
            self.assertEqual(model.addresses[index - 1:index + 1], [11, 22])
            previous_group, previous_lane = divmod(index - 1, 4)
            model.write(0x3A0 + previous_group, 7 << (8 * previous_lane))
            self.assertEqual(model.configs[index - 1], 7)
            self.assertEqual(model.configs[index], 0x88)

    def test_other_locked_modes_do_not_lock_previous_address(self):
        for config in (0x80, 0x90, 0x98):
            model = Reference()
            model.write(0x3A0, config << 8)
            model.write(0x3B0, 123)
            model.write(0x3B1, 456)
            self.assertEqual(model.addresses[:2], [123, 0])

    def test_napot_intervals_include_full_address_space(self):
        for address, expected in ((0, (0, 8)), (1, (0, 16)), (3, (0, 32)),
                                  (0x20000000, (0x80000000, 0x80000008)),
                                  (0x1FFFFFFF, (0, 1 << 32)), (0x3FFFFFFF, (0, 1 << 33))):
            model = Reference()
            model.write(0x3B0, address)
            model.write(0x3A0, 0x1F)
            self.assertEqual(model.interval(0), expected)

    def test_tor_first_and_empty_ranges(self):
        model = Reference()
        model.write(0x3B0, 4)
        model.write(0x3A0, 9)
        self.assertEqual(model.interval(0), (0, 16))
        self.assertTrue(model.allowed((15, 0, 0, 0)))
        self.assertFalse(model.allowed((15, 1, 1, 0)))
        for top in (0, 4):
            model = Reference()
            model.write(0x3B0, 4)
            model.write(0x3B1, top)
            model.write(0x3A0, 0x8900)
            self.assertFalse(model.allowed((0, 2, 0, 0)))
            self.assertTrue(model.allowed((0, 2, 1, 0)))

    def test_permissions_and_machine_bypass(self):
        for permissions in (0, 1, 3, 4, 5, 7):
            for locked in (0, 128):
                model = Reference()
                model.write(0x3B0, 0x400)
                model.write(0x3A0, 0x10 | locked | permissions)
                for kind in range(3):
                    allowed = bool(permissions & (1 << kind))
                    self.assertEqual(model.allowed((0x1000, 2, 0, kind)), allowed)
                    self.assertEqual(model.allowed((0x1000, 2, 1, kind)), allowed or not locked)

    def test_lowest_overlap_must_cover_the_whole_access(self):
        model = Reference()
        model.write(0x3B0, 0x401)
        model.write(0x3B1, 0x403)
        model.write(0x3A0, 0x1F10)
        for machine in (0, 1):
            self.assertFalse(model.allowed((0x1002, 2, machine, 0)))
        self.assertFalse(model.allowed((0x1004, 2, 0, 0)))
        self.assertTrue(model.allowed((0x1004, 2, 1, 0)))
        self.assertTrue(model.allowed((0x1000, 2, 0, 0)))
        model.write(0x3A0, 0x1F80)
        self.assertTrue(model.allowed((0x1002, 2, 0, 0)))

    def test_invalid_query_and_address_overflow(self):
        model = Reference()
        self.assertTrue(model.allowed((LIMIT - 4, 2, 1, 0)))
        self.assertFalse(model.allowed((LIMIT - 4, 2, 0, 0)))
        model.write(0x3B0, 0x1FFFFFFF)
        model.write(0x3A0, 0x9F)
        self.assertTrue(model.allowed((LIMIT - 1, 0, 0, 2)))
        for machine in (0, 1):
            for address, size, kind in ((LIMIT - 1, 1, 0), (LIMIT - 3, 2, 1), (0, 3, 0), (0, 0, 3)):
                self.assertFalse(model.allowed((address, size, machine, kind)))

    def test_commit_and_reset_edges(self):
        model = Reference()
        row = (0, 0x3A0, 0, 0x80, 0, 0, 0, 0, 0, 0, 1, 0)
        self.assertEqual(model.step(row, 0), (0, 1, 0, 0, 1))
        self.assertEqual(model.read(0x3A0), (True, 0))
        row = (0, 0x3A0, 1, 0x80, *row[4:])
        self.assertEqual(model.step(row, 1)[2], 0)
        self.assertEqual(model.read(0x3A0), (True, 0x80))
        row = (1, 0x3A0, 1, 0xFFFFFFFF, *row[4:])
        self.assertEqual(model.step(row, 2)[2], 0x80)
        self.assertEqual(model.read(0x3A0), (True, 0))

    def test_checker_and_mutation_reject_invalid_evidence(self):
        rows = [(0, 0x3A0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0)]
        self.assertEqual(check(rows, "0 1 00000000 0 1\n")["userNoMatch"], 1)
        for trace in ("0 1 00000000 1 1\n", "0 1 00000000 0\n", ""):
            with self.assertRaises(AssertionError):
                check(rows, trace)
        source = "assign data_allowed = valid & selected;"
        self.assertIn("data_address == 32'h1002", partial_match_mutant(source))
        for content in ("assign other_allowed = 1;", source + source):
            with self.assertRaises(AssertionError):
                partial_match_mutant(content)


if __name__ == "__main__":
    unittest.main()
