# SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
# SPDX-License-Identifier: MIT
"""Check timer oracle boundaries with fixed clock and bus expectations."""

import unittest

from timer import expected


class TimerOracleTests(unittest.TestCase):
    def test_write_overrides_tick_and_read_captures_before_tick(self):
        rows = [(1, 1, 1, 0, 0, 1, 9, 15, 2),
                (0, 1, 1, 0, 0, 1, 0xFFFFFFFF, 15, 2),
                (0, 1, 0, 0, 0, 0, 0, 0, 2),
                (0, 1, 0, 1, 0, 0, 0, 0, 2),
                (0, 1, 1, 0, 0, 0, 0, 0, 2),
                (0, 1, 0, 0, 0, 0, 0, 0, 2)]
        values, counts = expected(rows)
        self.assertEqual([item[5] for item in values],
                         [0, 0xFFFFFFFF, 0x100000000, 0x100000001, 0x100000002, 0x100000003])
        self.assertEqual(values[4][3], 1)
        self.assertEqual(values[5][3], 1)
        self.assertEqual(counts['timeWritesWithTick'], 1)

    def test_invalid_store_has_no_register_effect(self):
        rows = [(1, 0, 0, 1, 0, 0, 0, 0, 2),
                (0, 0, 1, 0, 16, 1, 1, 3, 2),
                (0, 0, 0, 1, 0, 0, 0, 0, 2),
                (0, 0, 1, 0, 16, 0, 0, 0, 2)]
        values, counts = expected(rows)
        self.assertEqual(values[1][4], 1)
        self.assertEqual(values[1][7], 0)
        self.assertEqual(values[3][3], 0)
        self.assertEqual(counts['faults'], 1)


if __name__ == '__main__':
    unittest.main()
