# SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
# SPDX-License-Identifier: MIT
"""Check benchmark outcomes and measurement boundaries."""

import unittest

from bit_benchmark import INPUT, INDICES, expected, fixed_memory_timing, measure_window, validate_profiles


class BenchmarkTests(unittest.TestCase):
    def test_fixed_results(self):
        output, result = expected("array_indexing")
        self.assertEqual(output[0], result)
        self.assertEqual(result, 0x21332FA0)
        bitmap, result = expected("bitmap_updates")
        self.assertEqual(result, 0)
        self.assertEqual(sum(word.bit_count() for word in bitmap), len(set(INDICES)))
        bytes_, result = expected("byte_processing")
        self.assertEqual(result, 0)
        self.assertEqual(bytes_[0], 0xB979379E)
        self.assertEqual(bytes_[-1], 0x5C6AD1D9)

    def test_retirement_window_excludes_startup_and_completion(self):
        trace = "R 1 0 19 4 0 0 0 0 0 0\nR 5 4 19 8 0 0 0 0 0 0\nR 9 8 19 12 0 0 0 0 0 0\nR 12 12 19 16 0 0 0 0 0 0\n"
        self.assertEqual(measure_window(trace, 4, 12), {"startCycle": 5, "endCycle": 12, "cycles": 7, "retiredInstructions": 2})
        with self.assertRaisesRegex(AssertionError, "missing or repeated"):
            measure_window(trace + "R 20 4 19 8 0 0 0 0 0 0\n", 4, 12)

    def test_memory_delay_is_measured(self):
        trace = "Q 2 I 0 0 0 0 2\nS 3 I 19 0\nQ 3 D 256 0 0 0 2\nS 4 D 0 0\n"
        self.assertEqual(fixed_memory_timing(trace), {"I": 1, "D": 1})
        with self.assertRaisesRegex(AssertionError, "not one cycle"):
            fixed_memory_timing(trace.replace("S 4 D", "S 5 D"))

    def test_profiles_reject_other_configuration_changes(self):
        base = {"parameters": {"resetVector": 0, "enableM": True, "enableC": True, "protectedMode": False,
                               "enableZba": False, "enableZbb": False, "enableZbs": False}, "sourceHashes": {"core": "fixed"}}
        changed = {**base, "parameters": {**base["parameters"], "enableZba": True, "enableM": False}}
        with self.assertRaisesRegex(AssertionError, "outside the bit options"):
            validate_profiles({0: base, 1: changed})


if __name__ == "__main__":
    unittest.main()
