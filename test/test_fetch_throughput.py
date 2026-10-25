# SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
# SPDX-License-Identifier: MIT
"""Reject missing retirements and real throughput gaps."""

import unittest

from fetch_throughput import bubble, window


class ThroughputTests(unittest.TestCase):
    def test_inclusive_window(self):
        addresses = list(range(0, 1280, 4))
        trace = "\n".join(f"R {index + 10} {address}" for index, address in enumerate(addresses))
        self.assertEqual(window(trace, addresses)["cycles"], 256)

    def test_gap_and_duplicate_retirement(self):
        addresses = list(range(0, 1280, 4))
        trace = "\n".join(f"R {index * 2} {address}" for index, address in enumerate(addresses))
        with self.assertRaisesRegex(AssertionError, "Retirement gap"):
            window(trace, addresses)
        self.assertEqual(window(trace, addresses, consecutive=False)["cycles"], 511)
        with self.assertRaisesRegex(AssertionError, "Missing or repeated"):
            window(trace + "\nR 640 128", addresses)

    def test_bubble_mutation(self):
        original = "wire offer = (~outstanding | response) & space;"
        self.assertEqual(bubble(original), "wire offer = (~outstanding) & space;")
        for text in ("", original + original):
            with self.assertRaisesRegex(AssertionError, "no longer matches"):
                bubble(text)


if __name__ == "__main__":
    unittest.main()
