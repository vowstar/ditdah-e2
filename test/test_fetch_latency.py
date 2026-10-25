# SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
# SPDX-License-Identifier: MIT
"""Keep tool failures separate from semantic latency counterexamples."""

import unittest

from fetch_latency import accept


class LatencyTests(unittest.TestCase):
    def test_semantic_counterexample_requires_a_trace(self):
        accept("negative", "FAIL", 2, True, 0)
        for status, code, witness in (("ERROR", 16, False), ("FAIL", 2, False), ("PASS", 0, False)):
            with self.assertRaisesRegex(AssertionError, "Missing semantic"):
                accept("negative", status, code, witness, 0)

    def test_cover_and_bound_status(self):
        accept("bmc", "PASS", 0, False, 0)
        accept("cover", "PASS", 0, True, 3)
        with self.assertRaisesRegex(AssertionError, "Missing latency cover"):
            accept("cover", "PASS", 0, True, 2)
        with self.assertRaisesRegex(AssertionError, "did not pass"):
            accept("bmc", "UNKNOWN", 4, False, 0)


if __name__ == "__main__":
    unittest.main()
