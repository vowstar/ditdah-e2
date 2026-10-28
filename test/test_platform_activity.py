# SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
# SPDX-License-Identifier: MIT
"""Reject incomplete or incorrectly timed activity files."""

from pathlib import Path
import tempfile
import unittest

from platform_activity import core_hierarchy, inspect_vcd, instrument


HEADER = """$timescale 1ps $end
$scope module TOP $end
$scope module PlatformBench $end
$scope module dut $end
$scope module platform $end
$scope module core $end
$var wire 1 ! clock $end
$var wire 1 \" reset $end
$var wire 1 # state $end
$upscope $end
$upscope $end
$upscope $end
$upscope $end
$upscope $end
$enddefinitions $end
"""
BODY = """#0
0!
1\"
0#
#750
1!
#1500
0!
#2250
1!
#3000
0!
0\"
#3750
1!
1#
#4500
0!
"""
HIERARCHY = {"": {"module": "DitDahE2", "registers": {"state": 1}}}


class ActivityTests(unittest.TestCase):
    def check(self, content, hierarchy=HIERARCHY, period=1500):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "activity.vcd"
            path.write_text(content)
            return inspect_vcd(path, 1, period, hierarchy)

    def test_reset_and_complete_cycle_window(self):
        record = self.check(HEADER + BODY)
        self.assertEqual(record["samples"], 7)
        self.assertEqual(record["workloadWindowPs"], [3000, 4500])
        self.assertEqual(record["coreStripPath"], "TOP/PlatformBench/dut/platform/core")
        self.assertEqual(record["coreRegisters"], 1)

    def test_truncated_waveform(self):
        with self.assertRaisesRegex(AssertionError, "sample range"):
            self.check(HEADER + BODY.rsplit("#4500", 1)[0])

    def test_wrong_clock_phase(self):
        with self.assertRaisesRegex(AssertionError, "clock differs"):
            self.check(HEADER + BODY.replace("#3750\n1!", "#3750\n0!"))

    def test_wrong_reset_release(self):
        with self.assertRaisesRegex(AssertionError, "reset differs"):
            self.check(HEADER + BODY.replace('#3000\n0!\n0"', '#3000\n0!').replace('#1500\n0!', '#1500\n0!\n0"'))

    def test_missing_module(self):
        hierarchy = HIERARCHY | {"/fetch": {"module": "DitDahE2Fetch", "registers": {}}}
        with self.assertRaisesRegex(AssertionError, "module scope"):
            self.check(HEADER + BODY, hierarchy)

    def test_missing_register(self):
        with self.assertRaisesRegex(AssertionError, "Missing Core register"):
            self.check(HEADER.replace('$var wire 1 # state $end\n', '') + BODY)

    def test_unknown_state(self):
        with self.assertRaisesRegex(AssertionError, "Unknown Core value"):
            self.check(HEADER + BODY.replace('1#', 'x#'))

    def test_wrong_timescale(self):
        with self.assertRaisesRegex(AssertionError, "one ps"):
            self.check(HEADER.replace('1ps', '1ns') + BODY)

    def test_invalid_period(self):
        for value in (0, -2, 1501):
            with self.subTest(period=value), self.assertRaisesRegex(AssertionError, "Invalid clock period"):
                self.check(HEADER + BODY, period=value)

    def test_hierarchy_reads_real_register_widths(self):
        with tempfile.TemporaryDirectory() as directory:
            rtl = Path(directory)
            (rtl / "DitDahE2.sv").write_text("reg [31:0] pc;\n  DitDahE2Fetch fetch (\n")
            (rtl / "DitDahE2Fetch.sv").write_text("reg pending;\n")
            result = core_hierarchy(rtl)
            self.assertEqual(result[""]["registers"], {"pc": 32})
            self.assertEqual(result["/fetch"]["registers"], {"pending": 1})

    def test_instrumentation_requires_expected_harness(self):
        with self.assertRaisesRegex(AssertionError, "evaluation sites changed"):
            instrument("int main() {}")


if __name__ == "__main__":
    unittest.main()
