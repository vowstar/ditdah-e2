# SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
# SPDX-License-Identifier: MIT
"""Check abstract formal property inventories and negative-control binding."""

import unittest

from formal.debug_abstract import run
from test.test_debug.debug_module import auto_mutant, busy_mutant


class DebugAbstractFormalTests(unittest.TestCase):
    def test_wrapper_inventory_and_binding(self):
        wrapper = (run.HERE / run.WRAPPER_NAME).read_bytes()
        run.check_wrapper(wrapper)
        self.assertEqual(len(run.ASSERTIONS), 22)
        self.assertEqual(len(run.COVERS), 8)
        self.assertIn("_GEN_151", run.OBSERVATIONS)
        text = wrapper.decode()
        self.assertIn("input clock, input reset", text)
        self.assertNotIn("reg reset", text)
        self.assertIn("initial_common_cold_reset: assume(reset)", text)
        self.assertIn("no_later_cold_reset: assume(!reset)", text)
        self.assertIn("wire check = past_valid && !reset && !past_reset;", text)
        self.assertNotIn("if (past_valid && !$past(reset))", text)
        self.assertNotIn(run.INITIAL_ASSUMPTION, run.ASSUMPTIONS)
        with self.assertRaisesRegex(ValueError, "inventory"):
            run.check_wrapper(wrapper + b"\nextra: assert(1'b1);\n")
        with self.assertRaisesRegex(ValueError, "binding"):
            run.check_wrapper(wrapper.replace(b"DitDahE2DebugModule dut (.*);", b"other dut (.*);"))

    def test_mutations_match_simulation_controls(self):
        sources = {
            "stale-operands": "if (autoStart_1) begin\n      operands_address <= data1;\n      operands_data <= data0;",
            "early-increment": "else if (commandComplete & command_memory & command_postIncrement & postincrement)",
            "backpressure-repeat": "wire        autoStart = accepted & read | write;",
        }
        for name, source in sources.items():
            with self.subTest(name=name):
                self.assertEqual(run.mutate(source.encode(), name), auto_mutant(source, name).encode())
                with self.assertRaises(ValueError):
                    run.mutate(b"", name)
        busy = "error <= 3'h1;"
        self.assertEqual(run.mutate(busy.encode(), "busy-priority"), busy_mutant(busy).encode())
        with self.assertRaises(ValueError):
            run.mutate(b"", "busy-priority")

    def test_cases_bind_one_negative_target(self):
        source = (b"if (autoStart_1) begin\n      operands_address <= data1;\n      operands_data <= data0;\n"
                  b"else if (commandComplete & command_memory & command_postIncrement & postincrement)\n"
                  b"wire        autoStart = accepted & read | write;\nerror <= 3'h1;\n")
        rtl = {run.RTL_NAME: source}
        wrapper = (run.HERE / run.WRAPPER_NAME).read_bytes()
        collector = (run.HERE / run.COLLECTOR_NAME).read_bytes()
        for name in run.CASES:
            with self.subTest(name=name):
                plan, contents = run.case_definition(name, rtl, wrapper, collector, 120)
                self.assertEqual(plan["timeLimitSeconds"], 120)
                self.assertEqual(set(plan["inputs"]), set(contents))
                self.assertNotIn(run.TOP + "." + run.INITIAL_ASSUMPTION, plan["assumptions"])
                if name.startswith("negative-"):
                    self.assertEqual(plan["goals"], [run.MUTATIONS[name.removeprefix("negative-")]])
                    self.assertEqual(plan["expected"], "cex")
                elif name == "safety":
                    self.assertEqual(plan["goals"], list(run.ASSERTIONS))
                    self.assertEqual(plan["expected"], "proven")
                else:
                    self.assertEqual(plan["covers"], list(run.COVERS))


if __name__ == "__main__":
    unittest.main()
