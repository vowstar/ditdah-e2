# SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
# SPDX-License-Identifier: MIT
"""Bind the implemented cold-reset profile without constraining inactive payloads."""

import argparse
import re
import unittest

from formal.trigger.run import (
    CORE_INITIAL_STATE,
    CORE_TOP,
    CORE_WRAPPER,
    HERE,
    UNIT_TOP,
    case_definition,
    check_core_reset_collectors,
    prepare,
)


class ColdResetTests(unittest.TestCase):
    @staticmethod
    def collectors():
        return {role: (HERE / filename).read_bytes() for role, filename in (
            ("legacy", "collect.tcl"), ("safety", "collect_safety.tcl"),
            ("multiply_safety", "collect_multiply_safety.tcl"), ("trace", "collect_trace.tcl"),
            ("multiply_retry", "collect_multiply_retry.tcl"),
            ("safety_retry", "collect_safety_retry.tcl"),
            ("negative_older", "collect_negative_older.tcl"))}

    def test_core_collectors_share_the_audited_reset_expression(self):
        collectors = self.collectors()
        check_core_reset_collectors(collectors)
        for role in ("safety", "multiply_safety", "multiply_retry", "trace", "negative_older"):
            expression = re.search(r"assume -reset \{([^\n]+)\}", collectors[role].decode()).group(1)
            for name in ("dut.registers", *(f"dut.registers_{index}" for index in range(30))):
                self.assertIn(name + " == 0", expression)
            for name in ("dut.debug.program0", "dut.debug.program1", "dut.dm.executionProgram0",
                         "dut.dm.executionProgram1", "dut.m_injected"):
                self.assertNotIn(name + " ==", expression)
            self.assertIn("dut.dm.commandValid == 0", expression)
            self.assertIn("dut.dm.auto == 0", expression)
            for name in ("dut.xInjected", "dut.xSequence", "dut.xTruncated", "dut.debug.ebreakUser",
                         "dut.debug.injecting", "dut.debug.cancelInjection", "dut.debug.pendingIssue",
                         "dut.debug.slot", "dut.dm.program0", "dut.dm.program1"):
                self.assertIn(name + " == 0", expression)
        self.assertEqual(CORE_INITIAL_STATE["profile"], "source-cold-reset122")
        self.assertEqual(CORE_INITIAL_STATE["resetFacts"], 122)
        self.assertEqual(CORE_INITIAL_STATE["resetGprs"], 31)
        self.assertEqual(CORE_INITIAL_STATE["addedResetFacts"], 52)

    def test_missing_register_or_unreset_payload_changes_are_rejected(self):
        for mutation in (" && dut.registers_0 == 0", " && dut.dm.commandValid == 0", " && dut.xInjected == 0"):
            collectors = self.collectors()
            self.assertIn(mutation.encode(), collectors["safety"])
            collectors["safety"] = collectors["safety"].replace(mutation.encode(), b"", 1)
            with self.assertRaisesRegex(ValueError, "cold-reset contract differs"):
                check_core_reset_collectors(collectors)

    def test_profile_is_bound_only_to_core_cases(self):
        wrappers = {UNIT_TOP: b"unit", CORE_TOP: b"core"}
        for name in ("unit-safety", "unit-covers", "core-store-safety", "core-dpc-safety", "core-older-covers"):
            with self.subTest(case=name):
                plan, _ = case_definition(name, {"unit.sv": b"u"}, {"core.sv": b"c"}, wrappers,
                                          self.collectors(), 120, 600)
                if plan["top"] == CORE_TOP:
                    self.assertEqual(plan["initialState"], CORE_INITIAL_STATE)
                else:
                    self.assertNotIn("initialState", plan)

    def test_unbound_external_seed_cannot_enter_a_cold_reset_bundle(self):
        for field in ("proof_seed", "proof_seed_scenario2", "proof_seed_scenario3"):
            with self.subTest(field=field):
                args = argparse.Namespace(**{field: "external checkpoint"})
                with self.assertRaisesRegex(ValueError, "external seeds are unsupported"):
                    prepare(args)

    def test_unsupported_payload_is_rejected_in_each_core_collector(self):
        collectors = self.collectors()
        for role in ("safety", "multiply_safety", "multiply_retry", "trace", "negative_older"):
            changed = dict(collectors)
            changed[role] = collectors[role].replace(b"systemReset == 0", b"systemReset == 0 && dut.m_injected == 0")
            with self.subTest(role=role), self.assertRaisesRegex(ValueError, "cold-reset contract differs"):
                check_core_reset_collectors(changed)

    def test_basis_with_a_different_debug_module_is_rejected(self):
        module = "DitDahE2DebugModule.sv"
        prefix = "base.target_first_event_is_breakpoint.0."
        sources = [module, CORE_WRAPPER]
        info = {"label": "target_first_event_is_breakpoint", "index": 0, "sources": sources,
                "firstTraceAttempt": 1, "nextTraceAttempt": 136,
                "inputMap": {name: prefix + name for name in sources}}
        contents = {prefix + module: b"earlier module", prefix + CORE_WRAPPER: b"core"}
        with self.assertRaisesRegex(ValueError, "design input differs.*DebugModule"):
            case_definition("core-multiply-safety", {"unit.sv": b"u"}, {module: b"current module"},
                            {UNIT_TOP: b"unit", CORE_TOP: b"core"}, self.collectors(), 120, 600,
                            property_bases={"target_first_event_is_breakpoint": [(info, contents)]})


if __name__ == "__main__":
    unittest.main()
