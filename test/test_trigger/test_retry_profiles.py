# SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
# SPDX-License-Identifier: MIT
"""Keep all-scenario retry scheduling and the store/DPC alias exactly bound."""

import unittest

from formal.trigger.run import (
    CORE_ASSERTIONS,
    CORE_TOP,
    EARLY_PROOF_GOALS,
    HERE,
    SAFETY_LATE_RETRY,
    SAFETY_RETRY_CASES,
    UNIT_TOP,
    case_definition,
    fact_first_groups,
    goal_bounds,
    late_retry_groups,
)


class RetryProfileTests(unittest.TestCase):
    @staticmethod
    def collectors():
        return {role: (HERE / filename).read_bytes() for role, filename in (
            ("safety_retry", "collect_safety_retry.tcl"), ("safety", "collect_safety.tcl"),
            ("multiply_retry", "collect_multiply_retry.tcl"))}

    def definition(self, name):
        return case_definition(name, {"unit.sv": b"unit"}, {"core.sv": b"core"},
                               {UNIT_TOP: b"unit", CORE_TOP: b"wrapper"}, self.collectors(), 120, 600)

    def test_every_safety_case_uses_the_complete_dynamic_selector_by_default(self):
        self.assertEqual(len(SAFETY_RETRY_CASES), 5)
        for name in SAFETY_RETRY_CASES:
            with self.subTest(case=name):
                plan, _ = self.definition(name)
                self.assertEqual(plan["lateRetry"], SAFETY_LATE_RETRY)
                self.assertEqual(plan["goals"], list(CORE_ASSERTIONS))
                self.assertEqual(plan["targetBounds"], goal_bounds(plan["scenario"])[1])

    def test_each_scenario_retains_every_bound_and_retry_starts_at_one(self):
        for scenario, count in enumerate((9, 8, 12, 15)):
            with self.subTest(scenario=scenario):
                groups = fact_first_groups(scenario, list(CORE_ASSERTIONS))
                labels = [label for group in groups for label in group["labels"]]
                self.assertEqual(len(labels), 21)
                self.assertEqual(len(set(labels)), 21)
                self.assertEqual(set(labels[:count]), set(EARLY_PROOF_GOALS[scenario]))
                for group in (*groups, *late_retry_groups(scenario, SAFETY_LATE_RETRY)):
                    self.assertEqual(group["first_trace_attempt"], 1)
                    for label in group["labels"]:
                        self.assertEqual(group["bound"], goal_bounds(scenario)[1][label])

    def test_store_and_dpc_alias_have_identical_plan_and_actual_inputs(self):
        store_plan, store_inputs = self.definition("core-store-safety")
        dpc_plan, dpc_inputs = self.definition("core-dpc-safety")
        self.assertEqual(store_plan, dpc_plan)
        self.assertEqual(store_inputs, dpc_inputs)


if __name__ == "__main__":
    unittest.main()
