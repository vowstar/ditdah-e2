# SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
# SPDX-License-Identifier: MIT
"""Keep the multiply completion search budget separate from semantic bounds."""

import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from formal.trigger import run


class MultiplyCoverBudgetTests(unittest.TestCase):
    @staticmethod
    def collectors():
        return {role: (run.HERE / filename).read_bytes() for role, filename in (
            ("legacy", "collect.tcl"), ("safety", "collect_safety.tcl"),
            ("multiply_safety", "collect_multiply_safety.tcl"), ("trace", "collect_trace.tcl"),
            ("multiply_retry", "collect_multiply_retry.tcl"),
            ("safety_retry", "collect_safety_retry.tcl"),
            ("negative_older", "collect_negative_older.tcl"))}

    @staticmethod
    def definition(name, collectors=None):
        return run.case_definition(
            name, {"unit.sv": b"unit"}, {"core.sv": b"core"},
            {run.UNIT_TOP: b"unit wrapper", run.CORE_TOP: b"core wrapper"},
            collectors or MultiplyCoverBudgetTests.collectors(), 120, 600)

    def test_only_completion_query_receives_more_search_time(self):
        collectors = MultiplyCoverBudgetTests.collectors()
        original = collectors["trace"]
        plan, files = self.definition("core-multiply-covers", collectors)
        before = b"prove_stage cover_multiply_done $prefix $stage_bound $stage_time_limit"
        after = b"prove_stage cover_multiply_done $prefix $stage_bound 1200"
        self.assertEqual(files["collect.tcl"], original.replace(before, after, 1))
        self.assertEqual(plan["stageTimeLimitsSeconds"], {"cover_multiply_done": 1200})
        self.assertEqual(plan["stageTimeLimitSeconds"], 240)
        self.assertEqual(plan["stageBound"], 128)
        self.assertEqual(plan["traceBound"], 352)
        self.assertEqual(plan["covers"], ["cover_multiply_finish"])
        self.assertEqual(plan["goals"], [])
        self.assertEqual(plan["nativeTimeoutSeconds"], 5400)
        # Resume, ten ordinary stages, the completion stage and final cover.
        self.assertGreaterEqual(plan["nativeTimeoutSeconds"], 2 * 600 + 10 * 240 + 1200 + 600)
        self.assertEqual(collectors["trace"], original)

    def test_other_cases_keep_original_collector_and_watchdog(self):
        collectors = MultiplyCoverBudgetTests.collectors()
        for name in run.CASES:
            if name == "core-multiply-covers" or name in run.NEGATIVE_TARGETS:
                continue
            with self.subTest(name=name):
                plan, files = self.definition(name, collectors)
                self.assertNotIn("stageTimeLimitsSeconds", plan)
                self.assertNotIn("nativeTimeoutSeconds", plan)
                if name.endswith("covers") and name.startswith("core-"):
                    self.assertEqual(files["collect.tcl"], collectors["trace"])

    def test_missing_or_ambiguous_completion_query_is_rejected(self):
        collectors = MultiplyCoverBudgetTests.collectors()
        anchor = b"set prefix [prove_stage cover_multiply_done $prefix $stage_bound $stage_time_limit]"
        for changed in (collectors["trace"].replace(anchor, b""), collectors["trace"] + anchor):
            with self.subTest(changed=changed[-80:]):
                with self.assertRaisesRegex(ValueError, "Missing or ambiguous multiply completion stage"):
                    self.definition("core-multiply-covers", {**collectors, "trace": changed})

    def test_collection_uses_declared_watchdog_without_changing_other_cases(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name, expected in (("core-multiply-covers", 5400), ("core-store-covers", 1800)):
                case = root / name
                case.mkdir()
                plan, _ = self.definition(name)
                (case / "plan.json").write_text(json.dumps(plan))
                with patch.object(run, "collect_case", return_value={}) as collect, \
                        patch.object(run, "read_records", return_value={}), \
                        patch.object(run, "check_native_records", return_value={"verdict": "proven"}):
                    result = run.collect_trigger_case(case, "jg", root / "private", 1800)
                self.assertEqual(collect.call_args.args[3], expected)
                self.assertEqual(result, {"verdict": "proven"})


if __name__ == "__main__":
    unittest.main()
