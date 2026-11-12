# SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
# SPDX-License-Identifier: MIT
"""Exercise fact-first safety retries while keeping bounded results out of the lemma set."""

import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from formal.debug_transport.run import EXPECTED_RESET, read_records
from formal.trigger.run import (
    CORE_ASSERTIONS,
    CORE_TOP,
    HERE,
    OLDER_HARD_GOALS,
    SAFETY_LATE_RETRY,
    UNIT_TOP,
    case_definition,
    check_late_retry,
    check_native_records,
    fact_first_groups,
    goal_bounds,
)
from test.test_trigger.test_late_retry import HARNESS

PENDING = ("older_fault_cause", "older_fault_blocks_target", "older_fault_blocks_store",
           "abstract_dpc_value", "resume_pc_matches")
QUALIFIED = "target_first_event_is_breakpoint"
PROVE = r'''
proc prove {args} {
    foreach label [array names ::states] {
        if {$::states($label) eq "bounded_proven_user"} {error "bounded fact used during proof"}
    }
    foreach item [lindex $args 1] {
        set label [lindex [split $item .] end]
        if {$label eq "target_first_event_is_breakpoint"} {
            set ::states($label) undetermined
            set ::lengths($label) 129
        } elseif {$label in {older_fault_cause older_fault_blocks_target older_fault_blocks_store abstract_dpc_value resume_pc_matches}} {
            if {$::proof_round == 1} {
                set facts 0
                foreach name [array names ::states] {
                    if {$::states($name) eq "proven"} {incr facts}
                }
                if {$facts < 15} {error "hard property attempted before current easy facts"}
            }
            if {$::mode eq "tool_error" && $::proof_round == 1} {error "test tool failure"}
            if {$::mode eq "cex" && $label eq "older_fault_cause"} {
                set ::states($label) cex
            } elseif {$::proof_round == 1 || $::mode eq "incomplete"} {
                set ::states($label) undetermined
                set ::lengths($label) 100
            } else {
                set ::states($label) proven
                set ::lengths($label) infinite
            }
        } else {
            set ::states($label) proven
        }
    }
}
'''
GENERIC_HARNESS = HARNESS[:HARNESS.index("proc prove")] + PROVE + HARNESS[HARNESS.index("proc assert"):]


class SafetyRetryTests(unittest.TestCase):
    def test_fact_first_plan_keeps_every_original_goal_and_bound(self):
        groups = fact_first_groups(3, list(CORE_ASSERTIONS))
        labels = [label for group in groups for label in group["labels"]]
        self.assertCountEqual(labels, CORE_ASSERTIONS)
        self.assertEqual(len(labels), 21)
        self.assertTrue(all(label not in OLDER_HARD_GOALS for label in labels[:15]))
        for group in groups:
            for label in group["labels"]:
                self.assertEqual(group["bound"], goal_bounds(3)[1][label])
        self.assertEqual(sum(int(group["time_limit"]) for group in groups), 720)

    def execute(self, root, mode):
        root.mkdir()
        collector = (HERE / "collect_safety_retry.tcl").read_bytes()
        plan, contents = case_definition("core-older-safety", {"unit.sv": b"u"}, {"core.sv": b"c"},
                                         {UNIT_TOP: b"unit", CORE_TOP: b"core"},
                                         {"safety_retry": collector}, 120, 600)
        for name, value in contents.items():
            (root / name).write_bytes(value)
        (root / "harness.tcl").write_text(f"set expected_reset {{{EXPECTED_RESET}}}\nset mode {mode}\n" + GENERIC_HARNESS)
        process = subprocess.run(["tclsh", "harness.tcl"], cwd=root, capture_output=True, text=True, check=False)
        self.assertTrue((root / "native.tsv").exists(), process.stderr)
        return process, read_records(root / "native.tsv"), plan

    @unittest.skipUnless(shutil.which("tclsh"), "tclsh is required for collector control-flow checks")
    def test_five_actual_pending_goals_retry_without_using_the_qualified_bound(self):
        with tempfile.TemporaryDirectory() as directory:
            for mode in ("pass", "incomplete", "cex", "tool_error"):
                with self.subTest(mode=mode):
                    process, records, plan = self.execute(Path(directory) / mode, mode)
                    self.assertEqual(plan["goals"], list(CORE_ASSERTIONS))
                    self.assertEqual(plan["targetBounds"], goal_bounds(3)[1])
                    self.assertEqual(plan["lateRetry"], SAFETY_LATE_RETRY)
                    if mode == "pass":
                        self.assertEqual(process.returncode, 0, process.stderr)
                        checked = check_native_records(records, plan)
                        self.assertEqual(checked["boundedGoals"], 1)
                        self.assertEqual(checked["unboundedGoals"], 20)
                        self.assertEqual(checked["lateRetryEvidence"]["selectedLabels"], list(PENDING))
                        self.assertEqual(records["retry.candidate." + QUALIFIED, "validity_status"], "undetermined")
                        for facts in checked["lateRetryEvidence"]["unboundedFacts"].values():
                            self.assertNotIn(QUALIFIED, facts)
                    else:
                        self.assertEqual(process.returncode, 1)
                        self.assertEqual(records["run", "state"], "failed")
                        with self.assertRaises(ValueError):
                            check_native_records(records, plan)

    @unittest.skipUnless(shutil.which("tclsh"), "tclsh is required for collector control-flow checks")
    def test_parser_rejects_missing_selector_state_and_hidden_earlier_counterexample(self):
        with tempfile.TemporaryDirectory() as directory:
            _, records, plan = self.execute(Path(directory) / "pass", "pass")
            check_late_retry(records, plan)
            changed = {**records, ("attempt.1.after.older_fault_cause", "validity_status"): "cex"}
            with self.assertRaisesRegex(ValueError, "counterexample cannot be hidden"):
                check_late_retry(changed, plan)
            changed = {key: value for key, value in records.items() if key[0] != "retry.candidate." + QUALIFIED}
            with self.assertRaisesRegex(ValueError, "assertion identity differs"):
                check_late_retry(changed, plan)


if __name__ == "__main__":
    unittest.main()
