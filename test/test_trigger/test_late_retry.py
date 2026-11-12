# SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
# SPDX-License-Identifier: MIT
"""Exercise late proof retries without hiding earlier tool failures or counterexamples."""

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
    MULTIPLY_LATE_RETRY,
    UNIT_TOP,
    case_definition,
    check_late_retry,
    check_native_records,
    goal_bounds,
    late_retry_groups,
)

HARNESS = r'''
rename clock native_clock
proc clock {args} {return {}}
proc reset {args} {
    if {[lindex $args 0] eq "-list"} {return $::expected_reset}
    return {}
}
proc assume {args} {
    if {$args eq {-reset -list -silent}} {return assume:0}
    if {$args eq {-list -silent -env}} {
        return "$::top.initial_common_cold_reset $::top.no_later_cold_reset"
    }
    return {}
}
proc analyze {args} {}
proc elaborate {args} {}
proc get_design_info {args} {return {}}
proc get_property_list {} {
    set result [list "$::top.initial_common_cold_reset" "$::top.no_later_cold_reset"]
    foreach label $::goals {lappend result "$::top.$label"}
    return $result
}
proc get_property_info {item} {
    set label [lindex [split $item .] end]
    if {$label in {initial_common_cold_reset no_later_cold_reset}} {
        return [list name $item type assume command assume disabled 0]
    }
    set verdict unknown
    if {[info exists ::states($label)]} {set verdict $::states($label)}
    set status [expr {$verdict eq "unknown" ? "unprocessed" : "processed"}]
    set length [expr {$verdict eq "proven" ? "infinite" : 100}]
    if {[info exists ::lengths($label)]} {set length $::lengths($label)}
    set bound 0
    if {[info exists ::converted($label)]} {set bound $::converted($label)}
    return [list name $item type assert command assert disabled 0 validity_status $verdict \
        run_status $status expression $label precondition 0 engine N min_length $length target_bound $bound]
}
proc prove {args} {
    foreach label [array names ::states] {
        if {$::states($label) eq "bounded_proven_user"} {error "bounded fact used during a proof"}
    }
    foreach item [lindex $args 1] {
        set label [lindex [split $item .] end]
        if {$label in {abstract_dpc_value target_first_event_is_breakpoint}} {
            if {$::mode eq "tool_error" && $::proof_round == 1} {error "test tool failure"}
            if {$::mode eq "cex" && $label eq "target_first_event_is_breakpoint"} {
                set ::states($label) cex
            } elseif {$::proof_round == 1 || $::mode eq "incomplete"} {
                set ::states($label) undetermined
                set ::lengths($label) 100
            } elseif {$::mode eq "bounded"} {
                set ::states($label) undetermined
                set ::lengths($label) $::bounds($label)
            } else {
                set ::states($label) proven
                set ::lengths($label) infinite
            }
        } else {
            set ::states($label) proven
        }
    }
}
proc assert {args} {
    set label [lindex [split [lindex $args 2] .] end]
    set ::states($label) bounded_proven_user
    set ::converted($label) [lindex $args 1]
}
proc save {args} {}
proc set_trace_optimization {args} {}
proc visualize {args} {}
source collect.tcl
'''


class LateRetryTests(unittest.TestCase):
    def test_retry_schedule_preserves_both_original_bounds(self):
        groups = late_retry_groups()
        self.assertEqual([group["labels"][0] for group in groups], MULTIPLY_LATE_RETRY["labels"])
        self.assertEqual([group["bound"] for group in groups], [128, 160])
        self.assertEqual([group["first_trace_attempt"] for group in groups], [1, 1])

    def execute(self, root, mode):
        root.mkdir()
        collector = (HERE / "collect_multiply_retry.tcl").read_bytes()
        plan, contents = case_definition("core-multiply-safety", {"unit.sv": b"unit"}, {"core.sv": b"rtl"},
                                         {UNIT_TOP: b"unit", CORE_TOP: b"core"},
                                         {"multiply_retry": collector}, 120, 600, retry_cases=())
        for name, value in contents.items():
            (root / name).write_bytes(value)
        (root / "harness.tcl").write_text(f"set expected_reset {{{EXPECTED_RESET}}}\nset mode {mode}\n" + HARNESS)
        process = subprocess.run(["tclsh", "harness.tcl"], cwd=root, capture_output=True, text=True, check=False)
        self.assertTrue((root / "native.tsv").exists(), process.stderr)
        return process, read_records(root / "native.tsv"), plan

    @unittest.skipUnless(shutil.which("tclsh"), "tclsh is required for collector control-flow checks")
    def test_first_round_incomplete_can_finish_without_duplicate_records(self):
        with tempfile.TemporaryDirectory() as directory:
            for mode in ("pass", "bounded", "incomplete", "cex", "tool_error"):
                with self.subTest(mode=mode):
                    process, records, plan = self.execute(Path(directory) / mode, mode)
                    self.assertEqual(plan["goals"], list(CORE_ASSERTIONS))
                    self.assertEqual(plan["targetBounds"], goal_bounds(1)[1])
                    self.assertEqual(records["after", "initial_common_cold_reset"], "1")
                    if mode in ("pass", "bounded"):
                        self.assertEqual(process.returncode, 0, process.stderr)
                        checked = check_native_records(records, plan)
                        self.assertEqual(checked["goals"], 21)
                        retry = checked["lateRetryEvidence"]
                        self.assertEqual(retry["selectedLabels"], MULTIPLY_LATE_RETRY["labels"])
                        self.assertEqual(len(retry["unboundedFacts"]["abstract_dpc_value"]), 19)
                        self.assertEqual(checked["boundedGoals"], 2 if mode == "bounded" else 0)
                        self.assertEqual(records["attempt.1.after.abstract_dpc_value", "validity_status"], "undetermined")
                    else:
                        self.assertEqual(process.returncode, 1)
                        self.assertEqual(records["run", "state"], "failed")
                        with self.assertRaises(ValueError):
                            check_native_records(records, plan)

    @unittest.skipUnless(shutil.which("tclsh"), "tclsh is required for collector control-flow checks")
    def test_retry_audit_rejects_changed_schedule_and_unproven_facts(self):
        with tempfile.TemporaryDirectory() as directory:
            _, records, plan = self.execute(Path(directory) / "pass", "pass")
            check_late_retry(records, plan)
            index = len(plan["proofGroups"]) + 1
            fact = records[f"group.{index}", "unbounded_facts"].split()[0]
            for key, value in (((f"group.{index}", "bound"), "127"),
                               ((f"lemma.{index}." + fact, "validity_status"), "bounded_proven_user"),
                               (("retry", "selected_labels"), "abstract_dpc_value")):
                with self.subTest(key=key):
                    changed = {**records, key: value}
                    with self.assertRaises(ValueError):
                        check_late_retry(changed, plan)


if __name__ == "__main__":
    unittest.main()
