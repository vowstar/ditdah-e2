# SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
# SPDX-License-Identifier: MIT
"""Bind staged scheduling, original bounds, native resources and unchanged cases."""

import argparse
import copy
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from formal.trigger import run, staged

from test.test_trigger.test_late_retry import HARNESS

PROVE = r'''

proc get_prove_invariants_import {} {return $::import_mode}
proc set_prove_invariants_import {value} {if {$value ne "on"} {error "wrong import setting"}; set ::import_mode on}
proc get_prove_orchestration {} {return auto}
proc prove {args} {
    incr ::proof_calls
    set tag [uplevel 1 {set tag}]
    set index [string range $tag 5 end]
    lassign [lindex $::query_schedule $index] declared kind fixed limit guard engines jobs
    if {$declared ne $tag || $::import_mode ne "on" || $::proof_calls != $::executed_queries} {error "query schedule/import mismatch"}
    foreach label $::all_assertions {
        if {![info exists ::states($label)]} {set ::states($label) unknown;set ::lengths($label) 1}
        if {$::states($label) in {bounded_proven bounded_proven_user}} {error "bounded state entered a proof"}
        if {$::states($label) eq "proven" && $::lengths($label) ne "infinite"} {error "finite fact entered with_proven"}
    }
    set selected $fixed
    if {$kind eq "remaining"} {
        set selected {}
        foreach label $::original_goals {
            set accepted [expr {$::states($label) eq "proven" && $::lengths($label) eq "infinite"}]
            set bound $::original_bounds($label)
            if {$bound>0 && $::states($label) eq "undetermined" && [string is integer -strict $::lengths($label)] && $::lengths($label)>=$bound} {set accepted 1}
            if {!$accepted} {lappend selected $label}
        }
        if {![llength $selected]} {error "empty query was not skipped"}
    }
    set prefix [expr {$::typed ? "<embedded>::" : ""}]
    set items {}
    foreach label $selected {lappend items "$prefix$::top.$label"}
    set expected [list -property $items -with_proven -engine_mode $engines]
    set cap 1
    if {$kind eq "remaining"} {
        foreach label $selected {if {$::original_bounds($label)>$cap} {set cap $::original_bounds($label)}}
        lappend expected -iter $cap -first_trace_attempt 1
    }
    lappend expected -time_limit $limit -per_property_time_limit $guard -per_engine_max_jobs $jobs
    if {$args ne $expected} {error "actual prove arguments differ"}
    foreach label $selected {
        set ::states($label) proven;set ::lengths($label) infinite
        set ::winners($label) [expr {$engines eq "B" ? "B" : ($label in {rom_local_fetch_rom_consistent core_geom_rom_packet_consistent core_data_owner_control_consistent} && $kind eq "helpers" ? "Hp" : "C")}]
        if {$kind eq "remaining"} {set ::states($label) undetermined;set ::lengths($label) $cap}
    }
    if {$kind eq "hint" && $::mode eq "hints_unknown"} {
        foreach label $selected {
            if {$::original_bounds($label)>0} {set ::states($label) unknown;set ::lengths($label) 1}
        }
    }
    if {$kind eq "dpc" && $::mode in {dpc_short dpc_finite dpc_unknown}} {
        foreach label $selected {
            set ::states($label) [expr {$::mode eq "dpc_unknown" ? "unknown" : "undetermined"}]
            set ::lengths($label) [expr {$::mode eq "dpc_short" ? 69 : ($::mode eq "dpc_finite" ? 128 : 999)}]
        }
    }
    if {$kind eq "helpers" && $::mode in {aux_unknown all_finite}} {
        foreach label $selected {set ::states($label) unknown;set ::lengths($label) 1}
    }
    if {$kind eq "helpers" && $::mode eq "skip_remaining"} {
        foreach label $::original_goals {set ::states($label) proven;set ::lengths($label) infinite;set ::winners($label) PRE}
    }
    if {$kind eq "helpers" && $::mode in {target_only initial_only}} {
        foreach label $::original_goals {
            if {($::mode eq "target_only" && $label ne "target_first_event_is_breakpoint") || ($::mode eq "initial_only" && $label ne "initial_dpc_zero")} {
                set ::states($label) proven;set ::lengths($label) infinite;set ::winners($label) PRE
            } else {set ::states($label) unknown;set ::lengths($label) 1}
        }
    }
    if {$::mode eq "all_finite"} {
        foreach label $selected {
            if {$label in $::original_goals && $::original_bounds($label)>0} {set ::states($label) undetermined;set ::lengths($label) $::original_bounds($label)}
        }
    }
    if {$kind eq "remaining" && $::mode eq "short"} {set ::states(older_fault_cause) undetermined;set ::lengths(older_fault_cause) 287}
    if {$kind eq "remaining" && $::mode eq "mixed_prefixes"} {
        set ::lengths(target_first_event_is_breakpoint) 129
        foreach label {older_fault_cause older_fault_blocks_target older_fault_blocks_store} {set ::lengths($label) 287}
    }
    if {$::mode eq "boundzero"} {set ::states(initial_dpc_zero) undetermined;set ::lengths(initial_dpc_zero) 999}
    if {$::mode eq "unknown_above"} {set ::states(native_epc_metadata) unknown;set ::lengths(native_epc_metadata) 999}
    if {$::mode eq "finite_fact" && $index==2} {set ::states(native_epc_metadata) proven;set ::lengths(native_epc_metadata) 999}
    if {$::mode eq "tool$index"} {error "actual declared query failed"}
    if {$::mode eq "cex$index"} {set ::states([lindex $selected 0]) cex}
}
proc assert {args} {
    if {!$::proof_queries_finished} {error "finite conversion before all query decisions ended"}
    set label [lindex [split [lindex $args 2] .] end]
    set ::states($label) bounded_proven_user
    set ::converted($label) [lindex $args 1]
}
'''


WITNESS_API = r'''
proc visualize {args} {
    if {[lindex $args 0] eq "-violation"} {set ::witness_property [lindex $args 2]; return}
    if {[lindex $args 0] ne "-save" || [lindex $args 1] ne "-vcd" || [llength $args] != 3} {error "unexpected witness command"}
    set destination [lindex $args 2]
    set handle [open $destination {WRONLY CREAT EXCL}]
    puts $handle $::witness_property
    close $handle
    set log [open witness_exports.log a]
    puts $log [list $destination $::witness_property]
    close $log
}
'''


def collectors():
    return {role: (run.HERE / name).read_bytes() for role, name in (
        ("legacy", "collect.tcl"), ("safety", "collect_safety.tcl"),
        ("multiply_safety", "collect_multiply_safety.tcl"), ("trace", "collect_trace.tcl"),
        ("multiply_retry", "collect_multiply_retry.tcl"), ("safety_retry", "collect_safety_retry.tcl"),
        ("negative_older", "collect_negative_older.tcl"), ("staged", "collect_staged.tcl"),
        ("staged_helpers", "staged_helpers.sv"))}


def rtl():
    unit = {run.UNIT_RTL: b"assign core_nativeAction = core_ready & core_matched_0 & ~core_debugAction_0;\nhit <= core_ready & _GEN_1 | (_GEN_2 ? writeData[20] : hit);\n"}
    core = {name: b"module empty; endmodule\n" for name in (
        "DitDahE2.sv", "DitDahE2Counters.sv", "DitDahE2Csr.sv", "DitDahE2DebugHart.sv",
        "DitDahE2DebugModule.sv", "DitDahE2Fetch.sv", "DitDahE2MultiplyDivide.sv", "DitDahE2Trigger.sv")}
    core[run.CORE_RTL] = (b"module DitDahE2(input clock);\nm_trap <= fault;\n"
        b"& ~eligibleInterrupt & ~sleeping_0 & ~x_fault & ~_debug_core_stop\n    & ~_csr_trigger_matched;\n"
        b"_GEN_466 = redirect_0 | returning | waiting | waking | synchronized;\nendmodule\n")
    return unit, core


def definition(name="core-older-safety", flow="staged"):
    return run.case_definition(name, *rtl(),
        {run.UNIT_TOP: (run.HERE / run.UNIT_WRAPPER).read_bytes(), run.CORE_TOP: (run.HERE / run.CORE_WRAPPER).read_bytes()},
        collectors(), 120, 600, flow=flow)


class StagedTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.harness = HARNESS[:HARNESS.index("proc prove")] + PROVE + HARNESS[HARNESS.index("proc save"):]
        cls.harness = cls.harness.replace('foreach label $::goals {lappend result "$::top.$label"}',
            'set prefix [expr {$::typed ? "<embedded>::" : ""}]\n    foreach label $::goals {lappend result "$prefix$::top.$label"}')
        cls.harness = cls.harness.replace('return [list name $item type assert',
            'set canonical $item\n    if {[string first {<embedded>::} $item]==0} {set canonical [string range $item 12 end]}\n    set e ?\n    if {[info exists ::winners($label)]} {set e $::winners($label)}\n    if {$::mode in {bad_engine invalid_engine} && $::proof_calls>=3 && $label eq "native_epc_metadata"} {set e [expr {$::mode eq "bad_engine" ? "?" : "UNKNOWN_ENGINE"}]}\n    return [list name $canonical type assert')
        cls.harness = cls.harness.replace('engine N min_length', 'engine $e min_length')
        cls.harness = cls.harness.replace('min_length $length target_bound $bound]',
            'min_length $length max_length infinite target_bound $bound trace_length 0 latest_trace_engine ?]')
        cls.harness = cls.harness.replace("proc visualize {args} {}", WITNESS_API)

    def execute(self, root, mode="pass", typed=True, name="core-older-safety"):
        root.mkdir()
        plan, contents = definition(name)
        for filename, value in contents.items():
            (root / filename).write_bytes(value)
        (root / "harness.tcl").write_text(f"set expected_reset {{{run.EXPECTED_RESET}}}\nset mode {mode}\nset typed {int(typed)}\nset proof_calls 0\nset import_mode auto\n" + self.harness)
        process = subprocess.run(["tclsh", "harness.tcl"], cwd=root, capture_output=True, text=True, check=False)
        self.assertTrue((root / "native.tsv").exists(), process.stderr)
        return process, run.read_records(root / "native.tsv"), plan

    def test_five_safety_profiles_keep_original_scope_bounds_and_store_alias(self):
        for name in run.SAFETY_RETRY_CASES:
            plan, contents = definition(name)
            self.assertEqual(plan["goals"], list(run.CORE_ASSERTIONS))
            self.assertEqual(plan["targetBounds"], run.goal_bounds(plan["scenario"])[1])
            self.assertEqual(plan["querySchedule"], staged.query_schedule())
            self.assertEqual(len(plan["allAssertions"]), 31)
            self.assertEqual(len(plan["inputs"]), 11)
            self.assertEqual(plan["sources"], [*rtl()[1], run.CORE_WRAPPER])
            self.assertEqual(plan["initialState"]["resetFacts"], 113)
            self.assertEqual(plan["dutInitialState"], run.CORE_INITIAL_STATE)
            fragment = collectors()["staged_helpers"]
            self.assertEqual(contents[run.CORE_WRAPPER].replace(fragment + b"\n", b""), (run.HERE / run.CORE_WRAPPER).read_bytes())
        self.assertEqual(definition("core-store-safety"), definition("core-dpc-safety"))
        older, contents = definition()
        self.assertEqual(run.sha(contents["plan.tcl"]), "f1d4f83e2053122e98270e08d5581e703f86208ccb30923238fbc722a50ed3e2")
        self.assertEqual(run.sha(contents[run.CORE_WRAPPER]), "9b4e9b477cacd66e725f653de94b0d95c3a25f4e366e38adf6c5d73443f8fff0")
        self.assertEqual(older["allAssertions"], [*staged.ORIGINALS, *staged.HELPERS])

    def test_twelve_legacy_cases_remain_byte_exact(self):
        names = [name for name in run.CASES if name not in run.SAFETY_RETRY_CASES]
        self.assertEqual(len(names), 12)
        for name in names:
            with self.subTest(case=name):
                self.assertEqual(definition(name), definition(name, "retry"))

    def test_reviewed_source_configuration_and_collisions_are_rejected(self):
        plan, _ = definition()
        for field, value in (("helperGoals", ["fake"]), ("dutColdFacts", 122), ("coldFacts", 123), ("name", "injection")):
            changed = copy.deepcopy(plan)
            changed["stagedConfiguration"][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                staged.validate_protocol({}, changed)
        self.assertEqual(len(staged.configuration()["helperGoals"]), 10)
        with self.assertRaisesRegex(ValueError, "Unsupported staged source configuration"):
            staged.configuration("injection")
        for key in ("staged", "staged_helpers"):
            modified = collectors()
            modified[key] += b"\n"
            with self.subTest(source=key), self.assertRaisesRegex(ValueError, "reviewed source"):
                run.case_definition("core-older-safety", *rtl(), {run.CORE_TOP: (run.HERE / run.CORE_WRAPPER).read_bytes()}, modified, 120, 600, flow="staged")
        # Identity checking derives its limit from the selected configuration inventory.
        names = [f"top.goal_{index}" for index in range(32)]
        staged.canonical_ids(" ".join(names), names)

    @unittest.skipUnless(shutil.which("tclsh"), "tclsh is required")
    def test_real_tcl_all_nine_queries_all_scenarios_and_typed_ids(self):
        with tempfile.TemporaryDirectory() as directory:
            for name in run.SAFETY_RETRY_CASES:
                for typed in (True, False):
                    process, records, plan = self.execute(Path(directory) / (name + str(typed)), typed=typed, name=name)
                    self.assertEqual(process.returncode, 0, process.stderr)
                    checked = run.check_native_records(records, plan)
                    self.assertEqual((checked["goals"], checked["unboundedGoals"], checked["boundedGoals"], checked["unboundedHelperGoals"]), (21, 17, 4, 10))
                    self.assertEqual(records["query8", "iteration_cap"], "352" if plan["scenario"] == 1 else "288")
                    self.assertEqual(len({tag for tag, key in records if key == "native_id" and not tag.startswith("bounded.")}), 620)
                    self.assertEqual(checked["stagedEvidence"]["executedQueries"], 9)
                    for label in ("older_fault_cause", "target_first_event_is_breakpoint"):
                        self.assertEqual(checked["propertyEvidence"][label]["verdict"], "bounded_proven_user")
                        self.assertEqual(checked["propertyEvidence"][label]["targetBound"], plan["targetBounds"][label])

    @unittest.skipUnless(shutil.which("tclsh"), "tclsh is required")
    def test_unknown_auxiliary_prefixes_and_empty_remaining_do_not_add_barriers(self):
        with tempfile.TemporaryDirectory() as directory:
            for mode in ("dpc_short", "dpc_finite", "dpc_unknown", "hints_unknown", "aux_unknown", "skip_remaining", "target_only"):
                process, records, plan = self.execute(Path(directory) / mode, mode)
                self.assertEqual(process.returncode, 0, process.stderr)
                checked = run.check_native_records(records, plan)
                self.assertEqual(checked["goals"], 21)
                if mode == "skip_remaining":
                    self.assertEqual(records["query8", "executed"], "0")
                    self.assertEqual(records["query8", "allocated_seconds"], "0")
                    self.assertEqual(records["query8", "iteration_cap"], "1")
                if mode == "target_only":
                    self.assertEqual(records["query8", "iteration_cap"], "128")
                if mode == "aux_unknown":
                    self.assertEqual(checked["unboundedHelperGoals"], 0)

    @unittest.skipUnless(shutil.which("tclsh"), "tclsh is required")
    def test_each_original_bound_and_initial_infinity_remain_required(self):
        with tempfile.TemporaryDirectory() as directory:
            for mode in ("mixed_prefixes", "initial_only", "short", "boundzero", "unknown_above", "finite_fact", "bad_engine", "invalid_engine"):
                process, records, plan = self.execute(Path(directory) / mode, mode)
                self.assertEqual(process.returncode, 1, (mode, process.stderr))
                with self.assertRaises(ValueError):
                    run.check_native_records(records, plan)
                if mode == "mixed_prefixes":
                    result = staged.validate_protocol(records, plan)
                    self.assertTrue(result["originalProperties"]["target_first_event_is_breakpoint"]["qualified"])
                    self.assertEqual(len(result["unresolvedOriginals"]), 3)
                if mode == "initial_only":
                    self.assertEqual(records["query8", "iteration_cap"], "1")

    @unittest.skipUnless(shutil.which("tclsh"), "tclsh is required")
    def test_parser_rejects_arguments_facts_scope_full_metadata_and_engine_mutations(self):
        with tempfile.TemporaryDirectory() as directory:
            _, records, plan = self.execute(Path(directory) / "pass")
            run.check_native_records(records, plan)
            changes = [
                (("query8", "iteration_cap"), "128"), (("query8", "first_trace_attempt"), "2"),
                (("query8", "engines"), "Mp N Hp"), (("query7", "iteration_cap"), "288"),
                (("query8", "labels"), staged.HELPERS[0]), (("query9", "labels"), ""),
                (("query7", "fact_labels"), ""), (("query7", "fact_actual_properties"), ""),
                (("setup", "native_assertions"), ""), (("setup", "dut_cold_facts"), "122"),
                (("before", "clock"), "clock"), (("before", "global"), ""),
                (("query6.before.native_epc_metadata", "engine"), "N"),
                (("query6.before.native_epc_metadata", "max_length"), "999"),
                (("query6.before.native_epc_metadata", "trace_length"), "1"),
                (("query6.before.native_epc_metadata", "latest_trace_engine"), "C"),
                (("bounded.older_fault_cause", "engine"), "N"),
                (("bounded.older_fault_cause", "max_length"), "288"),
                (("bounded.older_fault_cause", "trace_length"), "1"),
                (("bounded.older_fault_cause", "latest_trace_engine"), "B"),
            ]
            for key, value in changes:
                altered = dict(records); altered[key] = value
                with self.subTest(key=key), self.assertRaises(ValueError):
                    run.check_native_records(altered, plan)
            for tag in ("before", "final", *(f"query{i}.{phase}" for i in range(9) for phase in ("before", "after"))):
                for key in ("engine", "min_length", "max_length", "trace_length", "latest_trace_engine"):
                    altered = dict(records); del altered[tag + ".native_epc_metadata", key]
                    with self.subTest(tag=tag, key=key), self.assertRaises(ValueError):
                        run.check_native_records(altered, plan)
            for key in ("engine", "min_length", "max_length", "trace_length", "latest_trace_engine"):
                altered = dict(records); del altered["bounded.older_fault_cause", key]
                with self.subTest(bounded=key), self.assertRaises(ValueError):
                    run.check_native_records(altered, plan)
            altered = dict(records)
            for tag in ("query8.after", "final", "bounded"):
                altered[tag + ".older_fault_cause", "engine"] = "N"
            with self.assertRaisesRegex(ValueError, "B prefix"):
                run.check_native_records(altered, plan)

    @unittest.skipUnless(shutil.which("tclsh"), "tclsh is required")
    def test_each_stage_counterexample_or_error_blocks_later_commands(self):
        with tempfile.TemporaryDirectory() as directory:
            for index in range(9):
                for prefix in ("tool", "cex"):
                    process, records, plan = self.execute(Path(directory) / f"{prefix}{index}", f"{prefix}{index}")
                    self.assertEqual(process.returncode, 1)
                    for later in range(index + 1, 9):
                        self.assertEqual(records.get((f"query{later}", "executed")), "0")
                    with self.assertRaises(ValueError):
                        run.check_native_records(records, plan)

    def test_collect_dispatch_and_new_resource_receipts_are_explicit(self):
        with tempfile.TemporaryDirectory() as directory:
            case = Path(directory)
            for flow in ("retry", "staged"):
                plan, _ = definition(flow=flow)
                run.write_json(case / "plan.json", plan)
                (case / "native.tsv").write_text("")
                with patch.object(run, "collect_case", return_value={}) as collect, patch.object(run, "check_native_records", return_value={"goals": 21}):
                    run.collect_trigger_case(case, "unused", case, 1800)
                if flow == "staged":
                    self.assertEqual(collect.call_args.args[-1], 960)
                    self.assertEqual(collect.call_args.kwargs, {"cpu_count": 16})
                else:
                    self.assertEqual(collect.call_args.args[-1], 1800)
                    self.assertEqual(collect.call_args.kwargs, {})
        valid = {"cpu": 0, "cpuCount": 16, "cpuAffinity": list(range(16)), "timeoutSeconds": 960, "pid": 1}
        staged.check_resources(valid)
        for mutation in ({"cpuCount": 1}, {"cpuCount": True}, {"cpuAffinity": [0]}, {"timeoutSeconds": 1800}, {"cpu": False}):
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                staged.check_resources({**valid, **mutation})
        with self.assertRaises(ValueError):
            staged.check_resources({"cpu": 0, "pid": 1, "timeoutSeconds": 960})

    def prepare_bundle(self, directory, flow="staged"):
        root = Path(directory)
        paths = []
        for top, contents in zip(("DitDahE2Trigger", "DitDahE2"), rtl(), strict=True):
            target = root / top; target.mkdir()
            for filename, value in contents.items():
                (target / filename).write_bytes(value)
            run.write_json(target / "manifest.json", {"top": top, "exitStatus": 0,
                "parameters": {"triggerCount": 2, "enableDebug": True, "enableM": True, "enableC": False, "protectedMode": False},
                "rtlHashes": {name: run.sha(value) for name, value in contents.items()}, "sourceHashes": {}})
            paths.append(target)
        output = root / "evidence"
        args = argparse.Namespace(unit_rtl=paths[0], core_rtl=paths[1], source_root=root, output=output,
            time_limit=120, core_time_limit=600, proof_seed=None, proof_seed_scenario2=None, proof_seed_scenario3=None,
            multiply_target_base=[], multiply_older_base=[], retry_case=[], flow=flow, staged_configuration="native")
        run.prepare(args)
        return output

    def test_preparation_freezes_three_files_and_reconstructs_all_native_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            evidence = self.prepare_bundle(directory)
            manifest = run.validate_frozen(evidence)
            self.assertEqual(len(manifest["caseInputHashes"]), 17)
            self.assertEqual(len(manifest["casePlanHashes"]), 17)
            for name in staged.FILES:
                self.assertEqual(manifest["verificationHashes"][name], run.digest(evidence / name))
            for name in (*staged.FILES, "cases/core-older-safety/plan.tcl", "cases/core-older-safety/plan.json"):
                path = evidence / name; original = path.read_bytes(); path.write_bytes(original + b" ")
                with self.subTest(file=name), self.assertRaises(ValueError):
                    run.validate_frozen(evidence)
                path.write_bytes(original)
            run.validate_frozen(evidence)

    def test_default_bundle_retains_its_imported_verifier_dependencies(self):
        with tempfile.TemporaryDirectory() as directory:
            evidence = self.prepare_bundle(directory, flow="retry")
            run.validate_frozen(evidence)
            for name in staged.FILES:
                self.assertTrue((evidence / name).is_file())
            process = subprocess.run(
                [sys.executable, "-B", "runner.py", "validate", "--evidence", str(evidence)],
                cwd=evidence, capture_output=True, text=True, check=False,
            )
            self.assertEqual(process.returncode, 1)
            self.assertIn("receipt.json", process.stderr)
            self.assertNotIn("ModuleNotFoundError", process.stderr)

    def test_actual_imported_transport_dependencies_are_bound(self):
        with tempfile.TemporaryDirectory() as directory:
            evidence = self.prepare_bundle(directory)
            active = Path(directory) / "active"
            shutil.copytree(run.ROOT / "formal", active / "formal", ignore=shutil.ignore_patterns("__pycache__"))
            command = [sys.executable, "-B", "-c",
                "from pathlib import Path; from formal.trigger import run; import sys; run.validate_frozen(Path(sys.argv[1]))",
                str(evidence)]
            baseline = subprocess.run(command, cwd=active, capture_output=True, text=True, check=False)
            self.assertEqual(baseline.returncode, 0, baseline.stderr)
            for name in run.TRANSPORT_FILES:
                path = active / name
                original = path.read_bytes()
                path.write_bytes(original + b"\n# Changed active dependency.\n")
                changed = subprocess.run(command, cwd=active, capture_output=True, text=True, check=False)
                with self.subTest(source=name):
                    self.assertEqual(changed.returncode, 1)
                    self.assertIn("Running transport verifier differs", changed.stderr)
                path.write_bytes(original)

    def test_summary_counts_originals_and_helpers_separately_and_requires_new_receipts(self):
        with tempfile.TemporaryDirectory() as directory:
            evidence = self.prepare_bundle(directory)
            for name in run.CASES:
                case = evidence / "cases" / name
                plan = json.loads((case / "plan.json").read_text())
                (case / "native.tsv").write_text("")
                for label in (plan["goals"] if plan["expected"] == "cex" else plan["covers"]):
                    (case / (label + ".vcd")).write_text("receipt fixture\n")
                receipt = {"command": ["jg", "-no_gui", "-fpv", "-tcl", "collect.tcl"],
                    "pid": 1, "cpu": 0, "launcherSha256": "0" * 64,
                    "inputHashes": {filename: run.digest(case / filename) for filename in plan["inputs"]}}
                if plan.get("proofStrategy") == staged.STRATEGY:
                    receipt.update(cpuCount=16, cpuAffinity=list(range(16)), timeoutSeconds=960)
                run.write_json(case / "receipt.json", receipt)
                run.write_json(case / "completion.json", {"exitStatus": 0, "timedOut": False,
                    "inputsUnchanged": True, "nativeExecutableSha256": "1" * 64, "outputHashes": run.output_hashes(case)})

            def result(_records, plan):
                fields = {"goals": len(plan["goals"]), "covers": len(plan["covers"]), "verdict": plan["expected"]}
                if plan.get("proofStrategy") == staged.STRATEGY:
                    fields.update(unboundedGoals=17, boundedGoals=4, unboundedHelperGoals=10)
                return fields

            with patch.object(run, "check_native_records", side_effect=result):
                summary = run.validate_commercial(evidence)
                self.assertEqual(summary["assertionsProven"], 128)
                self.assertEqual(summary["unboundedAssertions"], 108)
                self.assertEqual(summary["boundedAssertions"], 20)
                self.assertEqual(summary["helperAssertionsProven"], 50)
                self.assertFalse(summary["fullCoreProven"])
                path = evidence / "cases/core-older-safety/receipt.json"
                receipt = json.loads(path.read_text())
                del receipt["cpuCount"]
                del receipt["cpuAffinity"]
                run.write_json(path, receipt)
                with self.assertRaisesRegex(ValueError, "sixteen CPUs"):
                    run.validate_commercial(evidence)


if __name__ == "__main__":
    unittest.main()
