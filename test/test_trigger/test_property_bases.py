# SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
# SPDX-License-Identifier: MIT
"""Reject incomplete or discontinuous bounded-proof compositions."""

import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from formal.debug_transport.run import EXPECTED_RESET, read_records, sha, write_json
from formal.trigger.run import (
    AUDITED_PROPERTY_BASES,
    CORE_ASSERTIONS,
    CORE_TOP,
    HERE,
    UNIT_TOP,
    case_definition,
    check_native_records,
    goal_bounds,
    load_property_base,
    safety_groups,
)

TARGET = "target_first_event_is_breakpoint"


class PropertyBaseTests(unittest.TestCase):
    def setUp(self):
        self.workspace = tempfile.TemporaryDirectory()
        self.addCleanup(self.workspace.cleanup)
        self.root = Path(self.workspace.name)

    def base(self, name="base", first=1, minimum=136, bound=160, complete=False):
        root = self.root / name
        root.mkdir()
        inputs = {"core.sv": b"rtl", "trigger_core_formal.sv": b"core",
                  "collect.tcl": f"prove -first_trace_attempt {first}\n".encode(), "plan.tcl": b"plan"}
        for filename, value in inputs.items():
            (root / filename).write_bytes(value)
        plan = {"top": CORE_TOP, "scenario": 1, "goals": [TARGET], "expected": "proven",
                "sources": ["core.sv", "trigger_core_formal.sv"], "inputs": list(inputs),
                "assumptions": [CORE_TOP + ".no_later_cold_reset"], "targetBounds": {TARGET: bound}}
        receipt = {"command": ["jg", "-no_gui", "-fpv", "-tcl", "collect.tcl"],
                   "inputHashes": {filename: sha(value) for filename, value in inputs.items()},
                   "pid": 1, "cpu": 0, "timeoutSeconds": 60, "launcherSha256": sha(b"tool")}
        scope = {"clock": "", "reset": EXPECTED_RESET, "reset_initial": "assume:0",
                 "initial_common_cold_reset": "1", "assumptions": CORE_TOP + ".no_later_cold_reset",
                 "global": CORE_TOP + ".initial_common_cold_reset " + CORE_TOP + ".no_later_cold_reset"}
        identity = {"name": CORE_TOP + "." + TARGET, "type": "assert", "command": "assert",
                    "expression": TARGET, "precondition": "0", "disabled": "0"}
        records = {("run", "state"): "complete" if complete else "failed",
                   ("setup", "clock_mode"): "free_running"}
        records.update({("setup", key): "0" for key in ("bbox_inst", "bbox_mod", "bbox_out", "stopat")})
        records.update({(tag, key): value for tag in ("before", "after") for key, value in scope.items()})
        records.update({(tag + "." + TARGET, key): value
                        for tag in ("before", "final") for key, value in identity.items()})
        records.update({("final." + TARGET, key): value for key, value in {
            "validity_status": "bounded_proven_user" if complete else "undetermined",
            "run_status": "processed", "min_length": str(minimum), "target_bound": str(bound),
            "engine": "K"}.items()})
        completion = {"exitStatus": 0 if complete else 1, "timedOut": False, "inputsUnchanged": True,
                      "nativeExecutableSha256": sha(b"tool")}
        self.save(root, plan, receipt, completion, records)
        self.authorize(root, first)
        return root, plan, receipt, completion, records

    def authorize(self, root, first=1):
        audit = {"label": TARGET, "firstTraceAttempt": first,
                 "planSha256": sha((root / "plan.json").read_bytes()),
                 "planTclSha256": sha((root / "plan.tcl").read_bytes())}
        self.enterContext(patch.dict(AUDITED_PROPERTY_BASES, {sha((root / "collect.tcl").read_bytes()): audit}))

    @staticmethod
    def save(root, plan, receipt, completion, records):
        native = "".join("\t".join(field.encode().hex() for field in (*key, value)) + "\n"
                         for key, value in records.items()).encode()
        (root / "native.tsv").write_bytes(native)
        completion["outputHashes"] = {"native.tsv": sha(native)}
        for filename, value in (("plan.json", plan), ("receipt.json", receipt), ("completion.json", completion)):
            write_json(root / filename, value)

    @staticmethod
    def definition(bases):
        wrappers = {UNIT_TOP: b"unit", CORE_TOP: b"core"}
        collectors = {role: b"" for role in ("legacy", "safety", "multiply_safety", "trace")}
        return case_definition("core-multiply-safety", {"unit.sv": b"unit"}, {"core.sv": b"rtl"},
                               wrappers, collectors, 120, 600, property_bases={TARGET: bases})

    def test_partial_base_preserves_final_obligations(self):
        root, *_ = self.base()
        loaded = load_property_base(root, TARGET, 0)
        plan, contents = self.definition([loaded])
        self.assertEqual(plan["goals"], list(CORE_ASSERTIONS))
        self.assertEqual(plan["targetBounds"][TARGET], 160)
        self.assertEqual(plan["targetBounds"]["older_load_retires_first"], 352)
        self.assertEqual(plan["propertyBases"][TARGET]["firstTraceAttempt"], 136)
        self.assertIn(b"set target_first_attempt 136", contents["plan.tcl"])
        self.assertEqual(loaded[0]["verdict"], "undetermined")

    def test_completed_bounded_base_is_accepted(self):
        root, *_ = self.base(minimum=161, complete=True)
        info, _ = load_property_base(root, TARGET, 0)
        self.assertEqual(info["nextTraceAttempt"], 160)

    def test_contiguous_multiple_segments_are_archived(self):
        first, *_ = self.base("first")
        second, *_ = self.base("second", first=136, minimum=150)
        plan, contents = self.definition([load_property_base(first, TARGET, 0),
                                          load_property_base(second, TARGET, 1)])
        self.assertEqual(plan["propertyBases"][TARGET]["firstTraceAttempt"], 150)
        self.assertIn("base." + TARGET + ".1.native.tsv", contents)

    def test_gap_and_duplicate_segment_index_are_rejected(self):
        for first_attempt, index in ((137, 1), (136, 0)):
            with self.subTest(first_attempt=first_attempt, index=index):
                first, *_ = self.base(f"first-{first_attempt}-{index}")
                second, *_ = self.base(f"second-{first_attempt}-{index}", first=first_attempt, minimum=150)
                with self.assertRaisesRegex(ValueError, "chain has a gap"):
                    self.definition([load_property_base(first, TARGET, 0),
                                     load_property_base(second, TARGET, index)])

    def test_changed_design_cannot_join_a_valid_chain(self):
        root, plan, receipt, completion, records = self.base()
        (root / "core.sv").write_bytes(b"different rtl")
        receipt["inputHashes"]["core.sv"] = sha(b"different rtl")
        self.save(root, plan, receipt, completion, records)
        with self.assertRaisesRegex(ValueError, "design input differs"):
            self.definition([load_property_base(root, TARGET, 0)])

    def test_native_scope_and_assertion_changes_are_rejected(self):
        mutations = [(("before", "clock"), "clock -period 10"),
                     (("after", "global"), CORE_TOP + ".extra"),
                     (("final." + TARGET, "precondition"), "1"),
                     (("before." + TARGET, "expression"), "different_property"),
                     (("final." + TARGET, "clock"), "other_clock"),
                     (("final." + TARGET, "disabled"), "1"),
                     (("final." + TARGET, "validity_status"), "cex"),
                     (("final." + TARGET, "run_status"), "unprocessed"),
                     (("final." + TARGET, "engine"), ""),
                     (("setup", "stopat"), "1")]
        for index, (key, value) in enumerate(mutations):
            with self.subTest(key=key):
                root, plan, receipt, completion, records = self.base(str(index))
                records[key] = value
                self.save(root, plan, receipt, completion, records)
                with self.assertRaises(ValueError):
                    load_property_base(root, TARGET, 0)

    def test_missing_after_scope_is_not_a_composition(self):
        root, plan, receipt, completion, records = self.base()
        records = {key: value for key, value in records.items() if key[0] != "after"}
        self.save(root, plan, receipt, completion, records)
        with patch.dict(AUDITED_PROPERTY_BASES, {}, clear=True), self.assertRaisesRegex(ValueError, "audit differs"):
            load_property_base(root, TARGET, 0)

    def test_audited_failed_base_retains_failure_and_scope_basis(self):
        root, plan, receipt, completion, records = self.base()
        records = {key: value for key, value in records.items() if key[0] != "after"}
        self.save(root, plan, receipt, completion, records)
        audit = {"label": TARGET, "firstTraceAttempt": 1,
                 "planSha256": sha((root / "plan.json").read_bytes()),
                 "planTclSha256": sha((root / "plan.tcl").read_bytes())}
        with patch.dict(AUDITED_PROPERTY_BASES, {sha((root / "collect.tcl").read_bytes()): audit}):
            info, _ = load_property_base(root, TARGET, 0)
        self.assertEqual(info["scopeBasis"], "frozen_collector_audit")
        self.assertEqual(info["verdict"], "undetermined")
        self.assertEqual(json.loads((root / "completion.json").read_text())["exitStatus"], 1)

    def test_audited_scope_rejects_collector_plan_and_seed_changes(self):
        for index, mutation in enumerate(("collector", "plan", "plan-tcl", "seed")):
            with self.subTest(mutation=mutation):
                root, plan, receipt, completion, records = self.base(str(index))
                records = {key: value for key, value in records.items() if key[0] != "after"}
                self.save(root, plan, receipt, completion, records)
                collector_hash = sha((root / "collect.tcl").read_bytes())
                audit = {"label": TARGET, "firstTraceAttempt": 1,
                         "planSha256": sha((root / "plan.json").read_bytes()),
                         "planTclSha256": sha((root / "plan.tcl").read_bytes())}
                if mutation == "collector":
                    (root / "collect.tcl").write_bytes(b"different collector")
                    receipt["inputHashes"]["collect.tcl"] = sha(b"different collector")
                elif mutation == "plan":
                    plan["targetBounds"][TARGET] = 159
                elif mutation == "plan-tcl":
                    (root / "plan.tcl").write_bytes(b"different plan")
                    receipt["inputHashes"]["plan.tcl"] = sha(b"different plan")
                else:
                    plan["proofSeed"] = {"file": "seed.jdb"}
                self.save(root, plan, receipt, completion, records)
                with (patch.dict(AUDITED_PROPERTY_BASES, {collector_hash: audit}),
                      self.assertRaisesRegex(ValueError, "audit differs")):
                    load_property_base(root, TARGET, 0)

    def test_proof_groups_preserve_every_original_bound(self):
        for scenario in range(4):
            groups = safety_groups(scenario, list(CORE_ASSERTIONS), 600)
            labels = [label for group in groups for label in group["labels"]]
            self.assertCountEqual(labels, CORE_ASSERTIONS)
            self.assertEqual(len(labels), len(set(labels)))
            expected = goal_bounds(scenario)[1]
            for group in groups:
                for label in group["labels"]:
                    self.assertEqual(group["bound"], expected[label])
            self.assertTrue(any(group["bound"] == goal_bounds(scenario)[0] for group in groups))

    def test_missing_or_tampered_execution_receipts_are_rejected(self):
        mutations = [("receipt", "launcherSha256", ""), ("receipt", "pid", 0),
                     ("receipt", "cpu", -1), ("receipt", "inputHashes", {}),
                     ("completion", "timedOut", True), ("completion", "inputsUnchanged", False),
                     ("completion", "exitStatus", 0), ("completion", "nativeExecutableSha256", "")]
        for index, (target, key, value) in enumerate(mutations):
            with self.subTest(target=target, key=key):
                root, plan, receipt, completion, records = self.base(str(index))
                (receipt if target == "receipt" else completion)[key] = value
                self.save(root, plan, receipt, completion, records)
                with self.assertRaises(ValueError):
                    load_property_base(root, TARGET, 0)

    def test_lower_bound_must_advance_from_declared_start(self):
        for index, (first, minimum) in enumerate(((136, 135), (136, 136), (0, 136))):
            with self.subTest(first=first, minimum=minimum):
                root, *_ = self.base(str(index), first=first, minimum=minimum)
                with self.assertRaisesRegex(ValueError, "attempt chain"):
                    load_property_base(root, TARGET, 0)

    def test_ambiguous_or_dynamic_first_attempt_is_rejected(self):
        for index, text in enumerate(("prove -first_trace_attempt $first\n",
                                      "prove -first_trace_attempt 1 -first_trace_attempt 136\n")):
            with self.subTest(text=text):
                root, plan, receipt, completion, records = self.base(str(index))
                value = text.encode()
                (root / "collect.tcl").write_bytes(value)
                receipt["inputHashes"]["collect.tcl"] = sha(value)
                self.save(root, plan, receipt, completion, records)
                self.authorize(root)
                with self.assertRaisesRegex(ValueError, "ambiguous first attempts"):
                    load_property_base(root, TARGET, 0)

    def test_compiled_sources_must_equal_the_final_source_list(self):
        for index, variant in enumerate(("missing", "extra", "duplicate")):
            with self.subTest(variant=variant):
                root, plan, receipt, completion, records = self.base(str(index))
                if variant == "missing":
                    plan["sources"].remove("core.sv")
                elif variant == "extra":
                    (root / "extra.sv").write_bytes(b"extra source")
                    plan["sources"].append("extra.sv")
                    plan["inputs"].append("extra.sv")
                    receipt["inputHashes"]["extra.sv"] = sha(b"extra source")
                else:
                    plan["sources"].append("core.sv")
                self.save(root, plan, receipt, completion, records)
                self.authorize(root)
                with self.assertRaisesRegex(ValueError, "(compiled source list|input inventory) differs"):
                    self.definition([load_property_base(root, TARGET, 0)])

    def test_matching_after_snapshot_does_not_authorize_unknown_collector(self):
        root, plan, receipt, completion, records = self.base()
        value = b"assume {1}; prove -first_trace_attempt 1; assume -clear\n"
        (root / "collect.tcl").write_bytes(value)
        receipt["inputHashes"]["collect.tcl"] = sha(value)
        self.save(root, plan, receipt, completion, records)
        with self.assertRaisesRegex(ValueError, "collector audit differs"):
            load_property_base(root, TARGET, 0)

    def test_plan_inventory_and_scenario_are_strict(self):
        for index, (key, value) in enumerate((("scenario", True), ("mutation", "changed"),
                                             ("expected", "cex"), ("inputs", ["../outside"]),
                                             ("sources", ["unbound.sv"]))):
            with self.subTest(key=key):
                root, plan, receipt, completion, records = self.base(str(index))
                plan[key] = value
                self.save(root, plan, receipt, completion, records)
                with self.assertRaises(ValueError):
                    load_property_base(root, TARGET, 0)

    def test_native_output_hash_is_checked(self):
        root, *_ = self.base()
        (root / "native.tsv").write_bytes(b"changed")
        with self.assertRaisesRegex(ValueError, "completion differs"):
            load_property_base(root, TARGET, 0)

    @unittest.skipUnless(shutil.which("tclsh"), "tclsh is required for collector control-flow checks")
    def test_collectors_finish_groups_and_defer_bounded_status(self):
        harness = r'''
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
    set length [expr {$verdict eq "proven" ? "infinite" : $::target_minimum}]
    set bound 0
    if {[info exists ::converted($label)]} {set bound $::converted($label)}
    return [list name $item type assert command assert disabled 0 validity_status $verdict \
        run_status $status expression $label precondition 0 engine K min_length $length target_bound $bound]
}
proc prove {args} {
    foreach label [array names ::states] {
        if {$::states($label) eq "bounded_proven_user"} {error "bounded property reused before all proves"}
    }
    foreach item [lindex $args 1] {
        set label [lindex [split $item .] end]
        set ::states($label) [expr {$label eq "target_first_event_is_breakpoint" ? "undetermined" : "proven"}]
    }
}
proc assert {args} {
    set label [lindex [split [lindex $args 2] .] end]
    set ::states($label) bounded_proven_user
    set ::converted($label) [lindex $args 1]
}
proc save {args} {}
source [lindex $argv 0]
'''
        wrappers = {UNIT_TOP: b"unit", CORE_TOP: b"core"}
        for filename in ("collect_safety.tcl", "collect_multiply_safety.tcl"):
            for minimum in (159, 160):
                with self.subTest(collector=filename, minimum=minimum):
                    root = self.root / f"{filename}-{minimum}"
                    root.mkdir()
                    collector = HERE / filename
                    plan, contents = case_definition(
                        "core-multiply-safety", {"unit.sv": b"unit"}, {"core.sv": b"rtl"}, wrappers,
                        {"safety": collector.read_bytes(), "multiply_retry": collector.read_bytes()}, 120, 600,
                        retry_cases=())
                    plan.pop("lateRetry", None)
                    (root / "plan.tcl").write_bytes(contents["plan.tcl"])
                    (root / "collect.tcl").write_bytes(collector.read_bytes())
                    script = f"set expected_reset {{{EXPECTED_RESET}}}\nset target_minimum {minimum}\n" + harness
                    (root / "harness.tcl").write_text(script)
                    process = subprocess.run(["tclsh", "harness.tcl", "collect.tcl"], cwd=root,
                                             capture_output=True, text=True, check=False)
                    self.assertTrue((root / "native.tsv").exists(), process.stderr)
                    records = read_records(root / "native.tsv")
                    self.assertEqual(process.returncode, int(minimum < 160), process.stderr)
                    self.assertEqual(records["final.native_hit_metadata", "validity_status"], "proven")
                    self.assertEqual(records["after", "initial_common_cold_reset"], "1")
                    if minimum < 160:
                        self.assertEqual(records["run", "state"], "failed")
                        self.assertIn("native proof groups failed", records["run", "error"])
                    else:
                        self.assertEqual(records["bounded." + TARGET, "validity_status"], "bounded_proven_user")
                        self.assertEqual(check_native_records(records, plan)["boundedGoals"], 1)


if __name__ == "__main__":
    unittest.main()
