# SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
# SPDX-License-Identifier: MIT
"""Reject altered native scope, finite prefixes and unlinked proof artifacts."""

import hashlib
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

from formal.debug_sba import run

INITIAL_RAW = {"validity_status": "unknown", "run_status": "unprocessed", "engine": "?",
               "min_length": "1", "max_length": "infinite", "target_bound": "0",
               "trace_length": "0", "latest_trace_engine": "?"}
ASSUMPTION_RAW = {"validity_status": "temporary", "run_status": "unprocessed", "target_bound": "0",
                  "engine": "__missing__", "min_length": "__missing__", "max_length": "__missing__",
                  "trace_length": "__missing__", "latest_trace_engine": "__missing__"}


def native_records(plan):
    records = {("setup", key): "0" for key in ("bbox_inst", "bbox_mod", "bbox_out", "stopat")}
    source = plan["allAssertions"] + plan["assumptions"] + plan["declaredCovers"]
    tags = [q[0] + side for q in run.queries(plan) for side in (".before", ".after")] + ["final"]
    inventories = {"native_assertions": plan["allAssertions"], "native_assumptions": plan["assumptions"],
                   "native_covers": plan["declaredCovers"] +
                                    [name + ":precondition1" for name in plan["allAssertions"] + plan["assumptions"]]}
    for tag in ["setup", *tags]:
        for key, names in inventories.items():
            records[tag, key] = " ".join(sorted(plan["top"] + "." + name for name in names))
    for tag in tags:
        records.update({(tag, "clock"): "{clock clock 1 1}", (tag, "reset"): run.RESET,
                        (tag, "global"): " ".join(plan["top"] + "." + name for name in plan["assumptions"]),
                        (tag, "reset_assumptions"): ""})
        for label in source:
            kind = "assert" if label in plan["allAssertions"] else "assume" if label in plan["assumptions"] else "cover"
            values = {"native_id": ("::" if kind == "assume" else "<embedded>::") + plan["top"] + "." + label,
                      "name": plan["top"] + "." + label,
                      "type": kind, "command": kind, "disabled": "0", "expression": label, "precondition": "0",
                      "clock": "__missing__", "edge": "__missing__", **(ASSUMPTION_RAW if kind == "assume" else INITIAL_RAW)}
            if tag != "query0.before" and label in plan["goals"]:
                values.update(validity_status="cex" if plan["kind"] == "negative" else "proven",
                              run_status="processed", engine="Mp", min_length="0" if plan["kind"] == "negative" else "infinite",
                              max_length="3" if plan["kind"] == "negative" else "infinite",
                              trace_length="3" if plan["kind"] == "negative" else "0",
                              latest_trace_engine="Mp" if plan["kind"] == "negative" else "?")
            if tag in ("query1.after", "final") and label in plan["covers"]:
                values.update(validity_status="covered", run_status="processed", engine="B", max_length="3",
                              trace_length="3", latest_trace_engine="B")
            records.update({(tag + "." + label, key): value for key, value in values.items()})
    for tag, kind, seconds, engines, iteration, labels in run.queries(plan):
        values = {"labels": " ".join(labels), "time_limit": str(seconds), "per_engine_max_jobs": "4",
                  "proven_facts_imported": "0", "engines": engines, "iteration_cap": iteration,
                  "command_attempted": "1", "actual_properties": " ".join("<embedded>::" + plan["top"] + "." + name for name in labels),
                  "first_trace_attempt": "1" if kind == "covers" else "none",
                  "per_property_time_limit": "none" if kind == "covers" else str(seconds * 64)}
        records.update({(tag, key): value for key, value in values.items()})
    records["run", "state"] = "complete"
    return records


def tsv(records):
    return "".join("\t".join(str(value).encode().hex() for value in (*key, item)) + "\n"
                   for key, item in records.items())


def rtl(spec, design):
    fields = []
    for name, (direction, width) in run.expected_ports(design).items():
        fields.append(direction + (" " if width == 1 else f" [{width - 1}:0] ") + name)
    return ("module " + spec["module"] + "(\n" + ",\n".join(fields) + ");\nassign " +
            spec["mutationPort"] + " = " + ("4'hf" if design == "sba" else "1'b0") + ";\nendmodule\n")


MOCK = r'''
source plan.tcl
set proofCount 0
set results [dict create]
set mode [lindex $argv 0]
proc analyze {args} {}
proc elaborate {args} {}
proc get_design_info {args} {return {}}
proc clock {args} {if {[lindex $args 0] eq "-list"} {return {{clock clock 1 1}}}}
proc property {args} {return native-reset-property}
proc resetTraceCheck {args} {
    set file [open trace-smoke.txt w];puts $file 1;close $file
}
proc reset {args} {
    if {[lindex $args 0] eq "-list"} {return $::resetText}
    if {[property native-reset] ne "native-reset-property"} {error "native property command was replaced"}
    trace add variable ::resetTraceSmoke write resetTraceCheck
    set ::resetTraceSmoke 1
    trace remove variable ::resetTraceSmoke write resetTraceCheck
}
proc assume {args} {
    if {"-env" in $args} {
        set out {};foreach label $::source_assumptions {lappend out "$::top.$label"}
        return $out
    }
    return {}
}
proc get_property_list {} {
    set out {}
    foreach label $::source_labels {
        if {$label in $::source_assumptions} {
            if {$::mode eq "bad-assume-id"} {lappend out "foreign::$::top.$label"} else {lappend out "::$::top.$label"}
        } else {lappend out "<embedded>::$::top.$label"}
    }
    foreach label [concat $::all_assertions $::source_assumptions] {lappend out "<embedded>::$::top.$label:precondition1"}
    if {$::mode eq "extra-cover" && $::proofCount > 0} {lappend out "$::top.foreign_cover"}
    return $out
}
proc get_property_info {item} {
    set bare [regsub {^.*::} $item {}]
    set name [string range $bare [expr {[string length $::top]+1}] end]
    set type [expr {$name in $::all_assertions ? "assert" : $name in $::source_assumptions ? "assume" : "cover"}]
    set values [list name $bare type $type command $type disabled 0 expression $name precondition 0]
    if {$type eq "assume"} {
        set values [concat $values {validity_status temporary run_status unprocessed target_bound 0}]
    } else {
        set values [concat $values {validity_status unknown run_status unprocessed engine ? min_length 1 max_length infinite target_bound 0 trace_length 0 latest_trace_engine ?}]
    }
    if {[dict exists $::results $item]} {set values [concat $values [dict get $::results $item]]}
    return $values
}
proc prove {args} {
    set query [lindex $::queries $::proofCount]
    incr ::proofCount
    set file [open proof-count.txt w];puts $file $::proofCount;close $file
    set items [lindex $args [expr {[lsearch -exact $args -property]+1}]]
    if {$::mode eq "error"} {error "controlled proof command error"}
    foreach item $items {
        set kind [lindex $query 1]
        if {$kind eq "covers"} {set result {validity_status covered run_status processed engine B trace_length 3 latest_trace_engine B}} elseif {$kind eq "negative" || $::mode eq "cex"} {
            set result {validity_status cex run_status processed engine Mp trace_length 3 latest_trace_engine Mp}
        } else {set result {validity_status proven run_status processed engine Mp min_length infinite max_length infinite}}
        dict set ::results $item $result
    }
}
proc visualize {args} {
    set index [lsearch -exact $args -vcd]
    if {$index >= 0} {
        set file [open [lindex $args [expr {$index+1}]] {WRONLY CREAT EXCL}]
        puts $file {$var wire 1 ! clock $end}
        puts $file {$enddefinitions $end}
        puts $file "#0\n0!\n#3\n1!"
        close $file
    }
}
set file [open proof-count.txt w];puts $file 0;close $file
source collect.tcl
'''


class CommercialTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="sba-commercial-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        for design in ("sba", "arbiter"):
            directory = self.root / design
            directory.mkdir()
            spec = run.SPECS[design]
            (directory / (spec["module"] + ".sv")).write_text(rtl(spec, design))
        self.evidence = self.root / "evidence"
        self.tool = hashlib.sha256(b"runtime-generated-sba-test-tool").hexdigest()
        self.manifest = run.prepare(self.root / "sba", self.evidence, self.root / "arbiter", tool_sha256=self.tool)

    def plan(self, name):
        return json.loads((self.evidence / "cases" / name / "plan.json").read_text())

    def test_exact_frozen_inputs_and_four_case_budget(self):
        self.assertEqual(run.validate_frozen(self.evidence), self.manifest)
        self.assertEqual(self.manifest["cases"], ["sba-positive", "sba-negative", "arbiter-positive", "arbiter-negative"])
        for name in self.manifest["cases"]:
            plan = self.plan(name)
            self.assertEqual(sum(q[2] for q in run.queries(plan)), 300)
            self.assertEqual(len(plan["inputs"]), 4)
        path = self.evidence / "cases/sba-positive/plan.tcl"
        path.write_text(path.read_text().replace("240", "241"))
        with self.assertRaisesRegex(ValueError, "query"):
            run.validate_frozen(self.evidence)

    def test_reset_adapter_preserves_reference_body_and_property_inventory(self):
        marker = b"  (* anyseq *)"
        for design, spec in run.SPECS.items():
            reference = (run.HERE / spec["wrapper"]).read_bytes()
            adapter = self.manifest["wrapperAdapters"][design]
            native = (self.evidence / adapter["native"]).read_bytes()
            with self.subTest(design=design):
                self.assertEqual((self.evidence / spec["wrapper"]).read_bytes(), reference)
                self.assertEqual(native, run.native_wrapper(reference, spec))
                self.assertEqual(native.split(marker, 1)[1], reference.split(marker, 1)[1])
                self.assertEqual(run.inventories(native), run.inventories(reference))
                self.assertEqual(adapter, run.wrapper_binding(reference, spec))
                self.assertEqual(adapter["version"], run.RESET_ADAPTER)
                self.assertIn(("module " + spec["top"] + "(input clock, input reset);\n").encode(), native)
                self.assertIn(b"  reg past_valid = 0;\n  always @(posedge clock) past_valid <= 1;\n", native)
                self.assertNotIn(b"reg reset", native)
                self.assertNotIn(b"reset <=", native)
                for kind in ("positive", "negative"):
                    plan = self.plan(design + "-" + kind)
                    self.assertEqual(plan["wrapperAdapter"], adapter)
                    self.assertIn(adapter["native"], plan["sources"])
                    self.assertNotIn(spec["wrapper"], plan["sources"])

    def test_reset_adapter_rejects_changed_reference_prolog(self):
        for design, spec in run.SPECS.items():
            reference = (run.HERE / spec["wrapper"]).read_bytes()
            for old, new in ((b"input clock", b"input clock, input reset"),
                             (b"reset = 1", b"reset = 0"),
                             (b"past_valid = 0", b"past_valid = 1"),
                             (b"reset <= 0", b"reset <= 1"),
                             (b"past_valid <= 1", b"past_valid <= 0"),
                             (b"  (* anyseq *)", b" (* anyseq *)")):
                with self.subTest(design=design, change=old), self.assertRaises(ValueError):
                    run.native_wrapper(reference.replace(old, new), spec)

    def test_rehashed_native_reset_adapter_changes_are_rejected(self):
        manifest_path = self.evidence / "manifest.json"
        original_manifest = manifest_path.read_bytes()
        for design, spec in run.SPECS.items():
            filename = self.manifest["wrapperAdapters"][design]["native"]
            path = self.evidence / filename
            original = path.read_bytes()
            changes = ((b"input clock, input reset", b"input clock"),
                       (b"past_valid = 0", b"past_valid = 1"),
                       (b"past_valid <= 1", b"past_valid <= 0"),
                       (b": assert(", b": assert(1 || "),
                       (b": assume(", b": assume(1 || "),
                       (b": cover(", b": cover(1 || "))
            for old, new in changes:
                changed = original.replace(old, new, 1)
                self.assertNotEqual(changed, original)
                path.write_bytes(changed)
                manifest = json.loads(original_manifest)
                manifest["verificationHashes"][filename] = run.digest(path)
                manifest["wrapperAdapters"][design]["nativeSha256"] = run.digest(path)
                run.write_json(manifest_path, manifest)
                with self.subTest(design=design, change=old), self.assertRaisesRegex(ValueError, "reset adapter"):
                    run.validate_frozen(self.evidence)
                path.write_bytes(original)
                manifest_path.write_bytes(original_manifest)
        manifest = json.loads(original_manifest)
        manifest["wrapperAdapters"]["sba"]["version"] = "unsupported-adapter"
        run.write_json(manifest_path, manifest)
        with self.assertRaisesRegex(ValueError, "adapter binding"):
            run.validate_frozen(self.evidence)

    def test_unbounded_positive_and_effective_negative(self):
        for name in self.manifest["cases"]:
            plan = self.plan(name)
            result = run.check_protocol(native_records(plan), plan)
            self.assertTrue(result["caseAccepted"])
            self.assertEqual(result["unboundedAssertions"], len(plan["goals"]) if plan["kind"] == "positive" else 0)

    def test_native_setup_schema_contains_no_proof_verdicts(self):
        for case in ("sba-positive", "arbiter-positive"):
            plan = self.plan(case)
            data = native_records(plan)
            for label in plan["allAssertions"] + plan["assumptions"] + plan["declaredCovers"]:
                assumption = label in plan["assumptions"]
                row = "query0.before." + label
                with self.subTest(case=case, label=label):
                    self.assertEqual({key: data[row, key] for key in run.RAW}, ASSUMPTION_RAW if assumption else INITIAL_RAW)
                    self.assertEqual(data[row, "native_id"], ("::" if assumption else "<embedded>::") + plan["top"] + "." + label)
                    self.assertEqual(data[row, "name"], plan["top"] + "." + label)
            for group, key in data:
                if group.split(".")[-1] in plan["allAssertions"] + plan["declaredCovers"] and key in INITIAL_RAW:
                    data[group, key] = INITIAL_RAW[key]
            with self.assertRaises(ValueError):
                run.check_protocol(data, plan)

    def test_assertion_and_cover_raw_fields_cannot_use_assumption_missing_fields(self):
        for case in ("sba-positive", "arbiter-positive"):
            plan = self.plan(case)
            for label in (plan["goals"][0], plan["covers"][0]):
                for tag in ("query0.before", "query0.after", "query1.before", "query1.after", "final"):
                    for key in run.RAW:
                        for absent in (False, True):
                            data = native_records(plan)
                            if absent:
                                del data[tag + "." + label, key]
                            else:
                                data[tag + "." + label, key] = "__missing__"
                            with self.subTest(case=case, label=label, tag=tag, key=key, absent=absent), self.assertRaises(ValueError):
                                run.check_protocol(data, plan)

    def test_assumption_metadata_supported_fields_and_missing_pattern_are_stable(self):
        mutations = (("native_id", "foreign::source"), ("name", "foreign.source"),
                     ("type", "assert"), ("command", "assert"), ("disabled", "1"),
                     ("expression", ""), ("precondition", "1"),
                     ("validity_status", "proven"), ("run_status", "processed"), ("target_bound", "64"),
                     ("validity_status", "__missing__"), ("run_status", "__missing__"), ("target_bound", "__missing__"),
                     ("engine", "?"), ("latest_trace_engine", "?"),
                     ("min_length", "1"), ("max_length", "infinite"), ("trace_length", "0"))
        for case in ("sba-positive", "arbiter-positive"):
            plan = self.plan(case)
            for label in plan["assumptions"]:
                for key, value in mutations:
                    data = native_records(plan)
                    data["query0.after." + label, key] = value
                    with self.subTest(case=case, label=label, key=key, value=value), self.assertRaises(ValueError):
                        run.check_protocol(data, plan)
                for key in run.RAW:
                    data = native_records(plan)
                    del data["query0.before." + label, key]
                    with self.subTest(case=case, label=label, absent=key), self.assertRaises(ValueError):
                        run.check_protocol(data, plan)

    def test_native_id_prefixes_are_exact_and_source_typed(self):
        plan = self.plan("sba-positive")
        for label, invalid in ((plan["assumptions"][0], "<embedded>::"),
                               (plan["assumptions"][0], "foreign::"),
                               (plan["goals"][0], "::"), (plan["covers"][0], "::")):
            data = native_records(plan)
            data["query0.before." + label, "native_id"] = invalid + plan["top"] + "." + label
            with self.subTest(label=label, prefix=invalid), self.assertRaises(ValueError):
                run.check_protocol(data, plan)

    def test_finite_wrong_engine_or_missing_raw_never_pass(self):
        plan = self.plan("sba-positive")
        name = plan["goals"][0]
        for field, value in (("min_length", "64"), ("max_length", "64"), ("engine", "B"), ("target_bound", "64")):
            data = native_records(plan)
            data["final." + name, field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                run.check_protocol(data, plan)
        data = native_records(plan)
        del data["query1.after." + name, "trace_length"]
        with self.assertRaises(ValueError):
            run.check_protocol(data, plan)

    def test_missing_sentinels_and_late_only_safety_proofs_are_rejected(self):
        for case in ("sba-positive", "arbiter-positive"):
            plan = self.plan(case)
            goal = plan["goals"][0]
            for tag in ("query0.before", "query0.after", "query1.before", "query1.after", "final"):
                for key in run.RAW:
                    data = native_records(plan)
                    data[tag + "." + goal, key] = "__missing__"
                    with self.subTest(case=case, tag=tag, key=key), self.assertRaises(ValueError):
                        run.check_protocol(data, plan)
            mutations = [("query0.before", "trace_length", "-3"),
                         ("query0.before", "target_bound", "0.0"),
                         ("query0.before", "min_length", "-1"),
                         ("query0.after", "validity_status", "unknown"),
                         ("query0.after", "run_status", "not_run"),
                         ("query0.after", "min_length", "64"),
                         ("query0.after", "max_length", "64"),
                         ("query0.after", "target_bound", "64"),
                         ("query0.after", "engine", "B"),
                         ("query1.before", "trace_length", "1"),
                         ("query1.after", "latest_trace_engine", "B")]
            for tag, key, wrong in mutations:
                data = native_records(plan)
                data[tag + "." + goal, key] = wrong
                with self.subTest(case=case, tag=tag, key=key), self.assertRaises(ValueError):
                    run.check_protocol(data, plan)
            data = native_records(plan)
            data["query0.before." + plan["assumptions"][0], "target_bound"] = "__missing__"
            with self.assertRaises(ValueError):
                run.check_protocol(data, plan)

    def test_cover_and_negative_must_finish_in_their_actual_query(self):
        for case, tag, field, wrong in (("sba-positive", "query1.after", "validity_status", "unknown"),
                                        ("arbiter-positive", "query1.after", "trace_length", "0"),
                                        ("sba-negative", "query0.after", "validity_status", "unknown"),
                                        ("arbiter-negative", "query0.after", "run_status", "unprocessed")):
            plan = self.plan(case)
            label = plan["covers"][0] if plan["kind"] == "positive" else plan["goals"][0]
            data = native_records(plan)
            data[tag + "." + label, field] = wrong
            with self.subTest(case=case), self.assertRaises(ValueError):
                run.check_protocol(data, plan)

    def test_scope_identity_inventory_and_query_mutations(self):
        plan = self.plan("arbiter-positive")
        mutations = [("query0.after", "global", "extra"), ("query0.before", "global", ""),
                     ("final", "global", " ".join([plan["top"] + "." + plan["assumptions"][0]] * len(plan["assumptions"]))),
                     ("query1.before", "clock", ""),
                     ("query1.after", "native_covers", ""), ("final", "native_assertions", ""),
                     ("query1", "time_limit", "61"), ("query0", "actual_properties", "wrong"),
                     ("query0", "proven_facts_imported", "1"), ("query2", "labels", "extra")]
        for group, key, value in mutations:
            data = native_records(plan)
            data[group, key] = value
            with self.subTest(group=group, key=key), self.assertRaises(ValueError):
                run.check_protocol(data, plan)
        data = native_records(plan)
        data["final", "native_covers"] += " " + plan["top"] + ".foreign:precondition1"
        with self.assertRaises(ValueError):
            run.check_protocol(data, plan)
        data = native_records(plan)
        source = plan["allAssertions"] + plan["assumptions"] + plan["declaredCovers"]
        for key in data:
            if key[0].split(".")[-1] in source:
                if key[1] == "clock":
                    data[key] = "clock"
                if key[1] == "edge":
                    data[key] = "posedge"
        self.assertTrue(run.check_protocol(data, plan)["caseAccepted"])
        data["query0.before." + plan["goals"][0], "clock"] = "different_clock"
        with self.assertRaises(ValueError):
            run.check_protocol(data, plan)

    def test_receipt_typed_resources_outputs_and_complete_gate(self):
        for name in self.manifest["cases"]:
            plan = self.plan(name)
            case = self.evidence / "cases" / name
            (case / "native.tsv").write_text(tsv(native_records(plan)))
            for label in plan["covers"] if plan["kind"] == "positive" else plan["targets"]:
                (case / (label + ".vcd")).write_text("$var wire 1 ! clock $end\n$enddefinitions $end\n#0\n0!\n#3\n1!\n")
            receipt = {"command": ["jg", "-no_gui", "-fpv", "-tcl", "collect.tcl"],
                       "inputHashes": self.manifest["inputHashes"][name], "pid": os.getpid(),
                       "cpuCount": 16, "cpu": 0, "cpuAffinity": list(range(16)), "timeoutSeconds": 360,
                       "launcherSha256": self.tool, "startedUtc": "2026-01-01T00:00:00+00:00"}
            completion = {"exitStatus": 0, "timedOut": False, "inputsUnchanged": True,
                          "nativeExecutableSha256": self.tool, "elapsedSeconds": 0.25,
                          "endedUtc": "2026-01-01T00:00:01+00:00", "outputHashes": run.backend().output_hashes(case)}
            run.write_json(case / "receipt.json", receipt)
            run.write_json(case / "completion.json", completion)
        result = run.validate(self.evidence)
        self.assertEqual((result["unboundedAssertions"], result["coversReached"], result["effectiveNegatives"]), (34, 17, 2))
        self.assertEqual(result["commercialGate"], "passed")
        self.assertFalse(result["fullCoreProven"])
        case = self.evidence / "cases/sba-positive"
        for filename, field, wrong in (("receipt.json", "pid", True), ("receipt.json", "cpuCount", True),
                                        ("receipt.json", "cpuAffinity", [True, *range(1, 16)]),
                                        ("receipt.json", "timeoutSeconds", 361),
                                        ("completion.json", "exitStatus", False),
                                        ("completion.json", "exitStatus", 0.0),
                                        ("completion.json", "elapsedSeconds", float("nan")),
                                        ("completion.json", "inputsUnchanged", False)):
            path = case / filename
            original = path.read_bytes()
            altered = json.loads(original)
            altered[field] = wrong
            run.write_json(path, altered)
            with self.subTest(filename=filename, field=field), self.assertRaises(ValueError):
                run.validate(self.evidence)
            path.write_bytes(original)
        witness = case / (self.plan("sba-positive")["covers"][0] + ".vcd")
        witness.unlink()
        with self.assertRaises(ValueError):
            run.validate(self.evidence)

    def test_real_tcl_positive_negative_fatal_and_stale_witness(self):
        for name, mode, wanted in (("sba-positive", "normal", 0), ("arbiter-negative", "normal", 0),
                                    ("sba-negative", "normal", 0), ("arbiter-positive", "error", 1)):
            case = self.evidence / "cases" / name
            (case / "mock.tcl").write_text("set resetText {" + run.RESET + "}\n" + MOCK)
            result = subprocess.run(["tclsh", "mock.tcl", mode], cwd=case, capture_output=True, text=True, check=False)
            self.assertEqual(result.returncode, wanted, result.stderr)
            records = run.backend().read_records(case / "native.tsv")
            if wanted == 0:
                self.assertTrue(run.check_protocol(records, self.plan(name))["caseAccepted"])
            else:
                self.assertEqual((case / "proof-count.txt").read_text().strip(), "1")
                self.assertIn(("final.arbiter_single_source_accept", "min_length"), records)
                with self.assertRaises(ValueError):
                    run.check_protocol(records, self.plan(name))
        case = self.evidence / "cases/arbiter-positive"
        (case / "cover_first_contention_grant.vcd").write_text("stale")
        result = subprocess.run(["tclsh", "mock.tcl", "normal"], cwd=case, capture_output=True, text=True, check=False)
        self.assertEqual(result.returncode, 1)
        self.assertEqual((case / "proof-count.txt").read_text().strip(), "0")

    def test_helpers_preserve_native_property_and_tcl_trace_commands(self):
        case = self.evidence / "cases/arbiter-positive"
        (case / "mock.tcl").write_text("set resetText {" + run.RESET + "}\n" + MOCK)
        for shadow in (None, "property", "trace"):
            collector = run.COLLECTOR
            if shadow == "property":
                collector = collector.replace("sba_property", "property")
            elif shadow == "trace":
                collector = collector.replace("sba_export_witness", "trace")
            (case / "collect.tcl").write_text(collector)
            for path in case.glob("*.vcd"):
                path.unlink()
            result = subprocess.run(["tclsh", "mock.tcl", "normal"], cwd=case,
                                    capture_output=True, text=True, check=False)
            with self.subTest(shadow=shadow):
                self.assertEqual(result.returncode, 0 if shadow is None else 1)
                self.assertEqual((case / "proof-count.txt").read_text().strip(), "2" if shadow is None else "0")
                if shadow is None:
                    self.assertEqual((case / "trace-smoke.txt").read_text().strip(), "1")

    def test_real_tcl_cex_or_after_inventory_change_stops_second_query(self):
        for mode in ("cex", "extra-cover"):
            case = self.evidence / "cases/sba-positive"
            for path in case.glob("*.vcd"):
                path.unlink()
            (case / "mock.tcl").write_text("set resetText {" + run.RESET + "}\n" + MOCK)
            result = subprocess.run(["tclsh", "mock.tcl", mode], cwd=case, capture_output=True, text=True, check=False)
            self.assertEqual(result.returncode, 1)
            self.assertEqual((case / "proof-count.txt").read_text().strip(), "1")

    def test_real_tcl_rejects_inexact_native_assumption_id_before_proof(self):
        case = self.evidence / "cases/sba-positive"
        (case / "mock.tcl").write_text("set resetText {" + run.RESET + "}\n" + MOCK)
        result = subprocess.run(["tclsh", "mock.tcl", "bad-assume-id"], cwd=case,
                                capture_output=True, text=True, check=False)
        self.assertEqual(result.returncode, 1)
        self.assertEqual((case / "proof-count.txt").read_text().strip(), "0")
        self.assertIn(tsv({("run", "state"): "failed"}).strip(), (case / "native.tsv").read_text().splitlines())


if __name__ == "__main__":
    unittest.main()
