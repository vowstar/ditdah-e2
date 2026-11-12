# SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
# SPDX-License-Identifier: MIT
"""Exercise semantic collection, strict qualification and immutable legacy cases."""

import argparse
import copy
import hashlib
import json
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from formal.trigger import run, staged

from test.test_trigger import test_staged as baseline
from test.test_trigger.test_staged import collectors, definition, rtl

CONFIGURATION = staged.SEMANTIC_CONFIG["name"]


def semantic_definition(name="core-older-safety"):
    selected = collectors()
    collector, helper = staged.artifacts(CONFIGURATION)
    selected.update(staged=(run.HERE / collector).read_bytes(), staged_helpers=(run.HERE / helper).read_bytes())
    return run.case_definition(name, *rtl(),
        {run.UNIT_TOP: (run.HERE / run.UNIT_WRAPPER).read_bytes(), run.CORE_TOP: (run.HERE / run.CORE_WRAPPER).read_bytes()},
        selected, 120, 600, flow="staged", source_configuration=CONFIGURATION)


class SemanticTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if shutil.which("tclsh") is None:
            raise RuntimeError("Real tclsh is required")
        baseline.StagedTests.setUpClass()
        extra = '''if {$kind eq "semantic" && $::mode eq "semantic_unknown"} {
            foreach label $selected {set ::states($label) unknown;set ::lengths($label) 1}
        }
        '''
        extra += '''if {$kind eq "helpers" && $::mode eq "cex_helpers"} {
            foreach label {core_frontend_stage_rom_consistent core_data_owner_control_consistent core_program_no_injection} {
                if {$label in $::all_assertions} {
                    set ::states($label) cex
                    set ::lengths($label) [expr {$label eq "core_frontend_stage_rom_consistent" ? 13 : 1}]
                }
            }
        }
        '''
        cls.harness = baseline.StagedTests.harness.replace('if {$::mode eq "all_finite"}', extra + 'if {$::mode eq "all_finite"}')

    def execute(self, root, mode="pass", name="core-older-safety", stale_witness=False):
        root.mkdir()
        plan, contents = semantic_definition(name)
        for filename, value in contents.items():
            (root / filename).write_bytes(value)
        (root / "harness.tcl").write_text(f"set expected_reset {{{run.EXPECTED_RESET}}}\nset mode {mode}\n"
            "set typed 1\nset proof_calls 0\nset import_mode auto\n" + self.harness)
        if stale_witness:
            (root / (staged.HELPERS[0] + ".vcd")).write_text("stale witness\n")
        process = subprocess.run(["tclsh", "harness.tcl"], cwd=root, capture_output=True, text=True, check=False)
        return process, run.read_records(root / "native.tsv"), plan

    def prepare_bundle(self, root):
        paths = []
        for top, contents in zip(("DitDahE2Trigger", "DitDahE2"), rtl(), strict=True):
            target = root / top
            target.mkdir()
            for filename, value in contents.items():
                (target / filename).write_bytes(value)
            run.write_json(target / "manifest.json", {"top": top, "exitStatus": 0,
                "parameters": {"triggerCount": 2, "enableDebug": True, "enableM": True, "enableC": False, "protectedMode": False},
                "rtlHashes": {name: run.sha(value) for name, value in contents.items()}, "sourceHashes": {}})
            paths.append(target)
        output = root / "evidence"
        args = argparse.Namespace(unit_rtl=paths[0], core_rtl=paths[1], source_root=root, output=output,
            time_limit=120, core_time_limit=600, proof_seed=None, proof_seed_scenario2=None, proof_seed_scenario3=None,
            multiply_target_base=[], multiply_older_base=[], retry_case=[], flow="staged", staged_configuration=CONFIGURATION)
        run.prepare(args)
        return output, paths

    def test_all_seventeen_cases_legacy_bytes_and_exact_store_dpc_alias(self):
        for name in run.CASES:
            plan, contents = semantic_definition(name)
            previous, old_contents = definition(name)
            if name not in run.SAFETY_RETRY_CASES:
                self.assertEqual((plan, contents), (previous, old_contents))
                continue
            for key in ("goals", "assumptions", "dutInitialState", "initialState", "targetBounds", "sources"):
                self.assertEqual(plan[key], previous[key])
            self.assertEqual(len(plan["allAssertions"]), len(staged.HELPERS) + 25)
            self.assertEqual(len(plan["querySchedule"]), 10)
            self.assertEqual(sum(row["timeLimit"] for row in plan["querySchedule"]), 960)
            fragment = (run.HERE / "semantic_helpers.sv").read_bytes()
            self.assertEqual(contents[run.CORE_WRAPPER].replace(fragment, b"", 1), old_contents[run.CORE_WRAPPER])
        self.assertEqual(semantic_definition("core-store-safety"), semantic_definition("core-dpc-safety"))

    def test_actual_tcl_all_scenarios_complete_inventory_and_own_bounds(self):
        with tempfile.TemporaryDirectory() as directory:
            for name in run.SAFETY_RETRY_CASES:
                process, records, plan = self.execute(Path(directory) / name, name=name)
                self.assertEqual(process.returncode, 0, process.stderr)
                checked = run.check_native_records(records, plan)
                self.assertEqual((checked["goals"], checked["unboundedGoals"], checked["boundedGoals"]), (21, 17, 4))
                self.assertEqual(checked["unboundedHelperGoals"], len(staged.HELPERS) + 4)
                self.assertEqual(records["query9", "iteration_cap"], "352" if plan["scenario"] == 1 else "288")
                self.assertEqual(len({tag for tag, key in records if key == "native_id" and not tag.startswith("bounded.")}),
                                 22 * len(plan["allAssertions"]))
            for mode in ("semantic_unknown", "skip_remaining", "initial_only", "mixed_prefixes"):
                process, records, plan = self.execute(Path(directory) / mode, mode)
                result = staged.validate_protocol(records, plan)
                self.assertEqual(result["caseAccepted"], mode not in ("initial_only", "mixed_prefixes"))
                self.assertEqual(process.returncode, int(not result["caseAccepted"]))
                if mode == "semantic_unknown":
                    self.assertEqual(len(result["unboundedHelpers"]), len(staged.HELPERS))
                if mode == "skip_remaining":
                    self.assertEqual(result["allocatedSearchSeconds"], 600)

    def test_every_tenth_profile_error_or_counterexample_stops_later_queries(self):
        with tempfile.TemporaryDirectory() as directory:
            for index in range(10):
                for prefix in ("tool", "cex"):
                    process, records, plan = self.execute(Path(directory) / f"{prefix}{index}", f"{prefix}{index}")
                    self.assertEqual(process.returncode, 1)
                    self.assertTrue(all(records[f"query{i}", "executed"] == "0" for i in range(index + 1, 10)))
                    with self.assertRaises(ValueError):
                        run.check_native_records(records, plan)

    def test_strict_ten_phase_facts_engine_metadata_and_original_bounds(self):
        with tempfile.TemporaryDirectory() as directory:
            _, records, plan = self.execute(Path(directory) / "pass")
            for key, value in [(("query9", "iteration_cap"), "128"), (("query9", "first_trace_attempt"), "2"),
                (("query8", "fact_actual_properties"), ""), (("query8", "labels"), "foreign"),
                (("query9.before.core_native_trap_metadata", "engine"), "N"),
                (("query9.after.core_native_trap_metadata", "max_length"), "999"),
                (("bounded.older_fault_cause", "engine"), "N")]:
                altered = dict(records)
                altered[key] = value
                with self.subTest(key=key), self.assertRaises(ValueError):
                    run.check_native_records(altered, plan)
            changed = copy.deepcopy(plan)
            changed["targetBounds"]["older_fault_cause"] = 128
            with self.assertRaises(ValueError):
                run.check_native_records(records, changed)

    def test_collection_and_resource_receipts_require_sixteen_cpus_and_1080(self):
        with tempfile.TemporaryDirectory() as directory:
            case = Path(directory)
            plan, _ = semantic_definition()
            run.write_json(case / "plan.json", plan)
            (case / "native.tsv").write_text("")
            with patch.object(run, "collect_case", return_value={}) as collect, patch.object(run, "check_native_records", return_value={}):
                run.collect_trigger_case(case, "unused", case, 1800)
            self.assertEqual(collect.call_args.args[-1], 1080)
            self.assertEqual(collect.call_args.kwargs, {"cpu_count": 16})
            valid = {"cpu": 0, "cpuCount": 16, "cpuAffinity": list(range(16)), "pid": 1, "timeoutSeconds": 1080}
            staged.check_resources(valid, plan)
            for mutation in ({"cpuCount": True}, {"cpu": False}, {"cpuAffinity": [0]}, {"timeoutSeconds": 960}, {"timeoutSeconds": 1080.0}):
                with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                    staged.check_resources({**valid, **mutation}, plan)

    def test_prepare_frozen_active_dependencies_and_cli(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            evidence, paths = self.prepare_bundle(root)
            run.validate_frozen(evidence)
            for name in staged.FILES:
                path = evidence / name
                original = path.read_bytes()
                path.write_bytes(original + b" ")
                with self.subTest(name=name), self.assertRaises(ValueError):
                    run.validate_frozen(evidence)
                path.write_bytes(original)
            process = subprocess.run([sys.executable, "-B", str(run.HERE / "run.py"), "prepare",
                "--unit-rtl", str(paths[0]), "--core-rtl", str(paths[1]), "--source-root", str(root),
                "--output", str(root / "cli-evidence"), "--flow", "staged", "--staged-configuration", CONFIGURATION],
                capture_output=True, text=True, check=False)
            self.assertEqual(process.returncode, 0, process.stderr)
            frozen = subprocess.run([sys.executable, "-B", "runner.py", "validate", "--evidence", str(evidence)],
                cwd=evidence, capture_output=True, text=True, check=False)
            self.assertEqual(frozen.returncode, 1)
            self.assertIn("receipt.json", frozen.stderr)
            self.assertNotIn("ModuleNotFoundError", frozen.stderr)

    def test_actual_cold_body_and_matching_family_are_mandatory(self):
        files = {name: (run.HERE / name).read_bytes() for name in staged.FILES}
        staged.check_collectors(files)
        config = staged.configuration(CONFIGURATION)
        source = files["collect_semantic.tcl"]
        actual = staged.check_cold_collector(source, config)
        self.assertEqual((actual["dutFacts"], actual["totalFacts"]),
                         (config["dutColdFacts"], config["coldFacts"]))
        self.assertEqual(source.replace(b"maximum_search_budget_seconds 960", b"maximum_search_budget_seconds 840"),
                         files["collect_staged.tcl"])
        expression = re.findall(rb"(?m)^\s*assume -reset \{([^\n]+)\}\s*$", source)[0]
        terms = expression.decode().split(" && ")
        omitted = {"dut.debug.cancelInjection", "dut.debug.ebreakUser", "dut.debug.injecting", "dut.debug.pendingIssue",
                   "dut.debug.slot", "dut.dm.program0", "dut.dm.program1", "dut.xInjected", "dut.xSequence", "dut.xTruncated"}
        if config["dutColdFacts"] == 122:
            wrong_terms = [term for term in terms if term.split(" == ")[0] not in omitted]
            self.assertEqual(len(terms) - len(wrong_terms), 10)
        else:
            wrong_terms = [term for term in terms if term != "dut.dm.auto == 0"]
            self.assertEqual(len(terms) - len(wrong_terms), 1)
        wrong = source.replace(expression, " && ".join(wrong_terms).encode())
        self.assertIn(("record setup dut_cold_facts " + str(config["dutColdFacts"])).encode(), wrong)
        with self.assertRaisesRegex(ValueError, "Actual collector cold-reset expression"):
            staged.check_cold_collector(wrong, config)
        bad_config = {**config, "coldExpressionSha256": hashlib.sha256(" && ".join(wrong_terms).encode()).hexdigest()}
        with self.assertRaisesRegex(ValueError, "fact count"):
            staged.check_cold_collector(wrong, bad_config)
        bad_files = {**files, "collect_semantic.tcl": wrong}
        with self.assertRaisesRegex(ValueError, "Actual collector cold-reset expression"):
            staged.check_collectors(bad_files)
        with self.assertRaises(ValueError):
            staged.check_cold_collector(source + b"\nassume -reset {reset}\n", config)

    def test_prepare_and_frozen_validation_recheck_actual_reset_body(self):
        files = {name: (run.HERE / name).read_bytes() for name in staged.FILES}
        source = files["collect_semantic.tcl"]
        expression = re.findall(rb"(?m)^\s*assume -reset \{([^\n]+)\}\s*$", source)[0]
        omitted = {"dut.debug.cancelInjection", "dut.debug.ebreakUser", "dut.debug.injecting", "dut.debug.pendingIssue",
                   "dut.debug.slot", "dut.dm.program0", "dut.dm.program1", "dut.xInjected", "dut.xSequence", "dut.xTruncated"}
        if staged.SEMANTIC_CONFIG["dutColdFacts"] != 122:
            omitted = {"dut.dm.auto"}
        wrong_terms = [term for term in expression.decode().split(" && ") if term.split(" == ")[0] not in omitted]
        bad = source.replace(expression, " && ".join(wrong_terms).encode())
        self.assertLess(source.index(b"set reset_initial [assume -reset -list"), source.index(b"assume -reset {"))
        original_read = Path.read_bytes

        def changed_read(path):
            if path == run.HERE / "collect_semantic.tcl":
                return bad
            return original_read(path)

        bad_config = {**run.staged.SEMANTIC_CONFIG, "collectorSha256": run.sha(bad)}
        with (tempfile.TemporaryDirectory() as directory,
              patch.object(Path, "read_bytes", changed_read),
              patch.object(run.staged, "SEMANTIC_CONFIG", bad_config),
              self.assertRaisesRegex(ValueError, "Actual collector cold-reset expression")):
            self.prepare_bundle(Path(directory))
        with tempfile.TemporaryDirectory() as directory:
            evidence, _ = self.prepare_bundle(Path(directory))
            manifest = json.loads((evidence / "manifest.json").read_text())
            (evidence / "collect_semantic.tcl").write_bytes(bad)
            manifest["verificationHashes"]["collect_semantic.tcl"] = run.sha(bad)
            manifest["stagedConfiguration"]["collectorSha256"] = run.sha(bad)
            run.write_json(evidence / "manifest.json", manifest)
            with (patch.object(Path, "read_bytes", changed_read),
                  patch.object(run.staged, "SEMANTIC_CONFIG", bad_config),
                  self.assertRaisesRegex(ValueError, "Actual collector cold-reset expression")):
                run.validate_frozen(evidence)

    def test_repeated_counterexamples_export_once_and_keep_failure_footer(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "case"
            process, records, plan = self.execute(root, "cex_helpers", name="core-store-safety")
            self.assertEqual(process.returncode, 1)
            labels = [label for label in ("core_frontend_stage_rom_consistent", "core_data_owner_control_consistent",
                                         "core_program_no_injection") if label in plan["allAssertions"]]
            exports = (root / "witness_exports.log").read_text().splitlines()
            self.assertEqual(len(exports), len(labels))
            for label in labels:
                self.assertTrue((root / (label + ".vcd")).is_file())
                self.assertEqual(records["query7.after." + label, "validity_status"], "cex")
                self.assertEqual(records["query8.before." + label, "validity_status"], "cex")
                self.assertEqual(records["final." + label, "min_length"], "13" if label == "core_frontend_stage_rom_consistent" else "1")
            self.assertNotIn("witness export failed", records["run", "fatal_errors"])
            self.assertEqual(records["query8", "executed"], "0")
            self.assertEqual(records["query9", "executed"], "0")
            self.assertEqual(records["run", "scheduled_queries"], "10")
            self.assertEqual(records["run", "proof_queries_finished"], "1")
            self.assertEqual(records["run", "state"], "failed")
            self.assertIn(("after", "global"), records)

    def test_preexisting_witness_is_rejected_without_overwriting(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "case"
            process, records, _ = self.execute(root, "cex7", stale_witness=True)
            self.assertEqual(process.returncode, 1)
            self.assertEqual((root / (staged.HELPERS[0] + ".vcd")).read_text(), "stale witness\n")
            self.assertFalse((root / "witness_exports.log").exists())
            self.assertIn("native witness path already exists", records["run", "fatal_errors"])
            self.assertEqual(records["query8", "executed"], "0")
            self.assertEqual(records["query9", "executed"], "0")
            self.assertEqual(records["run", "proof_queries_finished"], "1")
            self.assertIn(("after", "global"), records)

    def test_full_seventeen_case_summary_and_actual_resource_dispatch(self):
        with tempfile.TemporaryDirectory() as directory:
            evidence, _ = self.prepare_bundle(Path(directory))
            for name in run.CASES:
                case = evidence / "cases" / name
                plan = json.loads((case / "plan.json").read_text())
                (case / "native.tsv").write_text("")
                for label in (plan["goals"] if plan["expected"] == "cex" else plan["covers"]):
                    (case / (label + ".vcd")).write_text("test witness\n")
                receipt = {"command": ["jg", "-no_gui", "-fpv", "-tcl", "collect.tcl"], "pid": 1, "cpu": 0,
                    "launcherSha256": "0" * 64, "inputHashes": {filename: run.digest(case / filename) for filename in plan["inputs"]}}
                if staged.is_staged(plan):
                    receipt.update(cpuCount=16, cpuAffinity=list(range(16)), timeoutSeconds=1080)
                run.write_json(case / "receipt.json", receipt)
                run.write_json(case / "completion.json", {"exitStatus": 0, "timedOut": False, "inputsUnchanged": True,
                    "nativeExecutableSha256": "1" * 64, "outputHashes": run.output_hashes(case)})

            def result(_records, plan):
                fields = {"goals": len(plan["goals"]), "covers": len(plan["covers"]), "verdict": plan["expected"]}
                if staged.is_staged(plan):
                    fields.update(unboundedGoals=17, boundedGoals=4, unboundedHelperGoals=len(staged.HELPERS) + 4)
                return fields

            with patch.object(run, "check_native_records", side_effect=result):
                summary = run.validate_commercial(evidence)
                self.assertEqual(summary["assertionsProven"], 128)
                self.assertEqual(summary["helperAssertionsProven"], 5 * (len(staged.HELPERS) + 4))
                completion_path = evidence / "cases/core-older-safety/completion.json"
                completion = json.loads(completion_path.read_text())
                for status in (False, 0.0):
                    run.write_json(completion_path, {**completion, "exitStatus": status})
                    with self.subTest(exit_status=status), self.assertRaises(ValueError):
                        run.validate_commercial(evidence)
                run.write_json(completion_path, completion)
                path = evidence / "cases/core-older-safety/receipt.json"
                receipt = json.loads(path.read_text())
                receipt["cpuCount"] = 1
                run.write_json(path, receipt)
                with self.assertRaises(ValueError):
                    run.validate_commercial(evidence)


if __name__ == "__main__":
    unittest.main()
