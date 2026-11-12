# SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
# SPDX-License-Identifier: MIT
"""Check Program Buffer core formal inventories and evidence rejection paths."""

import argparse
import copy
import json
import re
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from formal.debug_program_core import run


class DebugProgramCoreFormalTests(unittest.TestCase):
    @staticmethod
    def parameter_evidence(root):
        rtl = {run.RTL_NAME: (b"complete & ~debugBreakpoint & ~driveTrap & ~m_injected;\n"
                              b"~(debugLocal & (debugLocal_0 | debugLocal_1))\n"
                              b".trigger_valid (xValid & ~xInjected)\n"),
               "DitDahE2DebugHart.sv": b"wire core_injection_valid_0 = pendingIssue & ~cancelInjection;"}
        parameters = {**run.REQUIRED_PARAMETERS, "enableZba": False, "enableZbb": False, "enableZbs": False}
        parameters.pop("enableJtag")
        build = {"parameters": parameters, "rtlHashes": {name: run.sha(value) for name, value in rtl.items()}}
        output = root / "evidence"
        args = argparse.Namespace(rtl=root, source_root=root, expected_rtl_sha256=run.sha(rtl[run.RTL_NAME]),
                                  output=output, time_limit=600)
        with patch.object(run, "load_candidate", return_value=(build, rtl)):
            run.prepare_bundle(args)
        return output

    def test_frozen_parameters_accept_the_implemented_profile(self):
        with tempfile.TemporaryDirectory() as directory:
            evidence = self.parameter_evidence(Path(directory))
            manifest = run.validate_frozen(evidence)
            self.assertEqual(manifest["parameters"]["protectedMode"], False)
            self.assertNotIn("enableJtag", manifest["parameters"])

    def test_frozen_parameters_reject_one_sided_or_joint_scope_changes(self):
        mutations = (("protectedMode", True), ("enableM", False), ("triggerCount", 1),
                     ("resetVector", 4), ("protectedMode", 0), ("enableM", 1),
                     ("triggerCount", 2.0), ("resetVector", False), ("enableJtag", True))
        with tempfile.TemporaryDirectory() as directory:
            evidence = self.parameter_evidence(Path(directory))
            original_manifest = json.loads((evidence / "manifest.json").read_text())
            original_build = json.loads((evidence / "rtl-build.json").read_text())
            for sides in ("manifest", "build", "both"):
                for name, value in mutations:
                    with self.subTest(sides=sides, parameter=name, value=value):
                        manifest, build = copy.deepcopy(original_manifest), copy.deepcopy(original_build)
                        if sides in ("manifest", "both"):
                            manifest["parameters"][name] = value
                        if sides in ("build", "both"):
                            build["parameters"][name] = value
                        (evidence / "manifest.json").write_text(json.dumps(manifest))
                        (evidence / "rtl-build.json").write_text(json.dumps(build))
                        with self.assertRaisesRegex(ValueError, "requires"):
                            run.validate_frozen(evidence)

    def test_frozen_parameter_maps_must_match_including_value_types(self):
        for parameters in (None, [], 0, False):
            with self.subTest(parameters=parameters), self.assertRaisesRegex(TypeError, "must be an object"):
                run.check_parameters(parameters)
        with tempfile.TemporaryDirectory() as directory:
            evidence = self.parameter_evidence(Path(directory))
            original = json.loads((evidence / "manifest.json").read_text())
            for name, value in (("enableZba", True), ("enableZba", 0), ("extraOption", False)):
                with self.subTest(parameter=name, value=value):
                    manifest = copy.deepcopy(original)
                    manifest["parameters"][name] = value
                    (evidence / "manifest.json").write_text(json.dumps(manifest))
                    with self.assertRaisesRegex(ValueError, "parameters differ"):
                        run.validate_frozen(evidence)

    def test_cold_reset_contract_has_exact_source_backed_state(self):
        collector = (run.HERE / run.COLLECTOR_NAME).read_bytes()
        run.check_reset_collector(collector)
        expression = re.search(r"assume -reset \{([^\n]+)\}", collector.decode()).group(1)
        facts = re.findall(r"\b(dut\.[A-Za-z0-9_.]+) == 0", expression)
        self.assertEqual(len(facts), 122)
        self.assertEqual(len(set(facts)), 122)
        for name in ("dut.registers", *(f"dut.registers_{index}" for index in range(30))):
            self.assertIn(name, facts)
        for name in run.INITIAL_STATE["unresetPayloadExclusions"]:
            self.assertNotIn(name, facts)
            changed = collector.replace(b"systemReset == 0", ("systemReset == 0 && " + name + " == 0").encode())
            with self.subTest(payload=name), self.assertRaisesRegex(ValueError, "cold-reset contract differs"):
                run.check_reset_collector(changed)
        changed = collector.replace(b" && dut.registers_29 == 0", b"", 1)
        with self.assertRaisesRegex(ValueError, "cold-reset contract differs"):
            run.check_reset_collector(changed)

    def test_initial_state_metadata_rejects_an_old_or_incomplete_scope(self):
        run.check_initial_state(run.INITIAL_STATE)
        mutations = {"initialStateProfile": "previous_scope", "resetFactCount": 112,
                     "resetExpressionSha256": "0" * 64, "unresetPayloadExclusions": []}
        for key, value in mutations.items():
            with self.subTest(field=key):
                changed = copy.deepcopy(run.INITIAL_STATE)
                changed[key] = value
                with self.assertRaisesRegex(ValueError, "initial-state profile differs"):
                    run.check_initial_state(changed)
        with self.assertRaisesRegex(ValueError, "initial-state profile differs"):
            run.check_initial_state({})

    def test_wrapper_inventory_and_binding(self):
        wrapper = (run.HERE / run.WRAPPER_NAME).read_bytes()
        run.check_wrapper(wrapper)
        self.assertEqual(len(run.ASSERTIONS), 7)
        self.assertEqual(len(run.ALL_COVERS), 14)
        self.assertEqual(set(run.COVER_SEQUENCE), set(run.ALL_COVERS) - {run.HELPER_COVER})
        self.assertEqual(len(run.MUTATIONS), 4)
        self.assertIn("dut.csr.trigger.core_valid", wrapper.decode())
        self.assertIn("reg dmi_request_valid = 0", wrapper.decode())
        self.assertIn("if (dmi_pending && phase_done", wrapper.decode())
        self.assertNotIn("end else if (check) begin", wrapper.decode())
        with self.assertRaisesRegex(ValueError, "inventory"):
            run.check_wrapper(wrapper + b"\nextra: assert(1'b1);\n")
        with self.assertRaisesRegex(ValueError, "binding"):
            run.check_wrapper(wrapper.replace(b"DitDahE2 dut (", b"other dut ("))

    def test_mutations_require_unique_targets(self):
        rtl = (b"m_injected <= xInjected;\ncomplete & ~debugBreakpoint & ~driveTrap & ~m_injected;\n"
               b"wire debugLocal = m_injected & m_csr;\n~(debugLocal & (debugLocal_0 | debugLocal_1)),\n"
               b".trigger_valid (xValid & ~xInjected),\n")
        hart = b"wire core_injection_valid_0 = pendingIssue & ~cancelInjection;"
        contents = {run.RTL_NAME: rtl, "DitDahE2DebugHart.sv": hart}
        for name in run.MUTATIONS:
            with self.subTest(name=name):
                changed = run.mutate(contents, name)
                filename = "DitDahE2DebugHart.sv" if name == "deactivate-issue" else run.RTL_NAME
                self.assertNotEqual(changed[filename], contents[filename])
                if name == "injection-identity":
                    self.assertIn(b"m_injected <= xInjected;", changed[filename])
                    self.assertNotIn(b"~driveTrap & ~m_injected", changed[filename])
                if name == "local-csr":
                    self.assertIn(b"wire debugLocal = m_injected & m_csr;", changed[filename])
                    self.assertNotIn(b"~(debugLocal & (debugLocal_0 | debugLocal_1))", changed[filename])
                if name == "deactivate-issue":
                    self.assertIn(b"pendingIssue | cancelInjection", changed[filename])
                with self.assertRaises(ValueError):
                    run.mutate({run.RTL_NAME: b"", "DitDahE2DebugHart.sv": b""}, name)

    def test_cases_bind_negative_targets_and_proof_modes(self):
        rtl = {run.RTL_NAME: (b"m_injected <= xInjected;\ncomplete & ~debugBreakpoint & ~driveTrap & ~m_injected;\nwire debugLocal = m_injected & m_csr;\n"
                              b"~(debugLocal & (debugLocal_0 | debugLocal_1)),\n.trigger_valid (xValid & ~xInjected),\n"),
               "DitDahE2DebugHart.sv": b"wire core_injection_valid_0 = pendingIssue & ~cancelInjection;"}
        wrapper = (run.HERE / run.WRAPPER_NAME).read_bytes()
        collector = (run.HERE / run.COLLECTOR_NAME).read_bytes()
        for name in run.CASES:
            with self.subTest(name=name):
                plan, contents = run.case_definition(name, rtl, wrapper, collector, 600)
                self.assertEqual(plan["timeLimitSeconds"], 600)
                self.assertEqual(plan["traceBound"], 512)
                self.assertIn(b"set trace_bound 512\nset stage_bound 96\nset stage_time_limit 240\n", contents["plan.tcl"])
                self.assertEqual(set(plan["inputs"]), set(contents))
                self.assertEqual(plan["traceEngineMode"], run.TRACE_ENGINES)
                self.assertIn(f"set trace_engines {run.TRACE_ENGINES}\n".encode(), contents["plan.tcl"])
                self.assertEqual(plan["coverSequence"], list(run.COVER_SEQUENCE) if name == "covers" else [])
                stages = list(run.NEGATIVE_STAGES.get(name.removeprefix("negative-"), ()))
                self.assertEqual(plan["negativeStages"], stages)
                self.assertIn(f"set negative_stages {{{' '.join(stages)}}}\n".encode(), contents["plan.tcl"])
                if name.startswith("negative-"):
                    mutation = name.removeprefix("negative-")
                    self.assertEqual(plan["goals"], [run.MUTATIONS[mutation]])
                    self.assertEqual(plan["expected"], "cex")
                    self.assertEqual(plan["proofMode"], "trace_commercial")
                    self.assertNotIn("negativePrefix", plan)
                    self.assertNotIn(b"negative_prefix", contents["plan.tcl"])
                elif name == "safety":
                    self.assertEqual(plan["goals"], list(run.ASSERTIONS))
                    self.assertEqual(plan["proofMode"], "unbounded_commercial")
                    self.assertEqual(plan["covers"], [])
                else:
                    self.assertEqual(plan["covers"], list(run.COVERS))
                    self.assertNotIn(run.HELPER_COVER, plan["covers"])

    def test_candidate_rejects_wrong_identity(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            (path / "manifest.json").write_text(json.dumps({"top": "other", "parameters": {}}))
            with self.assertRaisesRegex(ValueError, "complete RTL"):
                run.load_candidate(path, path, "0" * 64)

    def test_records_require_initial_reset_and_declared_state(self):
        with self.assertRaisesRegex(ValueError, "initial cold reset"):
            run.check_records({}, {"proofMode": "unbounded_commercial"})
        records = {
            ("before", run.INITIAL_ASSUMPTION): "1",
            ("after", run.INITIAL_ASSUMPTION): "1",
            ("before", "reset_initial"): "none",
        }
        with self.assertRaisesRegex(ValueError, "reset_initial"):
            run.check_records(records, {"proofMode": "unbounded_commercial"})

    def test_final_verdict_does_not_require_redundant_before_metadata(self):
        records = {
            ("setup", "bbox_inst"): "0", ("setup", "bbox_mod"): "0",
            ("setup", "bbox_out"): "0", ("setup", "stopat"): "0",
            ("setup", "clock_mode"): "free_running", ("run", "state"): "complete",
            ("before", run.INITIAL_ASSUMPTION): "1", ("after", run.INITIAL_ASSUMPTION): "1",
            ("before", "reset_initial"): "assume:0", ("after", "reset_initial"): "assume:0",
            ("before", "reset"): run.native.EXPECTED_RESET, ("after", "reset"): run.native.EXPECTED_RESET,
            ("before", "reset_assumptions"): "known_state", ("after", "reset_assumptions"): "known_state",
            ("before", "global"): f"{run.TOP}.{run.INITIAL_ASSUMPTION} {run.TOP}.no_later_cold_reset",
            ("after", "global"): f"{run.TOP}.{run.INITIAL_ASSUMPTION} {run.TOP}.no_later_cold_reset",
            ("before", "assumptions"): f"{run.TOP}.no_later_cold_reset",
            ("after", "assumptions"): f"{run.TOP}.no_later_cold_reset",
            ("before", "clock"): "", ("after", "clock"): "",
        }
        plan = {"top": run.TOP, "goals": ["injected_not_native_retire"], "covers": [],
                "assumptions": [f"{run.TOP}.no_later_cold_reset"],
                "expected": "proven", "proofMode": "unbounded_commercial"}
        records.update({("final.injected_not_native_retire", key): value for key, value in {
            "name": f"{run.TOP}.injected_not_native_retire", "type": "assert", "command": "assert",
            "disabled": "0", "run_status": "processed", "validity_status": "proven",
            "expression": "injected_not_native_retire", "precondition": "0"}.items()})
        self.assertEqual(run.check_records(records, plan)["goals"], 1)
        records[("final.injected_not_native_retire", "validity_status")] = "undetermined"
        with self.assertRaisesRegex(ValueError, "final assertion"):
            run.check_records(records, plan)


if __name__ == "__main__":
    unittest.main()
