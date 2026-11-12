# SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
# SPDX-License-Identifier: MIT
"""Check Program Buffer formal inventories, mutations, and frozen evidence."""

import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from formal.debug_program_hart import run

SOURCE = """module DitDahE2DebugHart(
);
wire startProgram_0, pendingIssue, injecting, cancelInjection, waiting, owner;
wire [31:0] program0, program1;
wire [2:0] slot;
wire finishingInjection_1 = core_injectionDone_fault | core_injectionDone_ebreak;
assign backend_writePulse =
  startProgram & format & ~memory & debug_request_bits_transfer & write;
assign core_injection_bits_truncated = _GEN_123 & (&(raw[1:0]));
assign debug_response_valid = debug_response_valid_0;
assign memory_response_ready = waiting;
always @(posedge clock) begin
  program1 <= debug_request_bits_program1;
end
assign word = condition ? {program1[15:0], program0[31:16]} : 32'h100073;
endmodule
"""


class DebugProgramHartFormalTests(unittest.TestCase):
    def test_wrapper_inventory_and_binding(self):
        wrapper = (run.HERE / run.WRAPPER_NAME).read_bytes()
        run.check_wrapper(wrapper)
        self.assertEqual(len(run.ASSERTIONS), 26)
        self.assertEqual(len(run.COVERS), 13)
        self.assertEqual(len(run.MUTATIONS), 8)
        text = wrapper.decode()
        self.assertIn("function automatic [31:0] program_word", text)
        self.assertNotIn("input [2:0] sequence,", text)
        self.assertNotIn(run.INITIAL_ASSUMPTION, run.ASSUMPTIONS)
        collector = (run.HERE / run.COLLECTOR_NAME).read_text()
        self.assertIn("assume -env -name initial_common_cold_reset -bound 1 {reset}", collector)
        self.assertIn("assume -name no_later_cold_reset {initialized |=> !reset}", collector)
        self.assertIn("clock clock\n", collector)
        self.assertIn("reset -none\n", collector)
        self.assertNotIn("clock -none", collector)
        self.assertNotIn("reset -expression reset", collector)
        with self.assertRaisesRegex(ValueError, "inventory"):
            run.check_wrapper(wrapper + b"\nextra: assert(1'b1);\n")
        with self.assertRaisesRegex(ValueError, "binding"):
            run.check_wrapper(wrapper.replace(b"DitDahE2DebugHart dut (.*);", b"other dut (.*);"))

    def test_mutations_require_unique_targets(self):
        for name in run.MUTATIONS:
            with self.subTest(name=name):
                changed = run.mutate(SOURCE.encode(), name)
                self.assertNotEqual(changed, SOURCE.encode())
                with self.assertRaises(ValueError):
                    run.mutate(b"", name)
                with self.assertRaises(ValueError):
                    run.mutate((SOURCE + SOURCE).encode(), name)

    def test_cases_bind_one_negative_target(self):
        rtl = {run.RTL_NAME: SOURCE.encode()}
        wrapper = (run.HERE / run.WRAPPER_NAME).read_bytes()
        collector = (run.HERE / run.COLLECTOR_NAME).read_bytes()
        for name in run.CASES:
            with self.subTest(name=name):
                plan, contents = run.case_definition(name, rtl, wrapper, collector, 120)
                self.assertEqual(plan["timeLimitSeconds"], 120)
                self.assertEqual(set(plan["inputs"]), set(contents))
                self.assertNotIn(run.TOP + "." + run.INITIAL_ASSUMPTION, plan["assumptions"])
                if name.startswith("negative-"):
                    self.assertEqual(plan["goals"], [run.MUTATIONS[name.removeprefix("negative-")]])
                    self.assertEqual(plan["expected"], "cex")
                elif name == "safety":
                    self.assertEqual(plan["goals"], list(run.ASSERTIONS))
                    self.assertEqual(plan["expected"], "proven")
                else:
                    self.assertEqual(plan["covers"], list(run.COVERS))

    def test_frozen_bundle_is_self_contained_and_tamper_evident(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            build = root / "build"
            rtl = build / "rtl"
            rtl.mkdir(parents=True)
            (rtl / run.RTL_NAME).write_text(SOURCE)
            digest = hashlib.sha256(SOURCE.encode()).hexdigest()
            report = {
                "exitStatus": 0,
                "parameters": {"resetVector": 0, "enableC": True, "protectedMode": False},
                "rtlHashes": {run.RTL_NAME: digest},
                "inputHashes": {},
            }
            (build / "build.json").write_text(json.dumps(report))
            evidence = root / "evidence"
            args = SimpleNamespace(rtl=build, source_root=root, expected_rtl_sha256=digest,
                                   output=evidence, time_limit=120)
            run.prepare_bundle(args)
            run.validate_frozen(evidence)
            self.assertEqual((evidence / "runner.py").read_bytes(), Path(run.__file__).read_bytes())
            self.assertEqual((evidence / "native.py").read_bytes(), Path(run.native.__file__).read_bytes())
            target = evidence / "cases" / "safety" / run.WRAPPER_NAME
            target.write_bytes(target.read_bytes() + b"\n")
            with self.assertRaisesRegex(ValueError, "Frozen native proof input differs"):
                run.validate_frozen(evidence)

    def test_record_validation_rejects_scope_drift_and_undetermined(self):
        label = "transfer_zero_no_backend_write"
        plan = {"top": run.TOP, "goals": [label], "covers": [], "expected": "proven",
                "assumptions": [run.qualified(name) for name in run.ASSUMPTIONS]}
        global_assumptions = " ".join(run.qualified(name) for name in
                                      (run.INITIAL_ASSUMPTION, *run.ASSUMPTIONS)
                                      if name != "no_later_cold_reset")
        records = {("run", "state"): "complete", ("setup", "clock_mode"): "single_posedge"}
        for key in ("bbox_inst", "bbox_mod", "bbox_out", "stopat"):
            records[("setup", key)] = "0"
        for tag in ("before", "after"):
            records[(tag, "clock")] = run.EXPECTED_CLOCK
            records[(tag, "reset")] = run.EXPECTED_RESET_SCOPE
            records[(tag, "global")] = global_assumptions
            records[(tag, "reset_assumptions")] = ""
            records[(tag, "assumptions")] = " ".join(sorted(plan["assumptions"]))
            records[(tag, run.INITIAL_ASSUMPTION)] = "1"
        metadata = {"name": run.TOP + "." + label, "type": "assert", "command": "assert",
                    "disabled": "0", "run_status": "processed", "validity_status": "proven",
                    "expression": label, "precondition": "0", "clock": "clock", "edge": "posedge"}
        for tag in ("before." + label, "final." + label):
            for key, value in metadata.items():
                records[(tag, key)] = value
        self.assertEqual(run.check_records(records, plan)["goals"], 1)
        for key, value in ((("before", "clock"), "clock"),
                           (("before", "reset"), run.native.EXPECTED_RESET)):
            changed = dict(records)
            changed[key] = value
            with self.assertRaisesRegex(ValueError, "scope differs"):
                run.check_records(changed, plan)
        changed = dict(records)
        changed[("final." + label, "validity_status")] = "undetermined"
        with self.assertRaisesRegex(ValueError, "no matching proof verdict"):
            run.check_records(changed, plan)

    def test_collect_delegates_only_expected_native_scope_errors(self):
        with tempfile.TemporaryDirectory() as directory:
            case = Path(directory)
            (case / "plan.json").write_text("{}\n")
            with patch.object(run.native, "collect_case",
                              side_effect=ValueError("Native clock environment is not free-running")), \
                    patch.object(run.native, "read_records", return_value="records"), \
                    patch.object(run, "check_records", return_value={"goals": 1}):
                self.assertEqual(run.collect_case(case, None, None, 1), {"goals": 1})
            with patch.object(run.native, "collect_case",
                              side_effect=ValueError("case: native execution timed out")), \
                    self.assertRaisesRegex(ValueError, "timed out"):
                run.collect_case(case, None, None, 1)


if __name__ == "__main__":
    unittest.main()
