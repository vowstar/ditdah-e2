# SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
# SPDX-License-Identifier: MIT
"""Bind physical implementation to the proven mapping and library inputs."""

import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from run_physical import freeze_physical, validate_limits
from run_synthesis import artifact_hashes, digest, validate_bundle, write_json


class PhysicalInputs(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.source = self.root / "source"
        self.proof = self.root / "proof"
        self.run = self.root / "candidate"
        for name in ("rtl/Core.sv", "evidence/manifest.json", "flow/synthesis_constraints.tcl",
                     "outputs/mapped.v", "outputs/mapped.sdc", "outputs/complete", "outputs/mapping.svf", "outputs/design.ndm/block/data"):
            path = self.source / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("synthetic input\n")
        (self.source / "outputs/complete").write_text("logic_opto\n")
        self.budgets = {"period_ns": 1.0, "input_delay_ns": 0.2, "output_delay_ns": 0.2,
                        "uncertainty_ns": 0.05, "input_transition_ns": 0.05, "output_load_ff": 2.0,
                        "threads": 16, "timeout_seconds": 60.0, "rtl_files": ["Core.sv"], "top": "Core"}
        write_json(self.source / "configuration.json", self.budgets)
        write_json(self.source / "inputs.json", {
            str(p.relative_to(self.source)): digest(p) for p in self.source.rglob("*")
            if p.is_file() and "outputs" not in p.parts})
        write_json(self.source / "output-manifest.json", {
            str(p.relative_to(self.source)): digest(p)
            for p in (self.source / "outputs").rglob("*") if p.is_file()})
        write_json(self.source / "summary.json", {"flowSucceeded": True})
        self.libraries = [{"path": "synthetic.ndm/data", "sha256": "1" * 64}]
        write_json(self.source / "library-inputs.json", self.libraries)
        (self.proof / "evidence").mkdir(parents=True)
        (self.proof / "outputs").mkdir()
        (self.proof / "evidence/synthesis-inputs.json").write_bytes((self.source / "inputs.json").read_bytes())
        (self.proof / "evidence/synthesis-outputs.json").write_bytes((self.source / "output-manifest.json").read_bytes())
        (self.proof / "outputs/result.txt").write_text("1\n")
        write_json(self.proof / "inputs.json", {
            "evidence/synthesis-inputs.json": digest(self.proof / "evidence/synthesis-inputs.json"),
            "evidence/synthesis-outputs.json": digest(self.proof / "evidence/synthesis-outputs.json")})
        write_json(self.proof / "output-manifest.json", {
            "outputs/result.txt": digest(self.proof / "outputs/result.txt")})
        self.verification = {
            "flowSucceeded": True, "mappedEquivalence": "passed", "frozenInputsStable": True,
            "mappedNetlistHash": digest(self.source / "outputs/mapped.v"),
            "constraintsHash": digest(self.source / "outputs/mapped.sdc"),
            "guidanceHashes": [digest(self.source / "outputs/mapping.svf")],
            "proof": {"toolResult": 1, "passing": 20, "failing": 0, "aborted": 0,
                      "unverified": 0, "blackBoxes": 0},
        }
        write_json(self.proof / "summary.json", self.verification)
        (self.run / "flow").mkdir(parents=True)

    def freeze(self, margin=0.0):
        with patch("run_physical.library_snapshot", return_value=self.libraries):
            freeze_physical(self.source, self.proof, self.run, 1.5, 8, 120, "VDD", "VSS", margin)

    def test_preserves_interface_budgets_and_proof_binding(self):
        self.freeze()
        config = json.loads((self.run / "configuration.json").read_text())
        for key in ("input_delay_ns", "output_delay_ns", "uncertainty_ns", "input_transition_ns", "output_load_ff"):
            self.assertEqual(config[key], self.budgets[key])
        self.assertEqual(config["period_ns"], 1.5)
        self.assertEqual(config["guidance_outputs"], ["mapping.svf", "physical.svf"])
        validate_bundle(self.run)
        (self.run / "checkpoint/design.ndm/block/data").write_text("candidate change\n")
        self.assertEqual((self.source / "outputs/design.ndm/block/data").read_text(), "synthetic input\n")
        with self.assertRaisesRegex(ValueError, "digest differs"):
            validate_bundle(self.run)

    def test_requires_complete_equivalence(self):
        self.verification["proof"]["unverified"] = 1
        write_json(self.proof / "summary.json", self.verification)
        with self.assertRaisesRegex(ValueError, "Mapped equivalence"):
            self.freeze()

    def test_rejects_another_mapping(self):
        self.verification["mappedNetlistHash"] = "0" * 64
        write_json(self.proof / "summary.json", self.verification)
        with self.assertRaisesRegex(ValueError, "Proof does not bind"):
            self.freeze()

    def test_rejects_changed_checkpoint(self):
        (self.source / "outputs/design.ndm/block/data").write_text("changed\n")
        with self.assertRaisesRegex(ValueError, "Frozen source changed"):
            self.freeze()

    def test_rejects_changed_bound_report(self):
        (self.source / "reports").mkdir()
        report = self.source / "reports/legality.txt"
        report.write_text("Total violations: 0\n")
        write_json(self.source / "output-manifest.json", artifact_hashes(self.source))
        (self.proof / "evidence/synthesis-outputs.json").write_bytes((self.source / "output-manifest.json").read_bytes())
        write_json(self.proof / "inputs.json", {
            str(p.relative_to(self.proof)): digest(p)
            for p in (self.proof / "evidence").iterdir()})
        report.write_text("Total violations: 1\n")
        with self.assertRaisesRegex(ValueError, "Frozen source changed"):
            self.freeze()

    def test_rejects_unlisted_checkpoint_file(self):
        (self.source / "outputs/design.ndm/extra").write_text("extra\n")
        with self.assertRaisesRegex(ValueError, "saved mapped checkpoint"):
            self.freeze()

    def test_rejects_changed_library(self):
        with patch("run_physical.library_snapshot", return_value=[]):
            with self.assertRaisesRegex(ValueError, "library inputs changed"):
                freeze_physical(self.source, self.proof, self.run, 1.5, 8, 120, "VDD", "VSS")

    def clocked_source(self, label="clock_opt"):
        (self.source / "outputs/complete").write_text(label + "\n")
        (self.source / "outputs/physical.svf").write_text("physical guidance\n")
        config = json.loads((self.source / "configuration.json").read_text())
        config["guidance_outputs"] = ["mapping.svf", "physical.svf"]
        config["period_ns"] = 1.5
        write_json(self.source / "configuration.json", config)
        inputs = json.loads((self.source / "inputs.json").read_text())
        write_json(self.source / "inputs.json", {name: digest(self.source / name) for name in inputs})
        write_json(self.source / "output-manifest.json", {str(p.relative_to(self.source)): digest(p)
                   for p in (self.source / "outputs").rglob("*") if p.is_file()})
        for name, target in (("inputs.json", "synthesis-inputs.json"), ("output-manifest.json", "synthesis-outputs.json")):
            (self.proof / "evidence" / target).write_bytes((self.source / name).read_bytes())
        write_json(self.proof / "inputs.json", {str(p.relative_to(self.proof)): digest(p)
                   for p in (self.proof / "evidence").iterdir()})
        self.verification["guidanceHashes"].append(digest(self.source / "outputs/physical.svf"))
        write_json(self.proof / "summary.json", self.verification)

    def test_first_clock_optimization_can_use_hold_margin(self):
        self.freeze(0.005)
        config = json.loads((self.run / "configuration.json").read_text())
        self.assertEqual(config["input_label"], "logic_opto")
        self.assertEqual(config["output_label"], "clock_opt")
        self.assertEqual(config["guidance_outputs"], ["mapping.svf", "physical.svf"])
        self.assertEqual(config["hold_margin_ns"], 0.005)
        validate_bundle(self.run)

    def test_rejects_repeated_clock_optimization(self):
        self.clocked_source()
        with self.assertRaisesRegex(ValueError, "cannot be repeated"):
            self.freeze(0.005)

    def test_rejects_changed_constraints_and_guidance(self):
        for key, value in (("constraintsHash", "0" * 64), ("guidanceHashes", ["0" * 64])):
            original = self.verification[key]
            self.verification[key] = value
            write_json(self.proof / "summary.json", self.verification)
            with self.assertRaisesRegex(ValueError, "bind"):
                self.freeze()
            self.verification[key] = original

    def test_rejects_changed_output_manifest(self):
        (self.source / "outputs/mapping.svf").write_text("changed guidance\n")
        outputs = json.loads((self.source / "output-manifest.json").read_text())
        outputs["outputs/mapping.svf"] = digest(self.source / "outputs/mapping.svf")
        write_json(self.source / "output-manifest.json", outputs)
        with self.assertRaisesRegex(ValueError, "bind"):
            self.freeze()

    def test_existing_path_margins_are_not_removed(self):
        (self.source / "outputs/mapped.sdc").write_text("set_path_margin -hold 0.01\n")
        self.verification["constraintsHash"] = digest(self.source / "outputs/mapped.sdc")
        self.clocked_source("logic_opto")
        with self.assertRaisesRegex(ValueError, "preservation plan"):
            self.freeze(0.005)

    def test_rejects_invalid_hold_margin(self):
        for margin in (-1, 2, float("nan"), True):
            with self.assertRaises(ValueError):
                validate_limits(1.5, 8, 120, "VDD", "VSS", margin)

    def test_rejects_unbounded_resources_and_invalid_supply_names(self):
        for values in ((1.5, 17, 120, "VDD", "VSS"), (float("nan"), 8, 120, "VDD", "VSS"),
                       (1.5, 8, 0, "VDD", "VSS"), (1.5, 8, 120, "VDD", "VDD"),
                       (1.5, 8, 120, "[exec anything]", "VSS")):
            with self.subTest(values=values), self.assertRaises(ValueError):
                validate_limits(*values)


if __name__ == "__main__":
    unittest.main()
