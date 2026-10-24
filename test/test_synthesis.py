# SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
# SPDX-License-Identifier: MIT
"""Check evidence binding and the remote synthesis input boundary."""

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from run_synthesis import (SITE_KEYS, TransportFailure, checked_status, digest, freeze, freeze_equivalence,
                           log_result, read_metrics, read_proof,
                           relative_name, remote, run_transport, settings, validate_bundle)


class SynthesisInputs(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.addCleanup(self.temporary.cleanup)
        self.rtl = self.root / "default/rtl"
        self.rtl.mkdir(parents=True)
        self.source = self.root / "inputs/design.scala"
        self.source.parent.mkdir()
        self.source.write_text("source snapshot\n")
        (self.rtl / "Core.sv").write_text("module Core(input clock)\nendmodule\n")
        (self.rtl / "filelist.f").write_text("Core.sv\n")
        self.manifest = {
            "exitStatus": 0, "top": "Core", "sourceHashes": {"design.scala": digest(self.source)},
            "rtlHashes": {"Core.sv": digest(self.rtl / "Core.sv")},
        }
        self.acceptance = self.root / "acceptance.json"
        self.budgets = {"period_ns": 1.0, "input_delay_ns": 0.2, "output_delay_ns": 0.2,
                        "uncertainty_ns": 0.05, "input_transition_ns": 0.05,
                        "output_load_ff": 2.0, "threads": 16, "timeout_seconds": 60.0}
        self.evidence()

    def evidence(self):
        (self.rtl / "manifest.json").write_text(json.dumps(self.manifest))
        report = self.root / "default/verification/summary.json"
        report.parent.mkdir(exist_ok=True)
        report.write_text(json.dumps({"exitStatus": 0,
                         "rtlManifestHash": digest(self.rtl / "manifest.json")}))
        self.acceptance.write_text(json.dumps({
            "exitStatus": 0, "sourceHashes": self.manifest["sourceHashes"],
            "sourceSnapshot": "inputs", "checks": [{"configuration": "default",
                                                    "reportHash": digest(report)}],
        }))

    def test_freeze_binds_accepted_snapshot(self):
        output = self.root / "bundle"
        with patch("run_synthesis.ROOT", Path(__file__).resolve().parents[1]):
            result = freeze(self.rtl, self.acceptance, output, self.budgets)
        self.assertEqual(result["inputManifestHash"], digest(output / "inputs.json"))
        validate_bundle(output)
        (output / "rtl/Core.sv").write_text("changed\n")
        with self.assertRaisesRegex(ValueError, "digest differs"):
            validate_bundle(output)

    def test_reject_changed_rtl(self):
        (self.rtl / "Core.sv").write_text("changed\n")
        with self.assertRaisesRegex(ValueError, "RTL input digest"):
            freeze(self.rtl, self.acceptance, self.root / "bundle", self.budgets)

    def mapping_fixture(self):
        source = self.root / "mapping"
        freeze(self.rtl, self.acceptance, source, self.budgets)
        (source / "outputs").mkdir()
        for name in ("mapped.v", "mapped.sdc", "mapping.svf"):
            (source / "outputs" / name).write_text("synthetic mapping input\n")
        (source / "output-manifest.json").write_text(json.dumps({
            "outputs/" + path.name: digest(path) for path in (source / "outputs").iterdir()}))
        (source / "summary.json").write_text(json.dumps({"flowSucceeded": True}))
        return source

    def test_equivalence_freezes_mapping_and_models(self):
        source = self.mapping_fixture()
        model = self.root / "model.db"
        model.write_text("synthetic model\n")
        destination = self.root / "proof"
        destination.mkdir()
        with patch.dict(os.environ, {"E2_TIMING_DBS": str(model)}):
            freeze_equivalence(source, destination, 4, 60)
        validate_bundle(destination)
        model.write_text("later source model\n")
        self.assertEqual((destination / "libraries/model-0.db").read_text(), "synthetic model\n")
        self.assertEqual(digest(destination / "implementation/mapped.v"),
                         digest(source / "outputs/mapped.v"))

    def test_equivalence_rejects_modified_mapping(self):
        source = self.mapping_fixture()
        (source / "outputs/mapped.v").write_text("changed\n")
        destination = self.root / "proof"
        destination.mkdir()
        with self.assertRaisesRegex(ValueError, "Mapping output changed"):
            freeze_equivalence(source, destination, 4, 60)

    def test_equivalence_rejects_failed_mapping(self):
        source = self.mapping_fixture()
        (source / "summary.json").write_text(json.dumps({"flowSucceeded": False}))
        with self.assertRaisesRegex(ValueError, "Completed mapping"):
            freeze_equivalence(source, self.root / "proof", 4, 60)

    def test_reject_changed_accepted_source(self):
        self.source.write_text("changed\n")
        with self.assertRaisesRegex(ValueError, "source snapshot differs"):
            freeze(self.rtl, self.acceptance, self.root / "bundle", self.budgets)

    def test_reject_unbound_report(self):
        report = self.root / "default/verification/summary.json"
        report.write_text(json.dumps({"exitStatus": 0, "rtlManifestHash": "0" * 64}))
        record = json.loads(self.acceptance.read_text())
        record["checks"][0]["reportHash"] = digest(report)
        self.acceptance.write_text(json.dumps(record))
        with self.assertRaisesRegex(ValueError, "does not bind"):
            freeze(self.rtl, self.acceptance, self.root / "bundle", self.budgets)

    def test_reject_duplicate_or_extra_rtl(self):
        for files in ("Core.sv\nCore.sv\n", "Core.sv\nextra.sv\n"):
            (self.rtl / "filelist.f").write_text(files)
            with self.assertRaisesRegex(ValueError, "file list differs"):
                freeze(self.rtl, self.acceptance, self.root / "bundle", self.budgets)

    def test_reject_unlisted_transfer_file(self):
        bundle = self.root / "bundle"
        bundle.mkdir()
        (bundle / "listed.txt").write_text("input\n")
        (bundle / "inputs.json").write_text(json.dumps({"listed.txt": digest(bundle / "listed.txt")}))
        (bundle / "extra.txt").write_text("unlisted\n")
        with self.assertRaisesRegex(ValueError, "Unexpected bundle"):
            validate_bundle(bundle)

    def test_worker_accepts_only_its_supervisor_log(self):
        bundle = self.root / "bundle"
        bundle.mkdir()
        (bundle / "listed.txt").write_text("input\n")
        (bundle / "inputs.json").write_text(json.dumps({"listed.txt": digest(bundle / "listed.txt")}))
        (bundle / "supervisor.log").write_text("")
        validate_bundle(bundle, allowed_extra=("supervisor.log",))
        with self.assertRaisesRegex(ValueError, "Unexpected bundle"):
            validate_bundle(bundle)
        (bundle / "extra.txt").write_text("unlisted\n")
        with self.assertRaisesRegex(ValueError, "Unexpected bundle"):
            validate_bundle(bundle, allowed_extra=("supervisor.log",))

    def test_reject_symlink_transfer(self):
        bundle = self.root / "bundle"
        bundle.mkdir()
        (bundle / "linked.txt").symlink_to(self.source)
        (bundle / "inputs.json").write_text(json.dumps({"linked.txt": digest(self.source)}))
        with self.assertRaisesRegex(ValueError, "digest differs"):
            validate_bundle(bundle)

    def test_reject_invalid_budgets(self):
        for key, value in (("period_ns", 0), ("period_ns", float("nan")),
                           ("output_load_ff", -1), ("threads", 17), ("threads", True)):
            with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                settings(dict(self.budgets, **{key: value}))

    def test_reject_path_escape(self):
        for name in ("../file", "/file", "a/../../file", "a\nfile", None):
            with self.subTest(name=name), self.assertRaises(ValueError):
                relative_name(name)

    def test_remote_exports_do_not_execute_values_or_forward_local_reference(self):
        marker = self.root / "unexpected"
        value = "quote'$(touch " + str(marker) + ")\nline"
        environment = {key: "unused" for key in SITE_KEYS}
        environment.update(EDA_SSH_TARGET="unused", E2_NDM_LIBS=value,
                           EDA_REFERENCE_ROOT="local-only")
        body = "python3 - <<'PYTHON'\nimport json, os\n"
        body += "print('E2_RESULT ' + json.dumps({'value': os.environ['E2_NDM_LIBS'], 'reference': 'EDA_REFERENCE_ROOT' in os.environ}))\nPYTHON\n"
        execute = subprocess.run

        def shell(command, **arguments):
            self.assertEqual(command[0], "ssh")
            arguments["env"] = {"PATH": os.environ["PATH"]}
            return execute(["bash", "-s"], **arguments)

        with patch("run_synthesis.subprocess.run", side_effect=shell):
            result = remote(environment, body)
        self.assertEqual(result, {"value": value, "reference": False})
        self.assertFalse(marker.exists())

    def test_export_only_numeric_report_fields(self):
        report = self.root / "metrics.tsv"
        report.write_text("standard_cells\t12\nsetup_wns_ns\tunavailable\n")
        self.assertEqual(read_metrics(report), {"standard_cells": 12.0,
                         "setup_wns_ns": None, "unconstrained_endpoints": None})
        report.write_text("site_detail\tunused\n")
        with self.assertRaisesRegex(ValueError, "Unexpected report field"):
            read_metrics(report)

    def test_timing_coverage_needs_zero_errors_and_warnings(self):
        report = self.root / "metrics.tsv"
        report.write_text("standard_cells\t12\n")
        self.assertEqual(read_metrics(report, "Errors: 0 Warnings: 0")["unconstrained_endpoints"], 0)
        for text in ("Errors: 0 Warnings: 2", "Warnings: 0", ""):
            self.assertIsNone(read_metrics(report, text)["unconstrained_endpoints"])

    def test_transport_exception_keeps_destination_out_of_public_error(self):
        destination = "synthetic-" + self.root.name + ".invalid"
        environment = {key: "unused" for key in SITE_KEYS}
        environment["EDA_SSH_TARGET"] = destination
        error = subprocess.CalledProcessError(255, ["ssh", destination],
                                              output=destination, stderr=destination)
        with patch("run_synthesis.subprocess.run", side_effect=error):
            with self.assertRaises(TransportFailure) as caught:
                run_transport(environment, "true\n")
        failure = caught.exception
        self.assertEqual(failure.category, "transport_exception")
        self.assertEqual(failure.exit_status, 255)
        self.assertNotIn(destination, str(failure))
        self.assertIn(destination, (failure.record / "exception.txt").read_text())
        self.assertEqual(failure.record.stat().st_mode & 0o777, 0o700)
        self.assertFalse(failure.record == self.root or self.root in failure.record.parents)

    def test_ssh_failure_exports_only_a_fixed_category(self):
        destination = "synthetic-" + self.root.name + ".invalid"
        environment = {key: "unused" for key in SITE_KEYS}
        environment["EDA_SSH_TARGET"] = destination
        process = subprocess.CompletedProcess(["ssh", destination], 255, destination,
                                              "Could not resolve hostname " + destination)
        with patch("run_synthesis.subprocess.run", return_value=process):
            with self.assertRaises(TransportFailure) as caught:
                run_transport(environment, "true\n")
        self.assertEqual(caught.exception.category, "name_resolution")
        self.assertNotIn(destination, str(caught.exception))


class SynthesisEvidence(unittest.TestCase):
    def test_status_rejects_free_text_in_public_fields(self):
        for value in ({"reason": "private diagnostic"}, {"metrics": {"standard_cells": "private"}},
                      {"messageCodes": ["private"]}, {"toolVersion": "private"},
                      {"mappedNetlistHash": "private"}, {"state": "private"}):
            with self.subTest(value=value), self.assertRaises(ValueError):
                checked_status(value)

    def test_proof_requires_explicit_counts(self):
        result = read_proof("Passing Points: 3\nFailing Points: 1\nAborted Points: 2\n",
                            "", 0)
        self.assertEqual(result, {"toolResult": 0, "passing": 3, "failing": 1,
                                  "aborted": 2, "unverified": None, "blackBoxes": None})

    def test_proof_reads_compare_point_totals(self):
        text = "217 Passing compare points\n20 Failing compare points\n0 Aborted compare points\n1720 Unverified compare points\n"
        result = read_proof(text, "No black boxes", 0)
        self.assertEqual(result, {"toolResult": 0, "passing": 217, "failing": 20,
                                  "aborted": 0, "unverified": 1720, "blackBoxes": 0})

    def test_unused_power_models_require_no_netlist_reference(self):
        report = "m unused_cell#PWR_FM_BBOX\n"
        self.assertEqual(read_proof("", report, 1, "module Core(); endmodule")["blackBoxes"], 0)
        self.assertEqual(read_proof("", report, 1, "unused_cell instance();")["blackBoxes"], 1)
        self.assertIsNone(read_proof("", "m unknown_model\n", 1, "")["blackBoxes"])

    def test_tool_exit_does_not_hide_script_errors(self):
        record = log_result("banner\nE2_SCRIPT_BEGIN\nError: failed (CMD-001)\n", 0, True)
        self.assertEqual(record["scriptErrors"], 1)
        self.assertEqual(record["messageCodes"], ["CMD-001"])
        self.assertFalse(record["cleanAcceptance"])

    def test_startup_expiration_is_separate(self):
        record = log_result("This script has expired\nE2_SCRIPT_BEGIN\ncomplete\n", 0, True)
        self.assertTrue(record["startupExpiration"])
        self.assertEqual(record["scriptErrors"], 0)
        self.assertFalse(record["cleanAcceptance"])

    def test_missing_marker_is_not_completion(self):
        record = log_result("banner\n", 0, False)
        self.assertFalse(record["scriptStarted"])
        self.assertFalse(record["scriptCompleted"])


if __name__ == "__main__":
    unittest.main()
