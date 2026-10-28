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
from run_synthesis import (SITE_KEYS, TransportFailure, artifact_hashes, checked_status, digest, freeze, freeze_equivalence,
                           log_result, read_metrics, read_proof,
                           relative_name, remote, run_transport, settings, technology_library_index,
                           validate_bundle, write_settings)


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

    def profile_evidence(self):
        self.manifest["parameters"] = {}
        self.evidence()
        result = self.root / "default/result"
        result.mkdir()
        self.rtl.rename(result / "rtl")
        self.rtl = result / "rtl"
        (self.root / "default/verification").rename(result / "verification")
        source = self.root / "default/source/design.scala"
        source.parent.mkdir()
        source.write_bytes(self.source.read_bytes())
        (result / "formal.log").write_text("checked synthetic proof input\n")
        self.acceptance.write_text(json.dumps({
            "exitStatus": 0,
            "profiles": [{"name": "default", "exitStatus": 0,
                          "parameters": self.manifest.get("parameters"),
                          "rtlHashes": self.manifest["rtlHashes"]}],
            "artifactHashes": {str(path.relative_to(self.root)): digest(path)
                               for path in (self.root / "default").rglob("*") if path.is_file()},
        }))

    def test_freeze_binds_profile_acceptance(self):
        self.profile_evidence()
        output = self.root / "bundle"
        freeze(self.rtl, self.acceptance, output, self.budgets)
        validate_bundle(output)
        self.assertEqual(digest(output / "evidence/acceptance.json"), digest(self.acceptance))

    def test_profile_rejects_changed_proof_artifact(self):
        self.profile_evidence()
        (self.root / "default/result/formal.log").write_text("changed proof input\n")
        with self.assertRaisesRegex(ValueError, "artifact changed"):
            freeze(self.rtl, self.acceptance, self.root / "bundle", self.budgets)

    def test_profile_requires_source_in_artifact_manifest(self):
        self.profile_evidence()
        record = json.loads(self.acceptance.read_text())
        del record["artifactHashes"]["default/source/design.scala"]
        self.acceptance.write_text(json.dumps(record))
        with self.assertRaisesRegex(ValueError, "missing required artifacts"):
            freeze(self.rtl, self.acceptance, self.root / "bundle", self.budgets)

    def test_profile_rejects_failed_gate(self):
        self.profile_evidence()
        record = json.loads(self.acceptance.read_text())
        record["profiles"][0]["exitStatus"] = 1
        self.acceptance.write_text(json.dumps(record))
        with self.assertRaisesRegex(ValueError, "does not bind"):
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

    def test_equivalence_binds_reports_and_tool_log(self):
        source = self.mapping_fixture()
        (source / "reports").mkdir()
        (source / "reports/timing-check.txt").write_text("Warnings: 2\n")
        (source / "tool.log").write_text("recorded tool execution\n")
        outputs = artifact_hashes(source)
        self.assertEqual(set(outputs), {"outputs/mapped.v", "outputs/mapped.sdc", "outputs/mapping.svf",
                                       "reports/timing-check.txt", "tool.log"})
        (source / "output-manifest.json").write_text(json.dumps(outputs))
        model = self.root / "model.db"
        model.write_text("synthetic model\n")
        destination = self.root / "proof"
        destination.mkdir()
        with patch.dict(os.environ, {"E2_TIMING_DBS": str(model)}):
            freeze_equivalence(source, destination, 4, 60)
        frozen = json.loads((destination / "evidence/synthesis-outputs.json").read_text())
        self.assertEqual(frozen, outputs)
        validate_bundle(destination)

    def test_equivalence_rejects_changed_bound_reports_and_log(self):
        source = self.mapping_fixture()
        (source / "reports").mkdir()
        files = ("reports/timing-check.txt", "tool.log")
        for name in files:
            (source / name).write_text("original\n")
        (source / "output-manifest.json").write_text(json.dumps(artifact_hashes(source)))
        model = self.root / "model.db"
        model.write_text("synthetic model\n")
        for name in files:
            with self.subTest(name=name):
                (source / name).write_text("changed\n")
                destination = self.root / ("proof-" + name.replace("/", "-"))
                with patch.dict(os.environ, {"E2_TIMING_DBS": str(model)}):
                    with self.assertRaisesRegex(ValueError, "Mapping output changed"):
                        freeze_equivalence(source, destination, 4, 60)
                (source / name).write_text("original\n")

    def test_equivalence_rejects_failed_mapping(self):
        source = self.mapping_fixture()
        (source / "summary.json").write_text(json.dumps({"flowSucceeded": False}))
        with self.assertRaisesRegex(ValueError, "Completed mapping"):
            freeze_equivalence(source, self.root / "proof", 4, 60)

    def test_equivalence_preserves_guidance_order(self):
        source = self.mapping_fixture()
        (source / "outputs/physical.svf").write_text("synthetic physical guidance\n")
        config = json.loads((source / "configuration.json").read_text())
        config["guidance_outputs"] = ["mapping.svf", "physical.svf"]
        (source / "configuration.json").write_text(json.dumps(config))
        inputs = json.loads((source / "inputs.json").read_text())
        inputs["configuration.json"] = digest(source / "configuration.json")
        (source / "inputs.json").write_text(json.dumps(inputs))
        outputs = json.loads((source / "output-manifest.json").read_text())
        outputs["outputs/physical.svf"] = digest(source / "outputs/physical.svf")
        (source / "output-manifest.json").write_text(json.dumps(outputs))
        model = self.root / "model.db"
        model.write_text("synthetic model\n")
        destination = self.root / "proof"
        destination.mkdir()
        with patch.dict(os.environ, {"E2_TIMING_DBS": str(model)}):
            freeze_equivalence(source, destination, 4, 60)
        frozen = json.loads((destination / "configuration.json").read_text())
        self.assertEqual(frozen["guidance_files"], ["implementation/mapping.svf", "implementation/physical.svf"])
        validate_bundle(destination)

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

    def technology_probe(self, index):
        bundle = self.root / "technology-bundle"
        freeze(self.rtl, self.acceptance, bundle,
               dict(self.budgets, technology_library_index=index))
        config = json.loads((bundle / "configuration.json").read_text())
        write_settings(bundle / "settings.tcl", config, 1)
        (bundle / "reports").mkdir()
        probe = bundle / "probe.tcl"
        probe.write_text("""proc set_host_options {args} {}
proc create_lib {args} {
    set position [lsearch -exact $args -use_technology_lib]
    set output [open selected-technology.txt w]
    puts $output [lindex $args [expr {$position + 1}]]
    close $output
    error {binding probe complete}
}
source flow/synthesis.tcl
""")
        result = subprocess.run(["tclsh", str(probe)], cwd=bundle,
                                env=dict(os.environ, E2_NDM_LIBS="cells.ndm\ntechnology.ndm"),
                                capture_output=True, text=True)
        return bundle, config, result

    def test_freezes_and_selects_nonfirst_technology_library(self):
        bundle, config, result = self.technology_probe(1)
        self.assertEqual(config["technology_library_index"], 1)
        self.assertEqual((bundle / "selected-technology.txt").read_text(), "technology.ndm\n")
        self.assertEqual((bundle / "reports/flow-error.txt").read_text().splitlines()[0],
                         "binding probe complete")
        self.assertEqual(result.returncode, 1)

    def test_rejects_technology_index_outside_site_references(self):
        bundle, _, result = self.technology_probe(2)
        self.assertEqual(result.returncode, 1)
        self.assertFalse((bundle / "selected-technology.txt").exists())
        self.assertEqual((bundle / "reports/flow-error.txt").read_text().splitlines()[0],
                         "Technology library index is outside the reference list")

    def test_legacy_configuration_selects_first_technology_library(self):
        self.assertEqual(technology_library_index(self.budgets, 2), 0)
        write_settings(self.root / "legacy-settings.tcl",
                       dict(self.budgets, rtl_files=["Core.sv"]), 1)
        self.assertIn("set technology_library_index 0\n",
                      (self.root / "legacy-settings.tcl").read_text())

    def test_rejects_invalid_technology_index(self):
        for value in (-1, True, 1.5, "1"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                settings(dict(self.budgets, technology_library_index=value))
        with self.assertRaises(ValueError):
            technology_library_index({"technology_library_index": 0}, 0)

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

    def test_physical_module_is_forwarded_only_when_requested(self):
        environment = {key: "unused" for key in SITE_KEYS}
        environment.update(EDA_SSH_TARGET="unused", CALIBRE_MODULE="synthetic-module")
        body = "python3 - <<'PYTHON'\nimport json, os\n"
        body += "print('E2_RESULT ' + json.dumps({'physical': os.environ.get('CALIBRE_MODULE')}))\nPYTHON\n"
        execute = subprocess.run

        def shell(command, **arguments):
            self.assertEqual(command[0], "ssh")
            arguments["env"] = {"PATH": os.environ["PATH"]}
            return execute(["bash", "-s"], **arguments)

        with patch("run_synthesis.subprocess.run", side_effect=shell):
            self.assertEqual(remote(environment, body), {"physical": None})
            self.assertEqual(remote(environment, body, extra_keys=("CALIBRE_MODULE",)),
                             {"physical": "synthetic-module"})

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

    def test_zero_proof_counts_need_their_own_reports(self):
        reports = {name: "There are no " + name + " compare points."
                   for name in ("failing", "aborted", "unverified")}
        result = read_proof("1957 Passing compare points", "No black boxes", 1,
                            point_reports=reports)
        self.assertEqual(result, {"toolResult": 1, "passing": 1957, "failing": 0,
                                  "aborted": 0, "unverified": 0, "blackBoxes": 0})

    def test_unused_power_models_require_no_netlist_reference(self):
        report = "m unused_cell#PWR_FM_BBOX\n"
        self.assertEqual(read_proof("", report, 1, "module Core(); endmodule")["blackBoxes"], 0)
        self.assertEqual(read_proof("", report, 1, "unused_cell instance();")["blackBoxes"], 1)
        self.assertIsNone(read_proof("", "m unknown_model\n", 1, "")["blackBoxes"])
        self.assertIsNone(read_proof("", report + "s hidden_core\n", 1, "module Core(); endmodule")["blackBoxes"])
        self.assertIsNone(read_proof("", report, 1, "")["blackBoxes"])
        self.assertEqual(read_proof("", "e empty_cell\n", 1, "empty_cell instance();")["blackBoxes"], 1)
        self.assertEqual(read_proof("", report + "e empty_cell\n", 1, "module Core(); endmodule")["unusedLibraryModels"], 2)

    def test_tool_exit_does_not_hide_script_errors(self):
        for prefix in ("Error", "ERROR", "error"):
            with self.subTest(prefix=prefix):
                record = log_result("banner\nE2_SCRIPT_BEGIN\n" + prefix + ": failed (CMD-001)\n", 0, True)
                self.assertEqual(record["scriptErrors"], 1)
                self.assertEqual(record["messageCodes"], ["CMD-001"])
                self.assertFalse(record["flowSucceeded"])
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
