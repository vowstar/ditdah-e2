# SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
# SPDX-License-Identifier: MIT
"""Check frozen formal inputs and reject stale mutation targets."""

import json
import os
from pathlib import Path
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from core_formal import check_inputs, digest, freeze_design, mutate_trap_cancellation, run_case, source_hashes, write_snapshot
from interrupt_formal import mutate_drain, mutate_fault_priority, mutate_local_wake, mutate_saved_pc


class FrozenDesignTests(unittest.TestCase):
    def setUp(self):
        scratch = "/data/tmp" if os.access("/data/tmp", os.W_OK) else None
        self.directory = tempfile.TemporaryDirectory(prefix="ditdah-e2-formal-test-", dir=scratch)
        self.addCleanup(self.directory.cleanup)
        self.work = Path(self.directory.name)
        self.root = self.work / "source"
        self.rtl = self.work / "rtl"
        self.rtl.mkdir()
        for name in ("ditdah_e2/src/Core.scala", "nix/toolchain.nix", "flake.nix", "flake.lock", "scripts/build_rtl.py"):
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("test input\n")
        self.wrapper = self.work / "wrapper.sv"
        self.runner = self.work / "runner.py"
        self.wrapper.write_text("module wrapper; endmodule\n")
        self.runner.write_text("print('test')\n")
        (self.rtl / "DitDahE2.sv").write_text("module DitDahE2; endmodule\n")
        manifest = {"parameters": {"resetVector": 0}, "sourceHashes": source_hashes(self.root),
                    "rtlHashes": {"DitDahE2.sv": digest(self.rtl / "DitDahE2.sv")}}
        (self.rtl / "manifest.json").write_text(json.dumps(manifest))

    def freeze(self):
        return freeze_design(self.rtl, self.root, self.wrapper, self.runner)

    def test_formal_configuration_is_explicit(self):
        path = self.rtl / "manifest.json"
        manifest = json.loads(path.read_text())
        for enabled in (False, True):
            for compressed in (False, True):
                for debug in (False, True):
                    manifest["parameters"] = {"resetVector": 0, "enableM": enabled, "enableC": compressed, "enableDebug": debug}
                    path.write_text(json.dumps(manifest))
                    self.assertEqual(self.freeze()[2]["parameters"], manifest["parameters"])
        for parameters in ({"resetVector": 4}, {"resetVector": False},
                           {"resetVector": 0, "enableM": 1},
                           {"resetVector": 0, "enableC": 1},
                           {"resetVector": 0, "enableDebug": 1}):
            manifest["parameters"] = parameters
            path.write_text(json.dumps(manifest))
            with self.assertRaisesRegex(AssertionError, "configuration"):
                self.freeze()

    def test_bit_configuration_binding(self):
        path = self.rtl / "manifest.json"
        manifest = json.loads(path.read_text())
        for subset in range(8):
            manifest["parameters"].update({"enable" + name: bool(subset & (1 << index))
                for index, name in enumerate(("Zba", "Zbb", "Zbs"))})
            path.write_text(json.dumps(manifest))
            self.assertEqual(self.freeze()[2]["parameters"], manifest["parameters"])
        for key in ("enableZba", "enableZbb", "enableZbs"):
            manifest["parameters"][key] = 1
            path.write_text(json.dumps(manifest))
            with self.assertRaisesRegex(AssertionError, "configuration"):
                self.freeze()
            manifest["parameters"][key] = False

    def test_snapshot_survives_later_source_changes(self):
        manifest, contents, bindings = self.freeze()
        frozen = write_snapshot(self.work / "snapshot", contents)
        (self.root / "ditdah_e2/src/Core.scala").write_text("later implementation\n")
        self.wrapper.write_text("later wrapper\n")
        check_inputs(frozen)
        self.assertEqual(bindings["sourceHashes"], manifest["sourceHashes"])
        self.assertEqual(contents["test/wrapper.sv"], b"module wrapper; endmodule\n")

    def test_snapshot_changes_are_rejected(self):
        _, contents, _ = self.freeze()
        frozen = write_snapshot(self.work / "snapshot", contents)
        path = next(iter(frozen))
        path.write_text("changed\n")
        with self.assertRaisesRegex(RuntimeError, "inputs changed"):
            check_inputs(frozen)

    def test_source_changes_and_new_units_are_rejected(self):
        (self.root / "ditdah_e2/src/New.scala").write_text("new unit\n")
        with self.assertRaisesRegex(AssertionError, "Stale RTL"):
            self.freeze()

    def test_rtl_changes_are_rejected(self):
        (self.rtl / "DitDahE2.sv").write_text("module Changed; endmodule\n")
        with self.assertRaisesRegex(AssertionError, "Changed RTL"):
            self.freeze()

    def test_cover_constraints_do_not_enter_safety_configuration(self):
        output = self.work / "evidence"
        output.mkdir()

        def run(command, cwd, **kwargs):
            (cwd / "run").mkdir()
            (cwd / "run/status").write_text("PASS\n")
            return SimpleNamespace(returncode=0, stdout="test process\n", stderr="")

        rtl = {"DitDahE2.sv": (self.rtl / "DitDahE2.sv").read_bytes()}
        with patch("core_formal.subprocess.run", side_effect=run), patch("builtins.print"):
            safety = run_case(self.work, output, rtl, self.wrapper.name, self.wrapper.read_bytes(),
                              "wrapper", "safety", "bmc", "abc bmc3", 72, parameters=(("SCENARIO", 2),))
            cover = run_case(self.work, output, rtl, self.wrapper.name, self.wrapper.read_bytes(),
                             "wrapper", "cover", "cover", "smtbmc z3", 72)
        self.assertEqual(safety["defines"], [])
        self.assertEqual(safety["parameters"], {"SCENARIO": 2})
        self.assertNotIn("REACHABILITY", (output / "safety.sby").read_text())
        self.assertIn("chparam -set SCENARIO 2 wrapper", (output / "safety.sby").read_text())
        self.assertIn("aigsmt z3", (output / "safety.sby").read_text())
        self.assertNotIn("aigsmt", (output / "cover.sby").read_text())
        archive = output / safety["inputDirectory"]
        self.assertEqual((archive / self.wrapper.name).read_bytes(), self.wrapper.read_bytes())
        self.assertEqual(digest(archive / "run.sby"), safety["inputHashes"]["run.sby"])
        self.assertEqual(cover["defines"], ["REACHABILITY"])

    def test_negative_control_requires_a_property_counterexample(self):
        output = self.work / "negative-evidence"
        output.mkdir()
        rtl = {"DitDahE2.sv": (self.rtl / "DitDahE2.sv").read_bytes()}
        for status, code in (("ERROR", 16), ("FAIL", 2)):
            def run(command, cwd, **kwargs):
                (cwd / "run").mkdir()
                (cwd / "run/status").write_text(status + "\n")
                return SimpleNamespace(returncode=code, stdout="test process\n", stderr="")

            with self.subTest(status=status), patch("core_formal.subprocess.run", side_effect=run), patch("builtins.print"):
                with self.assertRaises(AssertionError):
                    run_case(self.work, output, rtl, self.wrapper.name, self.wrapper.read_bytes(),
                             "wrapper", status.lower(), "bmc", "abc bmc3", 72, mutation=lambda value: value)


class MutationTests(unittest.TestCase):
    def test_trap_mutation_preserves_other_cancellation_causes(self):
        source = "wire redir = trap | interrupt;\nwire guard = redir | returning | waiting | waking;\n" \
                 "xValid <= ~guard & (arrive | ~advance & xValid);\n"
        changed = mutate_trap_cancellation(source)
        self.assertIn("xValid <= ~(interrupt | returning | waiting | waking)", changed)
        extended = source.replace(" | waking", " | waking | synchronized")
        extended += "wire synchronized = complete & m_fenceI & ~failed;\n"
        self.assertIn("waiting | waking | synchronized)", mutate_trap_cancellation(extended))
        debug = source.replace("xValid <= ~guard &", "xValid <=\n  ~(debugStop | debugResume | guard)\n  &")
        self.assertIn("~(debugStop | debugResume | interrupt | returning | waiting | waking)",
                      mutate_trap_cancellation(debug))
        with self.assertRaisesRegex(AssertionError, "semantics"):
            mutate_trap_cancellation(source.replace(" | waking", ""))

    def test_interrupt_mutations_change_only_the_selected_contract(self):
        source = "wire interrupt = ~mValid & eligibleInterrupt;\n" \
                 "wire waking = sleeping_0 & localWake;\n" \
                 ".trapPc (interrupt ? architecturalPc : m_instruction_pc)\n"
        self.assertIn("wire interrupt = eligibleInterrupt;", mutate_drain(source))
        self.assertIn("response & data_response_bits_fault", mutate_fault_priority(source))
        self.assertIn("architecturalPc + 32'h4", mutate_saved_pc(source))
        self.assertIn("sleeping_0 & eligibleInterrupt", mutate_local_wake(source))
        for mutation in (mutate_drain, mutate_fault_priority, mutate_saved_pc, mutate_local_wake):
            with self.assertRaisesRegex(AssertionError, "no longer matches"):
                mutation("module unrelated; endmodule\n")
            with self.assertRaisesRegex(AssertionError, "no longer matches"):
                mutation(source + source)


if __name__ == "__main__":
    unittest.main()
