# SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
# SPDX-License-Identifier: MIT
"""Check compressed fetch proof inputs and semantic mutation selection."""

import hashlib
import json
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from compressed_fetch_formal import execute, freeze, mutate, observe, source_hashes, verification_cases


def example_rtl():
    flags = ("outstanding", "held", "heldDiscarded", "discarded", "firstValid", "secondValid", "firstFault", "secondFault")
    words = ("assemblyPc", "nextWord", "firstWord", "secondWord", "firstAddress", "secondAddress", "address", "heldAddress")
    declarations = "".join(f"  reg {name};\n" for name in flags)
    declarations += "".join(f"  reg [31:0] {name};\n" for name in words)
    return "module DitDahE2Fetch(\n  input clock\n);\n" + declarations + """  wire release_0 = assemble & (assemblyPc[1] | crossing & ~headFault);
  assign fault_address = headFault ? firstAddress : failed ? tailAddress : assemblyPc;
  assign word = crossing_0 ? {raw[15:0], half_0} : half;
  assign memory_request_bits_address = memory_request_bits_address_0;
  assign memory_request_bits_machine = held ? heldMachine : machine;
  assign idle = ~held & ~outstanding & ~firstValid & ~secondValid & ~buffered;
  always @(posedge clock) nextWord <= nextWord + 32'h4;
  always @(posedge clock) discarded <= request ? flush | held & heldDiscarded : flush & outstanding | discarded;
  wire offer = ~held & ~flush & (~outstanding | response) & (~tailValid | release_0);
endmodule
"""


class CompressedFetchInputTests(unittest.TestCase):
    def setUp(self):
        scratch = "/data/tmp" if os.access("/data/tmp", os.W_OK) else None
        self.directory = tempfile.TemporaryDirectory(prefix="ditdah-e2-compressed-formal-test-", dir=scratch)
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.source = self.root / "source"
        self.rtl = self.root / "rtl"
        self.rtl.mkdir()
        for name in ("ditdah_e2/src/Fetch.scala", "nix/tools.nix", "flake.nix", "flake.lock", "scripts/build_rtl.py"):
            path = self.source / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("test input\n")
        (self.rtl / "DitDahE2Fetch.sv").write_text(example_rtl())
        self.manifest = {"parameters": {"resetVector": 0, "enableC": True, "enableM": True},
                         "sourceHashes": source_hashes(self.source),
                         "rtlHashes": {"DitDahE2Fetch.sv": hashlib.sha256(example_rtl().encode()).hexdigest()}}
        self.save_manifest()
        self.args = SimpleNamespace(rtl=self.rtl, source_root=self.source)

    def save_manifest(self):
        (self.rtl / "manifest.json").write_text(json.dumps(self.manifest))

    def test_configurations_and_stale_rtl(self):
        contents, bindings = freeze(self.args)
        self.assertEqual(contents["rtl/DitDahE2Fetch.sv"], example_rtl().encode())
        self.assertTrue(bindings["parameters"]["enableC"])
        self.manifest["parameters"]["enableC"] = False
        self.save_manifest()
        self.assertFalse(freeze(self.args)[1]["parameters"]["enableC"])
        self.manifest["parameters"]["resetVector"] = 2
        self.save_manifest()
        with self.assertRaisesRegex(AssertionError, "Misaligned reset"):
            freeze(self.args)
        self.manifest["parameters"]["enableC"] = True
        self.save_manifest()
        self.assertEqual(freeze(self.args)[1]["parameters"]["resetVector"], 2)
        self.save_manifest()
        (self.rtl / "DitDahE2Fetch.sv").write_text("module Changed; endmodule\n")
        with self.assertRaisesRegex(AssertionError, "Changed formal input"):
            freeze(self.args)

    def test_debug_option_does_not_change_fetch_scope(self):
        for value in (False, True):
            self.manifest["parameters"]["enableDebug"] = value
            self.save_manifest()
            self.assertEqual(freeze(self.args)[1]["parameters"]["enableDebug"], value)
        self.manifest["parameters"]["enableDebug"] = 1
        self.save_manifest()
        with self.assertRaisesRegex(AssertionError, "Invalid debug"):
            freeze(self.args)

    def test_bit_configuration_binding(self):
        for subset in range(8):
            self.manifest["parameters"].update({"enable" + name: bool(subset & (1 << index))
                for index, name in enumerate(("Zba", "Zbb", "Zbs"))})
            self.save_manifest()
            self.assertEqual(freeze(self.args)[1]["parameters"], self.manifest["parameters"])
        for key in ("enableZba", "enableZbb", "enableZbs"):
            self.manifest["parameters"][key] = 1
            self.save_manifest()
            with self.assertRaisesRegex(AssertionError, "Invalid bit"):
                freeze(self.args)
            self.manifest["parameters"][key] = False

    def test_observations_preserve_the_original_implementation(self):
        original = example_rtl()
        observed = observe(original)
        remaining = [line for line in observed.splitlines() if line.strip() and
                     not line.startswith(("  output formal_", "  output [31:0] formal_", "  assign formal_"))]
        self.assertEqual(remaining, original.splitlines())
        with self.assertRaisesRegex(AssertionError, "Missing observation signal"):
            observe(original.replace("reg firstValid;", "reg unrelated;"))

    def test_case_selection_matches_the_configuration(self):
        self.assertEqual(len(verification_cases(False, 4, None)), 8)
        self.assertEqual(len(verification_cases(True, 4, None)), 11)
        self.assertEqual(verification_cases(False, 4, ["idle"]), [("idle", "bmc", 24, True)])
        with self.assertRaisesRegex(AssertionError, "Unsupported fetch case"):
            verification_cases(False, 4, ["release"])

    def test_mutations_are_unique_and_change_the_selected_contract(self):
        original = example_rtl()
        self.assertIn("headFault | assemblyPc[1] | crossing", mutate(original, "release"))
        self.assertIn(": failed ? assemblyPc : assemblyPc", mutate(original, "fault-address"))
        self.assertIn("{half_0, raw[15:0]}", mutate(original, "cross-word"))
        self.assertIn("heldDiscarded ?", mutate(original, "held-request"))
        self.assertIn("assign memory_request_bits_machine = machine;", mutate(original, "held-privilege"))
        self.assertIn("assign idle = ~outstanding", mutate(original, "idle"))
        self.assertIn("& 1'b1;", mutate(original, "capacity"))
        self.assertIn("nextWord + 32'h8", mutate(original, "address-increment"))
        self.assertIn(": pause & outstanding | discarded", mutate(original, "stale-response"))
        for name in ("address-increment", "stale-response", "release", "fault-address", "cross-word", "held-request", "held-privilege", "idle", "capacity"):
            with self.subTest(name=name):
                with self.assertRaisesRegex(AssertionError, "no longer matches"):
                    mutate(original + original, name)
                with self.assertRaisesRegex(AssertionError, "no longer matches"):
                    mutate("module unrelated; endmodule\n", name)

    def test_failed_tools_and_missing_counterexamples_are_rejected(self):
        output = self.root / "output"
        output.mkdir()
        for index, (status, code) in enumerate((("ERROR", 16), ("FAIL", 2))):
            work = self.root / str(index)
            work.mkdir()

            def run(command, cwd, **kwargs):
                (cwd / "run").mkdir()
                (cwd / "run/status").write_text(status + "\n")
                return SimpleNamespace(returncode=code, stdout="test process\n", stderr="")

            with self.subTest(status=status), patch("compressed_fetch_formal.subprocess.run", side_effect=run), patch("builtins.print"):
                with self.assertRaises(AssertionError):
                    execute(work, output, example_rtl(), b"module wrapper; endmodule\n", "release", "bmc", 24, True)
        record = json.loads((output / "release.json").read_text())
        archived = output / record["inputDirectory"] / "DitDahE2Fetch.sv"
        self.assertEqual(hashlib.sha256(archived.read_bytes()).hexdigest(), record["inputHashes"][archived.name])


if __name__ == "__main__":
    unittest.main()
