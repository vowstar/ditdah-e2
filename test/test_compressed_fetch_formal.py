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

from compressed_fetch_formal import execute, freeze, mutate, observe, source_hashes


def example_rtl():
    flags = ("active", "sent", "discarded", "firstValid", "secondValid", "firstFault", "secondFault")
    words = ("assemblyPc", "nextWord", "firstWord", "secondWord", "firstAddress", "secondAddress")
    declarations = "".join(f"  reg {name};\n" for name in flags)
    declarations += "".join(f"  reg [31:0] {name};\n" for name in words)
    return "module DitDahE2Fetch(\n  input clock\n);\n" + declarations + """  wire        releaseFirst = assemblyPc[1] | crossing & ~firstFault;
  assign fault_address = firstFault ? firstAddress : failed ? secondAddress : assemblyPc;
  assign word = crossing_0 ? {secondWord[15:0], half} : firstWord;
  assign memory_request_bits_address = address;
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

    def test_disabled_compression_and_stale_rtl_are_rejected(self):
        contents, bindings = freeze(self.args)
        self.assertEqual(contents["rtl/DitDahE2Fetch.sv"], example_rtl().encode())
        self.assertTrue(bindings["parameters"]["enableC"])
        self.manifest["parameters"]["enableC"] = False
        self.save_manifest()
        with self.assertRaisesRegex(AssertionError, "enableC=true"):
            freeze(self.args)
        self.manifest["parameters"]["enableC"] = True
        self.save_manifest()
        (self.rtl / "DitDahE2Fetch.sv").write_text("module Changed; endmodule\n")
        with self.assertRaisesRegex(AssertionError, "Changed formal input"):
            freeze(self.args)

    def test_observations_preserve_the_original_implementation(self):
        original = example_rtl()
        observed = observe(original)
        remaining = [line for line in observed.splitlines() if line.strip() and
                     not line.startswith(("  output formal_", "  output [31:0] formal_", "  assign formal_"))]
        self.assertEqual(remaining, original.splitlines())
        with self.assertRaisesRegex(AssertionError, "Missing observation signal"):
            observe(original.replace("reg firstValid;", "reg unrelated;"))

    def test_mutations_are_unique_and_change_the_selected_contract(self):
        original = example_rtl()
        self.assertIn("firstFault | assemblyPc[1] | crossing", mutate(original, "release"))
        self.assertIn(": failed ? assemblyPc : assemblyPc", mutate(original, "fault-address"))
        self.assertIn("{half, secondWord[15:0]}", mutate(original, "cross-word"))
        self.assertIn("discarded && !sent ?", mutate(original, "held-request"))
        for name in ("release", "fault-address", "cross-word", "held-request"):
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
