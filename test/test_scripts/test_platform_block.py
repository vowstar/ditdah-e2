# SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
# SPDX-License-Identifier: MIT
"""Check block-interface projection and frozen-build provenance."""

import json
from pathlib import Path
import platform
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts"))
import build_platform_block as block


HEADER = """module DitDahE2PlatformTop(
  input clock, reset,
  input [31:0] tick,
  output axi_aw_valid,
  input axi_aw_ready,
  output [7:0] transmit_bits,
  output sleeping,
  output [31:0] retire_pc, retire_value,
  output timerInterrupt
);
endmodule
"""


class PlatformBlockTests(unittest.TestCase):
    def fixture(self, directory, header=HEADER):
        files = {
            "inputs/ditdah_e2/src/Example.scala": "source\n",
            "inputs/platform.json": '{"rom":{"base":0,"size":16}}\n',
            "inputs/generated/src/PlatformEntry.scala": "generated source\n",
            "parameters.json": '{"core":{"enableA":false}}\n',
            "map.json": '{"rom":{"base":0,"size":16}}\n',
            "memory.ld": "MEMORY {}\n", "platform.h": "#define ROM_BASE 0\n",
            "linked.mlirbc": "bytecode\n",
            "rtl/DitDahE2PlatformTop.sv": header,
            "rtl/DitDahE2.sv": "module DitDahE2; endmodule\n",
            "command-1.log": "original compiler log\n",
        }
        for name, content in files.items():
            path = directory / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content)
        for name in ("parameters.json", "map.json", "memory.ld", "platform.h"):
            (directory / "inputs/generated" / name).write_text(files[name])
        (directory / "rtl/filelist.f").write_text("DitDahE2.sv\nDitDahE2PlatformTop.sv\n")
        report = {
            "top": block.TOP, "exitStatus": 0, "scope": "platform RTL generation",
            "parameters": json.loads(files["parameters.json"]),
            "regions": json.loads(files["map.json"]),
            "sourceHashes": {"ditdah_e2/src/Example.scala": block.digest(directory / "inputs/ditdah_e2/src/Example.scala")},
            "platformHash": block.digest(directory / "inputs/platform.json"),
            "generatedHashes": block.tree_hashes(directory / "inputs/generated"),
            "rtlHashes": {name: block.digest(directory / "rtl" / name)
                          for name in ("DitDahE2.sv", "DitDahE2PlatformTop.sv")},
            "artifactHashes": {name: block.digest(directory / name)
                               for name in ("parameters.json", "map.json", "memory.ld", "platform.h", "linked.mlirbc")},
            "commands": [{"argv": ["compiler"], "exitStatus": 0}],
            "toolHashes": {"compiler": "0" * 64},
        }
        self.write_manifest(directory, report)
        return report

    def write_manifest(self, directory, report):
        (directory / "manifest.json").write_text(json.dumps(report, indent=2) + "\n")

    def test_exact_emitter_format_and_connections(self):
        text, kept, hidden = block.emit_wrapper("module DitDahE2PlatformTop(input clock, output [31:0] retire_pc, output sleeping); endmodule")
        self.assertEqual(text, """// SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
// SPDX-License-Identifier: MIT
module DitDahE2PlatformBlock(
  input  clock,
  output  sleeping
);
wire [31:0] observed_retire_pc;
DitDahE2PlatformTop fullTop(
  .clock(clock),
  .retire_pc(observed_retire_pc),
  .sleeping(sleeping)
);
endmodule
""")
        self.assertEqual([p["name"] for p in kept], ["clock", "sleeping"])
        self.assertEqual([p["name"] for p in hidden], ["retire_pc"])

    def test_inputs_debug_jtag_and_unknown_outputs_remain_ports(self):
        extra = """, input retire_valid,
          input dmi_request_valid, jtag_tck,
          output dmi_request_ready, jtag_tdo, jtag_tdoEnable,
          output [3:0] retire_future, interrupt_future, alarm"""
        text, kept, hidden = block.emit_wrapper(HEADER.replace("\n);", extra + "\n);"))
        names = {p["name"] for p in kept}
        self.assertTrue({"clock", "reset", "tick", "axi_aw_valid", "axi_aw_ready", "transmit_bits",
                         "sleeping", "retire_valid", "dmi_request_valid", "dmi_request_ready",
                         "jtag_tck", "jtag_tdo", "jtag_tdoEnable", "retire_future", "interrupt_future", "alarm"} <= names)
        self.assertEqual({p["name"] for p in hidden}, {"retire_pc", "retire_value", "timerInterrupt"})
        for name in names:
            self.assertIn(f".{name}({name})", text)
        self.assertEqual(next(p["width"] for p in hidden if p["name"] == "retire_value"), "[31:0]")

    def test_rejects_ambiguous_or_unsupported_headers(self):
        for header in ("module Other(input clock); endmodule", HEADER + HEADER,
                       HEADER.replace("input clock, reset", "input clock, clock"),
                       HEADER.replace("input clock", "inout clock"),
                       HEADER.replace("input clock", "input logic clock"),
                       HEADER.replace("input clock", "input observed_retire_pc"),
                       HEADER.replace("input clock", "input fullTop")):
            with self.subTest(header=header), self.assertRaises(ValueError):
                block.emit_wrapper(header)

    def test_build_retains_original_bytes_and_binds_new_artifacts(self):
        with tempfile.TemporaryDirectory(prefix="ditdah-e2-block-") as directory:
            root = Path(directory)
            original = self.fixture(root / "parent")
            before = block.tree_hashes(root / "parent")
            output = root / "block"
            report = block.build(root / "parent", output)
            self.assertEqual(block.tree_hashes(root / "parent"), before)
            for name, expected in before.items():
                if name not in ("manifest.json", "rtl/filelist.f"):
                    self.assertEqual(block.digest(output / name), expected)
            self.assertEqual((output / "original-manifest.json").read_bytes(), (root / "parent/manifest.json").read_bytes())
            self.assertEqual((output / "original-filelist.f").read_bytes(), (root / "parent/rtl/filelist.f").read_bytes())
            self.assertEqual(report["wrappedManifestHash"], before["manifest.json"])
            self.assertEqual(report["top"], block.BLOCK)
            self.assertEqual(report["wrappedTop"], block.TOP)
            self.assertEqual(report["internalObservationOutputs"], ["retire_pc", "retire_value", "timerInterrupt"])
            for key, base in (("sourceHashes", "inputs"), ("generatedHashes", "inputs/generated"),
                              ("rtlHashes", "rtl"), ("artifactHashes", "")):
                for name, value in original[key].items():
                    self.assertEqual(report[key][name], value)
                for name, value in report[key].items():
                    self.assertEqual(block.digest(output / base / name), value)
            self.assertEqual(report["parameters"], original["parameters"])
            self.assertEqual(report["regions"], original["regions"])
            self.assertEqual(report["platformHash"], original["platformHash"])
            self.assertEqual(report["commands"], original["commands"])
            derivation = report["derivation"]
            self.assertEqual(derivation["argv"], ["python3", "scripts/build_platform_block.py", "--platform-build",
                                                  "<parent>", "--output", "<output>"])
            self.assertEqual(derivation["exitStatus"], 0)
            self.assertEqual(derivation["python"]["version"], platform.python_version())
            self.assertEqual(derivation["python"]["executableSha256"], block.digest(Path(sys.executable)))
            self.assertEqual(derivation["sourceHash"], report["sourceHashes"]["scripts/build_platform_block.py"])
            self.assertEqual(derivation["sourceHash"], block.digest(Path(block.__file__)))
            self.assertEqual(derivation["inputManifestHash"], before["manifest.json"])
            self.assertEqual((output / "rtl/filelist.f").read_text().splitlines(), sorted(report["rtlHashes"]))
            self.assertEqual((output / "rtl/DitDahE2PlatformBlock.sv").read_bytes(),
                             (output / "inputs/generated/DitDahE2PlatformBlock.sv").read_bytes())
            with self.assertRaisesRegex(ValueError, "ordinary platform"):
                block.build(output, root / "second-block")

    def test_each_corrupt_binding_is_rejected_before_output(self):
        names = ("inputs/ditdah_e2/src/Example.scala", "inputs/generated/src/PlatformEntry.scala",
                 "rtl/DitDahE2.sv", "parameters.json", "map.json", "memory.ld", "platform.h",
                 "linked.mlirbc", "inputs/platform.json")
        for name in names:
            with self.subTest(name=name), tempfile.TemporaryDirectory(prefix="ditdah-e2-block-") as directory:
                root = Path(directory)
                self.fixture(root / "parent")
                (root / "parent" / name).write_text("changed\n")
                with self.assertRaisesRegex(ValueError, "(mismatch|differ)"):
                    block.build(root / "parent", root / "block")
                self.assertFalse((root / "block").exists())

    def test_unbound_sources_generated_rtl_and_filelist_are_rejected(self):
        for name in ("inputs/new.scala", "inputs/generated/new.scala", "rtl/New.sv", "rtl/Extra.v",
                     "rtl/Extra.vh", "rtl/nested/Extra.v", "rtl/filelist.f"):
            with self.subTest(name=name), tempfile.TemporaryDirectory(prefix="ditdah-e2-block-") as directory:
                root = Path(directory)
                self.fixture(root / "parent")
                (root / "parent" / name).parent.mkdir(parents=True, exist_ok=True)
                (root / "parent" / name).write_text("unbound\n")
                with self.assertRaisesRegex(ValueError, "(Unbound|differ)"):
                    block.build(root / "parent", root / "block")

    def test_bound_parent_filelist_is_updated_and_original_is_retained(self):
        with tempfile.TemporaryDirectory(prefix="ditdah-e2-block-") as directory:
            root = Path(directory)
            report = self.fixture(root / "parent")
            previous = block.digest(root / "parent/rtl/filelist.f")
            report["artifactHashes"]["rtl/filelist.f"] = previous
            self.write_manifest(root / "parent", report)
            result = block.build(root / "parent", root / "block")
            self.assertNotEqual(result["artifactHashes"]["rtl/filelist.f"], previous)
            self.assertEqual(result["artifactHashes"]["rtl/filelist.f"], block.digest(root / "block/rtl/filelist.f"))
            self.assertEqual(result["artifactHashes"]["original-filelist.f"], previous)
            original = json.loads((root / "block/original-manifest.json").read_text())
            self.assertEqual(original["artifactHashes"]["rtl/filelist.f"], previous)

    def test_individually_bound_but_mismatched_generated_artifacts_are_rejected(self):
        for name in ("parameters.json", "map.json", "memory.ld", "platform.h"):
            for missing in (False, True):
                with self.subTest(name=name, missing=missing), tempfile.TemporaryDirectory(prefix="ditdah-e2-block-") as directory:
                    root = Path(directory)
                    report = self.fixture(root / "parent")
                    if missing:
                        (root / "parent/inputs/generated" / name).unlink()
                        del report["generatedHashes"][name]
                    else:
                        if name == "parameters.json":
                            report["parameters"]["core"]["resetVector"] = 4
                            content = json.dumps(report["parameters"])
                        elif name == "map.json":
                            report["regions"]["rom"]["size"] = 32
                            content = json.dumps(report["regions"])
                        else:
                            content = "changed\n"
                        (root / "parent" / name).write_text(content)
                        report["artifactHashes"][name] = block.digest(root / "parent" / name)
                    self.write_manifest(root / "parent", report)
                    with self.assertRaisesRegex(ValueError, "generated snapshot"):
                        block.build(root / "parent", root / "block")
                    self.assertFalse((root / "block").exists())

    def test_failed_atomic_or_missing_hash_manifest_is_rejected(self):
        for field, value in (("exitStatus", 1), ("exitStatus", False),
                             ("top", "DitDahE2AtomicPlatformTop"),
                             ("parameters", {"core": {"enableA": True}}),
                             ("sourceHashes", {}), ("generatedHashes", {}),
                             ("rtlHashes", {}), ("artifactHashes", {})):
            with self.subTest(field=field, value=value), tempfile.TemporaryDirectory(prefix="ditdah-e2-block-") as directory:
                root = Path(directory)
                report = self.fixture(root / "parent")
                report[field] = value
                self.write_manifest(root / "parent", report)
                with self.assertRaises(ValueError):
                    block.build(root / "parent", root / "block")

    def test_manifest_metadata_and_required_artifacts_are_checked(self):
        for change in ("parameters", "regions", "missing-artifact", "unsafe-path", "bad-digest"):
            with self.subTest(change=change), tempfile.TemporaryDirectory(prefix="ditdah-e2-block-") as directory:
                root = Path(directory)
                report = self.fixture(root / "parent")
                if change == "parameters":
                    report["parameters"]["core"]["resetVector"] = 4
                elif change == "regions":
                    report["regions"]["rom"]["size"] = 32
                elif change == "missing-artifact":
                    del report["artifactHashes"]["linked.mlirbc"]
                elif change == "unsafe-path":
                    report["sourceHashes"]["../outside"] = "0" * 64
                else:
                    report["sourceHashes"]["ditdah_e2/src/Example.scala"] = "invalid"
                self.write_manifest(root / "parent", report)
                with self.assertRaises(ValueError):
                    block.build(root / "parent", root / "block")

    def test_no_overwrite_nested_output_reserved_artifact_or_symlink(self):
        with tempfile.TemporaryDirectory(prefix="ditdah-e2-block-") as directory:
            root = Path(directory)
            self.fixture(root / "parent")
            (root / "occupied").mkdir()
            for output in (root / "parent", root / "parent/nested", root / "occupied"):
                with self.subTest(output=output), self.assertRaisesRegex(ValueError, "new directory"):
                    block.build(root / "parent", output)
            (root / "parent/original-manifest.json").write_text("old record\n")
            with self.assertRaisesRegex(ValueError, "reserved"):
                block.build(root / "parent", root / "block")
            (root / "parent/original-manifest.json").unlink()
            (root / "parent/link").symlink_to("parameters.json")
            with self.assertRaisesRegex(ValueError, "symbolic links"):
                block.build(root / "parent", root / "block")

    def test_cli_uses_frozen_platform_build_without_tools(self):
        with tempfile.TemporaryDirectory(prefix="ditdah-e2-block-") as directory:
            root = Path(directory)
            self.fixture(root / "parent")
            result = subprocess.run([sys.executable, block.__file__, "--platform-build", str(root / "parent"),
                                     "--output", str(root / "block")], check=True, capture_output=True, text=True)
            self.assertIn("Generated DitDahE2 platform block RTL", result.stdout)
            self.assertEqual(json.loads((root / "block/manifest.json").read_text())["top"], block.BLOCK)

    def test_local_platform_direct_entry_imports_without_name_collision(self):
        root = Path(block.__file__).resolve().parents[1]
        result = subprocess.run([sys.executable, str(root / "test/test_local_memory/platform.py"), "--help"],
                                cwd=root, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("--platform", result.stdout)


if __name__ == "__main__":
    unittest.main()
