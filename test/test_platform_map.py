# SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
# SPDX-License-Identifier: MIT

import copy
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock
import subprocess

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import build_platform
from build_rtl import configuration
import platform_map


class PlatformMapTests(unittest.TestCase):
    def setUp(self):
        self.regions = json.loads((platform_map.ROOT / "platform.json").read_text())

    def test_default_map_and_artifacts(self):
        self.assertEqual(platform_map.validate(self.regions), {
            "rom": {"base": 0, "size": 65536},
            "sram": {"base": 0x20000000, "size": 65536},
            "console": {"base": 0x10000000, "size": 4096},
            "timer": {"base": 0x10001000, "size": 4096}})
        files = platform_map.artifacts(self.regions)
        self.assertEqual(json.loads(files["map.json"]), self.regions)
        self.assertIn("ROM (rx) : ORIGIN = 0x00000000, LENGTH = 0x10000", files["memory.ld"])
        self.assertIn("SRAM (rwx) : ORIGIN = 0x20000000, LENGTH = 0x10000", files["memory.ld"])
        for name, region in self.regions.items():
            for field, value in region.items():
                self.assertIn(f"#define DITDAH_{name.upper()}_{field.upper()} 0x{value:08x}UL", files["platform.h"])

    def test_map_schema(self):
        invalid = [[], None, {}, {**self.regions, "other": {}},
                   {**self.regions, "rom": {"base": 0}},
                   {**self.regions, "rom": {"base": 0, "size": 8, "execute": True}}]
        for value in invalid:
            with self.subTest(value=value), self.assertRaises(ValueError):
                platform_map.validate(value)

    def test_region_bounds_and_alignment(self):
        for base, size in ((-4, 4), (0x100000000, 4), (0, 0), (0, -4), (2, 4), (0, 6),
                           (0xFFFFFFFC, 8), (False, 8), (0, True), ("0", 8), (0, 8.0)):
            value = copy.deepcopy(self.regions)
            value["rom"] = {"base": base, "size": size}
            with self.subTest(base=base, size=size), self.assertRaises(ValueError):
                platform_map.validate(value)
        value = copy.deepcopy(self.regions)
        value["rom"] = {"base": 0xFFFFFFFC, "size": 4}
        self.assertEqual(platform_map.validate(value)["rom"], value["rom"])

    def test_overlap_and_register_extent(self):
        for name, base, size in (("sram", 0, 4), ("sram", 0xFFFC, 8),
                                  ("rom", 0, 0x20000004),
                                  ("console", 0x10000000, 4), ("timer", 0x10001000, 16)):
            value = copy.deepcopy(self.regions)
            value[name] = {"base": base, "size": size}
            with self.subTest(name=name, base=base, size=size), self.assertRaises(ValueError):
                platform_map.validate(value)
        value = copy.deepcopy(self.regions)
        value["sram"]["base"] = 65536
        self.assertEqual(platform_map.validate(value)["sram"]["base"], 65536)

    def test_parameters_and_reset(self):
        for core in ({"enableC": 1}, {"enableM": 1}, {"resetVector": 2, "enableC": False}, {"unknown": 1}):
            with self.subTest(core=core), self.assertRaises(ValueError):
                platform_map.parameters(self.regions, core)
        for enable_m in (False, True):
            for enable_c in (False, True):
                core = configuration({"enableM": enable_m, "enableC": enable_c,
                                      "resetVector": 2 if enable_c else 0})
                result = platform_map.parameters(self.regions, core)
                self.assertEqual(result["core"], core)
                self.assertEqual(result["ramBase"], 0x20000000)
                self.assertEqual(result["timerSize"], 4096)
        for reset in (65536, 0x20000000, 0xFFFFFFFC):
            with self.assertRaisesRegex(ValueError, "inside ROM"):
                platform_map.parameters(self.regions, configuration({"resetVector": reset}))

    def test_relocated_map_and_repeat_output(self):
        value = copy.deepcopy(self.regions)
        value["rom"]["base"] = 0x80000000
        result = platform_map.parameters(value, configuration({"resetVector": 0x80000002, "enableC": True}))
        self.assertEqual(result["romBase"], 0x80000000)
        with tempfile.TemporaryDirectory(prefix="ditdah-e2-map-") as directory:
            output = Path(directory)
            expected = platform_map.write(value, output)
            self.assertEqual(platform_map.write(value, output), expected)
            self.assertEqual({name: (output / name).read_text() for name in expected}, expected)

    def test_compilation_copy_keeps_core_module_name(self):
        contents = {"DitDahE2.scala": 'object DitDahE2 extends Generator:\n  val name = "DitDahE2"\n',
                    "DitDahE2Platform.scala": "val core = DitDahE2.instantiate(p.core)\n",
                    "Other.scala": "unchanged\n"}
        result = build_platform.compilation_sources(contents)
        self.assertIn('object CoreImplementation extends', result["DitDahE2.scala"])
        self.assertIn('val name = "DitDahE2"', result["DitDahE2.scala"])
        self.assertIn("CoreImplementation.instantiate(p.core)", result["DitDahE2Platform.scala"])
        self.assertEqual(result["Other.scala"], contents["Other.scala"])
        self.assertIn("object DitDahE2 extends Generator[PlatformParameters", result["PlatformEntry.scala"])
        self.assertIn("object DitDahE2 extends", contents["DitDahE2.scala"])
        for name in ("DitDahE2.scala", "DitDahE2Platform.scala"):
            for text in ("missing", contents[name] * 2):
                with self.subTest(name=name, text=text), self.assertRaises(ValueError):
                    build_platform.compilation_sources({**contents, name: text})
        with self.assertRaises(ValueError):
            build_platform.compilation_sources({**contents, "PlatformEntry.scala": "occupied"})

    def test_build_does_not_replace_evidence(self):
        with tempfile.TemporaryDirectory(prefix="ditdah-e2-map-") as directory:
            output = Path(directory)
            (output / "manifest.json").write_text("old evidence\n")
            with self.assertRaisesRegex(ValueError, "must be empty"):
                build_platform.build(output)
            self.assertEqual((output / "manifest.json").read_text(), "old evidence\n")

    def build_fixture(self, root):
        contents = {"ditdah_e2/src/DitDahE2.scala": "object DitDahE2 extends Generator\n",
                    "ditdah_e2/src/DitDahE2Platform.scala": "DitDahE2.instantiate(p.core)\n"}
        for name in ("flake.nix", "flake.lock", "scripts/build_rtl.py", "scripts/build_platform.py",
                     "scripts/platform_map.py", "test/test_platform_map.py"):
            contents[name] = "fixture\n"
        for name, value in contents.items():
            path = root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(value)
        (root / "platform.json").write_text(json.dumps(self.regions))
        return contents

    def test_build_binds_actual_inputs_and_artifacts(self):
        with tempfile.TemporaryDirectory(prefix="ditdah-e2-map-") as directory:
            root = Path(directory)
            contents = self.build_fixture(root)

            def run(command, cwd, **kwargs):
                if command[0] == "firld":
                    (cwd / "linked.mlirbc").write_bytes(b"linked")
                if command[0] == "firtool":
                    (cwd / "rtl").mkdir()
                    for name in (build_platform.TOP, "DitDahE2"):
                        (cwd / "rtl" / f"{name}.sv").write_text(f"module {name}; endmodule\n")
                return subprocess.CompletedProcess(command, 0, "", "")

            with mock.patch.object(build_platform, "ROOT", root), \
                    mock.patch.object(build_platform.shutil, "which", return_value=sys.executable), \
                    mock.patch.object(build_platform.subprocess, "check_output", return_value="fixture tool"), \
                    mock.patch.object(build_platform.subprocess, "run", side_effect=run):
                output = root / "result"
                report = build_platform.build(output, root / "platform.json", {"enableC": True})
            self.assertEqual(report["exitStatus"], 0)
            self.assertTrue(report["parameters"]["core"]["enableC"])
            self.assertEqual(len(report["commands"]), 3)
            for name, value in contents.items():
                self.assertEqual((output / "inputs" / name).read_text(), value)
                self.assertEqual(report["sourceHashes"][name], build_platform.digest(root / name))
            self.assertEqual(report["platformHash"], build_platform.digest(output / "inputs/platform.json"))
            for name, value in report["generatedHashes"].items():
                self.assertEqual(value, build_platform.digest(output / "inputs/generated" / name))
            for name, value in report["artifactHashes"].items():
                self.assertEqual(value, build_platform.digest(output / name))

    def test_compile_failure_is_retained(self):
        with tempfile.TemporaryDirectory(prefix="ditdah-e2-map-") as directory:
            root = Path(directory)
            self.build_fixture(root)
            with mock.patch.object(build_platform, "ROOT", root), \
                    mock.patch.object(build_platform.shutil, "which", return_value=sys.executable), \
                    mock.patch.object(build_platform.subprocess, "check_output", return_value="fixture tool"), \
                    mock.patch.object(build_platform.subprocess, "run", return_value=
                                      subprocess.CompletedProcess(["elaborate-ditdah-e2"], 1, "", "compile failure")):
                output = root / "result"
                with self.assertRaisesRegex(RuntimeError, "failed with status 1"):
                    build_platform.build(output, root / "platform.json")
            report = json.loads((output / "manifest.json").read_text())
            self.assertEqual(report["exitStatus"], 1)
            self.assertEqual(len(report["commands"]), 1)
            self.assertNotIn("rtlHashes", report)
            self.assertEqual((output / "command-1.log").read_text(), "compile failure")
            self.assertTrue((output / "inputs/generated/src/PlatformEntry.scala").is_file())


if __name__ == "__main__":
    unittest.main()
