# SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
# SPDX-License-Identifier: MIT
"""Check transport runner binding without substituting for RTL simulation."""

import json
from pathlib import Path
import tempfile
import unittest

from test.test_jtag.verify_jtag import (TEST_IDCODE, TOPS, configuration,
                                        load_design, simulation_passed)


class JtagRunnerTests(unittest.TestCase):
    def test_explicit_test_idcode(self):
        self.assertEqual(TEST_IDCODE, 0xE2000001)
        self.assertTrue(TEST_IDCODE & 1)
        self.assertLess(TEST_IDCODE, 1 << 32)
        self.assertEqual(configuration(), {"enableDebug": True, "enableJtag": True,
                                           "jtagIdcode": TEST_IDCODE})

    def test_completion_requires_a_pass_line(self):
        self.assertTrue(simulation_passed("checks complete\nPASS\n"))
        for text in ("", "PASSING\n", "PASS extra\n", "PASS\nFAIL\n"):
            with self.subTest(text=text):
                self.assertFalse(simulation_passed(text))

    def test_generated_design_binding(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name, top in TOPS:
                rtl = root / name
                rtl.mkdir()
                (rtl / f"{top}.sv").write_text(f"module {top}; endmodule\n")
                (rtl / "filelist.f").write_text(f"{top}.sv\n")
                (rtl / "manifest.json").write_text(json.dumps(
                    {"top": top, "parameters": configuration()}) + "\n")
                files, manifest = load_design(root, name, top)
                self.assertEqual(files, [(rtl / f"{top}.sv").resolve()])
                self.assertEqual(manifest["top"], top)

    def test_binding_rejects_wrong_identity_or_missing_rtl(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            name, top = TOPS[0]
            rtl = root / name
            rtl.mkdir()
            (rtl / "filelist.f").write_text(f"{top}.sv\n")
            manifest = rtl / "manifest.json"
            manifest.write_text(json.dumps({"top": top, "parameters": configuration()}) + "\n")
            with self.assertRaisesRegex(RuntimeError, "Incomplete generated file list"):
                load_design(root, name, top)
            (rtl / f"{top}.sv").write_text(f"module {top}; endmodule\n")
            manifest.write_text(json.dumps(
                {"top": top, "parameters": configuration() | {"jtagIdcode": TEST_IDCODE ^ 2}}) + "\n")
            with self.assertRaisesRegex(RuntimeError, "Explicit test IDCODE"):
                load_design(root, name, top)


if __name__ == "__main__":
    unittest.main()
