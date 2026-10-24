# SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
# SPDX-License-Identifier: MIT
"""Check arithmetic formal mutations and retained proof inputs."""

import os
from pathlib import Path
from subprocess import CompletedProcess
import tempfile
import unittest
from unittest.mock import patch

from multiply_divide_formal import check_files, configuration, freeze, mutate_cancel, mutate_duplicate, mutate_value, run_case


RTL = """active <= ~(cancel | finished) & (accepted | active);
valid <= ~cancel & (finished | ~(response_valid_0 & response_ready) & valid);
assign response_bits = value;
"""


class MultiplyFormalTests(unittest.TestCase):
    def workspace(self):
        return tempfile.TemporaryDirectory(prefix="ditdah-e2-arithmetic-test-",
                                           dir="/data/tmp" if os.access("/data/tmp", os.W_OK) else None)

    def test_cancel_and_duplicate_mutations(self):
        canceled = mutate_cancel(RTL)
        self.assertIn("active <= ~finished", canceled)
        self.assertIn("valid <= (finished", canceled)
        self.assertNotIn("~cancel", canceled)
        duplicate = mutate_duplicate(RTL)
        self.assertIn("finished | valid", duplicate)
        self.assertIn("~cancel", duplicate)
        self.assertIn("value ^ {32{response_ready}}", mutate_value(RTL))

    def test_mutations_require_exact_targets(self):
        for mutation in (mutate_cancel, mutate_duplicate, mutate_value):
            with self.assertRaisesRegex(AssertionError, "no longer matches"):
                mutation("module unrelated; endmodule")
            with self.assertRaisesRegex(AssertionError, "no longer matches"):
                mutation(RTL + RTL)

    def test_configuration_separates_proof_and_covers(self):
        control = configuration("prove", "abc pdr")
        stability = configuration("prove", "abc pdr", True)
        covers = configuration("cover", "smtbmc z3")
        self.assertIn("mode prove", control)
        self.assertIn("aigsmt z3", control)
        self.assertNotIn("CHECK_STABILITY", control)
        self.assertIn("-DCHECK_STABILITY", stability)
        self.assertNotIn("aigsmt", covers)

    def test_snapshot_retains_sources(self):
        with self.workspace() as directory:
            root = Path(directory)
            names = ["ditdah_e2/src/" + name for name in ("MultiplyDivide.scala", "Parameters.scala", "Interfaces.scala")]
            names += ["test/multiply_divide_formal.py", "test/multiply_divide_formal.sv",
                      "test/multiply_divide_unit.py", "flake.nix", "flake.lock", "nix/toolchain.nix"]
            for index, name in enumerate(names):
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(str(index))
            saved = freeze(root, root / "inputs")
            self.assertEqual(set(saved), set(names))
            check_files(saved, root / "inputs")
            (root / "inputs" / names[0]).write_text("changed")
            with self.assertRaisesRegex(AssertionError, "Frozen arithmetic inputs changed"):
                check_files(saved, root / "inputs")

    def test_negative_control_requires_a_counterexample(self):
        with self.workspace() as directory:
            output = Path(directory)

            def failed_run(command, *, cwd, **kwargs):
                (cwd / "run").mkdir()
                (cwd / "run/status").write_text("FAIL\n")
                return CompletedProcess(command, 2, "Property failed\n", "")

            with patch("multiply_divide_formal.subprocess.run", side_effect=failed_run):
                with self.assertRaisesRegex(AssertionError, "Missing semantic counterexample"):
                    run_case(output, RTL.encode(), b"module test; endmodule", "cancel", "bmc", "smtbmc z3", mutate_cancel)
            saved = output / "cases/cancel"
            self.assertEqual((saved / "DitDahE2MultiplyDivide.sv").read_text(), mutate_cancel(RTL))
            self.assertTrue((saved / "run.sby").is_file())
            self.assertTrue((saved / "multiply_divide_formal.sv").is_file())


if __name__ == "__main__":
    unittest.main()
