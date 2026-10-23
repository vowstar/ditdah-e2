# SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
# SPDX-License-Identifier: MIT
"""Reject changes to the inputs used by a formal run."""

from pathlib import Path
import os
import tempfile
import unittest

from formal import check_inputs, freeze_inputs
from core_formal import check_inputs as check_core_inputs


class FormalInputTests(unittest.TestCase):
    def test_changed_and_removed_inputs_are_rejected(self):
        scratch = "/data/tmp" if os.access("/data/tmp", os.W_OK) else None
        with tempfile.TemporaryDirectory(prefix="ditdah-e2-inputs-", dir=scratch) as directory:
            source = Path(directory) / "input.sv"
            source.write_text("module dut(input clock); endmodule\n")
            frozen = freeze_inputs([source])
            for check in (check_inputs, check_core_inputs):
                check(frozen)
            source.write_text("module dut(input reset); endmodule\n")
            for check in (check_inputs, check_core_inputs):
                with self.assertRaises(RuntimeError):
                    check(frozen)
            source.unlink()
            for check in (check_inputs, check_core_inputs):
                with self.assertRaises(RuntimeError):
                    check(frozen)


if __name__ == "__main__":
    unittest.main()
