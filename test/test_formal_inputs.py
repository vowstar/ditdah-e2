# SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
# SPDX-License-Identifier: MIT
"""Reject changes to the inputs used by a formal run."""

from pathlib import Path
import os
import tempfile
import unittest

from unittest.mock import patch

import formal
from core_formal import check_inputs, write_snapshot


class FormalInputTests(unittest.TestCase):
    def test_changed_and_removed_inputs_are_rejected(self):
        scratch = "/data/tmp" if os.access("/data/tmp", os.W_OK) else None
        with tempfile.TemporaryDirectory(prefix="ditdah-e2-inputs-", dir=scratch) as directory:
            frozen = write_snapshot(Path(directory), {"input.sv": b"module dut(input clock); endmodule\n"})
            source = Path(directory) / "inputs/input.sv"
            check_inputs(frozen)
            source.write_text("module dut(input reset); endmodule\n")
            with self.assertRaises(RuntimeError):
                check_inputs(frozen)
            source.unlink()
            with self.assertRaises(RuntimeError):
                check_inputs(frozen)

    def test_fetch_dispatch_preserves_bound_inputs(self):
        with patch("sys.argv", ["formal.py", "--rtl", "frozen/rtl", "--source-root", "frozen", "--output", "evidence"]), \
                patch("formal.subprocess.run") as run:
            formal.main()
        self.assertEqual(run.call_count, 2)
        first, second = [item.args[0] for item in run.call_args_list]
        self.assertTrue(first[1].endswith("compressed_fetch_formal.py"))
        self.assertTrue(second[1].endswith("fetch_latency.py"))
        self.assertEqual(first[2:], ["--rtl", "frozen/rtl", "--source-root", "frozen", "--output", "evidence"])
        self.assertEqual(second[-1], "evidence/latency")


if __name__ == "__main__":
    unittest.main()
