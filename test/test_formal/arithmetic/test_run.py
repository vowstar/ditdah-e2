# SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
# SPDX-License-Identifier: MIT
"""Check arithmetic entrypoints and frozen prepare/replay input binding."""

import contextlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from formal.arithmetic import run, source

ROOT = Path(__file__).resolve().parents[3]


class ArithmeticRunTests(unittest.TestCase):
    def workspace(self):
        return tempfile.TemporaryDirectory(
            prefix="ditdah-e2-arithmetic-run-",
            dir="/data/tmp" if os.access("/data/tmp", os.W_OK) else None,
        )

    def prepare_evidence(self, root):
        rtl_directory = root / "rtl"
        rtl_directory.mkdir()
        rtl = (
            "module DitDahE2MultiplyDivide(\n"
            "input clock,input reset,input cancel,input request_valid,output request_ready,"
            "input [2:0] request_bits_operation,input [31:0] request_bits_left,"
            "input [31:0] request_bits_right,output response_valid,input response_ready,"
            "output [31:0] response_bits\n);\nendmodule\n"
        ).encode()
        (rtl_directory / "DitDahE2MultiplyDivide.sv").write_bytes(rtl)
        manifest = {
            "parameters": {"enableM": True},
            "rtlHashes": {"DitDahE2MultiplyDivide.sv": source.digest(rtl)},
        }
        (rtl_directory / "manifest.json").write_text(json.dumps(manifest))
        evidence = root / "evidence"
        args = SimpleNamespace(
            rtl=rtl_directory, output=evidence, instruction=["mul"], time_limit=1
        )
        with contextlib.redirect_stdout(io.StringIO()):
            run.prepare(args)
        return evidence

    def test_direct_and_module_prepare_help(self):
        environment = dict(os.environ, PYTHONDONTWRITEBYTECODE="1")
        with self.workspace() as directory:
            direct = subprocess.run(
                [sys.executable, str(ROOT / "formal/arithmetic/run.py"), "prepare", "--help"],
                cwd=directory,
                env=environment,
                capture_output=True,
                text=True,
                timeout=10,
            )
        module = subprocess.run(
            [sys.executable, "-m", "formal.arithmetic.run", "prepare", "--help"],
            cwd=ROOT,
            env=environment,
            capture_output=True,
            text=True,
            timeout=10,
        )
        for result in (direct, module):
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("--rtl RTL", result.stdout)
            self.assertIn("--output OUTPUT", result.stdout)

    def test_prepare_and_replay_validate_frozen_inputs(self):
        with self.workspace() as directory:
            root = Path(directory)
            evidence = self.prepare_evidence(root)
            self.assertEqual(run.validate_inputs(evidence)["operations"], [0])
            case = evidence / "mul" / "facts"
            plan = json.loads((case / "plan.json").read_text())
            self.assertEqual(
                set(plan["inputs"]),
                {path.name for path in case.iterdir() if path.name != "plan.json"},
            )
            output = root / "replay"
            args = SimpleNamespace(evidence=evidence, output=output, z3="z3")
            with patch("formal.arithmetic.proofs.replay", return_value={"replayed": True}) as replay:
                with contextlib.redirect_stdout(io.StringIO()):
                    run.replay(args)
            replay.assert_called_once()
            self.assertEqual(replay.call_args.args[0], evidence.resolve())
            self.assertEqual(replay.call_args.args[2], output.resolve())
            (case / "bench.sv").write_text("changed\n")
            with patch("formal.arithmetic.proofs.replay") as replay:
                with self.assertRaisesRegex(ValueError, "Frozen arithmetic proof inputs changed"):
                    run.replay(args)
            replay.assert_not_called()


if __name__ == "__main__":
    unittest.main()
