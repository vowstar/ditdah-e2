# SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
# SPDX-License-Identifier: MIT
"""Reject invalid native arithmetic evidence and independently replay traces."""

import copy
import json
from pathlib import Path
import tempfile
import unittest
from arithmetic_formal import boolean, native, traces


class NativeArithmeticTests(unittest.TestCase):
    def test_initial_covers_bind_the_actual_observer_name(self):
        for label, name in (
            ("initial_frame_reached", "first_proof_frame"),
            ("division_initial_frame_reached", "division_first_proof_frame"),
        ):
            with self.subTest(label=label), tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / "initial.vcd"
                text = (
                    "$scope module md_math_bench $end\n"
                    "$var wire 1 a clock $end\n$var wire 1 b reset $end\n"
                    "$var reg 1 c " + name + " $end\n"
                    "$upscope $end\n$enddefinitions $end\n"
                    "#0\n0a\n0b\n1c\n#1\n1a\n#2\n0a\n"
                )
                path.write_text(text)
                self.assertTrue(
                    traces.replay_cover(path, 4 if label.startswith("division") else 0, label)[
                        "replayed"
                    ]
                )
                path.write_text(text.replace(name, "unrelated_frame"))
                with self.assertRaises(ValueError):
                    traces.replay_cover(path, 0, label)

    def test_native_process_failures_keep_case_and_log(self):
        scripts = {
            "exit": ("import sys\nsys.exit(7)\n", "exit status 7", 2),
            "identity": ("pass\n", "identity is missing", 2),
            "inputs": (
                "from pathlib import Path\nPath('input.sv').write_text('changed')\n",
                "inputs changed",
                2,
            ),
            "timeout": ("import time\ntime.sleep(10)\n", "timed out", 0.03),
            "metadata": (
                "from pathlib import Path\n"
                "Path('executable.private').write_text(__file__)\n"
                "Path('native.tsv').write_text('')\n",
                "did not finish",
                2,
            ),
        }
        for kind, (script, message, timeout) in scripts.items():
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                case = root / "instruction" / kind
                case.mkdir(parents=True)
                private = root / "private"
                private.mkdir()
                tool = root / "test-tool"
                tool.write_text("#!/usr/bin/env python3\n" + script)
                tool.chmod(0o700)
                (case / "input.sv").write_text("module fixture; endmodule\n")
                (case / "plan.json").write_text(json.dumps({"inputs": ["input.sv"]}))
                with self.assertRaises(ValueError) as captured:
                    native.collect(case, str(tool), private, timeout)
                text = str(captured.exception)
                self.assertIn("instruction/" + kind, text)
                self.assertIn(message, text)
                logs = list(private.glob("*/native.log"))
                self.assertEqual(len(logs), 1)
                self.assertIn(str(logs[0]), text)
                self.assertTrue((case / "completion.json").is_file())

    def write_boolean_trace(self, path, rows, observed=True):
        names = ["clock", "reset", "I", "first_frame"]
        if observed:
            names.append("previous_I")
        lines = ["$scope module boolean_induction_rule $end"]
        for code, name in enumerate(names):
            lines.append("$var wire 1 v%d %s $end" % (code, name))
        lines += ["$upscope $end", "$enddefinitions $end"]
        for index, row in enumerate(rows):
            for edge in range(2):
                lines.append("#" + str(index * 2 + edge))
                for code, name in enumerate(names):
                    value = edge if name == "clock" else row[name]
                    lines.append("b%d v%d" % (value, code))
        path.write_text("\n".join(lines) + "\n")

    def test_boolean_control_with_unused_observer(self):
        rows = [{"reset": 0, "I": 1, "first_frame": 1}, {"reset": 0, "I": 0, "first_frame": 0}]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "control.vcd"
            self.write_boolean_trace(path, rows, observed=False)
            result = boolean.replay_trace(path, "no_step")
            self.assertTrue(result["unusedObserverDerivedFromActualPast"])
            rows[1]["I"] = 1
            self.write_boolean_trace(path, rows, observed=False)
            with self.assertRaises(ValueError):
                boolean.replay_trace(path, "no_step")

    def test_boolean_control_rejects_wrong_observation(self):
        rows = [
            {"reset": 0, "I": 1, "first_frame": 1, "previous_I": 1},
            {"reset": 0, "I": 0, "first_frame": 0, "previous_I": 0},
        ]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "control.vcd"
            self.write_boolean_trace(path, rows)
            self.assertTrue(boolean.replay_trace(path, "bad_sample")["replayed"])
            rows[1]["previous_I"] = 1
            self.write_boolean_trace(path, rows)
            with self.assertRaises(ValueError):
                boolean.replay_trace(path, "bad_sample")

    def native_fixture(self):
        plan = {
            "top": "unit",
            "goals": [["goal", []]],
            "covers": ["reached"],
            "assumptions": ["unit.input_stable"],
            "expected": "proven",
        }
        reset = "expression reset file_type {} sequence {} file_name {} hier_path {} time {} start_time {} end_time {} time_scale {} non_resettable_regs {} formal false bound 0 max_iterations {} none false reset_declared true"
        records = {("run", "state"): "complete"}
        for key in ("bbox_inst", "bbox_mod", "bbox_out", "stopat"):
            records["setup", key] = "0"
        scope = {
            "clock": "{clock clock 1 1}",
            "reset": reset,
            "assumptions": "unit.input_stable",
            "global": "",
            "reset_assumptions": "",
        }
        for tag in ("before", "after"):
            records.update({(tag, key): value for key, value in scope.items()})
        identity = {
            "name": "unit.goal",
            "type": "assert",
            "command": "assert",
            "disabled": "0",
            "expression": "goal",
            "precondition": "0",
        }
        for tag, status, run in (
            ("before.goal", "unknown", "unprocessed"),
            ("final.goal", "proven", "processed"),
        ):
            records.update({(tag, key): value for key, value in identity.items()})
            records[tag, "validity_status"] = status
            records[tag, "run_status"] = run
        cover = {
            "name": "unit.reached",
            "type": "cover",
            "command": "cover",
            "disabled": "0",
            "run_status": "processed",
            "validity_status": "covered",
        }
        records.update({("cover.reached", key): value for key, value in cover.items()})
        return (records, plan)

    def test_complete_native_metadata_and_corruptions(self):
        records, plan = self.native_fixture()
        self.assertEqual(native.check_records(records, plan)["nativeGoals"], 1)
        corruptions = [
            ("final.goal", "type", "assume"),
            ("final.goal", "command", "assume"),
            ("final.goal", "disabled", "1"),
            ("final.goal", "run_status", "unprocessed"),
            ("final.goal", "validity_status", "unknown"),
            ("final.goal", "precondition", "1"),
            ("final.goal", "expression", "another_goal"),
            ("final.goal", "clock", "other_clock"),
            ("final.goal", "edge", "negedge"),
            ("before.goal", "type", "assume"),
            ("before", "assumptions", "unit.extra_input"),
            ("before", "clock", "{other_clock other_clock 1 1}"),
            ("before", "global", "1"),
            ("before", "reset_assumptions", "reset"),
            ("setup", "bbox_inst", "1"),
            ("setup", "bbox_mod", "1"),
            ("setup", "bbox_out", "1"),
            ("setup", "stopat", "1"),
            ("cover.reached", "validity_status", "unknown"),
        ]
        for tag, field, value in corruptions:
            with self.subTest(tag=tag, field=field):
                changed = copy.deepcopy(records)
                changed[tag, field] = value
                with self.assertRaises(ValueError):
                    native.check_records(changed, plan)
        for field, value in (
            ("assumptions", "unit.extra_input"),
            ("clock", "{other_clock other_clock 1 1}"),
            ("global", "1"),
            ("reset_assumptions", "reset"),
        ):
            with self.subTest(scope=field):
                changed = copy.deepcopy(records)
                changed["before", field] = changed["after", field] = value
                with self.assertRaises(ValueError):
                    native.check_records(changed, plan)
        for field, value in (("clock", "other_clock"), ("edge", "negedge")):
            changed = copy.deepcopy(records)
            changed["before.goal", field] = changed["final.goal", field] = value
            with self.assertRaises(ValueError):
                native.check_records(changed, plan)

    def test_missing_native_metadata_is_not_proof(self):
        plan = {
            "top": "md_math_bench",
            "goals": [["goal", []]],
            "covers": [],
            "assumptions": [],
            "expected": "proven",
        }
        for records in ({}, {("run", "state"): "complete"}):
            with self.assertRaises(ValueError):
                native.check_records(records, plan)

    def test_duplicate_native_record_is_rejected(self):
        row = "\t".join((value.encode().hex() for value in ("run", "state", "complete")))
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "native.tsv"
            path.write_text(row + "\n" + row + "\n")
            with self.assertRaises(ValueError):
                native.read_records(path)

    def test_independent_integer_results(self):
        cases = (
            (0, 4294967295, 2, 4294967294),
            (1, 4294967295, 4294967295, 0),
            (2, 4294967295, 4294967295, 4294967295),
            (3, 4294967295, 4294967295, 4294967294),
            (4, 2147483648, 4294967295, 2147483648),
            (4, 4294967289, 2, 4294967293),
            (5, 4294967295, 2, 2147483647),
            (6, 4294967289, 2, 4294967295),
            (7, 4294967295, 2, 1),
        )
        for operation, left, right, expected in cases:
            self.assertEqual(traces.architectural_result(operation, left, right), expected)
        for operation in range(4, 8):
            expected = 4294967295 if operation in (4, 5) else 2271560481
            self.assertEqual(traces.architectural_result(operation, 2271560481, 0), expected)

    def test_request_trace_detects_corrupt_response(self):
        widths = {
            "clock": 1,
            "reset": 1,
            "cancel": 1,
            "request_valid": 1,
            "request_ready": 1,
            "request_bits_operation": 3,
            "request_bits_left": 32,
            "request_bits_right": 32,
            "response_valid": 1,
            "response_ready": 1,
            "response_bits": 32,
            "expected": 32,
            "accepted": 1,
            "owner_op": 3,
        }
        rows = [{name: 0 for name in widths} for _ in range(3)]
        rows[0]["reset"] = 1
        rows[1].update(
            request_valid=1,
            request_ready=1,
            request_bits_left=4294967295,
            request_bits_right=2,
            accepted=1,
        )
        rows[2].update(
            response_valid=1, response_ready=1, response_bits=4294967294, expected=4294967294
        )
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "result.vcd"

            def write():
                lines = ["$scope module md_math_bench $end"]
                for index, (name, width) in enumerate(widths.items()):
                    lines.append("$var wire %d v%d %s $end" % (width, index, name))
                lines += ["$upscope $end", "$enddefinitions $end"]
                for index, row in enumerate(rows):
                    for edge in range(2):
                        lines.append("#" + str(index * 2 + edge))
                        for code, name in enumerate(widths):
                            value = edge if name == "clock" else row[name]
                            lines.append("b%s v%d" % (format(value, "b"), code))
                path.write_text("\n".join(lines) + "\n")

            write()
            self.assertTrue(traces.replay_result(path, 0)["effectiveGoalBitCounterexample"])
            rows[2]["response_bits"] ^= 1
            write()
            with self.assertRaises(ValueError):
                traces.replay_result(path, 0)
