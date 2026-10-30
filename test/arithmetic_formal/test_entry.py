# SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
# SPDX-License-Identifier: MIT
"""Reject invalid arithmetic proof scope, source contracts, and result traces."""

import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from arithmetic_formal import facts, multiply_contracts, source, syntax


class ArithmeticEntryTests(unittest.TestCase):
    def test_comment_markers_cannot_hide_live_driver_or_assumption(self):
        original = source.bench(0)
        driver = "// function begin\nassign request_bits_left[0] = 1'b0;\n// endfunction\n"
        changed = original.replace("    wire request_ready, response_valid;", driver + "    wire request_ready, response_valid;")
        with self.assertRaises(ValueError):
            multiply_contracts.bind(0, changed)
        assumption = ("// function begin\nalways @(posedge clock) begin\n"
                      "extra_input_limit: assume (request_bits_left[0] == 1'b0);\n"
                      "end\n// endfunction\n")
        changed = original.replace("    wire request_ready, response_valid;", assumption + "    wire request_ready, response_valid;")
        self.assertEqual(syntax.properties(changed)["extra_input_limit"]["kind"], "assume")
        with self.assertRaises(ValueError):
            multiply_contracts.bind(0, changed)

    def test_commented_reference_cannot_replace_actual_function(self):
        original = source.bench(0)
        reference = source.reference(original)
        changed = "/*\n" + reference + "\n*/\n" + original.replace(
            "unsigned_product[31:0]", "unsigned_product[63:32]")
        with self.assertRaises(ValueError):
            source.reference(changed)
        with self.assertRaises(ValueError):
            multiply_contracts.bind(0, changed)

    def test_request_domain_and_connections_cannot_change(self):
        text = source.bench(0)
        mutations = [
            text.replace(
                "input logic [31:0] request_bits_left", "input logic [15:0] request_bits_left"
            ),
            text.replace(
                "    wire request_ready, response_valid;",
                "    assign request_bits_left[0] = 1'b0;\n    wire request_ready, response_valid;",
            ),
            text.replace(
                "    wire request_ready, response_valid;",
                "    assign request_bits_operation[2] = 1'b0;\n    wire request_ready, response_valid;",
            ),
            text.replace(
                ".request_bits_left(request_bits_left)",
                ".request_bits_left({request_bits_left[31:1], 1'b0})",
            ),
            text.replace(
                ".remaining_high(dut.multiplier[31:1])", ".remaining_high(dut.multiplier[30:0])"
            ),
        ]
        for changed in mutations:
            self.assertNotEqual(changed, text)
            with self.assertRaises(ValueError):
                multiply_contracts.bind(0, changed)

    def test_polynomial_helper_cannot_change(self):
        text = source.bench(0)
        helper = (source.HERE / "multiply_step.sv").read_text()
        changed = helper.replace("input logic [63:0] accumulator", "input logic [31:0] accumulator")
        self.assertNotEqual(changed, helper)
        with self.assertRaises(ValueError):
            multiply_contracts.bind(0, text, helper_text=changed)

    def test_all_operations_keep_full_request_domain(self):
        for operation in range(8):
            text = source.bench(operation)
            self.assertEqual(text.count(": assume"), 5)
            self.assertIn("input logic [2:0] request_bits_operation", text)
            self.assertIn("input logic [31:0] request_bits_left", text)
            self.assertIn("input logic [31:0] request_bits_right", text)
            self.assertEqual(len(facts.goals(operation)), 65 if operation < 4 else 70)
            self.assertNotIn("derived_actual_total_update", text)

    def test_operation_parameter_cannot_be_relabelled(self):
        with self.assertRaises(ValueError):
            multiply_contracts.bind(2, source.bench(1))

    def test_changed_complete_guard_is_rejected(self):
        text = source.bench(0)
        changed = text.replace(
            "if (!reset && !cancel && response_valid && owner_op == OPERATION)",
            "if (!reset && !cancel && response_valid && owner_op == OPERATION && pending)",
        )
        self.assertNotEqual(changed, text)
        with self.assertRaises(ValueError):
            multiply_contracts.bind(0, changed)

    def test_changed_snapshot_and_width_are_rejected(self):
        text = source.bench(1)
        for old, new in (
            (
                "chain_previous_product == $past(dut.product)",
                "chain_previous_product == ($past(dut.product) ^ 64'd1)",
            ),
            ("wire [63:0] remaining_product", "wire [31:0] remaining_product"),
        ):
            self.assertIn(old, text)
            with self.assertRaises(ValueError):
                multiply_contracts.bind(1, text.replace(old, new))

    def test_standard_function_cannot_change(self):
        text = source.bench(0).replace("unsigned_product[31:0]", "unsigned_product[63:32]")
        with self.assertRaises(ValueError):
            source.reference(text)

    def test_solver_rules_keep_effective_negative_controls(self):
        from arithmetic_formal import capture_rules, multiply_result, multiply_rules, multiply_sign

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with contextlib.redirect_stdout(io.StringIO()):
                multiply_rules.prove(root / "middle", 0)
                capture_rules.prove(root / "capture")
                multiply_result.prove(root / "result", 0)
                multiply_sign.prove(root / "sign")
            for path in root.rglob("queries.json"):
                rows = json.loads(path.read_text())
                controls = [row for row in rows if row["name"].startswith("negative_")]
                self.assertTrue(controls)
                self.assertTrue(
                    all((row["actual"] == row["expected"] == "sat" for row in controls))
                )


if __name__ == "__main__":
    unittest.main()
