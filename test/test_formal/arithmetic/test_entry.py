# SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
# SPDX-License-Identifier: MIT
"""Reject invalid arithmetic proof scope, source contracts, and result traces."""

import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from formal.arithmetic import facts, multiply_contracts, proofs, source, syntax


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

    def test_composed_step_connections_cannot_change(self):
        text = source.bench(0)
        for old, new in (
            (".remaining_high(polynomial_state1_multiplier[31:1])",
             ".remaining_high(polynomial_state1_multiplier[30:0])"),
            ("wire [31:0] polynomial_state1_multiplier = {1'b0, dut.multiplier[31:1]}",
             "wire [31:0] polynomial_state1_multiplier = {1'b0, dut.multiplier[30:0]}"),
            ("dut.iteration == chain_previous_iteration + 6'd2",
             "dut.iteration == chain_previous_iteration + 6'd1"),
            ("chain_polynomial_snapshot_total: assert(chain_previous_total == $past(chain_total))",
             "chain_polynomial_snapshot_total: assert(chain_previous_total == $past(chain_total) + 64'd1)"),
        ):
            self.assertIn(old, text)
            with self.assertRaises(ValueError):
                multiply_contracts.bind(0, text.replace(old, new))

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
            self.assertEqual(len(facts.goals(operation)), 76 if operation < 4 else 70)
            self.assertNotIn("derived_actual_total_update", text)
            if operation < 4:
                native = {name for name, _ in facts.goals(operation)}
                self.assertTrue(native.isdisjoint(proofs.MULTIPLY_COMPOSED))
                self.assertEqual(len(native | proofs.MULTIPLY_COMPOSED.keys()), 79)

    def test_selected_pair_and_completion_scope_cannot_change(self):
        text = source.bench(0)
        for old, new in (
            ("wire owner_swap = !owner_op[2]", "wire owner_swap = owner_op[2]"),
            ("owner_op == 0 && dut.multiplier[31:2] == 0", "owner_op == 0 && dut.multiplier[31:3] == 0"),
            ("chain_low_finish ? chain_predicted_product : dut.product", "chain_low_finish ? dut.product : chain_predicted_product"),
            ("chain_previous_finish_product == $past(chain_finish_product)", "chain_previous_finish_product == $past(dut.product)"),
            ("chain_actual_step_operation: assert($past(dut.operation) == OPERATION)",
             "chain_actual_step_operation: assert($past(owner_op) == OPERATION)"),
            ("chain_previous_mul_hold || chain_previous_narrow_capture", "chain_previous_mul_hold"),
            ("request_bits_left[31:9] == 0", "request_bits_left[31:10] == 0"),
        ):
            self.assertIn(old, text)
            with self.assertRaises(ValueError):
                multiply_contracts.bind(0, text.replace(old, new))
        required = {"snapshot_finish_product_is_actual_past", "narrow_response_has_past_accept", "narrow_result_matches_reference"}
        self.assertTrue(required <= {name for name, _ in facts.goals(0)})
        self.assertIn("narrow_capture_reached", facts.covers(0))
        self.assertNotIn("narrow_capture_reached", facts.covers(1))

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

    def test_sampled_claims_keep_checked_native_premises(self):
        from formal.arithmetic import multiply_rules

        expected = {
            "chain_polynomial_snapshot_predicted_total",
            "chain_polynomial_snapshot_total",
            "chain_sampled_identity",
        }
        self.assertEqual(set(proofs.MULTIPLY_COMPOSED), expected)
        required = {
            "phi_predicted_snapshot_total", "phi_snapshot_total", "sampled_identity"
        }
        controls = {
            "negative_phi_predicted_snapshot_total_without_" + name
            for name in ("native_predicted_product_snapshot",
                         "native_predicted_multiplicand_snapshot",
                         "native_predicted_multiplier_snapshot")
        } | {
            "negative_phi_snapshot_total_without_" + name
            for name in ("native_snapshot_product", "native_snapshot_multiplicand",
                         "native_snapshot_multiplier", "native_sampled_step_flag")
        } | {
            "negative_sampled_identity_without_" + name
            for name in ("composed_predicted_snapshot_total",
                         "composed_original_snapshot_total",
                         "native_previous_polynomial_identity")
        }
        with tempfile.TemporaryDirectory() as directory:
            for operation in range(4):
                output = Path(directory) / str(operation)
                multiply_rules.prove(output, operation)
                rows = {row["name"]: row for row in
                        json.loads((output / "queries.json").read_text())}
                self.assertTrue(required <= rows.keys())
                self.assertTrue(controls <= rows.keys())
                for name in required:
                    self.assertEqual(rows[name]["actual"], "unsat")
                    self.assertEqual(rows[name + "_nonvacuity"]["actual"], "sat")
                for name in controls:
                    self.assertEqual(rows[name]["actual"], "sat")
                    self.assertEqual(rows[name]["claimValue"], "False")

    def test_solver_rules_keep_effective_negative_controls(self):
        from formal.arithmetic import capture_rules, multiply_result, multiply_rules, multiply_sign

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
