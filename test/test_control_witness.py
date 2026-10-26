# SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
# SPDX-License-Identifier: MIT
"""Reject missing or unrelated formal counterexamples."""

import unittest
from unittest.mock import patch

from control_witness import frames, witness
from interrupt_formal import mutate_source_priority


class ControlWitnessTests(unittest.TestCase):
    def test_top_scope_and_unknown_values(self):
        text = """$scope module top $end
$var wire 1 a valid $end
$scope module dut $end
$var wire 1 b valid $end
$upscope $end
$upscope $end
#0
1a
0b
#5
xa
#10
"""
        self.assertEqual(list(frames(text, {"valid"})), [(0, {"valid": 1}), (5, {"valid": None}), (10, {"valid": None})])
        with self.assertRaisesRegex(AssertionError, "observations missing"):
            list(frames(text, {"missing"}))

    def test_priority_requires_multiple_actual_sources(self):
        row = dict(reset=0, clock=1, interrupt_valid=1, irq_active=1,
                   pending_sources=5, interrupt_cause=0x80000003)
        with patch("control_witness.frames", return_value=[(30, row)]):
            self.assertEqual(witness("", "source-priority")["expectedCause"], 0x8000000B)
        for changes in ({"pending_sources": 1}, {"interrupt_valid": 0},
                        {"interrupt_cause": 0x8000000B}, {"clock": 0}, {"reset": 1}):
            with self.subTest(changes=changes), patch("control_witness.frames", return_value=[(30, {**row, **changes})]):
                with self.assertRaisesRegex(AssertionError, "intended semantic"):
                    witness("", "source-priority")

    def test_address_error_needs_a_previous_request(self):
        first = dict(reset=0, clock=1, request=1, redirect=0, pause=0, canceled_offer=0,
                     stream_valid=1, memory_request_valid=1, memory_request_bits_address=0, expected_request=0)
        wrong = {**first, "memory_request_bits_address": 8, "expected_request": 4}
        with patch("control_witness.frames", return_value=[(10, first), (20, wrong)]):
            self.assertEqual(witness("", "address-increment")["time"], 20)
        with patch("control_witness.frames", return_value=[(20, wrong)]):
            with self.assertRaisesRegex(AssertionError, "intended semantic"):
                witness("", "address-increment")

    def test_stale_output_needs_redirect_and_response(self):
        row = dict(reset=0, clock=1, redirect=1, outstanding=1, response=0, poisoned=0, flush=1,
                   available=0, output_valid=0, output_bits_pc=8, output_bits_word=0, expected_pc=8, expected_word=0)
        response = {**row, "redirect": 0, "response": 1, "poisoned": 1, "flush": 0}
        wrong = {**response, "response": 0, "output_valid": 1}
        with patch("control_witness.frames", return_value=[(10, row), (20, response), (30, wrong)]):
            self.assertTrue(witness("", "stale-response")["staleResponseAccepted"])
        for samples in ([(30, wrong)], [(10, row), (30, wrong)], [(20, response), (30, wrong)]):
            with patch("control_witness.frames", return_value=samples):
                with self.assertRaisesRegex(AssertionError, "intended semantic"):
                    witness("", "stale-response")

    def test_priority_mutation_is_unique(self):
        source = "wire [31:0] interruptCause = _csr_interruptPending[11] ? 32'h8000000B : fallback;"
        changed = mutate_source_priority(source)
        self.assertIn("(_csr_interruptPending[11] & ~_csr_interruptPending[3])", changed)
        for text in ("", source + source):
            with self.assertRaisesRegex(AssertionError, "no longer matches"):
                mutate_source_priority(text)


if __name__ == "__main__":
    unittest.main()
