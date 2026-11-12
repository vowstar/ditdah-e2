# SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
# SPDX-License-Identifier: MIT
"""Check Program Buffer hart reference-model boundaries and mutation anchors."""

import unittest

from test.test_debug.debug_hart import row
from test.test_debug.program_hart import (
    Driver,
    ProgramReference,
    expected,
    mutant,
    program_vectors,
)


class ProgramHartTests(unittest.TestCase):
    def test_compressed_boundaries_and_cancellation(self):
        rows = program_vectors({"enableC": True})
        _, counts = expected(rows, {"enableC": True})
        self.assertEqual(counts["crossWord"], 1)
        self.assertEqual(counts["truncated"], 1)
        self.assertEqual(counts["implicit"], 1)
        self.assertEqual(counts["cancelledInjection"], 2)
        self.assertEqual(counts["pending"], 0)

    def test_aligned_words_without_compressed_support(self):
        rows = program_vectors({"enableC": False})
        _, counts = expected(rows, {"enableC": False})
        self.assertGreater(counts["issues"], 5)
        self.assertEqual(counts["pending"], 0)

    def test_successful_read_survives_program_fault(self):
        driver = Driver({"enableC": True})
        driver.halt()
        driver.registers[0x1001] = 0x13579BDF
        driver.next_injection_fault = True
        driver.command(register=0x1001, post_exec=1, program0=0x00000013, program1=0x00100073,
                       expected_result=(0x13579BDF, 3))
        self.assertEqual(driver.last_data_valid, 1)

    def test_postexec_only_ignores_register_backend(self):
        driver = Driver({"enableC": True})
        driver.halt()
        driver.command(register=0xFFFF, size=0, transfer=0, post_exec=1,
                       program0=0x00100073, program1=0xDEADBEEF, expected_result=(0, 0))
        self.assertEqual(len(driver.injection_runs), 1)

    def test_fire_edge_is_not_cancel_completion(self):
        reference = ProgramReference({"enableC": True})
        reference.halted = True
        reference.owner = True
        reference.injecting = True
        reference.cancel_injection = False
        reference.pending_issue = True
        reference.step(row(active=1, warm_reset=1, injected_idle=1, injection_ready=1), 0)
        self.assertTrue(reference.injecting)
        self.assertFalse(reference.pending_issue)

    def test_completion_and_deactivation_do_not_latch_cancel(self):
        reference = ProgramReference({"enableC": True})
        reference.halted = True
        reference.owner = True
        reference.injecting = True
        reference.cancel_injection = False
        reference.step(row(active=0, done_valid=1, done_sequence=0, done_ebreak=1, injected_idle=1), 0)
        self.assertFalse(reference.injecting)
        self.assertFalse(reference.cancel_injection)
        reference.step(row(active=1, valid=1, transfer=0, post_exec=1, program0=0x00100073), 1)
        self.assertTrue(reference.injecting)

    def test_mutations_require_unique_targets(self):
        for name, source in (("no-issue", "assign core_injection_valid = pendingIssue;"),
                             ("no-data-valid", "assign debug_response_bits_dataValid = response_dataValid;")):
            with self.subTest(name=name):
                self.assertNotEqual(mutant(source, name), source)
                with self.assertRaises(ValueError):
                    mutant("", name)
                with self.assertRaises(ValueError):
                    mutant(source + source, name)


if __name__ == "__main__":
    unittest.main()
