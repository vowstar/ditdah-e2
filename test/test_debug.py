# SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
# SPDX-License-Identifier: MIT
"""Check independent debug state transitions and mutation targeting."""

import unittest

from debug_programs import cases, VALUE
from model import Model
from verify_debug import DebugReference, mutate_register_write, mutate_protection, mutate_reset


class DebugTests(unittest.TestCase):
    def setUp(self):
        self.model = Model(cases()[0].image, enable_m=True, enable_c=True, protected_mode=True)
        self.debug = DebugReference(self.model)

    def test_zero_register_ignores_write(self):
        self.assertEqual(self.debug.register(0x1000, VALUE), 0)

    def test_resume_uses_debug_pc(self):
        self.debug.active = self.debug.halted = True
        self.model.sleeping = True
        self.debug.register(0x7B1, 0x203)
        self.debug.request(0x10, 2, 0x40000001, 0)
        self.assertEqual(self.model.pc, 0x202)
        self.assertFalse(self.model.sleeping)

    def test_user_resume_clears_mprv(self):
        self.debug.active = self.debug.halted = True
        self.debug.register(0x7B0, 0)
        self.model.csrs[0x300] |= 1 << 17
        self.debug.request(0x10, 2, 0x40000001, 0)
        self.assertTrue(self.model.user_mode)
        self.assertFalse(self.model.csrs[0x300] & (1 << 17))

    def test_step_rejects_second_retirement(self):
        self.debug.step_start = 3
        with self.assertRaisesRegex(AssertionError, "incorrect instruction count"):
            self.debug.response(0x11, 1, 0, 0, 0x3A3,
                                {"outstanding": False, "completed": False, "pc": 16, "user": False, "retirements": 5})

    def test_halt_rejects_pending_memory(self):
        with self.assertRaisesRegex(AssertionError, "unfinished memory"):
            self.debug.response(0x11, 1, 0, 0, 0x3A3,
                                {"outstanding": True, "completed": False})

    def test_abstract_read_rejects_wrong_result(self):
        self.debug.data[0] = VALUE
        with self.assertRaisesRegex(AssertionError, "result mismatch"):
            self.debug.response(4, 1, 0, 0, VALUE ^ 1, {})

    def test_mutation_requires_unique_assignment(self):
        source = "assign backend_writePulse = accepted & write;"
        self.assertIn("16'h100A", mutate_register_write(source))
        for text in ("", source + source):
            with self.assertRaisesRegex(AssertionError, "target changed"):
                mutate_register_write(text)

    def test_word_aligned_debug_pc(self):
        reference = DebugReference(Model({}, enable_c=False))
        self.assertEqual(reference.register(0x7B1, 0x203), 0x200)

    def test_machine_only_privilege_is_fixed(self):
        reference = DebugReference(Model({}))
        self.assertEqual(reference.register(0x7B0, 0) & 3, 3)
        self.assertEqual(reference.register(0x340, VALUE), VALUE)

    def test_machine_only_memory_has_no_pmp(self):
        reference = DebugReference(Model({}))
        reference.active = reference.halted = True
        reference.data[1] = 0x400
        reference.request(0x17, 2, 0x2200000, 0)
        self.assertFalse(reference.pending["denied"])
        self.assertEqual(reference.pending["request"][5], 1)

    def test_cycle_samples_require_stability(self):
        self.debug.halted = True
        self.debug.data[0] = None
        self.debug.response(4, 1, 0, 0, 123, {})
        self.debug.data[0] = None
        with self.assertRaisesRegex(AssertionError, "counter advanced"):
            self.debug.response(4, 1, 0, 0, 124, {})

    def test_released_reset_remains_pending(self):
        self.debug.active = True
        self.debug.request(0x10, 2, 3, 0)
        self.debug.request(0x10, 2, 1, 0)
        self.assertTrue(self.debug.reset_expected)
        self.assertFalse(self.debug.reset_requested)

    def test_configuration_workloads(self):
        for protected in (False, True):
            for multiply in (False, True):
                for compressed in (False, True):
                    workloads = cases(multiply, compressed, protected)
                    self.assertEqual(len(workloads), 15 if protected else 12)
                    self.assertEqual(len({case.name for case in workloads}), len(workloads))
                    self.assertTrue(all(case.enable_m == multiply and case.enable_c == compressed and
                                        case.protected_mode == protected for case in workloads))

    def test_protocol_mutants_reject_missing_targets(self):
        for mutation in (mutate_protection, mutate_reset):
            with self.assertRaisesRegex(AssertionError, "target changed"):
                mutation("")


if __name__ == "__main__":
    unittest.main()
