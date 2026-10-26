# SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
# SPDX-License-Identifier: MIT
"""Check independent debug state transitions and mutation targeting."""

import unittest

from debug_programs import cases, VALUE, WRITE, WAIT_IRQ, RESTART
from model import Model
from verify_debug import (DebugReference, mutate_register_write, mutate_protection, mutate_reset,
                          mutate_trap_pc, mutate_mret_privilege, mutate_step_pc,
                          mutate_memory_fault, mutate_reset_halt, mutate_orphan_resume)


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

    def test_menvcfg_abstract_access_preserves_halted_state(self):
        for user in (False, True):
            with self.subTest(user=user):
                model = Model({}, protected_mode=True)
                model.user_mode, model.pc = user, RESTART
                for number, value in ((0x341, 0x234), (0x342, 7), (0x343, 0xABCDEF)):
                    model.write_csr(number, value)
                debug = DebugReference(model)
                debug.active = debug.halted = True
                debug.dpc, debug.control = RESTART, 0 if user else 3
                before = (model.pc, model.user_mode, dict(model.csrs), debug.dpc, debug.control)
                for value in (None, 0xFFFFFFFF, None):
                    if value is not None:
                        debug.request(4, 2, value, 0)
                    command = (2 << 20) | (1 << 17) | (int(value is not None) << 16) | 0x30A
                    debug.request(0x17, 2, command, 0)
                    debug.response(0x16, 1, 0, 0, 2, {})
                    if value is None:
                        debug.response(4, 1, 0, 0, 0, {})
                    self.assertEqual((model.pc, model.user_mode, model.csrs, debug.dpc, debug.control), before)

    def test_menvcfg_abstract_access_rejects_wrong_result_or_error(self):
        for data, status in ((1, 2), (0, 0x202)):
            debug = DebugReference(Model({}, protected_mode=True))
            debug.active = debug.halted = True
            debug.request(0x17, 2, 0x22030A, 0)
            with self.assertRaisesRegex(AssertionError, "Abstract (register result mismatch|command error differs)"):
                debug.response(0x16, 1, 0, 0, status, {})
                debug.response(4, 1, 0, 0, data, {})

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
                    self.assertEqual(len(workloads), 33 if protected else 24)
                    self.assertEqual(len({case.name for case in workloads}), len(workloads))
                    self.assertTrue(all(case.enable_m == multiply and case.enable_c == compressed and
                                        case.protected_mode == protected for case in workloads))

    def test_protocol_mutants_reject_missing_targets(self):
        for mutation in (mutate_protection, mutate_reset, mutate_trap_pc, mutate_mret_privilege, mutate_step_pc,
                         mutate_memory_fault, mutate_reset_halt, mutate_orphan_resume):
            with self.assertRaisesRegex(AssertionError, "target changed"):
                mutation("")

    def test_boundary_mutations_change_semantics(self):
        self.assertIn("+ 32'd4", mutate_trap_pc("mepc <= {trapPc[31:1], 1'h0};"))
        self.assertIn("? 1'h0 : userMode_0", mutate_mret_privilege("_GEN_230 ? mppUser : userMode_0"))
        self.assertIn("entryCause == 3'h4", mutate_step_pc(": core_architecturalPc;"))

    def test_abstract_fault_keeps_data_and_requires_error_clear(self):
        self.debug.active = self.debug.halted = True
        self.debug.data = [VALUE, 0x440]
        self.debug.request(0x17, 2, 0x2200000, 0)
        self.debug.pending.update(completed=True, fault=True)
        self.debug.response(0x16, 1, 0, 0, 0x502, {})
        self.assertEqual(self.debug.error, 5)
        self.assertEqual(self.debug.data[0], VALUE)
        with self.assertRaisesRegex(AssertionError, "before error clearance"):
            self.debug.request(0x17, 2, 0x2200000, 0)
        self.debug.request(0x16, 2, 0x700, 0)
        self.debug.request(0x17, 2, 0x2200000, 0)
        self.debug.pending.update(completed=True, fault=False)
        self.debug.response(0x16, 1, 0, 0, 2, {})
        self.assertEqual(self.debug.error, 0)

    def test_abstract_fault_rejects_success_status(self):
        self.debug.pending = {"request": (0x440, 0, 0, 0, 2, 1), "denied": False,
                              "completed": True, "fault": True}
        with self.assertRaisesRegex(AssertionError, "command error differs"):
            self.debug.response(0x16, 1, 0, 0, 2, {})

    def test_reset_halt_set_clear_and_busy(self):
        self.debug.active = True
        self.debug.request(0x10, 2, 9, 0)
        self.assertTrue(self.debug.halt_on_reset)
        self.debug.pending = {"request": (0x440, 1, 0, 15, 2, 1)}
        self.debug.request(0x10, 2, 5, 0)
        self.assertTrue(self.debug.halt_on_reset)
        self.debug.pending = None
        self.debug.request(0x10, 2, 13, 0)
        self.assertFalse(self.debug.halt_on_reset)

    def test_reset_halt_cause_and_boundary(self):
        self.debug.reset_halt_pending = True
        snapshot = {"outstanding": False, "completed": False, "pc": 0, "user": False, "retirements": 9}
        self.debug.response(0x11, 1, 0, 0, 0x3A3, snapshot)
        self.assertEqual((self.debug.cause, self.debug.dpc, self.debug.reset_halts), (5, 0, 1))
        self.debug.halted = False
        self.debug.reset_halt_pending = True
        with self.assertRaisesRegex(AssertionError, "initial boundary"):
            self.debug.response(0x11, 1, 0, 0, 0x3A3, snapshot | {"pc": 4})

    def test_directed_step_encodings(self):
        for case in cases():
            if case.step_outcome is None:
                continue
            with self.subTest(case=case.name):
                model = Model(case.image, enable_m=True, enable_c=True, protected_mode=True)
                debug = DebugReference(model)
                data = 0
                for kind, address, value, _ in case.actions:
                    if (kind, address, value) == (WRITE, 0x10, 0x40000001):
                        break
                    if kind == WRITE and address == 4:
                        data = value
                    if kind == WRITE and address == 0x17 and value >> 24 == 0 and value & (1 << 16):
                        debug.register(value & 0xFFFF, data)
                model.pc = debug.dpc
                model.user_mode = debug.control & 3 == 0
                event = model.step()
                self.assertEqual((event.pc, event.next_pc, event.trap, event.cause if event.trap else 0,
                                  event.user_mode), case.step_outcome)
                if case.name == "step_load":
                    self.assertEqual(event.value, 0x11223344)
                if case.name == "step_mret_user":
                    self.assertTrue(model.user_mode)

    def test_irq_program_requires_real_external_event(self):
        case = next(case for case in cases() if case.name == "user_irq_handler_halt")
        self.assertEqual(case.interrupts, 1)
        self.assertEqual([action[1] for action in case.actions if action[0] == WAIT_IRQ], [0x8000000B])
        model = Model(case.image, protected_mode=True)
        model.pc = RESTART
        model.user_mode = True
        model.write_csr(0x3B0, 0xFFFFFFFF)
        model.write_csr(0x3A0, 0x1F)
        model.write_csr(0x304, 0x800)
        model.write_csr(0x305, 0x180)
        model.write_csr(0x300, 0)
        model.clock(0, 4)
        self.assertEqual(model.interrupt(), (RESTART, 0x180, 0x8000000B))
        self.assertFalse(model.user_mode)
        self.assertEqual(model.read_csr(0x300), 0)

    def test_pending_resume_does_not_count_the_old_halt_as_a_step(self):
        self.debug.active = self.debug.halted = True
        self.debug.control = 7
        self.debug.orphan = {"completed": False}
        self.debug.cycle = 10
        self.debug.request(0x10, 2, 0x40000001, 3)
        snapshot = {"outstanding": True, "completed": False, "orphan": True, "retirements": 3}
        self.debug.response(0x11, 1, 0, 0, 0x3A3, snapshot)
        self.assertEqual(self.debug.steps, 0)
        with self.assertRaisesRegex(AssertionError, "Resume acknowledged before orphan"):
            self.debug.response(0x11, 1, 0, 0, 0x30CA3, snapshot)

    def test_orphan_scenarios_resume_without_waiting_for_the_transfer(self):
        for case in cases(False, False, False):
            if not case.orphan_step:
                continue
            resume = case.actions.index((WRITE, 0x10, 0x40000001, 0))
            deactivate = case.actions.index((WRITE, 0x10, 0, 0))
            self.assertEqual(case.actions[deactivate + 1:resume], [(WRITE, 0x10, 1, 0), (3, 0x16, 0, 1 << 12)])
            self.assertTrue(case.actions[resume + 1][0] == 3)
            self.assertEqual(case.steps, 1)

    def test_orphan_resume_mutation_removes_only_native_ownership(self):
        source = "wire resume = active & halted & ~responding & ~sending & ~waiting;"
        self.assertEqual(mutate_orphan_resume(source), "wire resume = active & halted & ~responding;")


if __name__ == "__main__":
    unittest.main()
