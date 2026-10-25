# SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
# SPDX-License-Identifier: MIT

from dataclasses import replace
import unittest

from model import M_INSTRUCTIONS, Model
from protected_programs import COMPLETION, cases
from verify import InputSchedule


def execute(case):
    model = Model(case.words(), case.reset, case.instruction_fault, case.data_fault,
                  enable_m=case.enable_m, enable_c=case.enable_c, protected_mode=case.protected_mode)
    schedule = InputSchedule(case.interrupt_schedule)
    events, interrupts = [], []
    arithmetic = None
    arithmetic_starts = 0
    for cycle in range(20000):
        model.clock(cycle, schedule.clock(cycle))
        if model.interrupt_cause() is not None:
            interrupts.append(model.interrupt())
            schedule.event("N", len(interrupts))
            arithmetic = None
            continue
        if model.sleeping:
            continue
        if case.enable_m and model.word(model.pc) & 0xFE00007F == 0x02000033:
            if arithmetic is None:
                arithmetic_starts += 1
                schedule.event("M", arithmetic_starts)
                # Synthetic latency drives inputs without predicting RTL timing.
                arithmetic = cycle + 34
            if cycle < arithmetic:
                continue
            arithmetic = None
        event = model.step()
        events.append(event)
        if event.memory is not None:
            schedule.event("D", event.memory[0])
        schedule.event("R", event.pc)
        if event.pc == case.completion_pc:
            assert not event.trap and not event.user_mode and event.word == 0x6F and event.next_pc == event.pc
            assert tuple(item.cause for item in events if item.trap) == case.expected_causes, "Protected trap sequence differs"
            assert tuple(item[2] for item in interrupts) == case.expected_interrupts, "Protected interrupt sequence differs"
            for address, value in case.signature.items():
                assert model.word(address) == value, f"Protected signature differs at {address:#x}"
            for pc, machine in case.expected_memory_machine.items():
                selected = [item for item in events if item.pc == pc]
                assert len(selected) == 1 and selected[0].memory_machine == machine, "Effective data privilege differs"
            return model, events, interrupts
    raise AssertionError(f"Protected program did not complete: {case.name}")


class ProtectedProgramTests(unittest.TestCase):
    def test_fixed_program_signatures(self):
        for enable_m in (False, True):
            for enable_c in (False, True):
                selected = cases(enable_m=enable_m, enable_c=enable_c)
                self.assertEqual(len({case.name for case in selected}), len(selected))
                for case in selected:
                    with self.subTest(name=case.name, m=enable_m, c=enable_c):
                        model, _, _ = execute(case)
                        self.assertEqual(model.pc, COMPLETION)

    def test_halfword_high_and_wrapped_boot(self):
        for reset in (2, 0x80000002, 0xFFFFFFFE):
            for case in cases(reset=reset, enable_c=True):
                with self.subTest(name=case.name, reset=reset):
                    _, events, _ = execute(case)
                    self.assertEqual(events[0].pc, reset)

    def test_mprv_data_keeps_machine_instruction_identity(self):
        case = next(case for case in cases() if case.name == "protected_mprv_data")
        _, events, _ = execute(case)
        operations = [event for event in events if event.pc in case.expected_memory_machine]
        self.assertEqual(len(operations), 2)
        self.assertTrue(all(not event.user_mode and not event.memory_machine for event in operations))
        self.assertTrue(all(event.memory is not None for event in operations))

    def test_mret_machine_keeps_mprv_with_user_data_permissions(self):
        case = next(case for case in cases() if case.name == "protected_mret_machine_mprv")
        model, events, _ = execute(case)
        self.assertTrue(all(not event.user_mode for event in events))
        accesses = [event for event in events if event.pc in case.expected_memory_machine]
        self.assertEqual(len(accesses), 4)
        self.assertTrue(all(not event.memory_machine for event in accesses))
        denied = next(event for event in accesses if event.trap)
        self.assertEqual((denied.cause, denied.tval, denied.memory), (7, 0x400, None))
        self.assertEqual(model.word(0x400), 73)

    def test_denied_data_has_no_external_operation(self):
        case = next(case for case in cases() if case.name == "protected_mprv_denied")
        model, events, _ = execute(case)
        denied = next(event for event in events if event.cause == 5)
        self.assertIsNone(denied.memory)
        self.assertFalse(denied.memory_machine)
        self.assertEqual(model.word(0x400), 73)

    def test_all_pmp_entries_modes_and_locks(self):
        selected = {case.name: case for case in cases()}
        for index in range(16):
            for mode in range(4):
                with self.subTest(index=index, mode=mode):
                    case = selected[f"protected_pmp_entry_{index}_{mode}"]
                    model, events, _ = execute(case)
                    self.assertEqual(model.word(0x400), 42 if mode else 7)
                    denied = [event for event in events if event.cause in (5, 7)]
                    self.assertEqual(len(denied), 1 if mode else 3)
                    self.assertTrue(all(event.memory is None and event.user_mode for event in denied))
                    execute(selected[f"protected_pmp_lock_{index}_{mode}"])

    def test_user_interrupt_returns_to_the_next_instruction(self):
        case = next(case for case in cases() if case.name == "protected_user_irq_mie_zero")
        _, events, interrupts = execute(case)
        self.assertEqual(interrupts, [(0x100C, 0x2000, 0x8000000B)])
        resumed = [event for event in events if event.pc == 0x100C]
        self.assertEqual(len(resumed), 1)
        self.assertTrue(resumed[0].user_mode)
        self.assertEqual(resumed[0].value, 8)

    def test_execute_permission_denial_keeps_raw_instruction_zero(self):
        for machine in (False, True):
            for locked in (False, True):
                for permission in range(8):
                    name = f"protected_pmp_execute_{int(machine)}_{int(locked)}_{permission}"
                    case = next(case for case in cases() if case.name == name)
                    _, events, _ = execute(case)
                    denied = [event for event in events if event.cause == 1]
                    permitted = machine and not locked or bool(permission & 4)
                    self.assertEqual(len(denied), int(not permitted))
                    if denied:
                        self.assertEqual((denied[0].word, denied[0].length, denied[0].pc), (0, 4, 0x1000))

    def test_pmp_update_discards_old_permission(self):
        selected = {case.name: case for case in cases()}
        _, granted, _ = execute(selected["protected_pmp_grant_refetch"])
        resumed = [event for event in granted if event.pc == 0x1004]
        self.assertEqual(len(resumed), 1)
        self.assertFalse(resumed[0].trap)
        self.assertEqual(resumed[0].value, 7)
        _, revoked, _ = execute(selected["protected_pmp_revoke_refetch"])
        denied = next(event for event in revoked if event.cause == 1)
        self.assertEqual((denied.word, denied.pc, denied.tval), (0, 0x1028, 0x1028))
        self.assertIsNone(denied.memory)

    def test_compressed_fault_lengths_and_retry(self):
        selected = {case.name: case for case in cases(enable_c=True)}
        for name, length, tval in (("protected_c_first_word_denied", 2, 0x1002),
                                   ("protected_c_second_word_denied", 4, 0x1004)):
            _, events, _ = execute(selected[name])
            denied = next(event for event in events if event.cause == 1)
            self.assertEqual((denied.word, denied.length, denied.pc, denied.tval), (0, length, 0x1002, tval))
        _, events, _ = execute(selected["protected_c_grant_retry"])
        attempts = [event for event in events if event.pc == 0x1002]
        self.assertEqual(len(attempts), 2)
        self.assertTrue(attempts[0].trap)
        self.assertFalse(attempts[1].trap)
        self.assertEqual(attempts[1].value, 42)
        _, events, _ = execute(selected["protected_c_region_end"])
        last = next(event for event in events if event.pc == 0x1002)
        self.assertEqual(last.length, 2)
        self.assertEqual(last.memory[0], 0x500)
        self.assertFalse(last.memory_machine)

    def test_compressed_user_interrupt_preserves_halfword_pc(self):
        for name in ("protected_c_irq_halfword", "protected_c_irq_crossing"):
            case = next(case for case in cases(enable_c=True) if case.name == name)
            _, events, interrupts = execute(case)
            self.assertEqual(interrupts, [(0x1006, 0x2000, 0x8000000B)])
            resumed = [event for event in events if event.pc == 0x1006]
            self.assertEqual(len(resumed), 1)
            self.assertTrue(resumed[0].user_mode)
            self.assertEqual(resumed[0].value, 7)

    def test_user_compute_interrupts_before_arithmetic_retirement(self):
        for compressed in (False, True):
            case = next(case for case in cases(enable_m=True, enable_c=compressed) if case.name == "protected_user_compute")
            _, events, interrupts = execute(case)
            self.assertEqual(len(interrupts), 1)
            operations = [event for event in events if event.instruction in M_INSTRUCTIONS]
            self.assertEqual(len(operations), 8)
            self.assertEqual({event.instruction for event in operations}, set(M_INSTRUCTIONS))
            self.assertEqual(interrupts[0][0], operations[0].pc)
            self.assertEqual(operations[0].instruction, "div")
            self.assertTrue(all(event.user_mode and not event.trap for event in operations))
            accesses = [event for event in events if event.user_mode and event.memory is not None]
            self.assertTrue(all(not event.memory_machine for event in accesses))
            self.assertEqual({event.memory[4] for event in accesses}, {0, 1, 2})
            if compressed:
                self.assertGreater(sum(event.user_mode and event.length == 2 for event in events), 8)

    def test_bad_signature_and_trap_sequence_are_rejected(self):
        case = next(case for case in cases() if case.name == "protected_user_ecall")
        for altered in (replace(case, signature={0x500: 99}), replace(case, expected_causes=(11,))):
            with self.assertRaises(AssertionError):
                execute(altered)
        original = case.words()
        changed = case.words()
        changed[0] = 0
        self.assertEqual(case.words(), original)

    def test_reset_alignment_is_explicit(self):
        for reset, enabled in ((1, True), (2, False), (-4, False), (1 << 32, True), (False, False)):
            with self.subTest(reset=reset, c=enabled), self.assertRaises(ValueError):
                cases(reset=reset, enable_c=enabled)


if __name__ == "__main__":
    unittest.main()
