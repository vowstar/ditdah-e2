# SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
# SPDX-License-Identifier: MIT
"""Check atomic instruction semantics without a hardware decoder."""

import unittest
from types import SimpleNamespace

from atomic_programs import atomic, cases, RAM
from model import Model, atomic_value
from verify_atomic import mutate_atomic, trace_cycles, selected_cases, check_competitors, atomic_write_witness, boundary_witness


class AtomicModelTests(unittest.TestCase):
    def model(self, word, old=0x80000003, operand=0x7FFFFFFE, **options):
        model = Model({0: word, RAM: old, RAM + 4: 0}, enable_a=True, **options)
        model.registers[1], model.registers[2] = RAM, operand
        return model

    def test_arithmetic_boundary_values(self):
        expected = {1: 0x7FFFFFFE, 0: 1, 4: 0xFFFFFFFD, 12: 2, 8: 0xFFFFFFFF,
                    16: 0x80000003, 20: 0x7FFFFFFE, 24: 0x7FFFFFFE, 28: 0x80000003}
        for function, value in expected.items():
            self.assertEqual(atomic_value(function, 0x80000003, 0x7FFFFFFE), value)

    def test_amo_returns_old_word(self):
        model = self.model(atomic("amoadd.w", 5, 1, 2))
        event = model.step()
        self.assertEqual((event.value, model.word(RAM), event.memory_operation), (0x80000003, 1, 4))

    def test_x0_still_updates_memory(self):
        model = self.model(atomic("amoswap.w", 0, 1, 2))
        event = model.step()
        self.assertEqual((event.rd, event.value, model.word(RAM)), (0, 0, 0x7FFFFFFE))

    def test_lr_rejects_nonzero_rs2(self):
        event = self.model(atomic("lr.w", 5, 1, 2)).step()
        self.assertTrue(event.trap)
        self.assertEqual(event.cause, 2)

    def test_disabled_extension_is_illegal(self):
        event = Model({0: atomic("amoadd.w", 5, 1, 2)}).step()
        self.assertEqual((event.trap, event.cause), (True, 2))

    def test_illegal_functions_and_widths(self):
        for word in (atomic("amoadd.w", 5, 1, 2) | 0x1000, (7 << 27) | 0x202F):
            event = self.model(word).step()
            self.assertEqual((event.trap, event.cause), (True, 2))

    def test_misalignment_causes(self):
        for operation, cause in (("lr.w", 4), ("sc.w", 6), ("amoadd.w", 6)):
            model = self.model(atomic(operation, 5, 1, 0 if operation == "lr.w" else 2))
            model.registers[1] += 2
            event = model.step()
            self.assertEqual((event.cause, event.tval, event.memory), (cause, RAM + 2, None))

    def test_sc_consumes_reservation(self):
        model = Model({0: atomic("lr.w", 5, 1), 4: atomic("sc.w", 6, 1, 2),
                       8: atomic("sc.w", 7, 1, 2), RAM: 42}, enable_a=True)
        model.registers[1], model.registers[2] = RAM, 91
        self.assertEqual([model.step().value for _ in range(3)], [42, 0, 1])
        self.assertEqual(model.word(RAM), 91)

    def test_second_lr_replaces_reservation(self):
        model = Model({0: atomic("lr.w", 5, 1), 4: atomic("lr.w", 6, 3),
                       8: atomic("sc.w", 7, 1, 2), RAM: 42, RAM + 4: 67}, enable_a=True)
        model.registers[1], model.registers[2], model.registers[3] = RAM, 91, RAM + 4
        self.assertEqual([model.step().value for _ in range(3)], [42, 67, 1])
        self.assertEqual(model.word(RAM), 42)

    def test_history_value_survives_later_memory_change(self):
        seen = []

        def completion(event):
            seen.append(event.memory)
            return 123, False

        model = self.model(atomic("amoadd.w", 5, 1, 2), old=999, operand=7, memory_access=completion)
        event = model.step()
        self.assertEqual((event.value, model.word(RAM)), (123, 130))
        self.assertEqual(seen, [(RAM, 1, 7, 15, 2)])

    def test_history_fault_has_store_cause(self):
        model = self.model(atomic("amoadd.w", 5, 1, 2), memory_access=lambda event: (0, True))
        event = model.step()
        self.assertEqual((event.trap, event.cause, event.tval), (True, 7, RAM))
        self.assertEqual(model.word(RAM), 0x80000003)

    def test_failed_sc_still_checks_permissions(self):
        model = self.model(atomic("sc.w", 5, 1, 2), protected_mode=True)
        model.user_mode = True
        model.pmp.write(0x3B0, RAM >> 2)
        model.pmp.write(0x3A0, 0x11)
        model.pmp.write(0x3B1, 0xFFFFFFFF)
        model.pmp.write(0x3A0, 0x1F11)
        event = model.step()
        self.assertEqual((event.cause, event.memory), (7, None))

    def test_amo_requires_read_and_write(self):
        for permissions in (1, 4, 5):
            model = self.model(atomic("amoadd.w", 5, 1, 2), protected_mode=True)
            model.user_mode = True
            model.pmp.write(0x3B0, RAM >> 2)
            model.pmp.write(0x3B1, 0xFFFFFFFF)
            model.pmp.write(0x3A0, 0x1F00 | 0x10 | permissions)
            event = model.step()
            self.assertEqual((event.cause, event.memory), (7, None))

    def test_fixed_programs_without_competitors(self):
        programs = cases()
        self.assertEqual(len({case.name for case in programs}), len(programs))
        for case in programs:
            if case.competitors or case.interrupts or case.debug or case.console or case.boundary:
                continue
            with self.subTest(case=case.name):
                model = Model(case.image, data_fault=case.pma_fault, enable_a=True, enable_m=True, enable_c=True, protected_mode=True)
                causes = []
                for _ in range(300):
                    event = model.step()
                    if event.trap:
                        causes.append(event.cause)
                    if event.pc == case.completion_pc:
                        break
                else:
                    self.fail("Atomic program did not complete")
                self.assertEqual(tuple(causes), case.expected_causes)
                self.assertEqual({address: model.word(address) for address in case.signature}, case.signature)

    def test_mutations_require_exact_targets(self):
        for kind in ("amo", "invalidation", "clear", "response", "reset", "forward", "split", "duplicate", "early-irq-clear", "early-halt-clear"):
            with self.assertRaisesRegex(AssertionError, "target changed"):
                mutate_atomic("", kind)
        source = "assign competitor_response_bits_data = responses_data_2;"
        self.assertIn("_memory_readData", mutate_atomic(source, "response"))
        with self.assertRaisesRegex(AssertionError, "target changed"):
            mutate_atomic(source + source, "response")
        source = "wire [31:0] b = match2 & ~m_load ? m_value : data;"
        self.assertIn("~isAtomic", mutate_atomic(source, "forward"))

    def test_bit_dependency_program(self):
        case = next(case for case in cases(True, True, True) if case.name == "atomic_bit_dependencies")
        model = Model(case.image, enable_a=True, enable_zba=True, enable_zbb=True, enable_zbs=True)
        operations = []
        for _ in range(100):
            event = model.step()
            self.assertFalse(event.trap)
            operations.append(event.instruction)
            if event.pc == case.completion_pc:
                break
        else:
            self.fail("Atomic bit program did not complete")
        self.assertEqual({address: model.word(address) for address in case.signature}, case.signature)
        for name in ("rev8", "bclri", "sh1add", "rori", "bseti", "sh2add", "amoadd.w", "amoxor.w", "lr.w", "sc.w"):
            self.assertEqual(operations.count(name), 1)

    def test_bit_program_requires_each_extension(self):
        for subset in range(7):
            self.assertNotIn("atomic_bit_dependencies", {case.name for case in cases(bool(subset & 1), bool(subset & 2), bool(subset & 4))})

    def test_forward_program_requires_multiply(self):
        self.assertNotIn("atomic_input_forward", {case.name for case in cases(enable_m=False)})
        self.assertTrue(next(case for case in cases() if case.name == "atomic_input_forward").requires_atomic_forward)

    def test_minimal_configuration_selects_executable_programs(self):
        parameters = dict.fromkeys(("enableM", "enableC", "protectedMode", "enableDebug"), False)
        programs = selected_cases(parameters)
        self.assertEqual(len(programs), 134)
        for case in programs:
            self.assertFalse(case.enable_m or case.enable_c or case.protected_mode or case.debug)
            if case.competitors or case.interrupts or case.console or case.boundary:
                continue
            model = Model(case.image, data_fault=case.pma_fault, enable_a=True)
            causes = []
            for _ in range(300):
                event = model.step()
                if event.trap:
                    causes.append(event.cause)
                if event.pc == case.completion_pc:
                    break
            else:
                self.fail("Minimal atomic program did not finish")
            self.assertEqual(tuple(causes), case.expected_causes)
            self.assertEqual({address: model.word(address) for address in case.signature}, case.signature)

    def test_disabled_program_requirements_are_rejected(self):
        parameters = dict.fromkeys(("enableM", "enableC", "protectedMode", "enableDebug"), False)
        for name in ("debug_halt_reservation", "user_atomic_execution", "lr_w_pmp_denied", "atomic_input_forward"):
            with self.assertRaisesRegex(AssertionError, "disabled required feature"):
                selected_cases(parameters, [name])

    def test_partial_trace_is_not_a_completed_run(self):
        source = "T 0 0 0 0 0 0 0 0\n"
        with self.assertRaisesRegex(AssertionError, "did not finish"):
            trace_cycles(source)
        self.assertEqual(len(trace_cycles(source, partial=True)), 1)

    def test_competitor_must_observe_flag_before_message(self):
        case = SimpleNamespace(competitors=[
            {"address": RAM, "size": 2, "write": False, "data": 0, "pollUntil": 1},
            {"address": RAM + 4, "size": 2, "write": False, "data": 0, "expectedRead": 42}])
        def read(address, value):
            return {"request": (address, 1, 0, 0, 0, 2, 0), "response": (value, 0)}
        history = [read(RAM, 0), read(RAM, 1), read(RAM + 4, 42)]
        self.assertEqual(check_competitors(case, history), {"transactions": 3, "actions": 2, "pollRetries": 1})
        with self.assertRaisesRegex(AssertionError, "payload differs"):
            check_competitors(case, [history[0], history[2]])
        with self.assertRaisesRegex(AssertionError, "wrong message"):
            check_competitors(case, [*history[:2], read(RAM + 4, 0)])
        with self.assertRaisesRegex(AssertionError, "Extra competing transaction"):
            check_competitors(case, history + history[-1:])

    def test_atomic_control_requires_a_real_pending_window(self):
        case = SimpleNamespace(boundary=("interrupt", 100, 1))
        groups = [[list(map(str, ("T", cycle, 0, 0, int(cycle == 3), 0, 0, 0, int(1 <= cycle <= 3))))]
                  for cycle in range(6)]
        for cycle, text in ((0, f"Q 0 D {RAM} 0 0 0 2 1 1"), (2, "S 2 D 42 0"),
                (2, "R 2 100 0 104"), (3, "N 3 104 2048 2147483659"),
                (4, "R 4 2056 807403635 104"), (5, "R 5 104 0 108")):
            groups[cycle].append(text.split())
        self.assertEqual(boundary_witness(case, groups)["controlCycle"], 1)
        groups[1][0][-1] = "0"
        with self.assertRaisesRegex(AssertionError, "did not arrive during"):
            boundary_witness(case, groups)
        groups[1][0][-1] = "1"
        groups[1][0][4] = "1"
        with self.assertRaisesRegex(AssertionError, "Reservation cleared before"):
            boundary_witness(case, groups)
        groups[1][0][4] = "0"
        groups[2].append(f"Q 2 D {RAM + 4} 1 17 15 2 1 0".split())
        with self.assertRaisesRegex(AssertionError, "Younger data request"):
            boundary_witness(case, groups)
        groups[2].pop()
        groups[3][1][2] = "108"
        with self.assertRaisesRegex(AssertionError, "saved the wrong PC"):
            boundary_witness(case, groups)

    def test_memory_fault_witness_requires_actual_writes(self):
        rows = [[0] * 57 for _ in range(4)]
        rows[0][-3:] = [0, 15, 16]
        rows[1][14], rows[1][15], rows[1][18], rows[1][21], rows[1][23] = 1, RAM, 3, 4, 1
        rows[1][-4:-2] = [1, 0]
        rows[2][-3:] = rows[3][-3:] = [0, 15, 19]
        def trace():
            return '\n'.join('B ' + str(cycle) + ' ' + ' '.join(map(str, row)) for cycle, row in enumerate(rows))
        self.assertEqual(atomic_write_witness(trace(), "duplicate")["secondWriteCycle"], 3)
        rows[3][-2] = 0
        with self.assertRaisesRegex(AssertionError, "faulty write effects"):
            atomic_write_witness(trace(), "duplicate")
        rows[3][-2] = 15
        rows[2][40], rows[2][41], rows[2][43], rows[2][44], rows[2][45], rows[2][49] = 1, RAM, 1, 128, 15, 1
        rows[2][-1] = 128
        self.assertEqual(atomic_write_witness(trace(), "split")["firstWriteCycle"], 2)
        rows[3][-1] = 128
        with self.assertRaisesRegex(AssertionError, "did not split"):
            atomic_write_witness(trace(), "split")


if __name__ == "__main__":
    unittest.main()
