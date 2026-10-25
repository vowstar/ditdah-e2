# SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
# SPDX-License-Identifier: MIT
"""Check atomic instruction semantics without a hardware decoder."""

import unittest

from atomic_programs import atomic, cases, RAM
from model import Model, atomic_value


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
            if case.competitors or case.interrupts or case.debug:
                continue
            with self.subTest(case=case.name):
                model = Model(case.image, enable_a=True, enable_m=True, enable_c=True, protected_mode=True)
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


if __name__ == "__main__":
    unittest.main()
