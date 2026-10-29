# SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
# SPDX-License-Identifier: MIT
"""Check fixed machine and user instruction effects and PMP fault ownership."""

import unittest

from model import Model


MRET = 0x30200073
WFI = 0x10500073
ECALL = 0x00000073


def user_program(word, *, status=0, permission=0x1F, enable_c=False, target=0x100):
    words = {0: MRET, target: word, 0x200: 0x0000006F}
    model = Model(words, protected_mode=True, enable_c=enable_c)
    model.write_csr(0x3B0, 0x1FFFFFFF)
    model.write_csr(0x3A0, permission)
    model.write_csr(0x305, 0x200)
    model.write_csr(0x341, target)
    model.write_csr(0x300, status)
    event = model.step()
    assert event.instruction == "mret" and not event.trap and not event.user_mode and model.user_mode
    return model


class PrivilegeTests(unittest.TestCase):
    def test_menvcfg_fixed_zero_and_access_privilege(self):
        for address in (0x30A, 0x31A):
            for operation in (1, 2, 3, 5, 6, 7):
                for source in (0, 1, 31):
                    word = (address << 20) | source << 15 | operation << 12 | 10 << 7 | 0x73
                    model = Model({0: word, 4: (address << 20) | 0x25F3}, protected_mode=True)
                    model.registers[1], model.registers[31], model.registers[10] = 0xFFFFFFFF, 0x55AA55AA, 55
                    event = model.step()
                    self.assertEqual((event.trap, event.rd, event.value, event.next_pc), (False, 10, 0, 4))
                    self.assertEqual(model.read_csr(address), 0)
                    self.assertEqual(model.step().value, 0)
                    for restricted in (Model({0: word}), user_program(word)):
                        pc, user = restricted.pc, restricted.user_mode
                        restricted.registers[10] = 55
                        event = restricted.step()
                        self.assertEqual((event.pc, event.user_mode, event.trap, event.cause, event.tval, event.rd),
                                         (pc, user, True, 2, word, 0))
                        self.assertEqual(restricted.registers[10], 55)
                        self.assertEqual(restricted.read_csr(0x341), pc)

    def test_menvcfg_zero_source_suppresses_only_set_and_clear_writes(self):
        for address in (0x30A, 0x31A):
            for operation in (1, 2, 3, 5, 6, 7):
                for source in (0, 1):
                    word = (address << 20) | source << 15 | operation << 12 | 0x73
                    model = Model({0: word}, protected_mode=True)
                    writes = []
                    original = model.write_csr
                    def record(address, value):
                        writes.append((address, value))
                        original(address, value)
                    model.write_csr = record
                    event = model.step()
                    self.assertFalse(event.trap)
                    self.assertEqual(event.rd, 0)
                    self.assertEqual(len(writes), int(operation in (1, 5) or source != 0))
                    self.assertEqual(model.read_csr(address), 0)

    def test_default_profile_is_unchanged(self):
        model = Model({0: ECALL})
        self.assertFalse(model.protected_mode)
        self.assertFalse(model.user_mode)
        self.assertIsNone(model.pmp)
        self.assertEqual(model.read_csr(0x301), 0x40000100)
        model.write_csr(0x300, 0xFFFFFFFF)
        self.assertEqual(model.read_csr(0x300), 0x1888)
        event = model.step()
        self.assertEqual((event.user_mode, event.cause), (False, 11))
        for word in (0x306020F3, 0x3A0020F3, 0x3B0020F3):
            event = Model({0: word}).step()
            self.assertEqual((event.trap, event.cause, event.tval), (True, 2, word))

    def test_profile_identity_and_status_warl(self):
        for enable_m in (False, True):
            for enable_c in (False, True):
                model = Model({}, protected_mode=True, enable_m=enable_m, enable_c=enable_c)
                self.assertEqual(model.read_csr(0x301), 0x40100100 | (int(enable_m) << 12) | (int(enable_c) << 2))
                self.assertEqual(model.read_csr(0x300), 0x1800)
                self.assertEqual(model.read_csr(0x306), 0)
                model.write_csr(0x301, 0)
                self.assertTrue(model.read_csr(0x301) & (1 << 20))
        for value, expected in ((0, 0), (0x800, 0x1800), (0x1000, 0x1800),
                                (0x1800, 0x1800), (0xFFFFFFFF, 0x221888)):
            model.write_csr(0x300, value)
            self.assertEqual(model.read_csr(0x300), expected)
        model.write_csr(0x306, 0xFFFFFFFF)
        self.assertEqual(model.read_csr(0x306), 7)

    def test_mret_restores_user_and_clears_mprv(self):
        model = user_program(ECALL, status=0x220080)
        self.assertEqual(model.pc, 0x100)
        self.assertEqual(model.read_csr(0x300), 0x200088)
        event = model.step()
        self.assertEqual((event.user_mode, event.cause, event.tval, event.next_pc), (True, 8, 0, 0x200))
        self.assertFalse(model.user_mode)
        self.assertEqual(model.read_csr(0x300), 0x200080)
        self.assertEqual(model.read_csr(0x341), 0x100)

    def test_mret_to_machine_preserves_mprv_and_resets_mpp(self):
        model = Model({0: MRET}, protected_mode=True)
        model.write_csr(0x300, 0x221880)
        model.write_csr(0x341, 0x100)
        event = model.step()
        self.assertFalse(event.user_mode)
        self.assertFalse(model.user_mode)
        self.assertEqual(model.read_csr(0x300), 0x220088)
        self.assertEqual(model.pc, 0x100)

    def test_user_machine_csr_and_mret_are_illegal(self):
        for word in (MRET, 0x300020F3, 0x306020F3, 0xF11020F3, 0x3A0020F3,
                     0x3B0020F3, 0xB00020F3, 0x340090F3):
            model = user_program(word)
            model.registers[1] = 0x55
            event = model.step()
            self.assertEqual((event.user_mode, event.trap, event.cause, event.tval), (True, True, 2, word))
            self.assertEqual(model.registers[1], 0x55)
            self.assertEqual(model.read_csr(0x340), 0)
            self.assertFalse(model.user_mode)

    def test_user_counter_aliases_require_individual_enable(self):
        for address in (0xC00, 0xC80, 0xC01, 0xC81, 0xC02, 0xC82):
            word = (address << 20) | 0x20F3
            bit = 1 << (address & 3)
            for mask in (0, bit, 7 ^ bit, 7):
                model = user_program(word)
                model.write_csr(0x306, mask)
                model.counters[0xB00] = 0x123456789ABCDEF0
                model.counters[0xB02] = 0x0FEDCBA987654321
                model.clock(1)
                model.time = 0x76543210FEDCBA98
                value = {0xC00: 0x9ABCDEF1, 0xC80: 0x12345678, 0xC01: 0xFEDCBA98,
                         0xC81: 0x76543210, 0xC02: 0x87654322, 0xC82: 0x0FEDCBA9}[address]
                event = model.step()
                self.assertEqual(event.trap, not bool(mask & bit))
                if mask & bit:
                    self.assertEqual((event.rd, event.value), (1, value))
                else:
                    self.assertEqual((event.cause, event.tval), (2, word))
        for word in (0xC00010F3, 0xC00090F3, 0xC000A0F3):
            model = user_program(word)
            model.write_csr(0x306, 7)
            self.assertEqual(model.step().cause, 2)

    def test_user_wfi_tw_and_local_wake(self):
        model = user_program(WFI, status=1 << 21)
        event = model.step()
        self.assertEqual((event.trap, event.cause, event.tval), (True, 2, WFI))
        self.assertFalse(model.sleeping)
        model = user_program(WFI)
        model.write_csr(0x304, 128)
        self.assertFalse(model.step().trap)
        self.assertTrue(model.sleeping)
        model.clock(2, 2)
        self.assertFalse(model.sleeping)
        self.assertEqual(model.interrupt_cause(), 0x80000007)
        model = Model({0: WFI}, protected_mode=True)
        model.write_csr(0x300, 1 << 21)
        self.assertFalse(model.step().trap)

    def test_user_interrupt_ignores_mie_and_preserves_prior_mode(self):
        model = user_program(0x00100093)
        model.write_csr(0x304, 0x888)
        model.clock(1, 7)
        self.assertEqual(model.read_csr(0x300) & 8, 0)
        self.assertEqual(model.interrupt(), (0x100, 0x200, 0x8000000B))
        self.assertFalse(model.user_mode)
        self.assertEqual(model.read_csr(0x300), 0)
        self.assertEqual(model.read_csr(0x343), 0)
        self.assertIsNone(model.interrupt_cause())

    def test_pmp_csr_instructions_read_before_write_and_lock(self):
        code = [0x3B009173, 0x3A019173, 0x3B021173, 0x3B0022F3]
        model = Model({4 * index: word for index, word in enumerate(code)}, protected_mode=True)
        model.registers[1], model.registers[3], model.registers[4] = 0x400, 0x90, 0x800
        values = [model.step().value for _ in code]
        self.assertEqual(values, [0, 0, 0x400, 0x400])
        self.assertEqual(model.read_csr(0x3B0), 0x400)

    def test_data_pmp_denial_has_no_memory_transaction_or_effect(self):
        for word, cause in ((0x0000A103, 5), (0x0020A023, 7)):
            model = user_program(word, permission=0x1C)
            model.registers[1], model.registers[2] = 0x1000, 0xA5A55A5A
            model.memory.update({0x1000: 0x55})
            event = model.step()
            self.assertEqual((event.cause, event.tval, event.memory), (cause, 0x1000, None))
            self.assertEqual(model.word(0x1000), 0x55)
            self.assertEqual(model.registers[2], 0xA5A55A5A)
        model = user_program(0x0020A023, permission=0x1C)
        model.registers[1] = 0x1001
        self.assertEqual(model.step().cause, 6)

    def test_mprv_only_changes_data_permissions(self):
        for status, permission, denied in ((0x20000, 0x1C, True), (0x21800, 0x1C, False),
                                           (0, 0x1C, False), (0, 0x9C, True)):
            model = Model({0: 0x0000A103, 0x1000: 123}, protected_mode=True)
            model.write_csr(0x3B0, 0x1FFFFFFF)
            model.write_csr(0x3A0, permission)
            model.write_csr(0x300, status)
            model.registers[1] = 0x1000
            event = model.step()
            self.assertEqual(event.trap, denied)
            self.assertEqual(event.cause if denied else event.value, 5 if denied else 123)
            self.assertFalse(event.user_mode)
        model = Model({0: 0x00100093}, protected_mode=True)
        model.write_csr(0x300, 0x20000)
        self.assertFalse(model.step().trap)

    def test_first_fetch_denial_and_locked_machine_denial(self):
        for compressed in (False, True):
            model = Model({0: MRET, 0x102: 0x00000013}, protected_mode=True, enable_c=compressed)
            target = 0x102 if compressed else 0x100
            model.write_csr(0x341, target)
            model.write_csr(0x300, 0)
            model.step()
            event = model.step()
            self.assertEqual((event.pc, event.word, event.length, event.cause, event.tval, event.user_mode),
                             (target, 0, 2 if compressed else 4, 1, target, True))
        model = Model({0: 0x00100093}, protected_mode=True)
        model.write_csr(0x3B0, 0)
        model.write_csr(0x3A0, 0x90)
        self.assertEqual(model.step().cause, 1)

    def test_crossing_fetch_checks_second_word(self):
        model = Model({0: MRET, 0x100: 0x00930001, 0x104: 0x00010070}, protected_mode=True, enable_c=True)
        model.write_csr(0x3B0, 0x40)
        model.write_csr(0x3A0, 0x14)
        model.write_csr(0x341, 0x102)
        model.write_csr(0x300, 0)
        model.step()
        event = model.step()
        self.assertEqual((event.pc, event.word, event.length, event.cause, event.tval), (0x102, 0, 4, 1, 0x104))
        self.assertEqual(model.registers[1], 0)
        self.assertEqual(model.read_csr(0x341), 0x102)

    def test_crossing_fetch_can_use_two_entries_and_wrap(self):
        for target, first, second in ((0x102, 0x100, 0x104), (0xFFFFFFFE, 0xFFFFFFFC, 0)):
            model = Model({0x200: MRET, first: 0x00930001, second: 0x00010070}, reset=0x200,
                          protected_mode=True, enable_c=True)
            model.write_csr(0x3B0, first >> 2)
            model.write_csr(0x3B1, second >> 2)
            model.write_csr(0x3A0, 0x1414)
            model.write_csr(0x341, target)
            model.write_csr(0x300, 0)
            model.step()
            event = model.step()
            self.assertEqual((event.pc, event.word, event.length, event.next_pc, event.value, event.trap),
                             (target, 0x00700093, 4, (target + 4) & 0xFFFFFFFF, 7, False))

    def test_bus_fault_keeps_the_accepted_memory_operation(self):
        model = Model({0: 0x0000A103, 0x1000: 123}, data_fault=0x1000, protected_mode=True)
        model.registers[1], model.registers[2] = 0x1000, 77
        event = model.step()
        self.assertEqual((event.cause, event.tval, event.memory), (5, 0x1000, (0x1000, 0, 0, 0, 2)))
        self.assertEqual(model.registers[2], 77)

    def test_allowed_byte_halfword_and_word_use_actual_size(self):
        for word, offset, expected in ((0x00008103, 3, 0x44), (0x00009103, 2, 0x4433),
                                       (0x0000A103, 0, 0x44332211)):
            model = user_program(word, permission=0x1C)
            model.write_csr(0x3B0, 0x400)
            model.write_csr(0x3B1, 0x1FFFFFFF)
            model.write_csr(0x3A0, 0x1C11)
            model.registers[1] = 0x1000 + offset
            model.memory.update({0x1000 + lane: value for lane, value in enumerate((0x11, 0x22, 0x33, 0x44))})
            event = model.step()
            self.assertFalse(event.trap)
            self.assertEqual(event.value, expected)
            self.assertEqual(event.memory[0], 0x1000 + offset)


if __name__ == "__main__":
    unittest.main()
