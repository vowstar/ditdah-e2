# SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
# SPDX-License-Identifier: MIT
"""Check instruction framing, compressed execution and fetch fault ownership."""

import unittest

from compressed_model import decode
from compressed_programs import cases
from model import MASK, Model
from programs import MRET, branch, immediate, jump
from verify import InputSchedule


def image(address, raw, length):
    words = {}
    for index in range(length):
        at = (address + index) & MASK
        words[at & ~3] = words.get(at & ~3, 0) | ((raw >> (8 * index)) & 255) << (8 * (at & 3))
    return words


def execute_case(case):
    model = Model(case.words(), case.reset, case.instruction_fault, case.data_fault,
                  enable_m=case.enable_m, enable_c=True)
    schedule = InputSchedule(case.interrupt_schedule)
    events, interrupts = [], []
    for cycle in range(200):
        model.clock(cycle, schedule.clock(cycle))
        if model.interrupt_cause() is not None:
            interrupts.append(model.interrupt())
            schedule.event("N", len(interrupts))
        else:
            event = model.step()
            events.append(event)
            schedule.event("R", event.pc)
            if event.pc == case.completion_pc:
                return model, events, interrupts
    raise AssertionError("Compressed program did not complete")


class CompressedDecodeTests(unittest.TestCase):
    def test_raw_encoding_and_width(self):
        decoded = decode(0xDEAD0085)
        self.assertEqual((decoded.raw, decoded.expanded, decoded.length, decoded.legal, decoded.hint, decoded.name),
                         (0x0085, 0x00108093, 2, True, False, "addi"))
        decoded = decode(0x12300093)
        self.assertEqual((decoded.raw, decoded.expanded, decoded.length, decoded.legal),
                         (0x12300093, 0x12300093, 4, True))
        self.assertFalse(decode(0x0001).hint)

    def test_hints_and_reserved_encodings(self):
        for raw, word in ((0x0005, 0x100013), (0x0081, 0x8093), (0x4001, 0x13),
                          (0x6005, 0x1037), (0x8001, 0x45413), (0x8401, 0x40045413),
                          (0x0002, 0x1013), (0x8006, 0x100033), (0x9006, 0x100033)):
            decoded = decode(raw)
            self.assertEqual((decoded.legal, decoded.hint, decoded.expanded, decoded.length), (True, True, word, 2))
        for raw in (0, 0x6001, 0x6101, 0x8002, 0x4002, 0x1002, 0x9001, 0x9401, 0x9C01, 0x2000):
            decoded = decode(raw)
            self.assertEqual((decoded.raw, decoded.legal, decoded.hint, decoded.expanded), (raw, False, False, 0))

    def test_long_prefix_and_disabled_c(self):
        for raw in (0x89AB001F, 0x89AB003F, 0x89AB007F, 0x89AB707F):
            for enabled in (False, True):
                decoded = decode(raw, enable_c=enabled)
                self.assertEqual((decoded.raw, decoded.expanded, decoded.length, decoded.legal), (raw, 0, 4, False))
        decoded = decode(0xDEAD0085, enable_c=False)
        self.assertEqual((decoded.raw, decoded.length, decoded.legal, decoded.hint), (0xDEAD0085, 4, False, False))

    def test_argument_validation(self):
        for raw in (-1, 1 << 32, True, 1.0):
            with self.assertRaises(ValueError):
                decode(raw)
        with self.assertRaises(ValueError):
            decode(0, enable_c=1)


class CompressedExecutionTests(unittest.TestCase):
    def test_jump_links_and_halfword_targets(self):
        model = Model(image(0x1002, 0x2001, 2), reset=0x1002, enable_c=True)
        event = model.step()
        self.assertEqual((event.word, event.length, event.value, event.next_pc, event.instruction),
                         (0x2001, 2, 0x1004, 0x1002, "c.jal"))
        model = Model(image(0, 0x9282, 2), enable_c=True)
        model.registers[5] = 0x2003
        event = model.step()
        self.assertEqual((event.rd, event.value, event.next_pc, event.instruction), (1, 2, 0x2002, "c.jalr"))
        for enabled in (False, True):
            model = Model({0: jump(1, 6)}, enable_c=enabled)
            event = model.step()
            self.assertEqual(event.trap, not enabled)
            if enabled:
                self.assertEqual((event.value, event.next_pc), (4, 6))
            else:
                self.assertEqual((event.cause, event.tval), (0, 6))
            event = Model({0: branch(0, 0, 2)}, enable_c=enabled).step()
            self.assertEqual(event.trap, not enabled)

    def test_mepc_misa_and_return(self):
        for enabled in (False, True):
            model = Model({0: MRET}, enable_m=True, enable_c=enabled)
            model.write_csr(0x341, MASK)
            model.write_csr(0x301, 0)
            self.assertEqual(model.csrs[0x301], 0x40001100 | (4 if enabled else 0))
            self.assertEqual(model.step().next_pc, 0xFFFFFFFE if enabled else 0xFFFFFFFC)

    def test_hint_has_no_register_effect(self):
        for raw in (0x0081, 0x6005, 0x8006, 0x9006):
            model = Model(image(0, raw, 2), enable_c=True)
            model.registers[1:] = list(range(1, 32))
            before = model.registers.copy()
            event = model.step()
            self.assertEqual(model.registers, before)
            self.assertEqual((event.rd, event.value, event.next_pc, event.memory),
                             (1, 1, 2, None) if raw == 0x0081 else (0, 0, 2, None))
            self.assertTrue(event.instruction.startswith("c.hint."))

    def test_illegal_raw_encoding_and_base_decoder(self):
        for raw, length in ((0x6001, 2), (0x89AB001F, 4), (0xFFFF007B, 4)):
            model = Model(image(0, raw, length), enable_c=True)
            event = model.step()
            self.assertEqual((event.word, event.length, event.trap, event.cause, event.tval), (raw, length, True, 2, raw))
        self.assertTrue(decode(0xFFFF007B).legal)

    def test_first_and_second_fetch_faults(self):
        model = Model(image(2, immediate(1, 0, 7), 4), reset=2, instruction_fault=0, enable_c=True)
        event = model.step()
        self.assertEqual((event.pc, event.word, event.length, event.cause, event.tval), (2, 0, 2, 1, 2))
        model = Model(image(2, immediate(1, 0, 7), 4), reset=2, instruction_fault=4, enable_c=True)
        event = model.step()
        self.assertEqual((event.pc, event.word, event.length, event.cause, event.tval), (2, 0, 4, 1, 4))
        self.assertEqual(model.registers[1], 0)
        model = Model(image(2, 0x0085, 2), reset=2, instruction_fault=4, enable_c=True)
        event = model.step()
        self.assertEqual((event.trap, event.value, event.next_pc), (False, 1, 4))
        self.assertEqual(model.step().cause, 1)

    def test_address_wrap(self):
        pc = 0xFFFFFFFE
        model = Model(image(pc, 0x0085, 2), reset=pc, enable_c=True)
        self.assertEqual(model.step().next_pc, 0)
        model = Model(image(pc, immediate(1, 0, 7), 4), reset=pc, instruction_fault=0, enable_c=True)
        event = model.step()
        self.assertEqual((event.word, event.length, event.cause, event.tval, model.csrs[0x341]), (0, 4, 1, 0, pc))

    def test_disabled_c_fault_encoding_is_unchanged(self):
        raw = immediate(1, 0, 7)
        event = Model({0: raw}, instruction_fault=0).step()
        self.assertEqual((event.word, event.length, event.cause, event.tval), (raw, 4, 1, 0))

    def test_program_images_and_signatures(self):
        for reset in (0, 2, 0x80000000, 0xFFFFFFFE):
            for case in cases(reset, enable_m=True):
                with self.subTest(case=case.name, reset=reset):
                    model, events, interrupts = execute_case(case)
                    self.assertEqual(tuple(event.cause for event in events if event.trap), case.expected_causes)
                    self.assertEqual(tuple(cause for _, _, cause in interrupts), case.expected_interrupts)
                    for address, value in case.signature.items():
                        self.assertEqual(model.word(address), value)
                    if case.name == "c_mixed_loop":
                        observed = {(event.pc & 3, event.length) for event in events}
                        self.assertTrue({(0, 2), (2, 2), (2, 4)} <= observed)

    def test_operation_and_hint_coverage(self):
        observed = set()
        for case in cases():
            _, events, _ = execute_case(case)
            observed.update(event.instruction for event in events)
        operations = {"addi4spn", "lw", "sw", "nop", "addi", "jal", "li", "lui", "addi16sp",
                      "srli", "srai", "andi", "sub", "xor", "or", "and", "j", "beqz", "bnez",
                      "slli", "lwsp", "jr", "mv", "ebreak", "jalr", "add", "swsp"}
        hints = {"nop", "addi", "li", "lui", "srli", "srai", "slli", "mv", "add"}
        self.assertTrue({"c." + name for name in operations} <= observed)
        self.assertTrue({"c.hint." + name for name in hints} <= observed)

    def test_recovery_program_layouts(self):
        names = set()
        for case in cases():
            self.assertNotIn(case.name, names)
            names.add(case.name)
            model, events, _ = execute_case(case)
            if case.name.startswith("c_illegal_"):
                trapped = next(event for event in events if event.trap)
                self.assertEqual((trapped.cause, trapped.word, trapped.tval),
                                 (2, model.word(case.program_pc) & (0xFFFF if trapped.length == 2 else MASK), trapped.word))
            if case.name.startswith("c_mret_"):
                returned = next(event for event in events if event.instruction == "mret")
                self.assertEqual(returned.next_pc & 3, 2)
            if case.name.startswith("c_fence_crossing_"):
                fence_index = next(index for index, event in enumerate(events) if event.instruction == "fence.i")
                self.assertEqual((events[fence_index].pc & 3, events[fence_index].length), (2, 4))
                replacement = events[fence_index + 1]
                self.assertEqual((replacement.pc & 3, replacement.rd, replacement.value), (2, 10, 17))
                self.assertEqual(replacement.length, 4 if case.name.endswith("code") else 2)
            if case.name == "c_redirect_crossing_fault":
                self.assertFalse(any(event.trap for event in events))
                self.assertNotIn(case.program_pc + 2, [event.pc for event in events])

    def test_reset_vector_is_observed_before_mtvec_write(self):
        for reset in (0, 2, 0x80000002, 0xFFFFFFFE):
            for enable_m in (False, True):
                case = next(case for case in cases(reset, enable_m) if case.name == "c_reset_vector")
                model = Model(case.words(), reset, enable_m=enable_m, enable_c=True)
                event = model.step()
                self.assertEqual((event.pc, event.instruction, event.rd, event.value), (reset, "auipc", 8, reset))
                event = model.step()
                self.assertEqual((event.instruction, event.rd, event.value), ("csrrs", 10, reset & ~3))

    def test_interrupt_resumes_each_target_once(self):
        for reset in (0, 2, 0x80000002, 0xFFFFFFFE):
            for enable_m in (False, True):
                selected = [case for case in cases(reset, enable_m) if case.name.startswith("c_irq_")]
                self.assertEqual(len(selected), 2)
                for case in selected:
                    with self.subTest(case=case.name, reset=reset, enable_m=enable_m):
                        model, events, interrupts = execute_case(case)
                        trigger = case.interrupt_schedule[0][1]
                        jumped = next(event for event in events if event.pc == trigger)
                        target = jumped.next_pc
                        self.assertEqual((jumped.instruction, target & 3), ("c.j", 2))
                        self.assertEqual(case.interrupt_schedule, (("R", trigger, 4), ("N", 1, 0)))
                        self.assertEqual(interrupts, [(target, case.handler_pc, 0x8000000B)])
                        resumed = [event for event in events if event.pc == target]
                        self.assertEqual(len(resumed), 1)
                        self.assertEqual((resumed[0].length, resumed[0].value),
                                         (4 if case.name == "c_irq_crossing" else 2, 17))
                        returned = next(event for event in events if event.instruction == "mret")
                        self.assertEqual(returned.next_pc, target)
                        self.assertLess(events.index(returned), events.index(resumed[0]))
                        self.assertEqual((model.registers[8], model.registers[11]), (17, 1))
                        self.assertEqual((model.csrs[0x341], model.csrs[0x342], model.csrs[0x343]),
                                         (target, 0x8000000B, 0))
                        self.assertFalse(any(event.trap for event in events))
                        for address, value in case.signature.items():
                            self.assertEqual(model.word(address), value)


if __name__ == "__main__":
    unittest.main()
