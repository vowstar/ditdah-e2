# SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
# SPDX-License-Identifier: MIT
"""Fixed CSR expectations and checks for program completion traces."""

import unittest

from copy import deepcopy

from model import Model, TIME_BASE
from programs import Case, PROGRAM_PC, TRAP_RECORD, cases, csr, immediate
from verify import InputSchedule, check, negative_controls


def execute(case):
    model = Model(case.words(), case.reset, case.instruction_fault, case.data_fault)
    events = []
    schedule = InputSchedule(case.interrupt_schedule)
    interrupts = []
    for cycle in range(10000):
        model.clock(cycle, schedule.clock(cycle))
        if model.interrupt_cause() is not None:
            interrupts.append(model.interrupt()[2])
            schedule.event("N", len(interrupts))
            continue
        if model.sleeping:
            continue
        event = model.step()
        events.append(event)
        if event.memory:
            schedule.event("D", event.memory[0])
        schedule.event("R", event.pc)
        if event.pc == case.completion_pc:
            if tuple(interrupts) != case.expected_interrupts:
                raise AssertionError("Unexpected model interrupt sequence")
            return model, events
    raise AssertionError(f"Model did not complete {case.name}")


def trace(case):
    model = Model(case.words(), case.reset, case.instruction_fault, case.data_fault)
    lines, cycle, traps, retired, interrupts, sleep_cycles = [], -1, 0, 0, 0, 0
    schedule = InputSchedule(case.interrupt_schedule)

    def clock():
        nonlocal cycle, sleep_cycles
        cycle += 1
        mask = schedule.clock(cycle)
        lines.append(f"T {cycle} {mask} {TIME_BASE + cycle}")
        sleep_cycles += model.sleeping
        model.clock(cycle, mask)

    clock()
    for _ in range(10000):
        if model.interrupt_cause() is not None:
            pc, target, cause = model.interrupt()
            lines.append(f"N {cycle} {pc} {target} {cause}")
            interrupts += 1
            schedule.event("N", interrupts)
            clock()
            continue
        if model.sleeping:
            clock()
            continue
        pc = model.pc
        word = model.word(pc)
        lines.append(f"Q {cycle} I {pc} 0 0 0 2")
        clock()
        lines.append(f"S {cycle} I {word} {int(pc == case.instruction_fault)}")
        clock()
        preview = deepcopy(model).step()
        if preview.memory:
            address, write, data, mask, size = preview.memory
            lines.append(f"Q {cycle} D {address} {write} {data} {mask} {size}")
            schedule.event("D", address)
            clock()
            lines.append(f"S {cycle} D {model.word(address & ~3)} {int(address == case.data_fault)}")
        event = model.step()
        lines.append(f"R {cycle} {event.pc} {event.word} {event.next_pc} {event.rd} "
                     f"{int(bool(event.rd))} {event.value} {int(event.trap)} {event.cause} {event.tval}")
        traps += event.trap
        retired += not event.trap
        schedule.event("R", event.pc)
        if event.pc == case.completion_pc:
            break
        clock()
    else:
        raise AssertionError("Synthetic trace did not complete")
    for index in range(8):
        if index:
            clock()
        lines.append(f"O {cycle} 1 {(case.completion_pc + 4) & 0xFFFFFFFF} 0 0 0 2")
    lines += [f"H {cycle} {(case.completion_pc + 4) & 0xFFFFFFFF} 0 0 0 2",
              f"C {cycle + 1} {retired} {traps} 0 0 0 0 0 0 {interrupts} {sleep_cycles}"]
    lines += [f"W {address} {model.word(address)}" for address in sorted({a & ~3 for a in model.memory})]
    return "\n".join(lines)


class CsrModelTests(unittest.TestCase):
    def test_read_before_write_and_masks(self):
        words = [immediate(1, 0, -1), csr(2, 0x300, 1, 1), csr(3, 0x300),
                 csr(4, 0x341, 1, 1), csr(5, 0x341), csr(6, 0x342, 1, 1), csr(7, 0x342)]
        model = Model({index * 4: word for index, word in enumerate(words)})
        values = [model.step().value for _ in words]
        self.assertEqual(values, [0xFFFFFFFF, 0x1800, 0x1888, 0, 0xFFFFFFFC, 0, 0xFFFFFFFF])

    def test_nonzero_register_with_zero_value_requests_write(self):
        for operation in (2, 3):
            word = csr(2, 0xF11, 1, operation)
            model = Model({0: immediate(2, 0, 27), 4: word})
            model.step()
            event = model.step()
            self.assertEqual((event.trap, event.cause, event.tval, event.rd), (True, 2, word, 0))
            self.assertEqual(model.registers[2], 27)

    def test_readonly_zero_masks_are_reads(self):
        for operation in (2, 3, 6, 7):
            model = Model({0: csr(2, 0xF11, 0, operation)})
            event = model.step()
            self.assertEqual((event.trap, event.rd, event.value), (False, 2, 0))

    def test_trap_state_and_return(self):
        selected = {case.name: case for case in cases()}
        for enabled in (0, 1):
            model, events = execute(selected[f"trap_mret_{enabled}"])
            self.assertEqual([event.cause for event in events if event.trap], [11, 3])
            self.assertEqual(model.word(TRAP_RECORD), PROGRAM_PC + 20)
            self.assertEqual(model.word(TRAP_RECORD + 8), PROGRAM_PC + 20)
            self.assertEqual(model.word(256), 0x1888 if enabled else 0x1880)
            self.assertEqual(sum(event.instruction == "mret" for event in events), 1)

    def test_program_signatures_and_exception_sequences(self):
        names = set()
        for case in cases():
            with self.subTest(case=case.name):
                self.assertNotIn(case.name, names)
                names.add(case.name)
                model, events = execute(case)
                self.assertEqual(tuple(event.cause for event in events if event.trap), case.expected_causes)
                for address, value in case.signature.items():
                    self.assertEqual(model.word(address), value, f"Signature at {address:#x}")

    def test_store_fault_cancels_the_younger_branch(self):
        case = next(case for case in cases() if case.name == "store_fault_younger_branch")
        model, events = execute(case)
        fault = next(event for event in events if event.trap)
        self.assertEqual((fault.pc, fault.next_pc, fault.cause, fault.tval),
                         (PROGRAM_PC + 4, case.handler_pc, 7, 256))
        self.assertFalse(any(PROGRAM_PC + 8 <= event.pc < PROGRAM_PC + 32 for event in events))
        for address, value in case.signature.items():
            self.assertEqual(model.word(address), value)
        self.assertEqual(check(case, trace(case))["traps"], 1)

    def test_image_regions_reject_overlap(self):
        for case in (Case("data_overlap", [], data={PROGRAM_PC: 0}),
                     Case("program_overlap", [0] * 1025),
                     Case("handler_overlap", [], handler=[0] * 1025),
                     Case("unaligned_data", [], data={257: 0}),
                     Case("signature_overlap", [], signature={PROGRAM_PC: 0})):
            with self.assertRaises(ValueError):
                case.words()

    def test_nested_trap_restores_outer_context(self):
        case = next(case for case in cases() if case.name == "nested_trap_return")
        model, events = execute(case)
        self.assertEqual([event.cause for event in events if event.trap], [11, 3])
        self.assertEqual(sum(event.instruction == "mret" for event in events), 2)
        self.assertEqual(model.word(256), 77)
        self.assertEqual(model.word(260), 0x1888)
        self.assertEqual(model.word(264), 11)
        self.assertEqual(model.word(268), 0)
        self.assertEqual(model.word(TRAP_RECORD), 0x1008)
        self.assertEqual(model.word(TRAP_RECORD + 12), 0x1880)
        self.assertEqual(model.word(TRAP_RECORD + 32), 0x2034)
        self.assertEqual(model.word(TRAP_RECORD + 44), 0x1800)
        self.assertEqual(model.word(TRAP_RECORD + 48), 0x1880)

    def test_high_reset_and_wrapped_programs(self):
        for reset in (0x80000000, 0xFFFFEFFC, 0xFFFFFFFC):
            for case in cases(reset):
                with self.subTest(reset=reset, case=case.name):
                    model, events = execute(case)
                    self.assertEqual(events[0].pc, reset)
                    self.assertEqual(events[0].next_pc, (reset + 4) & 0xFFFFFFFF)
                    self.assertEqual(model.csrs[0x305], (reset + 0x2000) & 0xFFFFFFFF)
                    self.assertEqual(tuple(event.cause for event in events if event.trap), case.expected_causes)
                    for address, value in case.signature.items():
                        self.assertEqual(model.word(address), value)
                    self.assertEqual(check(case, trace(case))["traps"], len(case.expected_causes))
                    if reset != 0x80000000:
                        self.assertTrue(any(event.pc == 0xFFFFFFFC and event.next_pc == 0 for event in events))


class CompletionTests(unittest.TestCase):
    def setUp(self):
        self.case = next(case for case in cases() if case.name == "sum_loop")
        self.text = trace(self.case)

    def test_completion_and_semantic_negative_controls(self):
        self.assertEqual(check(self.case, self.text)["traps"], 1)
        self.assertEqual(negative_controls(self.case, self.text), 11)

    def test_missing_completion_retirement(self):
        text = "\n".join(line for line in self.text.splitlines()
                         if not line.startswith(("H ", "O "))
                         and not (line.startswith("R ") and int(line.split()[2]) == self.case.completion_pc))
        with self.assertRaisesRegex(AssertionError, "Missing checked program completion"):
            check(self.case, text)

    def test_short_observation_window(self):
        lines = self.text.splitlines()
        final_cycle = max(int(line.split()[1]) for line in lines if line.startswith("T "))
        lines = [line for line in lines if not (line.startswith(("T ", "O "))
                 and int(line.split()[1]) == final_cycle)]
        held = next(i for i, line in enumerate(lines) if line.startswith("H "))
        held_fields = lines[held].split()
        held_fields[1] = str(final_cycle - 1)
        lines[held] = " ".join(held_fields)
        index = next(i for i, line in enumerate(lines) if line.startswith("C "))
        fields = lines[index].split()
        fields[1] = str(int(fields[1]) - 1)
        lines[index] = " ".join(fields)
        with self.assertRaisesRegex(AssertionError, "Incomplete observation window"):
            check(self.case, "\n".join(lines))

    def test_invalid_payload_does_not_change_empty_offer_state(self):
        lines = [line for line in self.text.splitlines() if not line.startswith("H ")]
        for index, line in enumerate(lines):
            if line.startswith("O "):
                fields = line.split()
                fields[2:] = ["0", str(index), "1", str(index + 1), "15", "3"]
                lines[index] = " ".join(fields)
        self.assertEqual(check(self.case, "\n".join(lines))["traps"], 1)

    def test_held_offer_must_match_observations(self):
        lines = self.text.splitlines()
        index = next(i for i, line in enumerate(lines) if line.startswith("H "))
        fields = lines[index].split()
        fields[2] = str(int(fields[2]) + 4)
        lines[index] = " ".join(fields)
        with self.assertRaisesRegex(AssertionError, "Held offer differs"):
            check(self.case, "\n".join(lines))


if __name__ == "__main__":
    unittest.main()
