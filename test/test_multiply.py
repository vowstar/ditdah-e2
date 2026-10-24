# SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
# SPDX-License-Identifier: MIT
"""Check M instruction arithmetic, configuration and operation ownership."""

from functools import partial
import unittest
from unittest.mock import patch

from model import MASK, M_INSTRUCTIONS, TIME_BASE, Model, multiply_divide
from programs import Case, M_RESULTS, PROGRAM_PC, cases, multiply
from test_csr import execute, trace
from verify import InputSchedule, check, feature_negative_controls


def arithmetic_trace(case):
    with patch("test_csr.Model", partial(Model, enable_m=case.enable_m)):
        text = trace(case)
    values = {int(fields[2]): int(fields[7]) for line in text.splitlines()
              if (fields := line.split())[0] == "R"}
    words = case.words()
    lines, pending = [], None
    for line in text.splitlines():
        lines.append(line)
        fields = line.split()
        if fields[0] == "Q" and fields[2] == "I":
            pc = int(fields[3])
            if words.get(pc, 0) & 0xFE00007F == 0x02000033:
                pending = pc
                lines.append(f"U {fields[1]} {pc} 1 0 0 0 0")
        if fields[0] == "S" and fields[2] == "I" and pending is not None:
            lines.append(f"U {fields[1]} {pending} 0 1 1 0 {values[pending]}")
            pending = None
    return "\n".join(lines)


class MultiplyModelTests(unittest.TestCase):
    def test_fixed_boundary_results(self):
        for left, right, expected in M_RESULTS:
            for operation, value in enumerate(expected):
                with self.subTest(operation=M_INSTRUCTIONS[operation], left=left, right=right):
                    self.assertEqual(multiply_divide(operation, left, right), value)

    def test_disabled_encodings_and_fixed_misa(self):
        for enabled in (False, True):
            for operation in range(8):
                word = multiply(3, 1, 2, operation)
                model = Model({0: word}, enable_m=enabled)
                model.registers[1:3] = [7, 3]
                event = model.step()
                self.assertEqual(event.trap, not enabled)
                self.assertEqual(model.csrs[0x301], 0x40000100 | (int(enabled) << 12))
                model.write_csr(0x301, MASK)
                self.assertEqual(model.csrs[0x301], 0x40000100 | (int(enabled) << 12))
                if not enabled:
                    self.assertEqual((event.cause, event.tval, event.rd), (2, word, 0))

    def test_zero_destination(self):
        for operation in range(8):
            model = Model({0: multiply(0, 1, 2, operation)}, enable_m=True)
            model.registers[1:3] = [MASK, 0]
            event = model.step()
            self.assertEqual((event.rd, event.value, model.registers[0]), (0, 0, 0))
            self.assertFalse(event.trap)

    def test_configuration_cases(self):
        disabled = {case.name: case for case in cases()}
        enabled = {case.name: case for case in cases(enable_m=True)}
        self.assertIn("illegal_2", disabled)
        self.assertNotIn("illegal_2", enabled)
        self.assertIn("m_zero_encoding", enabled)
        self.assertTrue(all(case.enable_m for case in enabled.values()))
        self.assertTrue(all(not case.enable_m for case in disabled.values()))

    def test_signatures(self):
        for reset in (0, 0x80000000, 0xFFFFFFFC):
            for case in cases(reset, enable_m=True):
                if case.name.startswith("m_interrupt_restart_"):
                    continue
                with self.subTest(case=case.name, reset=reset):
                    with patch("test_csr.Model", partial(Model, enable_m=True)):
                        model, events = execute(case)
                    self.assertEqual(tuple(event.cause for event in events if event.trap), case.expected_causes)
                    for address, value in case.signature.items():
                        self.assertEqual(model.word(address), value, f"Signature at {address:#x}")

    def test_interrupt_return_reloads_operands(self):
        for case in cases(enable_m=True):
            if not case.name.startswith("m_interrupt_restart_"):
                continue
            model = Model(case.words(), enable_m=True)
            pc = case.signature[0x800]
            while model.pc != pc:
                model.step()
            model.clock(model.cycle + 1, 4)
            self.assertEqual(model.interrupt()[0], pc)
            while model.pc != pc:
                model.clock(model.cycle + 1, 0)
                model.step()
            while model.pc != case.completion_pc:
                model.clock(model.cycle + 1, 0)
                model.step()
            for address, value in case.signature.items():
                self.assertEqual(model.word(address), value)


class MultiplyTraceTests(unittest.TestCase):
    def test_arithmetic_negative_controls(self):
        selected = {case.name: case for case in cases(enable_m=True)}
        for name in ("m_mulh_boundaries", "m_div_boundaries"):
            case = selected[name]
            text = arithmetic_trace(case)
            self.assertEqual(check(case, text)["mulDivStarts"], len(M_RESULTS))
            self.assertEqual(feature_negative_controls(case, text), 1)

    def test_duplicate_and_wrong_result(self):
        case = next(case for case in cases(enable_m=True) if case.name == "m_mul_boundaries")
        lines = arithmetic_trace(case).splitlines()
        index = next(index for index, line in enumerate(lines) if line.startswith("U ") and line.split()[4] == "1")
        duplicate = lines[:index + 1] + [lines[index]] + lines[index + 1:]
        with self.assertRaisesRegex(AssertionError, "Repeated arithmetic event"):
            check(case, "\n".join(duplicate))
        fields = lines[index].split()
        fields[7] = str(int(fields[7]) ^ 1)
        lines[index] = " ".join(fields)
        with self.assertRaisesRegex(AssertionError, "Arithmetic value differs"):
            check(case, "\n".join(lines))

    def test_missing_completion(self):
        case = next(case for case in cases(enable_m=True) if case.name == "m_mul_boundaries")
        lines = [line for line in arithmetic_trace(case).splitlines()
                 if not (line.startswith("U ") and line.split()[4] == "1")]
        with self.assertRaisesRegex(AssertionError, "lacks a completed operation"):
            check(case, "\n".join(lines))

    def test_schedule_priority_and_validation(self):
        schedule = InputSchedule((("M", 1, 4, 3), ("R", PROGRAM_PC, 2), ("C", 5, 1)))
        for cycle in range(3):
            self.assertEqual(schedule.clock(cycle), 0)
        schedule.event("M", 1)
        self.assertEqual(schedule.clock(3), 0)
        self.assertEqual(schedule.clock(4), 0)
        schedule.event("R", PROGRAM_PC)
        self.assertEqual(schedule.clock(5), 1)
        self.assertEqual(schedule.clock(6), 1)
        schedule = InputSchedule((("M", 1, 4, 2), ("R", PROGRAM_PC, 2)))
        schedule.clock(0)
        schedule.event("M", 1)
        self.assertEqual(schedule.clock(1), 0)
        schedule.event("R", PROGRAM_PC)
        self.assertEqual(schedule.clock(2), 4)
        for entry in (("M", 0, 1, 1), ("M", 1, 1, 0), ("M", 1, 1), ("R", 0, 1, 2)):
            with self.assertRaises(ValueError):
                Case("invalid", [], interrupt_schedule=(entry,)).words()

    def test_latency_and_result_stability(self):
        case = next(case for case in cases(enable_m=True) if case.name == "m_mul_boundaries")
        pc = PROGRAM_PC + 16
        lines = [f"T 0 0 {TIME_BASE}", f"U 0 {pc} 1 0 0 0 0"]
        delayed = lines + [f"T {cycle} 0 {TIME_BASE + cycle}" for cycle in range(1, 36)]
        with self.assertRaisesRegex(AssertionError, "exceeded latency bound"):
            check(case, "\n".join(delayed))
        withdrawn = lines + [f"T 1 0 {TIME_BASE + 1}", f"U 1 {pc} 0 1 0 0 0",
                             f"T 2 0 {TIME_BASE + 2}", f"T 3 0 {TIME_BASE + 3}"]
        with self.assertRaisesRegex(AssertionError, "valid was withdrawn"):
            check(case, "\n".join(withdrawn))

    def test_cancel_requires_an_exception_or_interrupt(self):
        case = next(case for case in cases(enable_m=True) if case.name == "m_mul_boundaries")
        pc = PROGRAM_PC + 16
        text = f"T 0 0 {TIME_BASE}\nU 0 {pc} 1 0 0 0 0\nT 1 0 {TIME_BASE + 1}\nU 1 {pc} 0 0 0 1 0"
        with self.assertRaisesRegex(AssertionError, "Unowned arithmetic cancellation"):
            check(case, text)

    def test_faulting_fetch_cannot_start_arithmetic(self):
        case = next(case for case in cases(enable_m=True) if case.name == "m_fetch_fault")
        text = f"T 0 0 {TIME_BASE}\nU 0 {case.instruction_fault} 1 0 0 0 0"
        with self.assertRaisesRegex(AssertionError, "Faulting instruction started arithmetic"):
            check(case, text)


if __name__ == "__main__":
    unittest.main()
