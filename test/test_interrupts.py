# SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
# SPDX-License-Identifier: MIT
"""Fixed interrupt, counter and input-schedule expectations."""

import unittest

from model import Model
from programs import cases, constant, csr
from test_csr import execute, trace
from verify import InputSchedule, check, feature_negative_controls


class InterruptTests(unittest.TestCase):
    def test_priority_and_pending_bits(self):
        code = constant(1, 0x888) + [csr(0, 0x304, 1, 1), csr(0, 0x300, 8, 6)]
        expected_pending = (0, 8, 128, 136, 2048, 2056, 2176, 2184)
        expected_causes = (None, 0x80000003, 0x80000007, 0x80000003,
                           0x8000000B, 0x8000000B, 0x8000000B, 0x8000000B)
        for mask in range(8):
            model = Model({4 * index: word for index, word in enumerate(code)})
            for cycle in range(len(code)):
                model.clock(cycle, mask)
                model.step()
            model.clock(len(code), mask)
            self.assertEqual(model.read_csr(0x344), expected_pending[mask])
            self.assertEqual(model.interrupt_cause(), expected_causes[mask])

    def test_schedule_trigger_edges(self):
        schedule = InputSchedule((("C", 1, 4), ("D", 256, 2), ("R", 4096, 1), ("N", 1, 0)))
        self.assertEqual(schedule.clock(0), 0)
        self.assertEqual(schedule.clock(1), 4)
        schedule.event("D", 256)
        self.assertEqual(schedule.mask, 4)
        self.assertEqual(schedule.clock(2), 2)
        schedule.event("R", 4096)
        self.assertEqual(schedule.clock(3), 1)
        schedule.event("N", 1)
        self.assertEqual(schedule.clock(4), 0)
        schedule.event("D", 256)
        self.assertEqual(schedule.clock(5), 0)

    def test_interrupt_and_counter_traces(self):
        selected = [case for case in cases() if case.name.startswith(("irq_", "wfi_", "counter_"))]
        controls = 0
        for case in selected:
            with self.subTest(case=case.name):
                text = trace(case)
                metrics = check(case, text)
                self.assertEqual(metrics["interrupts"], len(case.expected_interrupts))
                controls += feature_negative_controls(case, text)
        self.assertEqual(controls, 8)

    def test_wfi_requires_local_wake(self):
        case = next(case for case in cases() if case.name == "wfi_local_wake")
        model = Model(case.words())
        for cycle in range(100):
            model.clock(cycle)
            event = model.step()
            if event.instruction == "wfi":
                break
        self.assertTrue(model.sleeping)
        model.clock(cycle + 1, 1)
        self.assertTrue(model.sleeping)
        with self.assertRaisesRegex(AssertionError, "WFI waits"):
            model.step()
        model.clock(cycle + 2, 2)
        self.assertFalse(model.sleeping)
        self.assertIsNone(model.interrupt_cause())


class CounterTimingTests(unittest.TestCase):
    def test_clock_runs_without_retirement(self):
        model = Model({})
        for cycle in range(8):
            model.clock(cycle)
        self.assertEqual(model.read_csr(0xB00), 7)
        self.assertEqual(model.read_csr(0xB02), 0)

    def test_inhibit_uses_old_state_at_commit(self):
        code = [csr(0, 0x320, 5, 5), csr(0, 0xB02, 10, 5), csr(0, 0x320, 1, 5),
                csr(2, 0xC02), csr(0, 0x320, 5, 5), csr(3, 0xC02)]
        model = Model({4 * index: word for index, word in enumerate(code)})
        values = []
        for cycle in range(len(code)):
            model.clock(cycle)
            values.append(model.read_csr(0xB02))
            model.step()
        self.assertEqual(values, [0, 1, 10, 10, 11, 12])
        self.assertEqual((model.registers[2], model.registers[3]), (10, 12))
        self.assertEqual(model.read_csr(0xB00), 1)

    def test_time_rollover(self):
        model = Model({})
        for cycle in range(16):
            model.clock(cycle)
        self.assertEqual((model.read_csr(0xC81), model.read_csr(0xC01)), (0, 0xFFFFFFFF))
        model.clock(16)
        self.assertEqual((model.read_csr(0xC81), model.read_csr(0xC01)), (1, 0))

    def test_exceptions_interrupts_and_wait_retirement(self):
        expected = {"counter_exception": (0, 6), "counter_interrupt": (0, 3), "counter_wfi": (1, 0)}
        for case in cases():
            if case.name in expected:
                model, _ = execute(case)
                self.assertEqual((model.word(256), model.word(260)), expected[case.name])


if __name__ == "__main__":
    unittest.main()
