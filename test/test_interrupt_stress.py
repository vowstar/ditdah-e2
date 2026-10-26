# SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
# SPDX-License-Identifier: MIT
"""Check stress program expectations and bounded observation rejection."""

import unittest

from interrupt_stress import (boundary_case, check_boundary, cause, coverage, masked_wake_mutant, random_case,
                              sleep_observations, wfi_case)
from model import Model, TIME_BASE
from test_csr import execute
from verify import InputSchedule


def bounded_trace(case):
    model = Model(case.words())
    schedule = InputSchedule(case.interrupt_schedule)
    rows = []
    for cycle in range(128):
        pending = schedule.clock(cycle)
        sleeping = int(model.sleeping)
        rows += [f"T {cycle} {pending} {TIME_BASE + cycle}", f"L {cycle} {sleeping}"]
        model.clock(cycle, pending)
        if not model.sleeping:
            event = model.step()
            rows.append(f"R {cycle} {event.pc} {event.word} {event.next_pc} {event.rd} "
                        f"{int(bool(event.rd))} {event.value} {int(event.trap)} {event.cause} {event.tval}")
            schedule.event("R", event.pc)
    return "\n".join(rows)


class InterruptStressTests(unittest.TestCase):
    def test_wfi_expected_wake_and_entry_are_distinct(self):
        counts = {"sleep": 0, "wake": 0, "interrupt": 0}
        for pending in range(8):
            for enabled in range(8):
                for global_enable in range(2):
                    case, record = wfi_case(pending, enabled, global_enable)
                    self.assertEqual(record["localWake"], bool(pending & enabled))
                    self.assertEqual(record["interruptEntry"], bool(pending & enabled and global_enable))
                    if record["boundedObservation"]:
                        counts["sleep"] += 1
                        observations = sleep_observations(case, bounded_trace(case), True)
                        self.assertGreaterEqual(observations["sleepCycles"], 64)
                    else:
                        counts["interrupt" if global_enable else "wake"] += 1
                        model, events = execute(case)
                        self.assertEqual(sum(event.instruction == "wfi" for event in events), 1)
                        self.assertEqual(model.word(768), 73)
        self.assertEqual(counts, {"sleep": 54, "wake": 37, "interrupt": 37})

    def test_sleep_prefix_rejects_missing_or_wrong_observation(self):
        case, _ = wfi_case(1, 0, 1)
        text = bounded_trace(case)
        with self.assertRaisesRegex(AssertionError, "Missing sleep observation"):
            sleep_observations(case, text.replace("L 0 0\n", ""), True)
        with self.assertRaisesRegex(AssertionError, "Sleep state differs"):
            sleep_observations(case, text.replace("L 127 1", "L 127 0"), True)
        with self.assertRaisesRegex(AssertionError, "too short"):
            sleep_observations(case, "\n".join(line for line in text.splitlines() if int(line.split()[1]) < 32), True)

    def test_sleep_prefix_rejects_false_completion(self):
        case, _ = wfi_case(0, 0, 0)
        with self.assertRaisesRegex(AssertionError, "claims program completion"):
            sleep_observations(case, bounded_trace(case) + "\nC 128 1", True)

    def test_random_programs_keep_fixed_signatures_and_faults(self):
        reads, fault_kinds, masks, modes = set(), set(), set(), set()
        for seed in range(64):
            case, record = random_case(seed)
            self.assertEqual(case.words(), random_case(seed)[0].words())
            model, events = execute(case)
            self.assertEqual(tuple(event.cause for event in events if event.trap), case.expected_causes)
            for address, value in case.signature.items():
                self.assertEqual(model.word(address), value)
            reads.update(record["counterReads"])
            for trigger in record["triggers"]:
                masks.add(trigger["mask"])
                modes.add(trigger["trigger"])
                if trigger["fault"]:
                    fault_kinds.add(trigger["write"])
        self.assertEqual(len(reads), 10)
        self.assertEqual(fault_kinds, {False, True})
        self.assertEqual(masks, set(range(1, 8)))
        self.assertEqual(modes, {"D", "R"})

    def test_boundary_programs_preserve_faulted_destinations(self):
        for write in (False, True):
            for failed in (False, True):
                case, _ = boundary_case(write, failed)
                model, events = execute(case)
                self.assertEqual(tuple(event.cause for event in events if event.trap), case.expected_causes)
                for address, value in case.signature.items():
                    self.assertEqual(model.word(address), value)

    def test_boundary_evidence_requires_actual_clock(self):
        text = "T 0 0 0\nQ 0 D 768 0 0 0 2 1\nT 1 1 1\nS 1 D 0 0\n"
        self.assertEqual(check_boundary(text, 768, 1, 0)["responseCycle"], 1)
        with self.assertRaisesRegex(AssertionError, "scheduled clock"):
            check_boundary(text, 768, 2, 0)
        with self.assertRaisesRegex(AssertionError, "response boundary"):
            check_boundary(text, 768, 1, 1)

    def test_coverage_rejects_missing_and_duplicate_runs(self):
        record = {"case": "interrupt_random_0", "timingSeed": 0, "delay": 0, "checkerAccepted": True,
                  "group": "random", "programSeed": 0, "counterReads": [], "triggers": []}
        self.assertEqual(coverage([record], ["random"], [(0, 0)], [0])["runs"], 1)
        with self.assertRaisesRegex(AssertionError, "Incomplete random"):
            coverage([record], ["random"], [(0, 0)], [0, 1])
        with self.assertRaisesRegex(AssertionError, "Repeated"):
            coverage([record, record], ["random"], [(0, 0)], [0])

    def test_single_source_causes(self):
        self.assertEqual([cause(mask) for mask in (1, 2, 4)], [0x80000003, 0x80000007, 0x8000000B])

    def test_wake_mutant_changes_local_mask_and_requires_one_match(self):
        original = "wire waking = sleeping_0 & localWake;"
        self.assertIn("interrupts_software | interrupts_timer | interrupts_external", masked_wake_mutant(original))
        for text in ("", original + original):
            with self.assertRaisesRegex(AssertionError, "no longer matches"):
                masked_wake_mutant(text)


if __name__ == "__main__":
    unittest.main()
