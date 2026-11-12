# SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
# SPDX-License-Identifier: MIT
"""Check Program Buffer reference boundaries and mutation targeting."""

import unittest

from test.test_debug.verify_program_buffer import (
    EBREAK,
    TRAP_SENTINELS,
    ProgramReference,
    cases,
    mutate,
)


class ProgramBufferTests(unittest.TestCase):
    def test_mutations_require_unique_targets(self):
        sources = {
            "no-issue": "wire injectExecution =\n    condition;",
            "native-trap": "if (trap) begin\n        mepc <= _GEN_198;",
            "drop-writeback": "wire actualWriteback =\n    condition;",
            "drop-data-valid": "assign debug_response_bits_dataValid = response_dataValid;",
        }
        for name, source in sources.items():
            with self.subTest(name=name):
                self.assertNotEqual(mutate(source, name), source)
                for invalid in ("", source + source):
                    with self.assertRaisesRegex(ValueError, "target changed"):
                        mutate(invalid, name)
        with self.assertRaisesRegex(ValueError, "Unknown"):
            mutate("", "unknown")

    def test_fault_completion_keeps_request_snapshot_for_one_cycle(self):
        reference = ProgramReference(cases()[0])
        reference.active = True
        reference.cycle = 10
        pending = {"slot": 0, "dataValid": False, "readValue": None}
        reference.pending = pending
        reference.finish(pending, {}, fault=True)
        for cycle in (10, 11):
            reference.cycle = cycle
            self.assertEqual(reference.read(0x16) & 0x1700, 0x1000)
        reference.cycle = 12
        self.assertEqual(reference.read(0x16) & 0x1700, 0x300)

    def test_fault_blocks_new_commands_until_explicitly_cleared(self):
        branch = next(case for case in cases() if case.name == "branch")
        poll = branch.actions.index(next(action for action in branch.actions if action[2] == 0x40000))
        self.assertEqual(branch.actions[poll + 2][:3], (2, 0x16, 0x700))
        reference = ProgramReference(branch)
        reference.active = reference.halted = True
        for number, value in TRAP_SENTINELS.items():
            reference.register(number, value)
        reference.program = [0x0000006F, EBREAK]
        reference.start(0x00040000)
        reference.instruction((0, 0, 0x0000006F, 4, 0, 0, 0, 1, 0, 0, 0, 0, 0))
        self.assertEqual(reference.error, 3)
        reference.request(0x17, 2, 0x220341)
        self.assertIsNone(reference.pending)
        reference.request(0x16, 2, 0x700)
        self.assertEqual(reference.error, 0)
        reference.request(0x17, 2, 0x220341)
        self.assertEqual(reference.pending, {"simple": 1})
        reference.pending = None
        self.assertEqual(reference.read(4), TRAP_SENTINELS[0x341])
        for number, value in TRAP_SENTINELS.items():
            self.assertEqual(reference.model.read_csr(number), value)

    def test_successful_read_survives_later_program_fault(self):
        reference = ProgramReference(next(case for case in cases() if case.name == "read_then_fault"))
        reference.halted = True
        reference.model.registers[1] = 0x13579BDF
        reference.program = [0xFFFFFFFF, EBREAK]
        reference.start(0x00261001)
        self.assertFalse(reference.data[0])
        reference.instruction((0, 0, 0xFFFFFFFF, 4, 0, 0, 0, 1, 0, 0, 0, 0, 0))
        self.assertEqual(reference.error, 3)
        self.assertEqual(reference.data[0], 0x13579BDF)

    def test_deactivation_drains_only_the_orphan(self):
        reference = ProgramReference(cases()[0])
        reference.active = True
        reference.pending = {"slot": 0, "dataValid": False, "readValue": None}
        reference.request(0x10, 2, 0)
        self.assertIsNone(reference.pending)
        self.assertTrue(reference.orphan["deactivated"])
        self.assertEqual(reference.data, [0, 0])
        reference.finish(reference.orphan, {}, fault=False)
        self.assertIsNone(reference.orphan)
        self.assertEqual(reference.error, 0)
        self.assertEqual(len(reference.events), 1)

    def test_transport_errors_and_unknown_records_are_rejected(self):
        with self.assertRaises(AssertionError):
            from test.test_debug.verify_program_buffer import check
            check(cases()[0], "T 0 0 0 0\nK 0 0 1 0\n")


if __name__ == "__main__":
    unittest.main()
