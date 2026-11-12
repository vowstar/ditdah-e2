# SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
# SPDX-License-Identifier: MIT
"""Check fixed debug register effects and command ownership errors."""

import unittest

from test.test_debug.debug_module import (Driver, HEX_OUTPUT, Reference, auto_mutant, auto_vectors, busy_mutant,
                                          check, command_error, expected, program_mutant, program_vectors, row, vectors)


def render(samples):
    return "\n".join(" ".join(f"{value:x}" if index in HEX_OUTPUT else str(value)
                              for index, value in enumerate(sample)) for sample in samples) + "\n"


class DebugModuleTests(unittest.TestCase):
    def test_command_fields_and_absent_features(self):
        for word in (0x221001, 0x23101F, 0x261001, 0x00040000, 0x00261001,
                     0x02000000, 0x02110000, 0x02200000, 0x02080000, 0x02290000, 0x710FFF):
            self.assertEqual(command_error(word), 0)
        for word in (0x1221001, 0xA21001, 0x2A1001, 0x121001, 0x00280000,
                     0x02800000, 0x02300000, 0x02020000, 0x02004000, 0x02000001):
            self.assertEqual(command_error(word), 2)

    def test_dmi_response_survives_deactivation(self):
        driver = Driver()
        driver.dmi(0x10, 2, 1)
        driver.dmi(4, 2, 0x12345678)
        driver.dmi(0x10, 2, 0, stall=4)
        driver.dmi(0x10, 2, 1)
        driver.dmi(4, expected_data=0)
        samples, counts = expected(driver.rows)
        self.assertEqual(counts["dmiRequests"], counts["dmiResponses"])
        self.assertEqual(counts["responseBackpressure"], 4)
        check(driver.rows, render(samples))

    def test_busy_conflict_wins_simultaneous_hart_error(self):
        driver = Driver()
        driver.dmi(0x10, 2, 1)
        driver.next_error = 3
        driver.delay = 6
        driver.dmi(0x17, 2, 0x221001)
        while len(driver.rows) < driver.pending["due"]:
            driver.tick()
        driver.dmi(0x18, 2, 0)
        driver.dmi(0x16, expected_data=0x2000102)
        self.assertEqual(driver.reference.error, 1)
        self.assertEqual(driver.reference.counts["hartResults"], 1)

    def test_unowned_result_cannot_change_data(self):
        driver = Driver()
        driver.dmi(0x10, 2, 1)
        driver.dmi(4, 2, 0x12345678)
        driver.tick(result_valid=1, result_data=0xDEADBEEF, result_data_valid=1)
        driver.dmi(4, expected_data=0x12345678)
        self.assertEqual(driver.reference.counts["unownedResults"], 1)

    def test_deactivation_wins_same_edge_success(self):
        driver = Driver()
        driver.dmi(0x10, 2, 1)
        driver.registers[0x1001] = 0xABCDEF01
        driver.delay = 6
        driver.dmi(0x17, 2, 0x221001)
        while len(driver.rows) < driver.pending["due"]:
            driver.tick()
        driver.dmi(0x10, 2, 0, stall=3)
        driver.dmi(0x10, 2, 1)
        driver.dmi(4, expected_data=0)
        self.assertEqual(driver.reference.counts["hartResults"], 1)

    def test_cancelled_memory_drains_before_new_request(self):
        driver = Driver()
        driver.dmi(0x10, 2, 1)
        driver.dmi(4, 2, 0x12345678)
        driver.dmi(5, 2, 0x400)
        driver.delay = 30
        driver.dmi(0x17, 2, 0x02210000)
        driver.dmi(0x10, 2, 0)
        driver.dmi(0x10, 2, 1)
        driver.dmi(5, 2, 0x400)
        driver.dmi(0x17, 2, 0x02200000)
        driver.drain()
        driver.dmi(4, expected_data=0x12345678)
        self.assertEqual(driver.reference.counts["cancelled"], 1)
        self.assertEqual(driver.reference.counts["hartRequests"], 2)
        self.assertEqual(driver.reference.counts["hartResults"], 1)
        self.assertGreater(driver.reference.counts["hartBackpressure"], 10)

    def test_pending_reset_and_running_resume(self):
        driver = Driver()
        driver.dmi(0x10, 2, 1)
        driver.dmi(0x10, 2, 0x40000001)
        self.assertTrue(driver.reference.resume)
        driver.tick(resume_ack=1)
        driver.state.update(halted=0, running=1)
        driver.dmi(0x11, expected_data=0x430CA3)
        driver.dmi(0x10, 2, 0x40000001)
        self.assertFalse(driver.reference.resume)
        driver.dmi(0x11, expected_data=0x400CA3)
        driver.state.update(reset_pending=1)
        driver.dmi(0x11, expected_data=0x1400CA3)
        driver.state.update(reset_pending=0)
        driver.tick(reset_event=1)
        driver.dmi(0x11, expected_data=0x4C0CA3)

    def test_error_clear_is_bitwise_and_blocks_commands(self):
        driver = Driver()
        driver.dmi(0x10, 2, 1)
        driver.dmi(0x17, 2, 0x220FFF)
        driver.drain()
        driver.dmi(0x16, expected_data=0x2000302)
        driver.dmi(0x16, 2, 0x100)
        driver.dmi(0x16, expected_data=0x2000202)
        before = driver.reference.counts["commands"]
        driver.dmi(0x17, 2, 0x221001)
        self.assertEqual(driver.reference.counts["commands"], before)
        driver.clear_error()
        driver.dmi(0x16, expected_data=0x2000002)

    def test_bad_source_and_changed_response_are_rejected(self):
        reference = Reference()
        reference.step(row(reset=1), 0)
        reference.step(row(valid=1, op=1, address=0x10), 1)
        reference.step(row(valid=1, op=1, address=0x11, ready=0), 2)
        with self.assertRaisesRegex(AssertionError, "request changed"):
            reference.step(row(valid=1, op=1, address=0x16, ready=0), 3)
        rows = [row(reset=1), row(valid=1, address=0x10, op=2, data=1), row(ready=0), row()]
        samples, _ = expected(rows)
        samples[2] = (*samples[2][:3], 1, *samples[2][4:])
        with self.assertRaisesRegex(AssertionError, "transaction mismatch"):
            check(rows, render(samples))

    def test_fixed_and_random_driver_drains(self):
        rows = vectors(1)
        samples, counts = expected(rows)
        self.assertGreater(counts["commands"], 600)
        self.assertEqual(counts["cancelled"], 3)
        self.assertGreater(counts["busyConflicts"], 7)
        self.assertEqual(counts["pending"], 0)
        check(rows, render(samples))

    def test_abstract_auto_driver_covers_fresh_operands_and_exact_completion(self):
        rows = auto_vectors(1)
        samples, counts = expected(rows)
        self.assertEqual(counts["autoCommands"], 9)
        self.assertEqual(counts["postincrements"], 16)
        self.assertGreater(counts["responseBackpressure"], 8)
        self.assertGreater(counts["requestBackpressure"], 8)
        self.assertEqual(counts["pending"], 0)
        check(rows, render(samples))

    def test_program_buffer_driver_covers_execution_and_result_ownership(self):
        rows = program_vectors()
        samples, counts = expected(rows)
        self.assertEqual(counts["postexecCommands"], 9)
        self.assertEqual(counts["autoProgram"], 3)
        self.assertEqual(counts["cancelled"], 1)
        self.assertEqual(counts["pending"], 0)
        check(rows, render(samples))

    def test_mutation_requires_one_error_assignment(self):
        source = "error <= 3'h1;"
        self.assertEqual(busy_mutant(source), "error <= 3'h5;")
        for invalid in ("", source * 2):
            with self.assertRaises(ValueError):
                busy_mutant(invalid)

    def test_auto_mutations_require_unique_targets(self):
        sources = {
            "stale-operands": "if (autoStart_1) begin\n      operands_address <= data1;\n      operands_data <= data0;",
            "early-increment": "else if (commandComplete & command_memory & command_postIncrement & postincrement)",
            "backpressure-repeat": "wire        autoStart = accepted & read | write;",
        }
        for name, source in sources.items():
            with self.subTest(name=name):
                self.assertNotEqual(auto_mutant(source, name), source)
                with self.assertRaises(ValueError):
                    auto_mutant("", name)
                with self.assertRaises(ValueError):
                    auto_mutant(source + source, name)

    def test_program_mutations_require_unique_targets(self):
        for name, source in (("missing-postexec", "assign hart_request_bits_postExec = command_postExec;"),
                             ("drop-data-valid", "else if (commandComplete & hart_response_bits_dataValid)")):
            with self.subTest(name=name):
                self.assertNotEqual(program_mutant(source, name), source)
                with self.assertRaises(ValueError):
                    program_mutant("", name)
                with self.assertRaises(ValueError):
                    program_mutant(source + source, name)


if __name__ == "__main__":
    unittest.main()
