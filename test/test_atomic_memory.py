# SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
# SPDX-License-Identifier: MIT
"""Check fixed shared SRAM values and reservation rules."""

import unittest

from atomic_memory import Driver, Reference, amo, check, configuration, expected, mutate, render, request, row, vectors


class AtomicMemoryTests(unittest.TestCase):
    def test_configuration(self):
        self.assertEqual(configuration({"baseAddress": 0xFFFFFFFC, "sizeBytes": 4})["sizeBytes"], 4)
        for value in ({"baseAddress": 1}, {"baseAddress": -4}, {"sizeBytes": 3}, {"sizeBytes": True},
                      {"baseAddress": 0xFFFFFFFC, "sizeBytes": 8}, {"extra": 1}):
            with self.assertRaises(ValueError):
                configuration(value)

    def test_signed_unsigned_operations(self):
        values = {3: 1, 4: 0x80000001, 5: 0x80000001, 6: 0, 7: 0x80000001,
                  8: 0x80000000, 9: 1, 10: 1, 11: 0x80000000}
        for operation, value in values.items():
            self.assertEqual(amo(operation, 0x80000000, 1), value)
        self.assertEqual(amo(4, 0xFFFFFFFF, 1), 0)

    def test_lr_sc_success_and_attempt_clear(self):
        driver = Driver({"sizeBytes": 16})
        driver.command(2, request(0, write=True, data=7), expected_result=(0, 0))
        driver.command(1, request(0, operation=1), expected_result=(7, 0))
        driver.command(1, request(0, operation=2, write=True, data=9), expected_result=(0, 0))
        driver.command(1, request(0, operation=2, write=True, data=11), expected_result=(1, 0))
        driver.command(0, request(0), expected_result=(9, 0))

    def test_competing_byte_write_invalidates_without_changing_lr_response(self):
        driver = Driver({"sizeBytes": 16})
        driver.command(2, request(0, write=True, data=0x11223344))
        hold = (1, 0, 1, 1)
        driver.issue(1, request(0, operation=1), ready=hold)
        driver.tick(ready=hold)
        driver.issue(3, request(1, size=0, write=True, data=0xAA00), ready=hold)
        for _ in range(5):
            output = driver.tick(ready=hold)
            self.assertEqual(output[1][1:], (1, 0x11223344, 0))
        self.assertIsNone(driver.reference.reservation)
        driver.tick()
        driver.command(1, request(0, operation=2, write=True, data=1), expected_result=(1, 0))
        driver.command(0, request(0), expected_result=(0x1122AA44, 0))

    def test_different_word_and_instruction_read_preserve_reservation(self):
        driver = Driver({"sizeBytes": 16})
        driver.command(2, request(0, write=True, data=7))
        driver.command(1, request(0, operation=1))
        driver.command(3, request(4, write=True, data=9))
        driver.command(0, request(0), expected_result=(7, 0))
        driver.command(1, request(0, operation=2, write=True, data=11), expected_result=(0, 0))

    def test_latest_lr_replaces_reservation(self):
        driver = Driver({"sizeBytes": 16})
        for address in (0, 4):
            driver.command(2, request(address, write=True, data=7))
        driver.command(1, request(0, operation=1))
        driver.command(1, request(4, operation=1))
        driver.command(1, request(0, operation=2, write=True, data=9), expected_result=(1, 0))
        driver.command(1, request(4, operation=2, write=True, data=9), expected_result=(1, 0))

    def test_faulting_sc_clears_and_does_not_write(self):
        driver = Driver({"sizeBytes": 16})
        driver.command(2, request(0, write=True, data=7))
        driver.command(1, request(0, operation=1))
        driver.command(1, request(0, operation=2, size=0, write=True, data=9), expected_result=(0, 1))
        driver.command(1, request(0, operation=2, write=True, data=9), expected_result=(1, 0))
        driver.command(0, request(0), expected_result=(7, 0))

    def test_clear_wins_at_lr_and_sc_memory_points(self):
        driver = Driver({"sizeBytes": 16})
        driver.command(2, request(0, write=True, data=7))
        for operation, result in ((1, 7), (2, 1)):
            driver.command(1, request(0, operation=1))
            driver.issue(1, request(0, operation=operation, write=operation == 2, data=9))
            driver.tick(clear=1)
            output = driver.tick()
            self.assertEqual(output[1][1:], (1, result, 0))
            self.assertIsNone(driver.reference.reservation)
        driver.command(0, request(0), expected_result=(7, 0))

    def test_atomic_requests_only_use_core_data_port(self):
        driver = Driver({"sizeBytes": 16})
        driver.command(2, request(0, write=True, data=7))
        for port in (0, 2, 3):
            for operation in range(1, 12):
                driver.command(port, request(0, operation=operation, write=operation != 1, data=1), expected_result=(0, 1))
        driver.command(0, request(0), expected_result=(7, 0))

    def test_address_end_and_request_shape(self):
        driver = Driver({"baseAddress": 0xFFFFFFF4, "sizeBytes": 12})
        driver.command(2, request(0xFFFFFFFC, write=True, data=0))
        driver.command(3, request(0xFFFFFFFF, write=True, data=0xA5000000, size=0))
        driver.command(0, request(0xFFFFFFFC), expected_result=(0xA5000000, 0))
        for payload in (request(0), request(0xFFFFFFFC, mask=1), request(0xFFFFFFFD, size=1),
                        request(0xFFFFFFFC, write=True, data=1, mask=7), request(0xFFFFFFFC, size=3)):
            driver.command(1, payload, expected_result=(0, 1))
        driver.command(0, request(0xFFFFFFFC), expected_result=(0xA5000000, 0))

    def test_reset_retains_memory_and_clears_reservation(self):
        driver = Driver({"sizeBytes": 4})
        driver.command(2, request(0, write=True, data=7))
        driver.command(1, request(0, operation=1))
        driver.tick(reset=1)
        driver.command(1, request(0, operation=2, write=True, data=9), expected_result=(1, 0))
        driver.command(0, request(0), expected_result=(7, 0))

    def test_unknown_memory_and_changed_source_are_rejected(self):
        reference = Reference({"sizeBytes": 16})
        reference.step(row([request(0), None, None, None]), 0)
        with self.assertRaisesRegex(AssertionError, "precedes SRAM initialization"):
            reference.step(row(), 1)
        reference = Reference({"sizeBytes": 16})
        reference.step(row([None, request(0, write=True, data=7), request(4, write=True, data=9), None]), 0)
        with self.assertRaisesRegex(AssertionError, "changed a held request"):
            reference.step(row([None, None, request(8, write=True, data=9), None]), 1)

    def test_checker_rejects_storage_effect_before_response(self):
        parameters = configuration({"sizeBytes": 4})
        driver = Driver(parameters)
        driver.command(2, request(0, write=True, data=7))
        samples, _, _ = expected(driver.rows, parameters)
        cycle = next(index for index, sample in enumerate(samples) if sample[-2])
        damaged = list(samples)
        damaged[cycle] = (*damaged[cycle][:-1], 9)
        with self.assertRaisesRegex(AssertionError, "sram_data"):
            check(driver.rows, render(damaged), parameters)

    def test_random_arbitration_history_drains(self):
        parameters = configuration({"sizeBytes": 12})
        rows = vectors(parameters)
        samples, counts, history = expected(rows, parameters)
        self.assertGreater(counts["requests"], 3000)
        self.assertEqual(counts["requests"], counts["responses"])
        self.assertEqual(counts["pending"], 0)
        self.assertTrue(all(item["memoryCycle"] == item["acceptedCycle"] + 1 for item in history))
        check(rows, render(samples), parameters)

    def test_mutations_require_unique_sites(self):
        self.assertEqual(mutate("~(write & success)", "stale-reservation"), "1'h1")
        self.assertEqual(mutate("_memory_readData + request_data", "amo-subtract"), "_memory_readData - request_data")
        for source in ("", "~(write & success) ~(write & success)"):
            with self.assertRaises(ValueError):
                mutate(source, "stale-reservation")


if __name__ == "__main__":
    unittest.main()
