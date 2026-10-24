# SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
# SPDX-License-Identifier: MIT
"""Check fixed console timing and reject extra device effects."""

import unittest

from console import check, expected, fault_byte_mutant, vectors


def row(*, reset=0, valid=0, ready=1, transmit=1, address=0, write=0, data=0, mask=0, size=2):
    return reset, valid, ready, transmit, address, write, data, mask, size


def render(samples):
    return "\n".join(" ".join(f"{value:x}" if index in (3, 6) else str(value)
                              for index, value in enumerate(sample)) for sample in samples) + "\n"


class ConsoleTests(unittest.TestCase):
    def test_write_waits_for_transmit_and_response_acceptance(self):
        rows = [row(reset=1), row(valid=1, write=1, data=0x123456AB, mask=15),
                row(transmit=0), row(transmit=0), row(), row(ready=0), row(), row()]
        samples, counts = expected(rows)
        self.assertEqual([sample[2] for sample in samples], [0, 0, 0, 0, 0, 1, 1, 0])
        self.assertEqual([sample[5] for sample in samples], [0, 0, 1, 1, 1, 0, 0, 0])
        self.assertEqual([sample[6] for sample in samples[2:5]], [0xAB, 0xAB, 0xAB])
        self.assertEqual((counts["requests"], counts["responses"], counts["bytes"]), (1, 1, [0xAB]))
        check(rows, render(samples))
        changed = samples.copy()
        changed[2] = (*changed[2][:2], 1, *changed[2][3:])
        with self.assertRaisesRegex(AssertionError, "transaction mismatch"):
            check(rows, render(changed))

    def test_status_captures_transmit_ready_at_acceptance(self):
        rows = [row(reset=1), row(valid=1, address=4, transmit=0), row(ready=0), row(),
                row(valid=1, address=4), row(ready=0, transmit=0), row(transmit=0), row()]
        samples, counts = expected(rows)
        self.assertEqual([samples[index][3] for index in (2, 3, 5, 6)], [0, 0, 1, 1])
        self.assertEqual((counts["statusZero"], counts["statusOne"], counts["bytes"]), (1, 1, []))
        check(rows, render(samples))

    def test_fault_cannot_transmit_a_byte(self):
        for request in ({"address": 0}, {"address": 4, "write": 1, "mask": 15},
                        {"write": 1, "mask": 3}, {"write": 1, "mask": 15, "size": 1},
                        {"address": 0x10000000, "write": 1, "mask": 15}):
            rows = [row(reset=1), row(valid=1, data=0xA5, **request), row(), row()]
            samples, counts = expected(rows)
            self.assertEqual((samples[2][4], counts["faults"], counts["bytes"]), (1, 1, []))
            changed = samples.copy()
            changed[2] = (*changed[2][:5], 1, 0xA5)
            with self.assertRaisesRegex(AssertionError, "Unexpected console byte"):
                check(rows, render(changed))

    def test_source_must_hold_blocked_request(self):
        rows = [row(reset=1), row(valid=1, write=1, mask=15), row(valid=1, address=4, transmit=0)]
        for changed in (row(valid=1, address=8, transmit=0), row(valid=0, transmit=0)):
            with self.assertRaisesRegex(AssertionError, "request changed under backpressure"):
                expected(rows + [changed])

    def test_cold_reset_and_incomplete_transaction(self):
        rows = [row(reset=1), row(valid=1, write=1, mask=15)]
        with self.assertRaisesRegex(AssertionError, "reset requires"):
            expected(rows + [row(reset=1)])
        samples, _ = expected(rows)
        with self.assertRaisesRegex(AssertionError, "did not complete"):
            check(rows, render(samples))

    def test_fixed_stream_and_random_stimulus(self):
        rows = vectors(1)
        samples, counts = expected(rows)
        self.assertEqual(bytes(counts["bytes"][:259]), b"E2\n" + bytes(range(256)))
        self.assertEqual(counts["requests"], 2309)
        self.assertEqual(counts["pending"], 0)
        for name in ("blockedRequests", "blockedResponses", "blockedTransmit", "statusZero", "statusOne", "statusReadyChanges"):
            self.assertGreater(counts[name], 0)
        check(rows, render(samples))

    def test_mutation_requires_one_transmit_assignment(self):
        source = "assign transmit_valid = sending;"
        changed = fault_byte_mutant(source)
        self.assertIn("memory_response_valid & memory_response_bits_fault", changed)
        for invalid in ("", source + source):
            with self.assertRaisesRegex(ValueError, "assignment changed"):
                fault_byte_mutant(invalid)


if __name__ == "__main__":
    unittest.main()
