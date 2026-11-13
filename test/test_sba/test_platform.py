# SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
# SPDX-License-Identifier: MIT
"""Check firmware semantics and reject corrupted platform evidence."""

import unittest

from test.common.model import Model
from test.test_sba.platform import check, firmware


class PlatformTests(unittest.TestCase):
    def test_firmware_without_conflicting_writer(self):
        image = firmware() | {0x20000000: 0x11223344, 0x20000040: 1}
        model = Model(image, enable_a=True)
        released = False
        for _ in range(200):
            event = model.step()
            self.assertFalse(event.trap)
            if model.word(0x20000040) == 2 and not released:
                model.memory[0x20000040] = 3
                released = True
            if event.memory and event.memory[0] == 0x20000080:
                break
        else:
            self.fail("Firmware did not finish in the architectural model")
        self.assertTrue(released)
        self.assertEqual(model.word(0x20000000), 0x55667788)
        self.assertEqual(model.word(0x20000080), 0)
        self.assertEqual(model.word(0x20000084), 0x11223344)

    def test_protocol_counterexamples(self):
        request = "Q 1 536870912 1 1 1 15 2 0\n"
        self.assertEqual(check(request + "S 3 0 0\nF 4 1 1 1\n", False)["requests"], 1)
        for trace in (request + "N 2\nS 3 0 0\nF 4 1 1 1\n",
                      request + "S 1 0 0\nF 4 1 1 1\n",
                      request + request + "S 3 0 0\nF 4 2 1 1\n",
                      request.replace("1 15 2 0", "1 1 2 0") + "S 3 0 0\nF 4 1 1 1\n"):
            with self.subTest(trace=trace), self.assertRaises(ValueError):
                check(trace, False)

    def test_absent_atomic_witness_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "Missing same-word"):
            check("F 4 0 0 1\n", True)


if __name__ == "__main__":
    unittest.main()
