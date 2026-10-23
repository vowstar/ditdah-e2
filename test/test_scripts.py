# SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
# SPDX-License-Identifier: MIT
"""Input and independent-model checks with fixed architectural expectations."""

from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from build_rtl import configuration
from model import Model


class ConfigurationTests(unittest.TestCase):
    def test_reset_addresses(self):
        for address in (0, 4, 0x80000000, 0xFFFFFFFC):
            self.assertEqual(configuration({"resetVector": address}), {"resetVector": address})

    def test_reject_invalid_or_inactive_configuration(self):
        for value in ([], None, {"enableM": True}, {"resetVector": True},
                      {"resetVector": "0"}, {"resetVector": -4}, {"resetVector": 2},
                      {"resetVector": 1 << 32}, {"resetVector": 4.0}):
            with self.assertRaises(ValueError):
                configuration(value)


class ModelTests(unittest.TestCase):
    def test_signed_shift_and_unsigned_compare(self):
        model = Model({0: 0x800000B7, 4: 0x41F0D113, 8: 0xFFF0B193})
        self.assertEqual(model.step().value, 0x80000000)
        self.assertEqual(model.step().value, 0xFFFFFFFF)
        self.assertEqual(model.step().value, 1)

    def test_load_x0_still_faults(self):
        model = Model({0: 0x10002003}, data_fault=256)
        result = model.step()
        self.assertEqual((result.cause, result.tval, result.rd), (5, 256, 0))
        self.assertIsNotNone(result.memory)

    def test_pc_wrap(self):
        model = Model({0xFFFFFFFC: 0x00100093}, reset=0xFFFFFFFC)
        self.assertEqual(model.step().next_pc, 0)


if __name__ == "__main__":
    unittest.main()
