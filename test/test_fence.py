# SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
# SPDX-License-Identifier: MIT
"""Check instruction fence encodings and reject ambiguous RTL mutations."""

import unittest

from model import Model
from verify import without_instruction_sync


class FenceTests(unittest.TestCase):
    def test_reserved_fields_have_no_register_effect(self):
        for word in (0x0000100F, 0xFFFF9F8F):
            model = Model({0: word})
            model.registers[31] = 123
            event = model.step()
            self.assertFalse(event.trap)
            self.assertEqual(event.instruction, "fence.i")
            self.assertEqual((event.next_pc, event.rd), (4, 0))
            self.assertEqual(model.registers[31], 123)

    def test_mutation_requires_unique_logic(self):
        first = "m_fenceI <= isFenceI;"
        second = "| advance\n       & isFenceI & ~fault"
        self.assertNotEqual(without_instruction_sync(first + second), first + second)
        for text in ("", first, second, first + first + second, first + second + second):
            with self.subTest(text=text), self.assertRaisesRegex(AssertionError, "Cannot identify"):
                without_instruction_sync(text)


if __name__ == "__main__":
    unittest.main()
