# SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
# SPDX-License-Identifier: MIT
"""Check bit arithmetic examples, reserved encodings and trace rejection."""

import unittest

from bit_operations import ENCODINGS, MASK, arithmetic, check, decode, encode, expected, mutate


class BitOperationsTests(unittest.TestCase):
    def test_instruction_set_is_complete(self):
        self.assertEqual(len(ENCODINGS), 29)
        self.assertEqual([sum(extension == value for _, extension, _ in ENCODINGS.values())
                          for value in (1, 2, 4)], [3, 18, 8])

    def test_fixed_results(self):
        examples = (("sh1add", MASK, 2, 0, 0), ("sh2add", 0x40000001, 3, 0, 7),
                    ("sh3add", 0x20000001, MASK, 0, 7), ("andn", 0xFF, 0x55, 0, 0xAA),
                    ("orn", 0, 0, 0, MASK), ("xnor", MASK, 0, 0, 0),
                    ("clz", 0, 0, 0, 32), ("clz", 1, 0, 0, 31),
                    ("ctz", 0, 0, 0, 32), ("ctz", 0x80000000, 0, 0, 31),
                    ("cpop", MASK, 0, 0, 32), ("cpop", 0xA5A5A5A5, 0, 0, 16),
                    ("max", 0x80000000, 1, 0, 1), ("maxu", 0x80000000, 1, 0, 0x80000000),
                    ("min", 0x80000000, 1, 0, 0x80000000), ("minu", 0x80000000, 1, 0, 1),
                    ("sext.b", 0x12345680, 0, 0, 0xFFFFFF80),
                    ("sext.h", 0x12348000, 0, 0, 0xFFFF8000), ("zext.h", MASK, 0, 0, 0xFFFF),
                    ("rol", 0x80000001, 1, 0, 3), ("ror", 0x80000001, 1, 0, 0xC0000000),
                    ("rori", 1, MASK, 31, 2), ("orc.b", 0x01008000, 0, 0, 0xFF00FF00),
                    ("rev8", 0x12345678, 0, 0, 0x78563412),
                    ("bclr", MASK, 63, 0, 0x7FFFFFFF), ("bclri", MASK, 0, 31, 0x7FFFFFFF),
                    ("bext", 0x80000000, 63, 0, 1), ("bexti", 0x80000000, 0, 31, 1),
                    ("binv", 0, 63, 0, 0x80000000), ("binvi", MASK, 0, 31, 0x7FFFFFFF),
                    ("bset", 0, 63, 0, 0x80000000), ("bseti", 0, 0, 31, 0x80000000))
        for operation, a, b, shift, result in examples:
            with self.subTest(operation=operation):
                self.assertEqual(arithmetic(operation, a, b, shift), result)

    def test_shift_positions_and_ignored_upper_bits(self):
        for amount in range(32):
            self.assertEqual(arithmetic("bset", 0, amount | 0xFFFFFFE0, 0), 1 << amount)
            self.assertEqual(arithmetic("bexti", 1 << amount, 7, amount), 1)
            self.assertEqual(arithmetic("rol", 1, amount + 32, 0), 1 << amount)
            self.assertEqual(arithmetic("ror", 1 << amount, amount + 32, 0), 1)

    def test_all_subsets_and_operand_use(self):
        for subset in range(8):
            for operation, (_, extension, form) in ENCODINGS.items():
                result = expected((encode(operation), 0x12345678, 17), subset)
                self.assertEqual(result[0], bool(subset & extension))
                self.assertEqual(result[1], bool(subset & extension) and form == "R")
                if not subset & extension:
                    self.assertEqual(result, (0, 0, 0))

    def test_reserved_neighbors(self):
        illegal = (0x6B805013, 0x68705013, 0x62005013, 0x4A001013,
                   0x4A005013, 0x6A001013, 0x2A001013, 0x08104033,
                   0x60301013, 0x60601013, 0x0A001033, 0x0800003B,
                   0x2000203B, 0x6000501B, 0x6000103B, 0x6000503B)
        for word in illegal:
            self.assertIsNone(decode(word))
            self.assertEqual(expected((word, MASK, MASK), 7), (0, 0, 0))

    def test_unary_words_do_not_depend_on_second_operand(self):
        for operation, (_, _, form) in ENCODINGS.items():
            if form != "R":
                word = encode(operation, shift=13)
                self.assertEqual(expected((word, 0x12345678, 0), 7), expected((word, 0x12345678, MASK), 7))

    def test_checker_rejects_wrong_value_order_and_incomplete_trace(self):
        rows = [(encode("sh1add"), 1, 2), (0, 0, 0)]
        self.assertEqual(check(rows, "0 1 1 00000004\n1 0 0 00000000\n", 7), {"sh1add": 1, "rejected": 1})
        for trace in ("0 1 1 00000005\n1 0 0 00000000\n", "1 1 1 00000004\n",
                      "0 1 1 00000004\n", "0 x 1 00000004\n1 0 0 00000000\n"):
            with self.assertRaises(AssertionError):
                check(rows, trace, 7)

    def test_mutation_requires_actual_output_assignment(self):
        content = "assign result = a;\nassign valid = b;\nassign usesRs2 = c;\n"
        self.assertIn("32'h00000001 ^ a", mutate(content, "result"))
        self.assertIn("1'b1 | b", mutate(content, "valid"))
        with self.assertRaises(AssertionError):
            mutate("module changed; endmodule", "result")


if __name__ == "__main__":
    unittest.main()
