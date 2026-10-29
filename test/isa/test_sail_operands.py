# SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
# SPDX-License-Identifier: MIT
"""Exercise source-address classification independently of execution results."""

import unittest

from sail_operands import is_hint, sources


def config(**changes):
    return {"enableC": True, "enableM": True, "enableA": True,
            "enableZba": True, "enableZbb": True, "enableZbs": True} | changes


def regular(opcode, function=0, upper=0, first=17, second=23, destination=31):
    return upper << 25 | second << 20 | first << 15 | function << 12 | destination << 7 | opcode


C_CASES = (("addi4spn", 0x0040, (2, 0)), ("lw", 0x4104, (10, 0)), ("sw", 0xC20C, (12, 11)),
           ("addi", 0x0185, (3, 0)), ("jal", 0x2001, (0, 0)), ("li", 0x4285, (0, 0)),
           ("lui", 0x6185, (0, 0)), ("addi16sp", 0x6105, (2, 0)), ("srli", 0x8085, (9, 0)),
           ("srai", 0x8485, (9, 0)), ("andi", 0x8905, (10, 0)), ("sub", 0x8D91, (11, 12)),
           ("xor", 0x8DB1, (11, 12)), ("or", 0x8DD1, (11, 12)), ("and", 0x8DF1, (11, 12)),
           ("j", 0xA001, (0, 0)), ("beqz", 0xC281, (13, 0)), ("bnez", 0xE301, (14, 0)),
           ("slli", 0x0886, (17, 0)), ("lwsp", 0x4F82, (2, 0)), ("jr", 0x8F82, (31, 0)),
           ("mv", 0x89DE, (0, 23)), ("ebreak", 0x9002, (0, 0)), ("jalr", 0x9F82, (31, 0)),
           ("add", 0x99DE, (19, 23)), ("swsp", 0xC05E, (2, 23)))
HINTS = ((0x0001, (0, 0)), (0x0005, (0, 0)), (0x0181, (3, 0)),
         (0x4005, (0, 0)), (0x6005, (0, 0)), (0x805E, (0, 23)), (0x905E, (0, 23)),
         (0x0006, (0, 0)), (0x0182, (3, 0)), (0x8081, (9, 0)), (0x8481, (9, 0)))
RESERVED = (0x0000, 0x6101, 0x6181, 0x4002, 0x8002, 0x1186, 0x9085,
            0x9D91, 0x9DB1, 0x2000, 0x6000, 0xA000, 0xE000, 0x2002, 0x6002, 0xE002)


class CompressedSourcesTests(unittest.TestCase):
    def test_every_integer_compressed_family(self):
        for name, raw, expected in C_CASES:
            with self.subTest(name=name):
                self.assertEqual(sources(raw, 2, config()), expected)
                self.assertFalse(is_hint(raw, 2, config()))

    def test_hints_retain_their_base_equivalent_source_slots(self):
        for raw, expected in HINTS:
            with self.subTest(raw=hex(raw)):
                self.assertTrue(is_hint(raw, 2, config()))
                self.assertEqual(sources(raw, 2, config()), expected)
                self.assertFalse(is_hint(raw, 2, config(enableC=False)))
        self.assertFalse(is_hint(0x00000013, 4, config()))

    def test_reserved_forms_and_disabled_c_are_not_hints(self):
        for raw in RESERVED:
            with self.subTest(raw=hex(raw)):
                self.assertEqual(sources(raw, 2, config()), (0, 0))
                self.assertFalse(is_hint(raw, 2, config()))
        for _, raw, _ in C_CASES:
            self.assertEqual(sources(raw, 2, config(enableC=False)), (0, 0))

    def test_compact_register_bank_and_full_register_endpoints(self):
        for left in range(8, 16):
            for right in range(8, 16):
                word = 0xC000 | (left - 8) << 7 | (right - 8) << 2
                self.assertEqual(sources(word, 2, config()), (left, right))
        for register in range(1, 32):
            self.assertEqual(sources(0x8002 | register << 7, 2, config()), (register, 0))
            self.assertEqual(sources(0x9002 | register << 7, 2, config()), (register, 0))
        self.assertEqual(sources(0xC002, 2, config()), (2, 0))


class FullWidthSourcesTests(unittest.TestCase):
    def test_base_integer_families_and_x0(self):
        for opcode, functions, expected in ((0x03, (0, 1, 2, 4, 5), (17, 0)),
                                            (0x23, (0, 1, 2), (17, 23)),
                                            (0x63, (0, 1, 4, 5, 6, 7), (17, 23)),
                                            (0x67, (0,), (17, 0))):
            for function in functions:
                with self.subTest(opcode=opcode, function=function):
                    self.assertEqual(sources(regular(opcode, function), 4, config()), expected)
        for function in range(8):
            self.assertEqual(sources(regular(0x33, function), 4, config()), (17, 23))
        self.assertEqual(sources(regular(0x33, first=0, second=31), 4, config()), (0, 31))
        for opcode in (0x17, 0x37, 0x6F, 0x0F):
            self.assertEqual(sources(regular(opcode), 4, config()), (0, 0))

    def test_immediate_arithmetic_shift_and_illegal_shift_high_bits(self):
        for function in (0, 2, 3, 4, 6, 7):
            self.assertEqual(sources(regular(0x13, function, upper=0x7F), 4, config()), (17, 0))
        for function, upper in ((1, 0), (5, 0), (5, 0x20)):
            self.assertEqual(sources(regular(0x13, function, upper), 4, config()), (17, 0))
        self.assertEqual(sources(regular(0x13, 1, 0x20), 4, config()), (0, 0))

    def test_csr_register_and_zimm_forms_even_when_access_would_trap(self):
        for function in (1, 2, 3, 5, 6, 7):
            for address in (0x300, 0x301, 0x31A, 0xFFF):
                word = address << 20 | 17 << 15 | function << 12 | 31 << 7 | 0x73
                self.assertEqual(sources(word, 4, config()), (17, 0) if function < 5 else (0, 0))
        for word in (0x00000073, 0x00100073, 0x30200073, 0x10500073, 0x0000100F):
            self.assertEqual(sources(word, 4, config()), (0, 0))

    def test_m_is_configuration_gated(self):
        for function in range(8):
            word = regular(0x33, function, 1)
            self.assertEqual(sources(word, 4, config()), (17, 23))
            self.assertEqual(sources(word, 4, config(enableM=False)), (0, 0))

    def test_a_sources_lr_reserved_rs2_and_acquire_release(self):
        for operation in (0, 1, 2, 3, 4, 8, 12, 16, 20, 24, 28):
            for ordering in range(4):
                right = 0 if operation == 2 else 23
                word = operation << 27 | ordering << 25 | right << 20 | 17 << 15 | 2 << 12 | 0x2F
                self.assertEqual(sources(word, 4, config()), (17, right))
                self.assertEqual(sources(word, 4, config(enableA=False)), (0, 0))
        self.assertEqual(sources(2 << 27 | regular(0x2F, 2), 4, config()), (0, 0))

    def test_each_bit_group_is_gated_independently(self):
        groups = {"enableZba": [(0x33, f, 0x10) for f in (2, 4, 6)],
                  "enableZbb": [(0x33, f, 0x20) for f in (4, 6, 7)] +
                                  [(0x33, f, 5) for f in (4, 5, 6, 7)] + [(0x33, f, 0x30) for f in (1, 5)],
                  "enableZbs": [(0x33, 1, high) for high in (0x14, 0x24, 0x34)] + [(0x33, 5, 0x24)]}
        for feature, patterns in groups.items():
            for opcode, function, upper in patterns:
                word = regular(opcode, function, upper)
                with self.subTest(feature=feature, word=hex(word)):
                    self.assertEqual(sources(word, 4, config()), (17, 23))
                    self.assertEqual(sources(word, 4, config(**{feature: False})), (0, 0))

    def test_bit_unary_and_immediate_forms_have_no_second_gpr(self):
        for immediate, function in ((0x600, 1), (0x601, 1), (0x602, 1), (0x604, 1),
                                    (0x605, 1), (0x287, 5), (0x698, 5)):
            word = immediate << 20 | 17 << 15 | function << 12 | 0x13
            self.assertEqual(sources(word, 4, config()), (17, 0))
            self.assertEqual(sources(word, 4, config(enableZbb=False)), (0, 0))
        zext = regular(0x33, 4, 4, second=0)
        self.assertEqual(sources(zext, 4, config()), (17, 0))
        self.assertEqual(sources(zext | 1 << 20, 4, config()), (0, 0))
        for function, high in ((1, 0x14), (1, 0x24), (1, 0x34), (5, 0x24)):
            word = regular(0x13, function, high)
            self.assertEqual(sources(word, 4, config()), (17, 0))
            self.assertEqual(sources(word, 4, config(enableZbs=False)), (0, 0))
        self.assertEqual(sources(regular(0x13, 5, 0x30), 4, config()), (17, 0))

    def test_reserved_function_codes_have_no_sources(self):
        for word in (regular(0x03, 3), regular(0x23, 3), regular(0x63, 2), regular(0x67, 1),
                     regular(0x33, 2, 0x20), regular(0x33, 0, 2), regular(0x2F, 0),
                     regular(0x2F, 2, 0x7E), 0, 0xFFFFFFFF):
            with self.subTest(word=hex(word)):
                self.assertEqual(sources(word, 4, config()), (0, 0))

    def test_types_width_and_explicit_configuration(self):
        for word, length in ((True, 2), (-1, 4), (0x10000, 2), (1 << 32, 4), (0, 1), (0, True)):
            with self.subTest(word=word, length=length), self.assertRaises(ValueError):
                sources(word, length, config())
        for parameters in ({}, config(enableC=1)):
            with self.assertRaises(ValueError):
                sources(1, 2, parameters)


if __name__ == "__main__":
    unittest.main()
