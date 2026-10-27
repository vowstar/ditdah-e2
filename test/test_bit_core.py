# SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
# SPDX-License-Identifier: MIT
"""Check core bit programs and the architectural model against fixed results."""

from functools import partial
from pathlib import Path
import sys
import random
import unittest
from unittest.mock import patch

from bit_model import execute
from bit_operations import ENCODINGS, arithmetic, decode, encode
from bit_programs import FIXED, cases
from bit_pipeline import mutate
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from build_rtl import configuration
from model import Model
from test_csr import execute as run_program


class BitCoreTests(unittest.TestCase):
    def test_fixed_results(self):
        for name, value in FIXED.items():
            self.assertEqual(execute(encode(name, shift=7), 0x80000001, 31, True, True, True), (name, value))

    def test_all_subsets_and_operand_boundaries(self):
        rng = random.Random(0xB17)
        for subset in range(8):
            flags = tuple(bool(subset & (1 << index)) for index in range(3))
            for name, (_, extension, _) in ENCODINGS.items():
                for shift in range(32):
                    a, b = rng.getrandbits(32), rng.getrandbits(32)
                    result = execute(encode(name, shift=shift), a, b, *flags)
                    self.assertEqual(result, (name, arithmetic(name, a, b, shift)) if subset & extension else None)

    def test_reserved_decode_fields(self):
        for opcode in (0x13, 0x33, 0x1B, 0x3B):
            for immediate in range(4096):
                for function in range(8):
                    word = (immediate << 20) | (1 << 15) | (function << 12) | (3 << 7) | opcode
                    known = decode(word)
                    result = execute(word, 0x80000001, 31, True, True, True)
                    self.assertEqual(None if result is None else result[0], None if known is None else known[0])

    def test_program_signatures(self):
        for subset in range(8):
            flags = tuple(bool(subset & (1 << index)) for index in range(3))
            for case in cases(*flags):
                with self.subTest(subset=subset, case=case.name), patch('test_csr.Model',
                        partial(Model, enable_m=True, enable_c=True, enable_zba=flags[0],
                                enable_zbb=flags[1], enable_zbs=flags[2])):
                    model, events = run_program(case)
                    self.assertEqual(tuple(event.cause for event in events if event.trap), case.expected_causes)
                    for address, value in case.signature.items():
                        self.assertEqual(model.word(address), value)

    def test_mutation_rejects_unknown_structure(self):
        for kind in ("forwarding", "load_interlock"):
            with self.assertRaises(AssertionError):
                mutate("module empty; endmodule", kind)
        with self.assertRaises(ValueError):
            mutate("", "unknown")

    def test_forwarding_mutation_uses_the_actual_register_array(self):
        for name in ("_GEN", "_GEN_0", "register_values"):
            source = f"wire [31:0] b = match2 & ~m_load ? m_value : {name}[bits[24:20]];\n.b(b), .valid(_bit_valid)"
            changed = mutate(source, "forwarding")
            self.assertIn(f".b({name}[bits[24:20]]), .valid(_bit_valid)", changed)
            self.assertIn("match2 & ~m_load ? m_value", changed)

    def test_bit_options_and_misa(self):
        for subset in range(8):
            flags = tuple(bool(subset & (1 << index)) for index in range(3))
            options = dict(zip(('enableZba', 'enableZbb', 'enableZbs'), flags))
            self.assertEqual({key: configuration(options)[key] for key in options}, options)
            model = Model({}, enable_zba=flags[0], enable_zbb=flags[1], enable_zbs=flags[2])
            self.assertEqual(bool(model.csrs[0x301] & 2), subset == 7)
        for key in ('enableZba', 'enableZbb', 'enableZbs'):
            self.assertFalse(configuration({})[key])
            for value in (1, 'true', None, []):
                with self.assertRaises(ValueError):
                    configuration({key: value})


if __name__ == '__main__':
    unittest.main()
