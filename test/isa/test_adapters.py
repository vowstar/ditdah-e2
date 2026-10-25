# SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
# SPDX-License-Identifier: MIT
"""Reject malformed or changed architectural signatures."""

import unittest
import struct
import sys
from pathlib import Path

from isa_checks import architectural_configuration, compare_signatures, compressed_test_kind, execution_case, isa_specification, normalize_elf, signature_words, validate_rtl_configuration


class SignatureTests(unittest.TestCase):
    def test_rtl_profile_and_extension_binding(self):
        for enable_m in (False, True):
            for enable_c in (False, True):
                config = {"resetVector": 0x80000000, "enableM": enable_m,
                          "enableC": enable_c, "protectedMode": False}
                validate_rtl_configuration(config, enable_m, enable_c)
                for change in ({"protectedMode": True}, {"protectedMode": 1},
                               {"enableM": not enable_m}, {"enableC": not enable_c},
                               {"resetVector": 0}, {"unknown": False}):
                    with self.subTest(change=change), self.assertRaises(ValueError):
                        validate_rtl_configuration(config | change, enable_m, enable_c)

    def test_m_isa_and_misa_agree(self):
        for enabled, isa, misa, mask in ((False, 'RV32IZicsr', '0x40000100', '[0x100]'),
                                         (True, 'RV32IMZicsr', '0x40001100', '[0x1100]')):
            text = isa_specification(enabled)
            self.assertIn('ISA: ' + isa, text)
            self.assertIn('reset-val: ' + misa, text)
            self.assertIn(mask, text)
        with self.assertRaisesRegex(ValueError, 'Boolean'):
            isa_specification(1)

    def test_c_isa_and_misa_agree(self):
        for enable_m, isa, misa, mask in ((False, 'RV32ICZicsr', '0x40000104', '[0x104]'),
                                         (True, 'RV32IMCZicsr', '0x40001104', '[0x1104]')):
            text = isa_specification(enable_m, True)
            self.assertIn('ISA: ' + isa, text)
            self.assertIn('reset-val: ' + misa, text)
            self.assertIn(mask, text)
            self.assertEqual(architectural_configuration(isa), (enable_m, True, 'rv32imc_zicsr' if enable_m else 'rv32ic_zicsr'))
        with self.assertRaisesRegex(ValueError, 'Boolean'):
            isa_specification(False, 1)
        with self.assertRaisesRegex(ValueError, 'Unsupported'):
            architectural_configuration('RV32ICZcb')

    def test_compressed_selection_uses_declarations(self):
        self.assertEqual(compressed_test_kind('misalign1-cjr-01.S', 'RVTEST_ISA("RV32IC")'), 'selected')
        self.assertEqual(compressed_test_kind('cebreak-01.S', 'RVTEST_ISA("RV32IC_Zicsr")'), 'requires machine trap adapter')
        for isa in ('RV32I_Zca_Zcb', 'RV32IM_Zca_Zcb', 'RV32I_Zca_Zcb_Zbb'):
            self.assertEqual(compressed_test_kind('operation.S', f'RVTEST_ISA("{isa}")'), 'requires Zcb')
        for text in ('', 'RVTEST_ISA("RV64IC")', 'RVTEST_ISA("RV32IC")\ndef rvtest_mtrap_routine=True'):
            with self.assertRaises(ValueError):
                compressed_test_kind('operation.S', text)

    def test_current_execution_checker_contract(self):
        sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
        from verify import check
        lines = []
        for cycle in range(8):
            lines.append(f'T {cycle} 0 {0xFFFFFFF0 + cycle}')
            if cycle == 0:
                lines.append('R 0 0 111 0 0 0 0 0 0 0')
            lines.append(f'O {cycle} 0 0 0 0 0 2')
        lines += ['C 8 1 0 0 0 0 0 0 0 0 0', 'W 0 111']
        result = check(execution_case({0: 111}, 0, 0), '\n'.join(lines))
        self.assertEqual(result['retired'], 1)
        self.assertEqual(result['interrupts'], 0)

    def test_rvc_metadata(self):
        data = bytearray(88)
        data[:7] = b'\x7fELF\x01\x01\x01'
        struct.pack_into('<I', data, 28, 52)
        struct.pack_into('<I', data, 36, 1)
        struct.pack_into('<HH', data, 42, 32, 1)
        struct.pack_into('<8I', data, 52, 1, 84, 0x80000000, 0x80000000, 4, 4, 5, 4)
        struct.pack_into('<I', data, 84, 0x13)
        normalized = normalize_elf(bytes(data))
        self.assertEqual(normalized[36:40], b'\0\0\0\0')
        self.assertEqual(normalized[:36] + normalized[40:], data[:36] + data[40:])
        struct.pack_into('<I', data, 84, 0x00010001)
        self.assertEqual(normalize_elf(bytes(data), enable_c=True), bytes(data))
        with self.assertRaisesRegex(ValueError, 'non-32-bit encoding'):
            normalize_elf(bytes(data))
        struct.pack_into('<I', data, 84, 0x0000001f)
        with self.assertRaisesRegex(ValueError, 'non-32-bit encoding'):
            normalize_elf(bytes(data))
        struct.pack_into('<I', data, 68, 2)
        with self.assertRaisesRegex(ValueError, 'not word aligned'):
            normalize_elf(bytes(data))
        struct.pack_into('<I', data, 36, 3)
        with self.assertRaisesRegex(ValueError, 'Unsupported ELF flags'):
            normalize_elf(bytes(data))
        with self.assertRaisesRegex(ValueError, 'Unsupported ELF flags'):
            normalize_elf(bytes(data), enable_c=True)

    def test_signature_format(self):
        self.assertEqual(signature_words('12345678\nabcdef01\n'), (0x12345678, 0xabcdef01))
        for text in ('', '0\n', '1234567g\n', '123456789\n', '12345678\n\n'):
            with self.assertRaises(ValueError):
                signature_words(text)

    def test_changed_signature(self):
        compare_signatures('12345678\n', '12345678\n')
        with self.assertRaisesRegex(ValueError, 'Architectural signature mismatch'):
            compare_signatures('12345678\n', '12345679\n')
        with self.assertRaisesRegex(ValueError, 'Architectural signature mismatch'):
            compare_signatures('12345678\n', '12345678\n00000000\n')


if __name__ == '__main__':
    unittest.main()
