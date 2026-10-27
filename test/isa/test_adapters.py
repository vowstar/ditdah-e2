# SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
# SPDX-License-Identifier: MIT
"""Reject malformed or changed architectural signatures."""

import unittest
import hashlib
import tempfile
from unittest.mock import patch
import struct
import sys
from pathlib import Path
from types import SimpleNamespace

from machine_exceptions import MACHINE_ENVIRONMENT, MACHINE_TESTS, changed_exception_cause, machine_data_faults, machine_exception_causes, validate_machine_environment
from elf_mapping import instruction_pc, instruction_ranges
from isa_checks import architectural_configuration, bit_test_extension, bit_test_instruction, changed_andn_result, compare_signatures, compressed_test_kind, execution_case, isa_specification, normalize_elf, signature_words, test_extensions, validate_rtl_configuration, validate_test_isa


class SignatureTests(unittest.TestCase):
    @staticmethod
    def mapped_elf(code_symbol=b'$x'):
        data = bytearray(900)
        data[:7] = b'\x7fELF\x01\x01\x01'
        struct.pack_into('<HHIIIIIHHHHHH', data, 16, 2, 243, 1, 0x80000000,
                         52, 0x180, 1, 52, 32, 1, 40, 4, 0)
        struct.pack_into('<8I', data, 52, 1, 0x100, 0x80000000, 0x80000000, 12, 12, 5, 4)
        struct.pack_into('<3I', data, 0x100, 0x13, 0, 0x6f)
        struct.pack_into('<10I', data, 0x180 + 40, 0, 1, 6, 0x80000000, 0x100, 12, 0, 0, 4, 0)
        struct.pack_into('<10I', data, 0x180 + 80, 0, 2, 0, 0, 0x240, 64, 3, 0, 4, 16)
        strings = b'\0' + code_symbol + b'\0$d\0$x.1\0'
        struct.pack_into('<10I', data, 0x180 + 120, 0, 3, 0, 0, 0x300, len(strings), 0, 0, 1, 0)
        data[0x300:0x300 + len(strings)] = strings
        for index, (name, offset) in enumerate(((1, 0), (len(code_symbol) + 2, 4), (len(code_symbol) + 5, 8)), 1):
            struct.pack_into('<IIIBBH', data, 0x240 + 16 * index, name, 0x80000000 + offset, 0, 0, 0, 1)
        return data

    def test_mapped_data_preserves_all_nonflag_bytes(self):
        data = bytes(self.mapped_elf())
        self.assertEqual(instruction_ranges(data), ((0x80000000, 0x80000004), (0x80000008, 0x8000000c)))
        actual = normalize_elf(data, mapped_data=True)
        self.assertEqual(actual[:36] + actual[40:], data[:36] + data[40:])
        self.assertEqual(actual[36:40], b'\0\0\0\0')
        self.assertEqual(actual[0x104:0x108], b'\0\0\0\0')
        with self.assertRaisesRegex(ValueError, 'non-32-bit'):
            normalize_elf(data)
        self.assertEqual(normalize_elf(data, enable_c=True, mapped_data=True), data)

    def test_mapped_data_rejects_corrupt_boundaries_and_symbols(self):
        changes = (
            (0x250, '<I', 0),
            (0x25c, '<B', 16),
            (0x268, '<I', 1),
            (0x264, '<I', 0x80000000),
            (0x274, '<I', 0x8000000a),
            (0x274, '<I', 0x80000009),
            (0x100, '<I', 0x00010001),
            (0x100, '<I', 0x1f),
            (0x180 + 40 + 20, '<I', 8),
            (52 + 20, '<I', 16),
            (0x180 + 80 + 16, '<I', 790),
            (0x250, '<I', 4),
        )
        for offset, fmt, value in changes:
            data = self.mapped_elf()
            struct.pack_into(fmt, data, offset, value)
            with self.subTest(offset=offset, value=value), self.assertRaises(ValueError):
                normalize_elf(bytes(data), mapped_data=True)

    def test_mapped_unaligned_targets_cannot_retire_without_c(self):
        data = self.mapped_elf()
        struct.pack_into('<II', data, 52 + 16, 10, 10)
        struct.pack_into('<I', data, 0x180 + 40 + 20, 10)
        struct.pack_into('<I', data, 0x274, 0x80000006)
        struct.pack_into('<I', data, 0x106, 0x6f)
        ranges = instruction_ranges(data)
        self.assertEqual(ranges, ((0x80000000, 0x80000004), (0x80000006, 0x8000000a)))
        self.assertTrue(instruction_pc(ranges, 0x80000000))
        for address in (0x80000002, 0x80000004, 0x80000006, 0x80000008, 0x8000000a):
            self.assertFalse(instruction_pc(ranges, address))
        struct.pack_into('<I', data, 24, 0x80000006)
        with self.assertRaisesRegex(ValueError, 'entry'):
            instruction_ranges(data)

    def test_mapped_alignment_nop_is_not_an_instruction(self):
        data = self.mapped_elf()
        struct.pack_into('<II', data, 52 + 16, 16, 16)
        struct.pack_into('<I', data, 0x180 + 40 + 20, 16)
        struct.pack_into('<I', data, 0x274, 0x80000006)
        struct.pack_into('<IHI', data, 0x106, 0x13, 1, 0x6f)
        ranges = instruction_ranges(data)
        self.assertEqual(ranges, ((0x80000000, 0x80000004), (0x80000006, 0x8000000a),
                                  (0x8000000c, 0x80000010)))
        self.assertFalse(instruction_pc(ranges, 0x8000000a))
        self.assertTrue(instruction_pc(ranges, 0x8000000c))
        for offset, value in ((0x10a, 0x85), (0x10c, 1)):
            changed = bytearray(data)
            struct.pack_into('<H', changed, offset, value)
            with self.subTest(offset=offset), self.assertRaisesRegex(ValueError, 'unsupported instruction width'):
                instruction_ranges(changed)

    def test_mapped_code_qualifiers_require_supported_explicit_versions(self):
        for symbol in (b'$x', b'$x.1', b'$xrv32i2p1', b'$xrv32i2p1_zicsr2p0',
                       b'$xrv32i2p1_zicsr2p0.1', b'$xrv32i2p1_c2p0_zicsr2p0_zca1p0'):
            with self.subTest(symbol=symbol):
                self.assertEqual(len(instruction_ranges(self.mapped_elf(symbol))), 2)
        for symbol in (b'$xrv32i', b'$xrv32garbage', b'$xrv32i2', b'$xrv32i2p',
                       b'$xrv32i2pp1', b'$xrv32i2p1_zicsr', b'$xrv32i2p1_zicsr2p',
                       b'$xrv32i2p1zicsr2p0', b'$xrv32i2p1_zicsr2p0_zicsr2p0',
                       b'$xrv32i2p1_m2p0', b'$xrv64i2p1'):
            with self.subTest(symbol=symbol), self.assertRaisesRegex(ValueError, 'mapping symbol'):
                instruction_ranges(self.mapped_elf(symbol))

    def test_mapped_compressed_instructions_preserve_exact_starts(self):
        data = self.mapped_elf(b'$xrv32i2p1_c2p0_zicsr2p0_zca1p0')
        struct.pack_into('<HH', data, 0x100, 1, 0x9002)
        ranges = instruction_ranges(data, enable_c=True)
        self.assertEqual(ranges, ((0x80000000, 0x80000002), (0x80000002, 0x80000004),
                                  (0x80000008, 0x8000000c)))
        for address in (0x80000000, 0x80000002, 0x80000008):
            self.assertTrue(instruction_pc(ranges, address, enable_c=True))
        for address in (0x80000001, 0x80000004, 0x8000000a, 0x8000000c):
            self.assertFalse(instruction_pc(ranges, address, enable_c=True))
        for offset, word in ((0x100, 0x1f), (0x102, 0x13)):
            changed = bytearray(data)
            struct.pack_into('<H', changed, offset, word)
            with self.subTest(offset=offset), self.assertRaisesRegex(ValueError, 'instruction width'):
                instruction_ranges(changed, enable_c=True)
        with self.assertRaisesRegex(ValueError, 'Boolean'):
            instruction_ranges(data, enable_c=1)

    def test_compressed_breakpoint_binds_source_and_c_profile(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'C/src/cebreak-01.S'
            path.parent.mkdir(parents=True)
            path.write_bytes(b'compressed breakpoint fixture\n')
            with patch('machine_exceptions.COMPRESSED_BREAKPOINT_HASH', hashlib.sha256(path.read_bytes()).hexdigest()):
                self.assertEqual(machine_exception_causes(path, enable_c=True), (3, 11))
                with self.assertRaisesRegex(ValueError, 'C enabled'):
                    machine_exception_causes(path)
                path.write_bytes(b'changed\n')
                with self.assertRaisesRegex(ValueError, 'source changed'):
                    machine_exception_causes(path, enable_c=True)

    def test_machine_exception_source_and_profile_binding(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / 'privilege/src/ecall.S'
            source.parent.mkdir(parents=True)
            content = b'machine exception source fixture\n'
            source.write_bytes(content)
            expected = ((11,), hashlib.sha256(content).hexdigest())
            with patch.dict(MACHINE_TESTS, {'ecall.S': expected}):
                self.assertEqual(machine_exception_causes(source), (11, 11))
                with self.assertRaisesRegex(ValueError, 'C disabled'):
                    machine_exception_causes(source, enable_c=True)
                source.write_bytes(content + b'changed\n')
                with self.assertRaisesRegex(ValueError, 'source changed'):
                    machine_exception_causes(source)
            with self.assertRaisesRegex(ValueError, 'Unselected'):
                machine_exception_causes(source.with_name('unselected.S'))
            self.assertEqual(machine_exception_causes(Path(directory) / 'I/src/add-01.S'), ())

    def test_machine_environment_rejects_a_changed_trap_macro(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'arch_test.h'
            data = b'machine environment fixture\n'
            path.write_bytes(data)
            with patch.dict(MACHINE_ENVIRONMENT, {'arch_test.h': hashlib.sha256(data).hexdigest()}, clear=True):
                validate_machine_environment(directory)
                path.write_bytes(data + b'changed\n')
                with self.assertRaisesRegex(ValueError, 'environment changed'):
                    validate_machine_environment(directory)

    def test_jal_recovery_data_fault_requires_its_bound_layout(self):
        words = {0xa0: 0x20a0056f, 0xb0: 0x22a0006f, 0x2a8: 0x45130000,
                 0x2ac: 0x00010035, 0x2b4: 0x00000117, 0x2b8: 0x02610113,
                 0x2d4: 0x00010067}
        program = SimpleNamespace(symbols={'rvtest_code_begin': 0}, words=lambda: words)
        self.assertEqual(machine_data_faults('misalign-jal-01.S', program), {0x2a8: 0x45130000})
        self.assertEqual(machine_data_faults('ecall.S', program), {})
        for offset in words:
            changed = words | {offset: words[offset] ^ 1}
            program.words = lambda: changed
            with self.subTest(offset=offset), self.assertRaisesRegex(ValueError, 'layout changed'):
                machine_data_faults('misalign-jal-01.S', program)

    def test_exception_control_changes_only_the_cause(self):
        trace = 'R 7 8 115 16 0 0 0 1 11 0\n'
        self.assertEqual(changed_exception_cause(trace), 'R 7 8 115 16 0 0 0 1 10 0\n')
        for unchanged in ('', 'R 7 8 111 8 0 0 0 0 0 0\n'):
            with self.assertRaisesRegex(ValueError, 'No exception'):
                changed_exception_cause(unchanged)

    def test_rtl_profile_and_extension_binding(self):
        for enable_m in (False, True):
            for enable_c in (False, True):
                config = {"resetVector": 0x80000000, "enableM": enable_m,
                          "enableC": enable_c, "protectedMode": False, "enableDebug": False, "enableA": False, "enableZba": False, "enableZbb": False, "enableZbs": False}
                validate_rtl_configuration(config, enable_m, enable_c)
                for change in ({"protectedMode": True}, {"protectedMode": 1},
                               {"enableDebug": True}, {"enableDebug": 1},
                               {"enableA": True}, {"enableA": 1},
                               {"enableM": not enable_m}, {"enableC": not enable_c},
                               {"resetVector": 0}, {"unknown": False}, {"enableZba": True},
                               {"enableZbb": True}, {"enableZbs": True}, {"enableZba": 1}):
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
        self.assertEqual(compressed_test_kind('cebreak-01.S', 'RVTEST_ISA("RV32IC_Zicsr")'), 'selected')
        for isa in ('RV32I_Zca_Zcb', 'RV32IM_Zca_Zcb', 'RV32I_Zca_Zcb_Zbb'):
            self.assertEqual(compressed_test_kind('operation.S', f'RVTEST_ISA("{isa}")'), 'requires Zcb')
        for text in ('', 'RVTEST_ISA("RV64IC")', 'RVTEST_ISA("RV32IC")\ndef rvtest_mtrap_routine=True'):
            with self.assertRaises(ValueError):
                compressed_test_kind('operation.S', text)

    def test_bit_profiles_bind_misa_compiler_and_rtl(self):
        for mask in range(8):
            enabled = tuple(bool(mask & (1 << bit)) for bit in range(3))
            flags = dict(zip(('enable_zba', 'enable_zbb', 'enable_zbs'), enabled))
            names = [name for name, value in zip(('Zba', 'Zbb', 'Zbs'), enabled) if value]
            isa = 'RV32I' + ('B' if mask == 7 else '') + 'Zicsr' + ''.join('_' + name for name in names)
            text = isa_specification(**flags)
            self.assertIn('ISA: ' + isa, text)
            self.assertIn('reset-val: ' + hex(0x40000100 | (2 if mask == 7 else 0)), text)
            self.assertEqual(architectural_configuration(isa),
                             (False, False, 'rv32i_zicsr' + ''.join('_' + name.lower() for name in names)))
            parameters = {'resetVector': 0x80000000,
                          **dict(zip(('enableZba', 'enableZbb', 'enableZbs'), enabled))}
            validate_rtl_configuration(parameters, False, False, **flags)
            for name in flags:
                with self.assertRaisesRegex(ValueError, 'mismatch'):
                    validate_rtl_configuration(parameters, False, False, **(flags | {name: not flags[name]}))
        for name in ('enable_zba', 'enable_zbb', 'enable_zbs'):
            with self.assertRaisesRegex(ValueError, 'Boolean'):
                isa_specification(**{name: 1})

    def test_bit_selection_accepts_supported_alternatives(self):
        for extension in ('Zba', 'Zbb', 'Zbs'):
            self.assertEqual(bit_test_extension(f'RVTEST_ISA("RV32I{extension}")'), extension)
        self.assertEqual(bit_test_extension('RVTEST_ISA("RV32IZbb,RV32IZbkb,RV32IZk,RV32IZkn,RV32IZks")'), 'Zbb')
        for declaration in ('RV32IZbc', 'RV32IZbc,RV32IZbkc,RV32IZk,RV32IZkn,RV32IZks'):
            self.assertIsNone(bit_test_extension(f'RVTEST_ISA("{declaration}")'))
        for text in ('', 'RVTEST_ISA("RV64IZba")', 'RVTEST_ISA("RV32IZba,RV32IZbs")',
                     'RVTEST_ISA("RV32IZba,RV32IZba")', 'RVTEST_ISA("RV32IZba_Zbc")',
                     'RVTEST_ISA("RV32IZba")\ndef rvtest_mtrap_routine=True'):
            with self.assertRaises(ValueError):
                bit_test_extension(text)
        for source, instruction in (('sh1add-01.S', 'sh1add'), ('orcb_32-01.S', 'orc.b'),
                                    ('rev8_32-01.S', 'rev8'), ('zext.h_32-01.S', 'zext.h')):
            self.assertEqual(bit_test_instruction(source), instruction)

    def test_test_isa_must_fit_the_compiler_profile(self):
        validate_test_isa('RV32IZbb', 'rv32imc_zba_zbb_zbs_zicsr')
        validate_test_isa('RV32IC', 'rv32ic_zicsr')
        self.assertNotIn('c', test_extensions('RV32IZicsr'))
        for isa in ('RV32IZbb', 'RV32IM', 'RV32IC'):
            with self.assertRaisesRegex(ValueError, 'exceeds'):
                validate_test_isa(isa, 'rv32i_zicsr')
        for isa in ('RV64IZba', 'RV32IZbc', 'RV32IZbkb', 'RV32IZbb,Zks',
                    'RV32IZbb_Zbb', 'RV32IA', 'RV32IB'):
            with self.assertRaisesRegex(ValueError, 'Unsupported'):
                validate_test_isa(isa, 'rv32imc_zba_zbb_zbs_zicsr')

    def test_bit_flags_reach_the_independent_execution_check(self):
        sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
        from verify import check
        for flag, instruction, value in (('enable_zba', 0x200020b3, 0),
                                         ('enable_zbb', 0x60001093, 32),
                                         ('enable_zbb', 0x400070b3, 0),
                                         ('enable_zbs', 0x28001093, 1)):
            lines = []
            for cycle in range(9):
                lines.append(f'T {cycle} 0 {0xFFFFFFF0 + cycle}')
                if cycle == 0:
                    lines.append(f'R 0 0 {instruction} 4 1 1 {value} 0 0 0')
                if cycle == 1:
                    lines.append('R 1 4 111 4 0 0 0 0 0 0')
                if cycle >= 1:
                    lines.append(f'O {cycle} 0 0 0 0 0 2')
            lines += ['C 9 2 0 0 0 0 0 0 0 0 0', f'W 0 {instruction}', 'W 4 111']
            trace = '\n'.join(lines)
            result = check(execution_case({0: instruction, 4: 111}, 0, 4, **{flag: True}), trace)
            self.assertEqual(result['retired'], 2)
            with self.assertRaises(AssertionError):
                check(execution_case({0: instruction, 4: 111}, 0, 4), trace)
            if instruction == 0x400070b3:
                with self.assertRaisesRegex(AssertionError, 'Register result mismatch'):
                    check(execution_case({0: instruction, 4: 111}, 0, 4, enable_zbb=True), changed_andn_result(trace))

    def test_result_control_requires_an_andn_write(self):
        for trace in ('R 0 0 111 0 0 0 0 0 0 0', 'R 0 0 1073770547 4 0 0 0 0 0 0'):
            with self.assertRaisesRegex(ValueError, 'No ANDN'):
                changed_andn_result(trace)

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
