# SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
# SPDX-License-Identifier: MIT
"""Check the fields used by the external CSR comparison."""

from types import SimpleNamespace
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from menvcfg_reference import compare_external, digest, external_events, input_hashes, reuse_simulator


class ExternalComparisonTest(unittest.TestCase):
    def setUp(self):
        self.expected = [(0, 0x80000000, 0x30a02573, (10, 0), 0, 0, 0, 0x80000004),
                         (1, 0x80000004, 0x30a02573, None, 1, 2, 0x30a02573, 0x80000100)]
        self.lines = ['R 0 2147483648 815801715 2147483652 10 1 0 0 0 0 0',
                      'R 1 2147483652 815801715 2147483904 10 0 0 1 2 815801715 1']

    def check_changed_field(self, row, column, value):
        lines = self.lines.copy()
        fields = lines[row].split()
        fields[column] = str(value)
        lines[row] = ' '.join(fields)
        with self.assertRaisesRegex(AssertionError, '^External architectural event mismatch$'):
            compare_external('\n'.join(lines), self.expected, 0x80000004)

    def test_exact_events_pass(self):
        result = compare_external('\n'.join(self.lines), self.expected, 0x80000004)
        self.assertEqual(result['nextPcsCompared'], 2)
        self.assertEqual(result['csrAccessesCompared'], 2)
        self.assertEqual(result['successfulCsrResultsCompared'], 1)

    def test_wrong_csr_value_fails(self):
        self.check_changed_field(0, 7, 1)

    def test_wrong_trap_value_fails(self):
        self.check_changed_field(1, 10, 0)

    def test_wrong_trap_cause_fails(self):
        self.check_changed_field(1, 9, 3)

    def test_wrong_next_pc_fails(self):
        self.check_changed_field(1, 4, 0x80000104)

    def test_missing_event_fails(self):
        with self.assertRaisesRegex(AssertionError, '^External architectural event count differs$'):
            compare_external(self.lines[0], self.expected, 0x80000004)

    def test_trap_signature_supplies_the_fault_event(self):
        case = SimpleNamespace(image=SimpleNamespace(symbols={'trap_vector': 0x80000100}),
                               expected_traps=((0x80000004, 2, 0x30a02573, 1),),
                               words=lambda: {0x80000004: 0x30a02573})
        sequence = [(1, 0x80000000, 0x13, None), (0, 0x80000100, 0x34202e73, (28, 2))]
        state = [0] * 65
        state[33:36] = [2, 0x80000004, 0x30a02573]
        events = external_events(sequence, state, case)
        self.assertEqual(events[0][-1], 0x80000004)
        self.assertEqual(events[1], (1, 0x80000004, 0x30a02573, None, 1, 2, 0x30a02573, 0x80000100))

    def test_first_user_fault_after_mret_uses_saved_mpp(self):
        case = SimpleNamespace(image=SimpleNamespace(symbols={'trap_vector': 0x80000100}),
                               expected_traps=((0x80000004, 2, 0x30a02573, 1),),
                               words=lambda: {0x80000004: 0x30a02573})
        sequence = [(0, 0x80000000, 0x30200073, None),
                    (0, 0x80000100, 0x34202e73, (28, 2))]
        state = [0] * 65
        state[33:37] = [2, 0x80000004, 0x30a02573, 0]
        events = external_events(sequence, state, case)
        self.assertEqual(events[1][0], 1)
        state[36] = 3
        self.assertEqual(external_events(sequence, state, case)[1][0], 0)
        for mpp in (1, 2, 4):
            state[36] = mpp
            with self.subTest(mpp=mpp), self.assertRaisesRegex(AssertionError, 'Unsupported trap privilege'):
                external_events(sequence, state, case)

    def test_csr_count_requires_system_csr_encoding(self):
        for word in (0x30a00513, 0x30a00073, 0x30a04073):
            event = (0, 0x80000000, word, (10, 0), 0, 0, 0, 0x80000004)
            trace = f'R 0 2147483648 {word} 2147483652 10 1 0 0 0 0 0'
            result = compare_external(trace, [event], 0x80000000)
            self.assertEqual(result['csrAccessesCompared'], 0)
            self.assertEqual(result['successfulCsrResultsCompared'], 0)

    def test_input_binding_includes_imported_checker_and_entry_files(self):
        hashes = input_hashes()
        for name in ('test/verify_protected.py', 'test/protected_programs.py', 'test/pmp.py',
                     'test/elf.py', 'test/isa/test_menvcfg_reference.py', 'test/isa/menvcfg.sh',
                     'software/menvcfg_reference.ld'):
            self.assertIn(name, hashes)
            self.assertEqual(len(hashes[name]), 64)


class SimulatorReuseTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='ditdah-e2-reuse-')
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.previous = self.root / 'old/profile'
        for name in ('test/sim.cpp', 'test/inactive_debug.hpp'):
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text('source')
            frozen = self.root / 'old/inputs' / name
            frozen.parent.mkdir(parents=True, exist_ok=True)
            frozen.write_bytes(path.read_bytes())
        (self.previous / 'rtl').mkdir(parents=True)
        (self.previous / 'rtl/core.sv').write_text('rtl')
        self.rtl = {'core.sv': digest(self.previous / 'rtl/core.sv')}
        (self.previous / 'rtl/manifest.json').write_text(json.dumps({'rtlHashes': self.rtl}))
        (self.previous / 'obj').mkdir()
        (self.previous / 'obj/VDitDahE2').write_text('executable')
        for name in ('rtl-build.stdout', 'rtl-build.stderr'):
            (self.previous / name).write_text('build evidence')
        self.tools = {role: {'path': role, 'sha256': 'a' * 64, 'version': 'fixed'}
                      for role in ('verilator', 'cxx', 'make')}
        (self.root / 'old/summary.json').write_text(json.dumps({
            'exitStatus': 0, 'tools': self.tools,
            'sourceHashes': {name: digest(self.root / name)
                             for name in ('test/sim.cpp', 'test/inactive_debug.hpp')}}))
        (self.previous / 'summary.json').write_text(json.dumps({
            'exitStatus': 0, 'rtlManifestHash': digest(self.previous / 'rtl/manifest.json'),
            'simulatorHash': digest(self.previous / 'obj/VDitDahE2')}))
        (self.root / 'new').mkdir()

    def run_reuse(self):
        with patch('menvcfg_reference.ROOT', self.root):
            return reuse_simulator(self.previous, self.root / 'new/obj', self.rtl, self.tools)

    def test_matching_build_is_copied_and_bound(self):
        result = self.run_reuse()
        self.assertTrue(result['reused'])
        self.assertEqual(result['simulatorHash'], digest(self.root / 'new/obj/VDitDahE2'))

    def test_changed_executable_is_rejected(self):
        (self.previous / 'obj/VDitDahE2').write_text('changed')
        with self.assertRaisesRegex(AssertionError, 'Simulator executable differs'):
            self.run_reuse()

    def test_changed_header_is_rejected(self):
        (self.root / 'test/inactive_debug.hpp').write_text('changed')
        with self.assertRaisesRegex(AssertionError, 'Simulator source differs'):
            self.run_reuse()

    def test_changed_rtl_is_rejected(self):
        self.rtl['core.sv'] = 'b' * 64
        with self.assertRaisesRegex(AssertionError, 'Simulator RTL differs'):
            self.run_reuse()

    def test_changed_build_tool_is_rejected(self):
        self.tools['cxx']['sha256'] = 'b' * 64
        with self.assertRaisesRegex(AssertionError, 'Simulator build tool differs'):
            self.run_reuse()


if __name__ == '__main__':
    unittest.main()
