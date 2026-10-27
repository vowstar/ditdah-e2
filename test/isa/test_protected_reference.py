# SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
# SPDX-License-Identifier: MIT
"""Check reference state parsing and architectural sequence comparisons."""

import unittest

from protected_reference import WARNING, reference_sequence, reference_state, rtl_sequence


class ProtectedReferenceTests(unittest.TestCase):
    def state(self):
        values = [0x80000038, 1, 7, 0x800000b8, 0x20000000, 0x13579bdf, 8, 0x2468ace0, 0x13579bdf]
        raw = WARNING + '\n:\n' + f'0x{values[0]:08x}\nM\n'
        raw += ''.join(f'0x{value:08x}\n' for value in values[1:])
        return raw, values

    def test_final_state_and_signature(self):
        raw, values = self.state()
        self.assertEqual(reference_state(raw, values), values)
        for index in range(len(values)):
            changed = values.copy()
            changed[index] ^= 1
            with self.subTest(index=index), self.assertRaisesRegex(AssertionError, 'signature mismatch'):
                reference_state(raw, changed)

    def test_unknown_diagnostics_and_wrong_privilege_fail(self):
        raw, values = self.state()
        for changed in (raw.replace(WARNING, 'unknown diagnostic'), raw.replace('\nM\n', '\nU\n'),
                        raw + 'extra record\n', raw.replace('0x00000007', 'invalid value')):
            with self.subTest(changed=changed), self.assertRaises(AssertionError):
                reference_state(changed, values)

    def test_reference_boot_prefix_and_first_completion(self):
        raw = '\n'.join([
            'core   0: 3 0x00001000 (0x00000297) x5  0x00001000',
            'core   0: 0 0x80000000 (0x00100093) x1  0x00000001',
            'core   0: 3 0x80000004 (0x0000006f)',
            'core   0: 3 0x80000004 (0x0000006f)',
        ])
        sequence, causes = reference_sequence(raw, 0x80000000, 0x80000004)
        self.assertEqual(sequence, [(1, 0x80000000, 0x00100093, (1, 1)),
                                    (0, 0x80000004, 0x6f, None)])
        self.assertEqual(causes, [])

    def test_missing_reference_entry_completion_and_bad_records_fail(self):
        raw = 'core   0: 3 0x80000000 (0x00100093) x1  0x00000001\n'
        for changed, entry in ((raw, 0x80000000), (raw, 0x90000000), ('unknown\n', 0x80000000)):
            with self.subTest(changed=changed, entry=entry), self.assertRaises(AssertionError):
                reference_sequence(changed, entry, 0x80000004)

    def test_trap_cause_reads_are_independent_records(self):
        raw = '\n'.join([
            'core   0: 3 0x80000000 (0x342022f3) x5  0x00000007',
            'core   0: 3 0x80000004 (0x34202373) x6  0x00000008',
            'core   0: 3 0x80000008 (0x0000006f)',
        ])
        self.assertEqual(reference_sequence(raw, 0x80000000, 0x80000008)[1], [7, 8])

    def test_fault_events_do_not_count_as_successful_instructions(self):
        trace = '\n'.join([
            'R 0 2147483648 1048723 2147483652 1 1 1 0 0 0 1',
            'R 1 2147483652 115 2147483664 0 0 0 1 8 0 1',
            'R 2 2147483664 111 2147483664 0 0 0 0 0 0 0',
        ])
        sequence, traps = rtl_sequence(trace, 0x80000010)
        self.assertEqual(sequence, [(1, 0x80000000, 0x00100093, (1, 1)),
                                    (0, 0x80000010, 0x6f, None)])
        self.assertEqual(traps, [(0x80000004, 8, 0, 1)])

    def test_missing_or_trapping_rtl_completion_fails(self):
        for raw in ('', 'R 1 2147483652 115 2147483664 0 0 0 1 8 0 1'):
            with self.subTest(raw=raw), self.assertRaises(AssertionError):
                rtl_sequence(raw, 0x80000004)


if __name__ == '__main__':
    unittest.main()
