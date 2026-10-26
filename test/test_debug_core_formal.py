# SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
# SPDX-License-Identifier: MIT
"""Check debug proof observations and mutation contracts."""
import tempfile
from pathlib import Path
import unittest
from debug_core_formal import OBSERVATIONS, drain_schedule, mutate, observe, trace_witness


class DebugCoreFormalTests(unittest.TestCase):
    def test_observations_only_add_outputs(self):
        source = 'module DitDahE2(\n input clock\n);\n' + ''.join(
            f'wire {"[31:0] " if width == 32 else ""}{name};\n' for name, width in OBSERVATIONS.values()) + 'endmodule\n'
        result = observe(source)
        self.assertEqual(result.count('assign observed_'), 4)
        self.assertEqual(result.count('input '), 1)
        with self.assertRaises(ValueError):
            observe(source.replace('_debug_core_resumePc', 'changed'))

    def test_mutations_require_exact_targets(self):
        self.assertEqual(mutate('wire n = core_empty & core_fetchIdle;', 'early-halt'), "wire n = 1'b1;")
        self.assertIn('~core_completed', mutate('assign core_stop = halted | haltNeeded;', 'extra-step'))
        for name in ('early-halt', 'extra-step'):
            with self.assertRaises(ValueError):
                mutate('module unrelated; endmodule', name)

    def test_drain_control_selects_legal_three_cycle_response(self):
        source = b'  (* anyconst *) reg [1:0] initial_delay, stepped_delay;'
        self.assertIn(b'initial_delay = 2;', drain_schedule(source))
        self.assertIn(b'anyconst', drain_schedule(source))
        with self.assertRaises(ValueError):
            drain_schedule(b'')

    def test_witness_requires_observed_effect(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'trace.vcd'
            path.write_text('$var wire 1 n1 early_halt $end\n#0\nb0 n1\n#1\nb1 n1\n')
            self.assertEqual(trace_witness(path, lambda v: v.get('early_halt') == 1)['time'], 1)
            with self.assertRaises(ValueError):
                trace_witness(path, lambda v: v.get('extra_step') == 1)


if __name__ == '__main__':
    unittest.main()
