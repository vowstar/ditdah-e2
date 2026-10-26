# SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
# SPDX-License-Identifier: MIT
"""Check control deadlines and semantic counterexample acceptance."""
import unittest
from debug_latency_formal import OBSERVATIONS, bounds, general_step_bound, mutate, observe, step_bound, witness_condition


class DebugLatencyTests(unittest.TestCase):
    def test_service_bounds_include_draining_and_polling(self):
        self.assertEqual(bounds(), {'halt': 72, 'resume': 38, 'poll': 20})
        self.assertEqual(bounds(1, 1, 1), {'halt': 12, 'resume': 8, 'poll': 6})
        for values in ((0, 1, 1), (8, 33, 8), (True, 1, 1)):
            with self.assertRaises(ValueError):
                bounds(*values)

    def test_observations_do_not_change_inputs(self):
        source = 'module DitDahE2(\n input clock\n);\n' + ''.join(
            'wire ' + name + ';\n' for name in OBSERVATIONS.values()) + 'endmodule\n'
        changed = observe(source)
        self.assertEqual(changed.count('input '), 1)
        self.assertEqual(changed.count('assign observed_'), len(OBSERVATIONS))
        with self.assertRaises(ValueError):
            observe(source.replace('mValid', 'changed'))

    def test_step_bound_includes_crossing_multiply_and_final_fetch_drain(self):
        self.assertEqual(step_bound(8, 24, False, False), 112)
        self.assertEqual(step_bound(8, 24, True, False), 146)
        self.assertEqual(step_bound(8, 24, False, True), 144)
        self.assertEqual(step_bound(8, 24, True, True), 178)

    def test_general_step_includes_an_old_abstract_transfer(self):
        self.assertEqual(general_step_bound(8, 24, False, False), 150)
        self.assertEqual(general_step_bound(8, 24, True, False), 184)
        self.assertEqual(general_step_bound(8, 24, False, True), 182)
        self.assertEqual(general_step_bound(8, 24, True, True), 216)

    def test_mutants_change_completion_conditions(self):
        self.assertIn('& core_completed;', mutate('wire n = core_empty & core_fetchIdle;', 'halt-blocked'))
        self.assertIn("1'b0 &", mutate('wire resume = active & halted;', 'resume-blocked'))
        self.assertIn('~(core_completed & core_singleStep)', mutate('assign core_stop = halted | stopping;', 'extra-step'))
        for name in ('halt-blocked', 'resume-blocked', 'extra-step'):
            with self.assertRaises(ValueError):
                mutate('module unrelated; endmodule', name)

    def test_negative_acceptance_requires_expired_hardware_deadline(self):
        for name, flag in [('halt-blocked', 'halt_expired'), ('resume-blocked', 'resume_expired'), ('extra-step', 'extra_step')]:
            check = witness_condition(name)
            self.assertFalse(check({'finished': 1}))
            self.assertFalse(check({flag: 0}))
            self.assertTrue(check({flag: 1}))

    def test_cover_requires_its_transaction_boundary(self):
        check = witness_condition('data-offered')
        self.assertFalse(check({'finished': 1, 'halt_with_d_offered': 0}))
        self.assertFalse(check({'finished': 0, 'halt_with_d_offered': 1}))
        self.assertTrue(check({'finished': 1, 'halt_with_d_offered': 1}))

    def test_multiply_cover_identifies_the_completed_instruction(self):
        check = witness_condition('step-multiply')
        sample = {'finished': 1, 'step_multiply': 1, 'step_retired': 1, 'retire_word': 0x02000033}
        self.assertTrue(check(sample))
        self.assertFalse(check({**sample, 'retire_word': 0x00002003}))
        self.assertFalse(check({**sample, 'step_retired': 0}))


if __name__ == '__main__':
    unittest.main()
