# SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
# SPDX-License-Identifier: MIT
"""Check dynamic joint selection, modern proof arguments and original qualification."""
import copy
import subprocess
import tempfile
import unittest
from pathlib import Path

from formal.trigger import run, staged

from test.test_trigger import test_payload as payload


def definition(name='core-older-safety'):
    return payload.definition(name, staged.JOINT_CONFIG['name'])


class JointTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        payload.PayloadTests.setUpClass()
        harness = payload.PayloadTests.harness
        old = '''    set selected $fixed
    if {$kind eq "remaining"} {
        set selected {}
        foreach label $::original_goals {'''
        new = '''    set selected $fixed
    if {$kind in {joint remaining}} {
        set selected {}
        set candidates $::original_goals
        if {$kind eq "joint"} {set candidates [concat {abstract_dpc_value resume_pc_matches} $::original_goals]}
        set seen {}
        foreach label $candidates {
            if {$label in $seen} {continue}
            lappend seen $label'''
        assert old in harness
        harness = harness.replace(old, new, 1)
        anchor = '    if {$::mode eq "all_finite"} {'
        extra = '''    if {$kind eq "joint"} {foreach label $selected {set ::winners($label) Mp}}
    if {$kind eq "joint" && $::mode in {joint_unknown joint_finite tool9 cex9}} {
        foreach label $selected {
            set ::states($label) unknown;set ::lengths($label) 1
            if {$::mode eq "joint_finite" && $label in {abstract_dpc_value resume_pc_matches}} {
                set ::states($label) undetermined
                set ::lengths($label) $::original_bounds($label)
                set ::winners($label) N
            }
        }
    }
'''
        assert anchor in harness
        cls.harness = harness.replace(anchor, extra + anchor, 1)

    def execute(self, root, mode='pass', name='core-older-safety'):
        root.mkdir()
        plan, contents = definition(name)
        for n, b in contents.items():
            (root / n).write_bytes(b)
        (root / 'harness.tcl').write_text(f'set expected_reset {{{run.EXPECTED_RESET}}}\nset mode {mode}\nset typed 1\nset proof_calls 0\nset import_mode auto\n' + self.harness)
        process = subprocess.run(['tclsh', 'harness.tcl'], cwd=root, capture_output=True, text=True, check=False)
        return process, run.read_records(root / 'native.tsv'), plan

    def test_all_scenes_use_identical_sources_bounds_cold_and_exact_budget(self):
        for name in run.CASES:
            plan, contents = definition(name)
            old, previous = payload.definition(name)
            if name not in run.SAFETY_RETRY_CASES:
                self.assertEqual((plan, contents), (old, previous))
                continue
            self.assertEqual([n for n in plan['inputs'] if contents[n] != previous[n]], ['collect.tcl', 'plan.tcl'])
            for key in ('sources', 'goals', 'targetBounds', 'assumptions', 'initialState', 'dutInitialState', 'payloadParameters', 'allAssertions', 'nativeCovers'):
                self.assertEqual(plan[key], old[key])
            self.assertEqual(sum(q['timeLimit'] for q in plan['querySchedule']), 960)
            q8, q9 = plan['querySchedule'][8:]
            self.assertEqual((q8['kind'], q8['engines'], q8['timeLimit'], q8['propertyGuard'], q8['jobs']), ('joint', ['Mp', 'N', 'Hp'], 360, 23040, 4))
            self.assertEqual((q9['timeLimit'], q9['engines']), (120, ['B']))

    def test_real_tcl_pending_dpc_priority_and_empty_tail_all_scenarios(self):
        with tempfile.TemporaryDirectory() as directory:
            for name in run.SAFETY_RETRY_CASES:
                process, records, plan = self.execute(Path(directory) / name, name=name)
                self.assertEqual(process.returncode, 0, process.stderr)
                result = staged.validate_protocol(records, plan)
                self.assertTrue(result['caseAccepted'])
                self.assertEqual(records['query8', 'labels'].split(), ['abstract_dpc_value', 'resume_pc_matches', 'older_fault_cause', 'target_first_event_is_breakpoint', 'older_fault_blocks_target', 'older_fault_blocks_store'])
                self.assertEqual(records['query8', 'engines'], 'Mp N Hp')
                self.assertEqual(records['query8', 'iteration_cap'], 'none')
                self.assertEqual(records['query9', 'executed'], '0')
                self.assertEqual(result['allocatedSearchSeconds'], 840)
            process, records, plan = self.execute(Path(directory) / 'empty', mode='skip_remaining')
            self.assertEqual(process.returncode, 0, process.stderr)
            self.assertEqual((records['query8', 'executed'], records['query9', 'executed']), ('0', '0'))
            self.assertEqual(staged.validate_protocol(records, plan)['allocatedSearchSeconds'], 480)

    def test_unknown_or_finite_joint_results_are_not_infinity_facts(self):
        with tempfile.TemporaryDirectory() as directory:
            for mode in ('joint_unknown', 'joint_finite'):
                process, records, plan = self.execute(Path(directory) / mode, mode)
                self.assertEqual(process.returncode, 0, process.stderr)
                self.assertTrue(staged.validate_protocol(records, plan)['caseAccepted'])
                for label in ('abstract_dpc_value', 'resume_pc_matches'):
                    self.assertNotIn(label, records['query9', 'fact_labels'].split())
                self.assertEqual(len(records['query9', 'labels'].split()), 4 if mode == 'joint_finite' else 6)
                if mode == 'joint_finite':
                    self.assertEqual(records['bounded.abstract_dpc_value', 'engine'], 'N')
                    self.assertEqual(records['bounded.abstract_dpc_value', 'target_bound'], '128')
            process, records, plan = self.execute(Path(directory) / 'zero', 'boundzero')
            self.assertEqual(process.returncode, 1)
            self.assertIn('initial_dpc_zero', staged.validate_protocol(records, plan)['unresolvedOriginals'])

    def test_real_tcl_errors_and_counterexamples_stop_later_queries(self):
        with tempfile.TemporaryDirectory() as directory:
            for mode in ('tool8', 'cex8', 'tool9', 'cex9'):
                process, records, plan = self.execute(Path(directory) / mode, mode)
                self.assertEqual(process.returncode, 1)
                if mode.endswith('8'):
                    self.assertEqual(records['query9', 'executed'], '0')
                with self.assertRaises(ValueError):
                    staged.validate_protocol(records, plan)

    def test_strict_selection_facts_inventory_budget_and_original_conversion(self):
        with tempfile.TemporaryDirectory() as directory:
            _, records, plan = self.execute(Path(directory) / 'finite', 'joint_finite')
            mutants = [(('query8', 'labels'), ' '.join(reversed(records['query8', 'labels'].split()))),
                       (('query8', 'engines'), 'N C I'), (('query8', 'time_limit'), '120'),
                       (('query9', 'time_limit'), '360'), (('query9', 'iteration_cap'), '128'),
                       (('query8', 'fact_actual_properties'), ''), (('query8.after_inventory', 'native_covers'), ''),
                       (('final_inventory', 'native_assertions'), ''), (('bounded.abstract_dpc_value', 'target_bound'), '127')]
            for key, value in mutants:
                changed = dict(records);changed[key] = value
                with self.subTest(key=key), self.assertRaises(ValueError):
                    staged.validate_protocol(changed, plan)
            changed = copy.deepcopy(plan);changed['targetBounds']['older_fault_cause'] = 128
            with self.assertRaises(ValueError):
                staged.validate_protocol(records, changed)
