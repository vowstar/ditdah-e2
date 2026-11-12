# SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
# SPDX-License-Identifier: MIT
"""Exercise fixed-store helper staging, event priority and original qualification."""
import copy
import subprocess
import tempfile
import unittest
from pathlib import Path

from formal.trigger import run, staged

from test.test_trigger import test_joint as joint
from test.test_trigger import test_payload as payload


def definition(name='core-store-safety', configuration=None):
    return payload.definition(name, configuration or staged.STORE_STATE_CONFIG['name'])


class StoreStateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        joint.JointTests.setUpClass()
        harness = joint.JointTests.harness.replace('if {$kind in {joint remaining}} {', 'if {$kind in {joint remaining event_joint}} {', 1)
        anchor = '        set seen {}'
        order = '''        if {$kind eq "event_joint"} {
            set front {target_first_event_is_breakpoint target_retry_has_no_trap target_single_retry older_load_retires_first no_store_before_breakpoint}
            set back {native_epc_metadata native_cause_metadata native_tval_metadata native_control_metadata native_hit_metadata abstract_dpc_value resume_pc_matches}
            set middle {}
            foreach label $::original_goals {if {$label ni $front && $label ni $back} {lappend middle $label}}
            set candidates [concat $front $middle $back]
        }
'''
        assert harness.count(anchor) == 1
        harness = harness.replace(anchor, order + anchor, 1)
        extra = '''    if {$kind eq "store_state" && $::mode eq "state_unknown"} {
        foreach label $selected {set ::states($label) unknown;set ::lengths($label) 1}
    }
    if {$kind eq "store_state" && $::mode eq "cex_value"} {set ::states(core_store_value_owner_metadata) cex}
    if {$kind eq "store_state" && $::mode eq "cex_history"} {set ::states(core_store_configuration_history) cex}
    if {$kind eq "event_joint" && $::mode in {event_finite event_short}} {
        foreach label $selected {
            set ::states($label) undetermined
            set ::lengths($label) $::original_bounds($label)
            set ::winners($label) Mp
        }
        if {$::mode eq "event_short"} {incr ::lengths(target_first_event_is_breakpoint) -1}
    }
'''
        anchor = '    if {$::mode eq "all_finite"} {'
        assert harness.count(anchor) == 1
        cls.harness = harness.replace(anchor, extra + anchor, 1)

    def execute(self, root, mode='pass', typed=True):
        root.mkdir()
        plan, contents = definition()
        for name, value in contents.items():
            (root / name).write_bytes(value)
        (root / 'harness.tcl').write_text(f'set expected_reset {{{run.EXPECTED_RESET}}}\nset mode {mode}\nset typed {int(typed)}\nset proof_calls 0\nset import_mode auto\n' + self.harness)
        result = subprocess.run(['tclsh', 'harness.tcl'], cwd=root, capture_output=True, text=True, check=False)
        return result, run.read_records(root / 'native.tsv'), plan

    def test_only_fixed_store_cases_change_and_fragment_deletes_exactly(self):
        fragment = (run.HERE / 'store_state_helpers.sv').read_bytes()
        for name in run.CASES:
            plan, contents = definition(name)
            old, previous = definition(name, staged.JOINT_CONFIG['name'])
            if name not in ('core-store-safety', 'core-dpc-safety'):
                self.assertEqual((plan, contents), (old, previous))
                continue
            self.assertEqual(plan['scenario'], 0)
            self.assertEqual([n for n in plan['inputs'] if contents[n] != previous[n]], ['collect.tcl', 'plan.tcl', 'trigger_core_formal.sv'])
            self.assertEqual(contents[run.CORE_WRAPPER].replace(fragment + b'\n', b'', 1), previous[run.CORE_WRAPPER])
            for field in ('goals', 'sources', 'targetBounds', 'initialState', 'dutInitialState', 'assumptions', 'payloadParameters', 'nativeCovers'):
                self.assertEqual(plan[field], old[field])
            self.assertEqual(plan['allAssertions'], [*old['allAssertions'], 'core_store_source_state', 'core_armed_target_capture', 'core_store_value_owner_metadata', 'core_store_configuration_history'])
            self.assertEqual(len(plan['nativeCovers']), 48)
        self.assertEqual(definition(), definition('core-dpc-safety'))

    def test_dependency_order_exact_budget_and_no_b_search(self):
        plan, _ = definition()
        schedule = plan['querySchedule']
        self.assertEqual([q['kind'] for q in schedule], ['metadata', 'payload', 'store_state', *(['hint'] * 6), 'event_joint'])
        self.assertEqual([q['timeLimit'] for q in schedule], [120, 300, 120, *([10] * 6), 360])
        self.assertEqual(schedule[2]['labels'], ['core_store_source_state', 'core_armed_target_capture', 'core_store_value_owner_metadata', 'core_store_configuration_history'])
        self.assertFalse(set(schedule[2]['labels']).intersection(schedule[0]['labels']))
        self.assertEqual(schedule[1]['labels'], ['core_setup_exact_command_payload'])
        self.assertEqual(schedule[-1]['engines'], ['Mp', 'N', 'Hp'])
        self.assertEqual((plan['maximumSearchSeconds'], plan['outerTimeoutSeconds'], plan['cpuCount']), (960, 1080, 16))
        self.assertNotIn('B', [e for q in schedule for e in q['engines']])

    def test_real_tcl_typed_ids_full_raw_inventory_and_event_first_selection(self):
        with tempfile.TemporaryDirectory() as directory:
            for typed in (True, False):
                process, records, plan = self.execute(Path(directory) / str(typed), typed=typed)
                self.assertEqual(process.returncode, 0, process.stderr)
                result = staged.validate_protocol(records, plan)
                self.assertTrue(result['caseAccepted'])
                self.assertEqual(records['query9', 'labels'].split(), ['target_first_event_is_breakpoint', 'older_fault_cause', 'older_fault_blocks_target', 'older_fault_blocks_store', 'abstract_dpc_value', 'resume_pc_matches'])
                self.assertEqual((records['query9', 'iteration_cap'], records['query9', 'first_trace_attempt']), ('none', 'none'))
                self.assertIn('core_setup_exact_command_payload', records['query2', 'fact_labels'].split())
                self.assertEqual(len({tag for tag, key in records if key == 'native_id' and not tag.startswith('bounded.')}), 22 * len(plan['allAssertions']))
                self.assertEqual((result['executedQueries'], result['allocatedSearchSeconds']), (10, 960))

    def test_unknown_new_helpers_and_empty_original_query_do_not_add_barriers(self):
        with tempfile.TemporaryDirectory() as directory:
            process, records, plan = self.execute(Path(directory) / 'unknown', 'state_unknown')
            self.assertEqual(process.returncode, 0, process.stderr)
            result = staged.validate_protocol(records, plan)
            self.assertTrue(result['caseAccepted'])
            for name in staged.STORE_STATE_HELPERS:
                self.assertNotIn(name, records['query9', 'fact_labels'].split())
                self.assertNotIn(name, result['unboundedHelpers'])
            process, records, plan = self.execute(Path(directory) / 'empty', 'skip_remaining')
            self.assertEqual(process.returncode, 0, process.stderr)
            self.assertEqual(records['query9', 'executed'], '0')
            self.assertEqual(staged.validate_protocol(records, plan)['allocatedSearchSeconds'], 600)

    def test_original_finite_qualification_needs_no_b_and_zero_still_needs_infinity(self):
        with tempfile.TemporaryDirectory() as directory:
            process, records, plan = self.execute(Path(directory) / 'finite', 'event_finite')
            self.assertEqual(process.returncode, 0, process.stderr)
            result = staged.validate_protocol(records, plan)
            self.assertTrue(result['caseAccepted'])
            self.assertEqual(records['bounded.target_first_event_is_breakpoint', 'engine'], 'Mp')
            self.assertEqual(records['bounded.target_first_event_is_breakpoint', 'target_bound'], '128')
            for mode in ('event_short', 'boundzero'):
                process, records, plan = self.execute(Path(directory) / mode, mode)
                self.assertEqual(process.returncode, 1)
                self.assertFalse(staged.validate_protocol(records, plan)['caseAccepted'])

    def test_real_tcl_fatal_errors_preserve_footer_and_stop_future_queries(self):
        with tempfile.TemporaryDirectory() as directory:
            for mode in ('tool1', 'tool2', 'cex2', 'cex_value', 'cex_history', 'tool9', 'cex9'):
                process, records, plan = self.execute(Path(directory) / mode, mode)
                self.assertEqual(process.returncode, 1)
                self.assertEqual(records['run', 'scheduled_queries'], '10')
                if mode in ('tool1', 'tool2', 'cex2', 'cex_value', 'cex_history'):
                    self.assertEqual(records['query9', 'executed'], '0')
                with self.assertRaises(ValueError):
                    staged.validate_protocol(records, plan)

    def test_actual_after_inventory_corruption_is_recorded_and_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            for mode in ('missing_after', 'extra_after', 'duplicate_after'):
                process, records, plan = self.execute(Path(directory) / mode, mode)
                self.assertEqual(process.returncode, 1)
                self.assertIn(('query0.after_inventory', 'native_covers'), records)
                self.assertIn(('run', 'error'), records)
                with self.assertRaises(ValueError):
                    staged.validate_protocol(records, plan)

    def test_mutants_reject_selection_facts_inventory_raw_bound_and_scope_changes(self):
        with tempfile.TemporaryDirectory() as directory:
            _, records, plan = self.execute(Path(directory) / 'finite', 'event_finite')
            mutations = [(('query2', 'labels'), ''), (('query9', 'labels'), ' '.join(reversed(records['query9', 'labels'].split()))),
                         (('query9', 'engines'), 'B'), (('query9', 'iteration_cap'), '288'),
                         (('query2', 'fact_actual_properties'), ''), (('query2.after_inventory', 'native_covers'), ''),
                         (('final_inventory', 'native_assertions'), ''), (('query9', 'time_limit'), '480'),
                         (('bounded.target_first_event_is_breakpoint', 'target_bound'), '127'),
                         (('query2.before.core_armed_target_capture', 'max_length'), ''), (('query9.after_scope', 'clock'), 'clock')]
            for key, value in mutations:
                changed = dict(records);changed[key] = value
                with self.subTest(key=key), self.assertRaises(ValueError):
                    staged.validate_protocol(changed, plan)
            changed = copy.deepcopy(plan);changed['scenario'] = 3
            with self.assertRaises(ValueError):
                staged.validate_protocol(records, changed)
