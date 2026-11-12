# SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
# SPDX-License-Identifier: MIT
"""Check fixed-program routing without changing original proof acceptance."""

import copy
import subprocess
import tempfile
import unittest
from pathlib import Path

from formal.trigger import run, staged

from test.test_trigger import test_payload as payload
from test.test_trigger import test_store_state as store


def definition(scenario, configuration=None):
    names = ('core-store-safety', 'core-multiply-safety', 'core-illegal-safety', 'core-older-safety')
    return payload.definition(names[scenario], configuration or staged.PROGRAM_STATE_CONFIG['name'])


class ProgramStateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        store.StoreStateTests.setUpClass()
        anchor = '    if {$kind eq "store_state" && $::mode eq "cex_value"} {set ::states(core_store_value_owner_metadata) cex}'
        assert store.StoreStateTests.harness.count(anchor) == 1
        cls.harness = store.StoreStateTests.harness.replace(anchor, anchor + '\n    if {$kind eq "store_state" && $::mode eq "cex_program"} {set ::states(core_program_configuration_history) cex}', 1)

    def execute(self, root, scenario, mode='pass', typed=True):
        root.mkdir()
        plan, contents = definition(scenario)
        for name, value in contents.items():
            (root / name).write_bytes(value)
        (root / 'harness.tcl').write_text(f'set expected_reset {{{run.EXPECTED_RESET}}}\nset mode {mode}\nset typed {int(typed)}\nset proof_calls 0\nset import_mode auto\n' + self.harness)
        process = subprocess.run(['tclsh', 'harness.tcl'], cwd=root, capture_output=True, text=True, check=False)
        return process, run.read_records(root / 'native.tsv'), plan

    def test_only_multiply_and_illegal_route_to_program_observers(self):
        fragment = (run.HERE / 'program_state_helpers.sv').read_bytes()
        for name in run.CASES:
            plan, contents = payload.definition(name, staged.PROGRAM_STATE_CONFIG['name'])
            previous, old = payload.definition(name, staged.STORE_STATE_CONFIG['name'])
            if name not in ('core-multiply-safety', 'core-illegal-safety'):
                self.assertEqual((plan, contents), (previous, old))
                continue
            previous, old = payload.definition(name, staged.JOINT_CONFIG['name'])
            self.assertEqual([n for n in plan['inputs'] if contents[n] != old[n]], ['collect.tcl', 'plan.tcl', run.CORE_WRAPPER])
            self.assertEqual(contents[run.CORE_WRAPPER].replace(fragment + b'\n', b'', 1), old[run.CORE_WRAPPER])
            for field in ('goals', 'sources', 'targetBounds', 'initialState', 'dutInitialState', 'assumptions', 'payloadParameters', 'nativeCovers'):
                self.assertEqual(plan[field], previous[field])
            self.assertEqual(plan['allAssertions'], [*previous['allAssertions'], *staged.PROGRAM_STATE_HELPERS])

    def test_program_inventory_and_schedule_are_independent_of_store_inventory(self):
        expected = ('core_store_source_state', 'core_armed_target_capture', 'core_store_value_owner_metadata', 'core_program_configuration_history')
        self.assertEqual(staged.PROGRAM_STATE_HELPERS, expected)
        for scenario in (1, 2):
            plan, _ = definition(scenario)
            self.assertEqual(plan['querySchedule'][2]['labels'], list(expected))
            self.assertEqual(plan['querySchedule'], staged.program_state_schedule())
            self.assertEqual([q['timeLimit'] for q in plan['querySchedule']], [120, 300, 120, *([10] * 6), 360])
            self.assertEqual((plan['maximumSearchSeconds'], plan['outerTimeoutSeconds'], plan['cpuCount']), (960, 1080, 16))
            self.assertEqual(plan['targetBounds'], staged.declared_bounds(scenario))
            self.assertEqual(plan['payloadParameters'], staged.payload_parameters(scenario))
            self.assertEqual(291 in plan['payloadParameters']['domain'], scenario == 1)
            self.assertEqual((len(plan['originalGoals']), len(plan['nativeCovers'])), (21, 48))

    def test_real_tcl_full_inventory_and_current_infinite_fact_chain(self):
        with tempfile.TemporaryDirectory() as directory:
            for scenario, typed in ((1, True), (1, False), (2, True), (2, False)):
                process, records, plan = self.execute(Path(directory) / f'{scenario}-{typed}', scenario, typed=typed)
                self.assertEqual(process.returncode, 0, process.stderr)
                checked = staged.validate_protocol(records, plan)
                self.assertTrue(checked['caseAccepted'])
                self.assertEqual((checked['executedQueries'], checked['allocatedSearchSeconds']), (10, 960))
                self.assertEqual(records['query2', 'labels'].split(), list(staged.PROGRAM_STATE_HELPERS))
                self.assertIn('core_program_configuration_history', records['query3', 'fact_labels'].split())
                self.assertEqual(len({tag for tag, key in records if key == 'native_id' and not tag.startswith('bounded.')}), 22 * len(plan['allAssertions']))

    def test_unknown_program_helpers_and_empty_pending_add_no_barrier(self):
        with tempfile.TemporaryDirectory() as directory:
            for scenario in (1, 2):
                process, records, plan = self.execute(Path(directory) / f'{scenario}-unknown', scenario, 'state_unknown')
                self.assertEqual(process.returncode, 0, process.stderr)
                result = staged.validate_protocol(records, plan)
                self.assertTrue(result['caseAccepted'])
                self.assertFalse(set(staged.PROGRAM_STATE_HELPERS).intersection(result['unboundedHelpers']))
                self.assertFalse(set(staged.PROGRAM_STATE_HELPERS).intersection(records['query9', 'fact_labels'].split()))
                process, records, plan = self.execute(Path(directory) / f'{scenario}-empty', scenario, 'skip_remaining')
                self.assertEqual(process.returncode, 0, process.stderr)
                self.assertEqual(records['query9', 'executed'], '0')
                self.assertEqual(staged.validate_protocol(records, plan)['allocatedSearchSeconds'], 600)

    def test_program_counterexample_or_error_stops_later_proof_queries(self):
        with tempfile.TemporaryDirectory() as directory:
            for scenario in (1, 2):
                for mode in ('cex_program', 'tool2'):
                    process, records, plan = self.execute(Path(directory) / f'{scenario}-{mode}', scenario, mode)
                    self.assertEqual(process.returncode, 1)
                    self.assertEqual(records['query3', 'executed'], '0')
                    self.assertEqual(records['query9', 'executed'], '0')
                    self.assertIn(('final_inventory', 'native_assertions'), records)
                    with self.assertRaises(ValueError):
                        staged.validate_protocol(records, plan)

    def test_finite_originals_keep_their_own_scene_bounds_and_zero_needs_infinity(self):
        with tempfile.TemporaryDirectory() as directory:
            for scenario in (1, 2):
                process, records, plan = self.execute(Path(directory) / f'{scenario}-finite', scenario, 'event_finite')
                self.assertEqual(process.returncode, 0, process.stderr)
                self.assertTrue(staged.validate_protocol(records, plan)['caseAccepted'])
                self.assertEqual(records['bounded.target_first_event_is_breakpoint', 'target_bound'], str(160 if scenario == 1 else 128))
                for mode in ('event_short', 'boundzero'):
                    process, records, plan = self.execute(Path(directory) / f'{scenario}-{mode}', scenario, mode)
                    self.assertEqual(process.returncode, 1)
                    self.assertFalse(staged.validate_protocol(records, plan)['caseAccepted'])

    def test_scope_bound_payload_and_raw_metadata_mutations_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            _, records, plan = self.execute(Path(directory) / 'pass', 1)
            for key, value in ((('query2', 'labels'), ''), (('query2.before.core_program_configuration_history', 'max_length'), ''),
                               (('query3', 'fact_actual_properties'), ''), (('query9', 'time_limit'), '480')):
                changed = dict(records)
                changed[key] = value
                with self.subTest(key=key), self.assertRaises(ValueError):
                    staged.validate_protocol(changed, plan)
            for field, value in (('scenario', 0), ('targetBounds', staged.declared_bounds(2)),
                                  ('payloadParameters', staged.payload_parameters(2))):
                changed = copy.deepcopy(plan)
                changed[field] = value
                with self.subTest(field=field), self.assertRaises(ValueError):
                    staged.validate_protocol(records, changed)
