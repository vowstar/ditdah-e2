# SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
# SPDX-License-Identifier: MIT
"""Exercise payload scheduling and exact native inventories with real Tcl."""
import argparse
import copy
import hashlib
import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from formal.trigger import run, staged

from test.test_trigger import test_staged as baseline
from test.test_trigger.test_staged import collectors, rtl

CONFIGURATION = staged.PAYLOAD_CONFIG['name']


def definition(name='core-older-safety', configuration=CONFIGURATION):
    selected = collectors()
    collector, helper = staged.artifacts(configuration)
    selected.update(staged=(run.HERE / collector).read_bytes(), staged_helpers=(run.HERE / helper).read_bytes())
    return run.case_definition(name, *rtl(),
        {run.UNIT_TOP: (run.HERE / run.UNIT_WRAPPER).read_bytes(), run.CORE_TOP: (run.HERE / run.CORE_WRAPPER).read_bytes()},
        selected, 120, 600, flow='staged', source_configuration=configuration)


class PayloadTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not shutil.which('tclsh'):
            raise RuntimeError('Real tclsh is required')
        baseline.StagedTests.setUpClass()
        harness = baseline.StagedTests.harness
        harness = harness.replace('    return $result\n}', '''    set actual $::native_covers
    if {$::mode eq "missing_cover" || ($::mode eq "missing_after" && $::proof_calls>0)} {set actual [lrange $actual 1 end]}
    if {$::mode eq "extra_cover" || ($::mode eq "extra_after" && $::proof_calls>0)} {lappend actual foreign:precondition1}
    if {$::mode eq "duplicate_cover" || ($::mode eq "duplicate_after" && $::proof_calls>0)} {lappend actual [lindex $actual 0]}
    foreach label $actual {lappend result "$::top.$label"}
    return $result
}''', 1)
        harness = harness.replace('    if {$label in {initial_common_cold_reset no_later_cold_reset}} {', '''    if {$label in $::native_covers || $label eq "foreign:precondition1"} {
        return [list name "$::top.$label" type cover command cover disabled 0]
    }
    if {$label in {initial_common_cold_reset no_later_cold_reset}} {''', 1)
        harness = harness.replace('    if {$::mode eq "all_finite"} {', '''    if {$::mode eq "new_unknown" && $kind in {metadata payload}} {
        foreach label $selected {set ::states($label) unknown;set ::lengths($label) 1}
    }
    if {$kind eq "metadata" && $::mode eq "skip_remaining"} {
        foreach label $::original_goals {set ::states($label) proven;set ::lengths($label) infinite;set ::winners($label) PRE}
    }
    if {$::mode eq "all_finite"} {''', 1)
        cls.harness = harness

    def execute(self, root, mode='pass', name='core-older-safety', typed=True):
        root.mkdir()
        plan, contents = definition(name)
        for filename, value in contents.items():
            (root / filename).write_bytes(value)
        (root / 'harness.tcl').write_text(f'set expected_reset {{{run.EXPECTED_RESET}}}\nset mode {mode}\nset typed {int(typed)}\nset proof_calls 0\nset import_mode auto\n' + self.harness)
        process = subprocess.run(['tclsh', 'harness.tcl'], cwd=root, capture_output=True, text=True, check=False)
        return process, run.read_records(root / 'native.tsv'), plan

    def test_all_scenarios_scope_literals_and_exact_older_fragment(self):
        template = (run.HERE / 'payload_helpers.sv').read_bytes()
        for name in run.SAFETY_RETRY_CASES:
            plan, contents = definition(name)
            previous, old = definition(name, staged.SEMANTIC_CONFIG['name'])
            fragment = staged.payload_fragment(template, plan['scenario'])
            self.assertEqual(contents[run.CORE_WRAPPER].replace(fragment + b'\n', b'', 1), old[run.CORE_WRAPPER])
            for key in ('goals', 'sources', 'targetBounds', 'initialState', 'dutInitialState', 'assumptions'):
                self.assertEqual(plan[key], previous[key])
            self.assertEqual(len(plan['allAssertions']), len(previous['allAssertions']) + 2)
            self.assertEqual(len(plan['allCovers']), 25)
            self.assertEqual(len(plan['nativeCovers']), 48)
            self.assertEqual(sum(q['timeLimit'] for q in plan['querySchedule']), 960)
            self.assertEqual([q['kind'] for q in plan['querySchedule']], ['metadata', 'payload', *(['hint'] * 6), 'dpc', 'remaining'])
            target, handler = ((12, 256) if plan['scenario'] == 3 else (48, 56))
            self.assertIn(f"dut.dm.operands_data == 32'd{target})".encode(), fragment)
            self.assertIn(f"dut.dm.operands_data == 32'd{handler})".encode(), fragment)
            if plan['scenario'] != 3:
                self.assertNotIn(b"32'd12", fragment)
                self.assertNotIn(b"32'd256", fragment)
                self.assertIn(b"dut.dm.data0 == 32'd44", fragment)
            self.assertEqual(b"32'd291" in fragment, plan['scenario'] == 1)
        self.assertEqual(staged.payload_fragment(template, 3), template)
        self.assertEqual(definition('core-store-safety'), definition('core-dpc-safety'))

    def test_twelve_legacy_cases_and_previous_profiles_are_unchanged(self):
        for name in run.CASES:
            if name not in run.SAFETY_RETRY_CASES:
                self.assertEqual(definition(name), definition(name, staged.SEMANTIC_CONFIG['name']))
        for value in (-1, 4, True, 1.0):
            with self.assertRaises(ValueError):
                staged.payload_parameters(value)
        with self.assertRaises(ValueError):
            staged.payload_fragment((run.HERE / 'payload_helpers.sv').read_bytes() + b' ', 3)

    def test_real_tcl_complete_ten_queries_all_scenarios_and_unknown_helpers(self):
        with tempfile.TemporaryDirectory() as directory:
            for name in run.SAFETY_RETRY_CASES:
                process, records, plan = self.execute(Path(directory) / name, name=name)
                self.assertEqual(process.returncode, 0, process.stderr)
                checked = staged.validate_protocol(records, plan)
                self.assertTrue(checked['caseAccepted'])
                self.assertEqual(records['query8', 'time_limit'], '120')
                self.assertEqual(records['query9', 'iteration_cap'], '352' if plan['scenario'] == 1 else '288')
                self.assertEqual(len({tag for tag, key in records if key == 'native_id' and not tag.startswith('bounded.')}), 22 * len(plan['allAssertions']))
                self.assertEqual(len(records['final_inventory', 'native_covers'].split()), 48)
            for mode, typed in [('new_unknown', True), ('pass', False), ('skip_remaining', True)]:
                process, records, plan = self.execute(Path(directory) / mode, mode=mode, typed=typed)
                self.assertEqual(process.returncode, 0, process.stderr)
                self.assertTrue(staged.validate_protocol(records, plan)['caseAccepted'])
                if mode == 'new_unknown':
                    self.assertEqual(records['query1', 'fact_labels'], '')
                    self.assertEqual(staged.validate_protocol(records, plan)['unboundedHelpers'], [])
                if mode == 'skip_remaining':
                    self.assertEqual(records['query9', 'executed'], '0')

    def test_actual_tcl_bad_cover_inventory_rejects_before_proof(self):
        with tempfile.TemporaryDirectory() as directory:
            for mode in ('missing_cover', 'extra_cover', 'duplicate_cover'):
                process, records, plan = self.execute(Path(directory) / mode, mode)
                self.assertEqual(process.returncode, 1)
                self.assertNotIn(('query0', 'executed'), records)
                self.assertIn(('setup', 'native_covers'), records)
                with self.assertRaises(ValueError):
                    staged.validate_protocol(records, plan)

    def test_actual_after_prove_inventory_is_recorded_and_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            for mode in ('missing_after', 'extra_after', 'duplicate_after'):
                process, records, plan = self.execute(Path(directory) / mode, mode)
                self.assertEqual(process.returncode, 1)
                self.assertEqual(records['query0', 'executed'], '1')
                self.assertIn(('query0.after_inventory', 'native_covers'), records)
                self.assertNotIn(('query1', 'executed'), records)
                with self.assertRaises(ValueError):
                    staged.validate_protocol(records, plan)

    def test_prepare_freezes_payload_and_reconstructs_all_seventeen_cases(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory);paths = []
            for top, contents in zip(('DitDahE2Trigger', 'DitDahE2'), rtl(), strict=True):
                target = root / top;target.mkdir()
                for filename, value in contents.items():
                    (target / filename).write_bytes(value)
                run.write_json(target / 'manifest.json', {'top': top, 'exitStatus': 0,
                    'parameters': {'triggerCount': 2, 'enableDebug': True, 'enableM': True, 'enableC': False, 'protectedMode': False},
                    'rtlHashes': {name: run.sha(value) for name, value in contents.items()}, 'sourceHashes': {}})
                paths.append(target)
            output = root / 'evidence'
            args = argparse.Namespace(unit_rtl=paths[0], core_rtl=paths[1], source_root=root, output=output,
                time_limit=120, core_time_limit=600, proof_seed=None, proof_seed_scenario2=None, proof_seed_scenario3=None,
                multiply_target_base=[], multiply_older_base=[], retry_case=[], flow='staged', staged_configuration=CONFIGURATION)
            run.prepare(args);run.validate_frozen(output)
            self.assertEqual(len(json.loads((output / 'manifest.json').read_text())['cases']), 17)
            for filename in ('payload_helpers.sv', 'collect_payload.tcl'):
                path = output / filename;original = path.read_bytes();path.write_bytes(original + b' ')
                with self.subTest(filename=filename), self.assertRaises(ValueError):
                    run.validate_frozen(output)
                path.write_bytes(original)
            case = output / 'cases/core-older-safety';original = (case / 'plan.json').read_bytes()
            changed = json.loads(original);changed['payloadParameters']['target'] = 48
            run.write_json(case / 'plan.json', changed)
            with self.assertRaises(ValueError):
                run.validate_frozen(output)
            (case / 'plan.json').write_bytes(original)
            run.validate_frozen(output)
            self.assertEqual(hashlib.sha256((case / 'trigger_core_formal.sv').read_bytes()).hexdigest(),
                             hashlib.sha256(definition()[1][run.CORE_WRAPPER]).hexdigest())

    def test_all_inventory_positions_and_raw_arguments_reject_mutants(self):
        with tempfile.TemporaryDirectory() as directory:
            _, records, plan = self.execute(Path(directory) / 'pass')
            positions = ['setup', *(f'query{i}' for i in range(10)), *(f'query{i}.after_inventory' for i in range(10)), 'final_inventory']
            for tag in positions:
                for key in ('native_assertions', 'native_covers'):
                    values = records[tag, key].split()
                    for bad in (' '.join(values[1:]), ' '.join(values + [values[0]]), ' '.join([*values[:-1], 'trigger_core_formal.foreign'])):
                        changed = dict(records);changed[tag, key] = bad
                        with self.subTest(tag=tag, key=key), self.assertRaises(ValueError):
                            staged.validate_protocol(changed, plan)
            for key, value in [(('query0', 'labels'), 'core_setup_exact_command_payload'), (('query1', 'fact_labels'), ''),
                               (('query8', 'time_limit'), '300'), (('query9', 'iteration_cap'), '128'),
                               (('query9', 'first_trace_attempt'), '2'), (('query1.before.core_setup_transaction_payload_metadata', 'max_length'), '99')]:
                changed = dict(records);changed[key] = value
                with self.subTest(key=key), self.assertRaises(ValueError):
                    staged.validate_protocol(changed, plan)
            for field in ('target', 'handler'):
                changed = copy.deepcopy(plan);changed['payloadParameters'][field] = 123
                with self.assertRaises(ValueError):
                    staged.validate_protocol(records, changed)

    def test_every_stage_fatal_error_and_cex_stops_later_queries(self):
        with tempfile.TemporaryDirectory() as directory:
            for index in range(10):
                for prefix in ('tool', 'cex'):
                    process, records, plan = self.execute(Path(directory) / f'{prefix}{index}', f'{prefix}{index}')
                    self.assertEqual(process.returncode, 1)
                    self.assertTrue(all(records[f'query{i}', 'executed'] == '0' for i in range(index + 1, 10)))
                    with self.assertRaises(ValueError):
                        staged.validate_protocol(records, plan)

    def test_resource_dispatch_and_original_zero_bound_are_preserved(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory);plan, _ = definition();run.write_json(root / 'plan.json', plan)
            (root / 'native.tsv').write_text('')
            with patch.object(run, 'collect_case', return_value={}) as collect, patch.object(run, 'check_native_records', return_value={}):
                run.collect_trigger_case(root, 'unused', root, 1800)
            self.assertEqual(collect.call_args.args[-1], 1080)
            self.assertEqual(collect.call_args.kwargs, {'cpu_count': 16})
            process, records, plan = self.execute(root / 'boundzero', 'boundzero')
            self.assertEqual(process.returncode, 1)
            self.assertIn('initial_dpc_zero', staged.validate_protocol(records, plan)['unresolvedOriginals'])
