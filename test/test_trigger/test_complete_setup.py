# SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
# SPDX-License-Identifier: MIT
"""Check stronger setup payloads while retaining original case acceptance."""

import copy
import hashlib
import re
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from formal.trigger import run, staged
from test.test_trigger import test_payload as payload
from test.test_trigger import test_store_state as store


def definition(scenario=0, complete_program=False):
    name = ('core-store-safety', 'core-multiply-safety', 'core-illegal-safety', 'core-older-safety')[scenario]
    config = staged.PROGRAM_COMPLETE_CONFIG if complete_program else staged.STORE_COMPLETE_CONFIG
    return payload.definition(name, config['name'])


class CompleteSetupTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        store.StoreStateTests.setUpClass()
        anchor = '    if {$kind eq "store_state" && $::mode eq "cex_value"} {set ::states(core_store_value_owner_metadata) cex}'
        assert store.StoreStateTests.harness.count(anchor) == 1
        cls.harness = store.StoreStateTests.harness.replace(anchor, anchor + '\n    if {$kind eq "hint" && [lsearch -exact $selected core_complete_target_trap_metadata]>=0 && $::mode eq "cex_complete_state"} {set ::states(core_complete_target_trap_metadata) cex}', 1)
        complete_unknown = '    if {$kind eq "hint" && [lsearch -exact $selected core_complete_target_trap_metadata]>=0 && $::mode eq "complete_state_unknown"} {set ::states(core_complete_target_trap_metadata) unknown;set ::lengths(core_complete_target_trap_metadata) 1}\n'
        complete_anchor = '    if {$::mode eq "all_finite"} {'
        assert cls.harness.count(complete_anchor) == 1
        cls.harness = cls.harness.replace(complete_anchor, complete_unknown + complete_anchor, 1)
        phase_modes = """    if {$kind eq "store_state" && $::mode in {phase_unknown phase_cex5 phase_tool5}} {
        set ::states(core_store_configuration_history) unknown
        set ::lengths(core_store_configuration_history) 1
    }
    if {$kind eq "hint" && [lsearch -exact $selected core_store_configuration_history]>=0} {
        if {$::mode eq "phase_unknown"} {
            set ::states(core_store_configuration_history) unknown
            set ::lengths(core_store_configuration_history) 1
        }
        if {$::mode eq "phase_cex5"} {set ::states(core_store_configuration_history) cex}
        if {$::mode eq "epc_cex5"} {set ::states(native_epc_metadata) cex}
        if {$::mode eq "cause_cex5"} {set ::states(native_cause_metadata) cex}
        if {$::mode eq "event_finite"} {
            foreach label {native_epc_metadata native_cause_metadata} {
                set ::states($label) undetermined;set ::lengths($label) $::original_bounds($label);set ::winners($label) Mp
            }
        }
        if {$::mode eq "phase_tool5"} {error "mock phase proof error"}
    }
"""
        phase_anchor = '    if {$::mode eq "all_finite"} {'
        assert cls.harness.count(phase_anchor) == 1
        cls.harness = cls.harness.replace(phase_anchor, phase_modes + phase_anchor, 1)
        tail_modes = """    if {$::mode in {late_fresh cex10 tool10}} {
        if {$index < 9} {
            foreach label $selected {
                if {$label in $::original_goals && $::original_bounds($label) > 0} {
                    set ::states($label) unknown;set ::lengths($label) 1
                }
            }
        }
        if {$index == 9} {
            foreach label $selected {set ::states($label) unknown;set ::lengths($label) 1}
            foreach label {target_first_event_is_breakpoint abstract_dpc_value resume_pc_matches} {
                if {$label ni $selected} {error "late proof property was not pending"}
                set ::states($label) proven;set ::lengths($label) infinite
            }
            set ::states(native_epc_metadata) undetermined
            set ::lengths(native_epc_metadata) $::original_bounds(native_epc_metadata)
        }
        if {$kind eq "event_joint"} {foreach label $selected {set ::winners($label) Mp}}
    }
"""
        assert cls.harness.count(phase_anchor) == 1
        cls.harness = cls.harness.replace(phase_anchor, tail_modes + phase_anchor, 1)


    def execute(self, root, scenario=0, mode='pass', typed=True):
        root.mkdir()
        plan, contents = definition(scenario, complete_program=scenario != 0)
        for name, value in contents.items():
            (root / name).write_bytes(value)
        (root / 'harness.tcl').write_text(f'set expected_reset {{{run.EXPECTED_RESET}}}\nset mode {mode}\nset typed {int(typed)}\nset proof_calls 0\nset import_mode auto\n' + self.harness)
        process = subprocess.run(['tclsh', 'harness.tcl'], cwd=root, capture_output=True, text=True, check=False)
        return process, run.read_records(root / 'native.tsv'), plan

    def test_precise_case_routing_and_original_body_projection(self):
        extra = (run.HERE / 'complete_setup_helpers.sv').read_bytes()
        state = (run.HERE / 'complete_state_helpers.sv').read_bytes()
        for complete_program, config in ((False, staged.STORE_COMPLETE_CONFIG), (True, staged.PROGRAM_COMPLETE_CONFIG)):
            for name in run.CASES:
                plan, contents = payload.definition(name, config['name'])
                old_config = staged.PROGRAM_STATE_CONFIG if complete_program else staged.STORE_STATE_CONFIG
                previous, old = payload.definition(name, old_config['name'])
                changed = name in ('core-store-safety', 'core-dpc-safety') or complete_program and name in ('core-multiply-safety', 'core-illegal-safety')
                if not changed:
                    self.assertEqual((plan, contents), (previous, old))
                    continue
                original = staged.payload_fragment((run.HERE / 'payload_helpers.sv').read_bytes(), plan['scenario'])
                strengthened = staged.complete_payload_fragment(plan['scenario'], extra)
                compiled = staged.complete_protocol_fragment(state, (run.HERE / 'complete_protocol_helpers.sv').read_bytes(), plan["scenario"]) if plan["scenario"] in (0, 2) else state
                if plan["scenario"] == 0:
                    compiled = staged.complete_cluster_fragment(compiled, (run.HERE / 'complete_cluster_helpers.sv').read_bytes())
                if plan["scenario"] == 1:
                    compiled = staged.complete_multiply_fragment(compiled, (run.HERE / 'complete_multiply_helpers.sv').read_bytes())
                if plan["scenario"] == 2:
                    compiled = staged.complete_illegal_fragment(compiled, (run.HERE / 'complete_illegal_helpers.sv').read_bytes())
                projected = contents[run.CORE_WRAPPER].replace(compiled + b'\n', b'', 1).replace(strengthened, original, 1)
                self.assertEqual(projected, old[run.CORE_WRAPPER])
                self.assertEqual([n for n in plan['inputs'] if contents[n] != old[n]], ['plan.tcl', run.CORE_WRAPPER])
                for field in ('goals', 'sources', 'targetBounds', 'initialState', 'dutInitialState', 'assumptions', 'payloadParameters', 'nativeCovers'):
                    self.assertEqual(plan[field], previous[field])
        self.assertEqual(definition(), definition(complete_program=True))
        self.assertEqual(payload.definition('core-store-safety', staged.STORE_COMPLETE_CONFIG['name']), payload.definition('core-dpc-safety', staged.STORE_COMPLETE_CONFIG['name']))

    def test_old_three_payload_conjuncts_metadata_and_guard_covers_are_exact(self):
        extra = (run.HERE / 'complete_setup_helpers.sv').read_bytes()
        for scenario in (0, 1, 2):
            original = staged.payload_fragment((run.HERE / 'payload_helpers.sv').read_bytes(), scenario)
            strengthened = staged.complete_payload_fragment(scenario, extra)
            before = re.search(rb'core_setup_exact_command_payload: assert\((.*?)\);', original, re.DOTALL)
            after = re.search(rb'core_setup_exact_command_payload: assert\((.*?)\);', strengthened, re.DOTALL)
            self.assertEqual(after[1], before[1] + b' &&\n        k_complete_extra_payload')
            for pattern in (rb'core_setup_transaction_payload_metadata: assert\((.*?)\);', rb'cover_setup_guard_07a2: cover\((.*?)\);', rb'cover_setup_guard_07a1: cover\((.*?)\);', rb'cover_setup_guard_0305: cover\((.*?)\);'):
                self.assertEqual(re.search(pattern, original, re.DOTALL)[0], re.search(pattern, strengthened, re.DOTALL)[0])
        self.assertIn(b"scenario == 2'd1 && dut.dm.commandValid", extra)
        self.assertIn(b"operands_data == 32'd8", extra)
        self.assertIn(b"operands_data == 32'd44", extra)
        self.assertIn(b"operands_data == 32'd291", extra)
        with self.assertRaises(ValueError):
            staged.complete_payload_fragment(3, extra)

    def test_pc_and_controller_joint_remains_one_read_only_helper(self):
        fragment = (run.HERE / 'complete_state_helpers.sv').read_bytes()
        self.assertEqual(re.findall(rb"\b(\w+)\s*:\s*assert\s*\(", fragment),
                         [b'core_complete_target_trap_metadata'])
        self.assertFalse(re.search(rb"\b(reg|initial|assume|force|input|output|inout|cover)\b", fragment))
        self.assertEqual(re.findall(rb"dut\.([A-Za-z_][\w.]*)\[([0-9:]+)\]", fragment), [
            (b'x_pc', b'1:0'), (b'm_instruction_pc', b'1:0'), (b'architecturalPc', b'1:0'),
            (b'_debug_core_resumePc', b'1:0'), (b'csr.mepc', b'1:0'), (b'debug.breakPc', b'1:0')])
        self.assertIn(b"(!dut.xValid || dut.x_pc[1:0] == 2'b00)", fragment)
        self.assertIn(b"(!dut.mValid || dut.m_instruction_pc[1:0] == 2'b00)", fragment)
        self.assertIn(b"(!(dut.debug.stopping && dut.debug.stopCause == 3'd1) ||", fragment)
        self.assertIn(b'(dmi_pending == dut.dm.responding)', fragment)
        self.assertIn(b'(!dut.dm.busy || dut.dm.needsHart)', fragment)
        self.assertIn(b'(reset || !initialized || !target_trap || dmi_phase >= execution_phase)', fragment)
        self.assertIn(b'(past_valid && !past_reset && !systemReset)', fragment)
        self.assertIn(b"(reset || !initialized || (dmi_phase == 5'd0 && !dmi_pending) ||", fragment)
        for scenario in (0, 1, 2):
            plan, contents = definition(scenario, scenario != 0)
            compiled = staged.complete_protocol_fragment(fragment, (run.HERE / 'complete_protocol_helpers.sv').read_bytes(), scenario) if scenario in (0, 2) else fragment
            if scenario == 0:
                compiled = staged.complete_cluster_fragment(compiled, (run.HERE / 'complete_cluster_helpers.sv').read_bytes())
            if scenario == 1:
                compiled = staged.complete_multiply_fragment(compiled, (run.HERE / 'complete_multiply_helpers.sv').read_bytes())
            if scenario == 2:
                compiled = staged.complete_illegal_fragment(compiled, (run.HERE / 'complete_illegal_helpers.sv').read_bytes())
            self.assertEqual(contents[run.CORE_WRAPPER].count(compiled), 1)
            self.assertEqual(contents[run.CORE_WRAPPER].count(b"wire core_setup_protocol_consistent"), 1)
            for name in (b'core_pre_target_ok', b'core_post_target_ok'):
                self.assertEqual(contents[run.CORE_WRAPPER].count(b'wire ' + name + b' ='), 1)
            self.assertEqual(plan['allAssertions'].count(staged.COMPLETE_STATE_HELPER), 1)
            self.assertEqual(len(plan['nativeCovers']), 48)

    def test_illegal_state_is_single_read_only_assertion_with_actual_handler_order(self):
        state = staged.complete_protocol_fragment((run.HERE / 'complete_state_helpers.sv').read_bytes(),
                                                 (run.HERE / 'complete_protocol_helpers.sv').read_bytes(), 2)
        extra = (run.HERE / 'complete_illegal_helpers.sv').read_bytes()
        self.assertIn('complete_illegal_helpers.sv', staged.FILES)
        self.assertEqual(hashlib.sha256(extra).hexdigest(), staged.COMPLETE_ILLEGAL_SHA256)
        compiled = staged.complete_illegal_fragment(state, extra)
        self.assertEqual(re.findall(rb'\b(\w+)\s*:\s*assert\s*\(', compiled), [staged.COMPLETE_STATE_HELPER.encode()])
        self.assertEqual(compiled.count(b'always @(posedge clock)'), 1)
        self.assertFalse(re.search(rb'\b(reg|logic|initial|assume|force|input|output|inout|cover)\b', compiled))
        self.assertIn(b"dut.m_instruction_word == 32'h00438393", extra)
        self.assertIn(b"dut.m_value == 32'd52", extra)
        self.assertIn(b"dut.m_csrOperand == 32'd52", extra)
        self.assertIn(b"dut.m_instruction_pc == 32'd112 && dut.m_mret", extra)
        self.assertIn(b"dut.architecturalPc == 32'd52", extra)
        for unwanted in (b'normal_retry_', b'core_older_history_', b'wire store_phase_', b'registers_4', b"32'd291"):
            self.assertNotIn(unwanted, extra)
        self.assertFalse(re.search(rb'\bdut\.debug\.(core_resume|core_resumePc|dpc)\b', extra))
        self.assertEqual(b'dut.debug.cancelInjection' in extra,
                         staged.PROGRAM_COMPLETE_CONFIG['name'].startswith('injection-'))
        for scenario in (0, 1, 2):
            plan, contents = definition(scenario, scenario != 0)
            self.assertEqual(contents[run.CORE_WRAPPER].count(b'wire core_complete_illegal_consistent ='), int(scenario == 2))
            self.assertEqual(plan['targetBounds'], staged.declared_bounds(scenario))
            self.assertEqual(len(plan['querySchedule']), 11 if scenario == 0 else 10)
        with self.assertRaises(ValueError):
            staged.complete_illegal_fragment(state + b' ', extra)

    def test_illegal_state_rejects_registered_mutation_state_drivers_and_missing_components(self):
        state = staged.complete_protocol_fragment((run.HERE / 'complete_state_helpers.sv').read_bytes(),
                                                 (run.HERE / 'complete_protocol_helpers.sv').read_bytes(), 2)
        path = run.HERE / 'complete_illegal_helpers.sv'
        extra = path.read_bytes()
        with self.assertRaises(ValueError):
            staged.complete_illegal_fragment(state, extra + b' ')
        original = Path.read_bytes
        additions = [b'reg hidden_state;', b'logic hidden_state;', b'initial hidden_state = 0;',
                     b'always @* hidden_state = 0;', b'assign dut.xValid = 0;', b'assume(1);',
                     b'force dut.xValid = 0;', b'input hidden_input;', b'output hidden_output;',
                     b'module hidden; endmodule', b'wire hidden_any = $anyseq;', b'wire reset = 1;',
                     b'wire k_complete_extra_payload = 1;', b'wire core_complete_illegal_consistent = 1;']
        mutations = [extra + b'\n' + item + b'\n' for item in additions]
        required = (b'last_resume_ok', b'handler_first_pending_trap', b'handler_snapshot',
                    b'handler_pipeline_owner', b'handler_r7_owner', b'sc2_program_history')
        for name in required:
            changed, count = re.subn(rb'wire\s+' + name + rb'\s*=.*?;\n', b'', extra, count=1, flags=re.DOTALL)
            self.assertEqual(count, 1)
            mutations.append(changed)
        mutations.append(extra.replace(b' && (last_resume_ok)', b'', 1))
        for changed in mutations:
            def reader(candidate, content=changed):
                return content if candidate == path else original(candidate)
            with self.subTest(changed=hashlib.sha256(changed).hexdigest()), \
                    mock.patch.object(staged, 'COMPLETE_ILLEGAL_SHA256', hashlib.sha256(changed).hexdigest()), \
                    mock.patch.object(Path, 'read_bytes', reader), self.assertRaises(ValueError):
                definition(2, True)

    def test_multiply_state_is_single_read_only_assertion_with_actual_six_command_setup(self):
        state = (run.HERE / 'complete_state_helpers.sv').read_bytes()
        extra = (run.HERE / 'complete_multiply_helpers.sv').read_bytes()
        self.assertIn('complete_multiply_helpers.sv', staged.FILES)
        self.assertEqual(hashlib.sha256(extra).hexdigest(), staged.COMPLETE_MULTIPLY_SHA256)
        compiled = staged.complete_multiply_fragment(state, extra)
        self.assertEqual(re.findall(rb'\b(\w+)\s*:\s*assert\s*\(', compiled), [staged.COMPLETE_STATE_HELPER.encode()])
        self.assertEqual(compiled.count(b'always @(posedge clock)'), 1)
        self.assertFalse(re.search(rb'\b(reg|logic|initial|assume|force|input|output|inout|cover)\b', compiled))
        self.assertIn(b"16'h1006", extra)
        self.assertIn(b"dut.registers_4 == 32'd291", extra)
        self.assertIn(b"dmi_phase == 5'd22 && dmi_pending", extra)
        self.assertIn(b"dmi_phase == 5'd25", extra)
        self.assertIn(b'reset || !initialized || dmi_phase < execution_phase || core_older_history_ok', extra)
        self.assertNotIn(b'wire store_phase_', extra)
        self.assertFalse(re.search(rb'\bdut\.debug\.(core_resume|core_resumePc|dpc)\b', extra))
        self.assertEqual(b'dut.debug.cancelInjection' in extra, staged.PROGRAM_COMPLETE_CONFIG['name'].startswith('injection-'))
        for scenario in (0, 1, 2):
            plan, contents = definition(scenario, scenario != 0)
            self.assertEqual(contents[run.CORE_WRAPPER].count(b'wire core_complete_multiply_consistent ='), int(scenario == 1))
            self.assertEqual(plan['targetBounds'], staged.declared_bounds(scenario))
            self.assertEqual(len(plan['querySchedule']), 11 if scenario == 0 else 10)
        with self.assertRaises(ValueError):
            staged.complete_multiply_fragment(state + b' ', extra)

    def test_multiply_state_rejects_registered_mutation_state_drivers_and_missing_components(self):
        state = (run.HERE / 'complete_state_helpers.sv').read_bytes()
        path = run.HERE / 'complete_multiply_helpers.sv'
        extra = path.read_bytes()
        with self.assertRaises(ValueError):
            staged.complete_multiply_fragment(state, extra + b' ')
        original = Path.read_bytes
        additions = [b'reg hidden_state;', b'logic hidden_state;', b'initial hidden_state = 0;',
                     b'always @* hidden_state = 0;', b'assign dut.xValid = 0;', b'assume(1);',
                     b'force dut.xValid = 0;', b'input hidden_input;', b'output hidden_output;',
                     b'module hidden; endmodule', b'wire hidden_any = $anyseq;', b'wire reset = 1;',
                     b'wire k_complete_extra_payload = 1;', b'wire core_complete_multiply_consistent = 1;']
        mutations = [extra + b'\n' + item + b'\n' for item in additions]
        for name in (b'core_setup_protocol_consistent', b'last_resume_ok', b'handler_program_history', b'normal_retry_ok', b'core_older_history_ok'):
            changed, count = re.subn(rb'wire\s+' + name + rb'\s*=.*?;\n', b'', extra, count=1, flags=re.DOTALL)
            self.assertEqual(count, 1)
            mutations.append(changed)
        mutations.append(extra.replace(b"scenario == 2'd3 ||", b"scenario == 2'd3 || 1 ||", 1))
        for changed in mutations:
            def reader(candidate, content=changed):
                return content if candidate == path else original(candidate)
            with self.subTest(changed=hashlib.sha256(changed).hexdigest()), \
                    mock.patch.object(staged, 'COMPLETE_MULTIPLY_SHA256', hashlib.sha256(changed).hexdigest()), \
                    mock.patch.object(Path, 'read_bytes', reader), self.assertRaises(ValueError):
                definition(1, True)

    def test_cluster_is_one_read_only_sc0_assertion_with_guarded_older_history(self):
        state = (run.HERE / 'complete_state_helpers.sv').read_bytes()
        protocol = (run.HERE / 'complete_protocol_helpers.sv').read_bytes()
        cluster = (run.HERE / 'complete_cluster_helpers.sv').read_bytes()
        self.assertIn('complete_cluster_helpers.sv', staged.FILES)
        self.assertEqual(hashlib.sha256(cluster).hexdigest(), staged.COMPLETE_CLUSTER_SHA256)
        sigma = staged.complete_protocol_fragment(state, protocol, 0)
        combined = staged.complete_cluster_fragment(sigma, cluster)
        self.assertEqual(re.findall(rb'\b(\w+)\s*:\s*assert\s*\(', combined),
                         [staged.COMPLETE_STATE_HELPER.encode()])
        self.assertEqual(combined.count(b'always @(posedge clock)'), 1)
        self.assertFalse(re.search(rb'\b(reg|logic|initial|assume|force|input|output|inout|cover)\b', combined))
        self.assertIn(b'reset || !initialized || dmi_phase < execution_phase || core_older_history_ok', cluster)
        self.assertIn(b'dut.registers_5', cluster)
        self.assertIn(b'handler_mret_forward_metadata', cluster)
        self.assertFalse(re.search(rb'\bdut\.debug\.(core_resume|core_resumePc|dpc)\b', cluster))
        self.assertEqual(b'dut.debug.cancelInjection' in cluster,
                         staged.PROGRAM_COMPLETE_CONFIG['name'].startswith('injection-'))
        for scenario in (0, 1, 2):
            plan, contents = definition(scenario, scenario != 0)
            self.assertEqual(contents[run.CORE_WRAPPER].count(b'wire core_complete_cluster_consistent ='), int(scenario == 0))
            self.assertEqual(plan['targetBounds'], staged.declared_bounds(scenario))
        with self.assertRaises(ValueError):
            staged.complete_cluster_fragment(sigma + b' ', cluster)

    def test_cluster_rejects_registered_state_drivers_collisions_and_missing_components(self):
        state = staged.complete_protocol_fragment((run.HERE / 'complete_state_helpers.sv').read_bytes(),
                                                 (run.HERE / 'complete_protocol_helpers.sv').read_bytes(), 0)
        path = run.HERE / 'complete_cluster_helpers.sv'
        cluster = path.read_bytes()
        with self.assertRaises(ValueError):
            staged.complete_cluster_fragment(state, cluster + b' ')
        original = Path.read_bytes
        additions = [b'reg hidden_state;', b'logic hidden_state;', b'initial hidden_state = 0;',
                     b'always @* hidden_state = 0;', b'assign dut.xValid = 0;', b'assume(1);',
                     b'force dut.xValid = 0;', b'input hidden_input;', b'output hidden_output;',
                     b'module hidden; endmodule', b'wire hidden_any = $anyseq;',
                     b'wire reset = 1;', b'wire k_complete_extra_payload = 1;',
                     b'wire core_complete_cluster_consistent = 1;']
        mutations = [cluster + b'\n' + addition + b'\n' for addition in additions]
        for name in (b'core_cluster_handler', b'core_cluster_retry', b'core_cluster_older'):
            changed, count = re.subn(rb'wire\s+' + name + rb'\s*=.*?;\n', b'', cluster, count=1, flags=re.DOTALL)
            self.assertEqual(count, 1)
            mutations.append(changed)
        mutations.append(cluster.replace(b'core_cluster_handler && core_cluster_retry && core_cluster_older', b'core_cluster_handler && core_cluster_older'))
        for changed in mutations:
            def reader(candidate, content=changed):
                return content if candidate == path else original(candidate)
            with self.subTest(changed=hashlib.sha256(changed).hexdigest()), \
                    mock.patch.object(staged, 'COMPLETE_CLUSTER_SHA256', hashlib.sha256(changed).hexdigest()), \
                    mock.patch.object(Path, 'read_bytes', reader), self.assertRaises(ValueError):
                definition()

    def test_scene2_protocol_composes_existing_phase_wires_without_state_or_new_labels(self):
        state = (run.HERE / 'complete_state_helpers.sv').read_bytes()
        protocol = (run.HERE / 'complete_protocol_helpers.sv').read_bytes()
        self.assertEqual(staged.complete_protocol_fragment(state, protocol),
                         staged.complete_protocol_fragment(state, protocol, 0))
        for scenario in (False, True, 1, 3, -1, '2', 2.0, None):
            with self.subTest(scenario=scenario), self.assertRaises(ValueError):
                staged.complete_protocol_fragment(state, protocol, scenario)
        plan, contents = definition(2, complete_program=True)
        wrapper = contents[run.CORE_WRAPPER]
        compiled = staged.complete_protocol_fragment(state, protocol, 2)
        compiled = staged.complete_illegal_fragment(compiled, (run.HERE / 'complete_illegal_helpers.sv').read_bytes())
        self.assertEqual(wrapper.count(compiled), 1)
        self.assertIn(b"scenario != 2'd2 || ((", compiled)
        self.assertIn(b"&& core_setup_protocol_consistent && (!program_selected_scene ||", compiled)
        for name in ('program_selected_scene', 'program_phase_configuration',
                     'program_first_target_armed', 'program_retry_trigger_disabled',
                     'program_phase_clock_ready'):
            self.assertEqual(len(re.findall(rb'\bwire\s+' + name.encode() + rb'\s*=', wrapper)), 1)
            self.assertNotIn(b'wire ' + name.encode() + b' =', compiled)
        self.assertEqual(re.findall(rb'\b(\w+)\s*:\s*assert\s*\(', compiled),
                         [staged.COMPLETE_STATE_HELPER.encode()])
        self.assertFalse(re.search(rb'\b(reg|initial|assume|force|input|output|inout|cover)\b', compiled))
        self.assertEqual(len(plan['goals']), 21)
        self.assertEqual(len(plan['nativeCovers']), 48)
        self.assertEqual(len(plan['querySchedule']), 10)
        self.assertEqual(plan['targetBounds'], staged.declared_bounds(2))

    def test_protocol_purity_dependency_and_real_wrapper_collisions(self):
        state = (run.HERE / 'complete_state_helpers.sv').read_bytes()
        protocol_path = run.HERE / 'complete_protocol_helpers.sv'
        protocol = protocol_path.read_bytes()
        self.assertIn('complete_protocol_helpers.sv', staged.FILES)
        self.assertEqual(hashlib.sha256(protocol).hexdigest(), staged.COMPLETE_PROTOCOL_SHA256)
        self.assertIn(b'core_pre_target_ok && core_post_target_ok', protocol)
        for removed in (b'core_pre_target_ok && ', b' && core_post_target_ok'):
            with self.subTest(removed=removed), self.assertRaises(ValueError):
                staged.complete_protocol_fragment(state, protocol.replace(removed, b'', 1))
        with self.assertRaises(ValueError):
            staged.complete_protocol_fragment(state, protocol + b'// changed input\n')
        mutations = [
            b"reg protocol_state;", b"logic protocol_state;", b"initial protocol_state = 0;",
            b"always @* protocol_state = 0;", b"assume(1);", b"force protocol_state = 0;",
            b"input protocol_input;", b"output protocol_output;", b"inout protocol_port;",
            b"protocol_assert: assert(1);", b"protocol_cover: cover(1);", b"module other; endmodule",
            b"wire protocol_free = $anyseq;", b"wire core_setup_protocol_consistent = 1'b1;",
            b"wire core_target_breakpoint_has_armed_owner = 1'b1;",
            b"wire k_complete_extra_payload = 1'b1;", b"wire reset = 1'b1;",
        ]
        original_read = Path.read_bytes
        for addition in mutations:
            changed = protocol + b'\n' + addition + b'\n'
            def reader(path, content=changed):
                return content if path == protocol_path else original_read(path)
            with self.subTest(addition=addition), \
                    mock.patch.object(staged, 'COMPLETE_PROTOCOL_SHA256', hashlib.sha256(changed).hexdigest()), \
                    mock.patch.object(Path, 'read_bytes', reader), self.assertRaises(ValueError):
                definition()

    def test_unchanged_payload_query_budget_and_only_one_new_state_assertion(self):
        for scenario in (0, 1, 2):
            plan, _ = definition(scenario, scenario != 0)
            old, _ = payload.definition(('core-store-safety', 'core-multiply-safety', 'core-illegal-safety')[scenario], (staged.STORE_STATE_CONFIG if scenario == 0 else staged.PROGRAM_STATE_CONFIG)['name'])
            self.assertEqual(plan['querySchedule'][:2], old['querySchedule'][:2])
            self.assertEqual(plan['querySchedule'][1]['labels'], ['core_setup_exact_command_payload'])
            self.assertEqual(plan['querySchedule'][1]['timeLimit'], 300)
            unchanged = (0, 1, 4, 6, 7, 8) if scenario == 0 else (0, 1, *range(4, len(plan['querySchedule'])))
            for index in unchanged:
                self.assertEqual(plan['querySchedule'][index], old['querySchedule'][index])
            if scenario == 0:
                self.assertEqual((plan['querySchedule'][2]['timeLimit'], plan['querySchedule'][2]['propertyGuard']), (50, 3200))
                self.assertEqual(plan['querySchedule'][5], {
                    'tag': 'query5', 'kind': 'hint', 'labels': ['core_store_configuration_history', 'native_epc_metadata', 'native_cause_metadata'],
                    'engines': ['Mp', 'N', 'Hp'], 'jobs': 4, 'timeLimit': 60,
                    'propertyGuard': 5760, 'withProven': True})
            else:
                self.assertEqual((plan['querySchedule'][2]['timeLimit'], plan['querySchedule'][2]['propertyGuard']), (100, 6400))
            if scenario == 0:
                self.assertEqual(plan['querySchedule'][9], {**old['querySchedule'][9], 'timeLimit': 180})
                self.assertEqual(plan['querySchedule'][10], {**old['querySchedule'][9], 'tag': 'query10', 'timeLimit': 180})
            self.assertEqual(plan['querySchedule'][2]['labels'], old['querySchedule'][2]['labels'])
            self.assertEqual(plan['querySchedule'][3], {**old['querySchedule'][3],
                'labels': [staged.COMPLETE_STATE_HELPER, *old['querySchedule'][3]['labels']],
                'timeLimit': 30, 'propertyGuard': 2880, 'engines': ['Mp', 'N', 'Hp'], 'jobs': 4})
            self.assertEqual(plan['allAssertions'], [*old['allAssertions'], staged.COMPLETE_STATE_HELPER])
            self.assertEqual((len(plan['querySchedule']), plan['maximumSearchSeconds'], plan['outerTimeoutSeconds'], plan['cpuCount']), (11 if scenario == 0 else 10, 960, 1080, 16))
            self.assertEqual((len(plan['goals']), len(plan['nativeCovers'])), (21, 48))

    def test_real_tcl_fresh_infinite_facts_and_unknown_payload_has_no_barrier(self):
        with tempfile.TemporaryDirectory() as directory:
            for scenario in (0, 1, 2):
                for mode, typed in (('pass', True), ('pass', False), ('new_unknown', True)):
                    process, records, plan = self.execute(Path(directory) / f'{scenario}-{mode}-{typed}', scenario, mode, typed)
                    self.assertEqual(process.returncode, 0, process.stderr)
                    result = staged.validate_protocol(records, plan)
                    self.assertTrue(result['caseAccepted'])
                    self.assertEqual(len({tag for tag, key in records if key == 'native_id' and not tag.startswith('bounded.')}), (2 + 2 * len(plan['querySchedule'])) * len(plan['allAssertions']))
                    self.assertNotIn(staged.COMPLETE_STATE_HELPER, records['query3', 'fact_labels'].split())
                    self.assertIn(staged.COMPLETE_STATE_HELPER, records['query4', 'fact_labels'].split())
                    if mode == 'new_unknown':
                        self.assertNotIn('core_setup_exact_command_payload', records['query2', 'fact_labels'].split())
                    else:
                        self.assertIn('core_setup_exact_command_payload', records['query2', 'fact_labels'].split())

    def test_real_tcl_q3_dependency_order_and_unknown_helper_has_no_barrier(self):
        with tempfile.TemporaryDirectory() as directory:
            for mode in ('pass', 'complete_state_unknown', 'state_unknown'):
                for typed in (True, False):
                    process, records, plan = self.execute(Path(directory) / f'{mode}-{typed}', mode=mode, typed=typed)
                    self.assertEqual(process.returncode, 0, process.stderr)
                    self.assertTrue(staged.validate_protocol(records, plan)['caseAccepted'])
                    self.assertEqual(records['query2', 'labels'].split(), list(staged.STORE_STATE_HELPERS))
                    self.assertEqual(records['query3', 'labels'].split(), [staged.COMPLETE_STATE_HELPER, 'initial_dpc_zero'])
                    self.assertEqual(records['query3', 'engines'], 'Mp N Hp')
                    self.assertEqual(records['query3', 'time_limit'], '30')
                    self.assertEqual(records['query3', 'per_property_time_limit'], '2880')
                    self.assertEqual(records['query3', 'per_engine_max_jobs'], '4')
                    self.assertNotIn(staged.COMPLETE_STATE_HELPER, records['query2', 'fact_labels'].split())
                    self.assertNotIn(staged.COMPLETE_STATE_HELPER, records['query3', 'fact_labels'].split())
                    for label in staged.STORE_STATE_HELPERS:
                        self.assertEqual(label in records['query3', 'fact_labels'].split(), mode != 'state_unknown')
                    if mode == 'complete_state_unknown':
                        for index in range(4, len(plan['querySchedule'])):
                            self.assertNotIn(staged.COMPLETE_STATE_HELPER, records[f'query{index}', 'fact_labels'].split())
                    else:
                        self.assertIn(staged.COMPLETE_STATE_HELPER, records['query4', 'fact_labels'].split())
                    for key, value in ((('query3', 'engines'), 'N C I'),
                                       (('query3', 'per_engine_max_jobs'), '2'),
                                       (('query3', 'time_limit'), '10'),
                                       (('query3', 'per_property_time_limit'), '960'),
                                       (('query3', 'labels'), 'initial_dpc_zero ' + staged.COMPLETE_STATE_HELPER)):
                        mutated = dict(records)
                        mutated[key] = value
                        with self.subTest(mode=mode, key=key), self.assertRaises(ValueError):
                            staged.validate_protocol(mutated, plan)

    def test_payload_or_new_state_counterexample_stops_future_queries(self):
        with tempfile.TemporaryDirectory() as directory:
            for mode in ('cex1', 'tool1', 'cex_complete_state', 'tool2', 'tool3'):
                process, records, plan = self.execute(Path(directory) / mode, mode=mode)
                self.assertEqual(process.returncode, 1)
                self.assertEqual(records['query3', 'executed'], '1' if mode in ('cex_complete_state', 'tool3') else '0')
                self.assertEqual(records['query4', 'executed'], '0')
                self.assertEqual(records['query9', 'executed'], '0')
                self.assertIn(('final_inventory', 'native_assertions'), records)
                with self.assertRaises(ValueError):
                    staged.validate_protocol(records, plan)

    def test_real_tcl_phase_retry_and_unknown_phase_do_not_change_acceptance(self):
        with tempfile.TemporaryDirectory() as directory:
            for mode in ('pass', 'phase_unknown', 'skip_remaining'):
                for typed in (True, False):
                    process, records, plan = self.execute(Path(directory) / f'{mode}-{typed}', mode=mode, typed=typed)
                    self.assertEqual(process.returncode, 0, process.stderr)
                    result = staged.validate_protocol(records, plan)
                    self.assertTrue(result['caseAccepted'])
                    self.assertEqual(records['query2', 'time_limit'], '50')
                    self.assertEqual(records['query2', 'per_property_time_limit'], '3200')
                    self.assertEqual(records['query5', 'labels'].split(), ['core_store_configuration_history', 'native_epc_metadata', 'native_cause_metadata'])
                    self.assertEqual(records['query5', 'engines'], 'Mp N Hp')
                    self.assertEqual(records['query5', 'time_limit'], '60')
                    self.assertEqual(records['query5', 'per_property_time_limit'], '5760')
                    self.assertEqual(records['query5', 'per_engine_max_jobs'], '4')
                    self.assertEqual(records['query6', 'labels'].split(), ['native_tval_metadata', 'native_control_metadata', 'native_hit_metadata'])
                    if mode != 'skip_remaining':
                        for label in ('native_epc_metadata', 'native_cause_metadata'):
                            self.assertNotIn(label, records['query5', 'fact_labels'].split())
                            self.assertIn(label, records['query6', 'fact_labels'].split())
                    self.assertEqual(records['run', 'allocated_search_seconds'], '600' if mode == 'skip_remaining' else '780')
                    if mode == 'skip_remaining':
                        self.assertEqual(records['query9', 'executed'], '0')
                        self.assertEqual(records['query9', 'labels'], '')
                    if mode == 'pass':
                        self.assertIn('core_store_configuration_history', records['query5', 'fact_labels'].split())
                    if mode == 'phase_unknown':
                        self.assertNotIn('core_store_configuration_history', result['unboundedHelpers'])
                        for index in range(3, len(plan['querySchedule'])):
                            self.assertNotIn('core_store_configuration_history', records[f'query{index}', 'fact_labels'].split())
                    for labels in ('core_store_configuration_history',
                                   'native_epc_metadata core_store_configuration_history native_cause_metadata',
                                   records['query5', 'labels'] + ' native_hit_metadata',
                                   records['query5', 'labels'] + ' native_epc_metadata'):
                        changed = dict(records)
                        changed['query5', 'labels'] = labels
                        with self.subTest(labels=labels), self.assertRaises(ValueError):
                            staged.validate_protocol(changed, plan)
                    for key in (('query2', 'time_limit'), ('query5', 'time_limit'), ('query5', 'labels'), ('query5', 'engines'), ('query5', 'per_engine_max_jobs')):
                        changed = dict(records)
                        changed[key] = {'time_limit': '120', 'labels': '', 'engines': 'N C I', 'per_engine_max_jobs': '2'}[key[1]]
                        with self.subTest(key=key), self.assertRaises(ValueError):
                            staged.validate_protocol(changed, plan)

    def test_phase_retry_counterexample_or_tool_error_stops_later_queries(self):
        with tempfile.TemporaryDirectory() as directory:
            for mode in ('phase_cex5', 'phase_tool5', 'epc_cex5', 'cause_cex5'):
                process, records, plan = self.execute(Path(directory) / mode, mode=mode)
                self.assertEqual(process.returncode, 1)
                self.assertEqual(records['query5', 'executed'], '1')
                self.assertEqual(records['query6', 'executed'], '0')
                self.assertEqual(records['query9', 'executed'], '0')
                with self.assertRaises(ValueError):
                    staged.validate_protocol(records, plan)

    def test_original_own_bound_qualification_and_zero_infinity_are_unchanged(self):
        with tempfile.TemporaryDirectory() as directory:
            for scenario in (0, 1, 2):
                process, records, plan = self.execute(Path(directory) / f'{scenario}-finite', scenario, 'event_finite')
                self.assertEqual(process.returncode, 0, process.stderr)
                self.assertTrue(staged.validate_protocol(records, plan)['caseAccepted'])
                if scenario == 0:
                    for label in ('native_epc_metadata', 'native_cause_metadata'):
                        self.assertEqual(records['query5.after.' + label, 'min_length'], '160')
                        self.assertNotIn(label, records['query6', 'fact_labels'].split())
                        self.assertEqual(records['bounded.' + label, 'target_bound'], '160')
                self.assertEqual(records['bounded.target_first_event_is_breakpoint', 'target_bound'], str(160 if scenario == 1 else 128))
                process, records, plan = self.execute(Path(directory) / f'{scenario}-zero', scenario, 'boundzero')
                self.assertEqual(process.returncode, 1)
                self.assertFalse(staged.validate_protocol(records, plan)['caseAccepted'])

    def test_protocol_rejects_new_raw_fact_inventory_and_original_scope_mutations(self):
        with tempfile.TemporaryDirectory() as directory:
            _, records, plan = self.execute(Path(directory) / 'pass')
            mutations = [(('query2', 'labels'), ''), (('query2.before.' + staged.COMPLETE_STATE_HELPER, 'max_length'), ''),
                         (('query2', 'fact_actual_properties'), ''), (('query1', 'time_limit'), '360'),
                         (('final_inventory', 'native_assertions'), '')]
            for key, value in mutations:
                changed = dict(records)
                changed[key] = value
                with self.subTest(key=key), self.assertRaises(ValueError):
                    staged.validate_protocol(changed, plan)
            changed = copy.deepcopy(plan)
            changed['scenario'] = 3
            with self.assertRaises(ValueError):
                staged.validate_protocol(records, changed)

    def test_real_tcl_late_tail_reselects_pending_with_only_fresh_infinity_facts(self):
        with tempfile.TemporaryDirectory() as directory:
            for typed in (True, False):
                process, records, plan = self.execute(Path(directory) / str(typed), mode='late_fresh', typed=typed)
                self.assertEqual(process.returncode, 0, process.stderr)
                result = staged.validate_protocol(records, plan)
                self.assertTrue(result['caseAccepted'])
                self.assertEqual(records['run', 'scheduled_queries'], '11')
                self.assertEqual(records['run', 'allocated_search_seconds'], '960')
                for index in (9, 10):
                    tag = f'query{index}'
                    self.assertEqual(records[tag, 'kind'], 'event_joint')
                    self.assertEqual(records[tag, 'engines'], 'Mp N Hp')
                    self.assertEqual(records[tag, 'time_limit'], '180')
                    self.assertEqual(records[tag, 'per_property_time_limit'], '23040')
                    self.assertEqual(records[tag, 'per_engine_max_jobs'], '4')
                    self.assertEqual(records[tag, 'executed'], '1')
                fresh = ('target_first_event_is_breakpoint', 'abstract_dpc_value', 'resume_pc_matches')
                for label in fresh:
                    self.assertNotIn(label, records['query9', 'fact_labels'].split())
                    self.assertEqual(records['query9.after.' + label, 'min_length'], 'infinite')
                    self.assertIn(label, records['query10', 'fact_labels'].split())
                self.assertNotIn('native_epc_metadata', records['query10', 'fact_labels'].split())
                expected = [n for n in records['query9', 'labels'].split() if n not in (*fresh, 'native_epc_metadata')]
                self.assertEqual(records['query10', 'labels'].split(), expected)
                self.assertEqual(records['query10.before.native_epc_metadata', 'validity_status'], 'undetermined')
                self.assertEqual(records['bounded.native_epc_metadata', 'target_bound'], '160')
                snapshots = {tag for tag, key in records if key == 'native_id' and not tag.startswith('bounded.')}
                self.assertEqual(len(snapshots), 24 * len(plan['allAssertions']))
                inventories = ['setup', *(f'query{i}' for i in range(11)),
                               *(f'query{i}.after_inventory' for i in range(11)), 'final_inventory']
                self.assertEqual(len(inventories), 24)
                for tag in inventories:
                    self.assertEqual(len(records[tag, 'native_assertions'].split()), len(plan['allAssertions']))
                    self.assertEqual(len(records[tag, 'native_covers'].split()), 48)

    def test_real_tcl_late_tail_empty_and_failures_preserve_all_declared_snapshots(self):
        with tempfile.TemporaryDirectory() as directory:
            process, records, plan = self.execute(Path(directory) / 'empty')
            self.assertEqual(process.returncode, 0, process.stderr)
            self.assertTrue(staged.validate_protocol(records, plan)['caseAccepted'])
            self.assertEqual(records['query10', 'executed'], '0')
            self.assertEqual(records['query10', 'labels'], '')
            self.assertEqual(records['query10', 'allocated_seconds'], '0')
            self.assertEqual(records['run', 'allocated_search_seconds'], '780')
            for mode in ('cex9', 'tool9', 'cex10', 'tool10'):
                process, records, plan = self.execute(Path(directory) / mode, mode=mode)
                self.assertEqual(process.returncode, 1)
                self.assertEqual(records['query9', 'executed'], '1')
                self.assertEqual(records['query10', 'executed'], str(int(mode.endswith('10'))))
                if mode.endswith('9'):
                    self.assertEqual(records['query10', 'skip_reason'], 'prior_query_failed')
                for tag in ('query9.after_inventory', 'query10', 'query10.after_inventory', 'final_inventory'):
                    self.assertIn((tag, 'native_assertions'), records)
                    self.assertIn((tag, 'native_covers'), records)
                self.assertIn(('query10.after.' + staged.COMPLETE_STATE_HELPER, 'min_length'), records)
                with self.assertRaises(ValueError):
                    staged.validate_protocol(records, plan)

    def test_late_tail_rejects_missing_inventory_facts_raw_fields_and_undeclared_query(self):
        with tempfile.TemporaryDirectory() as directory:
            process, records, plan = self.execute(Path(directory) / 'late', mode='late_fresh')
            self.assertEqual(process.returncode, 0, process.stderr)
            mutations = [(('query10', 'engines'), 'N C I'), (('query10', 'per_engine_max_jobs'), '2'),
                         (('query9', 'time_limit'), '360'), (('query10', 'time_limit'), '360'),
                         (('query10', 'labels'), ' '.join(reversed(records['query10', 'labels'].split()))),
                         (('query10', 'fact_labels'), records['query10', 'fact_labels'] + ' native_epc_metadata'),
                         (('query10', 'native_covers'), ''),
                         (('query10.after_inventory', 'native_covers'), ''),
                         (('query10.after_inventory', 'native_covers'), records['query10.after_inventory', 'native_covers'] + ' foreign.cover'),
                         (('query10.after_inventory', 'native_covers'), records['query10.after_inventory', 'native_covers'] + ' ' + records['query10.after_inventory', 'native_covers'].split()[0]),
                         (('query10.after_inventory', 'native_covers'), 'foreign.cover ' + ' '.join(records['query10.after_inventory', 'native_covers'].split()[1:])),
                         (('query10.after_inventory', 'native_assertions'), ''),
                         (('final_inventory', 'native_assertions'), ''),
                         (('query11', 'executed'), '0')]
            for key, value in mutations:
                changed = dict(records)
                changed[key] = value
                with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                    staged.validate_protocol(changed, plan)
            for suffix in ('before', 'after'):
                for field in ('validity_status', 'run_status', 'engine', 'min_length', 'max_length',
                              'target_bound', 'trace_length', 'latest_trace_engine'):
                    changed = dict(records)
                    del changed[f'query10.{suffix}.target_single_retry', field]
                    with self.subTest(suffix=suffix, field=field), self.assertRaises(ValueError):
                        staged.validate_protocol(changed, plan)
