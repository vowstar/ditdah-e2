# SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
# SPDX-License-Identifier: MIT
"""Verify every staged native query and retain the original acceptance bounds."""


import copy
import hashlib
import re
from pathlib import Path

from formal.debug_transport.run import EXPECTED_RESET, check_cpu_receipt

HERE = Path(__file__).resolve().parent
PROFILE = "staged_current_facts"
STRATEGY = {"profile": PROFILE, "configuration": "injection"}
FILES = ("staged.py", "collect_staged.tcl", "staged_helpers.sv", "collect_semantic.tcl", "semantic_helpers.sv", "collect_payload.tcl", "payload_helpers.sv", "collect_joint.tcl", "collect_store_state.tcl", "store_state_helpers.sv", "program_state_helpers.sv", "complete_setup_helpers.sv", "complete_state_helpers.sv", "complete_protocol_helpers.sv", "complete_cluster_helpers.sv", "complete_multiply_helpers.sv", "complete_illegal_helpers.sv")
ORIGINALS = ('no_external_event', 'native_epc_metadata', 'native_cause_metadata', 'native_tval_metadata', 'native_control_metadata', 'native_hit_metadata', 'older_fault_cause', 'target_first_event_is_breakpoint', 'target_retry_has_no_trap', 'target_has_no_writeback_on_trap', 'target_single_retry', 'illegal_single_breakpoint', 'older_load_retires_first', 'older_fault_blocks_target', 'no_store_before_breakpoint', 'older_fault_blocks_store', 'no_multiply_before_breakpoint', 'multiply_has_target_identity', 'initial_dpc_zero', 'abstract_dpc_value', 'resume_pc_matches')
HELPERS = ('rom_local_response_class', 'rom_local_valid_word_class', 'rom_local_fetch_rom_consistent', 'core_geom_rom_packet_consistent', 'rom_local_fetch_fault_free', 'core_frontend_stage_rom_consistent', 'core_base_zero_memory_decode', 'core_data_owner_control_consistent', 'core_fetch_execute_fault_free', 'core_program_no_injection', 'core_reverse_memory_system_decode')
INJECTION_CONFIG = {'coldExpressionSha256': 'cddf44ae6e073813e60ded592a417e0110e7f0b4161dd629a3eb975937faf6cc', 'coldFacts': 123, 'collectorSha256': '02d3a9efc913bc2bf2049bff6e54449d57f84d1e1ee247fc7032d082c9f197e8', 'dutColdExpressionSha256': '8b3f32c82d236bf42e5487fb13e4d526b02abd1b54f3b275e44ab4eb17bd42a0', 'dutColdFacts': 122, 'helperGoals': ['rom_local_response_class', 'rom_local_valid_word_class', 'rom_local_fetch_rom_consistent', 'core_geom_rom_packet_consistent', 'rom_local_fetch_fault_free', 'core_frontend_stage_rom_consistent', 'core_base_zero_memory_decode', 'core_data_owner_control_consistent', 'core_fetch_execute_fault_free', 'core_program_no_injection', 'core_reverse_memory_system_decode'], 'helperSha256': '749262b3273f28caec4338b579d61b8ad48986275e09b15af78d52497c528694', 'name': 'injection', 'wrapperSha256': '5d9fb4c2e2ef2e1e8445df2a99bb68050cb6ba6602293cf191ac2d19357332a6'}

HINT_GROUPS = (('initial_dpc_zero',), ('no_external_event',), ('native_epc_metadata', 'native_cause_metadata'), ('native_tval_metadata', 'native_control_metadata', 'native_hit_metadata'), ('target_retry_has_no_trap', 'target_single_retry', 'illegal_single_breakpoint', 'older_load_retires_first'), ('target_has_no_writeback_on_trap', 'no_store_before_breakpoint', 'no_multiply_before_breakpoint', 'multiply_has_target_identity'))


SEMANTIC_HELPERS = ('core_native_pipeline_pc_owner', 'core_native_semantic_metadata', 'core_debug_command_register_domain', 'core_native_trap_metadata')
SEMANTIC_CONFIG = {'coldExpressionSha256': 'cddf44ae6e073813e60ded592a417e0110e7f0b4161dd629a3eb975937faf6cc', 'coldFacts': 123, 'collectorSha256': 'b484c1639fdf0bcd7f0a1728048afe0bb987ddbfc009459e6f55d0d0f548ed59', 'dutColdExpressionSha256': '8b3f32c82d236bf42e5487fb13e4d526b02abd1b54f3b275e44ab4eb17bd42a0', 'dutColdFacts': 122, 'helperGoals': ['rom_local_response_class', 'rom_local_valid_word_class', 'rom_local_fetch_rom_consistent', 'core_geom_rom_packet_consistent', 'rom_local_fetch_fault_free', 'core_frontend_stage_rom_consistent', 'core_base_zero_memory_decode', 'core_data_owner_control_consistent', 'core_fetch_execute_fault_free', 'core_program_no_injection', 'core_reverse_memory_system_decode', 'core_native_pipeline_pc_owner', 'core_native_semantic_metadata', 'core_debug_command_register_domain', 'core_native_trap_metadata'], 'helperSha256': '356dfe265c8eec191f6102c263d6d66f8baa779a12e140589c84f2d2650f2240', 'name': 'injection-semantic', 'wrapperSha256': '5d9fb4c2e2ef2e1e8445df2a99bb68050cb6ba6602293cf191ac2d19357332a6'}


PAYLOAD_HELPERS = ('core_setup_transaction_payload_metadata', 'core_setup_exact_command_payload')
PAYLOAD_COVERS = ('cover_target_breakpoint', 'cover_older_fault_event', 'cover_older_load_accepted', 'cover_native_epc', 'cover_native_cause', 'cover_native_tval', 'cover_native_control', 'cover_native_hit', 'cover_multiply_start', 'cover_multiply_done', 'cover_target_normal', 'cover_target_retry', 'cover_multiply_value', 'cover_completion', 'cover_metadata_complete', 'cover_store_finish', 'cover_multiply_finish', 'cover_illegal_finish', 'cover_older_fault', 'cover_resume_dpc', 'cover_first_dmi', 'cover_cold_reset', 'cover_setup_guard_07a2', 'cover_setup_guard_07a1', 'cover_setup_guard_0305')
PAYLOAD_CONFIG = {**SEMANTIC_CONFIG, "name": 'injection-payload-semantic', "helperGoals": [*SEMANTIC_CONFIG["helperGoals"], *PAYLOAD_HELPERS],
                  "helperSha256": '0f8835965ae765431d67cbb271369e38034b664a4d9995db286b1b555a23f4e5', "collectorSha256": '1b04615808145084779ea2e16c897885ef518701d804b007f3c46acf7ff3cf38'}


JOINT_CONFIG = {**PAYLOAD_CONFIG, "name": 'injection-payload-joint', "collectorSha256": 'caefbe8c9a3c1409055d261174135f09af924111a76dfd93080e3e831a1ca9ab'}


STORE_STATE_HELPERS = ("core_store_source_state", "core_armed_target_capture", "core_store_value_owner_metadata", "core_store_configuration_history")
STORE_STATE_CONFIG = {**JOINT_CONFIG, "name": 'injection-store-state',
    "helperGoals": [*JOINT_CONFIG["helperGoals"], *STORE_STATE_HELPERS],
    "collectorSha256": 'ef60ea4bc60c543040b4718a5f3c5b5d902da8cec5eb16b6f8acaac355da863d', "helperSha256": 'd2639d2f1a602a2672af733b1a98181a41810bef1ac8df1bbefe85022ccb92ae'}
STORE_EVENT_PRIORITY = ("target_first_event_is_breakpoint", "target_retry_has_no_trap", "target_single_retry",
                        "older_load_retires_first", "no_store_before_breakpoint")


PROGRAM_STATE_HELPERS = ("core_store_source_state", "core_armed_target_capture", "core_store_value_owner_metadata", "core_program_configuration_history")
PROGRAM_STATE_CONFIG = {**JOINT_CONFIG, "name": 'injection-program-state',
    "helperGoals": [*JOINT_CONFIG["helperGoals"], *PROGRAM_STATE_HELPERS],
    "collectorSha256": 'ef60ea4bc60c543040b4718a5f3c5b5d902da8cec5eb16b6f8acaac355da863d', "helperSha256": '0b698cbda65b828346ddf86df8103b74436637100f2a98822dffa4e761aca59c'}


def program_state_schedule():
    old = payload_schedule(SEMANTIC_CONFIG["helperGoals"])
    entries = [*old[:2], {"kind": "store_state", "labels": list(PROGRAM_STATE_HELPERS),
        "engines": ["Mp", "N", "Hp"], "timeLimit": 120, "propertyGuard": 7680, "jobs": 4, "withProven": True},
        *old[2:8], {"kind": "event_joint", "labels": [], "engines": ["Mp", "N", "Hp"],
        "timeLimit": 360, "propertyGuard": 23040, "jobs": 4, "withProven": True}]
    return [{**entry, "tag": f"query{index}"} for index, entry in enumerate(entries)]


COMPLETE_STATE_HELPER = "core_complete_target_trap_metadata"
COMPLETE_STATE_SHA256 = '4de96db901fd34066d5ec9bcc2bbb036ebea31168c091f4d487d38f99bcd083d'
COMPLETE_PROTOCOL_SHA256 = '51bcacb02c35f86dbfe4c5ec4b69c23b103d75a4a0fd79ed3f20f0d5bbb5513b'
COMPLETE_CLUSTER_SHA256 = '178be551e6ed96fde2eb863be184e679d7e5e29bb3afd3dcb44affb39dd53f26'
COMPLETE_MULTIPLY_SHA256 = '0e3c8bd87c521adabfc2f081b0634914cd3084baf35e03e7d7556ab1d1c6cc28'
COMPLETE_ILLEGAL_SHA256 = 'd7109855ab7fef670f67512fdd86004099b74719259c9db4dbdac26daede7a5a'

STORE_COMPLETE_CONFIG = {**STORE_STATE_CONFIG, "helperGoals": [*STORE_STATE_CONFIG["helperGoals"], COMPLETE_STATE_HELPER], "name": 'injection-store-complete', "helperSha256": 'b422d847eb95c971dcae972c2f70d9359885470554799e8467a9a5cec64c1731'}
PROGRAM_COMPLETE_CONFIG = {**PROGRAM_STATE_CONFIG, "helperGoals": [*PROGRAM_STATE_CONFIG["helperGoals"], COMPLETE_STATE_HELPER], "name": 'injection-program-complete', "helperSha256": 'b422d847eb95c971dcae972c2f70d9359885470554799e8467a9a5cec64c1731'}
COMPLETE_NAMES = (STORE_COMPLETE_CONFIG["name"], PROGRAM_COMPLETE_CONFIG["name"])


def complete_payload_fragment(scenario, extra):
    require(type(scenario) is int and scenario in (0, 1, 2), "Complete payload requires a configured program")
    require(hashlib.sha256(extra).hexdigest() == STORE_COMPLETE_CONFIG["helperSha256"], "Complete payload observer differs")
    old = payload_fragment((HERE / "payload_helpers.sv").read_bytes(), scenario)
    require(not re.search(rb"\b(reg|initial|assume|force|input|output|inout|assert|cover)\b", extra), "Complete payload observer changes state or environment")
    names = re.findall(rb"\bwire\s*(?:\[[^]]+\]\s*)?(\w+)", extra)
    require(len(names) == len(set(names)) and not set(names).intersection(re.findall(rb"\b\w+\b", old)), "Complete payload observer name collision")
    match = re.search(rb"core_setup_exact_command_payload: assert\((.*?)\);", old, re.DOTALL)
    require(match is not None, "Original exact payload assertion is missing")
    strengthened = match[1] + b" &&\n        k_complete_extra_payload"
    return extra + b"\n" + old[:match.start(1)] + strengthened + old[match.end(1):]


def complete_protocol_fragment(state, protocol, scenario=0):
    require(type(scenario) is int and scenario in (0, 2), "Complete protocol scenario differs")
    require(hashlib.sha256(state).hexdigest() == COMPLETE_STATE_SHA256,
            "Original complete observer differs")
    require(hashlib.sha256(protocol).hexdigest() == COMPLETE_PROTOCOL_SHA256 and
            not re.search(rb"\b(reg|logic|initial|always|assume|force|input|output|inout|assert|cover|module|endmodule|function|task)\b", protocol) and
            b"$" not in protocol, "Complete protocol observer differs")
    names = re.findall(rb"\bwire\s*(?:\[[^]]+\]\s*)?(\w+)", protocol)
    require(len(names) == len(set(names)) and b"core_setup_protocol_consistent" in names and
            not set(names).intersection(re.findall(rb"\b\w+\b", state)), "Complete protocol observer collision")
    match = re.search(rb"core_complete_target_trap_metadata: assert\((.*?)\);", state, re.DOTALL)
    require(match is not None and state.count(b"  always @(posedge clock) begin\n") == 1,
            "Complete assertion is not unique")
    if scenario == 0:
        expression = b"(" + match[1] + b") && (scenario != 2'd0 || core_setup_protocol_consistent)"
    else:
        phase = (b"!program_selected_scene ||\n"
                 b"        (program_phase_configuration && program_first_target_armed &&\n"
                 b"         program_retry_trigger_disabled && program_phase_clock_ready)")
        expression = b"scenario != 2'd2 || ((" + match[1] + b") && core_setup_protocol_consistent && (" + phase + b"))"
    strengthened = state[:match.start(1)] + expression + state[match.end(1):]
    return strengthened.replace(b"  always @(posedge clock) begin\n",
                                b"\n" + protocol + b"\n  always @(posedge clock) begin\n", 1)


def complete_cluster_fragment(state, cluster):
    expected = complete_protocol_fragment((HERE / "complete_state_helpers.sv").read_bytes(),
                                          (HERE / "complete_protocol_helpers.sv").read_bytes(), 0)
    require(state == expected, "SC0 complete observer differs")
    clean = re.sub(rb"/\*.*?\*/|//[^\n]*", b"", cluster, flags=re.DOTALL)
    wire = rb"\bwire\s*(?:\[[^]]+\]\s*)?([A-Za-z_]\w*)\s*=\s*[^;]+;"
    names = re.findall(wire, clean)
    require(hashlib.sha256(cluster).hexdigest() == COMPLETE_CLUSTER_SHA256 and
            not re.sub(wire, b"", clean).strip() and b"$" not in cluster and b"#" not in cluster and
            not re.search(rb"\b(reg|logic|initial|always|assume|force|input|output|inout|assert|cover|assign|module|endmodule|function|task|bind|alias|defparam)\b", clean),
            "Complete cluster observer changes state or environment")
    require(len(names) == len(set(names)) and
            {b"core_cluster_handler", b"core_cluster_retry", b"core_cluster_older", b"core_complete_cluster_consistent"}.issubset(names) and
            not set(names).intersection(re.findall(rb"\b\w+\b", state)), "Complete cluster observer collision")
    require(len(re.findall(rb"wire\s+core_complete_cluster_consistent\s*=\s*core_cluster_handler\s*&&\s*core_cluster_retry\s*&&\s*core_cluster_older\s*;", clean)) == 1,
            "Complete cluster conjunction differs")
    match = re.search(rb"core_complete_target_trap_metadata: assert\((.*?)\);", state, re.DOTALL)
    require(match is not None, "Complete assertion is missing")
    expression = b"(" + match[1] + b") && core_complete_cluster_consistent"
    strengthened = state[:match.start(1)] + expression + state[match.end(1):]
    return strengthened.replace(b"  always @(posedge clock) begin\n",
                                b"\n" + cluster + b"\n  always @(posedge clock) begin\n", 1)


def complete_multiply_fragment(state, multiply):
    require(hashlib.sha256(state).hexdigest() == COMPLETE_STATE_SHA256,
            "SC1 complete observer differs")
    clean = re.sub(rb"/\*.*?\*/|//[^\n]*", b"", multiply, flags=re.DOTALL)
    wire = rb"\bwire\s*(?:\[[^]]+\]\s*)?([A-Za-z_]\w*)\s*=\s*[^;]+;"
    names = re.findall(wire, clean)
    require(hashlib.sha256(multiply).hexdigest() == COMPLETE_MULTIPLY_SHA256 and
            not re.sub(wire, b"", clean).strip() and b"$" not in multiply and b"#" not in multiply and
            not re.search(rb"\b(reg|logic|initial|always|assume|force|input|output|inout|assert|cover|assign|module|endmodule|function|task|bind|alias|defparam)\b", clean),
            "Complete multiply observer changes state or environment")
    require(len(names) == len(set(names)) and b"core_complete_multiply_consistent" in names and
            not set(names).intersection(re.findall(rb"\b\w+\b", state)), "Complete multiply observer collision")
    match = re.search(rb"core_complete_target_trap_metadata: assert\((.*?)\);", state, re.DOTALL)
    require(match is not None and state.count(b"  always @(posedge clock) begin\n") == 1,
            "Complete assertion is not unique")
    require(b"(" + match[1] + b")" in multiply and
            all(name in names for name in (b"core_setup_protocol_consistent", b"last_resume_ok",
                                          b"handler_program_history", b"normal_retry_ok", b"core_older_history_ok")),
            "Complete multiply contract is incomplete")
    strengthened = state[:match.start(1)] + b"core_complete_multiply_consistent" + state[match.end(1):]
    return strengthened.replace(b"  always @(posedge clock) begin\n",
                                b"\n" + multiply + b"\n  always @(posedge clock) begin\n", 1)


def complete_illegal_fragment(state, illegal):
    expected = complete_protocol_fragment((HERE / "complete_state_helpers.sv").read_bytes(),
                                          (HERE / "complete_protocol_helpers.sv").read_bytes(), 2)
    require(state == expected, "SC2 complete observer differs")
    clean = re.sub(rb"/\*.*?\*/|//[^\n]*", b"", illegal, flags=re.DOTALL)
    wire = rb"\bwire\s*(?:\[[^]]+\]\s*)?([A-Za-z_]\w*)\s*=\s*[^;]+;"
    names = re.findall(wire, clean)
    require(hashlib.sha256(illegal).hexdigest() == COMPLETE_ILLEGAL_SHA256 and
            not re.sub(wire, b"", clean).strip() and b"$" not in illegal and b"#" not in illegal and
            not re.search(rb"\b(reg|logic|initial|always|assume|force|input|output|inout|assert|cover|assign|module|endmodule|function|task|bind|alias|defparam)\b", clean),
            "Complete illegal observer changes state or environment")
    required = (b"last_resume_ok", b"handler_first_pending_trap", b"handler_snapshot",
                b"handler_pipeline_owner", b"handler_r7_owner", b"sc2_program_history")
    require(len(names) == len(set(names)) and b"core_complete_illegal_consistent" in names and
            all(name in names for name in required) and
            not set(names).intersection(re.findall(rb"\b\w+\b", state)), "Complete illegal observer collision")
    match = re.search(rb"core_complete_target_trap_metadata: assert\((.*?)\);", state, re.DOTALL)
    aggregate = re.search(rb"wire\s+core_complete_illegal_consistent\s*=\s*(.*?);", clean, re.DOTALL)
    require(match is not None and aggregate is not None and state.count(b"  always @(posedge clock) begin\n") == 1,
            "Complete assertion is not unique")
    require(re.sub(rb"\s+", b"", b"(" + match[1] + b")") in re.sub(rb"\s+", b"", aggregate[1]) and
            all(re.search(rb"\b" + name + rb"\b", aggregate[1]) for name in required),
            "Complete illegal contract is incomplete")
    strengthened = state[:match.start(1)] + b"core_complete_illegal_consistent" + state[match.end(1):]
    return strengthened.replace(b"  always @(posedge clock) begin\n",
                                b"\n" + illegal + b"\n  always @(posedge clock) begin\n", 1)


def build_complete(plan, contents, config, extra):
    name = STORE_STATE_CONFIG["name"] if plan["scenario"] == 0 else PROGRAM_STATE_CONFIG["name"]
    helper = "store_state_helpers.sv" if plan["scenario"] == 0 else "program_state_helpers.sv"
    plan, contents = build(plan, contents, (HERE / "collect_store_state.tcl").read_bytes(), (HERE / helper).read_bytes(), name)
    original = contents["trigger_core_formal.sv"]
    old = payload_fragment((HERE / "payload_helpers.sv").read_bytes(), plan["scenario"])
    require(original.count(old) == 1, "Original payload fragment is not unique")
    names = re.findall(rb"\bwire\s*(?:\[[^]]+\]\s*)?(\w+)", extra)
    require(not set(names).intersection(re.findall(rb"\b\w+\b", original)), "Complete payload wrapper name collision")
    header = re.search(rb"\bmodule\s+DitDahE2\s*\((.*?)\);", contents["DitDahE2.sv"], re.DOTALL)
    require(header is not None and not set(names).intersection(re.findall(rb"\b\w+\b", header[1])), "Complete payload wildcard collision")
    contents["trigger_core_formal.sv"] = original.replace(old, complete_payload_fragment(plan["scenario"], extra), 1)
    state = (HERE / "complete_state_helpers.sv").read_bytes()
    require(hashlib.sha256(state).hexdigest() == COMPLETE_STATE_SHA256 and
            not re.search(rb"\b(reg|initial|assume|force|input|output|inout|cover)\b", state) and
            re.findall(rb"\b(\w+)\s*:\s*assert\s*\(", state) == [COMPLETE_STATE_HELPER.encode()], "Complete trap observer differs")
    if plan["scenario"] in (0, 2):
        state = complete_protocol_fragment(state, (HERE / "complete_protocol_helpers.sv").read_bytes(), plan["scenario"])
    if plan["scenario"] == 0:
        state = complete_cluster_fragment(state, (HERE / "complete_cluster_helpers.sv").read_bytes())
    if plan["scenario"] == 1:
        state = complete_multiply_fragment(state, (HERE / "complete_multiply_helpers.sv").read_bytes())
    if plan["scenario"] == 2:
        state = complete_illegal_fragment(state, (HERE / "complete_illegal_helpers.sv").read_bytes())
    names = re.findall(rb"\bwire\s*(?:\[[^]]+\]\s*)?(\w+)", state)
    require(len(names) == len(set(names)) and not set(names).intersection(re.findall(rb"\b\w+\b", contents["trigger_core_formal.sv"])) and
            not set(names).intersection(re.findall(rb"\b\w+\b", header[1])), "Complete trap observer collision")
    contents["trigger_core_formal.sv"] = contents["trigger_core_formal.sv"].replace(b"endmodule", state + b"\nendmodule")
    plan.update(proofStrategy=strategy(config["name"]), stagedConfiguration=config,
                helperGoals=list(config["helperGoals"]), allAssertions=[*ORIGINALS, *config["helperGoals"]],
                queryGoals=[*config["helperGoals"], *ORIGINALS], querySchedule=query_schedule(config["helperGoals"], config["name"]))
    contents["plan.tcl"] = plan_tcl(plan, config)
    return plan, contents


def store_original_order(original):
    tail = ("native_epc_metadata", "native_cause_metadata", "native_tval_metadata", "native_control_metadata",
            "native_hit_metadata", "abstract_dpc_value", "resume_pc_matches")
    return [*STORE_EVENT_PRIORITY, *(n for n in original if n not in (*STORE_EVENT_PRIORITY, *tail)), *tail]


def store_state_schedule():
    old = payload_schedule(SEMANTIC_CONFIG["helperGoals"])
    entries = [*old[:2], {"kind": "store_state", "labels": list(STORE_STATE_HELPERS),
        "engines": ["Mp", "N", "Hp"], "timeLimit": 120, "propertyGuard": 7680, "jobs": 4, "withProven": True},
        *old[2:8], {"kind": "event_joint", "labels": [], "engines": ["Mp", "N", "Hp"],
        "timeLimit": 360, "propertyGuard": 23040, "jobs": 4, "withProven": True}]
    return [{**entry, "tag": f"query{index}"} for index, entry in enumerate(entries)]


def build_store_state(plan, contents, collector, fragment, config, *, scenarios=(0,), helpers=STORE_STATE_HELPERS, schedule=None):
    require(plan["scenario"] in scenarios, "State profile requires its fixed program scenario")
    require(hashlib.sha256(collector).hexdigest() == config["collectorSha256"] and
            hashlib.sha256(fragment).hexdigest() == config["helperSha256"], "Store state source differs")
    plan, contents = build_payload(plan, contents, (HERE / "collect_joint.tcl").read_bytes(),
                                  (HERE / "payload_helpers.sv").read_bytes(), configuration(JOINT_CONFIG["name"]))
    original = contents["trigger_core_formal.sv"]
    require(not re.search(rb"\b(reg|initial|assume|force|input|output|inout)\b", fragment), "Store state observer changes state or environment")
    names = re.findall(rb"\bwire\s*(?:\[[^]]+\]\s*)?(\w+)", fragment)
    require(len(names) == len(set(names)) and not set(names).intersection(re.findall(rb"\b\w+\b", original)), "Store state observer name collision")
    header = re.search(rb"\bmodule\s+DitDahE2\s*\((.*?)\);", contents["DitDahE2.sv"], re.DOTALL)
    require(header is not None and not set(names).intersection(re.findall(rb"\b\w+\b", header[1])), "Store state wildcard collision")
    require(re.findall(rb"\b(\w+)\s*:\s*assert\s*\(", fragment) == [n.encode() for n in helpers] and
            not re.search(rb"\bcover\s*\(", fragment) and original.count(b"endmodule") == 1,
            "Store state assertion inventory differs")
    contents["trigger_core_formal.sv"] = original.replace(b"endmodule", fragment + b"\nendmodule")
    contents["collect.tcl"] = collector
    plan.update(proofStrategy=strategy(config["name"]), stagedConfiguration=config,
                helperGoals=list(config["helperGoals"]), allAssertions=[*ORIGINALS, *config["helperGoals"]],
                queryGoals=[*config["helperGoals"], *ORIGINALS], querySchedule=store_state_schedule() if schedule is None else schedule)
    contents["plan.tcl"] = plan_tcl(plan, config)
    return plan, contents


def joint_schedule(helpers):
    result = payload_schedule(helpers)
    result[8] = {"tag": "query8", "kind": "joint", "labels": [], "engines": ["Mp", "N", "Hp"],
                 "timeLimit": 360, "propertyGuard": 23040, "jobs": 4, "withProven": True}
    result[9]["timeLimit"] = 120
    return result


def payload_parameters(scenario):
    require(type(scenario) is int and scenario in range(4), "Payload scenario differs")
    return {"target": 12 if scenario == 3 else 48, "handler": 256 if scenario == 3 else 56,
            "control": 0x20000044, "domain": ([0, 8, 12, 256, 0x20000044] if scenario == 3 else
                [0, 8, 44, 48, 56, *([291] if scenario == 1 else []), 0x20000044])}


def payload_native_covers():
    return [*PAYLOAD_COVERS, *(name + ":precondition1" for name in (*ORIGINALS, "initial_common_cold_reset", "no_later_cold_reset"))]


def payload_fragment(template, scenario):
    require(hashlib.sha256(template).hexdigest() == PAYLOAD_CONFIG["helperSha256"], "Payload helper template differs")
    parameters = payload_parameters(scenario)
    fragment = template
    if scenario != 3:
        fragment = fragment.replace(b"32'd12", b"32'd48").replace(b"32'd256", b"32'd56")
        for field in (b"data0", b"operands_data"):
            anchor = b"dut.dm." + field + b" == 32'd56;"
            extra = b" || dut.dm." + field + b" == 32'd44"
            if scenario == 1:
                extra += b" || dut.dm." + field + b" == 32'd291"
            require(fragment.count(anchor) == 1, "Payload domain template boundary differs")
            fragment = fragment.replace(anchor, anchor[:-1] + extra + b";")
    require(parameters["target"] in (12, 48), "Payload target differs")
    return fragment


def payload_schedule(helpers):
    entries = [{"kind": "metadata", "labels": [PAYLOAD_HELPERS[0], *helpers], "engines": ["Mp", "N", "Hp"],
                "timeLimit": 120, "propertyGuard": 7680, "jobs": 4, "withProven": True},
               {"kind": "payload", "labels": [PAYLOAD_HELPERS[1]], "engines": ["N", "C", "I"],
                "timeLimit": 300, "propertyGuard": 5760, "jobs": 2, "withProven": True}]
    entries += [{"kind": "hint", "labels": list(labels), "engines": ["N", "C", "I"],
                 "timeLimit": 10, "propertyGuard": 960, "jobs": 2, "withProven": True} for labels in HINT_GROUPS]
    entries += [{"kind": "dpc", "labels": ["abstract_dpc_value", "resume_pc_matches"], "engines": ["N", "C", "I"],
                 "timeLimit": 120, "propertyGuard": 5760, "jobs": 2, "withProven": True},
                {"kind": "remaining", "labels": [], "engines": ["B"], "timeLimit": 360,
                 "propertyGuard": 13440, "jobs": 4, "withProven": True,
                 "iterationCap": "maximum_selected_original_bound_at_least_one", "firstTraceAttempt": 1}]
    return [{"tag": f"query{index}", **entry} for index, entry in enumerate(entries)]


def build_payload(plan, contents, collector, template, config):
    require(hashlib.sha256(collector).hexdigest() == config["collectorSha256"], "Payload collector differs")
    plan, contents = build_semantic(plan, contents, (HERE / "collect_semantic.tcl").read_bytes(),
                                    (HERE / "semantic_helpers.sv").read_bytes(), configuration(SEMANTIC_CONFIG["name"]))
    original = contents["trigger_core_formal.sv"]
    fragment = payload_fragment(template, plan["scenario"])
    require(not re.search(rb"\b(reg|initial|assume|force)\b", fragment), "Payload observer changes state or environment")
    names = re.findall(rb"\bwire\s*(?:\[[^]]+\]\s*)?(\w+)", fragment)
    require(len(names) == len(set(names)) and not set(names).intersection(re.findall(rb"\b\w+\b", original)), "Payload observer name collision")
    header = re.search(rb"\bmodule\s+DitDahE2\s*\((.*?)\);", contents["DitDahE2.sv"], re.DOTALL)
    require(header is not None and not set(names).intersection(re.findall(rb"\b\w+\b", header[1])), "Payload wildcard collision")
    require(re.findall(rb"\b(\w+)\s*:\s*assert\s*\(", fragment) == [n.encode() for n in PAYLOAD_HELPERS] and
            re.findall(rb"\b(\w+)\s*:\s*cover\s*\(", fragment) == [n.encode() for n in PAYLOAD_COVERS[-3:]], "Payload observer inventory differs")
    contents["trigger_core_formal.sv"] = original.replace(b"endmodule", fragment + b"\nendmodule")
    contents["collect.tcl"] = collector
    plan.update(proofStrategy=strategy(config["name"]), stagedConfiguration=config,
                helperGoals=list(config["helperGoals"]), allAssertions=[*ORIGINALS, *config["helperGoals"]],
                queryGoals=[*config["helperGoals"], *ORIGINALS], querySchedule=query_schedule(config["helperGoals"], config["name"]),
                allCovers=list(PAYLOAD_COVERS), nativeCovers=payload_native_covers(), payloadParameters=payload_parameters(plan["scenario"]))
    contents["plan.tcl"] = plan_tcl(plan, config)
    return plan, contents


def configuration(name="injection"):
    if name in COMPLETE_NAMES:
        return copy.deepcopy(STORE_COMPLETE_CONFIG if name == STORE_COMPLETE_CONFIG["name"] else PROGRAM_COMPLETE_CONFIG)
    if name == PROGRAM_STATE_CONFIG["name"]:
        return copy.deepcopy(PROGRAM_STATE_CONFIG)
    if name == STORE_STATE_CONFIG["name"]:
        return copy.deepcopy(STORE_STATE_CONFIG)
    if name == JOINT_CONFIG["name"]:
        return copy.deepcopy(JOINT_CONFIG)
    require(name in ("injection", "injection-semantic", "injection-payload-semantic"), "Unsupported staged source configuration: " + str(name))
    return copy.deepcopy(PAYLOAD_CONFIG if name == "injection-payload-semantic" else SEMANTIC_CONFIG if name == "injection-semantic" else INJECTION_CONFIG)


def strategy(name="injection"):
    configuration(name)
    return {"profile": PROFILE, "configuration": name}


def is_staged(plan):
    if plan.get("stagedConfiguration") is None:
        return False
    require(plan.get("proofStrategy") == strategy(plan["stagedConfiguration"]["name"]), "Staged strategy differs")
    return True


def artifacts(name):
    configuration(name)
    if name in COMPLETE_NAMES:
        return ("collect_store_state.tcl", "complete_setup_helpers.sv")
    if name == PROGRAM_STATE_CONFIG["name"]:
        return ("collect_store_state.tcl", "program_state_helpers.sv")
    if name == STORE_STATE_CONFIG["name"]:
        return ("collect_store_state.tcl", "store_state_helpers.sv")
    if name == JOINT_CONFIG["name"]:
        return ("collect_joint.tcl", "payload_helpers.sv")
    return (("collect_payload.tcl", "payload_helpers.sv") if name == "injection-payload-semantic" else ("collect_semantic.tcl", "semantic_helpers.sv") if name == "injection-semantic" else
            ("collect_staged.tcl", "staged_helpers.sv"))


def budgets(name):
    configuration(name)
    if name in COMPLETE_NAMES:
        return (960, 1080)
    if name in (JOINT_CONFIG["name"], STORE_STATE_CONFIG["name"], PROGRAM_STATE_CONFIG["name"]):
        return (960, 1080)
    return (960, 1080) if name in ("injection-semantic", "injection-payload-semantic") else (840, 960)


def check_cold_collector(collector, config):
    text = collector.decode()
    expressions = re.findall(r"(?m)^[ \t]*assume -reset \{([^\n{}]+)\}[ \t]*$", text)
    require(len(expressions) == 1 and len(re.findall(r"\bassume\s+-reset\s+\{", text)) == 1,
            "Collector requires one literal cold-reset command")
    expression = expressions[0]
    require(hashlib.sha256(expression.encode()).hexdigest() == config["coldExpressionSha256"],
            "Actual collector cold-reset expression differs")
    terms = expression.split(" && ")
    require(terms[:2] == ["reset", "systemReset == 0"] and len(terms) == len(set(terms)) and
            terms[-1] == "core_geom_sync_epoch == 1", "Actual collector cold-reset terms differ")
    dut_terms = terms[2:-1]
    require(all(re.fullmatch(r"dut\.[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)* == 0", term) for term in dut_terms) and
            len(dut_terms) == config["dutColdFacts"] and len(terms) - 2 == config["coldFacts"],
            "Actual collector cold-reset fact count differs")
    projection = " && ".join(terms[:-1])
    require(hashlib.sha256(projection.encode()).hexdigest() == config["dutColdExpressionSha256"],
            "Actual collector DUT cold-reset projection differs")
    return {"expressionSha256": hashlib.sha256(expression.encode()).hexdigest(),
            "dutExpressionSha256": hashlib.sha256(projection.encode()).hexdigest(),
            "dutFacts": len(dut_terms), "observerFacts": 1, "environmentTerms": 2,
            "totalFacts": len(terms) - 2}


def check_collectors(files):
    for config in (configuration(), configuration(SEMANTIC_CONFIG["name"]), configuration(PAYLOAD_CONFIG["name"]), configuration(JOINT_CONFIG["name"]), configuration(STORE_STATE_CONFIG["name"]), configuration(PROGRAM_STATE_CONFIG["name"]), configuration(STORE_COMPLETE_CONFIG["name"]), configuration(PROGRAM_COMPLETE_CONFIG["name"])):
        collector = files[artifacts(config["name"])[0]]
        check_cold_collector(collector, config)
        require(hashlib.sha256(collector).hexdigest() == config["collectorSha256"],
                "Reviewed collector source differs")
    base = files["collect_staged.tcl"]
    semantic = files["collect_semantic.tcl"]
    old_budget = b"record setup maximum_search_budget_seconds 840"
    new_budget = b"record setup maximum_search_budget_seconds 960"
    require(base.count(old_budget) == semantic.count(new_budget) == 1 and
            semantic.replace(new_budget, old_budget) == base,
            "Semantic collector differs from its family beyond the declared budget")


def declared_bounds(scenario):
    require(type(scenario) is int and scenario in range(4), "Staged scenario differs")
    bounds = dict.fromkeys(ORIGINALS, 352 if scenario == 1 else 288)
    bounds["initial_dpc_zero"] = 0
    for label in ("abstract_dpc_value", "resume_pc_matches"):
        bounds[label] = 112 if scenario == 0 else 128
    bounds["target_first_event_is_breakpoint"] = 160 if scenario == 1 else 128
    if scenario != 1:
        bounds.update(no_store_before_breakpoint=128, no_multiply_before_breakpoint=128)
    bounds.update(native_epc_metadata=176 if scenario == 1 else 160,
                  native_cause_metadata=176 if scenario == 1 else 160,
                  native_tval_metadata=192 if scenario == 1 else 176,
                  native_control_metadata=208 if scenario == 1 else 192,
                  native_hit_metadata=208 if scenario == 1 else 192)
    return bounds


def query_schedule(helpers=HELPERS, source_configuration=None):
    if source_configuration in COMPLETE_NAMES:
        config = configuration(source_configuration)
        require(list(helpers) == config["helperGoals"], "Complete payload helper inventory differs")
        entries = store_state_schedule() if source_configuration == STORE_COMPLETE_CONFIG["name"] else program_state_schedule()
        entries[2].update(timeLimit=100, propertyGuard=6400)
        entries[3].update(labels=[COMPLETE_STATE_HELPER, *entries[3]["labels"]],
                          timeLimit=30, propertyGuard=2880, engines=["Mp", "N", "Hp"], jobs=4)
        if source_configuration == STORE_COMPLETE_CONFIG["name"]:
            entries[2].update(timeLimit=50, propertyGuard=3200)
            entries[5].update(labels=[STORE_STATE_HELPERS[-1], "native_epc_metadata", "native_cause_metadata"], timeLimit=60, propertyGuard=5760, engines=["Mp", "N", "Hp"], jobs=4)
            entries[-1]["timeLimit"] = 180
            entries.append({**entries[-1], "tag": "query10"})
        return entries
    if source_configuration == PROGRAM_STATE_CONFIG["name"]:
        require(list(helpers) == PROGRAM_STATE_CONFIG["helperGoals"], "Program state helper inventory differs")
        return program_state_schedule()
    if source_configuration == STORE_STATE_CONFIG["name"]:
        require(list(helpers) == STORE_STATE_CONFIG["helperGoals"], "Store state helper inventory differs")
        return store_state_schedule()
    if source_configuration == JOINT_CONFIG["name"]:
        require(tuple(helpers[-2:]) == PAYLOAD_HELPERS, "Joint helper inventory differs")
        return joint_schedule(helpers[:-2])
    if tuple(helpers[-2:]) == PAYLOAD_HELPERS:
        return payload_schedule(helpers[:-2])
    entries = [{"tag": f"query{index}", "kind": "hint", "labels": list(labels), "engines": ["N", "C", "I"],
                "timeLimit": 10, "propertyGuard": 960, "jobs": 2, "withProven": True} for index, labels in enumerate(HINT_GROUPS)]
    result = entries + [
        {"tag": "query6", "kind": "dpc", "labels": ["abstract_dpc_value", "resume_pc_matches"], "engines": ["N", "C", "I"],
         "timeLimit": 300, "propertyGuard": 5760, "jobs": 2, "withProven": True},
        {"tag": "query7", "kind": "helpers", "labels": list(helpers), "engines": ["Mp", "N", "Hp"],
         "timeLimit": 120, "propertyGuard": 7680, "jobs": 4, "withProven": True},
        {"tag": "query8", "kind": "remaining", "labels": [], "engines": ["B"],
         "timeLimit": 360, "propertyGuard": 13440, "jobs": 4, "withProven": True,
         "iterationCap": "maximum_selected_original_bound_at_least_one", "firstTraceAttempt": 1}]

    if list(helpers[-4:]) == list(SEMANTIC_HELPERS):
        result[7]["labels"] = list(helpers[:-4])
        result[-1]["tag"] = "query9"
        result.insert(8, {"tag": "query8", "kind": "semantic", "labels": list(SEMANTIC_HELPERS),
            "engines": ["Mp", "N", "Hp"], "timeLimit": 120, "propertyGuard": 7680, "jobs": 4, "withProven": True})
    return result


def build(plan, contents, collector, fragment, source_configuration="injection"):
    config = configuration(source_configuration)
    check_cold_collector(collector, config)
    if source_configuration in COMPLETE_NAMES:
        if plan["scenario"] == 0:
            return build_complete(plan, contents, configuration(STORE_COMPLETE_CONFIG["name"]), fragment)
        if source_configuration == PROGRAM_COMPLETE_CONFIG["name"] and plan["scenario"] in (1, 2):
            return build_complete(plan, contents, config, fragment)
        return build(plan, contents, (HERE / "collect_store_state.tcl").read_bytes(),
                     (HERE / "store_state_helpers.sv").read_bytes(), STORE_STATE_CONFIG["name"])
    if source_configuration == PROGRAM_STATE_CONFIG["name"]:
        if plan["scenario"] == 0:
            return build(plan, contents, (HERE / "collect_store_state.tcl").read_bytes(),
                         (HERE / "store_state_helpers.sv").read_bytes(), STORE_STATE_CONFIG["name"])
        if plan["scenario"] in (1, 2):
            return build_store_state(plan, contents, collector, fragment, config, scenarios=(1, 2),
                                     helpers=PROGRAM_STATE_HELPERS, schedule=program_state_schedule())
        return build(plan, contents, (HERE / "collect_joint.tcl").read_bytes(),
                     (HERE / "payload_helpers.sv").read_bytes(), JOINT_CONFIG["name"])
    if source_configuration == STORE_STATE_CONFIG["name"]:
        if plan["scenario"] == 0:
            return build_store_state(plan, contents, collector, fragment, config)
        return build(plan, contents, (HERE / "collect_joint.tcl").read_bytes(),
                     (HERE / "payload_helpers.sv").read_bytes(), JOINT_CONFIG["name"])
    if source_configuration in ("injection-payload-semantic", "injection-payload-joint"):
        return build_payload(plan, contents, collector, fragment, config)
    if source_configuration == "injection-semantic":
        return build_semantic(plan, contents, collector, fragment, config)
    require(plan["goals"] == list(ORIGINALS) and plan["covers"] == [] and plan["expected"] == "proven" and
            plan["top"] == "trigger_core_formal", "Staged flow requires the original core safety scope")
    wrapper = contents["trigger_core_formal.sv"]
    require(hashlib.sha256(wrapper).hexdigest() == config["wrapperSha256"] and
            hashlib.sha256(collector).hexdigest() == config["collectorSha256"] and
            hashlib.sha256(fragment).hexdigest() == config["helperSha256"], "Staged reviewed source differs")
    require(wrapper.count(b"endmodule") == 1 and plan["initialState"]["resetFacts"] == config["dutColdFacts"] and
            plan["initialState"]["resetExpressionSha256"] == config["dutColdExpressionSha256"], "Staged cold source differs")
    local_names = set(re.findall(rb"\b(?:wire|reg)\s*(?:\[[^]]+\]\s*)?(\w+)", fragment))
    require(not local_names.intersection(re.findall(rb"\b\w+\b", wrapper)), "Staged observer name collision")
    dut_header = re.search(rb"\bmodule\s+DitDahE2\s*\((.*?)\);", contents["DitDahE2.sv"], re.DOTALL)
    require(dut_header is not None and not local_names.intersection(re.findall(rb"\b\w+\b", dut_header[1])), "Staged wildcard collision")
    plan = copy.deepcopy(plan)
    contents = dict(contents)
    contents["trigger_core_formal.sv"] = wrapper.replace(b"endmodule", fragment + b"\nendmodule")
    contents["collect.tcl"] = collector
    plan.update(proofMode="bounded_commercial", proofStrategy=dict(STRATEGY), stagedConfiguration=config,
                originalGoals=list(ORIGINALS), helperGoals=list(config["helperGoals"]),
                allAssertions=[*ORIGINALS, *config["helperGoals"]], queryGoals=[*config["helperGoals"], *ORIGINALS],
                querySchedule=query_schedule(config["helperGoals"]), caseSuccessUsesOriginalGoalsOnly=True,
                noExternalProofOrTheoremImports=True, freshSameTaskFactReuse=True,
                maximumSearchSeconds=840, outerTimeoutSeconds=960, cpuCount=16,
                targetBounds=declared_bounds(plan["scenario"]), traceBound=352 if plan["scenario"] == 1 else 288,
                dutInitialState=plan["initialState"], observerColdFacts={"core_geom_sync_epoch": 1})
    plan["initialState"] = {**plan["dutInitialState"], "profile": "implemented_cold_reset_with_geometry_observer",
        "resetFacts": config["coldFacts"], "dutResetFacts": config["dutColdFacts"], "observerResetFacts": 1,
        "previousResetExpressionSha256": config["dutColdExpressionSha256"], "addedResetFacts": 1,
        "scopeChange": "DUT cold122 unchanged; one read-only epoch is1 after implemented cold reset",
        "dutResetExpressionSha256": config["dutColdExpressionSha256"], "resetExpressionSha256": config["coldExpressionSha256"]}
    contents["plan.tcl"] = plan_tcl(plan, config)
    plan["inputs"] = sorted(contents)
    return plan, contents


def plan_tcl(plan, config):
    tcl = ("set cold_expression_sha256 " + config["coldExpressionSha256"] + "\nset top " + plan["top"] +
           "\nset sources {" + " ".join(plan["sources"]) + "}\nset scenario " + str(plan["scenario"]) + "\n" +
           "set original_goals {" + " ".join(ORIGINALS) + "}\nset all_assertions {" + " ".join(plan["allAssertions"]) + "}\n" +
           "set query_goals {" + " ".join(plan["queryGoals"]) + "}\nset response_goal " + HELPERS[0] + "\nset goals $all_assertions\n" +
           "set expected_assumptions {" + " ".join(plan["assumptions"]) + "}\narray set original_bounds {" +
           " ".join(f"{name} {bound}" for name, bound in plan["targetBounds"].items()) + "}\nset query_schedule {\n")
    for entry in plan["querySchedule"]:
        tcl += " {" + entry["tag"] + " " + entry["kind"] + " {" + " ".join(entry["labels"]) + "} " + str(entry["timeLimit"]) + " " + str(entry["propertyGuard"]) + " {" + " ".join(entry["engines"]) + "} " + str(entry["jobs"]) + "}\n"
    tcl += "}\n"
    if config["name"] in (PAYLOAD_CONFIG["name"], JOINT_CONFIG["name"], STORE_STATE_CONFIG["name"], PROGRAM_STATE_CONFIG["name"], *COMPLETE_NAMES):
        tcl += "set native_covers {" + " ".join(plan["nativeCovers"]) + "}\n"
    return tcl.encode()



def build_semantic(plan, contents, collector, fragment, config):
    require(hashlib.sha256(collector).hexdigest() == config["collectorSha256"] and
            hashlib.sha256(fragment).hexdigest() == config["helperSha256"], "Semantic reviewed source differs")
    plan, contents = build(plan, contents, (HERE / "collect_staged.tcl").read_bytes(),
                           (HERE / "staged_helpers.sv").read_bytes(), "injection")
    original = contents["trigger_core_formal.sv"]
    names = re.findall(rb"\bwire\s*(?:\[[^]]+\]\s*)?(\w+)", fragment)
    require(len(names) == len(set(names)) and not set(names).intersection(re.findall(rb"\b\w+\b", original)),
            "Semantic observer declaration collision")
    header = re.search(rb"\bmodule\s+DitDahE2\s*\((.*?)\);", contents["DitDahE2.sv"], re.DOTALL)
    require(header is not None and not set(names).intersection(re.findall(rb"\b\w+\b", header[1])) and
            not re.search(rb"\b(reg|initial|assume|cover)\b", fragment), "Semantic observer changed state or environment")
    contents["trigger_core_formal.sv"] = original.replace(b"endmodule", fragment + b"endmodule")
    contents["collect.tcl"] = collector
    plan.update(proofStrategy=strategy(config["name"]), stagedConfiguration=config,
                helperGoals=list(config["helperGoals"]), allAssertions=[*ORIGINALS, *config["helperGoals"]],
                queryGoals=[*config["helperGoals"], *ORIGINALS], querySchedule=query_schedule(config["helperGoals"]),
                timeLimitSeconds=960, maximumSearchSeconds=960, outerTimeoutSeconds=1080)
    plan["targetBounds"] = dict(sorted(plan["targetBounds"].items()))
    contents["plan.tcl"] = plan_tcl(plan, config)
    return plan, contents


def check_resources(receipt, plan=None):
    check_cpu_receipt(receipt)
    timeout = budgets(plan["stagedConfiguration"]["name"])[1] if plan is not None else 960
    require(receipt.get("cpuCount") == 16 and len(receipt.get("cpuAffinity", [])) == 16 and
            type(receipt.get("timeoutSeconds")) is int and receipt["timeoutSeconds"] == timeout and type(receipt.get("pid")) is int and receipt["pid"] > 0,
            "Staged receipt requires sixteen CPUs and its declared outer timeout")


def check_native_records(records, plan):
    result = validate_protocol(records, plan)
    require(result["caseAccepted"], "Native staged proof is incomplete: " + " ".join(result["unresolvedOriginals"]))
    evidence = result["originalProperties"]
    unbounded = sum(item["validity_status"] == "proven" for item in evidence.values())
    properties = {
        label: {"verdict": "proven" if item["validity_status"] == "proven" else "bounded_proven_user",
                "engine": item["engine"],
                "minLength": item["min_length"] if item["validity_status"] == "proven" else int(item["min_length"]),
                "targetBound": "0" if item["validity_status"] == "proven" else item["declaredBound"]}
        for label, item in evidence.items()
    }
    return {"goals": len(ORIGINALS), "covers": 0, "verdict": "proven", "proofMode": plan["proofMode"],
            "unboundedGoals": unbounded, "boundedGoals": len(ORIGINALS) - unbounded,
            "propertyEvidence": properties, "helperEvidence": result["auxiliaryFinalStates"],
            "unboundedHelperGoals": len(result["unboundedHelpers"]), "stagedEvidence": result}

KNOWN_ENGINES = frozenset(("PRE", "N", "C", "I", "Mp", "Hp", "B"))


def require(value, message):
    if not value:
        raise ValueError(message)


def canonical_ids(value, expected):
    require(len(expected) == len(set(expected)) and isinstance(value, str), "Native identity inventory differs")
    tokens = value.split()
    require(value == " ".join(tokens) and len(tokens) == len(set(tokens)) == len(expected), "Malformed native identity list")
    require(all(token in (wanted, "<embedded>::" + wanted) for token, wanted in zip(tokens, expected, strict=True)),
            "Native property prefix, top, identity or order differs")


def validate_protocol(records, plan):
    config = configuration(plan["stagedConfiguration"]["name"])
    require(plan["stagedConfiguration"] == config, "Staged source configuration differs")
    helpers, cold_sha, response = config["helperGoals"], config["coldExpressionSha256"], HELPERS[0]
    payload = config["name"] in (PAYLOAD_CONFIG["name"], JOINT_CONFIG["name"], STORE_STATE_CONFIG["name"], PROGRAM_STATE_CONFIG["name"], *COMPLETE_NAMES)
    if payload:
        require(plan["payloadParameters"] == payload_parameters(plan["scenario"]) and plan["allCovers"] == list(PAYLOAD_COVERS) and
                plan["nativeCovers"] == payload_native_covers(), "Payload parameter or cover scope differs")
    if config["name"] == STORE_STATE_CONFIG["name"]:
        require(plan["scenario"] == 0, "Store state scope is restricted to fixed store scenario")
    if config["name"] == PROGRAM_STATE_CONFIG["name"]:
        require(plan["scenario"] in (1, 2), "Program state scope requires multiply or illegal scenario")
    if config["name"] in COMPLETE_NAMES:
        require(plan["scenario"] == 0 if config["name"] == STORE_COMPLETE_CONFIG["name"] else plan["scenario"] in (1, 2), "Complete payload scene differs")
    expected_schedule = query_schedule(helpers, config["name"])
    search_budget, outer_timeout = budgets(config["name"])
    require(plan["proofStrategy"] == strategy(config["name"]) and plan["proofMode"] == "bounded_commercial" and plan["cpuCount"] == 16 and plan["targetBounds"] == declared_bounds(plan["scenario"]), "Original bounds or strategy differs")
    original, labels, schedule = plan["originalGoals"], plan["allAssertions"], plan["querySchedule"]
    require(len(original) == len(set(original)) == 21 and original == list(ORIGINALS) and labels == [*original, *helpers] and
            len(labels) == len(set(labels)) == len(original) + len(helpers) and plan["goals"] == original and plan["helperGoals"] == helpers and
            plan["queryGoals"] == [*helpers, *original] and plan["caseSuccessUsesOriginalGoalsOnly"] is True,
            "Original or auxiliary scope differs")
    require(schedule == expected_schedule and len(schedule) == len(expected_schedule) and plan["maximumSearchSeconds"] == search_budget and
            plan["outerTimeoutSeconds"] == outer_timeout, "Staged schedule or budget differs")
    require(plan["noExternalProofOrTheoremImports"] is True and plan["freshSameTaskFactReuse"] is True and
            plan["dutInitialState"]["resetFacts"] == config["dutColdFacts"] and plan["initialState"]["resetFacts"] == config["coldFacts"] and
            plan["dutInitialState"]["resetExpressionSha256"] == config["dutColdExpressionSha256"] and
            plan["initialState"]["resetExpressionSha256"] == cold_sha and plan["observerColdFacts"] == {"core_geom_sync_epoch": 1},
            "Source/reset/fact contract differs")
    require(not any(value == "cex" for (_, key), value in records.items() if key == "validity_status"), "Assertion counterexample")
    require(not any(value for (_, key), value in records.items() if key in ("tool_error", "scope_error")), "Native command failed")
    settings = {key: value for (tag, key), value in records.items() if tag == "settings"}
    require(set(settings) == {"before_invariants_import", "active_invariants_import", "after_invariants_import", "before_orchestration", "after_orchestration"} and
            settings["before_invariants_import"] in ("auto", "on", "off") and
            settings["active_invariants_import"] == settings["after_invariants_import"] == "on" and
            settings["before_orchestration"] == settings["after_orchestration"] and settings["before_orchestration"] in ("auto", "on", "off"),
            "Proof settings differ")
    top = plan["top"]
    allowed_tags = {"setup", "settings", "run", "before", "after"}
    allowed_tags.update(prefix + "." + label for prefix in ("before", "final", "bounded") for label in labels)
    for entry in schedule:
        tag = entry["tag"]
        allowed_tags.update((tag, tag + ".before_scope", tag + ".after_scope"))
        allowed_tags.update(tag + suffix + "." + label for suffix in (".before", ".after") for label in labels)
    if payload:
        allowed_tags.add("final_inventory")
        allowed_tags.update(q["tag"] + ".after_inventory" for q in schedule)
    require(all(tag in allowed_tags for tag, _ in records), "Unexpected query or assertion record")
    handles = {label: records.get(("before." + label, "native_id")) for label in labels}
    canonical_ids(" ".join(handles[label] or "" for label in labels), [top + "." + label for label in labels])

    def infinite(tag):
        return all(records.get((tag, key)) == value for key, value in {
            "validity_status": "proven", "run_status": "processed", "min_length": "infinite", "target_bound": "0"}.items())

    def identity(tag, label, bound=0):
        expected = {"name": top + "." + label, "native_id": handles[label], "type": "assert", "command": "assert", "disabled": "0",
                    "expression": label, "precondition": "0", "target_bound": str(bound)}
        require(all(records.get((tag, key)) == value for key, value in expected.items()), "Native property identity differs: " + tag)
        if label == response:
            require((tag, "clock") not in records and (tag, "edge") not in records, "Global response sampling differs")
        else:
            require(records.get((tag, "clock")) in (None, "", "clock") and records.get((tag, "edge")) in (None, "", "posedge"), "Posedge sampling differs")
        require(all(records.get(("before." + label, key)) == records.get((tag, key)) for key in ("expression", "precondition", "clock", "edge")),
                "Assertion sampling changed")

    def snapshot(tag):
        for label in labels:
            item = tag + "." + label
            identity(item, label)
            require(all((item, key) in records and records[item, key] != "" for key in ("validity_status", "run_status", "engine", "min_length", "max_length", "trace_length", "latest_trace_engine")), "Raw native status missing")
            verdict = records[item, "validity_status"]
            require(verdict in ("unknown", "undetermined", "proven"), "Unsafe raw proof state")
            if verdict == "proven":
                require(infinite(item) and records[item, "max_length"] == "infinite", "Finite or unprocessed result cannot be an infinity fact")
                require(records.get((item, "engine")) in KNOWN_ENGINES, "Infinity result has an unsupported native engine identity")

    def qualified(tag, label):
        bound, minimum = plan["targetBounds"][label], records.get((tag, "min_length"), "")
        return infinite(tag) or (bound > 0 and records.get((tag, "validity_status")) == "undetermined" and
            records.get((tag, "run_status")) == "processed" and records.get((tag, "target_bound")) == "0" and minimum.isdigit() and int(minimum) >= bound)

    scope_keys = ("clock", "reset", "global", "reset_initial", "declared_cold_expression_sha256", "initial_common_cold_reset", "assumptions")
    require(records.get(("before", "declared_cold_expression_sha256")) == cold_sha and
            records.get(("setup", "dut_cold_facts")) == str(config["dutColdFacts"]) and records.get(("setup", "observer_cold_facts")) == "1" and
            records.get(("setup", "maximum_search_budget_seconds")) == str(search_budget), "Declared scope/budget differs")
    require(all(("before", key) in records for key in scope_keys), "Initial scope is incomplete")
    expected_scope = {"declared_cold_expression_sha256": cold_sha, "clock": "", "reset": EXPECTED_RESET,
        "reset_initial": "assume:0", "initial_common_cold_reset": "1",
        "global": top + ".initial_common_cold_reset " + " ".join(plan["assumptions"]),
        "assumptions": " ".join(sorted(plan["assumptions"]))}
    require(top == "trigger_core_formal" and plan["assumptions"] == [top + ".no_later_cold_reset"] and
            all(records.get(("before", key)) == value for key, value in expected_scope.items()) and
            all(records.get(("setup", key)) == "0" for key in ("bbox_inst", "bbox_mod", "bbox_out", "stopat")) and
            records.get(("setup", "clock_mode")) == "free_running" and
            records.get(("setup", "target_search_bound")) == "0", "Native source scope differs")
    wanted = sorted(top + "." + label for label in labels)

    def inventory(value):
        names = value.split()
        require(len(names) == len(set(names)) == len(labels) and sorted(names) == wanted, "Complete fresh assertion inventory differs")

    inventory(records.get(("setup", "native_assertions"), ""))
    if payload:
        cover_names = records.get(("setup", "native_covers"), "").split()
        require(len(cover_names) == len(set(cover_names)) == 48 and sorted(cover_names) == sorted(top + "." + n for n in plan["nativeCovers"]), "Payload native cover inventory differs")
    if payload:
        for inventory_tag in [*(q["tag"] + ".after_inventory" for q in schedule), "final_inventory"]:
            native_inventory = {key: value for (group, key), value in records.items() if group == inventory_tag}
            require(set(native_inventory) == {"native_assertions", "native_covers"}, "Payload inventory fields differ")
            inventory(native_inventory["native_assertions"])
            cover_names = native_inventory["native_covers"].split()
            require(len(cover_names) == len(set(cover_names)) == 48 and sorted(cover_names) == sorted(top + "." + n for n in plan["nativeCovers"]), "Payload after/final native cover inventory differs")
    snapshot("before")
    previous, executed, allocated, query_evidence = "before", 0, 0, {}
    critical = ("native_id", "validity_status", "run_status", "engine", "min_length", "max_length", "target_bound", "trace_length", "latest_trace_engine")
    for entry in schedule:
        tag = entry["tag"]
        snapshot(tag + ".before")
        snapshot(tag + ".after")
        require(all(records.get((previous + "." + label, key)) == records.get((tag + ".before." + label, key)) for label in labels for key in critical),
                "Native state changed between recorded proof stages")
        for suffix in ("before_scope", "after_scope"):
            require(all((tag + "." + suffix, key) in records and records[tag + "." + suffix, key] == records["before", key] for key in scope_keys), "Query environment changed")
        inventory(records.get((tag, "native_assertions"), ""))
        if payload:
            cover_names = records.get((tag, "native_covers"), "").split()
            require(len(cover_names) == len(set(cover_names)) == 48 and sorted(cover_names) == sorted(top + "." + n for n in plan["nativeCovers"]), "Fresh payload native cover inventory differs")
        facts = [label for label in labels if infinite(tag + ".before." + label)]
        pending_order = (["abstract_dpc_value", "resume_pc_matches", *(label for label in original if label not in ("abstract_dpc_value", "resume_pc_matches"))]
                         if entry["kind"] == "joint" else original)
        if entry["kind"] == "event_joint":
            pending_order = store_original_order(original)
        selected = ([label for label in pending_order if not qualified(tag + ".before." + label, label)]
                    if entry["kind"] in ("joint", "remaining", "event_joint") else entry["labels"])
        iteration_cap = str(max([1, *(plan["targetBounds"][label] for label in selected)])) if entry["kind"] == "remaining" else "none"
        first_trace = "1" if entry["kind"] == "remaining" else "none"
        execute = bool(selected)
        raw = records.get((tag, "actual_properties"))
        fact_raw = records.get((tag, "fact_actual_properties"))
        canonical_ids(raw, [top + "." + label for label in selected])
        canonical_ids(fact_raw, [top + "." + label for label in facts])
        require(raw == " ".join(handles[label] for label in selected) and fact_raw == " ".join(handles[label] for label in facts), "Native ID links differ")
        expected = {"kind": entry["kind"], "labels": " ".join(selected), "actual_properties": raw, "canonical_properties": " ".join(top + "." + label for label in selected),
                    "engines": " ".join(entry["engines"]), "time_limit": str(entry["timeLimit"]), "per_property_time_limit": str(entry["propertyGuard"]),
                    "per_engine_max_jobs": str(entry["jobs"]), "iteration_cap": iteration_cap, "first_trace_attempt": first_trace, "uses_proven_directives": "1", "invariant_import": "on",
                    "executed": str(int(execute)), "skip_reason": "" if execute else "no_pending_originals", "allocated_seconds": str(entry["timeLimit"] if execute else 0),
                    "import_before": "on", "import_after": "on", "orchestration_before": settings["before_orchestration"], "orchestration_after": settings["before_orchestration"],
                    "fact_labels": " ".join(facts), "fact_actual_properties": fact_raw, "fact_canonical_properties": " ".join(top + "." + label for label in facts),
                    "native_assertions": records[tag, "native_assertions"]}
        if payload:
            expected["native_covers"] = records[tag, "native_covers"]
        require({key: value for (group, key), value in records.items() if group == tag} == expected, "Stage selection, exact infinity facts or arguments differ: " + tag)
        if entry["kind"] == "remaining":
            for label in selected:
                item = tag + ".after." + label
                if qualified(item, label) and not infinite(item):
                    require(records.get((item, "engine")) == "B", "Final B prefix has a different proof engine")
        if execute:
            executed += 1
            allocated += entry["timeLimit"]
        else:
            require(all(records.get((tag + ".before." + label, key)) == records.get((tag + ".after." + label, key)) for label in labels for key in critical), "Skipped query changed native states")
        query_evidence[tag] = {"selected": selected, "factsAvailable": facts, "factsUsed": facts if execute else [], "executed": execute}
        previous = tag + ".after"
    snapshot("final")
    require(all(records.get((previous + "." + label, key)) == records.get(("final." + label, key)) for label in labels for key in critical), "Final raw state changed")
    require(all(("after", key) in records and records["after", key] == records["before", key] for key in scope_keys), "Final scope changed")
    require(records.get(("run", "proof_queries_finished")) == "1" and records.get(("run", "scheduled_queries")) == str(len(expected_schedule)) and
            records.get(("run", "executed_queries")) == str(executed) and records.get(("run", "allocated_search_seconds")) == str(allocated), "Executed query budget differs")
    converted, incomplete, evidence = [], [], {}
    for label in original:
        final, bound = "final." + label, plan["targetBounds"][label]
        minimum = records.get((final, "min_length"), "")
        finite = not infinite(final) and qualified(final, label)
        if finite:
            tag = "bounded." + label
            identity(tag, label, bound)
            require(records.get((tag, "validity_status")) == "bounded_proven_user" and records.get((tag, "run_status")) == "processed" and
                    records.get((tag, "min_length")) == minimum, "Native finite conversion differs")
            require(records.get((tag, "engine")) in KNOWN_ENGINES and
                    records[tag, "engine"] == records.get((final, "engine")), "Native finite conversion changed its proof engine")
            require(all(records.get((tag, key)) == records.get((final, key)) for key in
                        ("max_length", "trace_length", "latest_trace_engine")), "Native finite conversion changed raw proof metadata")
            converted.append(label)
        if not qualified(final, label):
            incomplete.append(label)
        evidence[label] = {key: records.get((final, key)) for key in ("validity_status", "run_status", "engine", "min_length", "target_bound")}
        evidence[label].update({"declaredBound": bound, "qualified": label not in incomplete, "converted": finite})
    require({tag for tag, _ in records if tag.startswith("bounded.")} == {"bounded." + label for label in converted}, "Unexpected bounded metadata")
    require(records.get(("run", "converted")) == " ".join(converted) and records.get(("run", "incomplete")) == " ".join(incomplete) and
            records.get(("run", "fatal_errors")) == "" and records.get(("run", "state")) == ("failed" if incomplete else "complete"), "Terminal qualification differs")
    return {"caseAccepted": not incomplete, "full21Passed": not incomplete, "full17Passed": False, "executedQueries": executed,
            "allocatedSearchSeconds": allocated, "queries": query_evidence, "originalProperties": evidence, "unresolvedOriginals": incomplete,
            "unboundedHelpers": [label for label in helpers if infinite("final." + label)],
            "auxiliaryFinalStates": {label: {key: records.get(("final." + label, key)) for key in ("validity_status", "run_status", "engine", "min_length", "target_bound")} for label in helpers}}
