# SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
# SPDX-License-Identifier: MIT
"""Freeze, prove and validate execute-trigger properties with commercial formal."""

import argparse
import importlib.util
import json
import os
import re
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(ROOT))
import formal as formal_package
from formal import debug_transport as transport_package
from formal.debug_transport import run as transport_backend
from formal.debug_transport.run import (
    EXPECTED_RESET,
    check_records,
    collect_case,
    digest,
    labels,
    output_hashes,
    read_records,
    sha,
    tcl_plan,
    write_json,
)

_staged_spec = importlib.util.spec_from_file_location("trigger_staged", HERE / "staged.py")
staged = importlib.util.module_from_spec(_staged_spec)
_staged_spec.loader.exec_module(staged)

SCHEMA = "ditdah-e2.execute-trigger.v3"
REFERENCE_SCHEMA = "ditdah-e2.execute-trigger.reference.v1"
UNIT_TOP = "trigger_formal"
CORE_TOP = "trigger_core_formal"
UNIT_RTL = "DitDahE2Trigger.sv"
CORE_RTL = "DitDahE2.sv"
UNIT_WRAPPER = "trigger_formal.sv"
CORE_WRAPPER = "trigger_core_formal.sv"
MULTIPLY_COLLECTOR = "collect_multiply_safety.tcl"
MULTIPLY_RETRY_COLLECTOR = "collect_multiply_retry.tcl"
SAFETY_RETRY_COLLECTOR = "collect_safety_retry.tcl"
UNIT_ASSERTIONS = (
    "tinfo_version", "unsupported_context_zero", "mcontrol_type", "mcontrol_reserved_zero",
    "legal_debug_action0", "legal_debug_action1", "debug_excludes_native", "native_excludes_debug",
    "debug_mode_quiet", "native_machine_enable", "exact_match0", "exact_match1", "wrong_address0",
    "wrong_address1", "hit0_set", "hit1_set", "simultaneous_hits_set", "trap_saves_mte",
    "mret_restores_mte", "dmode0_only_debug", "dmode1_only_debug", "locked0_control", "locked1_control",
)
UNIT_COVERS = ("cover_simultaneous", "cover_native", "cover_debug", "cover_trap_mret", "cover_user",
               "cover_debug_mode")
CORE_ASSERTIONS = (
    "no_external_event", "native_epc_metadata", "native_cause_metadata", "native_tval_metadata",
    "native_control_metadata", "native_hit_metadata", "older_fault_cause",
    "target_first_event_is_breakpoint", "target_retry_has_no_trap", "target_has_no_writeback_on_trap",
    "target_single_retry", "illegal_single_breakpoint", "older_load_retires_first",
    "older_fault_blocks_target", "no_store_before_breakpoint", "older_fault_blocks_store",
    "no_multiply_before_breakpoint", "multiply_has_target_identity",
    "initial_dpc_zero", "abstract_dpc_value", "resume_pc_matches",
)
CORE_COVERS = ("cover_store_finish", "cover_multiply_finish", "cover_illegal_finish", "cover_older_fault")
CORE_HELPER_COVERS = ("cover_target_breakpoint", "cover_older_fault_event", "cover_older_load_accepted", "cover_native_epc",
                      "cover_native_cause", "cover_native_tval", "cover_native_control", "cover_native_hit",
                      "cover_multiply_start", "cover_multiply_done", "cover_target_normal", "cover_target_retry",
                      "cover_multiply_value", "cover_completion", "cover_metadata_complete")
CORE_DPC_COVER = "cover_resume_dpc"
CORE_RESET_COVERS = ("cover_cold_reset", "cover_first_dmi")
CORE_ALL_COVERS = (*CORE_COVERS, *CORE_HELPER_COVERS, CORE_DPC_COVER, *CORE_RESET_COVERS)
NEGATIVE_TARGETS = {
    "negative-priority": (UNIT_TOP, "debug_excludes_native"),
    "negative-hit": (UNIT_TOP, "hit0_set"),
    "negative-native-trap": (CORE_TOP, "target_first_event_is_breakpoint"),
    "negative-multiply-start": (CORE_TOP, "no_multiply_before_breakpoint"),
    "negative-older-priority": (CORE_TOP, "older_fault_blocks_target"),
}
CORE_NAMES = ("store", "multiply", "illegal", "older")
CORE_NEGATIVE_SCENARIOS = {"negative-native-trap": 0, "negative-multiply-start": 1, "negative-older-priority": 3}
SAFETY_STRATEGY = {
    "dpcEngineMode": "{C I N}", "engineMode": "{C I N B}",
    "dpcPerEngineMaxJobs": 2, "perEngineMaxJobs": 4,
    "dpcTimeLimitSeconds": 2400, "groupTimeLimitSeconds": 7200,
    "perPropertyTimeLimitSeconds": 2400,
    "multiplyTargetEngineMode": "K", "multiplyTargetPerEngineMaxJobs": 1,
    "multiplyTargetTimeLimitSeconds": 2400,
}
GROUP_PROBE_LIMITS = {"dpc": 60, "initial": 60, "group": 180, "perProperty": 60}
GROUP_PROBE_STRATEGY = {
    **SAFETY_STRATEGY,
    "profile": "per_bound_group_probe",
    "dpcTimeLimitSeconds": GROUP_PROBE_LIMITS["dpc"],
    "initialTimeLimitSeconds": GROUP_PROBE_LIMITS["initial"],
    "groupTimeLimitSeconds": GROUP_PROBE_LIMITS["group"],
    "perPropertyTimeLimitSeconds": GROUP_PROBE_LIMITS["perProperty"],
    "multiplyTargetTimeLimitSeconds": GROUP_PROBE_LIMITS["group"],
}
CORE_INITIAL_STATE = {
    "profile": "implemented_cold_reset",
    "resetExpressionSha256": "787a737d75c4f30d873a8531d22d002314584c10e254a1c016dcd26bb780b353",
    "resetFacts": 112,
    "resetGprs": 31,
    "addedResetFacts": 42,
    "previousResetExpressionSha256": "22b194ee11240f2f5b59baa2ff2c102943de00c0eb6a06a2ea02506989fc967a",
    "scopeChange": "Previously omitted implemented reset values are explicit; unreset payloads remain unconstrained",
}
MULTIPLY_LATE_RETRY = {
    "profile": "late_unbounded_fact_retry",
    "labels": ["abstract_dpc_value", "target_first_event_is_breakpoint"],
    "engines": "C I N", "per_engine_max_jobs": 4,
    "time_limit": "300", "per_property_time_limit": "300", "first_trace_attempt": 1,
}
SAFETY_LATE_RETRY = {**MULTIPLY_LATE_RETRY, "profile": "generic_late_unbounded_fact_retry",
                     "labels": list(CORE_ASSERTIONS)}
SAFETY_RETRY_CASES = (*(f"core-{name}-safety" for name in CORE_NAMES), "core-dpc-safety")
OLDER_HARD_GOALS = ("older_fault_cause", "target_first_event_is_breakpoint", "older_fault_blocks_target",
                    "older_fault_blocks_store", "abstract_dpc_value", "resume_pc_matches")
EARLY_PROOF_GOALS = {
    0: ("no_external_event", "older_fault_cause", "target_has_no_writeback_on_trap",
        "illegal_single_breakpoint", "older_fault_blocks_target", "older_fault_blocks_store",
        "no_multiply_before_breakpoint", "multiply_has_target_identity", "initial_dpc_zero"),
    1: ("no_external_event", "older_fault_cause", "target_has_no_writeback_on_trap",
        "illegal_single_breakpoint", "older_fault_blocks_target", "no_store_before_breakpoint",
        "older_fault_blocks_store", "initial_dpc_zero"),
    2: ("no_external_event", "older_fault_cause", "target_retry_has_no_trap", "target_has_no_writeback_on_trap",
        "target_single_retry", "older_load_retires_first", "older_fault_blocks_target", "no_store_before_breakpoint",
        "older_fault_blocks_store", "no_multiply_before_breakpoint", "multiply_has_target_identity", "initial_dpc_zero"),
    3: tuple(label for label in CORE_ASSERTIONS if label not in OLDER_HARD_GOALS),
}
CASES = ("unit-safety", "unit-covers", *(f"core-{name}-safety" for name in CORE_NAMES),
         *(f"core-{name}-covers" for name in CORE_NAMES), "core-dpc-safety", "core-dpc-covers", *NEGATIVE_TARGETS)
TRANSPORT_FILES = ("formal/__init__.py", "formal/debug_transport/__init__.py", "formal/debug_transport/run.py")
TRANSPORT_MODULES = (formal_package, transport_package, transport_backend)
# These exact collectors leave the recorded environment unchanged and never restore a seed in their bound plans.
AUDITED_PROPERTY_BASES = {
    "e2b8f07f969ae4327fe323d7e5d32e0382aa1e6569c14529d665ac4028ded344": {
        "label": "target_first_event_is_breakpoint", "firstTraceAttempt": 1,
        "planSha256": "6937ce8f7309c97f8d7bc547a8abb01839b14c50db88f4ddd52b59bb04e79e24",
        "planTclSha256": "327bcc096aa34c2b003a1ab71e109f94962fffaff3336c786b47053ef86c131c",
    },
    "6553edeab90c85cc2eec6bca6ebaf9f0c04677eb31f7b9b45b1014ea422be99e": {
        "label": "older_load_retires_first", "firstTraceAttempt": 132,
        "planSha256": "3e7f2245adb6a2deccb11a74555f3dcd9623d73340e367ffe48b8154d38fed47",
        "planTclSha256": "9f3cbe835b69211d27da9e96d08e9d7012999ced43cd9c898433e5a934397366",
    },
    "771caecd8ffe8f0c5f9776f1b8b34b399a4476ec2d935c6c8c2ce0e5fc19a730": {
        "label": "older_load_retires_first", "firstTraceAttempt": 1,
        "planSha256": "f593714f9a9884b9cbbabf8d4eb9bd4585c13dfd52d6e2521bd1ccb2d13c9567",
        "planTclSha256": "327bcc096aa34c2b003a1ab71e109f94962fffaff3336c786b47053ef86c131c",
    },
    "bc116f81368cc04f56f4eb1eab03a9b1658b6cca1b401a1ce8735c634400784c": {
        "label": "target_first_event_is_breakpoint", "firstTraceAttempt": 136,
        "planSha256": "965f702f1912817a101d7566b1400700b7927776105af544d261016205a57037",
        "planTclSha256": "9f3cbe835b69211d27da9e96d08e9d7012999ced43cd9c898433e5a934397366",
    },
}


def load_rtl(path, top, core, source_root):
    build = json.loads((path / "manifest.json").read_text())
    if build.get("top") != top or build.get("exitStatus") != 0:
        raise ValueError("Unexpected RTL build identity")
    parameters = build.get("parameters", {})
    if parameters.get("triggerCount") != 2 or parameters.get("enableDebug") is not True:
        raise ValueError("Proof requires two enabled triggers")
    if core and (parameters.get("enableM") is not True or parameters.get("enableC") is not False or
                 parameters.get("protectedMode") is not False):
        raise ValueError("Core proof configuration differs")
    contents = {}
    for name, expected in build.get("rtlHashes", {}).items():
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*\.sv", name):
            raise ValueError("Unsafe RTL filename")
        value = (path / name).read_bytes()
        if sha(value) != expected:
            raise ValueError("RTL digest differs from manifest")
        contents[name] = value
    for name, expected in build.get("sourceHashes", {}).items():
        source = source_root / name
        if not source.is_file() or digest(source) != expected:
            raise ValueError("Generation source differs: " + name)
    return build, contents


def check_wrappers():
    unit = (HERE / UNIT_WRAPPER).read_bytes()
    core = (HERE / CORE_WRAPPER).read_bytes()
    unit_assumptions = {"initial_common_cold_reset", "no_later_cold_reset"}
    core_assumptions = {"initial_common_cold_reset", "no_later_cold_reset"}
    if (labels(unit.decode(), "assert") != set(UNIT_ASSERTIONS) or
            labels(unit.decode(), "cover") != set(UNIT_COVERS) or
            labels(unit.decode(), "assume") != unit_assumptions or unit.count(b"DitDahE2Trigger dut(.*);") != 1):
        raise ValueError("Unit wrapper inventory differs")
    if (labels(core.decode(), "assert") != set(CORE_ASSERTIONS) or
            labels(core.decode(), "cover") != set(CORE_ALL_COVERS) or
            labels(core.decode(), "assume") != core_assumptions or core.count(b"DitDahE2 dut (") != 1):
        raise ValueError("Core wrapper inventory differs")
    return unit, core


def check_core_reset_collectors(collectors):
    for role in ("safety", "multiply_safety", "multiply_retry", "safety_retry", "trace", "negative_older"):
        expressions = re.findall(r"(?m)^\s*assume -reset \{([^\n]+)\}\s*$", collectors[role].decode())
        if len(expressions) != 1 or sha(expressions[0].encode()) != CORE_INITIAL_STATE["resetExpressionSha256"]:
            raise ValueError("Core cold-reset contract differs: " + role)


def mutate(contents, name):
    changed = dict(contents)
    if name == "negative-hit":
        pattern = r"hit <= core_ready & _GEN_\d+ \| \((_GEN_\d+) \? writeData\[20\] : hit\);"
        text, count = re.subn(pattern, r"hit <= \1 ? writeData[20] : hit;", changed[UNIT_RTL].decode())
        if count != 1:
            raise ValueError("Mutation anchor differs: " + name)
        changed[UNIT_RTL] = text.encode()
        return changed
    if name == "negative-priority":
        filename, target = UNIT_RTL, "assign core_nativeAction = core_ready & core_matched_0 & ~core_debugAction_0;"
        replacement = "assign core_nativeAction = core_ready & core_matched_0;"
    elif name == "negative-native-trap":
        filename, target = CORE_RTL, "m_trap <= fault;"
        replacement = "m_trap <= x_fault | ~legal | isBreak & ~isDebugBreak | isCall | badTarget | badData;"
    elif name == "negative-multiply-start":
        filename = CORE_RTL
        target = ("& ~eligibleInterrupt & ~sleeping_0 & ~x_fault & ~_debug_core_stop\n"
                  "    & ~_csr_trigger_matched;")
        replacement = "& ~eligibleInterrupt & ~sleeping_0 & ~x_fault & ~_debug_core_stop;"
    elif name == "negative-older-priority":
        filename = CORE_RTL
        target = "_GEN_466 = redirect_0 | returning | waiting | waking | synchronized;"
        replacement = "_GEN_466 = 1'h0;"
    else:
        raise ValueError("Unknown trigger mutation")
    text = changed[filename].decode()
    if text.count(target) != 1:
        raise ValueError("Mutation anchor differs: " + name)
    changed[filename] = text.replace(target, replacement).encode()
    return changed


def goal_bounds(scenario):
    trace_bound = 352 if scenario == 1 else 288
    bounds = {label: trace_bound for label in CORE_ASSERTIONS}
    bounds["initial_dpc_zero"] = 0
    for label in ("abstract_dpc_value", "resume_pc_matches"):
        bounds[label] = 112 if scenario == 0 else 128
    bounds["target_first_event_is_breakpoint"] = 160 if scenario == 1 else 128
    for label in ("no_store_before_breakpoint", "no_multiply_before_breakpoint"):
        if scenario != 1:
            bounds[label] = 128
    if scenario == 1:
        bounds.update(native_epc_metadata=176, native_cause_metadata=176, native_tval_metadata=192,
                      native_control_metadata=208, native_hit_metadata=208)
    else:
        bounds.update(native_epc_metadata=160, native_cause_metadata=160, native_tval_metadata=176,
                      native_control_metadata=192, native_hit_metadata=192)
    return trace_bound, bounds


def safety_groups(scenario, goals, time_limit, property_bases=None):
    trace_bound, bounds = goal_bounds(scenario)
    remaining = set(goals)
    groups = []

    def add(labels, bound, engines, jobs, limit, per_property, first=1):
        selected = [label for label in labels if label in remaining]
        if selected:
            groups.append({"labels": selected, "bound": bound, "engines": engines,
                           "per_engine_max_jobs": jobs, "time_limit": limit,
                           "per_property_time_limit": per_property, "first_trace_attempt": first})
            remaining.difference_update(selected)

    dpc_limit = str(GROUP_PROBE_LIMITS["dpc"])
    initial_limit = str(min(time_limit, GROUP_PROBE_LIMITS["initial"]))
    group_limit = str(GROUP_PROBE_LIMITS["group"])
    property_limit = str(GROUP_PROBE_LIMITS["perProperty"])
    add(("abstract_dpc_value", "resume_pc_matches"), 112 if scenario == 0 else 128,
        "C I N", 2, dpc_limit, dpc_limit)
    add(("initial_dpc_zero",), 0, "C I N", 1, initial_limit, initial_limit)
    bases = property_bases or {}
    if scenario == 1:
        add(("target_first_event_is_breakpoint",), 160, "K", 1, group_limit, property_limit,
            bases.get("target_first_event_is_breakpoint", {}).get("firstTraceAttempt", 1))
        if bases:
            add(("older_load_retires_first",), trace_bound, "C I N B", 4, group_limit, property_limit,
                bases.get("older_load_retires_first", {}).get("firstTraceAttempt", 1))
    for bound in sorted({bounds[label] for label in remaining}):
        add([label for label in CORE_ASSERTIONS if bounds[label] == bound], bound,
            "C I N B", 4, group_limit, property_limit)
    return groups


def tcl_groups(groups):
    rows = []
    for group in groups:
        values = []
        for key, value in group.items():
            values.extend((key, "{" + (" ".join(value) if isinstance(value, list) else str(value)) + "}"))
        rows.append("{" + " ".join(values) + "}")
    return ("set proof_groups {" + " ".join(rows) + "}\n").encode()


def late_retry_groups(scenario=1, strategy=None):
    strategy = MULTIPLY_LATE_RETRY if strategy is None else strategy
    bounds = goal_bounds(scenario)[1]
    return [{"labels": [label], "bound": bounds[label],
             **{key: value for key, value in strategy.items() if key not in ("profile", "labels")}}
            for label in strategy["labels"]]


def fact_first_groups(scenario, goals):
    bounds = goal_bounds(scenario)[1]
    early = set(EARLY_PROOF_GOALS.get(scenario, ("no_external_event", "initial_dpc_zero")))
    groups = []
    for hard in (False, True):
        selected = [label for label in CORE_ASSERTIONS if label in goals and (label not in early) == hard]
        for bound in sorted({bounds[label] for label in selected}):
            groups.append({"labels": [label for label in selected if bounds[label] == bound],
                           "bound": bound, "engines": "C I N B" if hard else "C I N",
                           "per_engine_max_jobs": 4 if bound else 1,
                           "time_limit": "180" if hard else "60", "per_property_time_limit": "60",
                           "first_trace_attempt": 1})
    return groups


def load_property_base(path, label, index):
    if label not in ("target_first_event_is_breakpoint", "older_load_retires_first"):
        raise ValueError("Unexpected property base label")
    if type(index) is not int or index < 0:
        raise ValueError("Property base index differs")
    path = Path(path)
    prefix = f"base.{label}.{index}."
    archived = (path / (prefix + "plan.json")).is_file()

    def read(name):
        return (path / ((prefix if archived else "") + name)).read_bytes()

    plan = json.loads(read("plan.json"))
    receipt = json.loads(read("receipt.json"))
    completion = json.loads(read("completion.json"))
    native = read("native.tsv")
    if (plan.get("top") != CORE_TOP or type(plan.get("scenario")) is not int or plan["scenario"] != 1 or
            plan.get("mutation") is not None or plan.get("expected") != "proven" or
            label not in plan.get("goals", []) or
            plan.get("assumptions") != [CORE_TOP + ".no_later_cold_reset"] or
            type(plan.get("targetBounds", {}).get(label)) is not int or plan["targetBounds"][label] < 1):
        raise ValueError("Property base plan differs: " + label)
    inputs = plan.get("inputs", [])
    sources = plan.get("sources", [])
    if (not inputs or len(inputs) != len(set(inputs)) or not sources or len(sources) != len(set(sources)) or
            any(not isinstance(name, str) or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.-]*", name)
                for name in inputs) or not set(sources).issubset(inputs) or
            not {"collect.tcl", "plan.tcl"}.issubset(inputs)):
        raise ValueError("Property base input inventory differs: " + label)
    contents = {prefix + name: read(name) for name in plan["inputs"]}
    input_hashes = {name: sha(contents[prefix + name]) for name in plan["inputs"]}
    if (receipt.get("command") != ["jg", "-no_gui", "-fpv", "-tcl", "collect.tcl"] or
            receipt.get("inputHashes") != input_hashes or type(receipt.get("pid")) is not int or
            receipt["pid"] <= 0 or type(receipt.get("cpu")) is not int or receipt["cpu"] < 0 or
            type(receipt.get("timeoutSeconds")) is not int or receipt["timeoutSeconds"] < 1 or
            not re.fullmatch(r"[0-9a-f]{64}", receipt.get("launcherSha256", ""))):
        raise ValueError("Property base receipt differs: " + label)
    if (completion.get("timedOut") is not False or completion.get("inputsUnchanged") is not True or
            not re.fullmatch(r"[0-9a-f]{64}", completion.get("nativeExecutableSha256", "")) or
            completion.get("outputHashes", {}).get("native.tsv") != sha(native)):
        raise ValueError("Property base completion differs: " + label)
    records = read_records(path / ((prefix if archived else "") + "native.tsv"))
    group = "final." + label
    if (records.get((group, "name")) != CORE_TOP + "." + label or
            records.get((group, "type")) != "assert" or records.get((group, "command")) != "assert" or
            records.get((group, "expression")) != label or records.get((group, "disabled")) != "0" or
            records.get((group, "precondition")) != "0" or
            records.get((group, "run_status")) != "processed" or
            records.get(("before", "clock")) != "" or
            records.get(("before", "initial_common_cold_reset")) != "1" or
            records.get(("before", "reset_initial")) != "assume:0" or
            records.get(("before", "reset")) != EXPECTED_RESET or
            records.get(("before", "global")) != CORE_TOP + ".initial_common_cold_reset " +
            CORE_TOP + ".no_later_cold_reset" or
            records.get(("before", "assumptions")) != CORE_TOP + ".no_later_cold_reset" or
            records.get(("setup", "clock_mode")) != "free_running" or
            any(records.get(("setup", key)) != "0" for key in ("bbox_inst", "bbox_mod", "bbox_out", "stopat"))):
        raise ValueError("Property base native scope differs: " + label)
    before = "before." + label
    for key in ("name", "type", "command", "disabled", "expression", "precondition", "clock", "edge"):
        if records.get((before, key)) != records.get((group, key)):
            raise ValueError("Property base assertion identity changed: " + label)
    if (records.get((group, "clock")) not in (None, "", "clock") or
            records.get((group, "edge")) not in (None, "", "posedge")):
        raise ValueError("Property base assertion clock differs: " + label)
    if not re.fullmatch(r"[A-Za-z][A-Za-z0-9_]*", records.get((group, "engine"), "")):
        raise ValueError("Property base proof engine is missing: " + label)
    run_state = records.get(("run", "state"))
    after = {key: value for (tag, key), value in records.items() if tag == "after"}
    scope_basis = "native_before_after"
    audit = AUDITED_PROPERTY_BASES.get(sha(contents[prefix + "collect.tcl"]), {})
    if (audit.get("label") != label or audit.get("planSha256") != sha(read("plan.json")) or
            audit.get("planTclSha256") != sha(contents[prefix + "plan.tcl"]) or
            plan.get("proofSeed") is not None or any(name.endswith(".jdb") for name in inputs) or
            b"proof_seed" in contents[prefix + "plan.tcl"]):
        raise ValueError("Property base collector audit differs: " + label)
    if not after:
        scope_basis = "frozen_collector_audit"
    elif any(after.get(key) != records.get(("before", key))
             for key in ("clock", "reset", "global", "reset_initial",
                         "initial_common_cold_reset", "assumptions")):
        raise ValueError("Property base proof scope changed: " + label)
    if run_state == "complete":
        if (completion.get("exitStatus") != 0 or
                not after):
            raise ValueError("Property base did not complete cleanly: " + label)
    elif run_state == "failed":
        if completion.get("exitStatus") != 1:
            raise ValueError("Property base failure status differs: " + label)
    else:
        raise ValueError("Property base run state is missing: " + label)
    verdict = records.get((group, "validity_status"))
    if verdict not in ("undetermined", "bounded_proven_user"):
        raise ValueError("Property base is not a bounded segment: " + label)
    if not re.fullmatch(r"[0-9]+", records.get((group, "min_length"), "")):
        raise ValueError("Property base min_length is missing: " + label)
    minimum = int(records[(group, "min_length")])
    target_bound = plan["targetBounds"][label]
    if verdict == "bounded_proven_user" and records.get((group, "target_bound")) != str(target_bound):
        raise ValueError("Property base target bound differs: " + label)
    if minimum < target_bound and run_state == "complete":
        raise ValueError("Property base completed below its bound: " + label)
    collector = contents[prefix + "collect.tcl"].decode()
    attempts = re.findall(r"-first_trace_attempt\s+([0-9]+)", collector)
    if len(attempts) > 1 or collector.count("-first_trace_attempt") != len(attempts):
        raise ValueError("Property base has ambiguous first attempts: " + label)
    first_attempt = int(attempts[0]) if attempts else 1
    if first_attempt != audit["firstTraceAttempt"]:
        raise ValueError("Property base audited first attempt differs: " + label)
    next_attempt = min(minimum, target_bound)
    if first_attempt < 1 or next_attempt <= first_attempt:
        raise ValueError("Property base attempt chain is inconsistent: " + label)
    for name in ("native.tsv", "receipt.json", "completion.json", "plan.json"):
        contents[prefix + name] = read(name)
    info = {"label": label, "index": index, "sources": sources, "firstTraceAttempt": first_attempt,
            "nextTraceAttempt": next_attempt, "minLength": minimum, "targetBound": target_bound,
            "engine": records.get((group, "engine"), "PRE"), "verdict": verdict,
            "scopeBasis": scope_basis,
            "native": prefix + "native.tsv", "nativeSha256": sha(native),
            "receipt": prefix + "receipt.json", "receiptSha256": sha(read("receipt.json")),
            "completion": prefix + "completion.json", "completionSha256": sha(read("completion.json")),
            "plan": prefix + "plan.json", "planSha256": sha(read("plan.json")),
            "inputMap": {name: prefix + name for name in plan["inputs"]}, "inputHashes": input_hashes}
    return info, contents


def case_definition(name, unit, core, wrappers, collectors, unit_time_limit, core_time_limit, proof_seed=None,
                    scenario_proof_seeds=None, property_bases=None, retry_cases=SAFETY_RETRY_CASES,
                    flow="retry", source_configuration="native"):
    if flow not in ("retry", "staged"):
        raise ValueError("Unsupported trigger safety flow")
    top = UNIT_TOP if name.startswith("unit") or NEGATIVE_TARGETS.get(name, (None,))[0] == UNIT_TOP else CORE_TOP
    rtl = dict(unit if top == UNIT_TOP else core)
    wrapper_name = UNIT_WRAPPER if top == UNIT_TOP else CORE_WRAPPER
    scenario = CORE_NEGATIVE_SCENARIOS.get(name)
    if scenario is None:
        scenario = next((index for index, label in enumerate(CORE_NAMES)
                         if name in (f"core-{label}-safety", f"core-{label}-covers")), None)
    if name in ("core-dpc-safety", "core-dpc-covers"):
        scenario = 0
    if name in NEGATIVE_TARGETS:
        rtl = mutate(rtl, name)
        goals = [NEGATIVE_TARGETS[name][1]]
        covers = []
        expected = "cex"
    else:
        goals = list(UNIT_ASSERTIONS if top == UNIT_TOP else CORE_ASSERTIONS) if name.endswith("safety") else []
        covers = ([CORE_DPC_COVER, *CORE_RESET_COVERS] if name == "core-dpc-covers" else
                  list(UNIT_COVERS if top == UNIT_TOP else [CORE_COVERS[scenario]]) if name.endswith("covers") else [])
        expected = "proven"
    safety_role = ("multiply_safety" if property_bases else "multiply_retry") if name == "core-multiply-safety" else "safety"
    if name in retry_cases and not property_bases:
        safety_role = "safety_retry"
    role = ("negative_older" if name == "negative-older-priority" else
            "legacy" if top == UNIT_TOP else safety_role if name.endswith("safety") else "trace")
    if flow == "staged" and name in SAFETY_RETRY_CASES:
        if proof_seed or scenario_proof_seeds or property_bases:
            raise ValueError("Staged safety cannot import proof seeds or property bases")
        role = "staged"
    trace_bound, bounds = goal_bounds(scenario)
    time_limit = unit_time_limit if top == UNIT_TOP else core_time_limit
    contents = dict(rtl)
    contents[wrapper_name] = wrappers[top]
    contents["collect.tcl"] = collectors[role]
    plan = {
        "top": top, "sources": [*rtl, wrapper_name], "goals": goals, "covers": covers,
        "expected": expected, "assumptions": [top + ".no_later_cold_reset"],
        "timeLimitSeconds": time_limit, "scenario": scenario,
        "mutation": name if name in NEGATIVE_TARGETS else None,
        "negativeTarget": goals[0] if expected == "cex" else None,
        "proofMode": "unbounded_commercial",
    }
    if top == CORE_TOP:
        plan["initialState"] = dict(CORE_INITIAL_STATE)
    if role == "staged":
        return staged.build(plan, contents, collectors["staged"], collectors["staged_helpers"], source_configuration)
    extra_tcl = b""
    if role in ("safety", "multiply_safety", "multiply_retry", "safety_retry"):
        plan.update(proofMode="bounded_commercial", traceBound=trace_bound, targetBounds=bounds,
                    engineMode="{C I N B}", dpcEngineMode="{C I N}", usesProvenDirectives=True,
                    proofStrategy=dict(GROUP_PROBE_STRATEGY),
                    boundedScope="no counterexample through each assertion targetBound")
        plan["targetFirstTimeLimitSeconds"] = 2400
        extra_tcl += f"set trace_bound {trace_bound}\nset target_first_time_limit {plan['targetFirstTimeLimitSeconds']}\n".encode()
        selected_seed = proof_seed if name in ("core-store-safety", "core-dpc-safety") else None
        seed_name = "proof_seed.jdb"
        if selected_seed is None and scenario_proof_seeds and name.endswith("safety"):
            selected_seed = scenario_proof_seeds.get(scenario)
            if selected_seed is not None:
                seed_name = f"proof_seed_scenario{scenario}.jdb"
        if selected_seed is not None:
            contents[seed_name] = selected_seed
            plan["proofSeed"] = {"file": seed_name, "sha256": sha(selected_seed)}
            extra_tcl += f"set proof_seed {seed_name}\n".encode()
        attempts = {"target_first_event_is_breakpoint": 1, "older_load_retires_first": 1}
        if property_bases:
            if name != "core-multiply-safety":
                raise ValueError("Property bases belong only to the multiply scenario")
            plan["segmentedProof"] = True
            plan["propertyBases"] = {}
            for label, segments in property_bases.items():
                if label not in attempts or label not in goals or not segments:
                    raise ValueError("Unexpected property base: " + label)
                previous = 1
                infos = []
                for index, (info, base_contents) in enumerate(segments):
                    if (info["label"] != label or info["index"] != index or
                            info["firstTraceAttempt"] != previous):
                        raise ValueError("Property base chain has a gap: " + label)
                    if info["sources"] != plan["sources"]:
                        raise ValueError("Property base compiled source list differs: " + label)
                    contents.update(base_contents)
                    for source in plan["sources"]:
                        archived = info["inputMap"].get(source)
                        if archived is None or contents[archived] != contents[source]:
                            raise ValueError("Property base design input differs: " + label + "/" + source)
                    infos.append(info)
                    previous = info["nextTraceAttempt"]
                if previous <= 1:
                    raise ValueError("Property base chain is empty: " + label)
                attempts[label] = previous
                plan["propertyBases"][label] = {"firstTraceAttempt": previous, "segments": infos}
        if role == "multiply_safety":
            extra_tcl += (f"set target_first_attempt {attempts['target_first_event_is_breakpoint']}\n"
                          f"set older_first_attempt {attempts['older_load_retires_first']}\n").encode()
        plan["proofGroups"] = safety_groups(scenario, goals, core_time_limit, plan.get("propertyBases"))
        if role == "safety_retry":
            plan["proofGroups"] = fact_first_groups(scenario, goals)
            plan["proofStrategy"] = {**GROUP_PROBE_STRATEGY, "profile": "fact_first_with_late_retry"}
        extra_tcl += tcl_groups(plan["proofGroups"])
        if role in ("multiply_retry", "safety_retry"):
            plan["lateRetry"] = dict(SAFETY_LATE_RETRY if role == "safety_retry" else MULTIPLY_LATE_RETRY)
            extra_tcl += tcl_groups(late_retry_groups(scenario, plan["lateRetry"])).replace(
                b"set proof_groups", b"set retry_groups", 1)
    elif role in ("trace", "negative_older"):
        plan.update(proofMode="trace_commercial", traceBound=trace_bound, stageBound=128,
                    stageTimeLimitSeconds=240, usesResumePrefix=True,
                    traceScope="linked covered or cex trace including the resume and load-accepted prefixes")
        if role == "negative_older":
            plan["directJoint"] = True
        extra_tcl += (f"set trace_bound {trace_bound}\nset stage_bound 128\n"
                      f"set stage_time_limit {plan['stageTimeLimitSeconds']}\n").encode()
    contents["plan.tcl"] = tcl_plan(plan) + extra_tcl + (f"set scenario {scenario}\n".encode() if scenario is not None else b"")
    plan["inputs"] = sorted(contents)
    return plan, contents


def check_proof_seed(path):
    labels = ["abstract_dpc_value", "resume_pc_matches", "initial_dpc_zero"]
    plan = {"top": CORE_TOP, "assumptions": [CORE_TOP + ".no_later_cold_reset"], "goals": labels,
            "covers": [], "expected": "proven", "proofMode": "unbounded_commercial"}
    records = read_records(path)
    check_native_records(records, plan)
    for label in labels:
        group = "final." + label
        if (records.get((group, "min_length")) != "infinite" or
                records.get((group, "target_bound")) != "0"):
            raise ValueError("Proof seed is not an unbounded native proof: " + label)


def prepare(args):
    if any(getattr(args, name, None) is not None
           for name in ("proof_seed", "proof_seed_scenario2", "proof_seed_scenario3")):
        raise ValueError("Implemented cold-reset proofs require fresh matching design inputs; external seeds are unsupported")
    flow = getattr(args, "flow", "retry")
    source_configuration = getattr(args, "staged_configuration", "native")
    if flow not in ("retry", "staged"):
        raise ValueError("Unsupported trigger safety flow")
    staged_files = {name: (HERE / name).read_bytes() for name in staged.FILES}
    staged.check_collectors(staged_files)
    if flow == "staged":
        staged.configuration(source_configuration)
        if getattr(args, "retry_case", []):
            raise ValueError("Retry case selection cannot change the staged safety flow")
    requested = getattr(args, "retry_case", [])
    requested_retry = {f"core-{name}-safety" for name in requested} if requested else set(SAFETY_RETRY_CASES)
    retry_cases = tuple(name for name in CASES if name in requested_retry) if flow == "retry" else ()
    unit_build, unit = load_rtl(args.unit_rtl, "DitDahE2Trigger", False, args.source_root)
    core_build, core = load_rtl(args.core_rtl, "DitDahE2", True, args.source_root)
    unit_wrapper, core_wrapper = check_wrappers()
    wrappers = {UNIT_TOP: unit_wrapper, CORE_TOP: core_wrapper}
    collectors = {role: (HERE / filename).read_bytes() for role, filename in
                  (("legacy", "collect.tcl"), ("safety", "collect_safety.tcl"),
                   ("multiply_safety", MULTIPLY_COLLECTOR), ("trace", "collect_trace.tcl"),
                   ("multiply_retry", MULTIPLY_RETRY_COLLECTOR),
                   ("safety_retry", SAFETY_RETRY_COLLECTOR),
                   ("negative_older", "collect_negative_older.tcl"))}
    if staged_files:
        collector_name, helper_name = staged.artifacts(source_configuration if flow == "staged" else "native")
        collectors.update(staged=staged_files[collector_name], staged_helpers=staged_files[helper_name])
    check_core_reset_collectors(collectors)
    runner = Path(__file__).read_bytes()
    transport = {name: Path(module.__file__).read_bytes()
                 for name, module in zip(TRANSPORT_FILES, TRANSPORT_MODULES, strict=True)}
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    output.chmod(0o700)
    proof_seed = args.proof_seed.read_bytes() if args.proof_seed else None
    if proof_seed is not None:
        (output / "proof_seed.jdb").write_bytes(proof_seed)
    scenario_proof_seeds = {}
    scenario_seed_info = {}
    for scenario in (2, 3):
        source = getattr(args, f"proof_seed_scenario{scenario}")
        if source is None:
            continue
        source_native = source.resolve().with_suffix(".tsv")
        check_proof_seed(source_native)
        value = source.read_bytes()
        seed_name = f"proof_seed_scenario{scenario}.jdb"
        native_name = f"proof_seed_scenario{scenario}.tsv"
        (output / seed_name).write_bytes(value)
        (output / native_name).write_bytes(source_native.read_bytes())
        scenario_proof_seeds[scenario] = value
        scenario_seed_info[str(scenario)] = {
            "file": seed_name, "sha256": sha(value), "nativeEvidence": native_name,
            "nativeSha256": digest(source_native), "sourceCommand": "jg -no_gui -fpv -tcl collect.tcl",
            "sourceScope": "abstract_dpc_value, resume_pc_matches and initial_dpc_zero unbounded proofs",
            "sourceNative": str(source_native.relative_to(ROOT)),
        }
    property_bases = {}
    for label, attribute in (("target_first_event_is_breakpoint", "multiply_target_base"),
                             ("older_load_retires_first", "multiply_older_base")):
        paths = getattr(args, attribute) or []
        if paths:
            property_bases[label] = [load_property_base(path, label, index)
                                     for index, path in enumerate(paths)]
    for directory, contents in (("unit-rtl", unit), ("core-rtl", core)):
        (output / directory).mkdir()
        for name, value in contents.items():
            (output / directory / name).write_bytes(value)
    for name, value in ((UNIT_WRAPPER, unit_wrapper), (CORE_WRAPPER, core_wrapper),
                        ("collect.tcl", collectors["legacy"]), ("collect_safety.tcl", collectors["safety"]),
                        (MULTIPLY_COLLECTOR, collectors["multiply_safety"]),
                        (MULTIPLY_RETRY_COLLECTOR, collectors["multiply_retry"]),
                        (SAFETY_RETRY_COLLECTOR, collectors["safety_retry"]),
                        ("collect_trace.tcl", collectors["trace"]),
                        ("collect_negative_older.tcl", collectors["negative_older"]), ("runner.py", runner)):
        (output / name).write_bytes(value)
    for name, value in staged_files.items():
        (output / name).write_bytes(value)
    for name, value in transport.items():
        (output / name).parent.mkdir(parents=True, exist_ok=True)
        (output / name).write_bytes(value)
    (output / "unit-build.json").write_text(json.dumps(unit_build, indent=2, sort_keys=True) + "\n")
    (output / "core-build.json").write_text(json.dumps(core_build, indent=2, sort_keys=True) + "\n")
    manifest = {
        "schema": SCHEMA, "cases": list(CASES), "timeLimitSeconds": args.time_limit,
        "coreTimeLimitSeconds": args.core_time_limit, "stageTimeLimitSeconds": 240,
        "targetFirstTimeLimitSeconds": 2400, "safetyProofStrategy": dict(GROUP_PROBE_STRATEGY),
        "unitRtlHashes": {name: sha(value) for name, value in unit.items()},
        "coreRtlHashes": {name: sha(value) for name, value in core.items()},
        "verificationHashes": {UNIT_WRAPPER: sha(unit_wrapper), CORE_WRAPPER: sha(core_wrapper),
                               "collect.tcl": sha(collectors["legacy"]), "collect_safety.tcl": sha(collectors["safety"]),
                               MULTIPLY_COLLECTOR: sha(collectors["multiply_safety"]),
                               MULTIPLY_RETRY_COLLECTOR: sha(collectors["multiply_retry"]),
                               SAFETY_RETRY_COLLECTOR: sha(collectors["safety_retry"]),
                               "collect_trace.tcl": sha(collectors["trace"]),
                               "collect_negative_older.tcl": sha(collectors["negative_older"]), "run.py": sha(runner),
                               **{name: sha(value) for name, value in transport.items()}},
        "proofMode": "mixed_commercial", "fullCoreProven": False,
        "coreInitialState": dict(CORE_INITIAL_STATE),
        "retryCases": list(retry_cases),
        "boundedScope": "core assertions are proven or bounded_proven_user at their declared per-property bounds",
        "traceScope": "all covers and negative controls require linked native traces",
        "scope": "standalone trigger bank and four fixed native programs on the complete core",
    }
    if flow == "staged":
        manifest.update(flow=flow, stagedConfiguration=staged.configuration(source_configuration),
                        safetyProofStrategy=staged.strategy(source_configuration), caseInputHashes={}, casePlanHashes={})
    manifest["verificationHashes"].update({name: sha(value) for name, value in staged_files.items()})
    if proof_seed is not None:
        source_native = args.proof_seed.resolve().with_suffix(".tsv")
        manifest["verificationHashes"]["proof_seed.jdb"] = sha(proof_seed)
        manifest["proofSeed"] = {"file": "proof_seed.jdb", "sha256": sha(proof_seed),
                                 "sourceCommand": "jg -no_gui -fpv -tcl collect.tcl",
                                 "sourceScope": "abstract_dpc_value unbounded proof",
                                 "sourceNative": str(source_native.relative_to(ROOT)),
                                 "sourceNativeSha256": digest(source_native)}
    if scenario_seed_info:
        manifest["scenarioProofSeeds"] = scenario_seed_info
        for info in scenario_seed_info.values():
            for key in ("file", "nativeEvidence"):
                manifest["verificationHashes"][info[key]] = info["sha256" if key == "file" else "nativeSha256"]
    case_modes, case_bounds = {}, {}
    for name in CASES:
        case = output / "cases" / name
        case.mkdir(parents=True)
        plan, contents = case_definition(name, unit, core, wrappers, collectors,
                                         args.time_limit, args.core_time_limit, proof_seed, scenario_proof_seeds,
                                         property_bases if name == "core-multiply-safety" else None, retry_cases, flow, source_configuration)
        for filename, value in contents.items():
            (case / filename).write_bytes(value)
        write_json(case / "plan.json", plan)
        if flow == "staged":
            manifest["caseInputHashes"][name] = {filename: sha(value) for filename, value in contents.items()}
            manifest["casePlanHashes"][name] = digest(case / "plan.json")
        if name == "core-multiply-safety" and plan.get("propertyBases"):
            manifest["segmentedProofs"] = plan["propertyBases"]
        case_modes[name] = plan["proofMode"]
        case_bounds[name] = {key: plan[key] for key in ("traceBound", "targetBounds", "stageBound") if key in plan}
    manifest["caseProofModes"] = case_modes
    manifest["caseBounds"] = case_bounds
    write_json(output / "manifest.json", manifest)
    return manifest


def validate_frozen(evidence):
    manifest = json.loads((evidence / "manifest.json").read_text())
    flow = manifest.get("flow", "retry")
    if flow not in ("retry", "staged"):
        raise ValueError("Frozen trigger safety flow differs")
    source_configuration = "native"
    if flow == "staged":
        source_configuration = manifest.get("stagedConfiguration", {}).get("name")
        if manifest.get("stagedConfiguration") != staged.configuration(source_configuration):
            raise ValueError("Frozen staged source configuration differs")
    for name in staged.FILES:
        if (digest(evidence / name) != manifest["verificationHashes"].get(name) or
                digest(HERE / name) != manifest["verificationHashes"].get(name)):
            raise ValueError("Frozen staged verification source differs")
    staged.check_collectors({name: (evidence / name).read_bytes() for name in staged.FILES})
    retry_cases = manifest.get("retryCases")
    allowed_retry = {name for name in CASES if name.startswith("core-") and name.endswith("safety")}
    if (not isinstance(retry_cases, list) or (flow == "staged" and retry_cases) or not set(retry_cases).issubset(allowed_retry) or
            retry_cases != [name for name in CASES if name in retry_cases]):
        raise ValueError("Frozen retry profile selection differs")
    if (manifest.get("schema") != SCHEMA or manifest.get("cases") != list(CASES) or
            manifest.get("proofMode") != "mixed_commercial" or manifest.get("fullCoreProven") is not False or
            manifest.get("coreInitialState") != CORE_INITIAL_STATE or
            type(manifest.get("timeLimitSeconds")) is not int or manifest["timeLimitSeconds"] < 1 or
            type(manifest.get("coreTimeLimitSeconds")) is not int or manifest["coreTimeLimitSeconds"] < 1 or
            manifest.get("stageTimeLimitSeconds") != 240 or manifest.get("targetFirstTimeLimitSeconds") != 2400 or
            manifest.get("safetyProofStrategy") != (staged.strategy(source_configuration) if flow == "staged" else GROUP_PROBE_STRATEGY)):
        raise ValueError("Frozen proof manifest differs")
    if manifest.get("proofSeed") is not None or manifest.get("scenarioProofSeeds"):
        raise ValueError("Implemented cold-reset proof bundles cannot restore external proof seeds")
    if digest(Path(__file__)) != manifest["verificationHashes"].get("run.py"):
        raise ValueError("Running verifier differs from frozen verifier")
    for name in (UNIT_WRAPPER, CORE_WRAPPER, "collect.tcl", "collect_safety.tcl", MULTIPLY_COLLECTOR, MULTIPLY_RETRY_COLLECTOR,
                 SAFETY_RETRY_COLLECTOR,
                 "collect_trace.tcl", "collect_negative_older.tcl", "runner.py"):
        key = "run.py" if name == "runner.py" else name
        if digest(evidence / name) != manifest["verificationHashes"].get(key):
            raise ValueError("Frozen verification source differs")
    for name, module in zip(TRANSPORT_FILES, TRANSPORT_MODULES, strict=True):
        if digest(evidence / name) != manifest["verificationHashes"].get(name):
            raise ValueError("Frozen transport verifier differs")
        if digest(Path(module.__file__)) != manifest["verificationHashes"].get(name):
            raise ValueError("Running transport verifier differs from the frozen dependency")
    proof_seed = None
    if manifest.get("proofSeed") is not None:
        seed_info = manifest["proofSeed"]
        if (seed_info.get("file") != "proof_seed.jdb" or
                seed_info.get("sha256") != manifest["verificationHashes"].get("proof_seed.jdb") or
                digest(evidence / "proof_seed.jdb") != seed_info["sha256"]):
            raise ValueError("Frozen proof seed differs")
        proof_seed = (evidence / "proof_seed.jdb").read_bytes()
    scenario_proof_seeds = {}
    for scenario, seed_info in manifest.get("scenarioProofSeeds", {}).items():
        if scenario not in ("2", "3"):
            raise ValueError("Unexpected proof seed scenario")
        seed_name = f"proof_seed_scenario{scenario}.jdb"
        native_name = f"proof_seed_scenario{scenario}.tsv"
        if (seed_info.get("file") != seed_name or seed_info.get("nativeEvidence") != native_name or
                seed_info.get("sha256") != manifest["verificationHashes"].get(seed_name) or
                seed_info.get("nativeSha256") != manifest["verificationHashes"].get(native_name) or
                digest(evidence / seed_name) != seed_info["sha256"] or
                digest(evidence / native_name) != seed_info["nativeSha256"]):
            raise ValueError("Frozen scenario proof seed differs")
        check_proof_seed(evidence / native_name)
        scenario_proof_seeds[int(scenario)] = (evidence / seed_name).read_bytes()
    unit = {name: (evidence / "unit-rtl" / name).read_bytes() for name in manifest["unitRtlHashes"]}
    core = {name: (evidence / "core-rtl" / name).read_bytes() for name in manifest["coreRtlHashes"]}
    for contents, expected in ((unit, manifest["unitRtlHashes"]), (core, manifest["coreRtlHashes"])):
        if {name: sha(value) for name, value in contents.items()} != expected:
            raise ValueError("Frozen RTL input differs")
    wrappers = {UNIT_TOP: (evidence / UNIT_WRAPPER).read_bytes(),
                CORE_TOP: (evidence / CORE_WRAPPER).read_bytes()}
    collectors = {role: (evidence / filename).read_bytes() for role, filename in
                  (("legacy", "collect.tcl"), ("safety", "collect_safety.tcl"),
                   ("multiply_safety", MULTIPLY_COLLECTOR), ("trace", "collect_trace.tcl"),
                   ("multiply_retry", MULTIPLY_RETRY_COLLECTOR),
                   ("safety_retry", SAFETY_RETRY_COLLECTOR),
                   ("negative_older", "collect_negative_older.tcl"))}
    if flow == "staged":
        collector_name, helper_name = staged.artifacts(source_configuration)
        collectors.update(staged=(evidence / collector_name).read_bytes(),
                          staged_helpers=(evidence / helper_name).read_bytes())
    check_core_reset_collectors(collectors)
    case_modes, case_bounds = {}, {}
    segmented_proofs = None
    for name in CASES:
        case = evidence / "cases" / name
        property_bases = None
        if name == "core-multiply-safety":
            property_bases = {}
            previous_plan = json.loads((case / "plan.json").read_text())
            for label, bundle in previous_plan.get("propertyBases", {}).items():
                segments = []
                for info in bundle["segments"]:
                    loaded = load_property_base(case, label, info["index"])
                    if loaded[0] != info:
                        raise ValueError("Frozen property base differs: " + label)
                    segments.append(loaded)
                property_bases[label] = segments
        plan, contents = case_definition(name, unit, core, wrappers, collectors,
                                         manifest["timeLimitSeconds"], manifest["coreTimeLimitSeconds"], proof_seed,
                                         scenario_proof_seeds, property_bases, tuple(retry_cases), flow, source_configuration)
        if json.loads((case / "plan.json").read_text()) != plan:
            raise ValueError("Frozen native plan differs")
        if flow == "staged" and (manifest.get("caseInputHashes", {}).get(name) !=
                {filename: sha(value) for filename, value in contents.items()} or
                manifest.get("casePlanHashes", {}).get(name) != digest(case / "plan.json")):
            raise ValueError("Frozen staged plan or native input hashes differ")
        for filename, value in contents.items():
            if (case / filename).read_bytes() != value:
                raise ValueError("Frozen native input differs")
        if name == "core-multiply-safety":
            segmented_proofs = plan.get("propertyBases")
        case_modes[name] = plan["proofMode"]
        case_bounds[name] = {key: plan[key] for key in ("traceBound", "targetBounds", "stageBound") if key in plan}
    if manifest.get("caseProofModes") != case_modes or manifest.get("caseBounds") != case_bounds:
        raise ValueError("Frozen proof scope differs")
    if manifest.get("segmentedProofs") != segmented_proofs:
        raise ValueError("Frozen segmented proof manifest differs")
    return manifest


def record_int(records, group, key):
    value = records.get((group, key))
    if not isinstance(value, str) or not re.fullmatch(r"[0-9]+", value):
        raise ValueError("Native numeric metadata is missing: " + group + "." + key)
    return int(value)


def trace_evidence(records, group, expected):
    if records.get((group, "validity_status")) != expected:
        raise ValueError("Native trace verdict differs: " + group)
    engine = records.get((group, "latest_trace_engine"))
    if not engine or engine == "?" or record_int(records, group, "trace_length") < 1:
        raise ValueError("Native linked trace is missing: " + group)
    return {"verdict": expected, "engine": records.get((group, "engine"), engine),
            "traceEngine": engine, "traceLength": record_int(records, group, "trace_length"),
            "targetBound": records.get((group, "target_bound"), "0")}


def check_late_retry(records, plan):
    strategy = plan.get("lateRetry")
    if strategy not in (MULTIPLY_LATE_RETRY, SAFETY_LATE_RETRY):
        raise ValueError("Late retry plan differs")

    def identity(tag, label):
        expected = {"name": CORE_TOP + "." + label, "type": "assert", "command": "assert",
                    "disabled": "0", "expression": label, "precondition": "0"}
        if any(records.get((tag, key)) != value for key, value in expected.items()):
            raise ValueError("Late retry assertion identity differs: " + label)

    selected = []
    for label in strategy["labels"]:
        tag = "retry.candidate." + label
        identity(tag, label)
        if records.get((tag, "validity_status")) == "undetermined":
            bound = plan["targetBounds"][label]
            if bound == 0 or record_int(records, tag, "min_length") < bound:
                selected.append(label)
    if records.get(("retry", "selected_labels")) != " ".join(selected):
        raise ValueError("Late retry selection differs")
    for label in plan["goals"]:
        identity("attempt.1.before." + label, label)
        identity("attempt.1.after." + label, label)
        if records.get(("attempt.1.after." + label, "validity_status")) == "cex":
            raise ValueError("A first-round counterexample cannot be hidden by a later verdict")
    facts = {}
    schedule = {group["labels"][0]: group for group in late_retry_groups(plan["scenario"], strategy)}
    for index, label in enumerate(selected, len(plan["proofGroups"]) + 1):
        for key, value in {**schedule[label], "round": 2}.items():
            expected = " ".join(value) if isinstance(value, list) else str(value)
            if records.get((f"group.{index}", key)) != expected:
                raise ValueError("Late retry scheduling metadata differs")
        identity("attempt.2.before." + label, label)
        identity("attempt.2.after." + label, label)
        if records.get(("attempt.2.after." + label, "validity_status")) == "cex":
            raise ValueError("A retry counterexample cannot be hidden by a later verdict")
        proven = records.get((f"group.{index}", "unbounded_facts"), "").split()
        if len(proven) != len(set(proven)) or not set(proven).issubset(plan["goals"]):
            raise ValueError("Late retry unbounded fact inventory differs")
        for fact in proven:
            tag = f"lemma.{index}." + fact
            identity(tag, fact)
            if (records.get((tag, "validity_status")) != "proven" or
                    records.get((tag, "run_status")) != "processed" or
                    records.get((tag, "min_length")) != "infinite" or
                    records.get((tag, "target_bound")) != "0"):
                raise ValueError("Late retry used an unproven fact")
        facts[label] = proven
    return {"selectedLabels": selected, "unboundedFacts": facts}


def check_native_records(records, plan):
    if plan.get("stagedConfiguration") is not None or plan.get("proofStrategy", {}).get("profile") == staged.PROFILE:
        return staged.check_native_records(records, plan)
    if (records.get(("before", "initial_common_cold_reset")) != "1" or
            records.get(("after", "initial_common_cold_reset")) != "1"):
        raise ValueError("Native initial cold reset assumption is missing")
    if records.get(("before", "reset_initial")) != "assume:0" or records.get(("after", "reset_initial")) != "assume:0":
        raise ValueError("Native reset_initial metadata differs")
    if records.get(("before", "reset")) != EXPECTED_RESET or records.get(("after", "reset")) != EXPECTED_RESET:
        raise ValueError("Native reset declaration metadata differs")
    expected_global = " ".join([plan["top"] + ".initial_common_cold_reset", *plan["assumptions"]])
    if records.get(("before", "global")) != expected_global or records.get(("after", "global")) != expected_global:
        raise ValueError("Native global embedded assumption set differs")
    records = dict(records)
    records[("before", "global")] = ""
    records[("after", "global")] = ""
    records[("before", "reset_assumptions")] = ""
    records[("after", "reset_assumptions")] = ""
    evidence = {}
    unbounded_goals = bounded_goals = 0
    if plan.get("proofMode") == "bounded_commercial":
        if plan.get("proofGroups") is not None:
            groups = (fact_first_groups(plan["scenario"], plan["goals"])
                      if plan.get("lateRetry") == SAFETY_LATE_RETRY else
                      safety_groups(plan["scenario"], plan["goals"], plan["timeLimitSeconds"],
                                    plan.get("propertyBases")))
            if plan["proofGroups"] != groups:
                raise ValueError("Native proof group plan differs")
            for index, group in enumerate(groups, 1):
                for key, value in group.items():
                    expected = " ".join(value) if isinstance(value, list) else str(value)
                    if records.get((f"group.{index}", key)) != expected:
                        raise ValueError("Native grouped proof strategy differs")
        elif plan.get("proofStrategy") == SAFETY_STRATEGY:
            groups = {
                1: {"bound": str(plan["targetBounds"]["abstract_dpc_value"]), "engines": "C I N",
                    "per_engine_max_jobs": "2", "time_limit": "2400", "per_property_time_limit": "2400"},
                2: {"bound": "0", "engines": "C I N", "per_engine_max_jobs": "1",
                    "time_limit": str(plan["timeLimitSeconds"]) + "s",
                    "per_property_time_limit": str(plan["timeLimitSeconds"]) + "s"},
                3: {"bound": str(plan["traceBound"]), "engines": "C I N B", "per_engine_max_jobs": "4",
                    "time_limit": "7200", "per_property_time_limit": "2400"},
            }
            if plan.get("scenario") == 1:
                groups[4] = groups[3]
                groups[3] = {"bound": "160", "engines": "K", "per_engine_max_jobs": "1",
                             "time_limit": "2400", "per_property_time_limit": "2400"}
            if plan.get("segmentedProof"):
                bases = plan.get("propertyBases", {})
                groups = {
                    1: groups[1], 2: groups[2],
                    3: {"bound": "160", "engines": "K", "per_engine_max_jobs": "1",
                        "time_limit": "2400", "per_property_time_limit": "2400"},
                    4: {"bound": str(plan["targetBounds"]["older_load_retires_first"]), "engines": "C I N B",
                        "per_engine_max_jobs": "4", "time_limit": "7200", "per_property_time_limit": "2400"},
                    5: groups[4],
                }
                for group, expected in groups.items():
                    expected["first_trace_attempt"] = "1"
                for group, label in ((3, "target_first_event_is_breakpoint"), (4, "older_load_retires_first")):
                    expected = groups[group]
                    expected["first_trace_attempt"] = str(
                        bases.get(label, {}).get("firstTraceAttempt", 1))
            for group, expected in groups.items():
                for key, value in expected.items():
                    if records.get((f"group.{group}", key)) != value:
                        raise ValueError("Native grouped proof strategy differs")
        for label in plan["goals"]:
            final = "final." + label
            verdict = records.get((final, "validity_status"))
            if verdict == "proven":
                evidence[label] = {"verdict": "proven", "engine": records.get((final, "engine"), "PRE"),
                                   "minLength": records.get((final, "min_length"), "infinite"),
                                   "targetBound": records.get((final, "target_bound"), "0")}
                unbounded_goals += 1
                if label in plan.get("propertyBases", {}):
                    evidence[label]["proofComposition"] = plan["propertyBases"][label]
                continue
            bounded = "bounded." + label
            bound = plan["targetBounds"][label]
            if (bound == 0 or verdict != "undetermined" or
                    records.get((bounded, "validity_status")) != "bounded_proven_user" or
                    record_int(records, bounded, "target_bound") != bound or
                    record_int(records, bounded, "min_length") < bound):
                raise ValueError("Native bounded proof is incomplete: " + label)
            evidence[label] = {"verdict": "bounded_proven_user",
                               "engine": records.get((bounded, "engine"), "unknown"),
                               "minLength": record_int(records, bounded, "min_length"),
                               "targetBound": bound}
            bounded_goals += 1
            if label in plan.get("propertyBases", {}):
                evidence[label]["proofComposition"] = plan["propertyBases"][label]
            records[(final, "validity_status")] = "proven"
    lemma_evidence = {}
    stage_evidence = {}
    if plan.get("proofMode") == "trace_commercial":
        for label in plan["goals"]:
            evidence[label] = trace_evidence(records, "final." + label, "cex")
        for label in plan["covers"]:
            evidence[label] = trace_evidence(records, "cover." + label, "covered")
        stages = ["cover_resume_dpc"]
        if plan["scenario"] == 3:
            if plan.get("directJoint"):
                stages.append("cover_older_load_accepted")
            elif plan["covers"] or "older_fault_blocks_target" in plan["goals"]:
                stages.append("cover_older_fault_event")
        elif plan["covers"] and plan["covers"][0] != "cover_resume_dpc":
            stages.extend(("cover_target_breakpoint", "cover_native_epc", "cover_native_cause",
                           "cover_native_tval", "cover_native_control", "cover_native_hit"))
            if plan["scenario"] == 1:
                stages.extend(("cover_multiply_start", "cover_multiply_done"))
            if plan["scenario"] <= 1:
                stages.append("cover_target_normal")
            if plan["scenario"] == 1:
                stages.append("cover_multiply_value")
            stages.append("cover_completion")
        for label in stages:
            stage_evidence[label] = trace_evidence(records, "stage." + label, "covered")
    result = check_records(records, plan)
    if plan.get("lateRetry") is not None:
        result["lateRetryEvidence"] = check_late_retry(records, plan)
    if evidence or stage_evidence or lemma_evidence:
        result.update(proofMode=plan["proofMode"], propertyEvidence=evidence, stageEvidence=stage_evidence,
                      lemmaEvidence=lemma_evidence, unboundedGoals=unbounded_goals, boundedGoals=bounded_goals)
    return result


def collect_trigger_case(case, executable, private_output, timeout):
    plan = json.loads((case / "plan.json").read_text())
    try:
        if staged.is_staged(plan):
            result = collect_case(case, executable, private_output, staged.budgets(plan["stagedConfiguration"]["name"])[1], cpu_count=16)
        else:
            result = collect_case(case, executable, private_output, timeout)
    except ValueError as error:
        if str(error) != "Unexpected native environment assumption":
            raise
        result = None
    plan = json.loads((case / "plan.json").read_text())
    checked = check_native_records(read_records(case / "native.tsv"), plan)
    return {**result, **checked} if result is not None else checked


def validate_commercial(evidence):
    manifest = validate_frozen(evidence)
    outcomes = []
    for name in CASES:
        case = evidence / "cases" / name
        plan = json.loads((case / "plan.json").read_text())
        receipt = json.loads((case / "receipt.json").read_text())
        completion = json.loads((case / "completion.json").read_text())
        if staged.is_staged(plan):
            staged.check_resources(receipt, plan)
        expected_inputs = {filename: digest(case / filename) for filename in plan["inputs"]}
        if (receipt.get("command") != ["jg", "-no_gui", "-fpv", "-tcl", "collect.tcl"] or
                receipt.get("inputHashes") != expected_inputs or type(receipt.get("pid")) is not int or
                type(receipt.get("cpu")) is not int or receipt["cpu"] < 0):
            raise ValueError("Native receipt differs")
        if (type(completion.get("exitStatus")) is not int or completion["exitStatus"] != 0 or completion.get("timedOut") is not False or
                completion.get("inputsUnchanged") is not True):
            raise ValueError("Native execution did not complete cleanly")
        for value in (receipt.get("launcherSha256"), completion.get("nativeExecutableSha256")):
            if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value):
                raise ValueError("Native tool identity is missing")
        if completion.get("outputHashes") != output_hashes(case):
            raise ValueError("Native outputs changed")
        required = plan["goals"] if plan["expected"] == "cex" else plan["covers"]
        if any(label + ".vcd" not in completion["outputHashes"] for label in required):
            raise ValueError("Required native witness is missing")
        result = check_native_records(read_records(case / "native.tsv"), plan)
        bounds = {key: plan[key] for key in ("targetBounds", "traceBound", "stageBound") if key in plan}
        outcomes.append({"case": name, "mutation": plan["mutation"], "negativeTarget": plan["negativeTarget"],
                         "proofMode": plan["proofMode"], "bounds": bounds, **result})
    summary = {
        "schema": SCHEMA, "exitStatus": 0, "commercialGate": "passed",
        "proofMode": "mixed_commercial", "outcomes": outcomes,
        "coreInitialState": manifest["coreInitialState"],
        "retryCases": manifest["retryCases"],
        "safetyProofStrategy": manifest["safetyProofStrategy"],
        "segmentedProofs": manifest.get("segmentedProofs"),
        "assertionsProven": sum(row["goals"] for row in outcomes if row["case"].endswith("safety")),
        "unboundedAssertions": sum(row.get("unboundedGoals", row["goals"])
                                   for row in outcomes if row["case"].endswith("safety")),
        "boundedAssertions": sum(row.get("boundedGoals", 0) for row in outcomes),
        "helperAssertionsProven": sum(row.get("unboundedHelperGoals", 0) for row in outcomes),
        "coversReached": sum(row["covers"] for row in outcomes if row["case"].endswith("covers")),
        "negativeCounterexamples": sum(row["case"].startswith("negative-") for row in outcomes),
        "caseBounds": manifest["caseBounds"],
        "boundedScope": manifest["boundedScope"], "traceScope": manifest["traceScope"],
        "assumptions": ["one initial synchronous reset", "directed DMI configuration before the checked native execution phase",
                        "fixed native ROM and one-cycle native responses"],
        "abstractions": ["four fixed native scenarios", "ideal one-cycle native memory", "linked stage-cover prefixes"],
        "excluded": ["complete ISA proof", "arbitrary programs and bus timing", "physical signoff"],
        "fullCoreProven": False,
    }
    write_json(evidence / "summary.json", summary)
    return summary


def reference(evidence, depth, timeout):
    validate_frozen(evidence)
    outcomes = []
    for name in CASES:
        source = evidence / "cases" / name
        plan = json.loads((source / "plan.json").read_text())
        work = evidence / "reference-work" / name
        work.mkdir(parents=True)
        for filename in plan["inputs"]:
            if filename not in ("collect.tcl", "plan.tcl"):
                (work / filename).write_bytes((source / filename).read_bytes())
        mode = "cover" if name.endswith("covers") else "bmc"
        config = (f"[options]\nmode {mode}\ndepth {depth}\ntimeout {timeout}\n"
                  "[engines]\nabc bmc3\n[script]\nread -formal -sv " + " ".join(plan["sources"]) +
                  "\nprep -top " + plan["top"] + " -flatten\n[files]\n" + "\n".join(plan["sources"]) + "\n")
        (work / "run.sby").write_text(config)
        frozen = {p.name: digest(p) for p in work.iterdir() if p.is_file()}
        try:
            process = subprocess.run(["sby", "-f", "run.sby"], check=False, cwd=work, stdout=subprocess.PIPE,
                                     stderr=subprocess.STDOUT, text=True, timeout=timeout + 30)
            log, status, code = process.stdout, None, process.returncode
        except subprocess.TimeoutExpired as error:
            log = error.stdout or ""
            if isinstance(log, bytes):
                log = log.decode()
            status, code = "TIMEOUT", None
        (work / "run.log").write_text(log)
        status_path = work / "run/status"
        status = status or (status_path.read_text().split()[0] if status_path.exists() else "ERROR")
        expected_failure = plan["expected"] == "cex"
        accepted = status == ("FAIL" if expected_failure else "PASS") and code == (2 if expected_failure else 0)
        if accepted and expected_failure:
            accepted = plan["negativeTarget"] in log and "Assert failed" in log
        if any(digest(work / filename) != value for filename, value in frozen.items()):
            raise ValueError("Reference inputs changed")
        outcomes.append({"case": name, "mode": mode, "depth": depth, "status": status,
                         "exitStatus": code, "accepted": accepted, "inputHashes": frozen})
        write_json(evidence / "reference-outcomes.json", outcomes)
        if not accepted:
            break
    accepted = len(outcomes) == len(CASES) and all(row["accepted"] for row in outcomes)
    summary = {"schema": REFERENCE_SCHEMA, "exitStatus": 0 if accepted else 1, "accepted": accepted,
               "proofMode": "bounded_open_source_reference", "commercialGate": "not_evaluated",
               "depth": depth, "outcomes": outcomes, "fullCoreProven": False}
    write_json(evidence / "reference-summary.json", summary)
    return summary


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    candidate = argparse.ArgumentParser(add_help=False)
    candidate.add_argument("--unit-rtl", type=Path, required=True)
    candidate.add_argument("--core-rtl", type=Path, required=True)
    candidate.add_argument("--source-root", type=Path, default=ROOT)
    candidate.add_argument("--output", type=Path, required=True)
    candidate.add_argument("--core-time-limit", type=int, default=600)
    candidate.add_argument("--proof-seed", type=Path)
    candidate.add_argument("--proof-seed-scenario2", type=Path)
    candidate.add_argument("--proof-seed-scenario3", type=Path)
    candidate.add_argument("--multiply-target-base", type=Path, action="append", default=[])
    candidate.add_argument("--multiply-older-base", type=Path, action="append", default=[])
    candidate.add_argument("--retry-case", action="append", choices=(*CORE_NAMES, "dpc"), default=[],
                           help="select a generic-retry core case; repeat as needed; default is all five")
    prepare_parser = commands.add_parser("prepare", parents=[candidate])
    prepare_parser.add_argument("--time-limit", type=int, default=120)
    prepare_parser.add_argument("--flow", choices=("retry", "staged"), default="retry")
    prepare_parser.add_argument("--staged-configuration", choices=("native", "semantic", "payload-semantic", "payload-joint", 'store-state', 'program-state', 'store-complete', 'program-complete'), default="native")
    collect = commands.add_parser("collect")
    collect.add_argument("--evidence", type=Path, required=True)
    collect.add_argument("--private-output", type=Path, required=True)
    collect.add_argument("--jg")
    collect.add_argument("--timeout", type=int, default=1800)
    collect.add_argument("--case", action="append", choices=CASES, default=[])
    validate = commands.add_parser("validate")
    validate.add_argument("--evidence", type=Path, required=True)
    reference_parser = commands.add_parser("reference", parents=[candidate])
    reference_parser.add_argument("--time-limit", type=int, default=120)
    reference_parser.add_argument("--depth", type=int, default=96)
    reference_parser.add_argument("--timeout", type=int, default=240)
    args = parser.parse_args()
    if (getattr(args, "time_limit", 1) < 1 or getattr(args, "core_time_limit", 1) < 1 or
            getattr(args, "timeout", 1) < 1 or getattr(args, "depth", 1) < 1):
        parser.error("Tool limits must be positive")
    try:
        if args.command == "prepare":
            result = {"prepared": True, "cases": len(CASES), **prepare(args)}
        elif args.command == "collect":
            evidence = args.evidence.resolve()
            validate_frozen(evidence)
            args.private_output.resolve().mkdir(parents=True, exist_ok=True)
            executable = args.jg or os.environ.get("JG_BIN", "jg")
            for name in args.case or CASES:
                result = collect_trigger_case(evidence / "cases" / name, executable, args.private_output.resolve(), args.timeout)
                write_json(evidence / "cases" / name / "outcome.json", result)
            result = {"collected": args.case or list(CASES), "commercialGate": "not_evaluated"}
        elif args.command == "validate":
            result = validate_commercial(args.evidence.resolve())
        else:
            prepare(args)
            result = reference(args.output.resolve(), args.depth, args.timeout)
        print(json.dumps(result, sort_keys=True))
        if args.command == "reference" and not result["accepted"]:
            raise ValueError("Bounded reference checks failed")
    except (OSError, ValueError, KeyError) as error:
        parser.exit(1, "Execute-trigger verification failed: " + str(error) + "\n")


if __name__ == "__main__":
    main()
