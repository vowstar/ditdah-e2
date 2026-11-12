# SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
# SPDX-License-Identifier: MIT
"""Prove core injection guards and collect bounded Program Buffer witnesses."""

import argparse
import hashlib
import importlib.util
import json
import os
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
if (HERE / "native.py").exists():
    spec = importlib.util.spec_from_file_location("debug_program_core_native", HERE / "native.py")
    native = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(native)
else:
    if not __package__:
        sys.path.insert(0, str(ROOT))
    from formal.debug_transport import run as native

SCHEMA = "ditdah-e2.debug-program-core.v2"
INITIAL_STATE = {
    "initialStateProfile": "source-cold-reset122",
    "resetExpressionSha256": "5b2e97475a16de82ba99191cdba519beded49bc010b4b4164e0dd277a34211ad",
    "resetFactCount": 122,
    "resetGprCount": 31,
    "addedResetFacts": 42,
    "unresetPayloadExclusions": ["dut.dm.executionProgram0", "dut.dm.executionProgram1",
                                 "dut.debug.program0", "dut.debug.program1", "dut.m_injected"],
    "initialStateScopeChange": "Unsupported payload-zero restrictions removed; all implemented reset values are explicit",
}
TOP = "debug_program_core_formal"
RTL_NAME = "DitDahE2.sv"
WRAPPER_NAME = "debug_program_core_formal.sv"
COLLECTOR_NAME = "collect.tcl"
ASSERTIONS = (
    "injected_not_native_retire",
    "injected_not_native_trap",
    "injected_csr_local",
    "injected_local_operands",
    "injected_no_trigger",
    "injected_backend_quiet",
    "deactivate_blocks_injected_issue",
)
HELPER_COVER = "cover_halted"
COVERS = (
    "cover_injected_execution",
    "cover_program_fault",
    "cover_trap_csr_preserved",
    "cover_cross_word",
    "cover_local_dpc",
    "cover_deactivated_store",
    "cover_implicit_ebreak",
    "cover_postexec_transfer",
)
HELPER_COVERS = (
    "cover_local_dpc_command",
    "cover_local_dpc_execution",
    "cover_store_program",
    "cover_store_accepted",
    "cover_store_deactivated",
)
COVER_SEQUENCE = (
    "cover_injected_execution",
    "cover_program_fault",
    "cover_trap_csr_preserved",
    "cover_cross_word",
    "cover_local_dpc_command",
    "cover_local_dpc_execution",
    "cover_local_dpc",
    "cover_store_program",
    "cover_store_accepted",
    "cover_store_deactivated",
    "cover_deactivated_store",
    "cover_postexec_transfer",
    "cover_implicit_ebreak",
)
ALL_COVERS = (HELPER_COVER, *COVERS, *HELPER_COVERS)
INITIAL_ASSUMPTION = "initial_common_cold_reset"
ASSUMPTIONS = ("no_later_cold_reset",)
MUTATIONS = {
    "injection-identity": "injected_not_native_retire",
    "local-csr": "injected_csr_local",
    "trigger-filter": "injected_no_trigger",
    "deactivate-issue": "deactivate_blocks_injected_issue",
}
NEGATIVE_STAGES = {
    "injection-identity": (),
    "local-csr": ("cover_injected_execution", "cover_program_fault", "cover_trap_csr_preserved",
                  "cover_cross_word", "cover_local_dpc_command"),
    "trigger-filter": (),
    "deactivate-issue": ("cover_injected_execution", "cover_program_fault", "cover_trap_csr_preserved",
                         "cover_cross_word", "cover_local_dpc_command", "cover_store_program",
                         "cover_store_accepted"),
}
TRACE_ENGINES = "{Hp Ht N B}"
CASES = ("safety", "covers", *("negative-" + name for name in MUTATIONS))
OBSERVATIONS = ("m_injected", "m_csrAddress", "xInjected", "debugLocal", "trigger_valid", "core_injection_valid_0")
REQUIRED_PARAMETERS = {"enableDebug": True, "enableJtag": False, "enableM": True, "enableC": True,
                       "protectedMode": False, "enableA": False, "triggerCount": 2, "resetVector": 0}


def sha(value):
    return hashlib.sha256(value).hexdigest()


def check_reset_collector(collector):
    expressions = re.findall(r"(?m)^\s*assume -reset \{([^\n]+)\}\s*$", collector.decode())
    if len(expressions) != 1 or sha(expressions[0].encode()) != INITIAL_STATE["resetExpressionSha256"]:
        raise ValueError("Program core cold-reset contract differs")


def check_initial_state(manifest):
    if any(manifest.get(key) != value for key, value in INITIAL_STATE.items()):
        raise ValueError("Program core initial-state profile differs")


def check_wrapper(value):
    text = value.decode()
    if (native.labels(text, "assert") != set(ASSERTIONS) or
            native.labels(text, "assume") != {INITIAL_ASSUMPTION, *ASSUMPTIONS} or
            native.labels(text, "cover") != set(ALL_COVERS)):
        raise ValueError("Program core formal property inventory differs from the runner")
    if text.count("DitDahE2 dut (") != 1:
        raise ValueError("Program core formal DUT binding differs")


def check_parameters(parameters):
    if not isinstance(parameters, dict):
        raise TypeError("Program core parameters must be an object")
    for name, expected in REQUIRED_PARAMETERS.items():
        value = parameters.get(name, False)
        if type(value) is not type(expected) or value != expected:
            raise ValueError(f"Program core proof requires {name}={expected}")


def check_parameter_binding(manifest, build):
    declared, generated = manifest.get("parameters"), build.get("parameters")
    check_parameters(declared)
    check_parameters(generated)
    if (declared != generated or
            any(type(declared[name]) is not type(value) for name, value in generated.items())):
        raise ValueError("Frozen program core parameters differ from the build")


def load_candidate(rtl, source_root, expected_hash):
    if not re.fullmatch(r"[0-9a-f]{64}", expected_hash):
        raise ValueError("Expected RTL SHA256 must be lowercase hexadecimal")
    build = json.loads((rtl / "manifest.json").read_text())
    if build.get("top") != "DitDahE2" or build.get("exitStatus") != 0:
        raise ValueError("Program core proof requires complete RTL")
    check_parameters(build.get("parameters"))
    hashes = build.get("rtlHashes", {})
    filelist = rtl / "filelist.f"
    files = filelist.read_text().splitlines() if filelist.exists() else sorted(hashes)
    if (not files or len(files) != len(set(files)) or set(files) != set(hashes) or
            RTL_NAME not in files or hashes.get(RTL_NAME) != expected_hash):
        raise ValueError("Program core RTL file list or expected digest differs")
    contents = {}
    for name in files:
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*\.sv", name):
            raise ValueError("Unsafe RTL filename")
        value = (rtl / name).read_bytes()
        if sha(value) != hashes[name]:
            raise ValueError("Generated RTL digest differs from its build manifest")
        contents[name] = value
    text = contents[RTL_NAME].decode()
    if text.count("module DitDahE2(") != 1:
        raise ValueError("Unexpected complete core identity")
    for name in OBSERVATIONS:
        if name not in text and name not in contents["DitDahE2DebugHart.sv"].decode():
            raise ValueError("Missing formal observation point: " + name)
    for name, expected in build.get("sourceHashes", {}).items():
        path = native.relative(name)
        if native.digest(source_root / path) != expected:
            raise ValueError("Generation source digest differs: " + path.as_posix())
    return build, contents


def mutate(contents, name):
    changed = dict(contents)
    if name == "injection-identity":
        filename, pattern = RTL_NAME, r"complete & ~debugBreakpoint & ~driveTrap & ~m_injected;"
        replacement = "complete & ~debugBreakpoint & ~driveTrap;"
    elif name == "local-csr":
        filename, pattern = RTL_NAME, r"~\(debugLocal & \(debugLocal_0 \| debugLocal_1\)\)"
        replacement = "1'h1"
    elif name == "trigger-filter":
        filename, pattern, replacement = RTL_NAME, r"\.trigger_valid\s+\(xValid & ~xInjected\)", ".trigger_valid (xValid)"
    elif name == "deactivate-issue":
        filename, pattern = "DitDahE2DebugHart.sv", r"wire\s+core_injection_valid_0 = pendingIssue & ~cancelInjection;"
        replacement = "wire core_injection_valid_0 = pendingIssue | cancelInjection;"
    else:
        raise ValueError("Unknown program core mutation")
    text, count = re.subn(pattern, replacement, changed[filename].decode())
    if count != 1:
        raise ValueError("Program core mutation anchor is missing or ambiguous: " + name)
    changed[filename] = text.encode()
    return changed


def case_definition(name, rtl, wrapper, collector, time_limit):
    negative = name.startswith("negative-")
    mutation = name.removeprefix("negative-") if negative else None
    target = MUTATIONS.get(mutation)
    contents = mutate(rtl, mutation) if mutation else dict(rtl)
    contents[WRAPPER_NAME] = wrapper
    plan = {
        "top": TOP,
        "sources": [*rtl, WRAPPER_NAME],
        "goals": [target] if negative else list(ASSERTIONS) if name == "safety" else [],
        "covers": list(COVERS) if name == "covers" else [],
        "expected": "cex" if negative else "proven",
        "assumptions": [TOP + "." + label for label in ASSUMPTIONS],
        "timeLimitSeconds": time_limit,
        "traceBound": 512,
        "stageBound": 96,
        "stageTimeLimitSeconds": 240,
        "mutation": mutation,
        "negativeTarget": target,
        "negativeStages": list(NEGATIVE_STAGES.get(mutation, ())),
        "coverSequence": list(COVER_SEQUENCE) if name == "covers" else [],
        "traceEngineMode": TRACE_ENGINES,
        "proofMode": "trace_commercial" if name != "safety" else "unbounded_commercial",
    }
    contents[COLLECTOR_NAME] = collector
    contents["plan.tcl"] = native.tcl_plan(plan) + (
        f"set trace_bound {plan['traceBound']}\nset stage_bound {plan['stageBound']}\n"
        f"set stage_time_limit {plan['stageTimeLimitSeconds']}\n"
        f"set trace_engines {plan['traceEngineMode']}\n"
        f"set cover_sequence {{{' '.join(plan['coverSequence'])}}}\n"
        f"set negative_stages {{{' '.join(plan['negativeStages'])}}}\n").encode()
    plan["inputs"] = sorted(contents)
    return plan, contents


def prepare_bundle(args):
    build, rtl = load_candidate(args.rtl, args.source_root, args.expected_rtl_sha256)
    wrapper = (HERE / WRAPPER_NAME).read_bytes()
    collector = (HERE / COLLECTOR_NAME).read_bytes()
    runner = Path(__file__).read_bytes()
    native_source = Path(native.__file__).read_bytes()
    check_wrapper(wrapper)
    check_reset_collector(collector)
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    output.chmod(0o700)
    (output / "rtl").mkdir()
    for name, value in rtl.items():
        (output / "rtl" / name).write_bytes(value)
    for name, value in ((WRAPPER_NAME, wrapper), (COLLECTOR_NAME, collector),
                        ("runner.py", runner), ("native.py", native_source)):
        (output / name).write_bytes(value)
    (output / "rtl-build.json").write_text(json.dumps(build, indent=2, sort_keys=True) + "\n")
    manifest = {
        "schema": SCHEMA,
        "top": "DitDahE2",
        "rtlSha256": args.expected_rtl_sha256,
        "rtlHashes": {name: sha(value) for name, value in rtl.items()},
        "verificationHashes": {WRAPPER_NAME: sha(wrapper), COLLECTOR_NAME: sha(collector),
                               "run.py": sha(runner), "native.py": sha(native_source)},
        "parameters": build["parameters"],
        "timeLimitSeconds": args.time_limit,
        "traceBound": 512,
        "stageBound": 96,
        "stageTimeLimitSeconds": 240,
        "cases": list(CASES),
        "fullCoreProven": False,
        "completeDebugProven": False,
        **INITIAL_STATE,
    }
    (output / "manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    for name in CASES:
        case = output / "cases" / name
        case.mkdir(parents=True)
        plan, contents = case_definition(name, rtl, wrapper, collector, args.time_limit)
        for filename, value in contents.items():
            (case / filename).write_bytes(value)
        (case / "plan.json").write_text(json.dumps(plan, indent=2, sort_keys=True) + "\n")
    return manifest


def validate_frozen(evidence):
    manifest = json.loads((evidence / "manifest.json").read_text())
    check_initial_state(manifest)
    if (manifest.get("schema") != SCHEMA or manifest.get("top") != "DitDahE2" or
            manifest.get("traceBound") != 512 or manifest.get("stageBound") != 96 or
            manifest.get("stageTimeLimitSeconds") != 240 or manifest.get("cases") != list(CASES) or
            type(manifest.get("timeLimitSeconds")) is not int or manifest["timeLimitSeconds"] < 1 or
            manifest.get("fullCoreProven") is not False or manifest.get("completeDebugProven") is not False):
        raise ValueError("Program core evidence configuration differs")
    recorded = manifest.get("verificationHashes", {})
    for name in (WRAPPER_NAME, COLLECTOR_NAME, "runner.py", "native.py"):
        key = "run.py" if name == "runner.py" else name
        if native.digest(evidence / name) != recorded.get(key):
            raise ValueError("Frozen verification source differs")
    if native.digest(Path(__file__)) != recorded.get("run.py"):
        raise ValueError("Running verifier differs from the frozen verifier")
    if native.digest(Path(native.__file__)) != recorded.get("native.py"):
        raise ValueError("Running native collector differs from the frozen collector")
    build = json.loads((evidence / "rtl-build.json").read_text())
    check_parameter_binding(manifest, build)
    if build.get("rtlHashes") != manifest.get("rtlHashes"):
        raise ValueError("Frozen RTL build manifest differs")
    rtl = {}
    for name, expected in manifest["rtlHashes"].items():
        value = (evidence / "rtl" / name).read_bytes()
        if sha(value) != expected:
            raise ValueError("Frozen RTL input differs")
        rtl[name] = value
    if sha(rtl[RTL_NAME]) != manifest.get("rtlSha256"):
        raise ValueError("Frozen complete core identity differs")
    wrapper = (evidence / WRAPPER_NAME).read_bytes()
    collector = (evidence / COLLECTOR_NAME).read_bytes()
    check_wrapper(wrapper)
    check_reset_collector(collector)
    for name in CASES:
        case = evidence / "cases" / name
        plan, contents = case_definition(name, rtl, wrapper, collector, manifest["timeLimitSeconds"])
        if json.loads((case / "plan.json").read_text()) != plan:
            raise ValueError("Frozen native query plan differs")
        for filename, value in contents.items():
            if (case / filename).read_bytes() != value:
                raise ValueError("Frozen native proof input differs")
    return manifest


def goal_records(records, plan):
    result = native.check_records(records, dict(plan, goals=[]))
    for label in plan["goals"]:
        prefix = "final." + label
        required = {
            "name": plan["top"] + "." + label,
            "type": "assert",
            "command": "assert",
            "disabled": "0",
            "run_status": "processed",
            "validity_status": plan["expected"],
            "expression": label,
            "precondition": "0",
        }
        if any(records.get((prefix, key)) != value for key, value in required.items()):
            raise ValueError("Native final assertion identity or verdict differs: " + label)
        for key, expected in (("clock", "clock"), ("edge", "posedge")):
            if records.get((prefix, key)) not in (None, "", expected):
                raise ValueError("Native assertion clock or edge differs: " + label)
    result["goals"] = len(plan["goals"])
    return result


def check_records(records, plan):
    if (records.get(("before", INITIAL_ASSUMPTION)) != "1" or
            records.get(("after", INITIAL_ASSUMPTION)) != "1"):
        raise ValueError("Native initial cold reset assumption is missing")
    if records.get(("before", "reset_initial")) != "assume:0" or records.get(("after", "reset_initial")) != "assume:0":
        raise ValueError("Native reset_initial metadata differs")
    if records.get(("before", "reset")) != native.EXPECTED_RESET or records.get(("after", "reset")) != native.EXPECTED_RESET:
        raise ValueError("Native reset declaration metadata differs")
    if (records.get(("before", "reset_assumptions")) != records.get(("after", "reset_assumptions")) or
            not records.get(("before", "reset_assumptions"))):
        raise ValueError("Native declared reset-state assumptions differ")
    expected_global = " ".join(TOP + "." + label for label in (INITIAL_ASSUMPTION, *ASSUMPTIONS))
    if (records.get(("before", "global")) != expected_global or
            records.get(("after", "global")) != expected_global):
        raise ValueError("Native global embedded assumption set differs")
    records = dict(records)
    for tag in ("before", "after"):
        records[(tag, "global")] = ""
        records[(tag, "reset_assumptions")] = ""
    result = goal_records(records, plan)
    if plan["proofMode"] == "trace_commercial":
        stages = list(plan.get("negativeStages", [])) if plan["expected"] == "cex" else list(HELPER_COVERS)
        groups = ["stage." + label for label in (HELPER_COVER, *stages)]
        groups += [] if plan["expected"] == "cex" else ["cover." + label for label in COVERS]
        for group in groups:
            if (records.get((group, "validity_status")) != "covered" or
                    not re.fullmatch(r"[1-9][0-9]*", records.get((group, "trace_length"), ""))):
                raise ValueError("Native bounded witness is missing: " + group)
            engine = records.get((group, "latest_trace_engine"))
            if not engine or engine == "?":
                raise ValueError("Native witness engine is missing: " + group)
        if plan["expected"] == "cex" and (
                not re.fullmatch(r"[1-9][0-9]*", records.get(("final." + plan["goals"][0], "trace_length"), "")) or
                not records.get(("final." + plan["goals"][0], "latest_trace_engine"))):
            raise ValueError("Negative witness is missing")
        if plan["expected"] == "cex":
            result["traceScope"] = "prefixed_cex" if stages else "direct_joint_cex"
        else:
            result["traceScope"] = "linked_cover_witnesses"
    else:
        result["traceScope"] = "unbounded_guard_proof"
    return result


def collect_case(case, executable, private_output, timeout):
    try:
        result = native.collect_case(case, executable, private_output, timeout)
    except ValueError as error:
        if str(error) != "Unexpected native environment assumption":
            raise
        result = None
    plan = json.loads((case / "plan.json").read_text())
    checked = check_records(native.read_records(case / "native.tsv"), plan)
    return result if result is not None else checked


def validate_commercial(evidence):
    manifest = validate_frozen(evidence)
    outcomes = []
    for name in CASES:
        case = evidence / "cases" / name
        plan = json.loads((case / "plan.json").read_text())
        receipt = json.loads((case / "receipt.json").read_text())
        completion = json.loads((case / "completion.json").read_text())
        expected_inputs = {filename: native.digest(case / filename) for filename in plan["inputs"]}
        if (receipt.get("command") != ["jg", "-no_gui", "-fpv", "-tcl", "collect.tcl"] or
                type(receipt.get("pid")) is not int or receipt["pid"] <= 0 or
                type(receipt.get("cpu")) is not int or receipt["cpu"] < 0 or
                receipt.get("inputHashes") != expected_inputs):
            raise ValueError("Native receipt does not bind the proof inputs")
        if (completion.get("exitStatus") != 0 or completion.get("timedOut") is not False or
                completion.get("inputsUnchanged") is not True):
            raise ValueError("Native execution did not finish with unchanged inputs")
        for value in (receipt.get("launcherSha256"), completion.get("nativeExecutableSha256")):
            if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value):
                raise ValueError("Native tool identity is missing")
        outputs = native.output_hashes(case)
        if completion.get("outputHashes") != outputs:
            raise ValueError("Native results changed after completion")
        required_traces = set(plan["goals"] if plan["expected"] == "cex" else
                              ALL_COVERS if plan["proofMode"] == "trace_commercial" else [])
        if plan["proofMode"] == "trace_commercial":
            required_traces.add(HELPER_COVER)
            required_traces.update(plan.get("negativeStages", []))
        if any(label + ".vcd" not in outputs for label in required_traces):
            raise ValueError("Required native witness is missing")
        result = check_records(native.read_records(case / "native.tsv"), plan)
        outcomes.append({"case": name, "mutation": plan["mutation"],
                         "negativeTarget": plan["negativeTarget"], **result})
    summary = {
        "schema": SCHEMA,
        "exitStatus": 0,
        "commercialGate": "passed",
        "proofScope": "unbounded_injection_guards_and_bounded_directed_core_witnesses",
        "rtlSha256": manifest["rtlSha256"],
        "parameters": manifest["parameters"],
        "outcomes": outcomes,
        "assertionsProven": len(ASSERTIONS),
        "coversReached": len(COVERS) + 1,
        "helperCoversReached": len(HELPER_COVERS),
        "negativeCounterexamples": len(MUTATIONS),
        "traceBound": 512,
        "assumptions": list(ASSUMPTIONS),
        "initialAssumptions": [INITIAL_ASSUMPTION],
        "abstractions": ["initial_common_cold_reset", "fixed_dmi_script", "bounded_memory_response"],
        "excluded": ["complete_core_proof", "complete_debug_conformance", "quick_access", "system_bus_access", "physical_transport"],
        "fullCoreProven": False,
        "completeDebugProven": False,
        **INITIAL_STATE,
    }
    (evidence / "summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
    return summary


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    command = commands.add_parser("prepare")
    command.add_argument("--rtl", type=Path, required=True)
    command.add_argument("--source-root", type=Path, default=ROOT)
    command.add_argument("--expected-rtl-sha256", required=True)
    command.add_argument("--output", type=Path, required=True)
    command.add_argument("--time-limit", type=int, default=600)
    command = commands.add_parser("collect")
    command.add_argument("--evidence", type=Path, required=True)
    command.add_argument("--private-output", type=Path, required=True)
    command.add_argument("--jg")
    command.add_argument("--timeout", type=int, default=3600)
    command = commands.add_parser("validate")
    command.add_argument("--evidence", type=Path, required=True)
    args = parser.parse_args()
    if getattr(args, "time_limit", 1) < 1 or getattr(args, "timeout", 1) < 1:
        parser.error("Tool limits must be positive")
    try:
        if args.command == "prepare":
            manifest = prepare_bundle(args)
            result = {"prepared": True, "cases": len(CASES), "rtlSha256": manifest["rtlSha256"]}
        elif args.command == "collect":
            evidence = args.evidence.resolve()
            validate_frozen(evidence)
            args.private_output.resolve().mkdir(parents=True, exist_ok=True)
            executable = args.jg or os.environ.get("JG_BIN", "jg")
            for name in CASES:
                collect_case(evidence / "cases" / name, executable,
                             args.private_output.resolve(), args.timeout)
            result = validate_commercial(evidence)
        else:
            result = validate_commercial(args.evidence.resolve())
        print(json.dumps(result, sort_keys=True))
    except (OSError, ValueError, KeyError, TypeError) as error:
        parser.exit(1, "Debug program core verification failed: " + str(error) + "\n")


if __name__ == "__main__":
    main()
