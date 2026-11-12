# SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
# SPDX-License-Identifier: MIT
"""Freeze and collect commercial proofs for abstract automatic execution."""

import argparse
import hashlib
import json
import os
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
if not __package__:
    sys.path.insert(0, str(ROOT))
from formal.debug_transport import run as native

SCHEMA = "ditdah-e2.debug-abstract.v2"
TOP = "debug_abstract_formal"
RTL_NAME = "DitDahE2DebugModule.sv"
WRAPPER_NAME = "debug_abstract_formal.sv"
COLLECTOR_NAME = "collect.tcl"
ASSERTIONS = (
    "start_without_pending_request",
    "hart_request_accepted_once",
    "dmi_response_has_owner",
    "dmi_request_blocked_with_response",
    "hart_request_has_start",
    "fresh_operands",
    "fresh_program_operands",
    "stable_command_description",
    "auto_requires_accepted_dmi",
    "auto_requires_enabled_access",
    "postexec_start_has_request",
    "postexec_only_preserves_data",
    "data_valid_updates_data0",
    "error_blocks_new_command",
    "dmi_response_valid_stable",
    "dmi_response_payload_stable",
    "hart_request_valid_stable",
    "hart_request_payload_stable",
    "data0_read_returns_previous",
    "abstractauto_reserved_bits_zero",
    "program_buffer_size_is_two",
    "implicit_ebreak_is_advertised",
    "data1_update_exactly_once",
    "busy_conflict_priority",
    "busy_conflict_preserves_error",
    "memory_bus_error_is_five",
    "postexec_error_is_three",
    "unsupported_command_error",
    "deactivate_clears_command_state",
)
INITIAL_ASSUMPTION = "initial_common_cold_reset"
ASSUMPTIONS = (
    "no_later_cold_reset",
    "dmi_request_valid_stable",
    "dmi_request_payload_stable",
    "hart_response_has_request",
    "hart_response_error_supported",
)
COVERS = (
    "cover_auto_write_data",
    "cover_auto_write_address",
    "cover_auto_read_data",
    "cover_auto_response_backpressure",
    "cover_successful_postincrement",
    "cover_fault_without_postincrement",
    "cover_busy_conflict_with_fault",
    "cover_deactivate_with_completion",
    "cover_postexec_only",
    "cover_postexec_with_transfer",
    "cover_program_auto_high",
    "cover_read_then_fault_preserves_data",
)
MUTATIONS = {
    "stale-operands": "fresh_operands",
    "early-increment": "data1_update_exactly_once",
    "backpressure-repeat": "auto_requires_accepted_dmi",
    "busy-priority": "busy_conflict_priority",
    "stale-program": "fresh_program_operands",
    "drop-postexec-need": "postexec_start_has_request",
    "drop-data-valid": "data_valid_updates_data0",
    "drop-implicit-ebreak": "implicit_ebreak_is_advertised",
}
CASES = ("safety", "covers", *("negative-" + name for name in MUTATIONS))
OBSERVATIONS = (
    "autoStart_1", "manualStart", "commandComplete", "command_memory", "command_write",
    "command_size", "command_register", "command_transfer", "command_postIncrement", "command_postExec",
    "operands_address", "data0", "data1", "error", "busy", "active", "auto", "commandValid", "needsHart",
    "program0", "program1", "executionProgram0", "executionProgram1",
)


def sha(value):
    return hashlib.sha256(value).hexdigest()


def write_json(path, value):
    Path(path).write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def check_wrapper(value):
    text = value.decode()
    if (native.labels(text, "assert") != set(ASSERTIONS) or
            native.labels(text, "assume") != {INITIAL_ASSUMPTION, *ASSUMPTIONS} or
            native.labels(text, "cover") != set(COVERS)):
        raise ValueError("Abstract formal property inventory differs from the runner")
    if text.count("DitDahE2DebugModule dut (.*);") != 1:
        raise ValueError("Abstract formal DUT binding differs")


def load_candidate(rtl, source_root, expected_hash):
    if not re.fullmatch(r"[0-9a-f]{64}", expected_hash):
        raise ValueError("Expected RTL SHA256 must be lowercase hexadecimal")
    build = json.loads((rtl / "manifest.json").read_text())
    parameters = build.get("parameters", {})
    if (build.get("top") != "DitDahE2DebugModule" or build.get("exitStatus") != 0 or
            parameters.get("enableDebug") is not True or parameters.get("enableJtag", False) is not False):
        raise ValueError("RTL build is not the standalone debug module configuration")
    hashes = build.get("rtlHashes", {})
    filelist = rtl / "filelist.f"
    files = filelist.read_text().splitlines() if filelist.exists() else sorted(hashes)
    if (not files or len(files) != len(set(files)) or set(files) != set(hashes) or
            RTL_NAME not in files or hashes.get(RTL_NAME) != expected_hash):
        raise ValueError("Debug module RTL file list or expected digest differs")
    contents = {}
    for name in files:
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*\.sv", name):
            raise ValueError("Unsafe RTL filename")
        value = (rtl / name).read_bytes()
        if sha(value) != hashes[name]:
            raise ValueError("Generated RTL digest differs from its build manifest")
        contents[name] = value
    text = contents[RTL_NAME].decode()
    if text.count("module DitDahE2DebugModule(") != 1:
        raise ValueError("Unexpected debug module identity")
    for name in OBSERVATIONS:
        if not re.search(r"\b" + re.escape(name) + r"\b", text):
            raise ValueError("Missing formal observation point: " + name)
    for name, expected in build.get("sourceHashes", {}).items():
        path = native.relative(name)
        if native.digest(source_root / path) != expected:
            raise ValueError("Generation source digest differs: " + path.as_posix())
    return build, contents


def mutate(value, name):
    text = value.decode()
    if name == "busy-priority":
        pattern = r"(error\s*<=\s*)3'h1(;)"
        replacement = r"\g<1>3'h5\2"
    elif name == "stale-operands":
        pattern = (r"(if \(autoStart_1\) begin\n(?:\s*executionProgram[01] <= [^;]+;\n){0,2}\s*)"
                   r"operands_address <= [^;]+;(\n\s*)operands_data <= [^;]+;")
        replacement = lambda match: (match[1] + "operands_address <= operands_address;" +
                                     match[2] + "operands_data <= operands_data;")
    elif name == "early-increment":
        pattern = (r"else if \(commandComplete & command_memory & command_postIncrement\s+"
                   r"& (?:postincrement|hart_response_bits_error == 3'h0)\)")
        replacement = "else if (busyConflict & ~issued & command_memory & command_postIncrement)"
    elif name == "backpressure-repeat":
        pattern = r"wire\s+autoStart = accepted & read \| write;"
        replacement = "wire        autoStart = dmi_request_valid & read | write;"
    elif name == "stale-program":
        pattern = (r"executionProgram0 <= write & autoSelected \? dmi_request_bits_data : program0;\n"
                   r"\s*executionProgram1 <= write & autoSelected_0 \? dmi_request_bits_data : program1;")
        replacement = "executionProgram0 <= executionProgram0;\n      executionProgram1 <= executionProgram1;"
    elif name == "drop-postexec-need":
        pattern = r"(\? memoryCommand \| dmi_request_bits_data\[17\] \|) dmi_request_bits_data\[18\]"
        replacement = r"\g<1> 1'h0"
    elif name == "drop-data-valid":
        pattern = r"data0 <= hart_response_bits_data;"
        replacement = "data0 <= data0;"
    elif name == "drop-implicit-ebreak":
        pattern = r"(\{7'h0,\s*ndmreset \| hart_status_resetPending,\s*)4'h4(,)"
        replacement = r"\g<1>4'h0\g<2>"
    else:
        raise ValueError("Unknown abstract mutation")
    changed, count = re.subn(pattern, replacement, text)
    if count != 1 or changed == text:
        raise ValueError("Abstract mutation anchor is missing or ambiguous: " + name)
    return changed.encode()


def case_definition(name, rtl, wrapper, collector, time_limit):
    negative = name.startswith("negative-")
    mutation = name.removeprefix("negative-") if negative else None
    target = MUTATIONS.get(mutation)
    contents = dict(rtl)
    if mutation:
        contents[RTL_NAME] = mutate(contents[RTL_NAME], mutation)
    contents[WRAPPER_NAME] = wrapper
    plan = {
        "top": TOP,
        "sources": [*rtl, WRAPPER_NAME],
        "goals": [target] if negative else list(ASSERTIONS) if name == "safety" else [],
        "covers": list(COVERS) if name == "covers" else [],
        "expected": "cex" if negative else "proven",
        "assumptions": [TOP + "." + label for label in ASSUMPTIONS],
        "timeLimitSeconds": time_limit,
        "mutation": mutation,
        "negativeTarget": target,
    }
    contents[COLLECTOR_NAME] = collector
    contents["plan.tcl"] = native.tcl_plan(plan)
    plan["inputs"] = sorted(contents)
    return plan, contents


def prepare_bundle(args):
    build, rtl = load_candidate(args.rtl, args.source_root, args.expected_rtl_sha256)
    wrapper = (HERE / WRAPPER_NAME).read_bytes()
    collector = (HERE / COLLECTOR_NAME).read_bytes()
    runner = Path(__file__).read_bytes()
    check_wrapper(wrapper)
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    output.chmod(0o700)
    (output / "rtl").mkdir()
    for name, value in rtl.items():
        (output / "rtl" / name).write_bytes(value)
    for name, value in ((WRAPPER_NAME, wrapper), (COLLECTOR_NAME, collector), ("runner.py", runner)):
        (output / name).write_bytes(value)
    write_json(output / "rtl-build.json", build)
    manifest = {
        "schema": SCHEMA,
        "top": "DitDahE2DebugModule",
        "rtlSha256": args.expected_rtl_sha256,
        "rtlHashes": {name: sha(value) for name, value in rtl.items()},
        "verificationHashes": {WRAPPER_NAME: sha(wrapper), COLLECTOR_NAME: sha(collector), "run.py": sha(runner)},
        "resetScope": "initial_common_cold_reset",
        "hartState": "halted_available",
        "timeLimitSeconds": args.time_limit,
        "cases": list(CASES),
        "programBufferProven": True,
        "fullCoreProven": False,
    }
    write_json(output / "manifest.json", manifest)
    for name in CASES:
        case = output / "cases" / name
        case.mkdir(parents=True)
        plan, contents = case_definition(name, rtl, wrapper, collector, args.time_limit)
        for filename, value in contents.items():
            (case / filename).write_bytes(value)
        write_json(case / "plan.json", plan)
    return manifest


def validate_frozen(evidence):
    manifest = json.loads((evidence / "manifest.json").read_text())
    if (manifest.get("schema") != SCHEMA or manifest.get("top") != "DitDahE2DebugModule" or
            manifest.get("resetScope") != "initial_common_cold_reset" or manifest.get("hartState") != "halted_available" or
            manifest.get("cases") != list(CASES) or manifest.get("programBufferProven") is not True or
            manifest.get("fullCoreProven") is not False or type(manifest.get("timeLimitSeconds")) is not int or
            manifest["timeLimitSeconds"] < 1):
        raise ValueError("Abstract evidence configuration differs")
    recorded = manifest.get("verificationHashes", {})
    for name in (WRAPPER_NAME, COLLECTOR_NAME, "runner.py"):
        key = "run.py" if name == "runner.py" else name
        if native.digest(evidence / name) != recorded.get(key):
            raise ValueError("Frozen verification source differs")
    if native.digest(Path(__file__)) != recorded.get("run.py"):
        raise ValueError("Running verifier differs from the frozen verifier")
    build = json.loads((evidence / "rtl-build.json").read_text())
    if build.get("rtlHashes") != manifest.get("rtlHashes"):
        raise ValueError("Frozen RTL build manifest differs")
    rtl = {}
    for name, expected in manifest["rtlHashes"].items():
        value = (evidence / "rtl" / name).read_bytes()
        if sha(value) != expected:
            raise ValueError("Frozen RTL input differs")
        rtl[name] = value
    if sha(rtl[RTL_NAME]) != manifest.get("rtlSha256"):
        raise ValueError("Frozen debug module identity differs")
    wrapper = (evidence / WRAPPER_NAME).read_bytes()
    collector = (evidence / COLLECTOR_NAME).read_bytes()
    check_wrapper(wrapper)
    for name in CASES:
        case = evidence / "cases" / name
        plan, contents = case_definition(name, rtl, wrapper, collector, manifest["timeLimitSeconds"])
        if json.loads((case / "plan.json").read_text()) != plan:
            raise ValueError("Frozen native query plan differs")
        for filename, value in contents.items():
            if (case / filename).read_bytes() != value:
                raise ValueError("Frozen native proof input differs")
    return manifest


def check_records(records, plan):
    if (records.get(("before", INITIAL_ASSUMPTION)) != "1" or
            records.get(("after", INITIAL_ASSUMPTION)) != "1"):
        raise ValueError("Native initial cold reset assumption is missing")
    expected_global = " ".join(TOP + "." + label for label in (INITIAL_ASSUMPTION, *ASSUMPTIONS))
    if (records.get(("before", "global")) != expected_global or
            records.get(("after", "global")) != expected_global):
        raise ValueError("Native global embedded assumption set differs")
    records = dict(records)
    records[("before", "global")] = ""
    records[("after", "global")] = ""
    return native.check_records(records, plan)


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
    validate_frozen(evidence)
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
        required_traces = set(plan["goals"] if plan["expected"] == "cex" else plan["covers"])
        if any(label + ".vcd" not in outputs for label in required_traces):
            raise ValueError("Required native witness is missing")
        result = check_records(native.read_records(case / "native.tsv"), plan)
        outcomes.append({"case": name, "mutation": plan["mutation"],
                         "negativeTarget": plan["negativeTarget"], **result})
    summary = {
        "schema": SCHEMA,
        "exitStatus": 0,
        "commercialGate": "passed",
        "proofScope": "unbounded_debug_module_abstract_and_program_buffer_safety",
        "rtlSha256": json.loads((evidence / "manifest.json").read_text())["rtlSha256"],
        "outcomes": outcomes,
        "assertionsProven": len(ASSERTIONS),
        "coversReached": len(COVERS),
        "negativeCounterexamples": len(MUTATIONS),
        "assumptions": list(ASSUMPTIONS),
        "initialAssumptions": [INITIAL_ASSUMPTION],
        "abstractions": ["single_hart_halted_available", "initial_common_cold_reset", "one_outstanding_hart_response"],
        "excluded": ["hart_program_execution", "native_trap_csr_isolation", "system_bus_access", "full_core_proof", "physical_transport"],
        "programBufferProven": True,
        "fullCoreProven": False,
    }
    write_json(evidence / "summary.json", summary)
    return summary


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    command = commands.add_parser("prepare")
    command.add_argument("--rtl", type=Path, required=True)
    command.add_argument("--source-root", type=Path, default=ROOT)
    command.add_argument("--expected-rtl-sha256", required=True)
    command.add_argument("--output", type=Path, required=True)
    command.add_argument("--time-limit", type=int, default=120)
    command = commands.add_parser("collect")
    command.add_argument("--evidence", type=Path, required=True)
    command.add_argument("--private-output", type=Path, required=True)
    command.add_argument("--jg")
    command.add_argument("--timeout", type=int, default=1800)
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
    except (OSError, ValueError, KeyError) as error:
        parser.exit(1, "Debug abstract verification failed: " + str(error) + "\n")


if __name__ == "__main__":
    main()
