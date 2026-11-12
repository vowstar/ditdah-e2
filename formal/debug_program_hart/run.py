# SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
# SPDX-License-Identifier: MIT
"""Freeze and collect commercial proofs for standalone Program Buffer execution."""

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
    spec = importlib.util.spec_from_file_location("debug_program_hart_native", HERE / "native.py")
    native = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(native)
else:
    if not __package__:
        sys.path.insert(0, str(ROOT))
    from formal.debug_transport import run as native

SCHEMA = "ditdah-e2.debug-program-hart.v1"
TOP = "debug_program_hart_formal"
RTL_NAME = "DitDahE2DebugHart.sv"
WRAPPER_NAME = "debug_program_hart_formal.sv"
COLLECTOR_NAME = "collect.tcl"
ASSERTIONS = (
    "transfer_zero_no_backend_write",
    "postexec_only_no_backend_write",
    "program_blocks_backend_write",
    "program_blocks_new_command",
    "injection_valid_matches_model",
    "injection_sequence_matches_model",
    "program0_fresh_operands",
    "program1_fresh_operands",
    "injection_word_matches_program",
    "injection_length_matches_program",
    "cross_word_32bit",
    "truncated_halfword",
    "implicit_ebreak",
    "injection_valid_stable",
    "injection_payload_stable",
    "terminate_ends_injection",
    "deactivate_cancels_issue",
    "reset_cancels_issue",
    "cancel_state_has_injection",
    "cancel_blocks_response_until_idle",
    "program_execution_blocks_response",
    "single_postexec_at_most_one_issue",
    "memory_response_ready_with_debt",
    "accepted_memory_not_reissued",
    "deactivate_drains_accepted_memory",
    "reset_drains_accepted_memory",
)
INITIAL_ASSUMPTION = "initial_common_cold_reset"
TCL_ASSUMPTIONS = {INITIAL_ASSUMPTION, "no_later_cold_reset"}
ASSUMPTIONS = (
    "no_later_cold_reset",
    "debug_request_valid_stable",
    "debug_request_payload_stable",
    "injection_done_has_accepted_issue",
    "injection_done_sequence_matches",
    "injection_done_ebreak_decoded",
    "injected_idle_has_no_accepted_issue",
    "memory_response_has_accepted_request",
)
COVERS = (
    "cover_postexec_only_start",
    "cover_postexec_only_single",
    "cover_program0_compressed",
    "cover_program0_32bit",
    "cover_program1_32bit",
    "cover_cross_word_32bit",
    "cover_truncated_halfword",
    "cover_implicit_ebreak",
    "cover_injection_backpressure",
    "cover_deactivate_cancel_wait",
    "cover_reset_cancel_response",
    "cover_deactivate_memory_drain",
    "cover_reset_memory_drain",
)
MUTATIONS = {
    "transfer-gate": "transfer_zero_no_backend_write",
    "stale-program1": "program1_fresh_operands",
    "cross-word": "cross_word_32bit",
    "truncated": "truncated_halfword",
    "implicit-ebreak": "implicit_ebreak",
    "early-cancel": "cancel_blocks_response_until_idle",
    "ignored-ebreak": "terminate_ends_injection",
    "memory-drain": "deactivate_drains_accepted_memory",
}
CASES = ("safety", "covers", *("negative-" + name for name in MUTATIONS))
OBSERVATIONS = (
    "startProgram_0", "program0", "program1", "slot", "pendingIssue",
    "injecting", "cancelInjection", "waiting", "owner", "finishingInjection_1",
)


def sha(value):
    return hashlib.sha256(value).hexdigest()


def write_json(path, value):
    Path(path).write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def check_wrapper(value):
    text = value.decode()
    if (native.labels(text, "assert") != set(ASSERTIONS) or
            native.labels(text, "assume") != set(ASSUMPTIONS) - {"no_later_cold_reset"} or
            native.labels(text, "cover") != set(COVERS)):
        raise ValueError("Program hart formal property inventory differs from the runner")
    if text.count("DitDahE2DebugHart dut (.*);") != 1:
        raise ValueError("Program hart formal DUT binding differs")
    for name in ("program_raw", "program_word", "program_length"):
        if text.count("function automatic") < 3 or name not in text:
            raise ValueError("Independent Program Buffer decoder is missing")


def load_candidate(rtl, source_root, expected_hash):
    if not re.fullmatch(r"[0-9a-f]{64}", expected_hash):
        raise ValueError("Expected RTL SHA256 must be lowercase hexadecimal")
    build = json.loads((rtl / "build.json").read_text())
    parameters = build.get("parameters", {})
    if (build.get("exitStatus") != 0 or parameters.get("resetVector") != 0 or
            parameters.get("enableC") is not True or parameters.get("protectedMode") is not False):
        raise ValueError("RTL build is not the compressed standalone debug hart configuration")
    hashes = build.get("rtlHashes", {})
    rtl_root = rtl / "rtl"
    filelist = rtl_root / "filelist.f"
    files = filelist.read_text().splitlines() if filelist.exists() else sorted(hashes)
    if (not files or len(files) != len(set(files)) or set(files) != set(hashes) or
            RTL_NAME not in files or hashes.get(RTL_NAME) != expected_hash):
        raise ValueError("Debug hart RTL file list or expected digest differs")
    contents = {}
    for name in files:
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*\.sv", name):
            raise ValueError("Unsafe RTL filename")
        value = (rtl_root / name).read_bytes()
        if sha(value) != hashes[name]:
            raise ValueError("Generated RTL digest differs from its build manifest")
        contents[name] = value
    text = contents[RTL_NAME].decode()
    if text.count("module DitDahE2DebugHart(") != 1:
        raise ValueError("Unexpected debug hart identity")
    for name in OBSERVATIONS:
        if not re.search(r"\b" + re.escape(name) + r"\b", text):
            raise ValueError("Missing formal observation point: " + name)
    for name, expected in build.get("inputHashes", {}).items():
        path = native.relative(name)
        if native.digest(source_root / path) != expected:
            raise ValueError("Generation source digest differs: " + path.as_posix())
    return build, contents


def mutate(value, name):
    text = value.decode()
    if name == "transfer-gate":
        pattern = r"(\bassign\s+backend_writePulse\s*=\s*[\s\S]*?)debug_request_bits_transfer"
        replacement = r"\g<1>1'h1"
    elif name == "stale-program1":
        pattern = r"program1 <= debug_request_bits_program1;"
        replacement = "program1 <= debug_request_bits_program0;"
    elif name == "cross-word":
        pattern = r"\{program1\[15:0\], program0\[31:16\]\}"
        replacement = "{16'h0, program0[31:16]}"
    elif name == "truncated":
        pattern = r"assign\s+core_injection_bits_truncated\s*=\s*[^;]+;"
        replacement = "assign core_injection_bits_truncated = 1'h0;"
    elif name == "implicit-ebreak":
        pattern = r"\b32'h100073\b"
        replacement = "32'h00000013"
    elif name == "early-cancel":
        pattern = r"assign debug_response_valid = debug_response_valid_0;"
        replacement = ("assign debug_response_valid = debug_response_valid_0 | "
                       "(cancelInjection & injecting & ~pendingIssue & ~core_injectedIdle & "
                       "owner & debug_control_active);")
    elif name == "ignored-ebreak":
        pattern = r"wire\s+finishingInjection_1\s*=\s*core_injectionDone_fault \| core_injectionDone_ebreak;"
        replacement = "wire finishingInjection_1 = core_injectionDone_fault;"
    elif name == "memory-drain":
        pattern = r"assign memory_response_ready = waiting;"
        replacement = "assign memory_response_ready = waiting & debug_control_active;"
    else:
        raise ValueError("Unknown program hart mutation")
    changed, count = re.subn(pattern, replacement, text)
    if count != 1 or changed == text:
        raise ValueError("Program hart mutation anchor is missing or ambiguous: " + name)
    return changed.encode()


def qualified(label):
    return label if label in TCL_ASSUMPTIONS else TOP + "." + label


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
        "assumptions": [qualified(label) for label in ASSUMPTIONS],
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
    native_source = Path(native.__file__).read_bytes()
    check_wrapper(wrapper)
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    output.chmod(0o700)
    (output / "rtl").mkdir()
    for name, value in rtl.items():
        (output / "rtl" / name).write_bytes(value)
    for name, value in ((WRAPPER_NAME, wrapper), (COLLECTOR_NAME, collector),
                        ("runner.py", runner), ("native.py", native_source)):
        (output / name).write_bytes(value)
    write_json(output / "rtl-build.json", build)
    manifest = {
        "schema": SCHEMA,
        "top": "DitDahE2DebugHart",
        "rtlSha256": args.expected_rtl_sha256,
        "rtlHashes": {name: sha(value) for name, value in rtl.items()},
        "verificationHashes": {
            WRAPPER_NAME: sha(wrapper), COLLECTOR_NAME: sha(collector),
            "run.py": sha(runner), "native.py": sha(native_source),
        },
        "parameters": build["parameters"],
        "programWords": 2,
        "memoryOutstanding": 1,
        "resetScope": "initial_common_cold_reset",
        "clockScope": "single_posedge",
        "hartState": "halted_available",
        "timeLimitSeconds": args.time_limit,
        "cases": list(CASES),
        "fullCoreProven": False,
        "nativeTrapCsrProven": False,
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
    parameters = manifest.get("parameters", {})
    if (manifest.get("schema") != SCHEMA or manifest.get("top") != "DitDahE2DebugHart" or
            parameters.get("resetVector") != 0 or parameters.get("enableC") is not True or
            parameters.get("protectedMode") is not False or manifest.get("programWords") != 2 or
            manifest.get("memoryOutstanding") != 1 or
            manifest.get("resetScope") != "initial_common_cold_reset" or
            manifest.get("clockScope") != "single_posedge" or
            manifest.get("hartState") != "halted_available" or
            manifest.get("cases") != list(CASES) or manifest.get("fullCoreProven") is not False or
            manifest.get("nativeTrapCsrProven") is not False or
            type(manifest.get("timeLimitSeconds")) is not int or manifest["timeLimitSeconds"] < 1):
        raise ValueError("Program hart evidence configuration differs")
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
    if build.get("rtlHashes") != manifest.get("rtlHashes"):
        raise ValueError("Frozen RTL build manifest differs")
    rtl = {}
    for name, expected in manifest["rtlHashes"].items():
        value = (evidence / "rtl" / name).read_bytes()
        if sha(value) != expected:
            raise ValueError("Frozen RTL input differs")
        rtl[name] = value
    if sha(rtl[RTL_NAME]) != manifest.get("rtlSha256"):
        raise ValueError("Frozen debug hart identity differs")
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


EXPECTED_RESET_SCOPE = native.EXPECTED_RESET.replace("expression reset", "expression {}").replace(
    "none false reset_declared true", "none true reset_declared false")
EXPECTED_CLOCK = "{clock clock 1 1}"


def check_records(records, plan):
    if (records.get(("before", INITIAL_ASSUMPTION)) != "1" or
            records.get(("after", INITIAL_ASSUMPTION)) != "1"):
        raise ValueError("Native initial cold reset assumption is missing")
    expected_global = {qualified(label) for label in (INITIAL_ASSUMPTION, *ASSUMPTIONS)
                       if label != "no_later_cold_reset"}
    if any(set(records.get((tag, "global"), "").split()) != expected_global for tag in ("before", "after")):
        raise ValueError("Native global embedded assumption set differs")
    if (records.get(("setup", "clock_mode")) != "single_posedge" or
            records.get(("before", "clock"), "").strip() != EXPECTED_CLOCK or
            records.get(("before", "clock")) != records.get(("after", "clock"))):
        raise ValueError("Native single-clock scope differs")
    if (records.get(("before", "reset"), "").strip() != EXPECTED_RESET_SCOPE or
            records.get(("before", "reset")) != records.get(("after", "reset"))):
        raise ValueError("Native initial reset scope differs")
    records = dict(records)
    records[("before", "global")] = ""
    records[("after", "global")] = ""
    records[("setup", "clock_mode")] = "free_running"
    records[("before", "clock")] = ""
    records[("after", "clock")] = ""
    records[("before", "reset")] = native.EXPECTED_RESET
    records[("after", "reset")] = native.EXPECTED_RESET
    return native.check_records(records, plan)


def collect_case(case, executable, private_output, timeout):
    try:
        result = native.collect_case(case, executable, private_output, timeout)
    except ValueError as error:
        if str(error) not in {"Unexpected native environment assumption",
                              "Native clock environment is not free-running",
                              case.name + ": native execution did not complete cleanly"}:
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
        "proofScope": "unbounded_standalone_debug_hart_program_buffer_safety",
        "rtlSha256": manifest["rtlSha256"],
        "parameters": manifest["parameters"],
        "outcomes": outcomes,
        "assertionsProven": len(ASSERTIONS),
        "boundedAssertions": 0,
        "unboundedAssertions": len(ASSERTIONS),
        "coversReached": len(COVERS),
        "negativeCounterexamples": len(MUTATIONS),
        "assumptions": list(ASSUMPTIONS),
        "initialAssumptions": [INITIAL_ASSUMPTION],
        "abstractions": [
            "standalone_debug_hart", "two_program_words", "compressed_decoder_enabled",
            "independent_injected_core_peer", "one_outstanding_memory_response",
            "single_posedge_clock", "initial_common_cold_reset",
        ],
        "excluded": [
            "full_core_proof", "native_trap_csr_proof", "injected_instruction_semantics",
            "physical_debug_transport", "later_cold_reset", "progress_without_fairness",
        ],
        "fullCoreProven": False,
        "nativeTrapCsrProven": False,
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
            errors = []
            for name in CASES:
                try:
                    collect_case(evidence / "cases" / name, executable,
                                 args.private_output.resolve(), args.timeout)
                except (OSError, ValueError, KeyError) as error:
                    errors.append(str(error))
            result = validate_commercial(evidence)
            if errors:
                raise ValueError("Native collection failed: " + errors[0])
        else:
            result = validate_commercial(args.evidence.resolve())
        print(json.dumps(result, sort_keys=True))
    except (OSError, ValueError, KeyError) as error:
        parser.exit(1, "Debug Program Buffer verification failed: " + str(error) + "\n")


if __name__ == "__main__":
    main()
