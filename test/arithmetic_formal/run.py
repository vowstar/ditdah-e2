# SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
# SPDX-License-Identifier: MIT
"""Collect full-width arithmetic facts from generated RTL and replay their proof."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import sys

if not __package__:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    from arithmetic_formal import boolean, facts, native, source
else:
    from . import boolean, facts, native, source

HERE = Path(__file__).resolve().parent
SCHEMA = "ditdah-e2.arithmetic.v1"


def write_json(path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def operation_list(values):
    result = []
    for name in values:
        if name not in facts.INSTRUCTIONS:
            raise ValueError("Unknown arithmetic instruction")
        operation = facts.INSTRUCTIONS.index(name)
        if operation in result:
            raise ValueError("Duplicate arithmetic instruction")
        result.append(operation)
    if not result:
        raise ValueError("No arithmetic instructions selected")
    return result


def expected_case(operation, negative, rtl_bytes, time_limit):
    step = "multiply_step.sv"
    plan = {"operation": operation, "top": "md_math_bench",
            "sources": ["DitDahE2MultiplyDivide.sv", "bench.sv", step],
            "goals": [["arithmetic_matches_reference", []]] if negative else
                     [[name, list(deps)] for name, deps in facts.goals(operation)],
            "expected": "cex" if negative else "proven",
            "covers": [] if negative else list(facts.covers(operation)),
            "assumptions": ["md_math_bench." + name for name in facts.ASSUMPTIONS],
            "timeLimitSeconds": time_limit}
    files = {"DitDahE2MultiplyDivide.sv": rtl_bytes,
             "bench.sv": source.bench(operation, negative).encode(),
             step: (HERE / step).read_bytes(),
             "collect.tcl": (HERE / "collect.tcl").read_bytes(),
             "plan.tcl": native.tcl_plan(plan).encode()}
    plan["inputs"] = sorted(files)
    return plan, files


def prepare(args):
    operations = operation_list(args.instruction or facts.INSTRUCTIONS)
    rtl_bytes, rtl_manifest = source.rtl(args.rtl)
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    output.chmod(0o700)
    for operation in operations:
        for kind in ("facts", "result-control"):
            case = output / facts.INSTRUCTIONS[operation] / kind
            case.mkdir(parents=True)
            plan, files = expected_case(operation, kind == "result-control",
                                        rtl_bytes, args.time_limit)
            for name, value in files.items():
                (case / name).write_bytes(value)
            write_json(case / "plan.json", plan)
    boolean.prepare(output / "induction", args.time_limit)
    write_json(output / "rtl-build.json", rtl_manifest)
    manifest = {"schema": SCHEMA, "operations": operations,
                "operandBitsEach": 32, "actualRequestOperationBits": 3,
                "resetScope": "initial_reset_only", "inputAssumptions": list(facts.ASSUMPTIONS),
                "sourceHashes": source.collection_hashes(),
                "rtlSha256": source.digest(rtl_bytes), "timeLimitSeconds": args.time_limit,
                "rtlConfiguration": rtl_manifest["parameters"],
                "fullCoreMProven": False}
    write_json(output / "manifest.json", manifest)
    print(json.dumps({"prepared": True, "operations": len(operations),
                      "operandBitsEach": 32, "nativeCases": 2 * len(operations) + 4}))


def validate_inputs(evidence):
    manifest = json.loads((evidence / "manifest.json").read_text())
    if manifest.get("schema") != SCHEMA:
        raise ValueError("Evidence schema differs")
    recorded = manifest.get("sourceHashes", {})
    current = source.collection_hashes()
    if (set(recorded) != set(current) or any(not isinstance(value, str) or len(value) != 64
                                           or any(c not in "0123456789abcdef" for c in value)
                                           for value in recorded.values())):
        raise ValueError("Collection source identity is incomplete")
    if any(recorded[name] != value for name, value in current.items()
           if Path(name).suffix in (".sv", ".svh", ".tcl")):
        raise ValueError("Native verification source differs")
    if (manifest.get("operandBitsEach") != 32 or
            manifest.get("actualRequestOperationBits") != 3 or
            manifest.get("resetScope") != "initial_reset_only" or
            manifest.get("inputAssumptions") != list(facts.ASSUMPTIONS)):
        raise ValueError("Arithmetic proof configuration differs")
    build = json.loads((evidence / "rtl-build.json").read_text())
    if (build.get("parameters") != manifest.get("rtlConfiguration")
            or build.get("parameters", {}).get("enableM") is not True
            or build.get("rtlHashes", {}).get("DitDahE2MultiplyDivide.sv") != manifest.get("rtlSha256")
            or manifest.get("fullCoreMProven") is not False):
        raise ValueError("Generated arithmetic RTL configuration differs")
    if type(manifest.get("timeLimitSeconds")) is not int or manifest["timeLimitSeconds"] < 1:
        raise ValueError("Native proof time limit is invalid")
    operations = manifest["operations"]
    if (not operations or len(operations) != len(set(operations)) or
            any(type(op) is not int or not 0 <= op < 4 for op in operations)):
        raise ValueError("Arithmetic operation set is invalid")
    for operation in operations:
        for kind in ("facts", "result-control"):
            case = evidence / facts.INSTRUCTIONS[operation] / kind
            rtl_bytes = (case / "DitDahE2MultiplyDivide.sv").read_bytes()
            if source.digest(rtl_bytes) != manifest["rtlSha256"]:
                raise ValueError("Arithmetic RTL changed")
            plan, files = expected_case(operation, kind == "result-control", rtl_bytes,
                                        manifest["timeLimitSeconds"])
            if json.loads((case / "plan.json").read_text()) != plan:
                raise ValueError("Native query plan changed")
            if any((case / name).read_bytes() != value for name, value in files.items()):
                raise ValueError("Frozen arithmetic proof inputs changed")
    boolean.validate(evidence / "induction", manifest["timeLimitSeconds"])
    return manifest


def collect(args):
    evidence = args.evidence.resolve()
    manifest = validate_inputs(evidence)
    executable = args.jg or os.environ.get("JG_BIN", "jg")
    private = args.private_output.resolve()
    private.mkdir(parents=True, exist_ok=True)
    boolean.collect(evidence / "induction", executable, private, args.timeout)
    for operation in manifest["operations"]:
        for kind in ("facts", "result-control"):
            case = evidence / facts.INSTRUCTIONS[operation] / kind
            native.collect(case, executable, private, args.timeout)
    validate_inputs(evidence)
    print(json.dumps({"nativeCollectionComplete": True,
                      "operations": len(manifest["operations"]), "fullCoreMProven": False}))


def replay(args):
    # Import the repository proof implementation, never an evidence-supplied reader.
    if __package__:
        from . import proofs
    else:
        from arithmetic_formal import proofs
    evidence = args.evidence.resolve()
    manifest = validate_inputs(evidence)
    result = proofs.replay(evidence, manifest, args.output.resolve(), args.z3)
    print(json.dumps(result, sort_keys=True))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command")
    command = commands.add_parser("prepare")
    command.add_argument("--rtl", type=Path, required=True)
    command.add_argument("--output", type=Path, required=True)
    command.add_argument("--instruction", action="append", choices=facts.INSTRUCTIONS)
    command.add_argument("--time-limit", type=int, default=60,
                         help="Seconds per native property, fixed during prepare (default: 60)")
    command.set_defaults(execute=prepare)
    command = commands.add_parser("collect")
    command.add_argument("--evidence", type=Path, required=True)
    command.add_argument("--private-output", type=Path, required=True)
    command.add_argument("--jg")
    command.add_argument("--timeout", type=int, default=1800,
                         help="Seconds per native process during collect (default: 1800)")
    command.set_defaults(execute=collect)
    command = commands.add_parser("replay")
    command.add_argument("--evidence", type=Path, required=True)
    command.add_argument("--output", type=Path, required=True)
    command.add_argument("--z3", default="z3")
    command.set_defaults(execute=replay)
    args = parser.parse_args()
    if not args.command:
        parser.error("An arithmetic command is required")
    if getattr(args, "time_limit", 1) < 1 or getattr(args, "timeout", 1) < 1:
        parser.error("Tool time limits must be positive")
    try:
        args.execute(args)
    except (OSError, ValueError, KeyError) as error:
        parser.exit(1, "Arithmetic verification failed: " + str(error) + "\n")


if __name__ == "__main__":
    main()
