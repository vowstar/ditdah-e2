# SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
# SPDX-License-Identifier: MIT
"""Prove permission retention and transaction ownership in the memory filter."""

import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import tempfile

from core_formal import check_inputs, freeze_tools, tool_versions, write_snapshot
from protection_port import digest, permission_mutant


def mutate(content, name):
    if name == "permission":
        return permission_mutant(content)
    changes = {
        "denial-fault": ("assign input_response_bits_fault = denied | output_response_bits_fault;",
                         "assign input_response_bits_fault = output_response_bits_fault;"),
        "denial-leak": ("assign output_request_valid = available & input_request_valid & permitted;",
                        "assign output_request_valid = available & input_request_valid;")}
    old, new = changes[name]
    assert content.count(old) == 1, "Protection mutation no longer matches RTL"
    return content.replace(old, new)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rtl", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    assert not args.output.exists(), "Output already exists"
    raw_build = (args.rtl / "build.json").read_bytes()
    build = json.loads(raw_build)
    assert build["exitStatus"] == 0, "RTL generation did not pass"
    contents = {"build.json": raw_build}
    for group, prefix in (("inputHashes", "inputs"), ("rtlHashes", "rtl")):
        for name, expected in build[group].items():
            value = (args.rtl / prefix / name).read_bytes()
            assert hashlib.sha256(value).hexdigest() == expected, "Changed protection input"
            contents[prefix + "/" + name] = value
    for name in ("protection_formal.py", "protection_formal.sv", "core_formal.py", "protection_port.py"):
        contents["test/" + name] = Path(__file__).with_name(name).read_bytes()
    args.output.mkdir(parents=True)
    frozen = write_snapshot(args.output, contents)
    tools, tool_hashes = freeze_tools()
    outcomes = []
    with tempfile.TemporaryDirectory(prefix="ditdah-e2-protection-formal-", dir="/data/tmp") as directory:
        work = Path(directory)
        for name, mode in (("safety", "prove"), ("cover", "cover"),
                           ("permission", "bmc"), ("denial-fault", "bmc"), ("denial-leak", "bmc")):
            case = work / name
            case.mkdir()
            rtl = contents["rtl/DitDahE2MemoryProtection.sv"].decode()
            if mode == "bmc":
                rtl = mutate(rtl, name)
            (case / "DitDahE2MemoryProtection.sv").write_text(rtl)
            (case / "protection_formal.sv").write_bytes(contents["test/protection_formal.sv"])
            engine = "abc pdr" if mode == "prove" else "smtbmc z3"
            replay = "aigsmt z3\n" if mode == "prove" else ""
            configuration = (f"[options]\nmode {mode}\ndepth 16\n{replay}[engines]\n{engine}\n"
                             "[script]\nread -formal -sv DitDahE2MemoryProtection.sv protection_formal.sv\n"
                             "prep -top protection_formal\n[files]\nDitDahE2MemoryProtection.sv\nprotection_formal.sv\n")
            (case / "run.sby").write_text(configuration)
            candidate = {path.name: path.read_bytes() for path in case.iterdir()}
            archived = write_snapshot(args.output / name, candidate)
            run = subprocess.run(["sby", "-f", "run.sby"], cwd=case, capture_output=True, text=True)
            log = (run.stdout + run.stderr).replace(str(work), "$WORK")
            (args.output / f"{name}.log").write_text(log)
            status_path = case / "run/status"
            status = status_path.read_text().split()[0] if status_path.exists() else "ERROR"
            traces = list((case / "run/engine_0").glob("trace*.*"))
            for trace in traces:
                shutil.copy2(trace, args.output / name / trace.name)
            check_inputs(archived)
            assert all((case / path).read_bytes() == value for path, value in candidate.items()), "Proof input changed"
            outcome = {"name": name, "mode": mode, "engine": engine, "status": status,
                       "exitStatus": run.returncode, "inputHashes": {path: hashlib.sha256(value).hexdigest() for path, value in candidate.items()},
                       "traceHashes": {path.name: digest(path) for path in traces}}
            outcomes.append(outcome)
            (args.output / "outcomes.json").write_text(json.dumps(outcomes, indent=2) + "\n")
            negative = mode == "bmc"
            assert (status, run.returncode) == (("FAIL", 2) if negative else ("PASS", 0)), f"{name}: {status}"
            if negative:
                assert any(path.suffix == ".vcd" for path in traces), "Missing counterexample"
            if mode == "cover":
                assert log.count("Reached cover statement") == 11, "Missing cover witness"
    check_inputs(frozen)
    check_inputs(tools)
    summary = {"scope": "unbounded memory filter safety with first-offer permissions", "exitStatus": 0,
               "inputHashes": {name: hashlib.sha256(value).hexdigest() for name, value in contents.items()},
               "rtlHashes": build["rtlHashes"], "toolHashes": tool_hashes, **tool_versions(), "outcomes": outcomes,
               "assumptions": ["initial reset without traffic", "upstream holds a blocked request",
                               "downstream responds only to an accepted request", "downstream holds a blocked response"],
               "limits": ["PMP interval matching is outside this proof", "No eventual response assumption"]}
    (args.output / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    print("PASS: protection safety, eleven covers and three RTL counterexamples")


if __name__ == "__main__":
    main()
