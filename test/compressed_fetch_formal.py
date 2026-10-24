# SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
# SPDX-License-Identifier: MIT
"""Prove compressed fetch ownership and parcel assembly from an independent queue."""

import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile

from core_formal import check_inputs, digest, freeze_tools, source_hashes, tool_versions, write_snapshot


def replace_once(content, old, new):
    assert content.count(old) == 1, "Compressed fetch mutation no longer matches RTL"
    return content.replace(old, new)


def mutate(content, name):
    changes = {
        "release": ("wire        releaseFirst = assemblyPc[1] | crossing & ~firstFault;",
                    "wire        releaseFirst = firstFault | assemblyPc[1] | crossing;"),
        "fault-address": (": failed ? secondAddress : assemblyPc;", ": failed ? assemblyPc : assemblyPc;"),
        "cross-word": ("crossing_0 ? {secondWord[15:0], half} : firstWord",
                       "crossing_0 ? {half, secondWord[15:0]} : firstWord"),
        "held-request": ("assign memory_request_bits_address = address;",
                         "assign memory_request_bits_address = discarded && !sent ? {target[31:2], 2'b0} : address;")}
    return replace_once(content, *changes[name])


def observe(content):
    scalars = {"active": "active", "sent": "sent", "discarded": "discarded", "first_valid": "firstValid",
               "second_valid": "secondValid", "first_fault": "firstFault", "second_fault": "secondFault"}
    words = {"assembly_pc": "assemblyPc", "next_word": "nextWord", "first_word": "firstWord",
             "second_word": "secondWord", "first_address": "firstAddress", "second_address": "secondAddress"}
    for signal in [*scalars.values(), *words.values()]:
        assert re.search(r"reg\s+(?:\[31:0\]\s+)?" + signal + r"\s*;", content), "Missing observation signal"
    ports = "  output " + ", ".join("formal_" + name for name in scalars) + ",\n"
    ports += "  output [31:0] " + ", ".join("formal_" + name for name in words) + ",\n"
    content = replace_once(content, "module DitDahE2Fetch(", "module DitDahE2Fetch(\n" + ports)
    assignments = "".join(f"  assign formal_{name} = {signal};\n" for name, signal in {**scalars, **words}.items())
    return replace_once(content, "endmodule", assignments + "endmodule")


def freeze(args):
    wrapper = Path(__file__).with_suffix(".sv")
    helper = Path(__file__).with_name("core_formal.py")
    raw_manifest = (args.rtl / "manifest.json").read_bytes()
    manifest = json.loads(raw_manifest)
    parameters = manifest["parameters"]
    assert parameters["resetVector"] == 0 and parameters.get("enableC") is True, "Compressed fetch requires resetVector=0 and enableC=true"
    assert set(parameters) <= {"resetVector", "enableM", "enableC"}, "Unknown fetch configuration"
    assert isinstance(parameters.get("enableM", False), bool), "Invalid M configuration"
    assert manifest["sourceHashes"] == source_hashes(args.source_root), "Stale RTL inputs"
    contents = {"manifest.json": raw_manifest, "rtl/manifest.json": raw_manifest,
                "test/" + wrapper.name: wrapper.read_bytes(), "test/" + Path(__file__).name: Path(__file__).read_bytes(),
                "test/core_formal.py": helper.read_bytes()}
    for group, prefix, root in (("sourceHashes", "source", args.source_root), ("rtlHashes", "rtl", args.rtl)):
        for name, expected in manifest[group].items():
            value = (root / name).read_bytes()
            assert hashlib.sha256(value).hexdigest() == expected, "Changed formal input"
            contents[prefix + "/" + name] = value
    assert manifest["sourceHashes"] == source_hashes(args.source_root), "Inputs changed before freezing"
    bindings = {"parameters": parameters, "sourceHashes": manifest["sourceHashes"], "rtlHashes": manifest["rtlHashes"],
                "manifestHash": hashlib.sha256(raw_manifest).hexdigest(), "runnerHash": digest(Path(__file__)),
                "wrapperHash": digest(wrapper), "helperHash": digest(helper)}
    return contents, bindings


def execute(work, output, rtl, wrapper, name, mode, depth, negative=False):
    case = work / name
    case.mkdir()
    source = mutate(rtl, name) if negative else rtl
    (case / "DitDahE2Fetch.sv").write_text(observe(source))
    (case / "compressed_fetch_formal.sv").write_bytes(wrapper)
    flags = "-DREFINEMENT " if mode == "prove" else ""
    config = (f"[options]\nmode {mode}\ndepth {depth}\n"
              "[engines]\nsmtbmc z3\n[script]\n"
              f"read -formal -sv {flags}DitDahE2Fetch.sv compressed_fetch_formal.sv\n"
              "prep -top compressed_fetch_formal\n"
              "[files]\nDitDahE2Fetch.sv\ncompressed_fetch_formal.sv\n")
    (case / "run.sby").write_text(config)
    frozen = {path: path.read_bytes() for path in case.iterdir() if path.is_file()}
    archive = output / (name + "-inputs")
    archive.mkdir(exist_ok=True)
    archived = {}
    for path, value in frozen.items():
        saved = archive / path.name
        saved.write_bytes(value)
        archived[saved] = value
    check_inputs(frozen)
    check_inputs(archived)
    print(f"Running compressed fetch {name}", flush=True)
    run = subprocess.run(["sby", "-f", "run.sby"], cwd=case, capture_output=True, text=True)
    log = (run.stdout + run.stderr).replace(str(work), "<workspace>")
    (output / (name + ".txt")).write_text(log)
    check_inputs(frozen)
    check_inputs(archived)
    status_path = case / "run/status"
    status = status_path.read_text().split()[0] if status_path.is_file() else "ERROR"
    traces = list((case / "run/engine_0").glob("trace*.*"))
    for trace in traces:
        shutil.copyfile(trace, output / (name + "-" + trace.name))
    reached = [{"cycle": int(step), "wrapperLine": int(line)} for step, line in
               re.findall(r"Reached cover statement in step (\d+) at compressed_fetch_formal: compressed_fetch_formal.sv:(\d+)\.", log)]
    result = {"name": name, "mode": mode, "depth": depth, "engine": "smtbmc z3", "status": status,
              "exitStatus": run.returncode, "refinementAssertions": mode == "prove", "inputDirectory": archive.name,
              "inputHashes": {path.name: hashlib.sha256(value).hexdigest() for path, value in frozen.items()},
              "traceHashes": {path.name: digest(path) for path in traces}, "reached": reached}
    (output / (name + ".json")).write_text(json.dumps(result, indent=2) + "\n")
    assert status == ("FAIL" if negative else "PASS") and run.returncode == (2 if negative else 0), f"{name}: {status} (exit {run.returncode})"
    if negative:
        assert any(path.suffix == ".vcd" for path in traces), "Missing semantic counterexample"
    if mode == "cover":
        assert len(reached) == 9, "Missing compressed fetch cover"
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rtl", type=Path, default=Path("result/rtl"))
    parser.add_argument("--source-root", type=Path, default=Path("."))
    parser.add_argument("--output", type=Path, default=Path("result/compressed-fetch-formal"))
    parser.add_argument("--case", action="append", choices=("prove", "cover", "release", "fault-address", "cross-word", "held-request"))
    parser.add_argument("--prove-depth", type=int, default=4)
    args = parser.parse_args()
    if args.prove_depth < 2:
        parser.error("Induction requires at least two steps")
    contents, bindings = freeze(args)
    tool_inputs, bindings["toolHashes"] = freeze_tools()
    args.output.mkdir(parents=True, exist_ok=True)
    archived = write_snapshot(args.output, contents)
    bindings["inputDirectory"] = "inputs"
    (args.output / "inputs.json").write_text(json.dumps(bindings, indent=2) + "\n")
    cases = [("prove", "prove", args.prove_depth, False), ("cover", "cover", 32, False)]
    cases += [(name, "bmc", 24, True) for name in ("release", "fault-address", "cross-word", "held-request")]
    cases = [item for item in cases if not args.case or item[0] in args.case]
    outcomes = []
    scratch = "/data/tmp" if os.access("/data/tmp", os.W_OK) else None
    with tempfile.TemporaryDirectory(prefix="ditdah-e2-compressed-fetch-formal-", dir=scratch) as directory:
        work = Path(directory)
        frozen = write_snapshot(work, contents)
        check_inputs(tool_inputs)
        with ThreadPoolExecutor(max_workers=2) as executor:
            futures = [executor.submit(execute, work, args.output, contents["rtl/DitDahE2Fetch.sv"].decode(),
                                       contents["test/compressed_fetch_formal.sv"], *case) for case in cases]
            for future in as_completed(futures):
                outcomes.append(future.result())
                outcomes.sort(key=lambda value: next(index for index, case in enumerate(cases) if case[0] == value["name"]))
                (args.output / "outcomes.json").write_text(json.dumps(outcomes, indent=2) + "\n")
        check_inputs(frozen)
        check_inputs(archived)
        check_inputs(tool_inputs)
    report = {"scope": "compressed fetch request ownership and independent parcel ordering", **bindings,
              "command": "python3 test/compressed_fetch_formal.py", "selectedCases": args.case, "exitStatus": 0,
              "outcomes": outcomes, **tool_versions(),
              "oracle": "six halfwords with addresses and faults, consumed only by output handshakes",
              "assumptions": ["initial synchronous reset", "halfword aligned redirect targets",
                              "one ordered response per accepted request, at least one cycle later",
                              "stable response while backpressured", "arbitrary request, response and output delays",
                              "when pause falls, redirect is asserted in the same or previous cycle"],
              "strengthening": "DUT state relations are asserted only in the unbounded proof and never assumed",
              "negativeControls": ["release a faulty low halfword with its whole word", "report the instruction PC for a second-part fault",
                                   "swap the halves of a crossing instruction", "change an offered request address on redirect"],
              "excluded": ["execution and retirement proof", "instruction decode", "eventual memory response", "other reset vectors"]}
    (args.output / "summary.json").write_text(json.dumps(report, indent=2) + "\n")
    print(f"PASS: {len(outcomes)} compressed fetch formal checks")


if __name__ == "__main__":
    main()
