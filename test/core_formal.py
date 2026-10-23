# SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
# SPDX-License-Identifier: MIT
"""Check precise load faults with a fixed ROM and arbitrary memory delays."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from build_rtl import digest, sources


def check_inputs(frozen):
    if any(not path.is_file() or path.read_bytes() != value for path, value in frozen.items()):
        raise RuntimeError("Core formal inputs changed during verification")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rtl", type=Path, default=Path("result/rtl"))
    parser.add_argument("--output", type=Path, default=Path("result/core-formal"))
    parser.add_argument("--depth", type=int, default=48)
    args = parser.parse_args()
    if args.depth < 48:
        parser.error("The ROM coverage requires at least 48 cycles")
    manifest_path = args.rtl / "manifest.json"
    manifest = json.loads(manifest_path.read_text())
    assert manifest["parameters"] == {"resetVector": 0}, "Core formal ROM requires resetVector=0"
    assert manifest["sourceHashes"] == sources(), "Stale RTL inputs"
    rtl_paths = [args.rtl / name for name in manifest["rtlHashes"]]
    for path in rtl_paths:
        assert digest(path) == manifest["rtlHashes"][path.name], "Changed RTL input"
    wrapper = Path("test/core_formal.sv")
    runner = Path(__file__)
    paths = [manifest_path, wrapper, runner, *rtl_paths,
             *(Path(name) for name in manifest["sourceHashes"])]
    frozen = {path: path.read_bytes() for path in paths}
    assert manifest["sourceHashes"] == sources(), "Inputs changed before freezing"
    check_inputs(frozen)
    args.output.mkdir(parents=True, exist_ok=True)
    bindings = {
        "parameters": manifest["parameters"],
        "sourceHashes": manifest["sourceHashes"], "rtlHashes": manifest["rtlHashes"],
        "manifestHash": hashlib.sha256(frozen[manifest_path]).hexdigest(),
        "wrapperHash": hashlib.sha256(frozen[wrapper]).hexdigest(),
        "runnerHash": hashlib.sha256(frozen[runner]).hexdigest()}
    (args.output / "inputs.json").write_text(json.dumps(bindings, indent=2) + "\n")
    scratch = "/data/tmp" if os.access("/data/tmp", os.W_OK) else None
    outcomes = []
    with tempfile.TemporaryDirectory(prefix="ditdah-e2-core-formal-", dir=scratch) as directory:
        work = Path(directory)
        (work / wrapper.name).write_bytes(frozen[wrapper])
        for name, mode, engine, negative in (("safety", "bmc", "abc bmc3", False),
                                             ("reachability", "cover", "smtbmc z3", False),
                                             ("negative", "bmc", "smtbmc --unroll z3", True)):
            for path in rtl_paths:
                content = frozen[path].decode()
                if negative and path.name == "DitDahE2.sv":
                    pattern = r"xValid <= ~(\w+) & ([^;]+);"
                    matches = list(re.finditer(pattern, content))
                    assert len(matches) == 1, "Trap cancellation mutation no longer matches RTL"
                    match = matches[0]
                    assert re.search(r"wire\s+" + match[1] + r"\s*=\s*trap\s*\|\s*returning;", content)
                    content = content[:match.start()] + f"xValid <= ~returning & {match[2]};" + content[match.end():]
                (work / path.name).write_text(content)
            names = " ".join([path.name for path in rtl_paths] + [wrapper.name])
            config = (f"[options]\nmode {mode}\ndepth {args.depth}\n"
                      f"[engines]\n{engine}\n[script]\n"
                      f"read -formal -sv {names}\nprep -top core_formal\n"
                      "[files]\n" + "\n".join([path.name for path in rtl_paths] + [wrapper.name]) + "\n")
            (work / f"{name}.sby").write_text(config)
            (args.output / f"{name}.sby").write_text(config)
            print(f"Running core {name} with {engine}", flush=True)
            run = subprocess.run(["sby", "-f", f"{name}.sby"], cwd=work, capture_output=True, text=True)
            (args.output / f"{name}.txt").write_text((run.stdout + run.stderr).replace(str(work), "<workspace>"))
            status_path = work / name / "status"
            status = status_path.read_text().split()[0] if status_path.is_file() else "ERROR"
            traces = list((work / name / "engine_0").glob("trace*.*"))
            for trace in traces:
                shutil.copyfile(trace, args.output / f"{name}-{trace.name}")
            expected = "FAIL" if negative else "PASS"
            outcome = {"name": name, "mode": mode, "engine": engine, "depth": args.depth,
                       "status": status, "exitStatus": run.returncode,
                       "configurationHash": hashlib.sha256(config.encode()).hexdigest(),
                       "traceHashes": {trace.name: digest(trace) for trace in traces}}
            outcomes.append(outcome)
            (args.output / "outcomes.json").write_text(json.dumps(outcomes, indent=2) + "\n")
            assert status == expected and run.returncode == (2 if negative else 0), f"{name}: {status} (exit {run.returncode})"
            if negative:
                assert any(trace.suffix == ".vcd" for trace in traces), "Missing semantic counterexample"
    check_inputs(frozen)
    assert manifest["sourceHashes"] == sources(), "RTL inputs changed during core checks"
    report = {
        "scope": "bounded precise load fault, younger store/CSR/MRET cancellation and data ownership",
        **bindings,
        "assumptions": ["initial synchronous reset", "fixed ROM with three younger instruction choices",
                        "ordered memory peers with arbitrary request and response delays",
                        "data fault response at least four cycles after request acceptance",
                        "no eventual response assumption"],
        "command": f"python3 test/core_formal.py --depth {args.depth}",
        "exitStatus": 0, "outcomes": outcomes,
        "negativeControl": "retain the younger X instruction on trap entry",
        "yosys": subprocess.check_output(["yosys", "-V"], text=True).strip(),
        "sby": subprocess.check_output(["sby", "--version"], text=True).strip(),
        "abc": subprocess.check_output(["yosys-abc", "-c", "version"], text=True).strip(),
        "solver": subprocess.check_output(["z3", "--version"], text=True).strip(),
        "excluded": ["unbounded core proof", "arbitrary programs", "nonzero reset vectors", "memory liveness"]}
    (args.output / "summary.json").write_text(json.dumps(report, indent=2) + "\n")
    print(f"PASS: fixed-ROM core safety for {args.depth} cycles, five covers and one semantic negative control")


if __name__ == "__main__":
    main()
