# SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
# SPDX-License-Identifier: MIT
"""Check learned target identity, privilege, correction ownership and clearing."""

import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess


def sha(data):
    return hashlib.sha256(data).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rtl", type=Path, default=Path("result/rtl"))
    parser.add_argument("--output", type=Path, default=Path("result/branch-prediction"))
    args = parser.parse_args()
    if args.output.exists() and any(args.output.iterdir()):
        raise ValueError("Prediction output directory must be empty")
    args.output.mkdir(parents=True)
    manifest_bytes = (args.rtl / "manifest.json").read_bytes()
    manifest = json.loads(manifest_bytes)
    assert manifest["parameters"].get("branchPrediction"), "Prediction must be enabled"
    rtl = (args.rtl / "DitDahE2BranchPrediction.sv").read_bytes()
    assert sha(rtl) == manifest["rtlHashes"]["DitDahE2BranchPrediction.sv"]
    wrapper = Path(__file__).with_name("branch_prediction.sv").read_bytes()
    report = {"scope": "Learned target unit port contract, not a complete CPU proof", "exitStatus": None,
              "manifestHash": sha(manifest_bytes), "rtlHash": sha(rtl), "wrapperHash": sha(wrapper),
              "runnerHash": sha(Path(__file__).read_bytes()), "outcomes": [],
              "contract": ["Every mismatch against the independently captured target requires correction",
                           "Without an intervening entry replacement, correction is exact",
                           "After target replacement, conservative correction is permitted",
                           "Clear cancels prediction ownership; execution and fetch handshakes transfer it"],
              "assumptions": ["Initial synchronous reset; all other unit inputs are unconstrained"]}
    for name, mode, engine in (("safety", "prove", "abc pdr"), ("cover", "cover", "smtbmc z3"),
                               ("ignore-clear", "bmc", "smtbmc z3"),
                               ("lost-fetch-replacement", "bmc", "smtbmc z3"),
                               ("lost-pending-replacement", "bmc", "smtbmc z3"),
                               ("bare-current-target", "bmc", "smtbmc z3")):
        directory = args.output / name
        directory.mkdir()
        source = rtl.decode()
        if name == "ignore-clear":
            source, count = re.subn(r"~clear\b", "1'h1", source)
            assert count == 3, "Clear mutation no longer matches RTL"
        mutations = {
            "lost-fetch-replacement": ("? hit & replacement", "? 1'h0"),
            "lost-pending-replacement": ("predicted & replacement | replaced", "replaced"),
            "bare-current-target": ("replaced | targetPc != executeNextPc", "targetPc != executeNextPc")}
        if name in mutations:
            before, after = mutations[name]
            assert source.count(before) == 1, "Replacement mutation no longer matches RTL"
            source = source.replace(before, after)
        (directory / "DitDahE2BranchPrediction.sv").write_text(source)
        (directory / "branch_prediction.sv").write_bytes(wrapper)
        replay = "aigsmt z3\n" if mode == "prove" else ""
        script = (f"[options]\nmode {mode}\ndepth 12\n{replay}[engines]\n{engine}\n"
                  "[script]\nread -formal -sv DitDahE2BranchPrediction.sv branch_prediction.sv\n"
                  "prep -top branch_prediction\n[files]\nDitDahE2BranchPrediction.sv\nbranch_prediction.sv\n")
        (directory / "run.sby").write_text(script)
        run = subprocess.run(["sby", "-f", "run.sby"], cwd=directory, capture_output=True, text=True)
        log = run.stdout + run.stderr
        (directory / "run.log").write_text(log)
        status = (directory / "run/status").read_text().split()[0]
        negative = name in ("ignore-clear", *mutations)
        assert status == ("FAIL" if negative else "PASS") and run.returncode == (2 if negative else 0), name
        traces = list((directory / "run/engine_0").glob("trace*.vcd"))
        if negative:
            assert traces, "Missing semantic counterexample"
        if mode == "cover":
            assert log.count("Reached cover statement") == 14, "Missing prediction cover"
        report["outcomes"].append({"name": name, "status": status, "engine": engine, "exitStatus": run.returncode,
                                   "rtlHash": sha(source.encode()), "traceHashes": {p.name: sha(p.read_bytes()) for p in traces}})
    report["exitStatus"] = 0
    report["tools"] = {name: subprocess.check_output(command, text=True).strip() for name, command in (
        ("sby", ["sby", "--version"]), ("yosys", ["yosys", "-V"]), ("z3", ["z3", "--version"]))}
    (args.output / "summary.json").write_text(json.dumps(report, indent=2) + "\n")
    print("PASS: learned target safety, coverage and four effective RTL controls")


if __name__ == "__main__":
    main()
