# SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
# SPDX-License-Identifier: MIT
"""Run bounded SBA protocol reference checks and reachable covers on frozen RTL."""

import argparse
import hashlib
import json
import shutil
import subprocess
import sys
from pathlib import Path

if not __package__:
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from test.test_sba.verify_sba import mutate


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run(work, rtl, wrapper, mode, depth, timeout, top="debug_sba_formal", module="DitDahE2DebugSystemBus"):
    work.mkdir()
    (work / (module + ".sv")).write_text(rtl)
    (work / (top + ".sv")).write_bytes(wrapper)
    script = (f"read_verilog -formal -sv {module}.sv {top}.sv\n"
              f"prep -top {top}\nasync2sync\ndffunmap\nwrite_smt2 -wires model.smt2\n")
    (work / "run.ys").write_text(script)
    commands = []
    for argv in (("yosys", "-Q", "-s", "run.ys"),
                 ("yosys-smtbmc", "-s", "z3", "-t", str(depth), "--dump-vcd", "trace.vcd",
                  *(["-c"] if mode == "cover" else []), "model.smt2")):
        name = "compile.log" if argv[0] == "yosys" else "solver.log"
        try:
            with (work / name).open("w") as stream:
                result = subprocess.run(argv, cwd=work, stdout=stream, stderr=subprocess.STDOUT,
                                        text=True, check=False, timeout=timeout)
        except subprocess.TimeoutExpired:
            (work / "timeout.json").write_text(json.dumps({"argv": list(argv), "seconds": timeout,
                                                           "result": "unknown_timeout"}, indent=2) + "\n")
            raise
        commands.append({"argv": list(argv), "exitStatus": result.returncode})
        if argv[0] == "yosys" and result.returncode:
            raise RuntimeError("SBA formal compilation failed")
    report = {"mode": mode, "depth": depth, "commands": commands, "exitStatus": result.returncode,
              "rtlSha256": digest(work / (module + ".sv")),
              "wrapperSha256": digest(work / (top + ".sv")),
              "solverLogSha256": digest(work / "solver.log")}
    if (work / "trace.vcd").exists():
        report["traceSha256"] = digest(work / "trace.vcd")
    (work / "outcome.json").write_text(json.dumps(report, indent=2) + "\n")
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rtl", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--depth", type=int, default=24)
    parser.add_argument("--timeout", type=int, default=180)
    args = parser.parse_args()
    if args.output.exists() or args.depth < 8 or args.timeout < 1:
        parser.error("Use a new output directory, depth>=8 and a positive timeout")
    args.output.mkdir(parents=True)
    source = args.rtl / "DitDahE2DebugSystemBus.sv" if args.rtl.is_dir() else args.rtl
    original, frozen = source.read_text(), digest(source)
    wrapper = Path(__file__).with_name("debug_sba_formal.sv").read_bytes()
    results = [run(args.output / "safety", original, wrapper, "bmc", args.depth, args.timeout),
               run(args.output / "covers", original, wrapper, "cover", args.depth, args.timeout),
               run(args.output / "negative-write-mask", mutate(original, "missing-write-lanes"),
                   wrapper, "bmc", args.depth, args.timeout)]
    if [item["exitStatus"] for item in results] != [0, 0, 1]:
        raise AssertionError("SBA bounded safety, covers or effective RTL negative did not qualify")
    if frozen != digest(source):
        raise AssertionError("SBA source RTL changed during reference checks")
    summary = {"scope": "bounded standalone SBA protocol reference, no completion latency assumption",
               "unboundedProven": False, "commercialGate": "not_run", "exitStatus": 0,
               "results": results, "tools": {name: digest(Path(shutil.which(name)).resolve())
                                              for name in ("yosys", "yosys-smtbmc", "z3")}}
    (args.output / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    print(f"PASS: SBA bounded protocol reference at depth {args.depth}, nine covers and an effective RTL negative")


if __name__ == "__main__":
    main()
