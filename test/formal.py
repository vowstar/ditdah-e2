# SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
# SPDX-License-Identifier: MIT
"""Prove fetch transaction ownership under an ordered, backpressured memory peer."""

import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from build_rtl import digest, sources


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rtl", type=Path, default=Path("result/rtl"))
    parser.add_argument("--output", type=Path, default=Path("result/formal"))
    args = parser.parse_args()
    manifest = json.loads((args.rtl / "manifest.json").read_text())
    assert manifest["sourceHashes"] == sources(), "Stale RTL inputs"
    source = args.rtl / "DitDahE2Fetch.sv"
    assert digest(source) == manifest["rtlHashes"][source.name], "Changed RTL"
    args.output.mkdir(parents=True, exist_ok=True)
    scratch = "/data/tmp" if os.access("/data/tmp", os.W_OK) else None
    outcomes = []
    with tempfile.TemporaryDirectory(prefix="ditdah-e2-formal-", dir=scratch) as directory:
        work = Path(directory)
        shutil.copyfile("test/fetch_formal.sv", work / "fetch_formal.sv")
        for name, mode, depth, negative in (("prove", "prove", 12, False),
                                            ("cover", "cover", 24, False),
                                            ("negative", "bmc", 12, True)):
            rtl = source.read_text()
            declaration = "module DitDahE2Fetch("
            assert rtl.count(declaration) == 1 and rtl.count("endmodule") == 1
            rtl = rtl.replace(declaration, declaration + "\n"
                "  output formal_active, formal_sent, formal_discarded, formal_buffered,\n"
                "  output [31:0] formal_next_pc,\n")
            rtl = rtl.replace("endmodule", "\n"
                "  assign formal_active = active;\n  assign formal_sent = sent;\n"
                "  assign formal_discarded = discarded;\n  assign formal_buffered = buffered;\n"
                "  assign formal_next_pc = nextPc;\nendmodule")
            if negative:
                old = "assign memory_request_bits_address = address;"
                assert old in rtl, "Negative control does not match generated RTL"
                rtl = rtl.replace(old, "assign memory_request_bits_address = redirect ? target : address;")
            (work / "DitDahE2Fetch.sv").write_text(rtl)
            config = (f"[options]\nmode {mode}\ndepth {depth}\n"
                      "[engines]\nsmtbmc z3\n[script]\n"
                      "read -formal DitDahE2Fetch.sv fetch_formal.sv\n"
                      "prep -top fetch_formal\n[files]\nDitDahE2Fetch.sv\nfetch_formal.sv\n")
            (work / f"{name}.sby").write_text(config)
            run = subprocess.run(["sby", "-f", f"{name}.sby"], cwd=work, capture_output=True, text=True)
            # Replace only this task's temporary root in retained diagnostics.
            (args.output / f"{name}.txt").write_text((run.stdout + run.stderr).replace(str(work), "<workspace>"))
            status = (work / name / "status").read_text().split()[0]
            expected = "FAIL" if negative else "PASS"
            for trace in (work / name / "engine_0").glob("trace*.*"):
                shutil.copyfile(trace, args.output / f"{name}-{trace.name}")
            assert status == expected and run.returncode == (2 if negative else 0), f"{name}: {status} (exit {run.returncode})"
            if negative:
                assert list((work / name / "engine_0").glob("trace*.vcd")), "Missing semantic counterexample"
            outcomes.append({"name": name, "mode": mode, "depth": depth,
                             "status": status, "exitStatus": run.returncode})
    report = {"scope": "fetch ownership, stable requests, redirect draining and fault metadata",
              "assumptions": ["initial synchronous reset", "aligned redirect target",
                              "one ordered response per accepted request, at least one cycle later",
                              "stable response while backpressured", "no liveness fairness assumption"],
              "rtlHash": digest(source), "wrapperHash": digest(Path("test/fetch_formal.sv")),
              "command": "python3 test/formal.py", "exitStatus": 0, "outcomes": outcomes,
              "yosys": subprocess.check_output(["yosys", "-V"], text=True).strip(),
              "sby": subprocess.check_output(["sby", "--version"], text=True).strip(),
              "solver": subprocess.check_output(["z3", "--version"], text=True).strip(),
              "excluded": ["execution and retirement proof", "data port proof", "eventual memory response"]}
    (args.output / "summary.json").write_text(json.dumps(report, indent=2) + "\n")
    print("PASS: fetch induction, reachable covers and a semantic negative control")


if __name__ == "__main__":
    main()
