# SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
# SPDX-License-Identifier: MIT
"""Check bounded fetch recovery with a one-cycle memory response."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile

from compressed_fetch_formal import freeze
from core_formal import check_inputs, digest, freeze_tools, tool_versions, write_snapshot
from fetch_throughput import bubble


def accept(mode, status, code, witnesses, reached):
    if mode == "negative":
        assert status == "FAIL" and code == 2 and witnesses, "Missing semantic latency counterexample"
    else:
        assert status == "PASS" and code == 0, "Latency check did not pass"
        if mode == "cover":
            assert reached == 3, "Missing latency cover"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rtl", type=Path, default=Path("result/rtl"))
    parser.add_argument("--source-root", type=Path, default=Path("."))
    parser.add_argument("--output", type=Path, default=Path("result/fetch-latency"))
    args = parser.parse_args()
    contents, bindings = freeze(args)
    for name in ("fetch_latency.py", "fetch_latency.sv", "test_fetch_latency.py", "fetch_throughput.py"):
        contents["test/" + name] = Path(__file__).with_name(name).read_bytes()
    bindings["inputHelperHash"] = bindings["runnerHash"]
    bindings["runnerHash"] = digest(Path(__file__))
    bindings["wrapperHash"] = digest(Path(__file__).with_suffix(".sv"))
    bindings["mutationHelperHash"] = digest(Path(__file__).with_name("fetch_throughput.py"))
    tool_inputs, bindings["toolHashes"] = freeze_tools()
    args.output.mkdir(parents=True, exist_ok=True)
    archived = write_snapshot(args.output, contents)
    compressed = bindings["parameters"].get("enableC", False)
    outcomes = []
    scratch = "/data/tmp" if os.access("/data/tmp", os.W_OK) else None
    with tempfile.TemporaryDirectory(prefix="ditdah-e2-fetch-latency-", dir=scratch) as directory:
        work = Path(directory)
        for name, mode in (("bound", "bmc"), ("cover", "cover"), ("negative", "bmc")):
            case = work / name
            case.mkdir()
            rtl = contents["rtl/DitDahE2Fetch.sv"].decode()
            if name == "negative":
                rtl = bubble(rtl)
            (case / "DitDahE2Fetch.sv").write_text(rtl)
            (case / "fetch_latency.sv").write_bytes(contents["test/fetch_latency.sv"])
            config = (f"[options]\nmode {mode}\ndepth 20\n[engines]\nsmtbmc z3\n[script]\n"
                      "read -formal -sv DitDahE2Fetch.sv fetch_latency.sv\n"
                      f"chparam -set COMPRESSED {int(compressed)} fetch_latency\nprep -top fetch_latency\n"
                      "[files]\nDitDahE2Fetch.sv\nfetch_latency.sv\n")
            (case / "run.sby").write_text(config)
            frozen = {path: path.read_bytes() for path in case.iterdir()}
            saved = write_snapshot(args.output / name, {path.name: value for path, value in frozen.items()})
            run = subprocess.run(["sby", "-f", "run.sby"], cwd=case, capture_output=True, text=True)
            log = (run.stdout + run.stderr).replace(str(work), "<work>")
            (args.output / (name + ".log")).write_text(log)
            check_inputs(frozen)
            check_inputs(saved)
            status_path = case / "run/status"
            status = status_path.read_text().split()[0] if status_path.is_file() else "ERROR"
            traces = list((case / "run/engine_0").glob("trace*.*"))
            for path in traces:
                shutil.copyfile(path, args.output / (name + "-" + path.name))
            reached = [{"cycle": int(step), "wrapperLine": int(line)} for step, line in
                       re.findall(r"Reached cover statement in step (\d+) at fetch_latency: fetch_latency.sv:(\d+)\.", log)]
            result = {"name": name, "mode": mode, "depth": 20, "status": status, "exitStatus": run.returncode,
                      "inputHashes": {path.name: hashlib.sha256(value).hexdigest() for path, value in frozen.items()},
                      "traceHashes": {path.name: digest(path) for path in traces}, "reached": reached}
            outcomes.append(result)
            (args.output / "outcomes.json").write_text(json.dumps(outcomes, indent=2) + "\n")
            accept(name if name == "negative" else mode, status, run.returncode,
                   any(path.suffix == ".vcd" for path in traces), len(reached))
            print(f"Fetch latency {name}: {status}", flush=True)
    check_inputs(archived)
    check_inputs(tool_inputs)
    report = {"scope": "bounded redirect recovery through 20 cycles", **bindings, **tool_versions(), "outcomes": outcomes,
              "inputHashes": {name: hashlib.sha256(value).hexdigest() for name, value in contents.items()},
              "boundCycles": 4 if compressed else 3, "command": "python3 test/fetch_latency.py", "exitStatus": 0,
              "assumptions": ["initial synchronous reset and aligned redirect targets", "one ordered response per accepted request",
                              "arbitrary delays before the selected redirect", "request and output ready after the selected redirect",
                              "one-cycle responses and no further pause or redirect until target delivery",
                              "response data is 0x00130013 and has no bus fault"],
              "excluded": ["unbounded latency proof", "CPU retirement timing", "arbitrary instruction response contents"]}
    (args.output / "summary.json").write_text(json.dumps(report, indent=2) + "\n")


if __name__ == "__main__":
    main()
