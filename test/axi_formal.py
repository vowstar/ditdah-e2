# SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
# SPDX-License-Identifier: MIT
"""Prove AXI adapter safety and reach legal channel schedules."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile


def sha(value):
    return hashlib.sha256(value).hexdigest()


def mutate_owner(content):
    pattern = r"(assign\s+data_response_valid\s*=\s*)([^;]+);"
    changed, count = re.subn(pattern, r"\g<1>instruction_response_valid;", content)
    assert count == 1, "Owner mutation no longer matches RTL"
    return changed


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rtl", type=Path, default=Path("result/axi"))
    parser.add_argument("--output", type=Path, default=Path("result/axi-formal"))
    args = parser.parse_args()
    summary_bytes = (args.rtl / "summary.json").read_bytes()
    summary = json.loads(summary_bytes)
    assert summary["exitStatus"] == 0 and summary["scope"] == "standalone dual native port to AXI4-Lite adapter", "Wrong RTL candidate"
    contents = {"summary.json": summary_bytes}
    for name, value in summary["inputHashes"].items():
        data = (args.rtl / "inputs" / name).read_bytes()
        assert sha(data) == value, "Changed adapter source snapshot"
        contents["source/" + name] = data
    for name, value in summary["rtlHashes"].items():
        data = (args.rtl / name).read_bytes()
        assert sha(data) == value, "Changed adapter RTL"
        contents["rtl/" + name] = data
    for name in ("axi_formal.py", "axi_formal.sv"):
        contents["test/" + name] = Path(__file__).with_name(name).read_bytes()
    tool_inputs = {name: Path(shutil.which(name)).read_bytes() for name in ("sby", "yosys", "yosys-abc", "z3")}
    args.output.mkdir(parents=True, exist_ok=True)
    for name, data in contents.items():
        path = args.output / "inputs" / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
    outcomes = []
    scratch = "/data/tmp" if os.access("/data/tmp", os.W_OK) else None
    with tempfile.TemporaryDirectory(prefix="ditdah-e2-axi-formal-", dir=scratch) as directory:
        work = Path(directory)
        for name, mode, engine in (("safety", "prove", "abc pdr"), ("reachability", "cover", "smtbmc z3"),
                                   ("wrong-owner", "bmc", "smtbmc z3"), ("wrong-privilege", "bmc", "smtbmc z3"),
                                   ("wrong-atomic", "bmc", "smtbmc z3")):
            case = work / name
            case.mkdir()
            rtl = contents["rtl/DitDahE2AxiLite.sv"].decode()
            if name == "wrong-owner":
                rtl = mutate_owner(rtl)
            if name == "wrong-privilege":
                rtl, count = re.subn(r"(assign\s+axi_ar_bits_protection\s*=\s*)([^;]+);", r"\g<1>3'd5;", rtl)
                assert count == 1, "Privilege mutation no longer matches RTL"
            if name == "wrong-atomic":
                rtl, count = re.subn(r"(wire\s+unsupported\s*=\s*)([^;]+);", r"\g<1>1'b0;", rtl)
                assert count == 1, "Atomic rejection mutation no longer matches RTL"
            (case / "DitDahE2AxiLite.sv").write_text(rtl)
            (case / "axi_formal.sv").write_bytes(contents["test/axi_formal.sv"])
            replay = "aigsmt z3\n" if engine.startswith("abc ") else ""
            config = (f"[options]\nmode {mode}\ndepth 24\n{replay}[engines]\n{engine}\n"
                      "[script]\nread -formal -sv DitDahE2AxiLite.sv axi_formal.sv\nprep -top axi_formal\n"
                      "[files]\nDitDahE2AxiLite.sv\naxi_formal.sv\n")
            (case / "run.sby").write_text(config)
            (args.output / f"{name}.sby").write_text(config)
            frozen = {path: path.read_bytes() for path in case.iterdir()}
            print(f"Running AXI {name} with {engine}", flush=True)
            result = subprocess.run(["sby", "-f", "run.sby"], cwd=case, capture_output=True, text=True)
            (args.output / f"{name}.log").write_text((result.stdout + result.stderr).replace(str(work), "<workspace>"))
            assert all(path.read_bytes() == data for path, data in frozen.items()), "Formal inputs changed"
            status_path = case / "run/status"
            status = status_path.read_text().split()[0] if status_path.exists() else "ERROR"
            traces = list((case / "run/engine_0").glob("trace*.*"))
            for trace in traces:
                shutil.copyfile(trace, args.output / f"{name}-{trace.name}")
            outcome = {"name": name, "mode": mode, "engine": engine, "depth": 24,
                       "exitStatus": result.returncode, "status": status,
                       "inputHashes": {path.name: sha(data) for path, data in frozen.items()},
                       "traceHashes": {path.name: sha(path.read_bytes()) for path in traces}}
            outcomes.append(outcome)
            (args.output / "outcomes.json").write_text(json.dumps(outcomes, indent=2) + "\n")
            negative = name.startswith("wrong-")
            assert status == ("FAIL" if negative else "PASS") and result.returncode == (2 if negative else 0), f"{name}: {status}"
            if negative:
                assert any(path.suffix == ".vcd" for path in traces), "Missing semantic counterexample"
            if mode == "cover":
                assert result.stdout.count("Reached cover statement") == 14, "Missing cover witness"
        assert all(Path(shutil.which(name)).read_bytes() == value for name, value in tool_inputs.items()), "Tools changed"
    versions = {name: subprocess.check_output(command, text=True).strip() for name, command in (
        ("sby", ["sby", "--version"]), ("yosys", ["yosys", "-V"]),
        ("abc", ["yosys-abc", "-c", "version"]), ("z3", ["z3", "--version"]))}
    report = {"scope": "unbounded AXI adapter ownership, payload and channel stability safety",
              "inputHashes": {name: sha(data) for name, data in contents.items()},
              "rtlHashes": summary["rtlHashes"], "toolHashes": {name: sha(data) for name, data in tool_inputs.items()},
              "tools": versions, "outcomes": outcomes, "command": "python3 test/axi_formal.py", "exitStatus": 0,
              "assumptions": ["initial synchronous cold reset with no offered request or response",
                              "instruction requests are reads", "native request payload remains stable while blocked",
                              "AXI response follows its address and data handshakes", "no repeated AXI response",
                              "AXI response payload remains stable while blocked", "EXOKAY is excluded",
                              "no eventual acceptance or response assumption"],
              "covers": ["AW before W", "W before AW", "AW and W together", "instruction response backpressure",
                         "data response backpressure", "instruction error", "data error", "contended alternating grants",
                         "machine instruction", "user instruction", "machine data", "user data",
                         "rejected instruction operation", "rejected data operation"],
              "negativeControls": ["deliver instruction responses to the data owner", "force privileged instruction attributes",
                                   "send atomic requests to AXI"],
              "excluded": ["CPU integration", "device effects", "liveness", "reset during a transaction"]}
    (args.output / "summary.json").write_text(json.dumps(report, indent=2) + "\n")
    print("PASS: AXI unbounded safety, fourteen covers and three counterexamples")


if __name__ == "__main__":
    main()
