# SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
# SPDX-License-Identifier: MIT
"""Generate arithmetic RTL and prove its request, response and cancellation contracts."""

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parents[1]


def sha(value):
    return hashlib.sha256(value).hexdigest()


def replace_once(text, pattern, replacement):
    text, count = re.subn(pattern, replacement, text)
    assert count == 1, "Arithmetic mutation no longer matches RTL"
    return text


def mutate_cancel(text):
    text = replace_once(text, r"active <= ~\(cancel \| (\w+)\) & ([^;]+);", r"active <= ~\1 & \2;")
    return replace_once(text, r"valid <= ~cancel & (\([^;]+\));", r"valid <= \1;")


def mutate_duplicate(text):
    return replace_once(text, r"~\(response_valid_0 & response_ready\) & valid", "valid")


def mutate_value(text):
    return replace_once(text, r"assign response_bits = value;", "assign response_bits = value ^ {32{response_ready}};")


def configuration(mode, engine, stability=False):
    replay = "aigsmt z3\n" if engine.startswith("abc ") else ""
    define = "-DCHECK_STABILITY " if stability else ""
    return (f"[options]\nmode {mode}\ndepth 80\n{replay}[engines]\n{engine}\n"
            f"[script]\nread -formal -sv {define}DitDahE2MultiplyDivide.sv multiply_divide_formal.sv\n"
            "prep -top multiply_divide_formal\n[files]\nDitDahE2MultiplyDivide.sv\nmultiply_divide_formal.sv\n")


def freeze(root, destination):
    names = ["ditdah_e2/src/" + name for name in ("MultiplyDivide.scala", "Parameters.scala", "Interfaces.scala")]
    names += ["test/multiply_divide_formal.py", "test/multiply_divide_formal.sv", "test/multiply_divide_unit.py",
              "flake.nix", "flake.lock"]
    names += [str(path.relative_to(root)) for path in sorted((root / "nix").glob("*.nix"))]
    contents = {name: (root / name).read_bytes() for name in names}
    for name, value in contents.items():
        path = destination / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(value)
    return contents


def check_files(contents, root):
    assert all((root / name).read_bytes() == value for name, value in contents.items()), "Frozen arithmetic inputs changed"


def run_case(output, rtl, wrapper, name, mode, engine, mutation=None, stability=False):
    directory = output / "cases" / name
    directory.mkdir(parents=True, exist_ok=True)
    candidate = mutation(rtl.decode()).encode() if mutation else rtl
    inputs = {"DitDahE2MultiplyDivide.sv": candidate, "multiply_divide_formal.sv": wrapper,
              "run.sby": configuration(mode, engine, stability).encode()}
    for filename, value in inputs.items():
        (directory / filename).write_bytes(value)
    print(f"Running arithmetic {name} with {engine}", flush=True)
    result = subprocess.run(["sby", "-f", "run.sby"], cwd=directory, capture_output=True, text=True)
    (directory / "run.log").write_text((result.stdout + result.stderr).replace(str(output), "<evidence>"))
    check_files(inputs, directory)
    status_path = directory / "run/status"
    status = status_path.read_text().split()[0] if status_path.exists() else "ERROR"
    traces = list((directory / "run/engine_0").glob("trace*.*"))
    for path in traces:
        shutil.copyfile(path, directory / path.name)
    outcome = {"name": name, "mode": mode, "engine": engine, "depth": 80,
               "defines": ["CHECK_STABILITY"] if stability else [],
               "status": status, "exitStatus": result.returncode,
               "inputHashes": {filename: sha(value) for filename, value in inputs.items()},
               "traceHashes": {path.name: sha(path.read_bytes()) for path in traces}}
    (directory / "outcome.json").write_text(json.dumps(outcome, indent=2) + "\n")
    expected = "FAIL" if mutation else "PASS"
    assert status == expected and result.returncode == (2 if mutation else 0), f"{name}: {status}"
    if mutation:
        assert any(path.suffix == ".vcd" for path in traces), "Missing semantic counterexample"
    if mode == "cover":
        assert result.stdout.count("Reached cover statement") == 6, "Missing arithmetic cover witness"
    return outcome


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=Path("result/multiply-divide-formal"))
    args = parser.parse_args()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    contents = freeze(ROOT, output / "inputs")
    specification = importlib.util.spec_from_file_location("frozen_arithmetic_unit", output / "inputs/test/multiply_divide_unit.py")
    unit = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(unit)
    contents["generated/ArithmeticTop.scala"] = unit.WRAPPER.encode()
    contents["generated/arithmetic_tb.sv"] = unit.HARNESS.encode()
    contents["parameters.json"] = b'{"resetVector":0,"enableM":true}\n'
    for name in ("generated/ArithmeticTop.scala", "generated/arithmetic_tb.sv", "parameters.json"):
        path = output / "inputs" / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(contents[name])
    tools = {name: Path(shutil.which(name)) for name in
             ("elaborate-ditdah-e2", "firld", "firtool", "iverilog", "vvp", "sby", "yosys", "yosys-abc", "z3")}
    tool_hashes = {name: sha(path.read_bytes()) for name, path in tools.items()}
    commands = []
    scratch = "/data/tmp" if os.access("/data/tmp", os.W_OK) else None
    with tempfile.TemporaryDirectory(prefix="ditdah-e2-arithmetic-formal-", dir=scratch) as directory:
        work = Path(directory)
        source = work / "source"
        source.mkdir()
        for name, value in contents.items():
            if name.startswith("ditdah_e2/src/"):
                (source / Path(name).name).write_bytes(value)
        (source / "ArithmeticTop.scala").write_bytes(contents["generated/ArithmeticTop.scala"])
        (work / "parameters.json").write_bytes(contents["parameters.json"])
        env = dict(os.environ, DITDAH_E2_SOURCE=str(source))

        def run(command):
            result = subprocess.run(command, cwd=work, env=env, capture_output=True, text=True)
            commands.append({"argv": command, "exitStatus": result.returncode})
            if result.returncode:
                raise RuntimeError((result.stdout + result.stderr).replace(str(work), "<workspace>"))
            return result.stdout

        run(["elaborate-ditdah-e2", "design", "parameters.json"])
        run(["firld", *[path.name for path in sorted(work.glob("*.mlirbc"))], "--base-circuit", "DitDahE2MultiplyDivideTest",
             "--no-mangle", "--emit-bytecode", "-o", "linked.mlirbc"])
        run(["firtool", "linked.mlirbc", "--split-verilog", "-disable-all-randomization",
             "--lowering-options=noAlwaysComb,disallowLocalVariables,locationInfoStyle=none", "-o", "rtl"])
        (output / "rtl").mkdir(exist_ok=True)
        rtl = {path.name: path.read_bytes() for path in sorted((work / "rtl").glob("*.sv"))}
        for name, value in rtl.items():
            (output / "rtl" / name).write_bytes(value)
        (work / "arithmetic_tb.sv").write_bytes(contents["generated/arithmetic_tb.sv"])
        rows = unit.vectors()
        vector_text = "".join(f"{operation} {left:08x} {right:08x} {hold} {cancel}\n"
                              for operation, left, right, hold, cancel in rows)
        (work / "vectors.txt").write_text(vector_text)
        (output / "vectors.txt").write_text(vector_text)
        run(["iverilog", "-g2012", "-s", "MultiplyDivideBench", "-o", "arithmetic-sim",
             *["rtl/" + name for name in rtl], "arithmetic_tb.sv"])
        trace = run(["vvp", "arithmetic-sim"])
        (output / "arithmetic.trace").write_text(trace)
        arithmetic = {"oracleChecks": unit.check_oracle(), "vectors": len(rows), **unit.check(rows, trace),
                      "negativeControls": unit.negative_controls(rows, trace), "vectorHash": sha(vector_text.encode()),
                      "traceHash": sha(trace.encode()), "rtlHash": sha(rtl["DitDahE2MultiplyDivide.sv"])}
        (output / "arithmetic.json").write_text(json.dumps(arithmetic, indent=2) + "\n")
    cases = (("control", "prove", "abc pdr", None, False),
             ("stability", "prove", "abc pdr", None, True),
             ("reachability", "cover", "smtbmc z3", None, False),
             ("cancel", "bmc", "smtbmc z3", mutate_cancel, False),
             ("duplicate", "bmc", "smtbmc z3", mutate_duplicate, False),
             ("changed-value", "bmc", "smtbmc z3", mutate_value, True))
    outcomes = []
    for name, mode, engine, mutation, stability in cases:
        outcomes.append(run_case(output, rtl["DitDahE2MultiplyDivide.sv"], contents["test/multiply_divide_formal.sv"],
                                 name, mode, engine, mutation, stability))
        (output / "outcomes.json").write_text(json.dumps(outcomes, indent=2) + "\n")
    check_files(contents, output / "inputs")
    assert all(sha(path.read_bytes()) == tool_hashes[name] for name, path in tools.items()), "Arithmetic tools changed"
    version_commands = {"firtool": ["firtool", "--version"], "firld": ["firld", "--version"],
                        "iverilog": ["iverilog", "-V"], "vvp": ["vvp", "-V"], "sby": ["sby", "--version"],
                        "yosys": ["yosys", "-V"], "abc": ["yosys-abc", "-c", "version"], "z3": ["z3", "--version"]}
    versions = {}
    for name, command in version_commands.items():
        result = subprocess.run(command, capture_output=True, text=True, check=True)
        version = (result.stdout + result.stderr).strip()
        versions[name] = version.splitlines()[0] if name in ("iverilog", "vvp") else version
    report = {"scope": "unbounded multiply and divide control safety, response stability and 34 cycle result bound",
              "parameters": json.loads(contents["parameters.json"]), "inputHashes": {name: sha(value) for name, value in contents.items()},
              "rtlHashes": {name: sha(value) for name, value in rtl.items()}, "toolHashes": tool_hashes, "tools": versions,
              "commands": commands, "command": "python3 test/multiply_divide_formal.py", "exitStatus": 0,
              "arithmetic": arithmetic, "outcomes": outcomes,
              "assumptions": ["initial synchronous reset", "blocked input request and operands remain stable"],
              "stateStrengthening": "none", "readyAssumption": "none", "arithmeticAbstraction": "none",
              "covers": ["request acceptance", "cancellation at cycle 17", "cancellation at cycle 34",
                         "cancellation of a blocked result", "result accepted after backpressure", "two completed requests"],
              "excluded": ["formal arithmetic equivalence", "CPU integration", "eventual response acceptance", "warm reset"]}
    (output / "summary.json").write_text(json.dumps(report, indent=2) + "\n")
    print(f"PASS: {len(rows)} arithmetic vectors, two unbounded proofs, six covers and three formal counterexamples")


if __name__ == "__main__":
    main()
