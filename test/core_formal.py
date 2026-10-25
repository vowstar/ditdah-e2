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
import tempfile


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def source_hashes(root):
    paths = sorted((root / "ditdah_e2/src").glob("*.scala"))
    paths += sorted((root / "nix").glob("*.nix"))
    paths += [root / name for name in ("flake.nix", "flake.lock", "scripts/build_rtl.py")]
    return {str(path.relative_to(root)): digest(path) for path in paths}


def check_inputs(frozen):
    if any(not path.is_file() or path.read_bytes() != value for path, value in frozen.items()):
        raise RuntimeError("Core formal inputs changed during verification")


def freeze_design(rtl, root, wrapper, runner):
    manifest_bytes = (rtl / "manifest.json").read_bytes()
    manifest = json.loads(manifest_bytes)
    parameters = manifest["parameters"]
    assert (isinstance(parameters, dict) and not parameters.keys() - {"resetVector", "enableM", "enableC", "protectedMode"}
            and type(parameters.get("resetVector")) is int and parameters["resetVector"] == 0
            and type(parameters.get("enableM", False)) is bool
            and type(parameters.get("enableC", False)) is bool
            and type(parameters.get("protectedMode", False)) is bool), "Unsupported formal ROM configuration"
    assert manifest["sourceHashes"] == source_hashes(root), "Stale RTL inputs"
    contents = {"manifest.json": manifest_bytes, "test/" + wrapper.name: wrapper.read_bytes(),
                "test/" + runner.name: runner.read_bytes()}
    for name, value in manifest["sourceHashes"].items():
        data = (root / name).read_bytes()
        assert hashlib.sha256(data).hexdigest() == value, "Changed source input"
        contents["source/" + name] = data
    for name, value in manifest["rtlHashes"].items():
        data = (rtl / name).read_bytes()
        assert hashlib.sha256(data).hexdigest() == value, "Changed RTL input"
        contents["rtl/" + name] = data
    assert manifest["sourceHashes"] == source_hashes(root), "Inputs changed before freezing"
    bindings = {
        "parameters": manifest["parameters"], "sourceHashes": manifest["sourceHashes"],
        "rtlHashes": manifest["rtlHashes"], "manifestHash": hashlib.sha256(manifest_bytes).hexdigest(),
        "wrapperHash": hashlib.sha256(contents["test/" + wrapper.name]).hexdigest(),
        "runnerHash": hashlib.sha256(contents["test/" + runner.name]).hexdigest()}
    return manifest, contents, bindings


def write_snapshot(work, contents):
    frozen = {}
    for name, value in contents.items():
        path = work / "inputs" / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(value)
        frozen[path] = value
    check_inputs(frozen)
    return frozen


def mutate_trap_cancellation(content):
    pattern = r"xValid <= ~(\w+) & ([^;]+);"
    matches = list(re.finditer(pattern, content))
    assert len(matches) == 1, "Trap cancellation mutation no longer matches RTL"
    match = matches[0]
    definitions = dict(re.findall(r"wire\s+(\w+)\s*=\s*([^;]+);", content))

    def terms(name, visited=()):
        assert name not in visited, "Cyclic cancellation guard"
        expression = definitions.get(name, "").strip()
        if name == "trap" or not re.fullmatch(r"\w+(?:\s*\|\s*\w+)*", expression):
            return [name]
        result = []
        for item in re.split(r"\s*\|\s*", expression):
            result.extend(terms(item, (*visited, name)))
        return list(dict.fromkeys(result))

    causes = terms(match[1])
    assert {"trap", "interrupt", "returning", "waiting", "waking"} <= set(causes), "Changed cancellation semantics"
    retained = " | ".join(cause for cause in causes if cause != "trap")
    replacement = f"xValid <= ~({retained}) & {match[2]};"
    return content[:match.start()] + replacement + content[match.end():]


def run_case(work, output, rtl, wrapper_name, wrapper, top, name, mode, engine, depth, mutation=None, parameters=()):
    directory = work / name
    directory.mkdir()
    for filename, value in rtl.items():
        content = value.decode()
        if mutation and filename == "DitDahE2.sv":
            content = mutation(content)
        (directory / filename).write_text(content)
    (directory / wrapper_name).write_bytes(wrapper)
    names = [*rtl, wrapper_name]
    macros = ["REACHABILITY"] if mode == "cover" else []
    options = "".join(f"-D{macro} " for macro in macros)
    parameter_script = "".join(f"chparam -set {key} {value} {top}\n" for key, value in parameters)
    replay = "aigsmt z3\n" if engine.startswith("abc ") else ""
    config = (f"[options]\nmode {mode}\ndepth {depth}\n{replay}"
              f"[engines]\n{engine}\n[script]\n"
              f"read -formal -sv {options}{' '.join(names)}\n{parameter_script}prep -top {top}\n"
              "[files]\n" + "\n".join(names) + "\n")
    (directory / "run.sby").write_text(config)
    (output / f"{name}.sby").write_text(config)
    frozen = {path: path.read_bytes() for path in directory.iterdir() if path.is_file()}
    archive = output / f"{name}-inputs"
    archive.mkdir(exist_ok=True)
    archived = {}
    for path, value in frozen.items():
        saved = archive / path.name
        saved.write_bytes(value)
        archived[saved] = value
    check_inputs(frozen)
    check_inputs(archived)
    print(f"Running {top} {name} with {engine}", flush=True)
    run = subprocess.run(["sby", "-f", "run.sby"], cwd=directory, capture_output=True, text=True)
    (output / f"{name}.txt").write_text((run.stdout + run.stderr).replace(str(work), "<workspace>"))
    check_inputs(frozen)
    check_inputs(archived)
    status_path = directory / "run/status"
    status = status_path.read_text().split()[0] if status_path.is_file() else "ERROR"
    traces = list((directory / "run/engine_0").glob("trace*.*"))
    for trace in traces:
        shutil.copyfile(trace, output / f"{name}-{trace.name}")
    outcome = {"name": name, "mode": mode, "engine": engine, "depth": depth,
               "defines": macros,
               "parameters": dict(parameters),
               "inputDirectory": archive.name,
               "status": status, "exitStatus": run.returncode,
               "inputHashes": {path.name: hashlib.sha256(value).hexdigest() for path, value in frozen.items()},
               "traceHashes": {trace.name: digest(trace) for trace in traces}}
    (output / f"{name}.json").write_text(json.dumps(outcome, indent=2) + "\n")
    expected = "FAIL" if mutation else "PASS"
    assert status == expected and run.returncode == (2 if mutation else 0), f"{name}: {status} (exit {run.returncode})"
    if mutation:
        assert any(trace.suffix == ".vcd" for trace in traces), "Missing semantic counterexample"
    return outcome


def tool_versions():
    commands = {"yosys": ["yosys", "-V"], "sby": ["sby", "--version"],
                "abc": ["yosys-abc", "-c", "version"], "solver": ["z3", "--version"]}
    return {name: subprocess.check_output(command, text=True).strip() for name, command in commands.items()}


def freeze_tools():
    paths = {name: Path(shutil.which(name)) for name in ("yosys", "yosys-abc", "sby", "z3")}
    frozen = {path: path.read_bytes() for path in paths.values()}
    hashes = {name: hashlib.sha256(frozen[path]).hexdigest() for name, path in paths.items()}
    return frozen, hashes


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rtl", type=Path, default=Path("result/rtl"))
    parser.add_argument("--output", type=Path, default=Path("result/core-formal"))
    parser.add_argument("--source-root", type=Path, default=Path("."))
    parser.add_argument("--depth", type=int, default=48)
    parser.add_argument("--case", action="append", choices=("safety", "reachability", "negative"))
    args = parser.parse_args()
    if args.depth < 48:
        parser.error("The ROM coverage requires at least 48 cycles")
    wrapper = Path(__file__).with_suffix(".sv")
    manifest, contents, bindings = freeze_design(args.rtl, args.source_root, wrapper, Path(__file__))
    tool_inputs, bindings["toolHashes"] = freeze_tools()
    args.output.mkdir(parents=True, exist_ok=True)
    archived = write_snapshot(args.output, contents)
    bindings["inputDirectory"] = "inputs"
    (args.output / "inputs.json").write_text(json.dumps(bindings, indent=2) + "\n")
    scratch = "/data/tmp" if os.access("/data/tmp", os.W_OK) else None
    outcomes = []
    with tempfile.TemporaryDirectory(prefix="ditdah-e2-core-formal-", dir=scratch) as directory:
        work = Path(directory)
        frozen = write_snapshot(work, contents)
        check_inputs(tool_inputs)
        rtl = {name: contents["rtl/" + name] for name in manifest["rtlHashes"]}
        for name, mode, engine, negative in (("safety", "bmc", "abc bmc3", False),
                                             ("reachability", "cover", "smtbmc z3", False),
                                             ("negative", "bmc", "abc bmc3", True)):
            if args.case and name not in args.case:
                continue
            outcome = run_case(work, args.output, rtl, wrapper.name, contents["test/" + wrapper.name],
                               "core_formal", name, mode, engine, args.depth,
                               mutate_trap_cancellation if negative else None)
            outcomes.append(outcome)
            (args.output / "outcomes.json").write_text(json.dumps(outcomes, indent=2) + "\n")
        check_inputs(frozen)
        check_inputs(tool_inputs)
        check_inputs(archived)
    report = {
        "scope": "bounded precise load fault, younger store/CSR/MRET cancellation and data ownership",
        **bindings,
        "assumptions": ["initial synchronous reset", "fixed ROM with three younger instruction choices",
                        "ordered memory peers with arbitrary request and response delays",
                        "data fault response at least four cycles after request acceptance",
                        "interrupt inputs and time input tied to zero",
                        "no eventual response assumption"],
        "command": f"python3 test/core_formal.py --depth {args.depth}",
        "exitStatus": 0, "outcomes": outcomes, "selectedCases": args.case,
        "negativeControl": "retain the younger X instruction on trap entry",
        "coverSchedule": "ready requests, prompt fetch responses except the younger word, data response after seven cycles",
        **tool_versions(),
        "excluded": ["unbounded core proof", "arbitrary programs", "nonzero reset vectors", "memory liveness"]}
    (args.output / "summary.json").write_text(json.dumps(report, indent=2) + "\n")
    print(f"PASS: {len(outcomes)} core formal checks at depth {args.depth}")


if __name__ == "__main__":
    main()
