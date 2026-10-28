# SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
# SPDX-License-Identifier: MIT
"""Synthesize frozen processor RTL into generic logic cells."""

import argparse
import json
from pathlib import Path
import re
import shutil
import subprocess

from build_rtl import digest, sources


ROOT = Path(__file__).resolve().parents[1]


def structure(design):
    modules = design.get("modules", {})
    assert set(modules) == {"DitDahE2"}, "Expected one flattened processor module"
    top = modules["DitDahE2"]
    assert not int(str(top.get("attributes", {}).get("blackbox", "0")), 2), "Black box module"
    cells = top.get("cells", {})
    assert cells, "Empty synthesized design"
    counts = {}
    scopes = 0
    for cell in cells.values():
        kind = cell["type"]
        if kind == "$scopeinfo":
            assert not cell.get("connections") and not cell.get("port_directions"), "Connected scope metadata"
            assert cell.get("parameters", {}).get("TYPE") == "module", "Unknown scope metadata"
            scopes += 1
            continue
        assert re.fullmatch(r"\$_[A-Z0-9_]+_", kind), "Unresolved or unmapped cell"
        assert "LATCH" not in kind and "TBUF" not in kind, "Unsupported latch or tri-state cell"
        counts[kind] = counts.get(kind, 0) + 1
    assert counts, "Empty synthesized logic"
    return {"cells": sum(counts.values()), "scopeMetadata": scopes, "cellTypes": dict(sorted(counts.items())),
            "clockedCells": sum(value for kind, value in counts.items() if "DFF" in kind),
            "latches": 0, "blackBoxes": 0, "modules": 1}


def script(names):
    assert names and all(re.fullmatch(r"[A-Za-z][A-Za-z0-9_]*\.sv", name) for name in names), "Invalid RTL filename"
    return ("read_verilog -sv " + " ".join("inputs/rtl/" + name for name in names) + "\n"
            "synth -top DitDahE2 -flatten\n"
            "check -assert -nolatches\n"
            "tee -o statistics.json stat -json\n"
            "write_verilog -noattr generic.v\n"
            "write_json generic.json\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rtl", type=Path, default=Path("result/rtl"))
    parser.add_argument("--output", type=Path, default=Path("result/generic-synthesis"))
    args = parser.parse_args()
    assert Path.cwd() == ROOT, "Run from the project root"
    original = args.rtl / "manifest.json"
    manifest = json.loads(original.read_text())
    assert manifest["sourceHashes"] == sources(), "Stale RTL source inputs"
    text = script(list(manifest["rtlHashes"]))
    args.output.mkdir(parents=True, exist_ok=False)
    output = args.output.resolve()
    bound = {original.resolve(): digest(original)}
    for group, files, parent in (("rtl", manifest["rtlHashes"], args.rtl),
                                  ("source", manifest["sourceHashes"], ROOT)):
        for name, value in files.items():
            relative = Path(name)
            assert not relative.is_absolute() and ".." not in relative.parts, "Unsafe input path"
            source = parent / relative
            assert not source.is_symlink() and digest(source) == value, "Changed synthesis input"
            target = output / "inputs" / group / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, target)
            bound[source.resolve()] = value
    shutil.copy2(original, output / "inputs/manifest.json")
    shutil.copy2(__file__, output / "inputs/synthesize.py")
    (output / "synthesis.ys").write_text(text)
    tools = {}
    for name, version in (("yosys", ["-V"]), ("yosys-abc", ["-c", "version"])):
        path = Path(shutil.which(name)).resolve()
        result = subprocess.run([str(path), *version], capture_output=True, text=True)
        assert result.returncode == 0, "Cannot read synthesis tool version"
        tools[name] = {"hash": digest(path), "version": (result.stdout + result.stderr).strip()}
        bound[path] = digest(path)
    bound[Path(__file__).resolve()] = digest(Path(__file__))
    frozen = {str(path.relative_to(output)): digest(path) for path in (output / "inputs").rglob("*") if path.is_file()}
    command = ["yosys", "-Q", "-T", "-s", "synthesis.ys"]
    report = {"scope": "generic processor synthesis", "exitStatus": 1,
              "parameters": manifest["parameters"], "instructions": manifest["instructions"],
              "sourceHashes": manifest["sourceHashes"], "rtlHashes": manifest["rtlHashes"],
              "manifestHash": digest(original), "inputHashes": frozen, "tools": tools,
              "command": command, "technologyArea": None, "physicalFrequency": None}
    try:
        result = subprocess.run(command, cwd=output, capture_output=True, text=True)
        (output / "synthesis.log").write_text(result.stdout + result.stderr)
        report["toolExitStatus"] = result.returncode
        assert result.returncode == 0, "Generic synthesis failed"
        report["structure"] = structure(json.loads((output / "generic.json").read_text()))
        report["statistics"] = json.loads((output / "statistics.json").read_text())
        assert all(digest(path) == value for path, value in bound.items()), "Synthesis source changed"
        assert all(digest(output / name) == value for name, value in frozen.items()), "Frozen synthesis input changed"
        report["artifactHashes"] = {name: digest(output / name) for name in
                                    ("generic.v", "generic.json", "statistics.json", "synthesis.ys", "synthesis.log")}
        report["exitStatus"] = 0
    finally:
        (output / "summary.json").write_text(json.dumps(report, indent=2) + "\n")
    print("PASS: generic processor synthesis")


if __name__ == "__main__":
    main()
