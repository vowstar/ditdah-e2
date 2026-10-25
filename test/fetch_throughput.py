# SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
# SPDX-License-Identifier: MIT
"""Measure native retirement throughput with independent instruction checks."""

import argparse
import hashlib
import importlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile

from core_formal import check_inputs, digest, source_hashes, write_snapshot


def window(text, addresses, consecutive=True):
    selected = addresses[32:288]
    assert len(selected) == len(set(selected)) == 256, "Invalid measurement addresses"
    retired = [(int(parts[1]), int(parts[2])) for line in text.splitlines()
               if (parts := line.split()) and parts[0] == "R" and int(parts[2]) in set(selected)]
    assert [pc for _, pc in retired] == selected, "Missing or repeated measurement retirement"
    cycles = [cycle for cycle, _ in retired]
    intervals = [second - first for first, second in zip(cycles, cycles[1:])]
    if consecutive:
        assert intervals == [1] * 255, "Retirement gap in the measurement window"
    return {"retirements": 256, "cycles": cycles[-1] - cycles[0] + 1,
            "firstCycle": cycles[0], "lastCycle": cycles[-1],
            "intervals": {str(value): intervals.count(value) for value in sorted(set(intervals))}}


def bubble(text):
    pattern = r"\(~outstanding \| response\)"
    result, count = re.subn(pattern, "(~outstanding)", text)
    assert count == 1, "Replacement mutation no longer matches generated RTL"
    return result


def freeze(args):
    manifest_bytes = (args.rtl / "manifest.json").read_bytes()
    manifest = json.loads(manifest_bytes)
    assert manifest["sourceHashes"] == source_hashes(args.source_root), "Stale RTL inputs"
    assert manifest["parameters"]["resetVector"] == 0, "Throughput programs require resetVector=0"
    contents = {"manifest.json": manifest_bytes}
    for group, prefix, root in (("sourceHashes", "source", args.source_root), ("rtlHashes", "rtl", args.rtl)):
        for name, expected in manifest[group].items():
            value = (root / name).read_bytes()
            assert hashlib.sha256(value).hexdigest() == expected, "Changed throughput input"
            contents[prefix + "/" + name] = value
    for name in ("sim.cpp", "inactive_debug.hpp", "model.py", "bit_model.py", "bit_programs.py", "bit_pipeline.py",
                 "bit_operations.py", "pmp.py", "programs.py", "compressed_model.py", "compressed_programs.py", "compressed_unit.py", "verify.py"):
        contents["test/" + name] = (args.source_root / "test" / name).read_bytes()
    for name in ("fetch_throughput.py", "test_fetch_throughput.py", "core_formal.py"):
        contents["test/" + name] = Path(__file__).with_name(name).read_bytes()
    assert manifest["sourceHashes"] == source_hashes(args.source_root), "Inputs changed before freezing"
    return manifest, contents


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rtl", type=Path, default=Path("result/rtl"))
    parser.add_argument("--source-root", type=Path, default=Path("."))
    parser.add_argument("--output", type=Path, default=Path("result/fetch-throughput"))
    args = parser.parse_args()
    output = args.output.resolve()
    assert not output.exists() or not any(output.iterdir()), "Throughput output directory must be empty"
    output.mkdir(parents=True, exist_ok=True)
    manifest, contents = freeze(args)
    archived = write_snapshot(output, contents)
    archive = output / "inputs"
    sys.path.insert(0, str(archive / "test"))
    sys.path.insert(0, str(archive / "source/scripts"))
    for name in ("verify", "model", "programs", "compressed_model", "compressed_programs", "compressed_unit"):
        sys.modules.pop(name, None)
    verify = importlib.import_module("verify")
    programs = importlib.import_module("programs")
    compressed = importlib.import_module("compressed_programs")
    patterns = {"independent32": [(programs.immediate(1, 0, index), 4) for index in range(320)],
                "dependent32": [(programs.immediate(8, 8, 1), 4)] * 320}
    enabled = manifest["parameters"].get("enableC", False)
    if enabled:
        patterns.update({"dependent16": [(0x405, 2)] * 320,
                         "mixed": ([(0x405, 2), (programs.immediate(8, 8, 1), 4), (0x405, 2)] * 107)[:320],
                         "crossing32": [(1, 2)] + [(programs.immediate(8, 8, 1), 4)] * 320})
    tools = {name: Path(shutil.which(name)).resolve() for name in ("verilator", "verilator_bin", "c++")}
    tool_hashes = {name: digest(path) for name, path in tools.items()}
    report = {"scope": "native retirement throughput with one-cycle instruction responses", "parameters": manifest["parameters"],
              "warmupInstructions": 32, "measurementInstructions": 256,
              "intervalDefinition": "last retirement cycle minus first retirement cycle plus one",
              "inputHashes": {name: hashlib.sha256(value).hexdigest() for name, value in contents.items()},
              "toolHashes": tool_hashes,
              "verilator": subprocess.check_output(["verilator", "--version"], text=True).strip(),
              "compiler": subprocess.check_output(["c++", "--version"], text=True).splitlines()[0],
              "runs": [], "negativeControl": None, "exitStatus": None}
    (output / "summary.json").write_text(json.dumps(report, indent=2) + "\n")
    scratch = "/data/tmp" if os.access("/data/tmp", os.W_OK) else None
    with tempfile.TemporaryDirectory(prefix="ditdah-e2-throughput-", dir=scratch) as directory:
        work = Path(directory)
        for variant in ("positive", "bubble"):
            case_output = output / variant
            case_output.mkdir()
            for name in manifest["rtlHashes"]:
                value = contents["rtl/" + name]
                if variant == "bubble" and name == "DitDahE2Fetch.sv":
                    value = bubble(value.decode()).encode()
                (case_output / name).write_bytes(value)
            frozen_rtl = {path: path.read_bytes() for path in case_output.glob("*.sv")}
            objects = work / variant
            command = ["verilator", "--cc", "--exe", "--build", "-j", "2", "--top-module", "DitDahE2", "--Mdir", str(objects),
                       "-CFLAGS", "-std=c++17", *[str(case_output / name) for name in manifest["rtlHashes"]], str(archive / "test/sim.cpp")]
            compiled = subprocess.run(command, capture_output=True, text=True)
            log = (compiled.stdout + compiled.stderr).replace(str(output), "<evidence>").replace(str(work), "<work>")
            (case_output / "build.log").write_text(log)
            assert compiled.returncode == 0, "Throughput RTL compilation failed"
            executable = objects / "VDitDahE2"
            executable_hash = digest(executable)
            for name, sequence in patterns.items():
                if variant == "bubble" and name != "independent32":
                    continue
                cursor = 0
                addresses = []
                for _, length in sequence:
                    addresses.append(cursor)
                    cursor += length
                if name == "crossing32":
                    addresses = addresses[1:]
                image = compressed._image(((0, sequence + [(programs.jump(0, 0x3000 - cursor), 4)]), (0x3000, [(0x6f, 4)])))
                case = compressed.CompressedCase(name, image, 0, 0, 0x2000, 0x3000, enable_c=enabled,
                                                enable_m=manifest["parameters"].get("enableM", False),
                                                enable_a=manifest["parameters"].get("enableA", False),
                                                protected_mode=manifest["parameters"].get("protectedMode", False),
                                                enable_zba=manifest["parameters"].get("enableZba", False),
                                                enable_zbb=manifest["parameters"].get("enableZbb", False),
                                                enable_zbs=manifest["parameters"].get("enableZbs", False))
                image_path = case_output / (name + ".hex")
                image_path.write_text("".join(f"{address:08x} {word:08x}\n" for address, word in sorted(image.items())))
                image_hash = digest(image_path)
                arguments = [str(executable), str(image_path), "1", "0", str(1 << 32), str(1 << 32), "20000", str(0x3000)]
                run = subprocess.run(arguments, capture_output=True, text=True)
                trace = case_output / (name + ".trace")
                trace.write_text(run.stdout)
                assert run.returncode == 0, "Throughput program did not complete"
                metrics = verify.check(case, run.stdout)
                measured = window(run.stdout, addresses, consecutive=variant == "positive")
                assert digest(image_path) == image_hash and digest(executable) == executable_hash, "Simulation inputs changed"
                record = {"program": name, "window": measured, "checkedRetirements": metrics["retired"],
                          "totalCycles": metrics["cycles"], "exitStatus": run.returncode, "imageHash": image_hash,
                          "traceHash": digest(trace), "binaryHash": executable_hash,
                          "rtlHashes": {path.name: hashlib.sha256(value).hexdigest() for path, value in frozen_rtl.items()},
                          "command": [part.replace(str(output), "<evidence>").replace(str(work), "<work>") for part in arguments],
                          "buildCommand": [part.replace(str(output), "<evidence>").replace(str(work), "<work>") for part in command]}
                if variant == "positive":
                    report["runs"].append(record)
                else:
                    try:
                        window(run.stdout, addresses)
                    except AssertionError as error:
                        assert "Retirement gap" in str(error), "Unexpected performance counterexample"
                        record["checkerError"] = str(error)
                    else:
                        raise AssertionError("Performance checker accepted a replacement bubble")
                    report["negativeControl"] = record
                (output / "summary.json").write_text(json.dumps(report, indent=2) + "\n")
                print(f"{variant} {name}: {measured['cycles']} cycles for 256 retirements", flush=True)
            check_inputs(frozen_rtl)
    check_inputs(archived)
    assert all(digest(path) == tool_hashes[name] for name, path in tools.items()), "Verification tools changed"
    report["exitStatus"] = 0
    (output / "summary.json").write_text(json.dumps(report, indent=2) + "\n")


if __name__ == "__main__":
    main()
