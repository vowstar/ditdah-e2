# SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
# SPDX-License-Identifier: MIT
"""Measure fixed C workloads on frozen bit-extension configurations."""

import argparse
from collections import Counter
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys

from elf import load_elf
from verify import check, checker_inputs


ROOT = Path(__file__).resolve().parents[1]
PROFILES = (0, 1, 2, 4, 7)
WORKLOADS = ("array_indexing", "bitmap_updates", "byte_processing")
BIT_KEYS = ("enableZba", "enableZbb", "enableZbs")
INPUT = tuple(((0x9E3779B9 * (i + 1)) ^ (0x01020304 * i)) & 0xFFFFFFFF for i in range(32))
INDICES = tuple(((i * 73 + 19) ^ (i >> 1)) & 255 for i in range(64))
SOFTWARE = ("bit_benchmark.c", "bit_benchmark_start.S", "bit_benchmark.ld")


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def expected(workload):
    output = [0] * 32
    result = 0
    if workload == "array_indexing":
        result = sum(INPUT[index % 32] for index in INDICES) & 0xFFFFFFFF
        output[0] = result
    elif workload == "bitmap_updates":
        for index in set(INDICES):
            output[index // 32] += 2 ** (index % 32)
    elif workload == "byte_processing":
        output = [int.from_bytes(value.to_bytes(4, "little"), "big") for value in INPUT]
    else:
        raise ValueError("Unknown benchmark workload")
    return output, result


def validate_profiles(manifests):
    baseline = manifests[0]
    stable = {key: value for key, value in baseline["parameters"].items() if key not in BIT_KEYS}
    assert stable.get("resetVector") == 0 and stable.get("enableM") and stable.get("enableC"), "Benchmark profiles require RV32IMC at reset zero"
    assert not any(stable.get(key, False) for key in ("enableA", "protectedMode", "enableDebug")), "Benchmark profiles require machine mode without A or debug"
    for subset, manifest in manifests.items():
        parameters = manifest["parameters"]
        assert {key: value for key, value in parameters.items() if key not in BIT_KEYS} == stable, "Benchmark profiles differ outside the bit options"
        assert tuple(parameters.get(key, False) for key in BIT_KEYS) == tuple(bool(subset & (1 << bit)) for bit in range(3)), "Bit profile differs from its directory"
        assert manifest["sourceHashes"] == baseline["sourceHashes"], "Benchmark profiles have different sources"


def measure_window(trace, begin, end):
    records = [list(map(int, line.split()[1:])) for line in trace.splitlines() if line.startswith("R ")]
    starts = [index for index, fields in enumerate(records) if fields[1] == begin]
    stops = [index for index, fields in enumerate(records) if fields[1] == end]
    assert len(starts) == len(stops) == 1 and starts[0] < stops[0], "Benchmark window is missing or repeated"
    first, last = starts[0], stops[0]
    assert not any(fields[7] for fields in records[first:last]), "Benchmark window contains a trap"
    return {"startCycle": records[first][0], "endCycle": records[last][0],
            "cycles": records[last][0] - records[first][0], "retiredInstructions": last - first}


def fixed_memory_timing(trace):
    pending = {}
    observed = Counter()
    for line in trace.splitlines():
        fields = line.split()
        if fields[0] == "Q":
            assert fields[2] not in pending, "Overlapping benchmark memory request"
            pending[fields[2]] = int(fields[1])
        elif fields[0] == "S":
            assert fields[2] in pending, "Unowned benchmark response"
            assert int(fields[1]) == pending.pop(fields[2]) + 1, "Benchmark memory response is not one cycle"
            observed[fields[2]] += 1
    assert not pending and observed["I"] and observed["D"], "Benchmark memory traffic is incomplete"
    return dict(observed)


class BenchmarkCase:
    instruction_fault = data_fault = None
    expected_causes = expected_interrupts = interrupt_schedule = ()
    enable_m = enable_c = True
    protected_mode = False

    def __init__(self, image, workload, subset):
        self.image = image
        self.name = workload
        self.reset = image.entry
        self.completion_pc = image.symbols["benchmark_done"]
        self.enable_zba, self.enable_zbb, self.enable_zbs = (bool(subset & (1 << bit)) for bit in range(3))
        self.initial_words = image.words()
        for name, values in (("benchmark_input", INPUT), ("benchmark_indices", INDICES)):
            assert all(self.initial_words[image.symbols[name] + index * 4] == value for index, value in enumerate(values)), "Compiled benchmark input differs from fixed data"
        output, result = expected(workload)
        self.signature = {image.symbols["benchmark_output"] + index * 4: value for index, value in enumerate(output)}
        self.signature[image.symbols["benchmark_return"]] = result
        assert self.initial_words[self.completion_pc] == 0x6F, "Invalid benchmark completion loop"

    def words(self):
        return dict(self.initial_words)


def tool(name):
    found = shutil.which(name)
    assert found, "Missing benchmark tool: " + name
    path = Path(found).resolve()
    version = subprocess.check_output([str(path), "--version"], text=True, stderr=subprocess.STDOUT).splitlines()[0]
    return path, {"version": version, "sha256": digest(path)}


def preserve(destination, source, hashes):
    for name, value in hashes.items():
        path = source / name
        assert digest(path) == value, "Benchmark input changed before preservation"
        output = destination / name
        output.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(path, output)


def build_program(work, workload, subset, compiler, objdump, software):
    work.mkdir(parents=True)
    for name in SOFTWARE:
        shutil.copyfile(software / name, work / name)
    march = "rv32imc" + "".join("_" + name for bit, name in enumerate(("zba", "zbb", "zbs")) if subset & (1 << bit))
    flags = ["-Os", "-std=c11", "-march=" + march, "-mabi=ilp32", "-mno-relax", "-msmall-data-limit=0",
             "-ffreestanding", "-fno-builtin", "-fno-pic", "-fno-pie", "-fno-ident", "-nostdlib", "-nostartfiles",
             "-static", "-Wl,--build-id=none", "-Wl,--no-relax", "-Wl,--defsym=__reset_vector=0",
             "-T", "bit_benchmark.ld", "-DWORKLOAD=" + str(WORKLOADS.index(workload)),
             "bit_benchmark_start.S", "bit_benchmark.c", "-o", "program.elf"]
    environment = dict(os.environ, SOURCE_DATE_EPOCH="0", LC_ALL="C", NIX_HARDENING_ENABLE="")
    result = subprocess.run([str(compiler), *flags], cwd=work, env=environment, capture_output=True, text=True)
    (work / "compile.log").write_text(result.stdout + result.stderr)
    assert result.returncode == 0, "Benchmark compilation failed"
    listing = subprocess.check_output([str(objdump), "-d", "-M", "no-aliases", "program.elf"], cwd=work, env=environment, text=True)
    (work / "program.dis").write_text(listing)
    image = load_elf(work / "program.elf", reset_vector=0, enable_c=True)
    required = ("_start", "benchmark", "benchmark_begin", "benchmark_end", "benchmark_done", "benchmark_output",
                "benchmark_return", "__benchmark_code_start", "__benchmark_code_end", "__benchmark_text_start", "__benchmark_text_end")
    assert all(name in image.symbols for name in required), "Missing benchmark symbol"
    sizes = {"kernelCodeBytes": image.symbols["__benchmark_code_end"] - image.symbols["__benchmark_code_start"],
             "textBytes": image.symbols["__benchmark_text_end"] - image.symbols["__benchmark_text_start"]}
    assert 0 < sizes["kernelCodeBytes"] < sizes["textBytes"], "Invalid benchmark code extent"
    return image, {"isa": march, "compilerCommand": ["riscv32-none-elf-gcc", *flags],
                   "objdumpCommand": ["riscv32-none-elf-objdump", "-d", "-M", "no-aliases", "program.elf"],
                   "elfHash": digest(work / "program.elf"), "listingHash": digest(work / "program.dis"), **sizes}


def execute(binary, case, directory):
    directory.mkdir(parents=True, exist_ok=True)
    image = directory / "image.hex"
    image.write_text("".join(f"{address:08x} {value:08x}\n" for address, value in sorted(case.words().items())))
    arguments = [str(binary.resolve()), str(image.resolve()), "0", "0", str(1 << 32), str(1 << 32), "20000", str(case.completion_pc)]
    result = subprocess.run(arguments, capture_output=True, text=True)
    (directory / "trace.txt").write_text(result.stdout)
    (directory / "stderr.txt").write_text(result.stderr)
    assert result.returncode == 0, result.stderr
    return result.stdout, {"command": ["VDitDahE2", "image.hex", *arguments[2:]], "exitStatus": result.returncode,
                           "imageHash": digest(image), "traceHash": digest(directory / "trace.txt"), "binaryHash": digest(binary)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--matrix", type=Path, required=True)
    parser.add_argument("--source-root", type=Path, default=ROOT)
    parser.add_argument("--output", type=Path, default=Path("result/bit-benchmark"))
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    manifests = {subset: json.loads((args.matrix / str(subset) / "rtl/manifest.json").read_text()) for subset in PROFILES}
    validate_profiles(manifests)
    initial = checker_inputs() | {name: digest(ROOT / name) for name in (
        "test/bit_benchmark.py", "test/test_bit_benchmark.py", "test/elf.py", *("software/" + name for name in SOFTWARE))}
    preserve(args.output / "inputs/checker", ROOT, initial)
    preserve(args.output / "inputs/design", args.source_root, manifests[0]["sourceHashes"])
    harness = {"test/sim.cpp": digest(args.source_root / "test/sim.cpp")}
    for header in sorted((args.source_root / "test").glob("*.hpp")):
        harness["test/" + header.name] = digest(header)
    preserve(args.output / "inputs/harness", args.source_root, harness)
    tools, executables = {}, {}
    for name in ("riscv32-none-elf-gcc", "riscv32-none-elf-objdump", "riscv32-none-elf-as", "riscv32-none-elf-ld", "verilator", "g++", "make", "python3"):
        executables[name], tools[name] = tool(name)
    cc1 = Path(subprocess.check_output([str(executables["riscv32-none-elf-gcc"]), "-print-prog-name=cc1"], text=True).strip()).resolve()
    tools["cc1"] = {"sha256": digest(cc1)}
    report = {"scope": "Fixed C workloads on frozen RV32IMC cores with optional bit extensions", "checkerHashes": initial,
              "sourceHashes": manifests[0]["sourceHashes"], "harnessHashes": harness, "tools": tools,
              "profiles": {}, "runs": [], "negativeControls": [],
              "memory": {"responseCycles": 1, "delayArgument": 0, "seed": 0, "instructionRequestReplacement": True},
              "environment": {"SOURCE_DATE_EPOCH": "0", "LC_ALL": "C", "NIX_HARDENING_ENABLE": ""},
              "measurement": "Retirement of benchmark_begin up to but excluding benchmark_end", "exitStatus": 1}
    try:
        for subset, manifest in manifests.items():
            design = args.output / "designs" / str(subset)
            rtl = design / "rtl"
            original = args.matrix / str(subset) / "rtl"
            preserve(rtl, original, manifest["rtlHashes"] | {"manifest.json": digest(original / "manifest.json")})
            report["profiles"][str(subset)] = {"parameters": manifest["parameters"], "rtlHashes": manifest["rtlHashes"],
                                               "manifestHash": digest(original / "manifest.json")}
            build = design / "build"
            command = ["verilator", "--cc", "--exe", "--build", "-j", "2", "--top-module", "DitDahE2", "--Mdir", str(build.resolve()),
                       "-CFLAGS", "-std=c++17", *[str((rtl / name).resolve()) for name in manifest["rtlHashes"]],
                       str((args.output / "inputs/harness/test/sim.cpp").resolve())]
            compiled = subprocess.run(command, capture_output=True, text=True)
            (design / "build.log").write_text(compiled.stdout + compiled.stderr)
            assert compiled.returncode == 0, "Benchmark simulator compilation failed"
            binary = build / "VDitDahE2"
            for workload in WORKLOADS:
                directory = args.output / f"profile-{subset}" / workload
                image, software = build_program(directory / "software", workload, subset, executables["riscv32-none-elf-gcc"],
                                                executables["riscv32-none-elf-objdump"], args.output / "inputs/checker/software")
                _, repeated = build_program(directory / "software-repeat", workload, subset, executables["riscv32-none-elf-gcc"],
                                             executables["riscv32-none-elf-objdump"], args.output / "inputs/checker/software")
                assert software == repeated, "Benchmark software is not reproducible"
                case = BenchmarkCase(image, workload, subset)
                trace, execution = execute(binary, case, directory)
                metrics = check(case, trace)
                timing = fixed_memory_timing(trace)
                window = measure_window(trace, image.symbols["benchmark_begin"], image.symbols["benchmark_end"])
                operation = {"array_indexing": "sh2add", "bitmap_updates": "bset", "byte_processing": "rev8"}[workload]
                needed = {"array_indexing": 1, "bitmap_updates": 4, "byte_processing": 2}[workload]
                if subset & needed:
                    assert metrics["instructions"].get(operation, 0), "Compiler did not use the measured extension"
                report["runs"].append({"workload": workload, "subset": subset, **software, **execution, **window,
                    "memoryResponses": timing, "instructions": metrics["instructions"], "programCycles": metrics["cycles"],
                    "expectedOutput": expected(workload)[0], "expectedReturn": expected(workload)[1]})
                if subset == 0:
                    if workload == "bitmap_updates":
                        unused = next(value for value in range(256) if value not in INDICES)
                        case.initial_words[image.symbols["benchmark_indices"]] = unused
                    else:
                        offset = (INDICES[0] % 32) * 4 if workload == "array_indexing" else 0
                        case.initial_words[image.symbols["benchmark_input"] + offset] ^= 1
                    changed, binding = execute(binary, case, directory / "changed-input")
                    try:
                        check(case, changed)
                    except AssertionError as error:
                        assert str(error) == "Program signature mismatch", "Changed benchmark input failed outside its result check"
                        report["negativeControls"].append({"workload": workload, "rejected": str(error), **binding})
                    else:
                        raise AssertionError("Changed benchmark input passed the fixed result check")
        assert all(digest(ROOT / name) == value for name, value in initial.items()), "Benchmark checker inputs changed"
        assert all(digest(args.output / "inputs/checker" / name) == value for name, value in initial.items()), "Preserved benchmark checker changed"
        assert all(digest(args.source_root / name) == value for name, value in manifests[0]["sourceHashes"].items()), "Benchmark design sources changed"
        assert all(digest(args.output / "inputs/design" / name) == value for name, value in manifests[0]["sourceHashes"].items()), "Preserved benchmark source changed"
        assert all(digest(args.source_root / name) == value for name, value in harness.items()), "Benchmark harness changed"
        for subset, manifest in manifests.items():
            assert all(digest(args.matrix / str(subset) / "rtl" / name) == value for name, value in manifest["rtlHashes"].items()), "Frozen benchmark RTL changed"
            assert all(digest(args.output / "designs" / str(subset) / "rtl" / name) == value for name, value in manifest["rtlHashes"].items()), "Preserved benchmark RTL changed"
            assert digest(args.matrix / str(subset) / "rtl/manifest.json") == report["profiles"][str(subset)]["manifestHash"], "Benchmark manifest changed"
        assert all(tool(name)[1] == value for name, value in tools.items() if name != "cc1") and digest(cc1) == tools["cc1"]["sha256"], "Benchmark tools changed"
        report["exitStatus"] = 0
    except Exception as error:
        report["failure"] = str(error)
        raise
    finally:
        (args.output / "summary.json").write_text(json.dumps(report, indent=2) + "\n")
    print(f"PASS: {len(report['runs'])} benchmark executions, {len(report['negativeControls'])} fixed-result controls")


if __name__ == "__main__":
    main()
