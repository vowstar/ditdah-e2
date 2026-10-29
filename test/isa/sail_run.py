# SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
# SPDX-License-Identifier: MIT
"""Run a bounded shared ELF on the actual RTL and locked Sail model."""

import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "test"))
from elf import Region, load_elf
from retirement import bind_native_trace, read_trace
from sail_compare import ComparisonError, compare, compare_signature
from sail_config import configuration, parse_defaults
from sail_program import RAM, RAM_SIZE, bit_encodings, linker, program
from sail_trace import parse_signature, parse_trace


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def execute(command, directory, name, timeout, *, env=None):
    receipt = directory / (name + ".command.json")
    receipt.write_text(json.dumps({"command": command, "timeout": timeout, "status": "started"}, indent=2) + "\n")
    try:
        result = subprocess.run(command, cwd=directory, capture_output=True, text=True, timeout=timeout, env=env)
    except subprocess.TimeoutExpired as error:
        (directory / (name + ".stdout")).write_bytes(error.stdout or b"")
        (directory / (name + ".stderr")).write_bytes(error.stderr or b"")
        receipt.write_text(json.dumps({"command": command, "status": "timeout", "timeout": timeout}, indent=2) + "\n")
        raise
    (directory / (name + ".stdout")).write_text(result.stdout)
    (directory / (name + ".stderr")).write_text(result.stderr)
    receipt.write_text(json.dumps({"command": command, "exitStatus": result.returncode}, indent=2) + "\n")
    if result.returncode:
        raise RuntimeError(f"{name} exited {result.returncode}")
    return {"command": command, "exitStatus": result.returncode}, result.stdout


def workload_coverage(image, steps, parameters):
    """Require each explicitly named case to occur in the independent native trace."""
    by_pc = {}
    for step in steps:
        by_pc.setdefault(step.pc, []).append(step)
    bit_rows, multiply_rows = [], []
    for vector in range(3):
        for name, group, encoding in bit_encodings():
            symbol = f"b_case_{vector}_{name}"
            observed = by_pc.get(image.symbols[symbol], [])
            enabled = parameters["enable" + group]
            if len(observed) != 1 or observed[0].instruction != encoding or observed[0].trap != (not enabled):
                raise ComparisonError("Native bit case was not executed with its selected configuration: " + symbol)
            if not enabled and observed[0].cause != 2:
                raise ComparisonError("A disabled bit instruction did not raise illegal instruction")
            bit_rows.append({"case": symbol, "group": group, "enabled": enabled, "trap": observed[0].trap})
    for symbol, pc in image.symbols.items():
        if symbol.startswith("m_case_"):
            observed = by_pc.get(pc, [])
            if len(observed) != 1 or observed[0].trap:
                raise ComparisonError("Native multiply/divide case did not execute: " + symbol)
            multiply_rows.append(symbol)
    return {"bitCases": bit_rows, "bitForms": len(bit_encodings()), "multiplyDivideCases": multiply_rows,
            "trapCauses": sorted({step.cause for step in steps if step.trap}),
            "nativeCompressedInstructions": sum(step.length == 2 for step in steps),
            "nativeCompressedMnemonics": sorted({step.mnemonic for step in steps if step.length == 2}),
            "nativeCsrAddresses": sorted({access.address for step in steps for access in step.csrs})}


def signature_from_memory(stdout, begin, end):
    memory = {}
    for line in stdout.splitlines():
        if not line.startswith("W "):
            continue
        fields = line.split()
        if len(fields) != 3:
            raise ComparisonError("Malformed actual memory dump")
        address, value = map(int, fields[1:])
        if address in memory or address % 4 or not 0 <= address <= 0xffffffff or not 0 <= value <= 0xffffffff:
            raise ComparisonError("Invalid or repeated actual memory word")
        memory[address] = value
    if end <= begin or begin % 4 or end % 4 or any(address not in memory for address in range(begin, end, 4)):
        raise ComparisonError("The actual memory dump does not cover the complete signature")
    return [memory[address] for address in range(begin, end, 4)]



def signature_control(stdout, begin, end, expected_signature):
    word = next(line for line in stdout.splitlines() if line.startswith(f"W {begin} "))
    fields = word.split()
    fields[2] = str(int(fields[2]) ^ 1)
    changed_dump = stdout.replace(word + "\n", " ".join(fields) + "\n", 1)
    changed_signature = signature_from_memory(changed_dump, begin, end)
    try:
        compare_signature(changed_signature, expected_signature)
    except ComparisonError as error:
        signature_rejection = str(error)
    else:
        raise ComparisonError("Changed signature was accepted")
    return {"mutation": "signature word", "word": 0, "changed": changed_signature[0],
                     "rejection": signature_rejection}

def corruption_controls(records, steps, parameters, boundaries, body_pc):
    choices = [
        ("destination result", "rd_wdata", lambda item: item["rd_addr"] != 0),
        ("next PC", "pc_wdata", lambda item: True),
        ("source operand", "rs1_rdata", lambda item: item["rs1_addr"] != 0),
        ("memory byte", "mem_wdata", lambda item: item["mem_wmask"] != 0),
        ("trap cause", "cause", lambda item: item["trap"]),
    ]
    controls = []
    for name, field, predicate in choices:
        index = next((index for index, record in enumerate(records[:len(steps)]) if predicate(record)), None)
        if index is None:
            raise ComparisonError("Required negative control is unreachable: " + name)
        changed = copy.deepcopy(records)
        bit = (changed[index]["mem_wmask"] & -changed[index]["mem_wmask"]).bit_length() - 1 if field == "mem_wdata" else 0
        changed[index][field] ^= 1 << (8 * bit) if field == "mem_wdata" else 1
        try:
            compare(changed, steps, parameters, **boundaries)
        except ComparisonError as error:
            controls.append({"mutation": name, "packet": index, "field": field,
                             "original": records[index][field], "changed": changed[index][field], "rejection": str(error)})
        else:
            raise ComparisonError("External comparison accepted changed " + name)
    for name, key, predicate in [("CSR read", "rdata", lambda record: record["csr"]["valid"] and record["csr"]["rmask"]),
                                  ("CSR post-state", "after", lambda record: record["pc_rdata"] == body_pc)]:
        index = next(index for index, record in enumerate(records[:len(steps)]) if predicate(record))
        changed = copy.deepcopy(records)
        target = changed[index]["csr"] if key == "rdata" else changed[index]["csr_states"]["mstatus"]
        target[key] ^= 1
        try:
            compare(changed, steps, parameters, **boundaries)
        except ComparisonError as error:
            controls.append({"mutation": name, "packet": index, "rejection": str(error)})
        else:
            raise ComparisonError("External comparison accepted changed " + name)
    for name in ("completion order", "completion CSR effect"):
        changed = copy.deepcopy(records)
        if name == "completion order":
            changed[-1]["order"] = 0
        else:
            state = changed[-1]["csr_states"]["mstatus"]
            state["after"] ^= 8
            state["wmask"] = 8
        try:
            compare(changed, steps, parameters, **boundaries)
        except ComparisonError as error:
            controls.append({"mutation": name, "packet": len(records) - 1, "rejection": str(error)})
        else:
            raise ComparisonError("External comparison accepted changed " + name)
    return controls


def run_profile(name, rtl, output, tools, defaults, instruction_limit, timeout):
    output.mkdir()
    manifest_path = rtl / "manifest.json"
    manifest = json.loads(manifest_path.read_text())
    parameters = manifest["parameters"]
    for path, expected in manifest["sourceHashes"].items():
        if digest(ROOT / path) != expected:
            raise ValueError("RTL source inputs differ: " + path)
        target = output / "inputs" / path
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / path, target)
    frozen = output / "rtl"
    frozen.mkdir()
    for path, expected in manifest["rtlHashes"].items():
        if Path(path).name != path or not path.endswith(".sv") or digest(rtl / path) != expected:
            raise ValueError("RTL artifact binding differs")
        shutil.copyfile(rtl / path, frozen / path)
    shutil.copyfile(manifest_path, frozen / "manifest.json")
    assembly, script = output / "program.S", output / "program.ld"
    assembly.write_text(program(parameters))
    script.write_text(linker(parameters))
    isa = "rv32i" + ("m" if parameters["enableM"] else "") + ("c" if parameters["enableC"] else "")
    isa += "_zicsr_zifencei" + "".join("_" + extension for key, extension in
                                     (("enableZba", "zba"), ("enableZbb", "zbb"), ("enableZbs", "zbs")) if parameters[key])
    elf = output / "program.elf"
    build, _ = execute([tools["compiler"]["path"], "-march=" + isa, "-mabi=ilp32", "-nostdlib", "-nostartfiles",
                        "-static", "-mno-relax", "-Wl,--no-relax", "-T", str(script), str(assembly), "-o", str(elf)],
                       output, "software-build", timeout)
    reset = parameters["resetVector"]
    image = load_elf(elf, reset_vector=reset, enable_c=parameters["enableC"],
                     regions=(Region("code", reset, 0x10000, 5), Region("data", RAM, RAM_SIZE, 6)))
    regions = [{"base": reset, "size": 0x10000, "read": True, "write": False, "execute": True, "atomic": False},
               {"base": RAM, "size": RAM_SIZE, "read": True, "write": True, "execute": False, "atomic": False}]
    config = output / "sail-config.json"
    config.write_text(json.dumps(configuration(defaults, parameters, regions, instruction_limit=instruction_limit), indent=2) + "\n")
    config_check, _ = execute([tools["sail"]["path"], "--config", str(config), "--validate-config"], output, "config-check", timeout)
    _, isa_string = execute([tools["sail"]["path"], "--config", str(config), "--print-isa-string"], output, "isa-string", timeout)
    native, _ = execute([tools["sail"]["path"], "--config", str(config), "--trace-instr", "--trace-reg", "--trace-mem",
                         "--trace-exception", "--trace-step", "--trace-output", str(output / "sail.trace"),
                         "--test-signature", str(output / "sail.signature"), "--inst-limit", str(instruction_limit), str(elf)],
                        output, "sail", timeout)
    steps = parse_trace((output / "sail.trace").read_text())
    if len(steps) >= instruction_limit:
        raise ComparisonError("Sail reached the instruction limit without accepted HTIF completion")
    begin, end = image.symbols["begin_signature"], image.symbols["end_signature"]
    expected_signature = parse_signature((output / "sail.signature").read_text(), (end - begin) // 4)
    coverage = workload_coverage(image, steps, parameters)
    memory = output / "program.hex"
    memory.write_text("".join(f"{address:08x} {word:08x}\n" for address, word in sorted(image.words().items())))
    rtl_build, _ = execute([tools["verilator"]["path"], "--cc", "--exe", "--build", "-j", "2", "--top-module", "DitDahE2",
                            "--Mdir", str(output / "obj"), "-CFLAGS", "-std=c++17",
                            *[str(frozen / path) for path in manifest["rtlHashes"]],
                            str(output.parent / "inputs/test/sim.cpp")],
                           output, "rtl-build", timeout)
    environment = os.environ | {"DITDAH_E2_RVFI_TRACE": str(output / "dut.jsonl")}
    dut, stdout = execute([str(output / "obj/VDitDahE2"), str(memory), "1", "24", str(0x90000000), str(1 << 32),
                           str(instruction_limit * 100 + 1000), str(image.symbols["software_done"])], output, "dut", timeout, env=environment)
    records = read_trace(output / "dut.jsonl")
    binding = bind_native_trace(records, stdout)
    boundaries = {"checked_end": image.symbols["checked_end"], "completion_pc": image.symbols["software_done"],
                  "tohost": image.symbols["tohost"]}
    external = compare(records, steps, parameters, **boundaries)
    actual_signature = signature_from_memory(stdout, begin, end)
    compare_signature(actual_signature, expected_signature)
    controls = corruption_controls(records, steps, parameters, boundaries, image.symbols["checked_start"])
    controls.append(signature_control(stdout, begin, end, expected_signature))
    if any(module in sys.modules for module in ("model", "bit_model", "compressed_model", "atomic_memory")):
        raise RuntimeError("A local ISA execution model was imported into the external comparison")
    if any(digest(ROOT / path) != expected for path, expected in manifest["sourceHashes"].items()):
        raise RuntimeError("RTL source input changed during the run")
    if any(digest(frozen / path) != expected for path, expected in manifest["rtlHashes"].items()):
        raise RuntimeError("Frozen RTL input changed during the run")
    result = {"profile": name, "parameters": parameters, "exitStatus": 0, "rtlManifestHash": digest(manifest_path),
              "softwareBuild": build, "configValidation": config_check, "nativeRun": native, "rtlBuild": rtl_build,
              "dutRun": dut, "rvfiEnvironment": {"DITDAH_E2_RVFI_TRACE": str(output / "dut.jsonl")},
              "nativeBinding": binding, "externalComparison": external, "workloadCoverage": coverage,
              "instructionAccessFaultAddress": 0x90000000,
              "signatureWords": len(actual_signature), "simulatorHash": digest(output / "obj/VDitDahE2"),
              "nativeIsaString": isa_string.strip(), "negativeControls": controls, "localIsaModelUsed": False,
              "rtlInputsUnchanged": True,
              "artifacts": {path.name: digest(path) for path in output.iterdir() if path.is_file()}}
    (output / "summary.json").write_text(json.dumps(result, indent=2) + "\n")
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", action="append", required=True, metavar="NAME=RTL")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--instruction-limit", type=int, default=10000)
    parser.add_argument("--timeout", type=int, default=120)
    args = parser.parse_args()
    if args.instruction_limit <= 0 or args.timeout <= 0 or args.output.exists():
        parser.error("Use positive limits and a new output directory")
    output = args.output.resolve()
    output.mkdir(parents=True)
    paths = [*[Path(__file__).parent / path for path in (
                "sail_run.py", "sail_compare.py", "sail_config.py", "sail_program.py", "sail_trace.py",
                "sail_operands.py", "sail.sh", "test_sail.py", "test_sail_operands.py", "sail_replay.py")],
             ROOT / "test/retirement.py", ROOT / "test/rvfi_trace.hpp", ROOT / "test/sim.cpp", ROOT / "test/inactive_debug.hpp",
             ROOT / "test/elf.py", ROOT / "flake.lock", ROOT / "nix/sail-tools.nix"]
    if any(specification.startswith("a=") for specification in args.profile):
        paths += [*[Path(__file__).parent / path for path in (
            "sail_atomic_run.py", "sail_atomic_program.py", "sail_atomic_compare.py", "sail_atomic_samples.py",
            "test_sail_atomic_samples.py")], ROOT / "test/atomic_sim.cpp"]
    sources = {str(path.relative_to(ROOT)): digest(path) for path in paths}
    for path in paths:
        target = output / "inputs" / path.relative_to(ROOT)
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(path, target)
    tools = {}
    for role, name, option in [("sail", "sail_riscv_sim", "--version"), ("compiler", "riscv32-none-elf-gcc", "--version"),
                               ("verilator", "verilator", "--version"), ("cxx", "g++", "--version"), ("make", "make", "--version")]:
        found = shutil.which(name)
        if found is None:
            raise RuntimeError("Missing tool: " + name)
        path = str(Path(found).resolve())
        _, version = execute([path, option], output, "tool-" + role, args.timeout)
        tools[role] = {"path": path, "sha256": digest(path), "version": version.strip()}
    if tools["sail"]["version"] != "0.12":
        raise RuntimeError("The Sail trace parser requires model 0.12")
    execute([tools["sail"]["path"], "--build-info"], output, "model-build-info", args.timeout)
    schema = Path(tools["sail"]["path"]).parents[1] / "share/sail-riscv/sail_riscv_config_schema.json"
    shutil.copyfile(schema, output / "native-config-schema.json")
    tools["sail"]["configurationSchemaHash"] = digest(schema)
    _, raw = execute([tools["sail"]["path"], "--rv32", "--print-default-config"], output, "native-defaults", args.timeout)
    defaults = parse_defaults(raw)
    results, names = [], set()
    for specification in args.profile:
        name, path = specification.split("=", 1)
        if not re.fullmatch("[a-z][a-z0-9-]*", name) or name in names:
            raise ValueError("Invalid or repeated profile")
        names.add(name)
        if name == "a":
            from sail_atomic_run import run_atomic_profile
            selected_runner = run_atomic_profile
        else:
            selected_runner = run_profile
        results.append(selected_runner(name, Path(path).resolve(), output / name, tools, defaults, args.instruction_limit, args.timeout))
    if any(digest(ROOT / path) != expected for path, expected in sources.items()):
        raise RuntimeError("Runner input changed")
    summary = {"exitStatus": 0, "scope": "Bounded shared ELF events and actual memory signatures against native Sail",
               "sourceHashes": sources, "tools": tools, "profiles": results}
    (output / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    shutil.copyfile(Path(__file__).parent / "sail_replay.py", output / "replay.py")
    artifacts = {}
    for path in sorted(output.rglob("*")):
        if not path.is_file():
            continue
        relative = path.relative_to(output)
        if "obj" in relative.parts and path.name not in ("VDitDahE2", "VAtomicBench"):
            continue
        artifacts[str(relative)] = {"sha256": digest(path), "bytes": path.stat().st_size}
    (output / "artifact-manifest.json").write_text(json.dumps({
        "schema": "ditdah-e2.sail-evidence.v1", "summary": "summary.json",
        "artifacts": artifacts}, indent=2) + "\n")
    print(f"PASS: {len(results)} bounded Sail profiles")


if __name__ == "__main__":
    main()
