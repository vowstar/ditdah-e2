# SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
# SPDX-License-Identifier: MIT
"""Run the shared ELF on the native model and actual atomic platform."""

import json
import os
from pathlib import Path
import shutil

from elf import Region, load_elf
from retirement import read_trace
from sail_atomic_compare import corruption_controls as atomic_controls, memory_checker, signature_from_samples
from sail_atomic_program import atomic_program, observer
from sail_atomic_samples import sample_atomic_witnesses
from sail_compare import ComparisonError, compare, compare_signature
from sail_config import configuration
from sail_program import RAM, RAM_SIZE, linker
from sail_trace import parse_signature, parse_trace


def run_atomic_profile(name, design, output, tools, defaults, instruction_limit, timeout):
    from sail_run import ROOT, corruption_controls, digest, execute, workload_coverage
    output.mkdir()
    manifest_path = design / "manifest.json"
    manifest = json.loads(manifest_path.read_text())
    parameters, regions = manifest["parameters"]["core"], manifest["regions"]
    if not parameters["enableA"] or parameters["enableDebug"] or regions["sram"] != {"base": RAM, "size": RAM_SIZE}:
        raise ValueError("Atomic profile requires the declared shared SRAM map and excludes Debug")
    for path, expected in manifest["sourceHashes"].items():
        if digest(ROOT / path) != expected:
            raise ValueError("Atomic source input differs: " + path)
        target = output / "inputs" / path
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / path, target)
    rtl = output / "rtl"
    rtl.mkdir()
    for path, expected in manifest["rtlHashes"].items():
        if Path(path).name != path or digest(design / "rtl" / path) != expected:
            raise ValueError("Atomic RTL input differs")
        shutil.copyfile(design / "rtl" / path, rtl / path)
    shutil.copyfile(manifest_path, rtl / "manifest.json")
    assembly, script, elf = output / "program.S", output / "program.ld", output / "program.elf"
    assembly.write_text(atomic_program(parameters))
    script.write_text(linker(parameters))
    isa = "rv32i" + ("m" if parameters["enableM"] else "") + "a" + ("c" if parameters["enableC"] else "") + "_zicsr_zifencei"
    software, _ = execute([tools["compiler"]["path"], "-march=" + isa, "-mabi=ilp32", "-nostdlib", "-nostartfiles",
                           "-static", "-mno-relax", "-Wl,--no-relax", "-T", str(script), str(assembly), "-o", str(elf)],
                          output, "software-build", timeout)
    reset = parameters["resetVector"]
    image = load_elf(elf, reset_vector=reset, enable_c=parameters["enableC"],
                     regions=(Region("code", reset, 0x10000, 5), Region("data", RAM, RAM_SIZE, 6)))
    memory_regions = [{"base": reset, "size": 0x10000, "read": True, "write": False, "execute": True, "atomic": False},
                      {"base": RAM, "size": RAM_SIZE, "read": True, "write": True, "execute": False, "atomic": True}]
    config = output / "sail-config.json"
    config.write_text(json.dumps(configuration(defaults, parameters, memory_regions, instruction_limit=instruction_limit), indent=2) + "\n")
    validation, _ = execute([tools["sail"]["path"], "--config", str(config), "--validate-config"], output, "config-check", timeout)
    native, _ = execute([tools["sail"]["path"], "--config", str(config), "--trace-instr", "--trace-reg", "--trace-mem",
                         "--trace-exception", "--trace-step", "--trace-output", str(output / "sail.trace"),
                         "--test-signature", str(output / "sail.signature"), "--inst-limit", str(instruction_limit), str(elf)], output, "sail", timeout)
    steps = parse_trace((output / "sail.trace").read_text())
    if len(steps) >= instruction_limit:
        raise ComparisonError("Sail reached its instruction limit")
    coverage = workload_coverage(image, steps, parameters)
    by_pc = {step.pc: step for step in steps}
    atomic_cases = {symbol: by_pc[pc].trap for symbol, pc in image.symbols.items() if symbol.startswith("a_case_")}
    if not atomic_cases:
        raise ComparisonError("No atomic fixture case executed")
    begin, end = image.symbols["begin_signature"], image.symbols["end_signature"]
    expected_signature = parse_signature((output / "sail.signature").read_text(), (end - begin) // 4)
    memory = output / "program.hex"
    memory.write_text("".join(f"{address:08x} {word:08x}\n" for address, word in sorted(image.words().items())))
    events = output / "events.txt"
    events.write_text("0\n" + str((end - begin) // 4) + "\n" + "\n".join(str(address) for address in range(begin, end, 4)) + "\n0\n0\n0\n")
    wrapper = output / "AtomicBench.sv"
    wrapper.write_text(observer(rtl, RAM_SIZE))
    flags = f"-std=c++17 -DDITDAH_E2_ENABLE_DEBUG=0 -DDITDAH_E2_ROM_BASE={reset}u -DDITDAH_E2_ROM_SIZE=65536 -DDITDAH_E2_MAX_CYCLES=1000000"
    build, _ = execute([tools["verilator"]["path"], "--cc", "--exe", "--build", "-j", "2", "--top-module", "AtomicBench",
                        "--Mdir", str(output / "obj"), "-CFLAGS", flags, str(wrapper),
                        *[str(rtl / path) for path in manifest["rtlHashes"]],
                        str(output.parent / "inputs/test/atomic_sim.cpp")], output, "rtl-build", timeout)
    environment = os.environ | {"DITDAH_E2_RVFI_TRACE": str(output / "dut.jsonl")}
    dut, stdout = execute([str(output / "obj/VAtomicBench"), str(memory), str(events), "1", "24",
                           str(image.symbols["software_done"])], output, "dut", timeout, env=environment)
    records = read_trace(output / "dut.jsonl")
    samples = sample_atomic_witnesses(records, stdout, sram_base=RAM, sram_size=RAM_SIZE)
    (output / "actual-atomic-samples.json").write_text(json.dumps(samples, indent=2) + "\n")
    boundaries = {"checked_end": image.symbols["checked_end"], "completion_pc": image.symbols["software_done"],
                  "tohost": image.symbols["tohost"], "memory_checker": memory_checker(samples)}
    external = compare(records, steps, parameters, **boundaries)
    compare_signature(signature_from_samples(samples, begin, end), expected_signature)
    controls = corruption_controls(records, steps, parameters, boundaries, image.symbols["checked_start"])
    controls += atomic_controls(records, steps, parameters, samples, boundaries, stdout, begin, end,
                                expected_signature, sram_base=RAM, sram_size=RAM_SIZE)
    if any(digest(ROOT / path) != expected for path, expected in manifest["sourceHashes"].items()) or any(digest(rtl / path) != expected for path, expected in manifest["rtlHashes"].items()):
        raise RuntimeError("Atomic source or RTL changed")
    result = {"profile": name, "parameters": parameters, "exitStatus": 0, "rtlManifestHash": digest(manifest_path),
              "softwareBuild": software, "configValidation": validation, "nativeRun": native, "rtlBuild": build,
              "dutRun": dut, "externalComparison": external, "workloadCoverage": coverage, "atomicCases": atomic_cases,
              "actualAtomicWitnesses": len(samples["witnesses"]), "unissuedAtomicFaults": len(samples["unissuedFaults"]),
              "signatureWords": len(expected_signature), "negativeControls": controls, "localIsaModelUsed": False,
              "rtlInputsUnchanged": True, "simulatorHash": digest(output / "obj/VAtomicBench"),
              "artifacts": {path.name: digest(path) for path in output.iterdir() if path.is_file()}}
    (output / "summary.json").write_text(json.dumps(result, indent=2) + "\n")
    return result
