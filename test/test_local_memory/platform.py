# SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
# SPDX-License-Identifier: MIT
"""Execute ROM boot and local-memory code against the independent CPU model."""

import argparse
import gzip
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "scripts"))
from build_local_software import bank_images, build as build_boot
from build_rtl import digest
from build_software import tool
from test.common.elf import Region, load_elf
from test.test_platform.verify_platform import check, observer, verify_platform_inputs


def verify_boot_payload(boot, payload, banks):
    if boot.symbols.get("__payload_entry") != payload.entry:
        raise ValueError("Boot entry does not match the payload")
    for name, contents in banks.items():
        start = boot.symbols.get(f"__{name}_image_start")
        end = boot.symbols.get(f"__{name}_image_end")
        if start is None or end is None or start % 4 or end - start != len(contents):
            raise ValueError("Boot bank image extent does not match the payload")
        if any(boot.memory.get(start + offset) != value for offset, value in enumerate(contents)):
            raise ValueError("Boot bank image bytes do not match the payload")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--platform-build", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--boot-elf", type=Path)
    parser.add_argument("--payload-elf", type=Path)
    args = parser.parse_args()
    if args.output.exists() or bool(args.boot_elf) != bool(args.payload_elf):
        raise ValueError("Use a fresh output and supply both executable inputs together")
    manifest = json.loads((args.platform_build / "manifest.json").read_text())
    verify_platform_inputs(args.platform_build, manifest)
    params, regions = manifest["parameters"]["core"], manifest["regions"]
    if not {"itcm", "dtcm"} <= regions.keys() or params.get("enableA"):
        raise ValueError("Local platform acceptance requires both banks and A disabled")
    args.output.mkdir(parents=True)
    shutil.copytree(args.platform_build, args.output / "platform")
    sources = ["test/test_local_memory/platform.py", "test/test_platform/verify_platform.py",
               "test/test_platform/platform_sim.cpp", "test/test_platform/console.py", "test/test_platform/timer.py",
               "test/common/rvfi_trace.hpp", "test/common/inactive_debug.hpp", "test/units/pmp.py",
               "test/units/compressed_unit.py", "scripts/build_local_software.py", "software/local-start.S",
               "scripts/build_software.py", "scripts/build_rtl.py", "scripts/build_platform_block.py", "scripts/platform_map.py",
               "software/local-memory.S", "software/local-memory.ld", "flake.lock"]
    sources += [str(path.relative_to(ROOT)) for path in (ROOT / "test/common").glob("*.py")]
    inputs = {name: (ROOT / name).read_bytes() for name in sorted(set(sources))}
    for name, content in inputs.items():
        destination = args.output / "inputs" / name
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(content)
    tools = {name: tool(name)[1] for name in ("verilator", "g++", "make", "riscv32-none-elf-gcc")}
    commands, runs = [], []
    software = args.output / "payload"
    software.mkdir()
    if args.payload_elf:
        shutil.copyfile(args.payload_elf, software / "payload.elf")
        shutil.copyfile(args.boot_elf, software / "program.elf")
    else:
        for name in ("platform.h", "memory.ld"):
            shutil.copyfile(args.output / "platform" / name, software / name)
        for name in ("local-memory.S", "local-memory.ld"):
            shutil.copyfile(args.output / "inputs/software" / name, software / name)
        cc = tool("riscv32-none-elf-gcc")[0]
        command = [str(cc), "-march=rv32imc_zicsr_zifencei", "-mabi=ilp32", "-mno-relax",
                   "-nostdlib", "-nostartfiles", "-static", "-Wl,--build-id=none", "-Wl,--no-relax",
                   "-T", "local-memory.ld", "local-memory.S", "-o", "payload.elf"]
        result = subprocess.run(command, cwd=software, capture_output=True, text=True,
                                env=dict(os.environ, SOURCE_DATE_EPOCH="0", LC_ALL="C"))
        (software / "compile.log").write_text(result.stdout + result.stderr)
        if result.returncode:
            raise RuntimeError("Local payload compilation failed")
        commands.append({"argv": [tools["riscv32-none-elf-gcc"]["name"], *command[1:]], "exitStatus": 0})
        build_boot(software / "payload.elf", args.output / "platform/map.json", args.output / "boot")
        shutil.copyfile(args.output / "boot/program.elf", software / "program.elf")
    payload, banks = bank_images(software / "payload.elf", regions)
    rom = regions["rom"]
    image = load_elf(software / "program.elf", reset_vector=params["resetVector"],
                     regions=(Region("rom", rom["base"], rom["size"], 5),), enable_c=params["enableC"])
    verify_boot_payload(image, payload, banks)
    image.symbols["software_done"] = payload.symbols["software_done"]
    if not image.memory or any(not rom["base"] <= at < rom["base"] + rom["size"] for at in image.memory):
        raise AssertionError("Boot image must initialize ROM only")
    scratch = "/data/tmp" if os.access("/data/tmp", os.W_OK) else None
    with tempfile.TemporaryDirectory(prefix="ditdah-e2-local-platform-", dir=scratch) as directory:
        work = Path(directory)

        def diagnostic(value):
            return str(value).replace(str(work), "<work>").replace(str(args.output.resolve()), "<output>").replace(str(ROOT), "<source>")

        (work / "PlatformBench.sv").write_text(observer(args.output / "platform/rtl", manifest["top"]))
        rtl = args.output / "platform/rtl"
        command = ["verilator", "--cc", "--exe", "--build", "-j", "2", "--top-module", "PlatformBench",
                   "--Mdir", "obj", "-CFLAGS", "-std=c++17 -I" + str((args.output / "inputs/test/common").resolve()),
                   str(work / "PlatformBench.sv"), *[str((rtl / name).resolve()) for name in manifest["rtlHashes"]],
                   str((args.output / "inputs/test/test_platform/platform_sim.cpp").resolve())]
        result = subprocess.run(command, cwd=work, capture_output=True, text=True)
        (args.output / "compile.log").write_text(diagnostic(result.stdout + result.stderr))
        commands.append({"argv": list(map(diagnostic, command)), "exitStatus": result.returncode})
        if result.returncode:
            raise RuntimeError("Local platform simulation did not compile")
        (work / "image.hex").write_text(" ".join(f"{regions[name][field]:x}" for name in ("rom", "sram")
                                                for field in ("base", "size")) + "\n" +
                                       "".join(f"{at:08x} {value:08x}\n" for at, value in sorted(image.words().items())))
        (work / "banks.hex").write_text("".join(f"{regions[key]['base']:x} {regions[key]['size']:x} "
                                              f"{int(regions[key]['backend'] == 'axi')}\n" for key in ("itcm", "dtcm")))
        for seed, delay in ((0, 0), (1, 9), (19, 24)):
            command = [str(work / "obj/VPlatformBench"), "image.hex", str(seed), str(delay),
                       str(image.symbols["software_done"]), "banks.hex"]
            result = subprocess.run(command, cwd=work, capture_output=True, text=True)
            name = f"local-s{seed}-d{delay}"
            with gzip.open(args.output / f"{name}.trace.gz", "wt") as trace:
                trace.write(result.stdout)
            (args.output / f"{name}.log").write_text(diagnostic(result.stderr))
            commands.append({"argv": list(map(diagnostic, command)), "exitStatus": result.returncode})
            if result.returncode:
                raise RuntimeError("Local platform execution failed")
            metrics = check(image, params, regions, result.stdout, "local", expected_output=b"L\n")
            runs.append({"seed": seed, "delay": delay, "exitStatus": 0, **metrics,
                         "traceHash": hashlib.sha256(result.stdout.encode()).hexdigest()})
    for name, content in inputs.items():
        if (ROOT / name).read_bytes() != content:
            raise RuntimeError("Local platform verification inputs changed")
    verify_platform_inputs(args.output / "platform", manifest)
    report = {"scope": "ROM boot, local/external memory and independent retirement checks", "exitStatus": 0,
              "platformManifestHash": digest(args.output / "platform/manifest.json"), "parameters": manifest["parameters"],
              "regions": regions, "preloadedRegions": ["rom"],
              "sourceHashes": {name: hashlib.sha256(content).hexdigest() for name, content in inputs.items()},
              "bootElfHash": digest(software / "program.elf"), "payloadElfHash": digest(software / "payload.elf"),
              "tools": tools, "commands": commands, "runs": runs}
    (args.output / "summary.json").write_text(json.dumps(report, indent=2) + "\n")
    print("Local platform boot and independent model checks passed")


if __name__ == "__main__":
    main()
