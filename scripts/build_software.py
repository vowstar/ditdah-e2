# SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
# SPDX-License-Identifier: MIT
"""Build and validate the freestanding RV32 workload."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "test"))
from elf import load_elf


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def sources():
    paths = sorted((ROOT / "software").glob("*"))
    paths += [ROOT / name for name in ("scripts/build_software.py", "test/elf.py", "flake.lock")]
    return {str(path.relative_to(ROOT)): digest(path) for path in paths if path.is_file()}


def tool(command):
    path = shutil.which(command)
    if path is None:
        raise ValueError(f"Required tool is unavailable: {Path(command).name}")
    executable = Path(path).resolve()
    version = subprocess.check_output([str(executable), "--version"], text=True).splitlines()[0]
    return executable, {"name": Path(command).name, "version": version, "sha256": digest(executable)}


def instruction_inventory(listing, enable_m=False, enable_c=False):
    instructions = []
    for line in listing.splitlines():
        match = re.match(r"\s*([0-9a-f]+):\s+([0-9a-f]+)\s+([\w.]+)", line)
        if not match:
            continue
        address, encoding, name = match.groups()
        raw, length = int(encoding, 16), len(encoding) // 2
        if length not in (2, 4) or length != (2 if raw & 3 != 3 else 4) or raw & 31 == 31:
            raise ValueError("Unsupported instruction width in executable code")
        if name.startswith(".") or length == 2 and not enable_c:
            raise ValueError("Unsupported instruction in executable code")
        if name in ("mul", "mulh", "mulhsu", "mulhu", "div", "divu", "rem", "remu") and not enable_m:
            raise ValueError("M instruction in an executable without M")
        instructions.append({"address": int(address, 16), "encoding": encoding, "length": length, "name": name})
    if not instructions or len({item["address"] for item in instructions}) != len(instructions):
        raise ValueError("Missing or duplicate executable instructions")
    if enable_m and not any(item["name"] == "mul" for item in instructions):
        raise ValueError("M workload does not contain MUL")
    if enable_c and not any(item["length"] == 2 for item in instructions):
        raise ValueError("C workload does not contain compressed instructions")
    return instructions


def build(output, compiler="riscv32-none-elf-gcc", objdump="riscv32-none-elf-objdump", reset_vector=0,
          *, enable_m=False, enable_c=False):
    if type(enable_m) is not bool or type(enable_c) is not bool:
        raise ValueError("ISA extension settings must be Boolean")
    if type(reset_vector) is not int or not 0 <= reset_vector < 0x10000 or reset_vector % (2 if enable_c else 4):
        raise ValueError("Reset vector must satisfy instruction alignment and be inside boot ROM")
    inputs = sources()
    cc, cc_info = tool(compiler)
    disassembler, disassembler_info = tool(objdump)
    scratch = "/data/tmp" if os.access("/data/tmp", os.W_OK) else None
    isa = "rv32i" + ("m" if enable_m else "") + ("c" if enable_c else "")
    flags = ["-Os", "-std=c11", f"-march={isa}", "-mabi=ilp32", "-mno-relax", "-msmall-data-limit=0",
             "-ffreestanding", "-fno-builtin", "-fno-pic", "-fno-pie", "-fno-ident",
             "-nostdlib", "-nostartfiles", "-static", "-Wl,--build-id=none", "-Wl,--no-relax",
             f"-Wl,--defsym=__reset_vector={reset_vector}", "-T", "link.ld", "start.S", "main.c", "multiply.c", "-o", "program.elf"]
    with tempfile.TemporaryDirectory(prefix="ditdah-e2-software-", dir=scratch) as directory:
        work = Path(directory)
        for name in ("start.S", "main.c", "multiply.c", "link.ld"):
            shutil.copyfile(ROOT / "software" / name, work / name)
        environment = dict(os.environ, SOURCE_DATE_EPOCH="0", LC_ALL="C", TMPDIR=str(work))
        subprocess.run([str(cc), *flags], cwd=work, env=environment, check=True, capture_output=True, text=True)
        listing = subprocess.check_output([str(disassembler), "-d", "-M", "no-aliases", "program.elf"],
                                          cwd=work, env=environment, text=True)
        (work / "program.dis").write_text(listing)
        image = load_elf(work / "program.elf", reset_vector=reset_vector, enable_c=enable_c)
        instructions = instruction_inventory(listing, enable_m, enable_c)
        for name in ("_start", "software_done", "software_signature", "software_seed", "software_factor", "software_product"):
            if name not in image.symbols:
                raise ValueError(f"Missing workload symbol: {name}")
        done = image.symbols["software_done"]
        if done & 3 or image.words().get(done) != 0x0000006F:
            raise ValueError("Completion symbol must contain a JAL self-loop")
        if sources() != inputs or tool(compiler)[1] != cc_info or tool(objdump)[1] != disassembler_info:
            raise RuntimeError("Software build inputs changed")
        artifact_hashes = {name: digest(work / name) for name in ("program.elf", "program.dis")}
        manifest = {
            "isa": isa, "abi": "ilp32", "resetVector": reset_vector,
            "parameters": {"resetVector": reset_vector, "enableM": enable_m, "enableC": enable_c},
            "elfFlags": image.flags, "instructions": instructions,
            "codeBytes": sum(item["length"] for item in instructions),
            "sourceHashes": inputs, "tools": {"compiler": cc_info, "objdump": disassembler_info},
            "artifactHashes": artifact_hashes, "symbols": image.symbols,
            "segments": [{"address": segment.address, "fileSize": len(segment.data),
                          "memorySize": segment.memory_size, "flags": segment.flags,
                          "fileSha256": hashlib.sha256(segment.data).hexdigest(),
                          "memorySha256": hashlib.sha256(segment.data + bytes(segment.memory_size - len(segment.data))).hexdigest()}
                         for segment in image.segments],
            "commands": [[cc_info["name"], *flags],
                         [disassembler_info["name"], "-d", "-M", "no-aliases", "program.elf"]],
            "environment": {"SOURCE_DATE_EPOCH": "0", "LC_ALL": "C"}, "exitStatus": 0,
            "scope": "software compilation and ELF validation",
        }
        output = Path(output)
        output.mkdir(parents=True, exist_ok=True)
        for name in artifact_hashes:
            shutil.copyfile(work / name, output / name)
        if sources() != inputs:
            raise RuntimeError("Software build inputs changed")
        (output / "manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    return manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--compiler", default="riscv32-none-elf-gcc")
    parser.add_argument("--objdump", default="riscv32-none-elf-objdump")
    parser.add_argument("--reset-vector", type=lambda value: int(value, 0), default=0)
    parser.add_argument("--enable-m", action="store_true")
    parser.add_argument("--enable-c", action="store_true")
    parser.add_argument("--output", type=Path, default=Path("result/software"))
    args = parser.parse_args()
    build(args.output, args.compiler, args.objdump, args.reset_vector, enable_m=args.enable_m, enable_c=args.enable_c)
    print("Built and validated RV32 ELF")


if __name__ == "__main__":
    main()
