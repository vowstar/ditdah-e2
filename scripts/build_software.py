# SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
# SPDX-License-Identifier: MIT
"""Build and validate the freestanding RV32I workload."""

import argparse
import hashlib
import json
import os
from pathlib import Path
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


def build(output, compiler="riscv32-none-elf-gcc", objdump="riscv32-none-elf-objdump", reset_vector=0):
    if type(reset_vector) is not int or not 0 <= reset_vector < 0x10000 or reset_vector % 4:
        raise ValueError("Reset vector must be word aligned and inside boot ROM")
    inputs = sources()
    cc, cc_info = tool(compiler)
    disassembler, disassembler_info = tool(objdump)
    scratch = "/data/tmp" if os.access("/data/tmp", os.W_OK) else None
    flags = ["-Os", "-std=c11", "-march=rv32i", "-mabi=ilp32", "-mno-relax", "-msmall-data-limit=0",
             "-ffreestanding", "-fno-builtin", "-fno-pic", "-fno-pie", "-fno-ident",
             "-nostdlib", "-nostartfiles", "-static", "-Wl,--build-id=none", "-Wl,--no-relax",
             f"-Wl,--defsym=__reset_vector={reset_vector}", "-T", "link.ld", "start.S", "main.c", "-o", "program.elf"]
    with tempfile.TemporaryDirectory(prefix="ditdah-e2-software-", dir=scratch) as directory:
        work = Path(directory)
        for name in ("start.S", "main.c", "link.ld"):
            shutil.copyfile(ROOT / "software" / name, work / name)
        environment = dict(os.environ, SOURCE_DATE_EPOCH="0", LC_ALL="C", TMPDIR=str(work))
        subprocess.run([str(cc), *flags], cwd=work, env=environment, check=True, capture_output=True, text=True)
        listing = subprocess.check_output([str(disassembler), "-d", "-M", "no-aliases", "program.elf"],
                                          cwd=work, env=environment, text=True)
        (work / "program.dis").write_text(listing)
        image = load_elf(work / "program.elf", reset_vector=reset_vector)
        for name in ("_start", "software_done", "software_signature", "software_seed"):
            if name not in image.symbols:
                raise ValueError(f"Missing workload symbol: {name}")
        done = image.symbols["software_done"]
        if image.words().get(done) != 0x0000006F:
            raise ValueError("Completion symbol must contain a JAL self-loop")
        if sources() != inputs or tool(compiler)[1] != cc_info or tool(objdump)[1] != disassembler_info:
            raise RuntimeError("Software build inputs changed")
        artifact_hashes = {name: digest(work / name) for name in ("program.elf", "program.dis")}
        manifest = {
            "isa": "rv32i", "abi": "ilp32", "resetVector": reset_vector,
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
    parser.add_argument("--output", type=Path, default=Path("result/software"))
    args = parser.parse_args()
    build(args.output, args.compiler, args.objdump, args.reset_vector)
    print("Built and validated RV32I ELF")


if __name__ == "__main__":
    main()
