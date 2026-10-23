# SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
# SPDX-License-Identifier: MIT
"""Validate the implemented configuration and generate bound RTL artifacts."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile


INSTRUCTIONS = ["lui", "auipc", "jal", "jalr", "beq", "bne", "blt", "bge", "bltu", "bgeu",
                "lb", "lh", "lw", "lbu", "lhu", "sb", "sh", "sw", "addi", "slti", "sltiu",
                "xori", "ori", "andi", "slli", "srli", "srai", "add", "sub", "sll", "slt",
                "sltu", "xor", "srl", "sra", "or", "and", "fence", "ecall", "ebreak"]


def configuration(value):
    if not isinstance(value, dict) or value.keys() - {"resetVector"}:
        raise ValueError("Only resetVector is supported")
    reset = value.get("resetVector", 0)
    if type(reset) is not int or not 0 <= reset <= 0xFFFFFFFF or reset % 4:
        raise ValueError("resetVector must be a word-aligned unsigned 32-bit integer")
    return {"resetVector": reset}


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def sources():
    paths = sorted(Path("ditdah_e2/src").glob("*.scala"))
    paths += sorted(Path("nix").glob("*.nix"))
    paths += [Path(p) for p in ("flake.nix", "flake.lock", "scripts/build_rtl.py")]
    return {str(p): digest(p) for p in paths}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path)
    parser.add_argument("--output", type=Path, default=Path("result/rtl"))
    args = parser.parse_args()
    params = configuration(json.loads(args.config.read_text()) if args.config else {})
    inputs = sources()
    scratch = "/data/tmp" if os.access("/data/tmp", os.W_OK) else None
    with tempfile.TemporaryDirectory(prefix="ditdah-e2-", dir=scratch) as directory:
        work = Path(directory)
        (work / "parameters.json").write_text(json.dumps(params) + "\n")
        environment = dict(os.environ, DITDAH_E2_SOURCE=str(Path("ditdah_e2/src").resolve()))
        subprocess.run(["elaborate-ditdah-e2", "design", "parameters.json"],
                       cwd=work, env=environment, check=True)
        subprocess.run(["firld", *map(str, sorted(work.glob("*.mlirbc"))),
                        "--base-circuit", "DitDahE2", "--no-mangle", "--emit-bytecode",
                        "-o", str(work / "linked.mlirbc")], check=True)
        subprocess.run(["firtool", str(work / "linked.mlirbc"), "--split-verilog",
                        "-disable-all-randomization",
                        "--lowering-options=noAlwaysComb,disallowLocalVariables,locationInfoStyle=none",
                        "-o", str(work / "rtl")], check=True)
        if sources() != inputs:
            raise RuntimeError("Sources changed during generation")
        rtl = sorted((work / "rtl").glob("*.sv"))
        if not rtl or not (work / "rtl/DitDahE2.sv").exists():
            raise RuntimeError("Missing generated processor RTL")
        manifest = {
            "parameters": params, "top": "DitDahE2", "isaComplete": False,
            "instructions": INSTRUCTIONS, "privilegedArchitecture": False,
            "pipeline": ["F", "X", "M"], "sourceHashes": inputs,
            "rtlHashes": {p.name: digest(p) for p in rtl},
            "firtool": subprocess.check_output(["firtool", "--version"], text=True).strip(),
            "command": "python3 scripts/build_rtl.py", "exitStatus": 0,
        }
        args.output.mkdir(parents=True, exist_ok=True)
        for path in rtl:
            shutil.copyfile(path, args.output / path.name)
        (args.output / "filelist.f").write_text("\n".join(p.name for p in rtl) + "\n")
        (args.output / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    print("Generated DitDahE2 RTL")


if __name__ == "__main__":
    main()
