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
                "sltu", "xor", "srl", "sra", "or", "and", "fence", "ecall", "ebreak",
                "csrrw", "csrrs", "csrrc", "csrrwi", "csrrsi", "csrrci", "mret", "wfi", "fence.i"]
A_INSTRUCTIONS = ["lr.w", "sc.w", "amoswap.w", "amoadd.w", "amoxor.w", "amoand.w", "amoor.w",
                  "amomin.w", "amomax.w", "amominu.w", "amomaxu.w"]
M_INSTRUCTIONS = ["mul", "mulh", "mulhsu", "mulhu", "div", "divu", "rem", "remu"]
C_INSTRUCTIONS = ["c.addi4spn", "c.lw", "c.sw", "c.addi", "c.jal", "c.li", "c.lui", "c.addi16sp",
                  "c.srli", "c.srai", "c.andi", "c.sub", "c.xor", "c.or", "c.and", "c.j", "c.beqz",
                  "c.bnez", "c.slli", "c.lwsp", "c.jr", "c.mv", "c.ebreak", "c.jalr", "c.add", "c.swsp", "c.nop"]
BIT_INSTRUCTIONS = {
    "Zba": ["sh1add", "sh2add", "sh3add"],
    "Zbb": ["andn", "orn", "xnor", "clz", "ctz", "cpop", "max", "maxu", "min", "minu",
            "sext.b", "sext.h", "zext.h", "rol", "ror", "rori", "orc.b", "rev8"],
    "Zbs": ["bclr", "bclri", "bext", "bexti", "binv", "binvi", "bset", "bseti"],
}


def configuration(value):
    if not isinstance(value, dict) or value.keys() - {"resetVector", "enableM", "enableC", "protectedMode", "enableDebug", "enableA", "enableZba", "enableZbb", "enableZbs"}:
        raise ValueError("Unknown core configuration field")
    enable_c = value.get("enableC", True)
    if type(enable_c) is not bool:
        raise ValueError("enableC must be a Boolean")
    reset = value.get("resetVector", 0)
    if type(reset) is not int or not 0 <= reset <= 0xFFFFFFFF or reset % (2 if enable_c else 4):
        raise ValueError("resetVector must be unsigned RV32 and satisfy instruction alignment")
    enable_m = value.get("enableM", True)
    if type(enable_m) is not bool:
        raise ValueError("enableM must be a Boolean")
    protected = value.get("protectedMode", False)
    if type(protected) is not bool:
        raise ValueError("protectedMode must be a Boolean")
    debug = value.get("enableDebug", False)
    if type(debug) is not bool:
        raise ValueError("enableDebug must be a Boolean")
    atomic = value.get("enableA", False)
    if type(atomic) is not bool:
        raise ValueError("enableA must be a Boolean")
    bits = {"enable" + name: value.get("enable" + name, False) for name in BIT_INSTRUCTIONS}
    if any(type(enabled) is not bool for enabled in bits.values()):
        raise ValueError("Bit extension options must be Boolean")
    return {"resetVector": reset, "enableM": enable_m, "enableC": enable_c, "protectedMode": protected, "enableDebug": debug, "enableA": atomic, **bits}


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def sources():
    paths = sorted(Path("ditdah_e2/src").glob("*.scala"))
    paths += sorted(Path("ditdah_e2/src").glob("*.sv"))
    paths += sorted(Path("nix").glob("*.nix"))
    paths += [Path(p) for p in ("flake.nix", "flake.lock", "scripts/build_rtl.py")]
    return {str(p): digest(p) for p in paths}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path)
    parser.add_argument("--output", type=Path, default=Path("result/rtl"))
    args = parser.parse_args()
    params = configuration(json.loads(args.config.read_text()) if args.config else {})
    bit_extensions = [name for name in BIT_INSTRUCTIONS if params["enable" + name]]
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
            "instructions": INSTRUCTIONS + (A_INSTRUCTIONS if params["enableA"] else []) + (M_INSTRUCTIONS if params["enableM"] else []) + (C_INSTRUCTIONS if params["enableC"] else []) +
                            [name for extension in bit_extensions for name in BIT_INSTRUCTIONS[extension]], "privilegedArchitecture": False,
            "machineTrapHandling": True, "extensions": ["I", "Zicsr", "Zicntr", "Zifencei"] + (["A"] if params["enableA"] else []) + (["M"] if params["enableM"] else []) + (["C"] if params["enableC"] else []) + bit_extensions,
            "machineInterrupts": ["software", "timer", "external"],
            "privilegeModes": ["M", "U"] if params["protectedMode"] else ["M"],
            "pmpEntries": 16 if params["protectedMode"] else 0,
            "debug": "synchronous DMI" if params["enableDebug"] else None,
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
