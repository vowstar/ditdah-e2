# SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
# SPDX-License-Identifier: MIT
"""Exhaustively check RV32 compressed instruction expansion and classification."""

import argparse
from collections import Counter
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile


OPERATIONS = {"addi4spn", "lw", "sw", "nop", "addi", "jal", "li", "lui", "addi16sp",
              "srli", "srai", "andi", "sub", "xor", "or", "and", "j", "beqz", "bnez",
              "slli", "lwsp", "jr", "mv", "ebreak", "jalr", "add", "swsp"}
WRAPPER = """// SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
// SPDX-License-Identifier: MIT
package ditdah_e2
import me.jiuyang.zaozi.*
import me.jiuyang.zaozi.default.{*, given}
import me.jiuyang.zaozi.reftpe.*
import me.jiuyang.zaozi.valuetpe.*
@generator
object DitDahE2 extends Generator[Parameters, UnitLayers, CompressedIO, UnitProbe]:
  override def moduleName(p: Parameters): String = "DitDahE2CompressedTest"
  def architecture(p: Parameters) =
    val io = summon[Interface[CompressedIO]]
    val unit = Compressed.instantiate(p)
    unit.io.raw := io.raw
    io.instruction := unit.io.instruction
    io.legal := unit.io.legal
    io.hint := unit.io.hint
"""
HARNESS = """// SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
// SPDX-License-Identifier: MIT
module CompressedBench;
  reg [15:0] raw;
  wire [31:0] instruction;
  wire legal, hint;
  integer file, fields;
  DitDahE2Compressed dut(.*);
  initial begin
    file = $fopen("vectors.txt", "r");
    if (!file) $fatal(1, "Cannot open compressed vectors");
    while (!$feof(file)) begin
      fields = $fscanf(file, "%h\\n", raw);
      if (fields == 1) begin
        #1;
        $display("%04h %0d %0d %08h", raw, legal, hint, instruction);
      end else if (fields != -1) $fatal(1, "Incomplete compressed vector");
    end
    $fclose(file);
    $finish(0);
  end
endmodule
"""


def signed(value, width):
    return value - (1 << width) if value & (1 << (width - 1)) else value


def immediate(rd, base, value, function=0, opcode=0x13):
    return ((value & 4095) << 20) | (base << 15) | (function << 12) | (rd << 7) | opcode


def register(rd, left, right, function=0, upper=0):
    return (upper << 25) | (right << 20) | (left << 15) | (function << 12) | (rd << 7) | 0x33


def store(source, base, offset):
    return ((offset >> 5) << 25) | (source << 20) | (base << 15) | 0x2000 | ((offset & 31) << 7) | 0x23


def jump(destination, offset):
    value = offset & ((1 << 21) - 1)
    return (((value >> 20) & 1) << 31) | (((value >> 1) & 1023) << 21) | \
        (((value >> 11) & 1) << 20) | (((value >> 12) & 255) << 12) | (destination << 7) | 0x6F


def branch(source, offset, unequal):
    value = offset & 8191
    return (((value >> 12) & 1) << 31) | (((value >> 5) & 63) << 25) | (source << 15) | \
        (int(unequal) << 12) | (((value >> 1) & 15) << 8) | (((value >> 11) & 1) << 7) | 0x63


def decode(raw):
    quadrant, family = raw & 3, raw >> 13
    rd, rs2 = (raw >> 7) & 31, (raw >> 2) & 31
    left, right = 8 + ((raw >> 7) & 7), 8 + ((raw >> 2) & 7)
    imm6 = ((raw >> 12) & 1) * 32 + rs2
    imm = signed(imm6, 6)

    def normal(name, word):
        return 1, 0, word & 0xFFFFFFFF, name

    def hint(name):
        return 1, 1, 0x13, "hint." + name

    def illegal(name):
        return 0, 0, 0, "illegal." + name

    if quadrant == 0:
        if family == 0:
            offset = ((raw >> 7) & 15) * 64 + ((raw >> 11) & 3) * 16 + \
                ((raw >> 5) & 1) * 8 + ((raw >> 6) & 1) * 4
            return normal("addi4spn", immediate(right, 2, offset)) if offset else illegal("addi4spn_zero")
        if family in (2, 6):
            offset = ((raw >> 5) & 1) * 64 + ((raw >> 10) & 7) * 8 + ((raw >> 6) & 1) * 4
            return normal("lw", immediate(right, left, offset, 2, 3)) if family == 2 else \
                normal("sw", store(right, left, offset))
        return illegal("reserved_quadrant_zero" if family == 4 else "floating_memory")
    if quadrant == 1:
        if family == 0:
            if raw == 1:
                return normal("nop", 0x13)
            return hint("nop" if rd == 0 else "addi") if rd == 0 or imm == 0 else \
                normal("addi", immediate(rd, rd, imm))
        if family in (1, 5):
            offset = ((raw >> 12) & 1) * 2048 + ((raw >> 8) & 1) * 1024 + \
                ((raw >> 9) & 3) * 256 + ((raw >> 6) & 1) * 128 + ((raw >> 7) & 1) * 64 + \
                ((raw >> 2) & 1) * 32 + ((raw >> 11) & 1) * 16 + ((raw >> 3) & 7) * 2
            return normal("jal" if family == 1 else "j", jump(int(family == 1), signed(offset, 12)))
        if family == 2:
            return hint("li") if rd == 0 else normal("li", immediate(rd, 0, imm))
        if family == 3:
            if imm == 0:
                return illegal("addi16sp_zero" if rd == 2 else "lui_zero")
            if rd == 2:
                offset = ((raw >> 12) & 1) * 512 + ((raw >> 3) & 3) * 128 + \
                    ((raw >> 5) & 1) * 64 + ((raw >> 2) & 1) * 32 + ((raw >> 6) & 1) * 16
                return normal("addi16sp", immediate(2, 2, signed(offset, 10)))
            return hint("lui") if rd == 0 else normal("lui", ((imm & 0xFFFFF) << 12) | (rd << 7) | 0x37)
        if family == 4:
            selector = (raw >> 10) & 3
            if selector < 2:
                name = "srai" if selector else "srli"
                if imm6 >= 32:
                    return illegal("custom_" + name)
                return hint(name) if imm6 == 0 else normal(name, immediate(left, left, imm6 + 1024 * selector, 5))
            if selector == 2:
                return normal("andi", immediate(left, left, imm, 7))
            if raw & 0x1000:
                return illegal("rv64_arithmetic" if ((raw >> 5) & 3) < 2 else "reserved_arithmetic")
            name, function, upper = (("sub", 0, 32), ("xor", 4, 0), ("or", 6, 0), ("and", 7, 0))[(raw >> 5) & 3]
            return normal(name, register(left, left, right, function, upper))
        offset = ((raw >> 12) & 1) * 256 + ((raw >> 5) & 3) * 64 + \
            ((raw >> 2) & 1) * 32 + ((raw >> 10) & 3) * 8 + ((raw >> 3) & 3) * 2
        return normal("bnez" if family == 7 else "beqz", branch(left, signed(offset, 9), family == 7))
    if quadrant == 2:
        if family == 0:
            if imm6 >= 32:
                return illegal("custom_slli")
            return hint("slli") if rd == 0 or imm6 == 0 else normal("slli", immediate(rd, rd, imm6, 1))
        if family == 2:
            if rd == 0:
                return illegal("lwsp_zero")
            offset = ((raw >> 2) & 3) * 64 + ((raw >> 12) & 1) * 32 + ((raw >> 4) & 7) * 4
            return normal("lwsp", immediate(rd, 2, offset, 2, 3))
        if family == 4:
            if rs2 == 0:
                if raw & 0x1000:
                    return normal("jalr", immediate(1, rd, 0, 0, 0x67)) if rd else normal("ebreak", 0x00100073)
                return normal("jr", immediate(0, rd, 0, 0, 0x67)) if rd else illegal("jr_zero")
            name = "add" if raw & 0x1000 else "mv"
            return hint(name) if rd == 0 else normal(name, register(rd, rd if raw & 0x1000 else 0, rs2))
        if family == 6:
            offset = ((raw >> 7) & 3) * 64 + ((raw >> 9) & 15) * 4
            return normal("swsp", store(rs2, 2, offset))
        return illegal("floating_stack")
    return illegal("uncompressed")


def check_oracle():
    cases = ((0x0000, 0, 0, 0), (0x0001, 1, 0, 0x13), (0x0081, 1, 1, 0x13),
             (0x0005, 1, 1, 0x13), (0x0085, 1, 0, 0x00108093), (0x10FD, 1, 0, 0xFFF08093),
             (0x2001, 1, 0, 0xEF), (0xA001, 1, 0, 0x6F), (0x4001, 1, 1, 0x13),
             (0x4085, 1, 0, 0x00100093), (0x6001, 0, 0, 0), (0x6005, 1, 1, 0x13),
             (0x6081, 0, 0, 0), (0x6085, 1, 0, 0x10B7), (0x6101, 0, 0, 0),
             (0x6141, 1, 0, 0x01010113), (0x8001, 1, 1, 0x13), (0x8005, 1, 0, 0x00145413),
             (0x9001, 0, 0, 0), (0x8401, 1, 1, 0x13), (0x8405, 1, 0, 0x40145413),
             (0x9401, 0, 0, 0), (0x8801, 1, 0, 0x00047413), (0x8C01, 1, 0, 0x40840433),
             (0x9C01, 0, 0, 0), (0x0002, 1, 1, 0x13), (0x0006, 1, 1, 0x13),
             (0x0082, 1, 1, 0x13), (0x0086, 1, 0, 0x00109093), (0x1002, 0, 0, 0),
             (0x4002, 0, 0, 0), (0x4082, 1, 0, 0x00012083), (0x8002, 0, 0, 0),
             (0x8082, 1, 0, 0x00008067), (0x8006, 1, 1, 0x13), (0x8086, 1, 0, 0x001000B3),
             (0x9002, 1, 0, 0x00100073), (0x9082, 1, 0, 0x000080E7), (0x9006, 1, 1, 0x13),
             (0x9086, 1, 0, 0x001080B3), (0x2000, 0, 0, 0), (0x2002, 0, 0, 0), (0x0003, 0, 0, 0))
    for raw, legal, hint, instruction in cases:
        assert decode(raw)[:3] == (legal, hint, instruction), f"Oracle mismatch for {raw:04x}"
    return len(cases)


def check(trace):
    lines = trace.splitlines()
    assert len(lines) == 65536, "Missing compressed vectors"
    coverage = Counter()
    for raw, line in enumerate(lines):
        value, legal, hint, instruction = line.split()
        assert int(value, 16) == raw, "Compressed vector sequence differs"
        expected = decode(raw)
        assert (int(legal), int(hint), int(instruction, 16)) == expected[:3], f"Compressed decode differs for {raw:04x}"
        coverage[expected[3]] += 1
    assert OPERATIONS <= coverage.keys(), "Unreached compressed operation"
    return dict(sorted(coverage.items()))


def negative_controls(trace):
    lines = trace.splitlines()
    outcomes = []
    for name, raw, field, value in (("reserved_lui", 0x6001, 1, "1"),
                                   ("lui_hint", 0x6005, 2, "0"),
                                   ("shift_custom", 0x1002, 1, "1"),
                                   ("stack_offset", 0x6141, 3, "02010113"),
                                   ("jump_destination", 0x2001, 3, "0000006f")):
        changed = lines.copy()
        fields = changed[raw].split()
        fields[field] = value
        changed[raw] = " ".join(fields)
        text = "\n".join(changed)
        try:
            check(text)
        except AssertionError as error:
            outcomes.append({"name": name, "raw": raw, "replacement": changed[raw],
                             "rejected": str(error), "traceHash": sha(text.encode())})
        else:
            raise AssertionError(f"Checker accepted {name}")
    return outcomes


def sha(data):
    return hashlib.sha256(data).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=Path("result/compressed-unit"))
    args = parser.parse_args()
    oracle_checks = check_oracle()
    root = Path(__file__).resolve().parents[1]
    names = ["ditdah_e2/src/Compressed.scala", "ditdah_e2/src/Parameters.scala",
             "ditdah_e2/src/Interfaces.scala", "test/compressed_unit.py", "flake.nix", "flake.lock"]
    names += [str(path.relative_to(root)) for path in sorted((root / "nix").glob("*.nix"))]
    contents = {name: (root / name).read_bytes() for name in names}
    hashes = {name: sha(data) for name, data in contents.items()}
    tools = {name: Path(shutil.which(name)) for name in ("elaborate-ditdah-e2", "firld", "firtool", "iverilog", "vvp")}
    tool_hashes = {name: sha(path.read_bytes()) for name, path in tools.items()}
    vector_text = "".join(f"{raw:04x}\n" for raw in range(65536))
    commands = []
    scratch = "/data/tmp" if os.access("/data/tmp", os.W_OK) else None
    with tempfile.TemporaryDirectory(prefix="ditdah-e2-compressed-", dir=scratch) as directory:
        work = Path(directory)
        for name, data in contents.items():
            target = work / "inputs" / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
        source = work / "inputs/ditdah_e2/src"
        (source / "CompressedTop.scala").write_text(WRAPPER)
        (work / "parameters.json").write_text('{"resetVector":0}\n')
        (work / "vectors.txt").write_text(vector_text)
        (work / "compressed_tb.sv").write_text(HARNESS)
        frozen = {path: sha(path.read_bytes()) for path in work.rglob("*") if path.is_file()}
        environment = dict(os.environ, DITDAH_E2_SOURCE=str(source))

        def verify_inputs():
            assert all(sha(path.read_bytes()) == value for path, value in frozen.items()), "Frozen compressed inputs changed"
            assert all(sha(path.read_bytes()) == tool_hashes[name] for name, path in tools.items()), "Compressed tools changed"

        def run(command):
            result = subprocess.run(command, cwd=work, env=environment, capture_output=True, text=True)
            commands.append({"argv": command, "exitStatus": result.returncode})
            if result.returncode:
                raise RuntimeError((result.stdout + result.stderr).replace(str(work), "<workspace>"))
            return result.stdout

        verify_inputs()
        run(["elaborate-ditdah-e2", "design", "parameters.json"])
        run(["firld", *[path.name for path in sorted(work.glob("*.mlirbc"))],
             "--base-circuit", "DitDahE2CompressedTest", "--no-mangle", "--emit-bytecode", "-o", "linked.mlirbc"])
        run(["firtool", "linked.mlirbc", "--split-verilog", "-disable-all-randomization",
             "--lowering-options=noAlwaysComb,disallowLocalVariables,locationInfoStyle=none", "-o", "rtl"])
        rtl = sorted((work / "rtl").glob("*.sv"))
        assert (work / "rtl/DitDahE2Compressed.sv").is_file(), "Missing compressed RTL"
        rtl_hashes = {path.name: sha(path.read_bytes()) for path in rtl}
        run(["iverilog", "-g2012", "-s", "CompressedBench", "-o", "compressed-sim",
             *[str(path.relative_to(work)) for path in rtl], "compressed_tb.sv"])
        trace = run(["vvp", "compressed-sim"])
        coverage = check(trace)
        controls = negative_controls(trace)
        verify_inputs()
        assert rtl_hashes == {path.name: sha(path.read_bytes()) for path in rtl}, "Compressed RTL changed"
        versions = {}
        for name in ("firtool", "firld", "iverilog", "vvp"):
            result = subprocess.run([name, "--version" if name in ("firtool", "firld") else "-V"],
                                    capture_output=True, text=True, check=True)
            version = (result.stdout + result.stderr).strip()
            versions[name] = version if name in ("firtool", "firld") else version.splitlines()[0]
        args.output.mkdir(parents=True, exist_ok=True)
        for path in rtl:
            shutil.copyfile(path, args.output / path.name)
        (args.output / "compressed.trace").write_text(trace)
        (args.output / "vectors.txt").write_text(vector_text)
        report = {"scope": "RV32C integer decompressor", "parameters": {"resetVector": 0},
                  "command": "python3 test/compressed_unit.py", "exitStatus": 0,
                  "inputHashes": hashes, "tools": versions, "toolHashes": tool_hashes, "commands": commands,
                  "rtlHashes": rtl_hashes, "wrapperHash": sha(WRAPPER.encode()), "harnessHash": sha(HARNESS.encode()),
                  "vectorHash": sha(vector_text.encode()), "traceHash": sha(trace.encode()),
                  "vectors": 65536, "oracleChecks": oracle_checks, "coverage": coverage,
                  "negativeControls": controls,
                  "integrationChecksRequired": ["instruction assembly", "instruction length", "raw trap encoding", "halfword targets"]}
        (args.output / "summary.json").write_text(json.dumps(report, indent=2) + "\n")
    print(f"PASS: 65536 compressed vectors and {len(controls)} semantic negative controls")


if __name__ == "__main__":
    main()
