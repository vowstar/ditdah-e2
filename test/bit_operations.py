# SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
# SPDX-License-Identifier: MIT
"""Check all RV32 Zba, Zbb and Zbs subsets against independent arithmetic."""

import argparse
from collections import Counter
import hashlib
import json
import os
from pathlib import Path
import random
import re
import shutil
import subprocess
import tempfile


MASK = 0xFFFFFFFF
SEED = 0x42495453
BOUNDARY = (0, 1, 2, 31, 32, 0x7FFFFFFF, 0x80000000, 0x80000001,
            0xFFFFFFFE, MASK, 0xA5A5A5A5, 0x010080FF)
ENCODINGS = {
    "sh1add": (0x20002033, 1, "R"), "sh2add": (0x20004033, 1, "R"),
    "sh3add": (0x20006033, 1, "R"), "andn": (0x40007033, 2, "R"),
    "orn": (0x40006033, 2, "R"), "xnor": (0x40004033, 2, "R"),
    "clz": (0x60001013, 2, "U"), "ctz": (0x60101013, 2, "U"),
    "cpop": (0x60201013, 2, "U"), "max": (0x0A006033, 2, "R"),
    "maxu": (0x0A007033, 2, "R"), "min": (0x0A004033, 2, "R"),
    "minu": (0x0A005033, 2, "R"), "sext.b": (0x60401013, 2, "U"),
    "sext.h": (0x60501013, 2, "U"), "zext.h": (0x08004033, 2, "U"),
    "rol": (0x60001033, 2, "R"), "ror": (0x60005033, 2, "R"),
    "rori": (0x60005013, 2, "I"), "orc.b": (0x28705013, 2, "U"),
    "rev8": (0x69805013, 2, "U"), "bclr": (0x48001033, 4, "R"),
    "bclri": (0x48001013, 4, "I"), "bext": (0x48005033, 4, "R"),
    "bexti": (0x48005013, 4, "I"), "binv": (0x68001033, 4, "R"),
    "binvi": (0x68001013, 4, "I"), "bset": (0x28001033, 4, "R"),
    "bseti": (0x28001013, 4, "I"),
}
WRAPPER = """// SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
// SPDX-License-Identifier: MIT
package ditdah_e2
import me.jiuyang.zaozi.*
import me.jiuyang.zaozi.default.{*, given}
import me.jiuyang.zaozi.reftpe.*
import me.jiuyang.zaozi.valuetpe.*
@generator
object DitDahE2 extends Generator[BitParameters, BitLayers, BitIO, BitProbe]:
  override def moduleName(p: BitParameters): String = "DitDahE2BitTest"
  def architecture(p: BitParameters) =
    val io = summon[Interface[BitIO]]
    val unit = BitOperations.instantiate(p)
    unit.io.word := io.word
    unit.io.a := io.a
    unit.io.b := io.b
    io.valid := unit.io.valid
    io.result := unit.io.result
    io.usesRs2 := unit.io.usesRs2
"""
HARNESS = """// SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
// SPDX-License-Identifier: MIT
module BitBench;
  reg [31:0] word, a, b;
  wire valid, usesRs2;
  wire [31:0] result;
  integer file, fields, row = 0;
  DitDahE2BitOperations dut(.*);
  initial begin
    file = $fopen("vectors.txt", "r");
    if (!file) $fatal(1, "Cannot open bit vectors");
    while (!$feof(file)) begin
      fields = $fscanf(file, "%h %h %h\\n", word, a, b);
      if (fields == 3) begin
        #1;
        $display("%0d %0d %0d %08h", row, valid, usesRs2, result);
        row = row + 1;
      end else if (fields != -1) $fatal(1, "Incomplete bit vector");
    end
    $fclose(file);
    $finish(0);
  end
endmodule
"""


def encode(operation, rd=3, rs1=1, rs2=2, shift=0):
    pattern, _, form = ENCODINGS[operation]
    assert all(type(value) is int and 0 <= value < 32 for value in (rd, rs1, rs2, shift))
    return pattern | (rd << 7) | (rs1 << 15) | ((rs2 if form == "R" else shift if form == "I" else 0) << 20)


def decode(word):
    for operation, (pattern, extension, form) in ENCODINGS.items():
        mask = 0xFFF0707F if form == "U" else 0xFE00707F
        if word & mask == pattern:
            return operation, extension, form
    return None


def signed(value):
    return value - (1 << 32) if value & (1 << 31) else value


def arithmetic(operation, a, b, shift):
    if operation.startswith("sh"):
        result = a * (2 ** int(operation[2])) + b
    elif operation == "andn":
        result = a & ~b
    elif operation == "orn":
        result = a | ~b
    elif operation == "xnor":
        result = ~(a ^ b)
    elif operation == "clz":
        result = 32 - a.bit_length()
    elif operation == "ctz":
        result = 32 if a == 0 else (a & -a).bit_length() - 1
    elif operation == "cpop":
        result = a.bit_count()
    elif operation in ("max", "min", "maxu", "minu"):
        values = (a, b) if operation.endswith("u") else (signed(a), signed(b))
        result = max(values) if operation.startswith("max") else min(values)
    elif operation in ("sext.b", "sext.h"):
        width = 8 if operation.endswith("b") else 16
        value = a % (1 << width)
        result = value - (1 << width) if value >= 1 << (width - 1) else value
    elif operation == "zext.h":
        result = a % 65536
    elif operation == "rol":
        amount = b % 32
        result = (a << amount) | (a >> (32 - amount))
    elif operation in ("ror", "rori"):
        amount = shift if operation == "rori" else b % 32
        result = (a >> amount) | (a << (32 - amount))
    elif operation == "orc.b":
        result = sum(255 << offset for offset in range(0, 32, 8) if (a >> offset) % 256)
    elif operation == "rev8":
        result = int.from_bytes(a.to_bytes(4, "little"), "big")
    else:
        amount = shift if operation.endswith("i") else b % 32
        bit = 1 << amount
        if operation.startswith("bclr"):
            result = a & ~bit
        elif operation.startswith("bext"):
            result = (a >> amount) % 2
        elif operation.startswith("binv"):
            result = a ^ bit
        elif operation.startswith("bset"):
            result = a | bit
        else:
            raise ValueError("Unknown bit operation")
    return result & MASK


def expected(row, subset):
    word, a, b = row
    decoded = decode(word)
    if decoded is None or not decoded[1] & subset:
        return 0, 0, 0
    operation, _, form = decoded
    return 1, int(form == "R"), arithmetic(operation, a, b, (word >> 20) & 31)


def vectors(random_pairs=4096):
    rng = random.Random(SEED)
    rows = []
    for operation, (_, _, form) in ENCODINGS.items():
        for a in BOUNDARY:
            for b in BOUNDARY:
                rows.append((encode(operation, shift=b & 31), a, b))
        for _ in range(random_pairs):
            rows.append((encode(operation, shift=rng.randrange(32)), rng.getrandbits(32), rng.getrandbits(32)))
        for field in ("rd", "rs1", "rs2"):
            row = encode(operation, **{field: 0})
            rows.append((row, 0 if field == "rs1" else MASK, 0 if field == "rs2" and form == "R" else MASK))
        if operation.startswith("b") or operation in ("rol", "ror", "rori"):
            for amount in range(32):
                for upper in (0, 32, 0x80000000, 0xFFFFFFE0):
                    for a in (0, 1, 0x80000000, 0x80000001, MASK):
                        rows.append((encode(operation, shift=amount), a, upper | amount))
    for opcode in (0x13, 0x33, 0x1B, 0x3B):
        for immediate in range(4096):
            for function in range(8):
                rows.append(((immediate << 20) | 0x8000 | (function << 12) | 0x180 | opcode,
                             0x01234567, 0xFEDCBA98))
    for opcode in range(128):
        for upper in (0, 0x200, 0x400, 0x480, 0x600, 0x698):
            rows.append(((upper << 20) | 0x51180 | opcode, MASK, 31))
    return rows


def check(rows, trace, subset):
    coverage = Counter()
    seen = 0
    for line in trace.splitlines():
        if line.startswith(("VCD info:", "$finish", "bit_tb.sv:")):
            continue
        fields = line.split()
        if len(fields) != 4 or not fields[0].isdecimal():
            raise AssertionError("Unexpected bit trace record")
        index = int(fields[0])
        assert index == seen and index < len(rows), "Bit trace order changed"
        assert fields[1] in ("0", "1") and fields[2] in ("0", "1"), "Unknown bit control value"
        assert re.fullmatch(r"[0-9a-fA-F]{8}", fields[3]), "Unknown bit result"
        actual = int(fields[1]), int(fields[2]), int(fields[3], 16)
        assert actual == expected(rows[index], subset), "Bit output differs from independent arithmetic"
        decoded = decode(rows[index][0])
        coverage[decoded[0] if actual[0] else "rejected"] += 1
        seen += 1
    assert seen == len(rows), "Bit trace ended before all vectors completed"
    return dict(coverage)


def mutate(content, signal):
    assert signal in {"result", "valid", "usesRs2"}
    pattern = r"assign\s+" + signal + r"\s*=\s*"
    matches = list(re.finditer(pattern, content))
    assert len(matches) == 1, "Bit mutation does not match generated RTL"
    replacement = "assign " + signal + (" = 32'h00000001 ^ " if signal == "result" else " = 1'b1 | ")
    return re.sub(pattern, replacement, content, count=1)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def vector_text(rows):
    return "".join(f"{word:08x} {a:08x} {b:08x}\n" for word, a, b in rows)


def formal_reference(subset):
    expressions = {
        "sh1add": "a * 32'd2 + b", "sh2add": "a * 32'd4 + b", "sh3add": "a * 32'd8 + b",
        "andn": "a & ~b", "orn": "a | ~b", "xnor": "~(a ^ b)",
        "clz": "leading(a)", "ctz": "trailing(a)", "cpop": "population(a)",
        "max": "$signed(a) > $signed(b) ? a : b", "min": "$signed(a) < $signed(b) ? a : b",
        "maxu": "a > b ? a : b", "minu": "a < b ? a : b",
        "sext.b": "a[7] ? (a & 32'd255) - 32'd256 : a & 32'd255",
        "sext.h": "a[15] ? (a & 32'd65535) - 32'd65536 : a & 32'd65535",
        "zext.h": "a & 32'd65535", "rol": "(a << b[4:0]) | (a >> (32 - b[4:0]))",
        "ror": "(a >> b[4:0]) | (a << (32 - b[4:0]))",
        "rori": "(a >> word[24:20]) | (a << (32 - word[24:20]))",
        "orc.b": "bytes_nonzero(a)", "rev8": "reverse_bytes(a)",
    }
    for operation in ("bclr", "bclri", "bext", "bexti", "binv", "binvi", "bset", "bseti"):
        count = "word[24:20]" if operation.endswith("i") else "b[4:0]"
        if operation.startswith("bext"):
            expressions[operation] = f"(a >> {count}) & 32'd1"
        else:
            operator = "& ~" if operation.startswith("bclr") else "^" if operation.startswith("binv") else "|"
            expressions[operation] = f"a {operator} (32'd1 << {count})"
    text = """// SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
// SPDX-License-Identifier: MIT
module BitFormal(input [31:0] word, a, b, output good, output valid, usesRs2,
                 output [31:0] result);
  reg reference_valid, reference_uses;
  reg [31:0] reference_result;
  DitDahE2BitOperations dut(.*);
  function [31:0] leading(input [31:0] value);
    integer i;
    begin
      leading = 32;
      for (i = 0; i < 32; i = i + 1) if (value[i]) leading = 31 - i;
    end
  endfunction
  function [31:0] trailing(input [31:0] value);
    integer i;
    begin
      trailing = 32;
      for (i = 31; i >= 0; i = i - 1) if (value[i]) trailing = i;
    end
  endfunction
  function [31:0] population(input [31:0] value);
    integer i;
    begin
      population = 0;
      for (i = 0; i < 32; i = i + 1) population = population + value[i];
    end
  endfunction
  function [31:0] bytes_nonzero(input [31:0] value);
    integer i;
    begin
      bytes_nonzero = 0;
      for (i = 0; i < 4; i = i + 1)
        if (((value >> (i * 8)) & 255) != 0) bytes_nonzero = bytes_nonzero | (32'd255 << (i * 8));
    end
  endfunction
  function [31:0] reverse_bytes(input [31:0] value);
    integer i;
    begin
      reverse_bytes = 0;
      for (i = 0; i < 4; i = i + 1)
        reverse_bytes = reverse_bytes | (((value >> (i * 8)) & 255) << ((3 - i) * 8));
    end
  endfunction
  always @* begin
    reference_valid = 0;
    reference_uses = 0;
    reference_result = 0;
"""
    for operation, (pattern, extension, form) in ENCODINGS.items():
        if subset & extension:
            mask = 0xFFF0707F if form == "U" else 0xFE00707F
            text += f"    if ((word & 32'h{mask:08x}) == 32'h{pattern:08x}) begin\n"
            text += f"      reference_valid = 1; reference_uses = {int(form == 'R')};\n"
            text += f"      reference_result = {expressions[operation]};\n    end\n"
    return text + """  end
  assign good = (valid == reference_valid) && (usesRs2 == reference_uses) && (result == reference_result);
endmodule
"""


def proof_script(subset, rtl_names):
    lines = ["read_verilog -formal -sv " + " ".join(rtl_names) + " bit_formal.sv",
             "prep -top BitFormal -flatten", "check -assert",
             "select -assert-none t:$dff t:$adff t:$sdff t:$dlatch t:$adlatch",
             "sat -verify -prove good 1 -set-def-inputs -show-inputs -show-outputs"]
    for operation, (_, extension, _) in ENCODINGS.items():
        if subset & extension:
            lines.append(f"sat -set word 32'd{encode(operation)} -set valid 1 -set-def-inputs -show valid")
    return "\n".join(lines) + "\n"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=Path("result/bit-operations"))
    parser.add_argument("--subset", type=int, choices=range(8))
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    names = ["ditdah_e2/src/BitInterfaces.scala", "ditdah_e2/src/BitOperations.scala",
             "test/bit_operations.py", "test/test_bit_operations.py", "flake.nix", "flake.lock"]
    names += [str(path.relative_to(root)) for path in sorted((root / "nix").glob("*.nix"))]
    contents = {name: (root / name).read_bytes() for name in names}
    tool_names = ("elaborate-ditdah-e2", "firld", "firtool", "iverilog", "vvp", "yosys")
    missing = [name for name in tool_names if not shutil.which(name)]
    if missing:
        raise RuntimeError("Missing tools: " + ", ".join(missing))
    tools = {name: Path(shutil.which(name)) for name in tool_names}
    tool_hashes = {name: sha(path.read_bytes()) for name, path in tools.items()}
    rows = vectors()
    text = vector_text(rows)
    results = []
    scratch = "/data/tmp" if os.access("/data/tmp", os.W_OK) else None
    with tempfile.TemporaryDirectory(prefix="ditdah-e2-bit-", dir=scratch) as directory:
        base = Path(directory)
        for name, data in contents.items():
            target = base / "inputs" / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
        source = base / "inputs/ditdah_e2/src"
        (source / "BitTop.scala").write_text(WRAPPER)
        frozen = {path: sha(path.read_bytes()) for path in base.rglob("*") if path.is_file()}
        args.output.mkdir(parents=True, exist_ok=True)
        for path in frozen:
            target = args.output / path.relative_to(base)
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(path, target)
        environment = dict(os.environ, DITDAH_E2_SOURCE=str(source))
        for subset in ([args.subset] if args.subset is not None else range(8)):
            work = base / str(subset)
            work.mkdir()
            output = args.output / str(subset)
            output.mkdir(parents=True, exist_ok=True)
            params = {name: bool(subset & (1 << index)) for index, name in enumerate(("enableZba", "enableZbb", "enableZbs"))}
            (work / "parameters.json").write_text(json.dumps(params) + "\n")
            (work / "vectors.txt").write_text(text)
            (work / "bit_tb.sv").write_text(HARNESS)
            for name in ("parameters.json", "vectors.txt", "bit_tb.sv"):
                shutil.copyfile(work / name, output / name)
            commands = []

            def run(command, cwd=work):
                result = subprocess.run(command, cwd=cwd, env=environment, capture_output=True, text=True, timeout=300)
                commands.append({"argv": command, "exitStatus": result.returncode})
                if result.returncode:
                    (output / "failure.log").write_text((result.stdout + result.stderr).replace(str(base), "<workspace>"))
                    raise RuntimeError("Bit tool failed with exit status " + str(result.returncode))
                return result.stdout

            run(["elaborate-ditdah-e2", "design", "parameters.json"])
            run(["firld", *[path.name for path in sorted(work.glob("*.mlirbc"))],
                 "--base-circuit", "DitDahE2BitTest", "--no-mangle", "--emit-bytecode", "-o", "linked.mlirbc"])
            run(["firtool", "linked.mlirbc", "--split-verilog", "-disable-all-randomization",
                 "--lowering-options=noAlwaysComb,disallowLocalVariables,locationInfoStyle=none", "-o", "rtl"])
            rtl = sorted((work / "rtl").glob("*.sv"))
            unit = work / "rtl/DitDahE2BitOperations.sv"
            assert unit.is_file(), "Missing bit operation RTL"
            rtl_hashes = {path.name: sha(path.read_bytes()) for path in rtl}
            for path in rtl:
                shutil.copyfile(path, output / path.name)
            run(["iverilog", "-g2012", "-s", "BitBench", "-o", "bit-sim",
                 *[str(path.relative_to(work)) for path in rtl], "bit_tb.sv"])
            trace = run(["vvp", "bit-sim"])
            coverage = check(rows, trace, subset)
            reference = formal_reference(subset)
            proof = proof_script(subset, [str(path.relative_to(work)) for path in rtl])
            (work / "bit_formal.sv").write_text(reference)
            (work / "proof.ys").write_text(proof)
            (output / "bit_formal.sv").write_text(reference)
            (output / "proof.ys").write_text(proof)
            proof_log = run(["yosys", "-Q", "-T", "-s", "proof.ys"])
            assert "SAT proof finished - no model found: SUCCESS!" in proof_log, "Missing complete bit proof"
            expected_covers = sum(bool(subset & extension) for _, extension, _ in ENCODINGS.values())
            assert proof_log.count("SAT solving finished - model found:") == expected_covers, "Missing bit decode covers"
            controls = []
            small = [(encode("sh1add"), 1, 2), (encode("clz"), 0, 17),
                     (encode("bseti", shift=31), 0, 7), (0, 0, 0)]
            for signal in ("result", "valid", "usesRs2"):
                negative = work / signal
                negative.mkdir()
                mutated = mutate(unit.read_text(), signal)
                (negative / unit.name).write_text(mutated)
                (negative / "bit_tb.sv").write_text(HARNESS)
                (negative / "vectors.txt").write_text(vector_text(small))
                run(["iverilog", "-g2012", "-s", "BitBench", "-o", "bit-sim", unit.name, "bit_tb.sv"], negative)
                changed_trace = run(["vvp", "bit-sim"], negative)
                try:
                    check(small, changed_trace, subset)
                except AssertionError as error:
                    assert str(error) == "Bit output differs from independent arithmetic", "Negative control failed before semantic checking"
                else:
                    raise AssertionError("Bit RTL mutation escaped checking")
                control_output = output / "negative" / signal
                control_output.mkdir(parents=True, exist_ok=True)
                for name in (unit.name, "bit_tb.sv", "vectors.txt"):
                    shutil.copyfile(negative / name, control_output / name)
                (control_output / "bit.trace").write_text(changed_trace)
                controls.append({"signal": signal, "rtlHash": sha(mutated.encode()), "traceHash": sha(changed_trace.encode()), "result": "semantic mismatch"})
            assert all(sha(path.read_bytes()) == value for path, value in frozen.items()), "Frozen bit inputs changed"
            assert all(sha(path.read_bytes()) == tool_hashes[name] for name, path in tools.items()), "Bit tools changed"
            assert rtl_hashes == {path.name: sha(path.read_bytes()) for path in rtl}, "Bit RTL changed"
            (output / "bit.trace").write_text(trace)
            (output / "proof.log").write_text(proof_log.replace(str(base), "<workspace>"))
            versions = {}
            for name in ("firtool", "firld", "iverilog", "vvp", "yosys"):
                result = subprocess.run([name, "--version" if name in ("firtool", "firld") else "-V"],
                                        capture_output=True, text=True, check=True)
                version = (result.stdout + result.stderr).strip()
                versions[name] = version if name in ("firtool", "firld") else version.splitlines()[0]
            report = {"scope": "independent combinational RV32 bit unit", "parameters": params,
                      "exitStatus": 0, "inputHashes": {name: sha(data) for name, data in contents.items()},
                      "toolHashes": tool_hashes, "commands": commands, "rtlHashes": rtl_hashes,
                      "wrapperHash": sha(WRAPPER.encode()), "harnessHash": sha(HARNESS.encode()),
                      "vectorHash": sha(text.encode()), "traceHash": sha(trace.encode()),
                      "tools": versions, "proof": {"result": "passed", "scope": "all defined word and operand values",
                          "referenceHash": sha(reference.encode()), "scriptHash": sha(proof.encode()),
                          "logHash": sha(proof_log.replace(str(base), "<workspace>").encode()), "decodeCovers": expected_covers},
                      "randomSeed": SEED, "randomPairsPerOperation": 4096, "vectors": len(rows),
                      "decodeFieldCombinations": 131072, "coverage": coverage, "negativeControls": controls,
                      "integrationChecksRequired": ["operand forwarding", "load-use interlock", "M writeback", "illegal instruction traps"]}
            (output / "summary.json").write_text(json.dumps(report, indent=2) + "\n")
            results.append({"subset": subset, "summaryHash": sha((output / "summary.json").read_bytes())})
            print(f"PASS: bit subset {subset}, {len(rows)} vectors, three RTL negative controls", flush=True)
    (args.output / "summary.json").write_text(json.dumps({"exitStatus": 0, "subsets": results}, indent=2) + "\n")


if __name__ == "__main__":
    main()
