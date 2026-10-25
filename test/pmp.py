# SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
# SPDX-License-Identifier: MIT
"""Check sixteen PMP entries against independent byte interval permissions."""

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


ROOT = Path(__file__).resolve().parents[1]
LIMIT = 1 << 32
ADDRESS_MASK = (1 << 30) - 1
SPECIFICATION = "https://docs.riscv.org/reference/isa/v20260120/priv/machine.html"
WRAPPER = """// SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
// SPDX-License-Identifier: MIT
package ditdah_e2
import me.jiuyang.zaozi.*
import me.jiuyang.zaozi.default.{*, given}
import me.jiuyang.zaozi.reftpe.*
import me.jiuyang.zaozi.valuetpe.*
@generator
object DitDahE2 extends Generator[Parameters, UnitLayers, PmpIO, UnitProbe]:
  override def moduleName(p: Parameters): String = "DitDahE2PmpTest"
  def architecture(p: Parameters) =
    val io = summon[Interface[PmpIO]]
    val pmp = Pmp.instantiate(p)
    pmp.io.clock := io.clock
    pmp.io.reset := io.reset
    pmp.io.address := io.address
    pmp.io.commitWrite := io.commitWrite
    pmp.io.writeData := io.writeData
    io.readData := pmp.io.readData
    io.implemented := pmp.io.implemented
    io.instruction :<>= pmp.io.instruction
    io.data :<>= pmp.io.data
"""
HARNESS = """// SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
// SPDX-License-Identifier: MIT
module PmpBench;
  reg clock = 0, reset = 1, commitWrite = 0;
  reg [11:0] address = 0;
  reg [31:0] writeData = 0, instruction_address = 0, data_address = 0;
  reg [1:0] instruction_size = 0, instruction_kind = 0, data_size = 0, data_kind = 0;
  reg instruction_machine = 0, data_machine = 0;
  wire [31:0] readData;
  wire implemented, instruction_allowed, data_allowed;
  integer file, fields, sample = 0;
  DitDahE2Pmp dut(.*);
  initial begin
    #1 clock = 1;
    #1 clock = 0;
    file = $fopen("vectors.txt", "r");
    if (!file) $fatal(1, "Cannot open PMP vectors");
    while (!$feof(file)) begin
      fields = $fscanf(file, "%d %h %d %h %h %d %d %d %h %d %d %d\\n",
        reset, address, commitWrite, writeData,
        instruction_address, instruction_size, instruction_machine, instruction_kind,
        data_address, data_size, data_machine, data_kind);
      if (fields == 12) begin
        #1 $display("%0d %0d %08h %0d %0d", sample, implemented, readData,
          instruction_allowed, data_allowed);
        clock = 1;
        #1 clock = 0;
        sample = sample + 1;
      end else if (fields != -1) $fatal(1, "Incomplete PMP vector");
    end
    $fclose(file);
    $finish(0);
  end
endmodule
"""


class Reference:
    def __init__(self):
        self.configs = [0] * 16
        self.addresses = [0] * 16
        self.counts = Counter()

    def read(self, address):
        if 0x3A0 <= address <= 0x3A3:
            start = 4 * (address - 0x3A0)
            return True, sum(self.configs[start + lane] << (8 * lane) for lane in range(4))
        if 0x3B0 <= address <= 0x3BF:
            return True, self.addresses[address - 0x3B0]
        return False, 0

    def write(self, address, value):
        if 0x3A0 <= address <= 0x3A3:
            for lane in range(4):
                index = 4 * (address - 0x3A0) + lane
                if self.configs[index] & 128:
                    self.counts["lockedConfig"] += 1
                    continue
                raw = value >> (8 * lane) & 255
                legal = raw & 0x9F
                if not legal & 1:
                    legal &= ~2
                self.counts["warlConfig"] += int(raw != legal)
                self.configs[index] = legal
        elif 0x3B0 <= address <= 0x3BF:
            index = address - 0x3B0
            locked = bool(self.configs[index] & 128)
            previous = index < 15 and self.configs[index + 1] & 0x98 == 0x88
            self.counts["lockedAddress"] += locked
            self.counts["torPredecessor"] += previous
            if not locked and not previous:
                self.addresses[index] = value & ADDRESS_MASK
                self.counts["warlAddress"] += int(value > ADDRESS_MASK)
        else:
            self.counts["unknownWrite"] += 1

    def interval(self, index):
        mode = self.configs[index] >> 3 & 3
        value = self.addresses[index]
        if mode == 0:
            return 0, 0
        if mode == 1:
            return (self.addresses[index - 1] * 4 if index else 0), value * 4
        if mode == 2:
            return value * 4, value * 4 + 4
        ones = 0
        while value & (1 << ones):
            ones += 1
        size = 1 << (ones + 3)
        start = value * 4 // size * size
        return start, start + size

    def allowed(self, query):
        address, size, machine, kind = query
        assert 0 <= address < LIMIT and size in range(4) and machine in (0, 1) and kind in range(4)
        self.counts[f"kind{kind}"] += 1
        if size == 3 or kind == 3:
            self.counts["unsupportedQuery"] += 1
            return False
        if address + (1 << size) > LIMIT:
            self.counts["overflow"] += 1
            return False
        touched = tuple(range(address, address + (1 << size)))
        for index, config in enumerate(self.configs):
            start, end = self.interval(index)
            inside = [start <= byte < end for byte in touched]
            if not any(inside):
                continue
            self.counts[f"entry{index}"] += 1
            self.counts[f"mode{config >> 3 & 3}"] += 1
            if not all(inside):
                self.counts["partial"] += 1
                return False
            if machine and not config & 128:
                self.counts["machineBypass"] += 1
                return True
            permitted = bool(config & (1 << kind))
            self.counts["permissionAllow" if permitted else "permissionDeny"] += 1
            return permitted
        self.counts["machineNoMatch" if machine else "userNoMatch"] += 1
        return bool(machine)

    def step(self, row, cycle):
        reset, address, commit, value, *queries = row
        assert reset in (0, 1) and commit in (0, 1) and 0 <= address < 4096 and 0 <= value < LIMIT
        implemented, data = self.read(address)
        result = (cycle, int(implemented), data, int(self.allowed(queries[:4])), int(self.allowed(queries[4:])))
        if reset:
            self.configs, self.addresses = [0] * 16, [0] * 16
            self.counts["resets"] += 1
        elif commit:
            self.write(address, value)
        return result


def vectors(seed=0x3A0):
    rows, labels, packed = [], [], [0] * 4

    def add(label, address=0, value=0, commit=0, reset=0,
            instruction=(0, 0, 0, 0), data=(0xFFFFFFFF, 2, 1, 1)):
        rows.append((reset, address, commit, value, *instruction, *data))
        labels.append(label)

    def reset():
        packed[:] = [0] * 4
        add("reset", reset=1)

    def write(address, value):
        add("write", address, value, 1)
        add("readback", address)

    def config(index, value):
        group, lane = divmod(index, 4)
        packed[group] = (packed[group] & ~(255 << (8 * lane))) | (value << (8 * lane))
        write(0x3A0 + group, packed[group])

    reset()
    for address in range(4096):
        add("csr_decode", address, 0xFFFFFFFF)
    for address in (0, 0x39F, 0x3A4, 0x3AF, 0x3C0, 0xFFF):
        write(address, 0xFFFFFFFF)
    for index in range(16):
        for raw in range(256):
            reset()
            if index:
                write(0x3AF + index, 0x400)
            write(0x3B0 + index, 0x401)
            config(index, raw)
            add("permissions", 0x3A0 + index // 4,
                instruction=(0x1004, 0, (raw >> 5) & 1, raw % 3), data=(0x1002, 2, 1, raw % 3))
            write(0x3B0 + index, 0xFFFFFFFF)
            config(index, raw ^ 0x9F)
    for index in range(16):
        for mode in range(4):
            reset()
            write(0x3B0 + index, 0x400)
            if index:
                write(0x3AF + index, 0x200)
            config(index, 128 | (mode << 3) | 7)
            write(0x3B0 + index, 0x800)
            if index:
                write(0x3AF + index, 0x100)
                config(index - 1, 7)
            config(index, 0)
    for ones in range(31):
        for index in (0, 15):
            reset()
            size = 1 << (ones + 3)
            start = 0x80000000 if size <= 0x80000000 else 0
            write(0x3B0 + index, (start >> 2) | ((1 << ones) - 1))
            config(index, 0x9F)
            for address in (0, start, min(LIMIT - 1, start + size - 1),
                            (start - 1) & 0xFFFFFFFF, min(LIMIT - 1, start + size), 0xFFFFFFFC, 0xFFFFFFFF):
                for width in range(4):
                    for kind in range(4):
                        add("napot_boundaries", instruction=(address, width, 0, kind), data=(address, width, 1, kind))
    for first in range(15):
        for second in range(first + 1, 16):
            reset()
            write(0x3B0 + first, 0x401)
            write(0x3B0 + second, 0x403)
            config(first, 0x10)
            config(second, 0x1F)
            for address in (0x1000, 0x1002, 0x1004, 0x1007, 0x1008, 0x101F, 0x1020):
                for kind in range(3):
                    add("priority_overlap", instruction=(address, 2, 0, kind), data=(address, 2, 1, kind))
    for first, top in ((0, 0), (0, 4), (0x401, 0x400), (0x400, 0x400), (0x3FFFFFFE, 0x3FFFFFFF)):
        reset()
        write(0x3B0, first)
        write(0x3B1, top)
        config(1, 0x8F)
        for address in (0, 0x1000, 0xFFFFFFF8, 0xFFFFFFFB, 0xFFFFFFFC, 0xFFFFFFFF):
            for size in range(3):
                add("tor_boundaries", instruction=(address, size, 0, 0), data=(address, size, 1, 2))
    rng = random.Random(seed)
    for epoch in range(32):
        reset()
        for index in range(16):
            write(0x3B0 + index, rng.choice((rng.randrange(1024), rng.randrange(1 << 32))))
            config(index, rng.randrange(128))
        for _ in range(256):
            query = lambda: (rng.choice((rng.randrange(4096), rng.randrange(LIMIT))),
                             rng.randrange(4), rng.randrange(2), rng.randrange(4))
            add("random", rng.choice((*range(0x3A0, 0x3A4), *range(0x3B0, 0x3C0), 0x300)),
                rng.randrange(LIMIT), int(rng.randrange(3) == 0), instruction=query(), data=query())
    add("reset_priority", 0x3A0, 0xFFFFFFFF, commit=1, reset=1)
    for address in (*range(0x3A0, 0x3A4), *range(0x3B0, 0x3C0)):
        add("reset_readback", address)
    return rows, labels


def check(rows, trace):
    lines = [line.split() for line in trace.splitlines()]
    assert len(lines) == len(rows), "PMP sample count differs"
    model = Reference()
    for cycle, (row, fields) in enumerate(zip(rows, lines, strict=True)):
        assert len(fields) == 5, "Invalid PMP observation width"
        actual = tuple(int(value, 16 if index == 2 else 10) for index, value in enumerate(fields))
        expected = model.step(row, cycle)
        assert actual == expected, f"PMP mismatch at cycle {cycle}: expected {expected}, observed {actual}"
    return dict(sorted(model.counts.items()))


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def build(output):
    names = ["ditdah_e2/src/Parameters.scala", "ditdah_e2/src/Interfaces.scala", "ditdah_e2/src/Pmp.scala",
             "ditdah_e2/src/PmpInterfaces.scala", "test/pmp.py", "test/test_pmp.py", "flake.nix", "flake.lock"]
    names += [str(path.relative_to(ROOT)) for path in sorted((ROOT / "nix").glob("*.nix"))]
    contents = {name: (ROOT / name).read_bytes() for name in names}
    for name, value in contents.items():
        path = output / "inputs" / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(value)
    generated = output / "inputs/generated"
    generated.mkdir()
    (generated / "Top.scala").write_text(WRAPPER)
    (generated / "pmp_tb.sv").write_text(HARNESS)
    (generated / "parameters.json").write_text("{}\n")
    tool_hashes = {name: digest(Path(shutil.which(name))) for name in
                   ("elaborate-ditdah-e2", "firld", "firtool", "iverilog", "vvp")}
    commands = []
    scratch = "/data/tmp" if os.access("/data/tmp", os.W_OK) else None
    with tempfile.TemporaryDirectory(prefix="ditdah-e2-pmp-build-", dir=scratch) as directory:
        work = Path(directory)
        (work / "src").mkdir()
        for name, value in contents.items():
            if name.endswith(".scala"):
                (work / "src" / Path(name).name).write_bytes(value)
        shutil.copyfile(generated / "Top.scala", work / "src/Top.scala")
        shutil.copyfile(generated / "parameters.json", work / "parameters.json")
        environment = dict(os.environ, DITDAH_E2_SOURCE=str(work / "src"))
        stages = [["elaborate-ditdah-e2", "design", "parameters.json"]]
        for stage in range(3):
            if stage == 1:
                stages.append(["firld", *[path.name for path in sorted(work.glob("*.mlirbc"))], "--base-circuit",
                               "DitDahE2PmpTest", "--no-mangle", "--emit-bytecode", "-o", "linked.mlirbc"])
            elif stage == 2:
                stages.append(["firtool", "linked.mlirbc", "--split-verilog", "-disable-all-randomization",
                               "--lowering-options=noAlwaysComb,disallowLocalVariables,locationInfoStyle=none", "-o", "rtl"])
            result = subprocess.run(stages[stage], cwd=work, env=environment, capture_output=True, text=True)
            commands.append({"argv": stages[stage], "exitStatus": result.returncode})
            log = re.sub(r"\x1b\[[0-9;]*m", "", result.stdout + result.stderr).replace(str(work), "<work>")
            (output / f"build-{stage}.log").write_text(log)
            assert result.returncode == 0, f"PMP generation failed at command {stage}"
        shutil.copytree(work / "rtl", output / "rtl")
    assert all((ROOT / name).read_bytes() == value for name, value in contents.items()), "PMP source changed"
    report = {"exitStatus": 0, "parameters": {}, "specification": SPECIFICATION, "commands": commands,
              "inputHashes": {name: hashlib.sha256(value).hexdigest() for name, value in contents.items()},
              "generatedHashes": {path.name: digest(path) for path in generated.iterdir()},
              "rtlHashes": {path.name: digest(path) for path in (output / "rtl").glob("*.sv")},
              "toolHashes": tool_hashes,
              "firtool": subprocess.check_output(["firtool", "--version"], text=True).strip()}
    (output / "build.json").write_text(json.dumps(report, indent=2) + "\n")
    return report


def simulate(output, rows, rtl):
    output.mkdir(parents=True)
    (output / "vectors.txt").write_text("".join(" ".join(f"{value:x}" if index in (1, 3, 4, 8) else str(value)
                                                         for index, value in enumerate(row)) + "\n" for row in rows))
    (output / "pmp_tb.sv").write_text(HARNESS)
    shutil.copyfile(rtl, output / "DitDahE2Pmp.sv")
    commands = []
    for command in (["iverilog", "-g2012", "-s", "PmpBench", "-o", "pmp-sim", "DitDahE2Pmp.sv", "pmp_tb.sv"],
                    ["vvp", "pmp-sim"]):
        result = subprocess.run(command, cwd=output, capture_output=True, text=True)
        commands.append({"argv": command, "exitStatus": result.returncode})
        (output / f"command-{len(commands)}.log").write_text(result.stdout + result.stderr)
        assert result.returncode == 0, "PMP simulation failed"
    trace = "\n".join(line for line in result.stdout.splitlines() if line and line[0].isdigit()) + "\n"
    (output / "pmp.trace").write_text(trace)
    (output / "commands.json").write_text(json.dumps(commands, indent=2) + "\n")
    return trace


def partial_match_mutant(content):
    pattern = r"(assign\s+data_allowed\s*=\s*)([^;]+)(;)"
    assert len(re.findall(pattern, content)) == 1, "PMP output mutation no longer matches RTL"
    return re.sub(pattern, r"\1(\2) | (data_machine & (data_address == 32'h1002) & (data_size == 2))\3", content)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=Path("result/pmp"))
    args = parser.parse_args()
    assert not args.output.exists() or not any(args.output.iterdir()), "PMP output must be empty"
    report = build(args.output)
    rows, labels = vectors()
    trace = simulate(args.output / "normal", rows, args.output / "rtl/DitDahE2Pmp.sv")
    counts = check(rows, trace)
    required = ("lockedConfig", "lockedAddress", "torPredecessor", "warlConfig", "warlAddress", "overflow",
                "unsupportedQuery", "partial", "machineBypass", "permissionAllow", "permissionDeny",
                "machineNoMatch", "userNoMatch", *[f"entry{index}" for index in range(16)], "mode1", "mode2", "mode3")
    assert all(counts.get(name, 0) > 0 for name in required), "Missing PMP coverage"
    mutant = args.output / "partial-match-mutant.sv"
    mutant.write_text(partial_match_mutant((args.output / "rtl/DitDahE2Pmp.sv").read_text()))
    changed = simulate(args.output / "partial-match", rows, mutant)
    reference = Reference()
    expected = [reference.step(row, cycle) for cycle, row in enumerate(rows)]
    observed = [tuple(int(value, 16 if index == 2 else 10) for index, value in enumerate(line.split()))
                for line in changed.splitlines()]
    witness = next((cycle for cycle, (wanted, actual) in enumerate(zip(expected, observed, strict=True))
                    if wanted[4] == 0 and actual[4] == 1 and rows[cycle][8:11] == (0x1002, 2, 1)), None)
    assert witness is not None, "PMP mutant did not allow a denied M operation"
    try:
        check(rows, changed)
    except AssertionError as error:
        reason = str(error)
        assert reason.startswith("PMP mismatch"), reason
    else:
        raise AssertionError("PMP checker accepted a partial access bypass")
    assert all(digest(ROOT / name) == value for name, value in report["inputHashes"].items()), "PMP source changed"
    (args.output / "labels.json").write_text(json.dumps(labels) + "\n")
    summary = {"scope": "standalone sixteen-entry RV32 PMP CSR bank and two permission queries", "exitStatus": 0,
               "buildHash": digest(args.output / "build.json"), "cycles": len(rows), "queries": 2 * len(rows),
               "coverage": counts, "traceHash": digest(args.output / "normal/pmp.trace"),
               "vectorsHash": digest(args.output / "normal/vectors.txt"), "labelsHash": digest(args.output / "labels.json"),
               "negativeControls": [{"name": "partial M access bypass", "cycle": witness, "reason": reason,
                                     "rtlHash": digest(mutant), "traceHash": digest(args.output / "partial-match/pmp.trace")}],
               "excluded": ["CPU privilege integration", "transaction cancellation", "formal proof"]}
    (args.output / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    print(f"PASS: {len(rows)} PMP cycles and one RTL negative control")


if __name__ == "__main__":
    main()
