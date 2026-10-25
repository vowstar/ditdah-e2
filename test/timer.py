# SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
# SPDX-License-Identifier: MIT
"""Check timer register transactions, coherent reads and interrupt levels."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import random
import shutil
import subprocess
import tempfile


MASK64 = (1 << 64) - 1
FIELDS = ("reset", "tick", "valid", "ready", "address", "write", "data", "mask", "size")
WRAPPER = """// SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
// SPDX-License-Identifier: MIT
package ditdah_e2
import me.jiuyang.zaozi.*
import me.jiuyang.zaozi.default.{*, given}
import me.jiuyang.zaozi.reftpe.*
import me.jiuyang.zaozi.valuetpe.*
@generator
object DitDahE2 extends Generator[Parameters, UnitLayers, MachineTimerIO, UnitProbe]:
  override def moduleName(p: Parameters): String = "DitDahE2TimerTest"
  def architecture(p: Parameters) =
    val io = summon[Interface[MachineTimerIO]]
    val timer = MachineTimer.instantiate(p)
    timer.io.clock := io.clock
    timer.io.reset := io.reset
    timer.io.tick := io.tick
    timer.io.memory :<>= io.memory
    io.timeValue := timer.io.timeValue
    io.timerInterrupt := timer.io.timerInterrupt
    io.softwareInterrupt := timer.io.softwareInterrupt
"""
HARNESS = """// SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
// SPDX-License-Identifier: MIT
module TimerBench;
  reg clock = 0;
  reg reset, tick, memory_request_valid, memory_response_ready;
  wire memory_request_bits_machine = 1;
  reg memory_request_bits_write;
  reg [31:0] memory_request_bits_address, memory_request_bits_data;
  reg [3:0] memory_request_bits_mask;
  reg [1:0] memory_request_bits_size;
  wire memory_request_ready, memory_response_valid, memory_response_bits_fault;
  wire [31:0] memory_response_bits_data;
  wire [63:0] timeValue;
  wire timerInterrupt, softwareInterrupt;
  integer file, fields, sample = 0;
  DitDahE2MachineTimer dut(.*);
  initial begin
    file = $fopen("vectors.txt", "r");
    if (!file) $fatal(1, "Cannot open timer vectors");
    while (!$feof(file)) begin
      clock = 0;
      fields = $fscanf(file, "%d %d %d %d %h %d %h %h %d\\n",
        reset, tick, memory_request_valid, memory_response_ready,
        memory_request_bits_address, memory_request_bits_write,
        memory_request_bits_data, memory_request_bits_mask, memory_request_bits_size);
      if (fields == 9) begin
        #1 clock = 1;
        #1 $display("%0d %0d %0d %08h %0d %016h %0d %0d", sample,
          memory_request_ready, memory_response_valid,
          memory_response_valid ? memory_response_bits_data : 0,
          memory_response_valid ? memory_response_bits_fault : 0,
          timeValue, timerInterrupt, softwareInterrupt);
        sample = sample + 1;
      end else if (fields != -1) $fatal(1, "Incomplete timer vector");
    end
    $fclose(file);
    $finish(0);
  end
endmodule
"""


def vectors():
    transactions = []

    def access(address, value=None, *, mask=None, size=2):
        write = value is not None
        transactions.append((address, int(write), value or 0,
                             (15 if write else 0) if mask is None else mask, size))

    for address in (0, 4, 8, 12, 16):
        access(address)
    access(12, 0)
    access(8, 10)
    access(0, 20)
    access(8, 1000)
    for value in (0, 1, 2, 0xFFFFFFFF):
        access(16, value)
        access(16)
    access(4, 0x12345678)
    access(0, 0xFFFFFFFF)
    for address in (4, 0, 4):
        access(address)
    access(4, 0xFFFFFFFF)
    access(0, 0xFFFFFFFF)
    for address in (4, 0, 4):
        access(address)
    for address in (0, 4, 8, 12, 16):
        for size in (0, 1, 3):
            access(address, 0xBAD0CAFE, size=size)
        for mask in (0, 1, 3, 7, 14):
            access(address, 0xBAD0CAFE, mask=mask)
        access(address, mask=15)
        access(address)
    for address in (1, 2, 3, 20, 0x10001000, 0xFFFFFFFF):
        access(address, 1)
        access(address)
    rng = random.Random(0x7100)
    for _ in range(1024):
        address = rng.choice((0, 4, 8, 12, 16, 20, 1))
        access(address, rng.randrange(1 << 32) if rng.randrange(2) else None)
    rows = [(1, 1, 1, 0, 0, 1, 0xDEADBEEF, 15, 2)]
    pending, index, cycle = False, 0, 0
    while index < len(transactions) or pending:
        ready = int(cycle % 9 == 8 or rng.randrange(4) == 0)
        valid = index < len(transactions)
        transaction = transactions[index] if valid else (0, 0, 0, 0, 2)
        rows.append((0, int(rng.randrange(3) != 0), int(valid), ready, *transaction))
        if not pending and valid:
            pending = True
            index += 1
        elif pending and ready:
            pending = False
        cycle += 1
    rows.append((0, 0, 0, 1, 0, 0, 0, 0, 2))
    return rows


def expected(rows):
    time, compare, software, pending, data, fault = 0, MASK64, 0, False, 0, False
    result, counts = [], {"requests": 0, "faults": 0, "blockedResponses": 0,
                          "timeWritesWithTick": 0, "timerTransitions": 0, "softwareTransitions": 0}
    for index, row in enumerate(rows):
        reset, tick, valid, ready, address, write, value, mask, size = row
        previous_timer, previous_software = time >= compare, software
        if reset:
            time, compare, software, pending = 0, MASK64, 0, False
        else:
            before = time
            time = (time + tick) & MASK64
            if pending:
                counts["blockedResponses"] += int(not ready)
                if ready:
                    pending = False
            elif valid:
                values = {0: before & 0xFFFFFFFF, 4: before >> 32,
                          8: compare & 0xFFFFFFFF, 12: compare >> 32, 16: software}
                fault = address not in values or size != 2 or mask != (15 if write else 0)
                data = values.get(address, 0) if not write and not fault else 0
                pending = True
                counts["requests"] += 1
                counts["faults"] += int(fault)
                if write and not fault:
                    if address in (0, 4):
                        upper, lower = divmod(before, 1 << 32)
                        time = (value << 32) | lower if address == 4 else (upper << 32) | value
                        counts["timeWritesWithTick"] += tick
                    elif address in (8, 12):
                        upper, lower = divmod(compare, 1 << 32)
                        compare = (value << 32) | lower if address == 12 else (upper << 32) | value
                    else:
                        software = value & 1
            counts["timerTransitions"] += int(previous_timer != (time >= compare))
            counts["softwareTransitions"] += int(previous_software != software)
        result.append((index, int(not pending), int(pending), data if pending else 0,
                       int(fault) if pending else 0, time, int(time >= compare), software))
    return result, counts


def check(rows, trace):
    target, counts = expected(rows)
    lines = trace.splitlines()
    if len(lines) != len(target):
        raise AssertionError("Timer sample count mismatch")
    for wanted, line in zip(target, lines, strict=True):
        fields = line.split()
        actual = tuple(int(value, 16 if index in (3, 5) else 10) for index, value in enumerate(fields))
        if actual != wanted:
            raise AssertionError(f"Timer transaction mismatch at cycle {wanted[0]}")
    return counts


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=Path("result/timer"))
    args = parser.parse_args()
    names = ["ditdah_e2/src/Parameters.scala", "ditdah_e2/src/Interfaces.scala",
             "ditdah_e2/src/MachineTimer.scala", "test/timer.py", "flake.nix", "flake.lock"]
    names += [str(path) for path in sorted(Path("nix").glob("*.nix"))]
    contents = {name: Path(name).read_bytes() for name in names}
    args.output.mkdir(parents=True, exist_ok=True)
    for name, value in contents.items():
        path = args.output / "inputs" / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(value)
    scratch = "/data/tmp" if os.access("/data/tmp", os.W_OK) else None
    commands = []
    with tempfile.TemporaryDirectory(prefix="ditdah-e2-timer-", dir=scratch) as directory:
        work = Path(directory)
        (work / "src").mkdir()
        for name, value in contents.items():
            if name.endswith(".scala"):
                (work / "src" / Path(name).name).write_bytes(value)
        (work / "src/Top.scala").write_text(WRAPPER)
        (work / "parameters.json").write_text("{}\n")
        (work / "timer_tb.sv").write_text(HARNESS)
        for name in ("parameters.json", "timer_tb.sv", "src/Top.scala"):
            target = args.output / "inputs/generated" / name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(work / name, target)
        environment = dict(os.environ, DITDAH_E2_SOURCE=str(work / "src"))

        def run(command):
            process = subprocess.run(command, cwd=work, env=environment, capture_output=True, text=True)
            commands.append({"argv": command, "exitStatus": process.returncode})
            if process.returncode:
                raise RuntimeError(process.stdout + process.stderr)
            return process.stdout

        run(["elaborate-ditdah-e2", "design", "parameters.json"])
        run(["firld", *[path.name for path in sorted(work.glob("*.mlirbc"))], "--base-circuit",
             "DitDahE2TimerTest", "--no-mangle", "--emit-bytecode", "-o", "linked.mlirbc"])
        run(["firtool", "linked.mlirbc", "--split-verilog", "-disable-all-randomization",
             "--lowering-options=noAlwaysComb,disallowLocalVariables,locationInfoStyle=none", "-o", "rtl"])
        rows = vectors()
        text = "".join(" ".join(f"{value:x}" if index in (4, 6, 7) else str(value)
                               for index, value in enumerate(row)) + "\n" for row in rows)
        (work / "vectors.txt").write_text(text)
        (args.output / "vectors.txt").write_text(text)
        run(["iverilog", "-g2012", "-s", "TimerBench", "-o", "timer-sim",
             "rtl/DitDahE2MachineTimer.sv", "timer_tb.sv"])
        trace = run(["vvp", "timer-sim"])
        trace = "\n".join(line for line in trace.splitlines() if line and line[0].isdigit()) + "\n"
        counts = check(rows, trace)
        assert all(counts.values()), "Missing timer behavior coverage"
        (args.output / "timer.trace").write_text(trace)
        controls = 0
        for field, wanted in ((4, "1"), (6, "1"), (7, "1")):
            lines = trace.splitlines()
            index = next(index for index, line in enumerate(lines) if line.split()[field] == wanted)
            values = lines[index].split()
            values[field] = "0"
            lines[index] = " ".join(values)
            try:
                check(rows, "\n".join(lines))
            except AssertionError:
                controls += 1
            else:
                raise AssertionError("Timer checker accepted a changed fault or interrupt")
        shutil.copytree(work / "rtl", args.output / "rtl", dirs_exist_ok=True)
    assert all(Path(name).read_bytes() == value for name, value in contents.items()), "Timer inputs changed"
    report = {"scope": "native timer endpoint with external synchronous ticks", "exitStatus": 0,
              "command": "python3 test/timer.py", "commands": commands, "cycles": len(rows), **counts,
              "negativeControls": controls, "inputHashes": {name: hashlib.sha256(value).hexdigest() for name, value in contents.items()},
              "generatedHashes": {str(path.relative_to(args.output / "inputs")): digest(path)
                                  for path in (args.output / "inputs/generated").rglob("*") if path.is_file()},
              "rtlHashes": {path.name: digest(path) for path in (args.output / "rtl").glob("*.sv")},
              "traceHash": digest(args.output / "timer.trace"), "vectorsHash": digest(args.output / "vectors.txt"),
              "toolHashes": {name: digest(Path(shutil.which(name)).resolve()) for name in
                             ("elaborate-ditdah-e2", "firld", "firtool", "iverilog", "vvp")},
              "tools": {name: subprocess.check_output(command, text=True, stderr=subprocess.STDOUT).strip()
                        for name, command in {"firtool": ["firtool", "--version"], "iverilog": ["iverilog", "-V"]}.items()},
              "excluded": ["timer tick generation", "CPU integration", "clock domain crossing", "formal proof"]}
    (args.output / "summary.json").write_text(json.dumps(report, indent=2) + "\n")
    print(f"PASS: {len(rows)} timer cycles, {counts['requests']} requests and {controls} semantic negative controls")


if __name__ == "__main__":
    main()
