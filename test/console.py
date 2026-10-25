# SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
# SPDX-License-Identifier: MIT
"""Check console transaction ownership, transmitted bytes and status snapshots."""

import argparse
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
FIELDS = ("reset", "valid", "response_ready", "transmit_ready", "address", "write", "data", "mask", "size")
WRAPPER = """// SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
// SPDX-License-Identifier: MIT
package ditdah_e2
import me.jiuyang.zaozi.*
import me.jiuyang.zaozi.default.{*, given}
import me.jiuyang.zaozi.reftpe.*
import me.jiuyang.zaozi.valuetpe.*
@generator
object DitDahE2 extends Generator[Parameters, UnitLayers, ConsoleIO, UnitProbe]:
  override def moduleName(p: Parameters): String = "DitDahE2ConsoleTest"
  def architecture(p: Parameters) =
    val io = summon[Interface[ConsoleIO]]
    val console = Console.instantiate(p)
    console.io.clock := io.clock
    console.io.reset := io.reset
    console.io.memory :<>= io.memory
    io.transmit :<>= console.io.transmit
"""
HARNESS = """// SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
// SPDX-License-Identifier: MIT
module ConsoleBench;
  reg clock = 0, reset = 1;
  reg memory_request_valid = 0, memory_response_ready = 0, transmit_ready = 0;
  wire memory_request_bits_machine = 1;
  wire [3:0] memory_request_bits_operation = 0;
  reg memory_request_bits_write = 0;
  reg [31:0] memory_request_bits_address = 0, memory_request_bits_data = 0;
  reg [3:0] memory_request_bits_mask = 0;
  reg [1:0] memory_request_bits_size = 2;
  wire memory_request_ready, memory_response_valid, memory_response_bits_fault;
  wire [31:0] memory_response_bits_data;
  wire transmit_valid;
  wire [7:0] transmit_bits;
  integer file, fields, sample = 0;
  DitDahE2Console dut(.*);
  initial begin
    #1 clock = 1;
    #1 clock = 0;
    file = $fopen("vectors.txt", "r");
    if (!file) $fatal(1, "Cannot open console vectors");
    while (!$feof(file)) begin
      fields = $fscanf(file, "%d %d %d %d %h %d %h %h %d\\n", reset,
        memory_request_valid, memory_response_ready, transmit_ready,
        memory_request_bits_address, memory_request_bits_write,
        memory_request_bits_data, memory_request_bits_mask, memory_request_bits_size);
      if (fields == 9) begin
        #1 $display("%0d %0d %0d %08h %0d %0d %02h", sample,
          memory_request_ready, memory_response_valid,
          memory_response_valid ? memory_response_bits_data : 0,
          memory_response_valid ? memory_response_bits_fault : 0,
          transmit_valid, transmit_valid ? transmit_bits : 0);
        clock = 1;
        #1 clock = 0;
        sample = sample + 1;
      end else if (fields != -1) $fatal(1, "Incomplete console vector");
    end
    $fclose(file);
    $finish(0);
  end
endmodule
"""


class Reference:
    def __init__(self):
        self.owner = None
        self.held = None
        self.bytes = []
        self.counts = dict.fromkeys(("requests", "responses", "writes", "faults", "statusZero", "statusOne",
                                    "blockedRequests", "blockedResponses", "blockedTransmit", "statusReadyChanges"), 0)

    def step(self, row, cycle):
        if len(row) != 9:
            raise AssertionError("Invalid console stimulus width")
        reset, valid, ready, tx_ready, address, write, value, mask, size = row
        if any(value not in (0, 1) for value in (reset, valid, ready, tx_ready, write)) or not (
                0 <= address < 1 << 32 and 0 <= value < 1 << 32 and 0 <= mask < 16 and 0 <= size < 4):
            raise AssertionError("Invalid console stimulus value")
        request = (address, write, value, mask, size)
        if self.held is not None and (not valid or request != self.held):
            raise AssertionError("Console request changed under backpressure")
        owner = self.owner
        if reset and (owner is not None or valid or self.held is not None):
            raise AssertionError("Console reset requires no offered or pending transaction")
        response = owner is not None and (owner["kind"] != "write" or owner["sent"] is not None)
        transmit = owner is not None and owner["kind"] == "write" and owner["sent"] is None
        output = (cycle, int(owner is None), int(response), owner["data"] if response else 0,
                  int(owner["kind"] == "fault") if response else 0, int(transmit), owner["byte"] if transmit else 0)
        self.held = request if valid and owner is not None else None
        if reset:
            return output
        self.counts["blockedRequests"] += int(valid and owner is not None)
        self.counts["blockedResponses"] += int(response and not ready)
        self.counts["blockedTransmit"] += int(transmit and not tx_ready)
        if owner is None and valid:
            kind = "write" if request[0:2] == (0, 1) and mask == 15 and size == 2 else \
                   "status" if request[0:2] == (4, 0) and mask == 0 and size == 2 else "fault"
            self.owner = {"kind": kind, "byte": value & 255, "data": tx_ready if kind == "status" else 0,
                          "accepted": cycle, "sent": None}
            self.counts["requests"] += 1
            self.counts["writes"] += int(kind == "write")
            self.counts["faults"] += int(kind == "fault")
            if kind == "status":
                self.counts["statusOne" if tx_ready else "statusZero"] += 1
        elif transmit and tx_ready:
            self.bytes.append(owner["byte"])
            owner["sent"] = cycle
        elif response:
            if owner["kind"] == "status" and tx_ready != owner["data"]:
                self.counts["statusReadyChanges"] += 1
            if ready:
                self.counts["responses"] += 1
                self.owner = None
        return output


def vectors(seed=1):
    rng = random.Random(seed)
    transactions = [((0, 1, byte, 15, 2), None) for byte in b"E2\n"]
    transactions += [((0, 1, rng.getrandbits(24) << 8 | byte, 15, 2), None) for byte in range(256)]
    transactions += [((4, 0, 0, 0, 2), ready) for ready in (0, 1)]
    for address in (0, 4, 1, 2, 3, 8, 0x10000000, 0xFFFFFFFF):
        for write in (0, 1):
            for size in range(4):
                for mask in range(16):
                    transactions.append(((address, write, rng.getrandbits(32), mask, size), None))
    for _ in range(1024):
        choice = rng.randrange(5)
        request = (0, 1, rng.getrandbits(32), 15, 2) if choice < 3 else \
                  (4, 0, 0, 0, 2) if choice == 3 else \
                  (rng.choice((0, 4, 3, 8)), rng.randrange(2), rng.getrandbits(32), rng.randrange(16), rng.randrange(4))
        transactions.append((request, None))
    rows = [(1, 0, 0, 0, 0, 0, 0, 0, 2)]
    reference = Reference()
    reference.step(rows[0], 0)
    offered, index, cycle = None, 0, 1
    while index < len(transactions) or offered is not None or reference.owner is not None:
        if offered is None and index < len(transactions) and rng.randrange(4):
            offered = transactions[index]
        owner = reference.owner
        ready = int(cycle % 13 == 12 or rng.randrange(4) == 0)
        tx_ready = int(cycle % 11 == 10 or rng.randrange(4) == 0)
        if owner is not None:
            age = cycle - owner["accepted"]
            if owner["kind"] == "write" and age <= 4:
                tx_ready = 0
            if owner["kind"] == "status" and age <= 3:
                ready, tx_ready = 0, 1 - owner["data"]
            if owner["kind"] == "fault":
                tx_ready = 1
        elif offered is not None and offered[1] is not None:
            tx_ready = offered[1]
        request = offered[0] if offered is not None else (0, 0, 0, 0, 2)
        row = (0, int(offered is not None), ready, tx_ready, *request)
        output = reference.step(row, cycle)
        rows.append(row)
        if offered is not None and output[1]:
            index += 1
            offered = None
        cycle += 1
        if cycle > 200000:
            raise AssertionError("Console stimulus did not drain")
    rows.extend([(0, 0, 1, 1, 0, 0, 0, 0, 2)] * 2)
    return rows


def expected(rows):
    reference = Reference()
    outputs = [reference.step(row, cycle) for cycle, row in enumerate(rows)]
    counts = reference.counts | {"transmitted": len(reference.bytes), "bytes": reference.bytes,
                                 "pending": int(reference.owner is not None)}
    return outputs, counts


def parse_trace(trace):
    result = []
    for line in trace.splitlines():
        fields = line.split()
        if len(fields) != 7:
            raise AssertionError("Console trace field count mismatch")
        result.append(tuple(int(value, 16 if index in (3, 6) else 10) for index, value in enumerate(fields)))
    return result


def check(rows, trace):
    wanted, counts = expected(rows)
    observed = parse_trace(trace)
    if len(observed) != len(wanted):
        raise AssertionError("Console sample count mismatch")
    for row, actual, target in zip(rows, observed, wanted, strict=True):
        if actual[5] and row[3] and not target[5]:
            raise AssertionError(f"Unexpected console byte at cycle {target[0]}")
        if actual != target:
            raise AssertionError(f"Console transaction mismatch at cycle {target[0]}")
    if counts["pending"] or counts["requests"] != counts["responses"] or counts["writes"] != counts["transmitted"]:
        raise AssertionError("Console transactions did not complete")
    return counts


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def build(output):
    output = Path(output)
    names = ["ditdah_e2/src/Parameters.scala", "ditdah_e2/src/Interfaces.scala", "ditdah_e2/src/Console.scala",
             "test/console.py", "test/test_console.py", "flake.nix", "flake.lock"]
    names += [str(path.relative_to(ROOT)) for path in sorted((ROOT / "nix").glob("*.nix"))]
    contents = {name: (ROOT / name).read_bytes() for name in names}
    for name, value in contents.items():
        path = output / "inputs" / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(value)
    tools = {name: Path(shutil.which(name)).resolve() for name in
             ("elaborate-ditdah-e2", "firld", "firtool", "iverilog", "vvp")}
    tool_hashes = {name: digest(path) for name, path in tools.items()}
    scratch = "/data/tmp" if os.access("/data/tmp", os.W_OK) else None
    commands = []
    with tempfile.TemporaryDirectory(prefix="ditdah-e2-console-build-", dir=scratch) as directory:
        work = Path(directory)
        (work / "src").mkdir()
        for name, value in contents.items():
            if name.endswith(".scala"):
                (work / "src" / Path(name).name).write_bytes(value)
        (work / "src/Top.scala").write_text(WRAPPER)
        (work / "parameters.json").write_text("{}\n")
        (work / "console_tb.sv").write_text(HARNESS)
        for name in ("parameters.json", "console_tb.sv", "src/Top.scala"):
            target = output / "inputs/generated" / name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(work / name, target)
        environment = dict(os.environ, DITDAH_E2_SOURCE=str(work / "src"))

        def run(command):
            result = subprocess.run(command, cwd=work, env=environment, capture_output=True, text=True)
            commands.append({"argv": command, "exitStatus": result.returncode})
            if result.returncode:
                raise RuntimeError(result.stdout + result.stderr)

        run(["elaborate-ditdah-e2", "design", "parameters.json"])
        run(["firld", *[path.name for path in sorted(work.glob("*.mlirbc"))], "--base-circuit", "DitDahE2ConsoleTest",
             "--no-mangle", "--emit-bytecode", "-o", "linked.mlirbc"])
        run(["firtool", "linked.mlirbc", "--split-verilog", "-disable-all-randomization",
             "--lowering-options=noAlwaysComb,disallowLocalVariables,locationInfoStyle=none", "-o", "rtl"])
        shutil.copytree(work / "rtl", output / "rtl", dirs_exist_ok=True)
    assert all((ROOT / name).read_bytes() == value for name, value in contents.items()), "Console inputs changed"
    report = {"exitStatus": 0, "parameters": {}, "commands": commands,
              "inputHashes": {name: hashlib.sha256(value).hexdigest() for name, value in contents.items()},
              "generatedHashes": {str(path.relative_to(output / "inputs")): digest(path)
                                  for path in (output / "inputs/generated").rglob("*") if path.is_file()},
              "rtlHashes": {path.name: digest(path) for path in (output / "rtl").glob("*.sv")},
              "toolHashes": tool_hashes,
              "tools": {name: subprocess.check_output(command, text=True, stderr=subprocess.STDOUT).strip()
                        for name, command in {"firtool": ["firtool", "--version"], "iverilog": ["iverilog", "-V"]}.items()}}
    (output / "build.json").write_text(json.dumps(report, indent=2) + "\n")
    return report


def simulate(output, rows, rtl, commands):
    output.mkdir(parents=True, exist_ok=True)
    text = "".join(" ".join(f"{value:x}" if index in (4, 6, 7) else str(value)
                            for index, value in enumerate(row)) + "\n" for row in rows)
    (output / "vectors.txt").write_text(text)
    (output / "console_tb.sv").write_text(HARNESS)
    shutil.copyfile(rtl, output / "DitDahE2Console.sv")
    for command in (["iverilog", "-g2012", "-s", "ConsoleBench", "-o", "console-sim", "DitDahE2Console.sv", "console_tb.sv"],
                    ["vvp", "console-sim"]):
        result = subprocess.run(command, cwd=output, capture_output=True, text=True)
        commands.append({"directory": output.name, "argv": command, "exitStatus": result.returncode})
        if result.returncode:
            raise RuntimeError(result.stdout + result.stderr)
    (output / "simulation.log").write_text(result.stdout)
    trace = "\n".join(line for line in result.stdout.splitlines() if line and line[0].isdigit()) + "\n"
    (output / "console.trace").write_text(trace)
    return trace


def fault_byte_mutant(rtl):
    pattern = r"(assign\s+transmit_valid\s*=\s*)([^;]+)(;)"
    if len(re.findall(pattern, rtl)) != 1:
        raise ValueError("Console transmit assignment changed")
    return re.sub(pattern, r"\1(\2) | (memory_response_valid & memory_response_bits_fault)\3", rtl)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=Path("result/console"))
    args = parser.parse_args()
    report = build(args.output)
    commands, runs = [], []
    for seed in (1, 19, 83):
        rows = vectors(seed)
        directory = args.output / f"seed-{seed}"
        trace = simulate(directory, rows, args.output / "rtl/DitDahE2Console.sv", commands)
        counts = check(rows, trace)
        assert bytes(counts.pop("bytes"))[:259] == b"E2\n" + bytes(range(256)), "Missing fixed console byte stream"
        for name in ("faults", "blockedRequests", "blockedResponses", "blockedTransmit", "statusZero", "statusOne", "statusReadyChanges"):
            assert counts[name], f"Missing console coverage: {name}"
        runs.append({"seed": seed, "cycles": len(rows), **counts, "traceHash": digest(directory / "console.trace"),
                     "vectorsHash": digest(directory / "vectors.txt")})
    rows = vectors(1)
    mutant = args.output / "fault-byte-mutant.sv"
    mutant.write_text(fault_byte_mutant((args.output / "rtl/DitDahE2Console.sv").read_text()))
    trace = simulate(args.output / "fault-byte", rows, mutant, commands)
    target, _ = expected(rows)
    actual = parse_trace(trace)
    witness = next((index for index, (row, wanted, observed) in enumerate(zip(rows, target, actual, strict=True))
                    if row[3] and observed[5] and not wanted[5] and wanted[2] and wanted[4]), None)
    assert witness is not None, "Mutant did not transfer a byte for a faulting transaction"
    try:
        check(rows, trace)
    except AssertionError as error:
        reason = str(error)
        assert reason.startswith("Unexpected console byte"), reason
    else:
        raise AssertionError("Console checker accepted a failed access byte")
    control = {"mutation": "transmit during fault response", "exitStatus": 0, "cycle": witness,
               "byte": actual[witness][6], "rejected": reason, "rtlHash": digest(mutant),
               "traceHash": digest(args.output / "fault-byte/console.trace")}
    assert all(digest(ROOT / name) == value for name, value in report["inputHashes"].items()), "Console inputs changed"
    assert all(digest(args.output / "rtl" / name) == value for name, value in report["rtlHashes"].items()), "Console RTL changed"
    summary = {"scope": "native console endpoint and ready/valid byte output", "exitStatus": 0,
               "command": "python3 test/console.py", "buildHash": digest(args.output / "build.json"),
               "commands": commands, "runs": runs, "negativeControls": [control],
               "excluded": ["CPU integration", "UART serialization", "clock domain crossing", "formal proof"]}
    (args.output / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    print(f"PASS: {sum(run['cycles'] for run in runs)} console cycles, {sum(run['requests'] for run in runs)} requests and one RTL negative control")


if __name__ == "__main__":
    main()
