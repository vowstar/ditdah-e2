# SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
# SPDX-License-Identifier: MIT
"""Check shared atomic SRAM against an independent arbitration history."""

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
MASK = 0xFFFFFFFF
PORTS = ("instruction", "data", "debug", "competitor")
FIELDS = (("address", 32), ("machine", 1), ("write", 1), ("data", 32), ("mask", 4), ("size", 2), ("operation", 4))
INPUTS = [("reset", 1), ("clearReservation", 1)]
OUTPUTS = []
MEMORY_OUTPUTS = ("sram_read", "sram_address", "sram_mask", "sram_data")
for port in PORTS:
    INPUTS += [(port + "_request_valid", 1)]
    INPUTS += [(port + "_request_bits_" + name, width) for name, width in FIELDS]
    INPUTS += [(port + "_response_ready", 1)]
    OUTPUTS += [(port + "_request_ready", 1), (port + "_response_valid", 1),
                (port + "_response_bits_data", 32), (port + "_response_bits_fault", 1)]
WRAPPER = """// SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
// SPDX-License-Identifier: MIT
package ditdah_e2
import me.jiuyang.zaozi.*
import me.jiuyang.zaozi.default.{*, given}
import me.jiuyang.zaozi.reftpe.*
import me.jiuyang.zaozi.valuetpe.*
@generator
object DitDahE2 extends Generator[AtomicParameters, AtomicLayers, AtomicMemoryIO, AtomicProbe]:
  override def moduleName(p: AtomicParameters): String = "DitDahE2AtomicMemoryTest"
  def architecture(p: AtomicParameters) =
    val io = summon[Interface[AtomicMemoryIO]]
    val memory = AtomicMemory.instantiate(p)
    memory.io.clock := io.clock
    memory.io.reset := io.reset
    memory.io.clearReservation := io.clearReservation
    memory.io.instruction :<>= io.instruction
    memory.io.data :<>= io.data
    memory.io.debug :<>= io.debug
    memory.io.competitor :<>= io.competitor
"""


def configuration(value):
    if not isinstance(value, dict) or value.keys() - {"baseAddress", "sizeBytes"}:
        raise ValueError("Invalid atomic memory configuration fields")
    result = {"baseAddress": value.get("baseAddress", 0), "sizeBytes": value.get("sizeBytes", 4096)}
    base, size = result["baseAddress"], result["sizeBytes"]
    if type(base) is not int or base < 0 or base > MASK or base % 4:
        raise ValueError("Atomic base must be an aligned RV32 address")
    if type(size) is not int or size < 4 or size >= 1 << 31 or size % 4 or base + size > 1 << 32:
        raise ValueError("Atomic size must contain complete RV32 words")
    return result


def request(address, *, operation=0, write=False, data=0, size=2, machine=True, mask=None):
    if mask is None:
        mask = ((1 << (1 << size)) - 1) << (address % 4) if write and size < 3 else 0
    return address, int(machine), int(write), data, mask, size, operation


def row(requests=None, ready=(1, 1, 1, 1), *, reset=0, clear=0):
    requests = requests or (None,) * 4
    assert len(requests) == len(ready) == 4
    result = [reset, clear]
    for payload, available in zip(requests, ready, strict=True):
        result += [int(payload is not None), *(payload or (0,) * 7), available]
    return tuple(result)


def decode(values):
    assert len(values) == len(INPUTS), "Atomic stimulus width differs"
    assert all(type(value) is int and 0 <= value < 1 << width for value, (_, width) in zip(values, INPUTS, strict=True)), "Atomic stimulus value exceeds its width"
    requests, ready = [], []
    for index in range(4):
        start = 2 + index * 9
        requests.append(tuple(values[start + 1:start + 8]) if values[start] else None)
        ready.append(values[start + 8])
    return bool(values[0]), bool(values[1]), requests, ready


def signed(value):
    return value if value < 1 << 31 else value - (1 << 32)


def amo(operation, old, operand):
    if operation == 3:
        return operand
    if operation == 4:
        return (old + operand) & MASK
    if operation == 5:
        return old ^ operand
    if operation == 6:
        return old & operand
    if operation == 7:
        return old | operand
    if operation in (8, 9):
        values = (signed(old), signed(operand))
        return (min(values) if operation == 8 else max(values)) & MASK
    if operation in (10, 11):
        return min(old, operand) if operation == 10 else max(old, operand)
    raise ValueError("Unknown AMO operation")


class Reference:
    def __init__(self, parameters):
        self.parameters = configuration(parameters)
        self.memory = {}
        self.reservation = None
        self.cursor = 0
        self.pending = None
        self.responses = [None] * 4
        self.held = [None] * 4
        self.counts = Counter()
        self.history = []

    def legal(self, port, payload):
        address, _, write, _, mask, size, operation = payload
        base, length = self.parameters["baseAddress"], self.parameters["sizeBytes"]
        if size > 2 or address % (1 << size) or not base <= address < base + length:
            return False
        if operation == 0:
            expected = ((1 << (1 << size)) - 1) << (address % 4) if write else 0
            return mask == expected and (port != 0 or not write and size == 2)
        return (port == 1 and 1 <= operation <= 11 and size == 2 and address % 4 == 0 and
                write == (operation != 1) and mask == (0 if operation == 1 else 15))

    def read(self, address):
        aligned = address & ~3
        assert all(aligned + lane in self.memory for lane in range(4)), "Read precedes SRAM initialization"
        return sum(self.memory[aligned + lane] << (8 * lane) for lane in range(4))

    def apply(self, item, cycle, clear):
        port, payload, accepted = item
        address, machine, write, data, mask, size, operation = payload
        aligned = address & ~3
        before = self.reservation
        legal = self.legal(port, payload)
        old = None
        updated = None
        value = 0
        if port == 1 and operation == 2:
            self.reservation = None
        if legal:
            if operation == 2:
                value = int(before != aligned or clear)
                if value == 0:
                    updated = data
                self.counts["scFailure" if value else "scSuccess"] += 1
            elif operation >= 3:
                old = self.read(address)
                value, updated = old, amo(operation, old, data)
                self.counts["amo" + str(operation)] += 1
            elif write:
                updated = data
            else:
                old = value = self.read(address)
                if operation == 1:
                    self.reservation = aligned
                    self.counts["lr"] += 1
            if updated is not None:
                for lane in range(4):
                    if mask >> lane & 1:
                        self.memory[aligned + lane] = updated >> (8 * lane) & 255
                if self.reservation == aligned:
                    self.reservation = None
                    self.counts["writeInvalidations"] += 1
                self.counts["writes"] += 1
        else:
            self.counts["faults"] += 1
        if clear:
            self.reservation = None
        assert self.responses[port] is None, "Atomic response overwrote a previous owner"
        self.responses[port] = value, int(not legal)
        self.history.append({"acceptedCycle": accepted, "memoryCycle": cycle, "port": PORTS[port], "request": payload,
                             "oldValue": old, "writeValue": updated, "response": self.responses[port],
                             "reservationBefore": before, "reservationAfter": self.reservation})
        self.counts["completed"] += 1

    def step(self, values, cycle):
        reset, clear, requests, ready = decode(values)
        for index in range(4):
            if self.held[index] is not None:
                assert requests[index] == self.held[index], "Atomic source changed a held request"
        order = [(self.cursor + offset) % 4 for offset in range(4)]
        selected = next((index for index in order if requests[index] is not None and
                         (self.responses[index] is None or ready[index])), None) if self.pending is None else None
        outputs = [cycle]
        for index in range(4):
            response = self.responses[index]
            outputs += [int(index == selected), int(response is not None), *(response or (0, 0))]
            self.held[index] = requests[index] if requests[index] is not None and index != selected else None
        if reset:
            assert self.pending is None and not any(self.responses) and not any(requests), "Cold reset with atomic traffic"
            self.cursor, self.reservation = 0, None
            self.counts["coldResets"] += 1
            return tuple(outputs + [0, 0, 0, 0])
        read = selected is not None and self.legal(selected, requests[selected])
        address = (requests[selected][0] - self.parameters["baseAddress"]) // 4 if read else 0
        write_mask = write_data = 0
        for index in range(4):
            if self.responses[index] is not None:
                if ready[index]:
                    self.responses[index] = None
                    self.counts["responses"] += 1
                else:
                    self.counts["responseStalls"] += 1
            if requests[index] is not None and index != selected:
                self.counts["requestStalls"] += 1
        if clear:
            self.reservation = None
            self.counts["clears"] += 1
        if self.pending is not None:
            self.apply(self.pending, cycle, clear)
            event = self.history[-1]
            if event["writeValue"] is not None:
                address = (event["request"][0] - self.parameters["baseAddress"]) // 4
                write_mask, write_data = event["request"][4], event["writeValue"]
            self.pending = None
        elif selected is not None:
            self.pending = selected, requests[selected], cycle
            self.cursor = (selected + 1) % 4
            self.counts["requests"] += 1
            self.counts["port" + str(selected)] += 1
        return tuple(outputs + [int(read), address, write_mask, write_data])


def expected(rows, parameters):
    reference = Reference(parameters)
    samples = [reference.step(values, cycle) for cycle, values in enumerate(rows)]
    counts = dict(reference.counts)
    counts["pending"] = int(reference.pending is not None) + sum(response is not None for response in reference.responses)
    return samples, counts, reference.history


def render(samples):
    return "\n".join(str(sample[0]) + " " + " ".join(f"{value:x}" for value in sample[1:]) for sample in samples) + "\n"


def parse(trace):
    result = []
    for line in trace.splitlines():
        fields = line.split()
        assert len(fields) == len(OUTPUTS) + len(MEMORY_OUTPUTS) + 1, "Atomic trace width differs"
        result.append((int(fields[0]), *(int(value, 16) for value in fields[1:])))
    return result


def check(rows, trace, parameters):
    targets, counts, history = expected(rows, parameters)
    actual = parse(trace)
    assert len(actual) == len(targets), "Atomic trace length differs"
    for observed, target in zip(actual, targets, strict=True):
        if observed != target:
            names = [name for name, _ in OUTPUTS] + list(MEMORY_OUTPUTS)
            differences = [name for index, name in enumerate(names, 1) if observed[index] != target[index]]
            raise AssertionError(f"Atomic mismatch at cycle {target[0]}: {','.join(differences)}")
    assert counts["pending"] == 0 and counts["requests"] == counts["completed"] == counts["responses"], "Atomic transactions did not drain"
    return counts, history


class Driver:
    def __init__(self, parameters, seed=1):
        self.reference = Reference(parameters)
        self.random = random.Random(seed)
        self.rows = []
        self.tick(reset=1)

    def tick(self, requests=None, ready=(1, 1, 1, 1), **signals):
        values = row(requests, ready, **signals)
        outputs = self.reference.step(values, len(self.rows))
        self.rows.append(values)
        return [outputs[1 + index * 4:5 + index * 4] for index in range(4)]

    def issue(self, port, payload, ready=(1, 1, 1, 1), **signals):
        requests = [None] * 4
        requests[port] = payload
        for _ in range(1000):
            outputs = self.tick(requests, ready, **signals)
            if outputs[port][0]:
                return
        raise AssertionError("Atomic request did not transfer")

    def command(self, port, payload, *, expected_result=None, stall=0):
        self.issue(port, payload)
        ready = [1] * 4
        ready[port] = 0
        for _ in range(stall):
            self.tick(ready=ready)
        for _ in range(1000):
            outputs = self.tick()
            if outputs[port][1]:
                value = tuple(outputs[port][2:])
                if expected_result is not None:
                    assert value == expected_result, f"Fixed atomic result differs: {value} != {expected_result}"
                return value
        raise AssertionError("Atomic response did not transfer")


def vectors(parameters, seed=1):
    driver = Driver(parameters, seed)
    base, words = parameters["baseAddress"], parameters["sizeBytes"] // 4
    addresses = [base + index * 4 for index in range(min(words, 64))]
    if addresses[-1] != base + words * 4 - 4:
        addresses.append(base + words * 4 - 4)
    for index, address in enumerate(addresses):
        driver.command(2, request(address, write=True, data=(0x13579BDF ^ index * 0x9E3779B9) & MASK), expected_result=(0, 0))
    for operation, value in ((3, 1), (4, 0x80000001), (5, 0x80000001), (6, 0), (7, 0x80000001),
                             (8, 0x80000000), (9, 1), (10, 1), (11, 0x80000000)):
        driver.command(2, request(base, write=True, data=0x80000000))
        driver.command(1, request(base, operation=operation, write=True, data=1), expected_result=(0x80000000, 0), stall=5)
        driver.command(0, request(base), expected_result=(value, 0))
    for old, operand in ((0, MASK), (MASK, 1), (0x7FFFFFFF, 0x80000000), (0x80000000, 0xFFFFFFFF)):
        for operation in range(3, 12):
            driver.command(2, request(base, write=True, data=old))
            driver.command(1, request(base, operation=operation, write=True, data=operand), expected_result=(old, 0))
            driver.command(1, request(base), expected_result=(amo(operation, old, operand), 0))
    driver.command(2, request(base, write=True, data=7))
    driver.command(1, request(base, operation=1), expected_result=(7, 0))
    driver.command(1, request(base, operation=2, write=True, data=9), expected_result=(0, 0))
    driver.command(1, request(base, operation=2, write=True, data=11), expected_result=(1, 0))
    driver.command(0, request(base), expected_result=(9, 0))
    for port in (1, 2, 3):
        for size in range(3):
            for lane in range(0, 4, 1 << size):
                driver.command(1, request(base, operation=1))
                driver.command(port, request(base + lane, write=True, size=size, data=(0xA5A5A5A5 << (lane * 8)) & MASK))
                driver.command(1, request(base, operation=2, write=True, data=0), expected_result=(1, 0))
    if words > 1:
        driver.command(1, request(base, operation=1))
        driver.command(3, request(base + 4, write=True, data=99))
        driver.command(1, request(base, operation=2, write=True, data=13), expected_result=(0, 0))
        driver.command(1, request(base, operation=1))
        driver.command(1, request(base + 4, operation=2, write=True, data=55), expected_result=(1, 0))
        driver.command(1, request(base, operation=2, write=True, data=55), expected_result=(1, 0))
    driver.command(2, request(base, write=True, data=0x11223344))
    hold = (1, 0, 1, 1)
    driver.issue(1, request(base, operation=1), ready=hold)
    driver.tick(ready=hold)
    driver.issue(3, request(base + 1, size=0, write=True, data=0xAA00), ready=hold)
    for _ in range(5):
        outputs = driver.tick(ready=hold)
        assert outputs[1][1:] == (1, 0x11223344, 0)
    driver.tick()
    driver.command(1, request(base, operation=2, write=True, data=0), expected_result=(1, 0))
    driver.command(0, request(base), expected_result=(0x1122AA44, 0))
    driver.command(2, request(base, write=True, data=10))
    driver.issue(1, request(base, operation=4, write=True, data=5), ready=hold)
    driver.tick(ready=hold)
    driver.issue(3, request(base, write=True, data=77), ready=hold)
    for _ in range(5):
        outputs = driver.tick(ready=hold)
        assert outputs[1][1:] == (1, 10, 0)
    driver.tick()
    driver.command(0, request(base), expected_result=(77, 0))
    for operation in (1, 2):
        driver.command(1, request(base, operation=1))
        driver.issue(1, request(base, operation=operation, write=operation == 2, data=9))
        driver.tick(clear=1)
        outputs = driver.tick()
        assert outputs[1][1:] == (1, 1 if operation == 2 else 77, 0)
        driver.command(1, request(base, operation=2, write=True, data=9), expected_result=(1, 0))
    for port, invalid in ((0, request(base, write=True, data=1)), (0, request(base, size=0)),
                          (2, request(base, operation=1)), (3, request(base, operation=4, write=True, data=3)),
                          (1, request(base, operation=12, write=True, data=3)), (1, request(base + 1, size=1)),
                          (1, request(base, write=True, data=3, mask=3)), (1, request(base, mask=15)),
                          (1, request(base, operation=1, write=True, data=3)),
                          (1, request(base, operation=4, write=True, data=3, size=0)),
                          (1, request((base + parameters["sizeBytes"]) & MASK, operation=2, write=True, data=3))):
        driver.command(1, request(base, operation=1))
        driver.command(port, invalid, expected_result=(0, 1))
    driver.command(1, request(base, operation=2, write=True, data=3), expected_result=(1, 0))
    driver.command(0, request(base), expected_result=(77, 0))
    simultaneous = [request(base), request(base, operation=4, write=True, data=1),
                    request(base, write=True, data=100), request(base, write=True, data=200)]
    observed_order = []
    first = driver.reference.cursor
    for _ in range(12):
        outputs = driver.tick(simultaneous)
        for index in range(4):
            if simultaneous[index] is not None and outputs[index][0]:
                observed_order.append(index)
                simultaneous[index] = None
    assert observed_order == [(first + offset) % 4 for offset in range(4)]
    offered = [None] * 4
    for _ in range(6000):
        for port in range(4):
            if offered[port] is None and driver.random.randrange(4) != 0:
                address = driver.random.choice(addresses)
                if port == 0:
                    payload = request(address)
                elif port == 1 and driver.random.randrange(2):
                    operation = driver.random.randrange(1, 12)
                    payload = request(address, operation=operation, write=operation != 1, data=driver.random.getrandbits(32),
                                      machine=bool(driver.random.randrange(2)))
                else:
                    size = driver.random.randrange(3)
                    lane = driver.random.randrange(4 >> size) << size
                    payload = request(address + lane, size=size, write=bool(driver.random.randrange(2)),
                                      data=driver.random.getrandbits(32), machine=bool(driver.random.randrange(2)))
                offered[port] = payload
        ready = tuple(int(driver.random.randrange(4) != 0) for _ in range(4))
        outputs = driver.tick(offered, ready, clear=int(driver.random.randrange(97) == 0))
        for port in range(4):
            if outputs[port][0]:
                offered[port] = None
    for _ in range(40):
        outputs = driver.tick(offered)
        for port in range(4):
            if outputs[port][0]:
                offered[port] = None
    assert not any(offered)
    for address in addresses:
        driver.command(0, request(address), expected_result=(driver.reference.read(address), 0))
    driver.tick(reset=1)
    driver.command(1, request(base, operation=2, write=True, data=1), expected_result=(1, 0))
    driver.tick()
    return driver.rows


def harness():
    lines = ["// SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>", "// SPDX-License-Identifier: MIT",
             "module AtomicMemoryBench;", "  reg clock = 0;"]
    lines += [f"  reg {'[' + str(width - 1) + ':0] ' if width > 1 else ''}{name} = {int(name == 'reset')};" for name, width in INPUTS]
    lines += [f"  wire {'[' + str(width - 1) + ':0] ' if width > 1 else ''}{name};" for name, width in OUTPUTS]
    values = []
    for name, _ in OUTPUTS:
        port = name.split("_")[0]
        values.append(f"{port}_response_valid ? {name} : 0" if "response_bits" in name else name)
    values += ["dut.memory.readEnable", "(dut.memory.readEnable || dut.memory.writeMask != 0) ? dut.memory.address : 0",
               "dut.memory.writeMask", "dut.memory.writeMask != 0 ? dut.memory.writeData : 0"]
    lines += ["  integer file, fields, sample = 0;", "  DitDahE2AtomicMemory dut(.*);", "  initial begin",
              "    #1 clock = 1;", "    #1 clock = 0;", '    file = $fopen("vectors.txt", "r");',
              '    if (!file) $fatal(1, "Cannot open atomic vectors");', "    while (!$feof(file)) begin",
              '      fields = $fscanf(file, "' + " ".join(["%h"] * len(INPUTS)) + '\\n", ' + ", ".join(name for name, _ in INPUTS) + ");",
              f"      if (fields == {len(INPUTS)}) begin", '        #1 $display("%0d ' + " ".join(["%h"] * len(values)) + '", sample, ' + ", ".join(values) + ");",
              "        clock = 1;", "        #1 clock = 0;", "        sample = sample + 1;", '      end else if (fields != -1) $fatal(1, "Incomplete atomic vector");',
              "    end", "    $fclose(file);", "    $finish(0);", "  end", "endmodule"]
    return "\n".join(lines) + "\n"


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def build(output, parameters):
    output = Path(output).resolve()
    names = ["ditdah_e2/src/Parameters.scala", "ditdah_e2/src/Interfaces.scala", "ditdah_e2/src/AtomicInterfaces.scala",
             "ditdah_e2/src/AtomicMemory.scala", "ditdah_e2/src/AtomicSram.sv", "test/atomic_memory.py", "test/test_atomic_memory.py",
             "platform.json", "flake.nix", "flake.lock"]
    names += [str(path.relative_to(ROOT)) for path in sorted((ROOT / "nix").glob("*.nix"))]
    contents = {name: (ROOT / name).read_bytes() for name in names}
    for name, data in contents.items():
        target = output / "inputs" / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
    tools = {name: Path(shutil.which(name)).resolve() for name in ("elaborate-ditdah-e2", "firld", "firtool", "iverilog", "vvp", "yosys")}
    commands = []
    with tempfile.TemporaryDirectory(prefix="ditdah-e2-atomic-build-", dir="/data/tmp") as directory:
        work = Path(directory)
        (work / "src").mkdir()
        for name, data in contents.items():
            if name.endswith(".scala"):
                (work / "src" / Path(name).name).write_bytes(data)
        (work / "src/Top.scala").write_text(WRAPPER)
        (work / "parameters.json").write_text(json.dumps(parameters) + "\n")
        for name in ("src/Top.scala", "parameters.json"):
            target = output / "inputs/generated" / name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(work / name, target)
        environment = dict(os.environ, DITDAH_E2_SOURCE=str(work / "src"))
        for number in range(3):
            command = ["elaborate-ditdah-e2", "design", "parameters.json"] if number == 0 else \
                      ["firld", *[path.name for path in sorted(work.glob("*.mlirbc"))], "--base-circuit", "DitDahE2AtomicMemoryTest",
                       "--no-mangle", "--emit-bytecode", "-o", "linked.mlirbc"] if number == 1 else \
                      ["firtool", "linked.mlirbc", "--split-verilog", "-disable-all-randomization",
                       "--lowering-options=noAlwaysComb,disallowLocalVariables,disallowPackedArrays,locationInfoStyle=none", "-o", "rtl"]
            result = subprocess.run(command, cwd=work, env=environment, capture_output=True, text=True)
            commands.append({"argv": command, "exitStatus": result.returncode})
            (output / f"build-{number}.log").write_text(result.stdout + result.stderr)
            (output / "commands.json").write_text(json.dumps(commands, indent=2) + "\n")
            if result.returncode:
                raise RuntimeError(f"Atomic generation failed in command {number}")
        shutil.copytree(work / "rtl", output / "rtl")
    shutil.copyfile(output / "inputs/ditdah_e2/src/AtomicSram.sv", output / "rtl/AtomicSram.sv")
    report = {"exitStatus": 0, "parameters": parameters, "commands": commands,
              "inputHashes": {name: hashlib.sha256(data).hexdigest() for name, data in contents.items()},
              "generatedHashes": {str(path.relative_to(output / "inputs")): digest(path) for path in (output / "inputs/generated").rglob("*") if path.is_file()},
              "rtlHashes": {path.name: digest(path) for path in (output / "rtl").glob("*.sv")},
              "toolHashes": {name: digest(path) for name, path in tools.items()}}
    (output / "build.json").write_text(json.dumps(report, indent=2) + "\n")
    return report


def infer(output, parameters, commands):
    directory = output / "inference"
    directory.mkdir()
    help_command = ["yosys", "-Q", "-T", "-p", "help hierarchy; help memory_dff; help memory_share; help memory_collect; help check"]
    result = subprocess.run(help_command, cwd=directory, capture_output=True, text=True)
    (directory / "help.log").write_text(result.stdout + result.stderr)
    commands.append({"directory": "inference", "argv": help_command, "exitStatus": result.returncode})
    assert result.returncode == 0, "Yosys command help failed"
    sources = sorted((output / "rtl").glob("*.sv"))
    script = "read_verilog -sv " + " ".join("../rtl/" + path.name for path in sources) + "\n"
    script += "hierarchy -check -top DitDahE2AtomicMemory\nproc\nopt\nmemory_dff\nmemory_share\nmemory_collect\nopt_clean\ncheck -assert\nwrite_json memory.json\nstat -json\n"
    (directory / "infer.ys").write_text(script)
    command = ["yosys", "-Q", "-T", "-s", "infer.ys"]
    result = subprocess.run(command, cwd=directory, capture_output=True, text=True)
    (directory / "inference.log").write_text(result.stdout + result.stderr)
    commands.append({"directory": "inference", "argv": command, "exitStatus": result.returncode})
    (directory / "commands.json").write_text(json.dumps(commands[-2:], indent=2) + "\n")
    if result.returncode:
        raise RuntimeError("Atomic SRAM inference failed")
    design = json.loads((directory / "memory.json").read_text())
    memories = []
    for name, module in design["modules"].items():
        assert not int(module.get("attributes", {}).get("blackbox", "0"), 2), "Atomic SRAM is a black box"
        for cell in module["cells"].values():
            if cell["type"] == "$mem_v2":
                values = cell["parameters"]
                memories.append({"module": name, "width": int(values["WIDTH"], 2), "words": int(values["SIZE"], 2),
                                 "readPorts": int(values["RD_PORTS"], 2), "writePorts": int(values["WR_PORTS"], 2),
                                 "synchronousReads": int(values["RD_CLK_ENABLE"], 2)})
    assert len(memories) == 1, "Atomic design must contain one SRAM"
    memory = memories[0]
    assert memory["width"] == 32 and memory["words"] == parameters["sizeBytes"] // 4, "Atomic SRAM geometry differs"
    assert memory["readPorts"] == 1 and memory["synchronousReads"] == 1, "Atomic SRAM read must be synchronous"
    return {"exitStatus": 0, "memory": memory, "netlistHash": digest(directory / "memory.json")}


def simulate(directory, rows, rtl, commands, mutant=None):
    directory.mkdir(parents=True)
    for path in sorted(rtl.glob("*.sv")):
        shutil.copyfile(path, directory / path.name)
    if mutant is not None:
        (directory / "DitDahE2AtomicMemory.sv").write_text(mutant)
    (directory / "atomic_tb.sv").write_text(harness())
    (directory / "vectors.txt").write_text("".join(" ".join(f"{value:x}" for value in values) + "\n" for values in rows))
    local_commands = []
    for command in (["iverilog", "-g2012", "-s", "AtomicMemoryBench", "-o", "atomic-sim", "atomic_tb.sv",
                     "DitDahE2AtomicMemory.sv", "AtomicSram.sv"], ["vvp", "atomic-sim"]):
        result = subprocess.run(command, cwd=directory, capture_output=True, text=True)
        item = {"directory": directory.name, "argv": command, "exitStatus": result.returncode}
        commands.append(item)
        local_commands.append(item)
        (directory / "commands.json").write_text(json.dumps(local_commands, indent=2) + "\n")
        (directory / ("compile.log" if command[0] == "iverilog" else "simulation.log")).write_text(result.stdout + result.stderr)
        if result.returncode:
            raise RuntimeError("Atomic RTL simulation failed")
    trace = "\n".join(line for line in result.stdout.splitlines() if line and line[0].isdigit()) + "\n"
    (directory / "atomic.trace").write_text(trace)
    return trace


def mutate(source, kind):
    before, after = {"stale-reservation": ("~(write & success)", "1'h1"),
                     "amo-subtract": ("_memory_readData + request_data", "_memory_readData - request_data")}[kind]
    if source.count(before) != 1:
        raise ValueError("Atomic mutation site changed")
    return source.replace(before, after)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=Path("result/atomic-memory"))
    parser.add_argument("--config", type=Path)
    args = parser.parse_args()
    if args.output.exists() and any(args.output.iterdir()):
        raise ValueError("Atomic output must be empty")
    if args.config:
        parameters = configuration(json.loads(args.config.read_text()))
    else:
        region = json.loads((ROOT / "platform.json").read_text())["sram"]
        parameters = configuration({"baseAddress": region["base"], "sizeBytes": region["size"]})
    output = args.output.resolve()
    report = build(output, parameters)
    commands, runs, controls = [], [], []
    inference = infer(output, parameters, commands)
    for seed in (1, 19, 83):
        rows = vectors(parameters, seed)
        directory = output / f"seed-{seed}"
        trace = simulate(directory, rows, output / "rtl", commands)
        counts, history = check(rows, trace, parameters)
        assert all(counts.get("amo" + str(operation), 0) > 0 for operation in range(3, 12)), "AMO coverage incomplete"
        assert all(counts.get(name, 0) > 0 for name in ("lr", "scSuccess", "scFailure", "faults", "clears", "writeInvalidations",
                                                       "requestStalls", "responseStalls", "port0", "port1", "port2", "port3")), "Atomic coverage incomplete"
        (directory / "history.json").write_text(json.dumps(history, indent=2) + "\n")
        runs.append({"seed": seed, "cycles": len(rows), **counts, "traceHash": digest(directory / "atomic.trace"),
                     "historyHash": digest(directory / "history.json"), "vectorsHash": digest(directory / "vectors.txt")})
    original = (output / "rtl/DitDahE2AtomicMemory.sv").read_text()
    rows = vectors(parameters)
    targets, _, _ = expected(rows, parameters)
    for kind in ("stale-reservation", "amo-subtract"):
        directory = output / kind
        trace = simulate(directory, rows, output / "rtl", commands, mutate(original, kind))
        try:
            check(rows, trace, parameters)
        except AssertionError as error:
            reason = str(error)
            assert "sram_" in reason, "Atomic mutant did not reach a wrong storage effect"
        else:
            raise AssertionError("Atomic checker accepted faulty RTL")
        observed = parse(trace)
        witness = next(index for index, (actual, target) in enumerate(zip(observed, targets, strict=True)) if actual != target)
        assert observed[witness][-2] != 0, "Atomic mutant did not write SRAM"
        controls.append({"mutation": kind, "exitStatus": 0, "cycle": witness, "rejected": reason,
                         "expectedStorage": targets[witness][-4:], "observedStorage": observed[witness][-4:],
                         "rtlHash": digest(directory / "DitDahE2AtomicMemory.sv"), "traceHash": digest(directory / "atomic.trace")})
    assert all(digest(output / "inputs" / name) == value for name, value in report["inputHashes"].items())
    assert all(digest(output / "rtl" / name) == value for name, value in report["rtlHashes"].items())
    summary = {"exitStatus": 0, "scope": "four-port shared atomic SRAM", "parameters": parameters,
               "buildHash": digest(output / "build.json"), "commands": commands, "inference": inference,
               "runs": runs, "negativeControls": controls,
               "excluded": ["core integration", "PMP implementation", "instruction ordering bits", "unbounded atomic proof", "technology mapping"]}
    (output / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    artifacts = {str(path.relative_to(output)): digest(path) for path in sorted(output.rglob("*")) if path.is_file()}
    (output / "artifacts.json").write_text(json.dumps(artifacts, indent=2) + "\n")
    print(f"PASS: {sum(run['cycles'] for run in runs)} atomic SRAM cycles and two RTL negative controls")


if __name__ == "__main__":
    main()
