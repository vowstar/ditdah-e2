# SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
# SPDX-License-Identifier: MIT
"""Score generated SBA RTL against logical registers and addressed byte effects.

Generate the standalone top with scripts/build_rtl.py, then run this module with
--rtl pointing to that frozen RTL directory and --output to a new directory.
"""

import argparse
import hashlib
import json
import random
import re
import shutil
import subprocess
from pathlib import Path

from test.test_sba.reference import (
    MASK32,
    READ,
    SBADDRESS,
    SBCS,
    SBDATA,
    WRITE,
    ByteMemory,
    SbaModel,
)

FIELDS = ("reset", "active", "accepted", "address", "operation", "value", "request_ready",
          "response_valid", "response_data", "response_fault")
HEX_INPUT = (3, 5, 8)
HEX_OUTPUT = (1, 4, 7, 8)
ROOT = Path(__file__).resolve().parents[2]
HARNESS = r"""// SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
// SPDX-License-Identifier: MIT
module SbaBench;
  reg clock = 0, reset = 1, active = 0, accepted = 0;
  reg [6:0] request_address = 0;
  reg [1:0] request_op = 0;
  reg [31:0] request_data = 0;
  wire [31:0] readData;
  wire idle, systemBus_request_valid, systemBus_response_ready;
  wire [31:0] systemBus_request_bits_address, systemBus_request_bits_data;
  wire systemBus_request_bits_machine, systemBus_request_bits_write;
  wire [3:0] systemBus_request_bits_mask, systemBus_request_bits_operation;
  wire [1:0] systemBus_request_bits_size;
  reg systemBus_request_ready = 0, systemBus_response_valid = 0;
  reg [31:0] systemBus_response_bits_data = 0;
  reg systemBus_response_bits_fault = 0;
  DitDahE2DebugSystemBus dut (.*);
  integer file, fields, sample = 0;
  initial begin
    #1 clock = 1;
    #1 clock = 0;
    file = $fopen("vectors.txt", "r");
    if (!file) $fatal(1, "Cannot open SBA vectors");
    while (!$feof(file)) begin
      fields = $fscanf(file, "%d %d %d %h %d %h %d %d %h %d\n",
        reset, active, accepted, request_address, request_op, request_data,
        systemBus_request_ready, systemBus_response_valid,
        systemBus_response_bits_data, systemBus_response_bits_fault);
      if (fields == 10) begin
        #1 $display("%0d %08h %0d %0d %08h %0d %0d %08h %0h %0d %0d %0d",
          sample, readData, idle, systemBus_request_valid,
          systemBus_request_valid ? systemBus_request_bits_address : 0,
          systemBus_request_valid ? systemBus_request_bits_machine : 0,
          systemBus_request_valid ? systemBus_request_bits_write : 0,
          systemBus_request_valid ? systemBus_request_bits_data : 0,
          systemBus_request_valid ? systemBus_request_bits_mask : 0,
          systemBus_request_valid ? systemBus_request_bits_size : 0,
          systemBus_request_valid ? systemBus_request_bits_operation : 0,
          systemBus_response_ready);
        clock = 1;
        #1 clock = 0;
        sample = sample + 1;
      end else if (fields != -1) $fatal(1, "Incomplete SBA vector");
    end
    $fclose(file);
    $finish(0);
  end
endmodule
"""


def control(size=2, read_address=False, read_data=False, increment=False, clear=0):
    return (size << 17 | int(read_address) << 20 | int(read_data) << 15 |
            int(increment) << 16 | clear)


def row(**values):
    state = dict.fromkeys(FIELDS, 0)
    state.update(active=1, request_ready=1)
    if values.keys() - state.keys():
        raise ValueError("Unknown SBA vector field")
    state.update(values)
    limits = {"address": 7, "operation": 2, "value": 32, "response_data": 32}
    for name, value in state.items():
        if type(value) is not int or not 0 <= value < 1 << limits.get(name, 1):
            raise ValueError("SBA vector field has invalid type or width: " + name)
    return tuple(state[name] for name in FIELDS)


def step(model, values, cycle):
    state = dict(zip(FIELDS, values, strict=True))
    row(**state)
    result, result_mask = model.read_register(state["address"], bool(state["active"]))
    offered, busy = model.offered, model.busy
    waiting = busy and model.pending.accepted
    payload = model.pending.transfer.bus_payload if offered else (0,) * 7
    wanted = (cycle, result, int(not busy), int(offered), *payload, int(waiting))
    masks = [MASK32] * len(wanted)
    masks[1] = result_mask
    if offered and not model.pending.transfer.write:
        masks[7] = 0  # Read request write-data is not a meaningful transaction field.
    if state["reset"]:
        model.cold_reset()
        return wanted, masks
    model.activate(bool(state["active"]))
    if state["accepted"]:
        model.access(state["address"], state["operation"], state["value"])
    if offered and state["request_ready"]:
        model.accept_bus_request(payload)
    if waiting and state["response_valid"]:
        model.complete_bus(state["response_data"], bool(state["response_fault"]))
    return wanted, masks


class Driver:
    """Drive legal bus responders independently of RTL register encodings."""

    def __init__(self, seed=1):
        self.random = random.Random(seed)
        self.model, self.memory = SbaModel(), ByteMemory()
        self.rows = []
        self.response = None
        self.delay, self.next_fault = 5, False
        self.active = 1
        self.tick(reset=1, active=0)
        self.tick()

    def tick(self, **changes):
        cycle = len(self.rows)
        values = {"active": self.active, "request_ready": int(cycle % 5 != 0)}
        if self.response is not None and cycle >= self.response["due"]:
            values.update(response_valid=1, response_data=self.response["data"],
                          response_fault=int(self.response["fault"]))
        values.update(changes)
        values = row(**values)
        state = dict(zip(FIELDS, values, strict=True))
        offered = self.model.offered and state["request_ready"]
        completed = self.model.pending is not None and self.model.pending.accepted and state["response_valid"]
        if offered:
            if self.response is not None:
                raise AssertionError("Responder received two outstanding requests")
            transaction = self.model.pending.transfer
            self.response = {"due": cycle + self.delay,
                             "data": self.memory.response(transaction, self.next_fault),
                             "fault": self.next_fault}
            self.next_fault = False
        sample = step(self.model, values, cycle)
        if completed:
            self.response = None
        self.rows.append(values)
        return sample

    def dmi(self, address, operation=READ, value=0):
        return self.tick(accepted=1, address=address, operation=operation, value=value)

    def drain(self):
        for _ in range(256):
            if self.model.idle:
                return
            self.tick()
        raise AssertionError("SBA reference transaction failed to drain")

    def configure(self, **values):
        self.dmi(SBCS, WRITE, control(**values))


def vectors(seed=1):
    driver = Driver(seed)
    driver.dmi(SBCS)
    driver.dmi(SBCS, WRITE, MASK32)
    driver.configure()
    for size in range(3):
        width = 1 << size
        for lane in range(0, 4, width):
            driver.configure(size=size, increment=True)
            driver.dmi(SBADDRESS, WRITE, 0x100 + lane)
            driver.dmi(SBDATA, WRITE, driver.random.getrandbits(32))
            driver.drain()
            driver.configure(size=size, read_address=True)
            driver.dmi(SBADDRESS, WRITE, 0x100 + lane)
            driver.drain()
            driver.dmi(SBDATA)
    # Autoread returns the old word and only then starts the following transfer.
    driver.configure(read_address=True, read_data=True, increment=True)
    driver.dmi(SBADDRESS, WRITE, 0x200)
    driver.drain()
    for _ in range(5):
        driver.dmi(SBDATA)
        driver.drain()
    driver.configure()
    # Invalid sizes and alignments must remain local errors without a bus offer.
    for size in range(3, 8):
        driver.configure(size=size, clear=7 << 12)
        driver.dmi(SBDATA, WRITE, 0x11223344)
        driver.dmi(SBCS)
    for size, lane in ((1, 1), (2, 1), (2, 2), (2, 3)):
        driver.configure(size=size, clear=7 << 12)
        driver.dmi(SBADDRESS, WRITE, 0x300 + lane)
        driver.dmi(SBDATA, WRITE, 0x11223344)
        driver.dmi(SBCS)
    driver.configure(clear=1 << 12)
    driver.dmi(SBCS)
    driver.dmi(SBDATA, WRITE, 7)
    driver.configure(clear=7 << 12)
    # Pending ownership survives attempted register changes and busy W1C writes.
    driver.dmi(SBADDRESS, WRITE, 0x400)
    driver.delay = 15
    driver.dmi(SBDATA, WRITE, 0x12345678)
    driver.dmi(SBADDRESS, WRITE, 0x408)
    driver.dmi(SBDATA)
    driver.dmi(SBCS, WRITE, MASK32)
    driver.drain()
    driver.dmi(SBCS)
    driver.dmi(SBDATA, WRITE, 0xBAD)
    driver.configure(clear=1 << 22)
    driver.dmi(SBADDRESS, WRITE, 0x480)
    driver.delay = 6
    driver.dmi(SBDATA, WRITE, 0xAABBCCDD)
    while driver.response is None or len(driver.rows) < driver.response["due"]:
        driver.tick()
    driver.dmi(SBDATA)
    driver.drain()
    driver.dmi(SBCS)
    driver.configure(clear=1 << 22)
    # A bus fault does not autoincrement; W1C does not clear unrelated error bits.
    driver.configure(read_address=True, increment=True)
    driver.next_fault = True
    driver.dmi(SBADDRESS, WRITE, 0x500)
    driver.drain()
    driver.dmi(SBCS)
    driver.dmi(SBADDRESS)
    driver.configure(clear=1 << 12)
    driver.dmi(SBCS)
    driver.configure(clear=2 << 12)
    # Turn off both an unaccepted offer and an accepted response owner.
    for accepted in (False, True):
        driver.configure(read_address=True, increment=True)
        driver.dmi(SBADDRESS, WRITE, 0x600)
        if accepted:
            while driver.model.offered:
                driver.tick(request_ready=1)
        driver.active = 0
        driver.tick(request_ready=0)
        driver.dmi(SBCS)
        driver.active = 1
        driver.tick(request_ready=0)
        driver.dmi(SBCS)
        driver.drain()
        driver.dmi(SBDATA)
        driver.dmi(SBADDRESS)
    driver.configure(increment=True)
    driver.dmi(SBADDRESS, WRITE, 0xFFFFFFFC)
    driver.dmi(SBDATA, WRITE, 0x12345678)
    driver.drain()
    driver.dmi(SBADDRESS)
    for _ in range(96):
        size = driver.random.randrange(3)
        width = 1 << size
        address = driver.random.randrange(0x800, 0x900) & ~(width - 1)
        driver.delay = driver.random.randrange(2, 13)
        driver.configure(size=size)
        driver.dmi(SBADDRESS, WRITE, address)
        driver.dmi(SBDATA, WRITE, driver.random.getrandbits(32))
        driver.drain()
        driver.configure(size=size, read_address=True)
        driver.dmi(SBADDRESS, WRITE, address)
        driver.drain()
        driver.dmi(SBDATA)
    driver.tick()
    return driver.rows


def check(rows, text):
    samples = []
    for line in text.splitlines():
        fields = line.split()
        if not fields or not fields[0].isdigit():
            continue
        if len(fields) != 12:
            raise AssertionError("SBA trace field count differs")
        samples.append(tuple(int(value, 16 if index in HEX_OUTPUT else 10) for index, value in enumerate(fields)))
    if len(samples) != len(rows):
        raise AssertionError("SBA trace sample count differs")
    model, held = SbaModel(), None
    for cycle, (values, actual) in enumerate(zip(rows, samples, strict=True)):
        wanted, masks = step(model, values, cycle)
        if any((a & mask) != (b & mask) for a, b, mask in zip(actual, wanted, masks, strict=True)):
            raise AssertionError(f"SBA transaction mismatch at cycle {cycle}: {actual} != {wanted}")
        payload = actual[4:11]
        if held is not None and (not actual[3] or payload != held):
            raise AssertionError("SBA request changed under backpressure")
        held = payload if actual[3] and not values[6] else None
    if model.busy or model.counts["busAccepted"] != model.counts["busCompleted"]:
        raise AssertionError("SBA bus ownership did not drain")
    return dict(model.counts)


def simulate(output, rtl, rows):
    output.mkdir()
    (output / "vectors.txt").write_text("".join(" ".join(f"{value:x}" if index in HEX_INPUT else str(value)
                                                       for index, value in enumerate(values)) + "\n" for values in rows))
    (output / "sba_tb.sv").write_text(HARNESS)
    (output / "DitDahE2DebugSystemBus.sv").write_text(rtl)
    commands = []
    for argv in (("iverilog", "-g2012", "-s", "SbaBench", "-o", "sba-sim", "DitDahE2DebugSystemBus.sv", "sba_tb.sv"),
                 ("vvp", "sba-sim")):
        result = subprocess.run(argv, cwd=output, capture_output=True, text=True, check=False)
        commands.append({"argv": list(argv), "exitStatus": result.returncode})
        (output / ("compile.log" if argv[0] == "iverilog" else "simulation.log")).write_text(result.stdout + result.stderr)
        if result.returncode:
            raise RuntimeError("SBA simulation command failed: " + argv[0])
    (output / "commands.json").write_text(json.dumps(commands, indent=2) + "\n")
    return result.stdout


def mutate(rtl, kind):
    port, value = {"missing-write-lanes": ("systemBus_request_bits_mask", "4'h0"),
                   "duplicate-request": ("systemBus_request_valid", "~idle")}[kind]
    changed, count = re.subn(r"(assign\s+" + port + r"\s*=)[^;]+;", r"\g<1> " + value + ";", rtl)
    if count != 1 or changed == rtl:
        raise ValueError("SBA mutation target differs: " + kind)
    return changed


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rtl", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists():
        parser.error("Output directory must not exist")
    args.output.mkdir(parents=True)
    source = args.rtl / "DitDahE2DebugSystemBus.sv" if args.rtl.is_dir() else args.rtl
    rtl = source.read_text()
    digest = lambda path: hashlib.sha256(path.read_bytes()).hexdigest()
    frozen = digest(source)
    runs = []
    for seed in (1, 19, 83):
        rows = vectors(seed)
        work = args.output / f"seed-{seed}"
        trace = simulate(work, rtl, rows)
        counts = check(rows, trace)
        for field in ("busAccepted", "increments", "unsupportedSizes", "misaligned", "busyConflicts", "busFaults", "discardedResults"):
            if counts.get(field, 0) == 0:
                raise AssertionError("SBA coverage is empty: " + field)
        runs.append({"seed": seed, "cycles": len(rows), "counts": counts,
                     "traceSha256": digest(work / "simulation.log"), "vectorsSha256": digest(work / "vectors.txt")})
    controls = []
    for kind in ("missing-write-lanes", "duplicate-request"):
        work = args.output / kind
        rows = vectors(1)
        trace = simulate(work, mutate(rtl, kind), rows)
        try:
            check(rows, trace)
        except AssertionError as error:
            reason = str(error)
        else:
            raise AssertionError("SBA RTL mutation was not rejected: " + kind)
        controls.append({"mutation": kind, "rejected": True, "reason": reason,
                         "traceSha256": digest(work / "simulation.log")})
    if digest(source) != frozen:
        raise AssertionError("SBA RTL input changed")
    tools = {name: digest(Path(shutil.which(name)).resolve()) for name in ("iverilog", "vvp")}
    report = {"scope": "standalone 32-bit SBA register and physical transaction ownership", "exitStatus": 0,
              "rtlSha256": frozen, "toolHashes": tools, "runs": runs, "negativeControls": controls,
              "excluded": ["integrated DMI response channel", "hart interaction", "host debugger", "unbounded proof", "physical signoff"]}
    (args.output / "summary.json").write_text(json.dumps(report, indent=2) + "\n")
    print(f"PASS: {sum(run['cycles'] for run in runs)} SBA cycles and {len(controls)} RTL negative controls")


if __name__ == "__main__":
    main()
