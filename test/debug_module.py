# SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
# SPDX-License-Identifier: MIT
"""Check the debug module with an independent DMI driver and a fake hart."""

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
FIELDS = ("reset", "valid", "ready", "address", "op", "data", "hart_ready", "result_valid", "result_data",
          "result_error", "halted", "running", "unavailable", "reset_event", "resume_ack", "reset_pending")
HEX_INPUT = (3, 5, 8)
HEX_OUTPUT = (3, 9, 10, 11)
WRAPPER = """// SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
// SPDX-License-Identifier: MIT
package ditdah_e2
import me.jiuyang.zaozi.*
import me.jiuyang.zaozi.default.{*, given}
import me.jiuyang.zaozi.reftpe.*
import me.jiuyang.zaozi.valuetpe.*
@generator
object DitDahE2 extends Generator[Parameters, UnitLayers, DebugModuleIO, UnitProbe]:
  override def moduleName(p: Parameters): String = "DitDahE2DebugTest"
  def architecture(p: Parameters) =
    val io = summon[Interface[DebugModuleIO]]
    val dm = DebugModule.instantiate(p)
    dm.io.clock := io.clock
    dm.io.reset := io.reset
    dm.io.dmi :<>= io.dmi
    io.hart :<>= dm.io.hart
"""
HARNESS = """// SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
// SPDX-License-Identifier: MIT
module DebugBench;
  reg clock = 0, reset = 1;
  reg dmi_request_valid = 0, dmi_response_ready = 0;
  reg [6:0] dmi_request_bits_address = 0;
  reg [1:0] dmi_request_bits_op = 0;
  reg [31:0] dmi_request_bits_data = 0;
  reg hart_request_ready = 0, hart_response_valid = 0;
  reg [31:0] hart_response_bits_data = 0;
  reg [2:0] hart_response_bits_error = 0;
  reg hart_status_halted = 0, hart_status_running = 1, hart_status_unavailable = 0;
  reg hart_status_resetEvent = 0, hart_status_resumeAck = 0, hart_status_resetPending = 0;
  wire dmi_request_ready, dmi_response_valid;
  wire [31:0] dmi_response_bits_data;
  wire [1:0] dmi_response_bits_status;
  wire hart_request_valid, hart_response_ready;
  wire hart_request_bits_memory, hart_request_bits_write;
  wire [1:0] hart_request_bits_size;
  wire [15:0] hart_request_bits_register;
  wire [31:0] hart_request_bits_address, hart_request_bits_data;
  wire hart_control_active, hart_control_halt, hart_control_resume, hart_control_reset, hart_control_haltOnReset;
  integer file, fields, sample = 0;
  DitDahE2DebugModule dut(.*);
  initial begin
    #1 clock = 1;
    #1 clock = 0;
    file = $fopen("vectors.txt", "r");
    if (!file) $fatal(1, "Cannot open debug vectors");
    while (!$feof(file)) begin
      fields = $fscanf(file, "%d %d %d %h %d %h %d %d %h %d %d %d %d %d %d %d\\n",
        reset, dmi_request_valid, dmi_response_ready, dmi_request_bits_address,
        dmi_request_bits_op, dmi_request_bits_data, hart_request_ready,
        hart_response_valid, hart_response_bits_data, hart_response_bits_error,
        hart_status_halted, hart_status_running, hart_status_unavailable,
        hart_status_resetEvent, hart_status_resumeAck, hart_status_resetPending);
      if (fields == 16) begin
        #1 $display("%0d %0d %0d %08h %0d %0d %0d %0d %0d %04h %08h %08h %0d %0d %0d %0d %0d %0d",
          sample, dmi_request_ready, dmi_response_valid,
          dmi_response_valid ? dmi_response_bits_data : 0,
          dmi_response_valid ? dmi_response_bits_status : 0, hart_request_valid,
          hart_request_valid ? hart_request_bits_memory : 0,
          hart_request_valid ? hart_request_bits_write : 0,
          hart_request_valid ? hart_request_bits_size : 0,
          hart_request_valid ? hart_request_bits_register : 0,
          hart_request_valid ? hart_request_bits_address : 0,
          hart_request_valid ? hart_request_bits_data : 0,
          hart_response_ready, hart_control_active, hart_control_halt,
          hart_control_resume, hart_control_reset, hart_control_haltOnReset);
        clock = 1;
        #1 clock = 0;
        sample = sample + 1;
      end else if (fields != -1) $fatal(1, "Incomplete debug vector");
    end
    $fclose(file);
    $finish(0);
  end
endmodule
"""


def row(**values):
    defaults = dict.fromkeys(FIELDS, 0)
    defaults.update(ready=1, hart_ready=1, halted=1)
    if values.keys() - defaults.keys():
        raise ValueError("Unknown debug stimulus field")
    return tuple(values.get(name, defaults[name]) for name in FIELDS)


def command_error(word):
    kind, size = word >> 24, word >> 20 & 7
    if kind == 0:
        return 2 if word & 0x8C0000 or (word & 0x20000 and size != 2) else 0
    if kind == 2:
        return 2 if word & 0x8EFFFF or size > 2 else 0
    return 2


class Reference:
    def __init__(self):
        self.response = None
        self.held = None
        self.counts = Counter()
        self.clear()

    def clear(self):
        self.active = False
        self.halt = self.resume = self.resume_ack = self.halt_on_reset = self.ndmreset = self.have_reset = False
        self.data = [0, 0]
        self.error = 0
        self.command = None
        self.issued = False

    def read(self, address, state):
        if not self.active:
            return 0
        if address in (4, 5):
            return self.data[address - 4] if self.command is None else 0
        if address == 0x10:
            return 1 | int(self.ndmreset) << 1
        if address == 0x11:
            available = not state["unavailable"]
            return (0xA3 | int(available and state["halted"]) * 0x300 |
                    int(available and state["running"]) * 0xC00 | state["unavailable"] * 0x3000 |
                    int(self.resume_ack) * 0x30000 | int(self.have_reset) * 0xC0000 |
                    int(self.ndmreset or state["reset_pending"]) << 24)
        if address == 0x16:
            return 2 | self.error << 8 | int(self.command is not None) << 12
        return 0

    def step(self, values, cycle):
        if len(values) != len(FIELDS):
            raise AssertionError("Invalid debug stimulus width")
        state = dict(zip(FIELDS, values, strict=True))
        for name, value in state.items():
            bits = 7 if name == "address" else 2 if name == "op" else 32 if name in ("data", "result_data") else 3 if name == "result_error" else 1
            assert type(value) is int and 0 <= value < 1 << bits, "Invalid debug stimulus value"
        assert state["halted"] + state["running"] + state["unavailable"] == 1, "Hart state is not exclusive"
        request = (state["address"], state["op"], state["data"])
        if self.held is not None:
            assert state["valid"] and self.held == request, "DMI request changed under backpressure"
        ready = self.response is None
        busy = self.command is not None
        active = self.active
        error = self.error
        command = self.command
        offer = active and busy and command["transfer"] and not self.issued
        payload = command["payload"] if offer else (0,) * 6
        output = (cycle, int(ready), int(self.response is not None), *(self.response or (0, 0)), int(offer),
                  *payload, 1, int(active), int(active and self.halt), int(active and self.resume and not self.halt),
                  int(active and self.ndmreset), int(active and self.halt_on_reset))
        read_data = self.read(state["address"], state)
        self.held = request if state["valid"] and not ready else None
        if state["reset"]:
            assert not busy and self.response is None and not state["valid"], "Debug reset requires no owned transaction"
            self.clear()
            return output
        self.counts["responseBackpressure"] += int(self.response is not None and not state["ready"])
        self.counts["requestBackpressure"] += int(state["valid"] and not ready)
        self.counts["hartBackpressure"] += int(offer and not state["hart_ready"])
        self.counts["resetPendingCycles"] += int(active and state["reset_pending"])
        if self.response is not None and state["ready"]:
            self.response = None
            self.counts["dmiResponses"] += 1
        if offer and state["hart_ready"]:
            self.issued = True
            self.counts["hartRequests"] += 1
        if active and busy and not command["transfer"]:
            self.command = None
            self.counts["noTransfer"] += 1
        if state["result_valid"]:
            if active and busy and command["accepted"]:
                self.command = None
                self.issued = False
                if not error:
                    self.error = state["result_error"]
                if not command["payload"][1] and not state["result_error"]:
                    self.data[0] = state["result_data"]
                self.counts["hartResults"] += 1
            else:
                self.counts["unownedResults"] += 1
        if offer and state["hart_ready"]:
            command["accepted"] = True
        if active and self.resume and state["resume_ack"]:
            self.resume = False
            self.resume_ack = True
            self.counts["resumeAcks"] += 1
        accepted = state["valid"] and ready
        address, operation, data = request
        read, write = accepted and operation == 1, accepted and operation == 2
        control = write and address == 0x10
        conflict = active and busy and ((read or write) and address in (4, 5) or write and address in (0x16, 0x17, 0x18))
        if accepted:
            self.response = (read_data if operation == 1 else 0, 2 if operation == 3 else 0)
            self.counts["dmiRequests"] += 1
        if control:
            self.active = bool(data & 1)
            if active and data & 1:
                self.ndmreset = bool(data & 2)
                if not busy:
                    self.halt = bool(data >> 31)
                    if self.halt:
                        self.resume = False
                    if data & (1 << 30) and not self.halt:
                        self.resume_ack = False
                        self.resume = bool(state["halted"] and not state["unavailable"])
                        self.counts["resumeRunning"] += int(bool(state["running"]))
                    if data & (1 << 28):
                        self.have_reset = False
                    if data & 8:
                        self.halt_on_reset = True
                    if data & 4:
                        self.halt_on_reset = False
        if active and state["reset_event"]:
            self.have_reset = True
            self.counts["resetEvents"] += 1
        if active and write and not busy:
            if address in (4, 5):
                self.data[address - 4] = data
            elif address == 0x16:
                self.error &= ~(data >> 8 & 7)
            elif address == 0x17 and not error:
                failure = command_error(data)
                if failure:
                    self.error = failure
                    self.counts["unsupported"] += 1
                elif not state["halted"] or state["unavailable"]:
                    self.error = 4
                    self.counts["wrongState"] += 1
                else:
                    memory = data >> 24 == 2
                    self.command = {"payload": (int(memory), data >> 16 & 1, data >> 20 & 3,
                                                 data & 65535, self.data[1], self.data[0]),
                                    "transfer": memory or bool(data & 0x20000), "accepted": False}
                    self.issued = False
                    self.counts["commands"] += 1
        if conflict and not error:
            self.error = 1
            self.counts["busyConflicts"] += 1
        if not active or control and not data & 1:
            new_active = self.active
            if self.command is not None:
                self.counts["cancelled"] += 1
            self.clear()
            self.active = new_active
        return output


def expected(rows):
    reference = Reference()
    samples = [reference.step(values, cycle) for cycle, values in enumerate(rows)]
    return samples, dict(reference.counts) | {"pending": int(reference.command is not None or reference.response is not None)}


class Driver:
    def __init__(self, seed=1):
        self.random = random.Random(seed)
        self.reference = Reference()
        self.rows = []
        self.pending = None
        self.delay = 7
        self.next_error = 0
        self.ready = True
        self.state = dict(halted=1, running=0, unavailable=0, reset_pending=0)
        self.registers = dict.fromkeys(range(0x1000, 0x1020), 0) | {0x300: 0, 0x301: 0x40000100, 0x7B0: 0, 0x7B1: 0}
        self.memory = {}
        self.tick(reset=1)

    def result(self, request):
        memory, write, size, register, address, data = request
        if self.next_error:
            error, self.next_error = self.next_error, 0
            return 0, error
        if memory:
            if address % (1 << size):
                return 0, 3
            if address >= 0xFFFF0000:
                return 0, 5
            if write:
                for lane in range(1 << size):
                    self.memory[address + lane] = data >> (8 * lane) & 255
                return 0, 0
            return sum(self.memory.get(address + lane, 0) << (8 * lane) for lane in range(1 << size)), 0
        if register not in self.registers:
            return 0, 3
        if write:
            if register == 0x301:
                return 0, 3
            if register != 0x1000:
                self.registers[register] = data
            return 0, 0
        return self.registers[register], 0

    def tick(self, **overrides):
        cycle = len(self.rows)
        pending = self.pending
        result_valid = pending is not None and cycle >= pending["due"] and not pending["cancelled"]
        response = pending["response"] if result_valid else (0, 0)
        values = dict(self.state, hart_ready=int(self.ready and pending is None), result_valid=int(result_valid),
                      result_data=response[0], result_error=response[1])
        values.update(overrides)
        stimulus = row(**values)
        output = self.reference.step(stimulus, cycle)
        self.rows.append(stimulus)
        if pending is not None and cycle >= pending["due"]:
            self.pending = None
        if not output[13] and self.pending is not None:
            self.pending["cancelled"] = True
            if not self.pending["request"][0]:
                self.pending = None
        if output[5] and stimulus[6]:
            request = output[6:12]
            assert self.pending is None, "Fake hart accepted overlapping commands"
            self.pending = {"request": request, "response": self.result(request), "due": cycle + self.delay, "cancelled": False}
        return output

    def dmi(self, address, op=1, data=0, expected_data=None, stall=0):
        for _ in range(1000):
            output = self.tick(valid=1, address=address, op=op, data=data)
            if output[1]:
                break
        else:
            raise AssertionError("DMI request did not transfer")
        for _ in range(stall):
            self.tick(ready=0)
        for _ in range(1000):
            output = self.tick()
            if output[2]:
                if expected_data is not None:
                    assert output[3] == expected_data, f"Fixed DMI result differs at {address:#x}: {output[3]:#x}"
                return output[3:5]
        raise AssertionError("DMI response did not transfer")

    def drain(self):
        for _ in range(1000):
            if self.reference.command is None and self.reference.response is None and self.pending is None:
                return
            self.tick()
        raise AssertionError("Debug command did not drain")

    def clear_error(self):
        self.dmi(0x16, 2, 0x700)


def vectors(seed=1):
    driver = Driver(seed)
    driver.dmi(0x11, expected_data=0)
    driver.dmi(0x10, 2, 1, stall=3)
    driver.dmi(0x11, expected_data=0x3A3)
    driver.tick(valid=1, address=0x11, op=1, ready=0)
    for _ in range(3):
        driver.tick(valid=1, address=0x16, op=1, ready=0)
    driver.tick(valid=1, address=0x16, op=1)
    driver.tick(valid=1, address=0x16, op=1)
    driver.tick()
    driver.dmi(0x10, 2, 0x07FFFFC1)
    driver.dmi(0x10, expected_data=1)
    driver.dmi(0x16, expected_data=2)
    for address in sorted(set(range(128)) - {4, 5, 0x10, 0x11, 0x16, 0x17}):
        driver.dmi(address, 2, MASK)
        driver.dmi(address, expected_data=0)
    driver.dmi(0, 0)
    assert driver.dmi(0, 3) == (0, 2)
    for register in (*range(0x1000, 0x1020), 0x300, 0x7B0, 0x7B1):
        value = (register * 0x12345 + seed) & MASK
        driver.dmi(4, 2, value)
        driver.dmi(0x17, 2, 0x230000 | register)
        driver.drain()
        driver.dmi(0x16, expected_data=2)
        driver.dmi(0x17, 2, 0x220000 | register)
        driver.drain()
        driver.dmi(4, expected_data=0 if register == 0x1000 else value, stall=2)
    for size in range(3):
        driver.dmi(5, 2, 0x400 + (size * 4))
        driver.dmi(4, 2, 0xA9876543)
        driver.dmi(0x17, 2, 0x02010000 | size << 20)
        driver.drain()
        driver.dmi(0x17, 2, 0x02000000 | size << 20)
        driver.drain()
        driver.dmi(4, expected_data=0xA9876543 & ((1 << (8 << size)) - 1))
    for address, failure in ((0x401, 3), (0xFFFF0000, 5)):
        driver.dmi(5, 2, address)
        driver.dmi(0x17, 2, 0x02200000)
        driver.drain()
        driver.dmi(0x16, expected_data=2 | failure << 8)
        driver.clear_error()
    for word, failure in ((0x230301, 3), (0x220FFF, 3), (0x220020, 3), (0x221020, 3), (0x22FFFF, 3), (0x01000000, 2),
                          (0x230000 | 1 << 23, 2), (0x280000, 2), (0x260000, 2), (0x320000, 2),
                          (0x02800000, 2), (0x02300000, 2), (0x02080000, 2), (0x02020000, 2), (0x02000001, 2)):
        driver.dmi(0x17, 2, word)
        driver.drain()
        driver.dmi(0x16, expected_data=2 | failure << 8)
        driver.dmi(0x17, 2, 0x221000)
        driver.dmi(0x16, expected_data=2 | failure << 8)
        if failure == 3:
            driver.dmi(0x16, 2, 0x100)
            driver.dmi(0x16, expected_data=0x202)
        driver.clear_error()
    driver.next_error = 7
    driver.dmi(0x17, 2, 0x221001)
    driver.drain()
    driver.dmi(0x16, expected_data=0x702)
    driver.clear_error()
    driver.dmi(0x17, 2, 0x710FFF)
    driver.drain()
    driver.dmi(0x16, expected_data=2)
    driver.delay = 80
    driver.dmi(0x17, 2, 0x221001)
    for control in (0x80000001, 0x40000001, 0x10000001, 9, 5):
        driver.dmi(0x10, 2, control)
        assert not driver.reference.halt and not driver.reference.resume and not driver.reference.halt_on_reset
    driver.dmi(0x10, 2, 3)
    driver.dmi(0x10, expected_data=3)
    driver.dmi(0x10, 2, 1)
    driver.drain()
    driver.dmi(0x16, expected_data=2)
    for address, write in ((4, False), (4, True), (5, False), (5, True), (0x16, True), (0x17, True), (0x18, True)):
        driver.delay = 30
        driver.next_error = 5
        driver.dmi(0x17, 2, 0x221001)
        driver.dmi(0x16)
        driver.dmi(0x18, expected_data=0)
        driver.dmi(address, 2 if write else 1, MASK)
        driver.drain()
        driver.dmi(0x16, expected_data=0x102)
        driver.clear_error()
    driver.delay = 5
    driver.next_error = 3
    driver.dmi(0x17, 2, 0x221001)
    while len(driver.rows) < driver.pending["due"]:
        driver.tick()
    driver.dmi(0x18, 2, 0)
    driver.drain()
    driver.dmi(0x16, expected_data=0x102)
    driver.clear_error()
    driver.dmi(0x10, 2, 9)
    driver.dmi(0x10, 2, 3)
    driver.state.update(halted=0, unavailable=1, reset_pending=1)
    driver.dmi(0x11, expected_data=0x10030A3)
    driver.dmi(0x10, 2, 1)
    driver.dmi(0x11, expected_data=0x10030A3)
    driver.state.update(halted=1, unavailable=0, reset_pending=0)
    driver.tick(reset_event=1)
    driver.dmi(0x11, expected_data=0xC03A3)
    driver.dmi(0x10, 2, 0x10000001)
    driver.dmi(0x11, expected_data=0x3A3)
    driver.dmi(0x10, 2, 5)
    driver.dmi(0x10, 2, 0x80000001)
    driver.dmi(0x10, expected_data=1)
    driver.dmi(0x10, 2, 0xC0000001)
    assert not driver.reference.resume
    driver.dmi(0x10, 2, 0x40000001)
    driver.tick(resume_ack=1)
    driver.state.update(halted=0, running=1)
    driver.dmi(0x11, expected_data=0x30CA3)
    driver.dmi(0x10, 2, 0x40000001)
    driver.dmi(0x11, expected_data=0xCA3)
    driver.dmi(0x17, 2, 0x221001)
    driver.dmi(0x16, expected_data=0x402)
    driver.clear_error()
    driver.state.update(halted=1, running=0)
    driver.ready = False
    driver.dmi(0x17, 2, 0x221001)
    driver.tick()
    driver.dmi(0x10, 2, 0, stall=5)
    driver.dmi(0x10, 2, 1)
    driver.ready = True
    driver.tick(result_valid=1, result_data=0xBAD, result_error=0)
    driver.dmi(4, expected_data=0)
    driver.delay = 25
    driver.dmi(5, 2, 0x500)
    driver.dmi(0x17, 2, 0x02200000)
    driver.dmi(0x10, 2, 0)
    driver.dmi(0x10, 2, 1)
    driver.dmi(0x17, 2, 0x221001)
    driver.drain()
    driver.dmi(4, expected_data=driver.registers[0x1001])
    driver.delay = 30
    driver.dmi(4, 2, 0x13579BDF)
    driver.dmi(5, 2, 0x504)
    driver.dmi(0x17, 2, 0x02210000)
    driver.dmi(0x10, 2, 0)
    driver.dmi(0x10, 2, 1)
    driver.dmi(5, 2, 0x504)
    driver.dmi(0x17, 2, 0x02200000)
    driver.drain()
    driver.dmi(4, expected_data=0x13579BDF)
    driver.delay = 6
    driver.dmi(0x17, 2, 0x221001)
    while len(driver.rows) < driver.pending["due"]:
        driver.tick()
    driver.dmi(0x10, 2, 0, stall=3)
    driver.dmi(0x10, 2, 1)
    driver.dmi(4, expected_data=0)
    for _ in range(256):
        driver.delay = driver.random.randrange(2, 13)
        register = driver.random.randrange(0x1000, 0x1020)
        value = driver.random.getrandbits(32)
        driver.dmi(4, 2, value, stall=driver.random.randrange(4))
        driver.dmi(0x17, 2, 0x230000 | register)
        driver.drain()
        driver.dmi(0x17, 2, 0x220000 | register)
        driver.drain()
        driver.dmi(4, expected_data=0 if register == 0x1000 else value, stall=driver.random.randrange(4))
    driver.drain()
    driver.tick()
    return driver.rows


def parse_trace(trace):
    result = []
    for line in trace.splitlines():
        fields = line.split()
        assert len(fields) == 18, "Debug trace field count mismatch"
        result.append(tuple(int(value, 16 if index in HEX_OUTPUT else 10) for index, value in enumerate(fields)))
    return result


def check(rows, trace):
    wanted, counts = expected(rows)
    observed = parse_trace(trace)
    assert len(wanted) == len(observed), "Debug sample count mismatch"
    for actual, target in zip(observed, wanted, strict=True):
        assert actual == target, f"Debug transaction mismatch at cycle {target[0]}: {actual} != {target}"
    assert not counts["pending"] and counts["dmiRequests"] == counts["dmiResponses"], "Debug transactions did not drain"
    return counts


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def build(output):
    output = Path(output)
    names = ["ditdah_e2/src/Parameters.scala", "ditdah_e2/src/Interfaces.scala", "ditdah_e2/src/DebugInterfaces.scala",
             "ditdah_e2/src/DebugModule.scala", "test/debug_module.py", "test/test_debug_module.py", "flake.nix", "flake.lock"]
    names += [str(path.relative_to(ROOT)) for path in sorted((ROOT / "nix").glob("*.nix"))]
    contents = {name: (ROOT / name).read_bytes() for name in names}
    for name, data in contents.items():
        path = output / "inputs" / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
    tools = {name: Path(shutil.which(name)).resolve() for name in ("elaborate-ditdah-e2", "firld", "firtool", "iverilog", "vvp")}
    commands = []
    with tempfile.TemporaryDirectory(prefix="ditdah-e2-debug-build-", dir="/data/tmp") as directory:
        work = Path(directory)
        (work / "src").mkdir()
        for name, data in contents.items():
            if name.endswith(".scala"):
                (work / "src" / Path(name).name).write_bytes(data)
        (work / "src/Top.scala").write_text(WRAPPER)
        (work / "parameters.json").write_text("{}\n")
        (work / "debug_tb.sv").write_text(HARNESS)
        for name in ("src/Top.scala", "parameters.json", "debug_tb.sv"):
            target = output / "inputs/generated" / name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(work / name, target)
        environment = dict(os.environ, DITDAH_E2_SOURCE=str(work / "src"))
        commands_to_run = [["elaborate-ditdah-e2", "design", "parameters.json"]]
        for number in range(3):
            if number == 1:
                commands_to_run.append(["firld", *[path.name for path in sorted(work.glob("*.mlirbc"))],
                                        "--base-circuit", "DitDahE2DebugTest", "--no-mangle", "--emit-bytecode", "-o", "linked.mlirbc"])
            elif number == 2:
                commands_to_run.append(["firtool", "linked.mlirbc", "--split-verilog", "-disable-all-randomization",
                                        "--lowering-options=noAlwaysComb,disallowLocalVariables,locationInfoStyle=none", "-o", "rtl"])
            command = commands_to_run[number]
            result = subprocess.run(command, cwd=work, env=environment, text=True, capture_output=True)
            commands.append({"argv": command, "exitStatus": result.returncode})
            (output / f"build-{number}.log").write_text(result.stdout + result.stderr)
            (output / "commands.json").write_text(json.dumps(commands, indent=2) + "\n")
            if result.returncode:
                raise RuntimeError(f"Debug generation failed in command {number}")
        shutil.copytree(work / "rtl", output / "rtl")
    report = {"exitStatus": 0, "parameters": {}, "commands": commands,
              "inputHashes": {name: hashlib.sha256(data).hexdigest() for name, data in contents.items()},
              "generatedHashes": {str(path.relative_to(output / "inputs")): digest(path)
                                  for path in (output / "inputs/generated").rglob("*") if path.is_file()},
              "rtlHashes": {path.name: digest(path) for path in (output / "rtl").glob("*.sv")},
              "toolHashes": {name: digest(path) for name, path in tools.items()},
              "toolVersions": {name: subprocess.check_output(command, text=True, stderr=subprocess.STDOUT).strip()
                               for name, command in {"firtool": ["firtool", "--version"], "iverilog": ["iverilog", "-V"]}.items()}}
    (output / "build.json").write_text(json.dumps(report, indent=2) + "\n")
    return report


def simulate(output, rows, rtl, commands):
    output.mkdir(parents=True)
    (output / "vectors.txt").write_text("".join(" ".join(f"{value:x}" if index in HEX_INPUT else str(value)
                                                      for index, value in enumerate(row)) + "\n" for row in rows))
    (output / "debug_tb.sv").write_text(HARNESS)
    shutil.copyfile(rtl, output / "DitDahE2DebugModule.sv")
    for command in (["iverilog", "-g2012", "-s", "DebugBench", "-o", "debug-sim", "DitDahE2DebugModule.sv", "debug_tb.sv"],
                    ["vvp", "debug-sim"]):
        result = subprocess.run(command, cwd=output, capture_output=True, text=True)
        commands.append({"directory": output.name, "argv": command, "exitStatus": result.returncode})
        if result.returncode:
            raise RuntimeError(result.stdout + result.stderr)
    (output / "simulation.log").write_text(result.stdout)
    trace = "\n".join(line for line in result.stdout.splitlines() if line and line[0].isdigit()) + "\n"
    (output / "debug.trace").write_text(trace)
    return trace


def busy_mutant(rtl):
    pattern = r"(error\s*<=\s*)3'h1(;)"
    if len(re.findall(pattern, rtl)) != 1:
        raise ValueError("Debug busy error assignment changed")
    return re.sub(pattern, r"\g<1>3'h5\2", rtl)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=Path("result/debug-module"))
    args = parser.parse_args()
    if args.output.exists() and any(args.output.iterdir()):
        raise ValueError("Debug output directory must be empty")
    report = build(args.output)
    commands, runs = [], []
    for seed in (1, 19, 83):
        rows = vectors(seed)
        directory = args.output / f"seed-{seed}"
        trace = simulate(directory, rows, args.output / "rtl/DitDahE2DebugModule.sv", commands)
        counts = check(rows, trace)
        for field in ("responseBackpressure", "requestBackpressure", "hartBackpressure", "busyConflicts", "cancelled", "unownedResults",
                      "resetPendingCycles", "resetEvents", "resumeRunning", "resumeAcks", "unsupported", "wrongState", "noTransfer"):
            assert counts[field] > 0, f"Missing debug coverage: {field}"
        runs.append({"seed": seed, "cycles": len(rows), **counts, "traceHash": digest(directory / "debug.trace"),
                     "vectorsHash": digest(directory / "vectors.txt")})
    mutant = args.output / "busy-mutant.sv"
    mutant.write_text(busy_mutant((args.output / "rtl/DitDahE2DebugModule.sv").read_text()))
    rows = vectors(1)
    trace = simulate(args.output / "busy-mutant", rows, mutant, commands)
    try:
        check(rows, trace)
    except AssertionError as error:
        reason = str(error)
    else:
        raise AssertionError("Debug checker accepted incorrect busy priority")
    wanted, _ = expected(rows)
    observed = parse_trace(trace)
    witness = next(index for index, (actual, target) in enumerate(zip(observed, wanted, strict=True))
                   if actual[2] and target[3] == 0x102 and actual[3] == 0x502)
    control = {"mutation": "busy conflict reports bus error", "exitStatus": 0, "cycle": witness,
               "rejected": reason, "rtlHash": digest(mutant), "traceHash": digest(args.output / "busy-mutant/debug.trace")}
    assert all(digest(ROOT / name) == value for name, value in report["inputHashes"].items()), "Debug inputs changed"
    assert all(digest(args.output / "rtl" / name) == value for name, value in report["rtlHashes"].items()), "Debug RTL changed"
    summary = {"scope": "single hart debug module with fake hart", "exitStatus": 0,
               "command": ["python3", "test/debug_module.py", "--output", str(args.output)],
               "buildHash": digest(args.output / "build.json"),
               "commands": commands, "runs": runs, "negativeControls": [control],
               "excluded": ["core integration", "full Debug 1.0 conformance", "physical transport", "formal proof"]}
    (args.output / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    print(f"PASS: {sum(run['cycles'] for run in runs)} debug cycles and one RTL negative control")


if __name__ == "__main__":
    main()
