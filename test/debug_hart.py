# SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
# SPDX-License-Identifier: MIT
"""Check debug hart control, register effects and native transaction draining."""

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
INPUTS = (("reset", "reset", 1), ("active", "debug_control_active", 1), ("halt", "debug_control_halt", 1),
          ("resume", "debug_control_resume", 1), ("warm_reset", "debug_control_reset", 1),
          ("halt_on_reset", "debug_control_haltOnReset", 1), ("empty", "core_empty", 1),
          ("fetch_idle", "core_fetchIdle", 1), ("pc", "core_architecturalPc", 32), ("user", "core_userMode", 1),
          ("completed", "core_completed", 1), ("breakpoint", "core_breakpoint", 1), ("break_pc", "core_breakpointPc", 32),
          ("valid", "debug_request_valid", 1), ("memory", "debug_request_bits_memory", 1),
          ("write", "debug_request_bits_write", 1), ("size", "debug_request_bits_size", 2),
          ("register", "debug_request_bits_register", 16), ("address", "debug_request_bits_address", 32),
          ("data", "debug_request_bits_data", 32), ("ready", "debug_response_ready", 1),
          ("backend_data", "backend_readData", 32), ("backend_error", "backend_error", 1),
          ("allowed", "protection_allowed", 1), ("machine", "protection_machine", 1),
          ("bus_ready", "memory_request_ready", 1), ("bus_valid", "memory_response_valid", 1),
          ("bus_data", "memory_response_bits_data", 32), ("bus_fault", "memory_response_bits_fault", 1))
OUTPUTS = (("ready", "debug_request_ready", 1), ("valid", "debug_response_valid", 1),
           ("data", "debug_response_bits_data", 32), ("error", "debug_response_bits_error", 3),
           ("halted", "debug_status_halted", 1), ("running", "debug_status_running", 1),
           ("unavailable", "debug_status_unavailable", 1), ("reset_event", "debug_status_resetEvent", 1),
           ("resume_ack", "debug_status_resumeAck", 1), ("reset_pending", "debug_status_resetPending", 1),
           ("stop", "core_stop", 1), ("resume", "core_resume", 1), ("pc", "core_resumePc", 32),
           ("user", "core_resumeUser", 1), ("core_reset", "core_coreReset", 1), ("step", "core_singleStep", 1),
           ("ebreak_m", "core_ebreakMachine", 1), ("ebreak_u", "core_ebreakUser", 1),
           ("freeze", "core_freezeCounters", 1), ("register", "backend_register", 16),
           ("write_requested", "backend_writeRequested", 1), ("write_pulse", "backend_writePulse", 1),
           ("write_data", "backend_writeData", 32), ("query_address", "protection_address", 32),
           ("query_size", "protection_size", 2), ("query_write", "protection_write", 1),
           ("bus_valid", "memory_request_valid", 1), ("bus_address", "memory_request_bits_address", 32),
           ("bus_machine", "memory_request_bits_machine", 1), ("bus_write", "memory_request_bits_write", 1),
           ("bus_data", "memory_request_bits_data", 32), ("bus_mask", "memory_request_bits_mask", 4),
           ("bus_size", "memory_request_bits_size", 2), ("bus_ready", "memory_response_ready", 1))
WRAPPER = """// SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
// SPDX-License-Identifier: MIT
package ditdah_e2
import me.jiuyang.zaozi.*
import me.jiuyang.zaozi.default.{*, given}
import me.jiuyang.zaozi.reftpe.*
import me.jiuyang.zaozi.valuetpe.*
@generator
object DitDahE2 extends Generator[DebugHartParameters, DebugHartLayers, DebugHartIO, DebugHartProbe]:
  override def moduleName(p: DebugHartParameters): String = "DitDahE2DebugHartTest"
  def architecture(p: DebugHartParameters) =
    val io = summon[Interface[DebugHartIO]]
    val hart = DebugHart.instantiate(p)
    hart.io.clock := io.clock
    hart.io.reset := io.reset
    hart.io.debug :<>= io.debug
    io.core :<>= hart.io.core
    io.backend :<>= hart.io.backend
    io.protection :<>= hart.io.protection
    io.memory :<>= hart.io.memory
"""


def harness():
    declarations = [f"  reg {'[' + str(width - 1) + ':0] ' if width > 1 else ''}{name} = {int(name == 'reset')};"
                    for _, name, width in INPUTS]
    declarations += [f"  wire {'[' + str(width - 1) + ':0] ' if width > 1 else ''}{name};" for _, name, width in OUTPUTS]
    values = []
    for _, name, _ in OUTPUTS:
        valid = "debug_response_valid" if name.startswith("debug_response_bits_") else \
                "memory_request_valid" if name.startswith("memory_request_bits_") else None
        values.append(f"{valid} ? {name} : 0" if valid else name)
    return """// SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
// SPDX-License-Identifier: MIT
module DebugHartBench;
  reg clock = 0;
""" + "\n".join(declarations) + """
  integer file, fields, sample = 0;
  DitDahE2DebugHart dut(.*);
  initial begin
    #1 clock = 1;
    #1 clock = 0;
    file = $fopen("vectors.txt", "r");
    if (!file) $fatal(1, "Cannot open debug hart vectors");
    while (!$feof(file)) begin
""" + '      fields = $fscanf(file, "' + " ".join(["%h"] * len(INPUTS)) + '\\n", ' + \
        ", ".join(name for _, name, _ in INPUTS) + ");\n" + \
        f"      if (fields == {len(INPUTS)}) begin\n" + '        #1 $display("%0d ' + \
        " ".join(["%h"] * len(OUTPUTS)) + '", sample, ' + ", ".join(values) + ");\n" + """
        clock = 1;
        #1 clock = 0;
        sample = sample + 1;
      end else if (fields != -1) $fatal(1, "Incomplete debug hart vector");
    end
    $fclose(file);
    $finish(0);
  end
endmodule
"""


def configuration(value):
    if not isinstance(value, dict) or value.keys() - {"resetVector", "enableC", "protectedMode"}:
        raise ValueError("Invalid debug hart configuration fields")
    result = {"resetVector": value.get("resetVector", 0), "enableC": value.get("enableC", False),
              "protectedMode": value.get("protectedMode", False)}
    if type(result["resetVector"]) is not int or not 0 <= result["resetVector"] <= MASK:
        raise ValueError("Debug reset vector must fit RV32")
    if any(type(result[name]) is not bool for name in ("enableC", "protectedMode")):
        raise ValueError("Debug feature values must be Boolean")
    if result["resetVector"] % (2 if result["enableC"] else 4):
        raise ValueError("Debug reset vector must satisfy instruction alignment")
    return result


def row(**values):
    defaults = dict.fromkeys((name for name, _, _ in INPUTS), 0)
    defaults.update(active=1, empty=1, fetch_idle=1, size=2, ready=1, allowed=1, machine=1, bus_ready=1)
    if values.keys() - defaults.keys():
        raise ValueError("Unknown debug hart stimulus field")
    return tuple(values.get(name, defaults[name]) for name, _, _ in INPUTS)


class Reference:
    def __init__(self, parameters=None):
        self.parameters = configuration(parameters or {})
        self.halted = False
        self.pending_halt = None
        self.break_pc = 0
        self.step_enabled = self.stepping = self.ebreak_m = self.ebreak_u = self.user = False
        self.cause = 0
        self.pc = self.parameters["resetVector"]
        self.reset_phase = None
        self.reset_event = self.resume_ack = False
        self.response = None
        self.owner = False
        self.native = None
        self.held = None
        self.counts = Counter()

    def status(self):
        return (0x40000410 | (0 if self.user else 3) | int(self.step_enabled) << 2 |
                self.cause << 6 | int(self.ebreak_u) << 12 | int(self.ebreak_m) << 15)

    def step(self, values, cycle):
        assert len(values) == len(INPUTS), "Invalid debug hart stimulus width"
        state = dict(zip((name for name, _, _ in INPUTS), values, strict=True))
        assert all(type(value) is int and 0 <= value < 1 << width for value, (_, _, width) in zip(values, INPUTS, strict=True)), "Invalid debug hart stimulus value"
        assert not (state["completed"] and state["breakpoint"]), "Debug breakpoint cannot retire"
        active = bool(state["active"])
        request = tuple(state[name] for name in ("memory", "write", "size", "register", "address", "data"))
        if active and self.held is not None:
            assert state["valid"] and request == self.held, "Abstract request changed before acceptance"
        reset_request = active and state["warm_reset"]
        resetting = self.reset_phase == "asserted"
        reset_busy = bool(reset_request or self.reset_phase is not None)
        halt_request = active and state["halt"]
        reasons = [] if self.pending_halt is None else [self.pending_halt]
        if self.stepping and state["completed"]:
            reasons.append("step")
        if state["breakpoint"]:
            reasons.append("breakpoint")
        if halt_request:
            reasons.append("halt")
        priority = {"step": 0, "breakpoint": 1, "halt": 2}
        reason = max(reasons, key=priority.get) if reasons else None
        response = self.response
        native = self.native
        halted = self.halted
        old_status, old_pc = self.status(), self.pc
        ready = active and response is None and native is None and not reset_busy and not state["resume"]
        accepted = ready and state["valid"]
        valid = response is not None and active
        resume = active and state["resume"] and self.halted and not halt_request and not reset_busy and response is None and native is None
        local = state["register"] in (0x7B0, 0x7B1)
        legal_size = state["size"] <= 2 if state["memory"] else state["size"] == 2
        write_pulse = accepted and self.halted and legal_size and not state["memory"] and not local and state["write"] and not state["backend_error"]
        new_offer = active and not reset_busy
        bus_valid = native is not None and native["stage"] == "offer" and (native["offered"] or new_offer)
        bus_ready = native is not None and native["stage"] == "wait"
        result = {"ready": ready, "valid": valid, "data": response[0] if valid else 0, "error": response[1] if valid else 0,
                  "halted": self.halted and not reset_busy, "running": not self.halted and not reset_busy,
                  "unavailable": reset_busy, "reset_event": self.reset_event, "resume_ack": self.resume_ack,
                  "reset_pending": reset_busy, "stop": self.halted or reason is not None or reset_busy,
                  "resume": resume, "pc": self.pc, "user": self.user, "core_reset": resetting, "step": self.stepping,
                  "ebreak_m": self.ebreak_m, "ebreak_u": self.ebreak_u,
                  "freeze": self.halted or bool(state["breakpoint"]) or self.pending_halt == "breakpoint",
                  "register": state["register"], "write_requested": not state["memory"] and state["write"],
                  "write_pulse": write_pulse, "write_data": state["data"], "query_address": state["address"],
                  "query_size": state["size"], "query_write": state["write"], "bus_valid": bus_valid, "bus_ready": bus_ready}
        payload = native["request"] if bus_valid else (0,) * 6
        result.update(zip(("bus_address", "bus_machine", "bus_write", "bus_data", "bus_mask", "bus_size"), payload, strict=True))
        output = (cycle, *(int(result[name]) for name, _, _ in OUTPUTS))
        self.held = request if active and state["valid"] and not ready else None
        if state["reset"]:
            assert not self.owner and native is None and not state["valid"] and not state["bus_valid"], "Cold reset with debug traffic"
            counts = self.counts
            self.__init__(self.parameters)
            self.counts = counts
            self.counts["coldResets"] += 1
            return output
        self.counts["abstractStalls"] += int(state["valid"] and not ready)
        self.counts["responseStalls"] += int(valid and not state["ready"])
        self.counts["memoryStalls"] += int(bus_valid and not state["bus_ready"])
        self.counts["resetDrainCycles"] += int(reset_busy and not resetting)
        self.reset_event = self.resume_ack = False
        if not self.halted and reason is not None and not reset_busy:
            self.pending_halt = reason
            if state["breakpoint"]:
                self.break_pc = state["break_pc"]
            if state["empty"] and state["fetch_idle"]:
                self.halted = True
                self.pending_halt = None
                self.stepping = False
                self.cause = {"halt": 3, "step": 4, "breakpoint": 1}[reason]
                self.user = bool(state["user"] and self.parameters["protectedMode"])
                self.pc = self.break_pc if reason == "breakpoint" else state["pc"]
                self.counts["haltCause" + str(self.cause)] += 1
        if resume:
            self.halted = False
            self.pending_halt = None
            self.stepping = self.step_enabled
            self.resume_ack = True
            self.counts["resumes"] += 1
        if valid and state["ready"]:
            self.response = None
            self.owner = False
            self.counts["responses"] += 1
        if accepted:
            self.owner = True
            self.response = (0, 2 if not legal_size else 4 if not halted else 0)
            self.counts["requests"] += 1
            if legal_size and halted:
                if not state["memory"]:
                    error = 3 if not local and state["backend_error"] else 0
                    value = old_status if state["register"] == 0x7B0 else old_pc if local else state["backend_data"]
                    self.response = (value if not state["write"] and not error else 0, error)
                    if state["write"] and state["register"] == 0x7B0:
                        self.step_enabled = bool(state["data"] & 4)
                        self.ebreak_m = bool(state["data"] & 0x8000)
                        self.ebreak_u = bool(self.parameters["protectedMode"] and state["data"] & 0x1000)
                        self.user = bool(self.parameters["protectedMode"] and state["data"] & 3 == 0)
                    elif state["write"] and state["register"] == 0x7B1:
                        self.pc = state["data"] & (0xFFFFFFFE if self.parameters["enableC"] else 0xFFFFFFFC)
                else:
                    self.response = (0, 3)
                    if state["address"] % (1 << state["size"]) == 0 and state["allowed"]:
                        lane = state["address"] % 4
                        mask = ((1 << (1 << state["size"])) - 1) << lane if state["write"] else 0
                        self.native = {"stage": "offer", "offered": False,
                                       "request": (state["address"], state["machine"], state["write"],
                                                   state["data"] << (lane * 8) & MASK, mask, state["size"])}
                        self.response = None
                    else:
                        self.counts["localMemoryFaults"] += 1
        if bus_valid:
            if state["bus_ready"]:
                native["stage"] = "wait"
                native["offered"] = False
                self.counts["memoryRequests"] += 1
            else:
                native["offered"] = True
        if native is not None and native["stage"] == "offer" and not native["offered"] and not new_offer:
            self.native = None
            if self.owner and active:
                self.response = (0, 4)
        if state["bus_valid"]:
            assert bus_ready, "Native response lacks an accepted request"
            self.native = None
            self.counts["memoryResponses"] += 1
            if self.owner and active:
                address, _, write, _, _, size = native["request"]
                error = 4 if reset_busy else 5 if state["bus_fault"] else 0
                value = state["bus_data"] >> (8 * (address % 4)) & ((1 << (8 << size)) - 1)
                self.response = (0 if write or error else value, error)
                self.counts["busFaults"] += int(bool(state["bus_fault"]))
            else:
                self.counts["discardedMemoryResults"] += 1
        if not active:
            if self.owner:
                self.counts["cancelled"] += 1
            self.owner = False
            self.response = None
        if reset_request and self.reset_phase is None:
            self.reset_phase = "drain"
        if reset_busy and not resetting and state["empty"] and state["fetch_idle"] and native is None:
            self.reset_phase = "asserted"
            self.halted = self.stepping = self.step_enabled = self.ebreak_m = self.ebreak_u = self.user = False
            self.pending_halt = None
            self.cause = 0
            self.pc = self.parameters["resetVector"]
            self.counts["resetAssertions"] += 1
        if resetting and not reset_request:
            self.reset_phase = None
            self.reset_event = True
            self.halted = bool(halt_request or active and state["halt_on_reset"])
            if self.halted:
                self.cause = 5 if state["halt_on_reset"] else 3
                self.counts["haltCause" + str(self.cause)] += 1
        return output


def expected(rows, parameters=None):
    reference = Reference(parameters)
    samples = [reference.step(values, cycle) for cycle, values in enumerate(rows)]
    return samples, dict(reference.counts) | {"pending": int(reference.owner or reference.response is not None or reference.native is not None)}


def unpack(output):
    return dict(zip((name for name, _, _ in OUTPUTS), output[1:], strict=True))


class Driver:
    def __init__(self, parameters=None, seed=1):
        self.reference = Reference(parameters)
        self.random = random.Random(seed)
        self.rows = []
        self.inputs = dict(active=1, pc=0x1000, user=0, bus_ready=1)
        self.registers = {index: (index * 0x10101) & MASK for index in range(0x1000, 0x1020)}
        self.registers[0x1000] = 0
        self.registers.update({0x300: 0x1800, 0xF11: 0})
        self.memory = {0x400 + lane: byte for lane, byte in enumerate(bytes.fromhex("017fff80"))}
        self.peer = None
        self.delay = 5
        self.random_stalls = False
        self.tick(reset=1, active=0)

    def tick(self, **overrides):
        values = dict(self.inputs)
        if self.random_stalls:
            values["bus_ready"] = int(self.random.randrange(4) != 0)
        values.update(overrides)
        if self.peer is not None and len(self.rows) >= self.peer["due"]:
            values.update(bus_valid=1, bus_data=self.peer["data"], bus_fault=self.peer["fault"])
        register = values.get("register", 0)
        if register not in (0x7B0, 0x7B1):
            values.setdefault("backend_data", self.registers.get(register, 0))
            values.setdefault("backend_error", int(register not in self.registers or bool(values.get("write", 0) and register == 0xF11)))
        stimulus = row(**values)
        output = self.reference.step(stimulus, len(self.rows))
        self.rows.append(stimulus)
        observed = unpack(output)
        if observed["write_pulse"] and register != 0x1000:
            self.registers[register] = observed["write_data"]
        if observed["bus_ready"] and stimulus[26]:
            self.peer = None
        if observed["bus_valid"] and stimulus[25]:
            assert self.peer is None, "Peer saw overlapping native requests"
            address = observed["bus_address"]
            aligned = address & ~3
            fault = int(address >= 0xFFFF0000)
            if observed["bus_write"] and not fault:
                for lane in range(4):
                    if observed["bus_mask"] >> lane & 1:
                        self.memory[aligned + lane] = observed["bus_data"] >> (8 * lane) & 255
            data = sum(self.memory.get(aligned + lane, 0) << (8 * lane) for lane in range(4))
            self.peer = {"data": data, "fault": fault, "due": len(self.rows) - 1 + self.delay}
        return observed

    def command(self, *, expected_result=None, stall=0, **request):
        for _ in range(1000):
            result = self.tick(valid=1, **request)
            if result["ready"]:
                break
        else:
            raise AssertionError("Abstract request did not transfer")
        for _ in range(stall):
            self.tick(ready=0)
        for _ in range(1000):
            result = self.tick()
            if result["valid"]:
                value = result["data"], result["error"]
                if expected_result is not None:
                    assert value == expected_result, f"Fixed abstract result differs: {value} != {expected_result}"
                return value
        raise AssertionError("Abstract response did not transfer")

    def halt(self, pc=0x1000, user=False):
        self.inputs.update(pc=pc, user=int(user))
        self.tick(halt=1, empty=0, fetch_idle=0)
        self.tick(empty=1, fetch_idle=0)
        self.tick()
        assert self.reference.halted and self.reference.pc == pc

    def resume(self):
        result = self.tick(resume=1)
        assert result["resume"], "Hart did not resume"
        self.inputs.update(pc=result["pc"], user=result["user"])
        self.tick()


def vectors(parameters, seed=1):
    driver = Driver(parameters, seed)
    protected = parameters["protectedMode"]
    driver.command(register=0x1001, expected_result=(0, 4))
    driver.halt(user=protected)
    initial = 0x400004D0 | (0 if protected else 3)
    driver.command(register=0x7B0, expected_result=(initial, 0), backend_error=1)
    driver.command(register=0x7B1, expected_result=(0x1000, 0))
    driver.command(register=0x7B0, write=1, data=MASK)
    driver.command(register=0x7B0, expected_result=(0x400084D7 | (0x1000 if protected else 0), 0))
    driver.command(register=0x7B1, write=1, data=MASK)
    driver.command(register=0x7B1, expected_result=(0xFFFFFFFE if parameters["enableC"] else 0xFFFFFFFC, 0))
    for mode in range(4):
        driver.command(register=0x7B0, write=1, data=mode)
        driver.command(register=0x7B0, expected_result=(0x400004D0 | (0 if protected and mode == 0 else 3), 0))
    driver.command(register=0x7B1, write=1, data=0x1000)
    for register in (*range(0x1000, 0x1020), 0x300):
        value = driver.random.getrandbits(32)
        driver.command(register=register, write=1, data=value)
        driver.command(register=register, expected_result=(driver.registers[register], 0), stall=2)
    for register in (0xF11, 0xFFF, 0x1020):
        driver.command(register=register, write=1, data=MASK, expected_result=(0, 3))
    for size in (0, 1, 3):
        driver.command(register=0x7B0, size=size, write=1, data=MASK, expected_result=(0, 2))
    for size, address, value in ((0, 0x403, 128), (1, 0x402, 0x80FF), (2, 0x400, 0x80FF7F01)):
        driver.command(memory=1, address=address, size=size, expected_result=(value, 0), stall=3)
    for size in range(3):
        driver.command(memory=1, address=0x410, size=size, write=1, data=0x87654321)
        driver.command(memory=1, address=0x410, size=size, expected_result=(0x87654321 & ((1 << (8 << size)) - 1), 0))
    for request, error in ((dict(size=3, address=0x400), 2), (dict(size=1, address=0x401), 3),
                           (dict(size=2, address=0x402), 3), (dict(size=2, address=0x400, allowed=0), 3),
                           (dict(size=2, address=0xFFFF0000), 5)):
        driver.command(memory=1, expected_result=(0, error), **request)
    driver.command(register=0x7B0, write=1, data=4)
    driver.resume()
    driver.tick(empty=0, fetch_idle=0)
    result = driver.tick(completed=1, empty=0, fetch_idle=0)
    assert result["stop"] and result["step"]
    driver.inputs["pc"] = 0x1800
    driver.tick(fetch_idle=0)
    driver.tick()
    driver.command(register=0x7B0, expected_result=(0x40000514, 0) if protected else (0x40000517, 0))
    driver.command(register=0x7B1, expected_result=(0x1800, 0))
    driver.command(register=0x7B0, write=1, data=0x9003)
    driver.resume()
    driver.tick(breakpoint=1, break_pc=0x1880, empty=0, fetch_idle=0)
    driver.inputs["pc"] = 0x1884
    driver.tick()
    driver.command(register=0x7B1, expected_result=(0x1880, 0))
    driver.command(register=0x7B0, expected_result=(0x40008453 | (0x1000 if protected else 0), 0))
    driver.resume()
    driver.tick(halt=1, breakpoint=1, break_pc=0x1900, empty=0, fetch_idle=0)
    driver.inputs["pc"] = 0x1900
    driver.tick()
    driver.command(register=0x7B0, expected_result=(0x400084D3 | (0x1000 if protected else 0), 0))
    driver.inputs["bus_ready"] = 0
    driver.tick(valid=1, memory=1, write=1, address=0x420, data=0xAABBCCDD, machine=0 if protected else 1)
    driver.tick()
    driver.tick(active=0, allowed=0, machine=1)
    driver.tick(active=1, allowed=0, valid=1, register=0x1001)
    driver.inputs["bus_ready"] = 1
    driver.command(register=0x1001, expected_result=(driver.registers[0x1001], 0))
    driver.command(memory=1, address=0x420, expected_result=(0xAABBCCDD, 0))
    driver.tick(valid=1, memory=1, address=0x400)
    driver.tick()
    while len(driver.rows) < driver.peer["due"]:
        driver.tick()
    driver.tick(active=0)
    driver.tick()
    assert driver.reference.response is None and driver.reference.native is None
    driver.tick(valid=1, memory=1, address=0x400)
    driver.tick(active=0)
    driver.tick()
    assert driver.reference.native is None and not driver.reference.owner
    driver.delay = 10
    driver.tick(valid=1, memory=1, address=0x400)
    driver.tick()
    driver.tick(warm_reset=1, halt_on_reset=1, empty=0, fetch_idle=0, ready=0)
    driver.inputs.update(halt_on_reset=1, warm_reset=0)
    for _ in range(driver.delay + 1):
        driver.tick(empty=0, fetch_idle=0, ready=0)
    assert driver.reference.response == (0, 4)
    driver.tick(fetch_idle=0, ready=0)
    driver.tick(ready=0)
    driver.tick(ready=0)
    driver.tick(ready=0)
    result = driver.tick()
    assert (result["data"], result["error"]) == (0, 4)
    driver.command(register=0x7B0, expected_result=(0x40000553, 0))
    driver.command(register=0x7B1, expected_result=(parameters["resetVector"], 0))
    driver.inputs.update(halt_on_reset=0)
    driver.tick(valid=1, register=0x1001, ready=0)
    held_response = driver.reference.response
    driver.tick(warm_reset=1, ready=0)
    for _ in range(4):
        result = driver.tick(warm_reset=1, ready=0)
        assert result["core_reset"] and result["reset_pending"] and not result["reset_event"]
        assert (result["data"], result["error"]) == held_response
    driver.tick(halt=1, ready=0)
    result = driver.tick(ready=0)
    assert result["reset_event"] and result["halted"]
    driver.tick()
    driver.command(register=0x7B0, expected_result=(0x400004D3, 0))
    driver.inputs["bus_ready"] = 0
    driver.tick(valid=1, memory=1, write=1, address=0x424, data=0x12345678)
    driver.tick()
    for index in range(4):
        result = driver.tick(warm_reset=int(index == 0), ready=0)
        assert result["bus_valid"] and not result["core_reset"]
    driver.inputs["bus_ready"] = 1
    driver.tick(ready=0)
    for _ in range(driver.delay + 4):
        driver.tick(ready=0)
    assert driver.reference.response == (0, 4) and driver.memory[0x424] == 0x78
    driver.tick()
    driver.halt()
    driver.command(register=0x7B0, write=1, data=0x8007)
    driver.resume()
    driver.tick(breakpoint=1, break_pc=0x2040, empty=0, fetch_idle=0)
    driver.tick(pc=0x2044)
    driver.command(register=0x7B1, expected_result=(0x2040, 0))
    driver.command(register=0x7B0, expected_result=(0x40008457, 0))
    driver.command(register=0x7B1, write=1, data=0x2100)
    driver.tick(valid=1, register=0x1001, ready=0)
    driver.tick(active=0, ready=0)
    assert driver.reference.halted and driver.reference.pc == 0x2100
    driver.command(register=0x7B1, expected_result=(0x2100, 0))
    driver.command(register=0x7B0, write=1, data=3)
    driver.resume()
    driver.tick(halt=1, completed=1, empty=0, fetch_idle=0)
    driver.tick(pc=0x2800, fetch_idle=0)
    driver.tick(pc=0x2800)
    driver.command(register=0x7B1, expected_result=(0x2800, 0))
    driver.resume()
    driver.tick(valid=1, register=0x7B0, halt=1, pc=0x2900)
    result = driver.tick()
    assert result["valid"] and result["error"] == 4
    driver.command(register=0x7B1, expected_result=(0x2900, 0))
    driver.resume()
    driver.halt(pc=0x2000)
    driver.random_stalls = True
    for index in range(128):
        size = driver.random.randrange(3)
        address = 0x600 + (index % 32) * 4
        value = driver.random.getrandbits(32)
        driver.delay = driver.random.randrange(2, 10)
        driver.command(memory=1, write=1, address=address, size=size, data=value, stall=driver.random.randrange(4))
        driver.command(memory=1, address=address, size=size, expected_result=(value & ((1 << (8 << size)) - 1), 0))
    driver.tick(reset=1, active=0)
    result = driver.tick()
    assert result["running"] and not result["step"] and result["pc"] == parameters["resetVector"]
    return driver.rows


def parse_trace(trace):
    samples = []
    for line in trace.splitlines():
        fields = line.split()
        assert len(fields) == len(OUTPUTS) + 1, "Debug hart trace width mismatch"
        samples.append((int(fields[0]), *(int(value, 16) for value in fields[1:])))
    return samples


def check(rows, trace, parameters=None):
    wanted, counts = expected(rows, parameters)
    observed = parse_trace(trace)
    assert len(wanted) == len(observed), "Debug hart trace length mismatch"
    for actual, target in zip(observed, wanted, strict=True):
        if actual != target:
            names = [name for index, (name, _, _) in enumerate(OUTPUTS, 1) if actual[index] != target[index]]
            raise AssertionError(f"Debug hart mismatch at cycle {target[0]}: {','.join(names)}")
    assert not counts["pending"], "Debug hart commands did not drain"
    assert counts.get("memoryRequests", 0) == counts.get("memoryResponses", 0), "Debug native traffic did not drain"
    return counts


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def build(output, parameters):
    output = Path(output)
    names = ["ditdah_e2/src/Parameters.scala", "ditdah_e2/src/Interfaces.scala", "ditdah_e2/src/DebugInterfaces.scala",
             "ditdah_e2/src/DebugHartInterfaces.scala", "ditdah_e2/src/DebugHart.scala",
             "test/debug_hart.py", "test/test_debug_hart.py", "flake.nix", "flake.lock"]
    names += [str(path.relative_to(ROOT)) for path in sorted((ROOT / "nix").glob("*.nix"))]
    contents = {name: (ROOT / name).read_bytes() for name in names}
    for name, data in contents.items():
        target = output / "inputs" / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
    tools = {name: Path(shutil.which(name)).resolve() for name in ("elaborate-ditdah-e2", "firld", "firtool", "iverilog", "vvp")}
    commands = []
    with tempfile.TemporaryDirectory(prefix="ditdah-e2-debug-hart-build-", dir="/data/tmp") as directory:
        work = Path(directory)
        (work / "src").mkdir()
        for name, data in contents.items():
            if name.endswith(".scala"):
                (work / "src" / Path(name).name).write_bytes(data)
        (work / "src/Top.scala").write_text(WRAPPER)
        (work / "parameters.json").write_text(json.dumps(parameters) + "\n")
        (work / "debug_hart_tb.sv").write_text(harness())
        for name in ("src/Top.scala", "parameters.json", "debug_hart_tb.sv"):
            target = output / "inputs/generated" / name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(work / name, target)
        environment = dict(os.environ, DITDAH_E2_SOURCE=str(work / "src"))
        for number in range(3):
            if number == 0:
                command = ["elaborate-ditdah-e2", "design", "parameters.json"]
            elif number == 1:
                command = ["firld", *[path.name for path in sorted(work.glob("*.mlirbc"))], "--base-circuit", "DitDahE2DebugHartTest",
                           "--no-mangle", "--emit-bytecode", "-o", "linked.mlirbc"]
            else:
                command = ["firtool", "linked.mlirbc", "--split-verilog", "-disable-all-randomization",
                           "--lowering-options=noAlwaysComb,disallowLocalVariables,locationInfoStyle=none", "-o", "rtl"]
            result = subprocess.run(command, cwd=work, env=environment, capture_output=True, text=True)
            commands.append({"argv": command, "exitStatus": result.returncode})
            (output / f"build-{number}.log").write_text(result.stdout + result.stderr)
            (output / "commands.json").write_text(json.dumps(commands, indent=2) + "\n")
            if result.returncode:
                raise RuntimeError(f"Debug hart generation failed in command {number}")
        shutil.copytree(work / "rtl", output / "rtl")
    report = {"exitStatus": 0, "parameters": parameters, "commands": commands,
              "inputHashes": {name: hashlib.sha256(data).hexdigest() for name, data in contents.items()},
              "generatedHashes": {str(path.relative_to(output / "inputs")): digest(path)
                                  for path in (output / "inputs/generated").rglob("*") if path.is_file()},
              "rtlHashes": {path.name: digest(path) for path in (output / "rtl").glob("*.sv")},
              "toolHashes": {name: digest(path) for name, path in tools.items()}}
    (output / "build.json").write_text(json.dumps(report, indent=2) + "\n")
    return report


def simulate(output, rows, rtl, commands):
    output.mkdir(parents=True)
    (output / "vectors.txt").write_text("".join(" ".join(f"{value:x}" for value in values) + "\n" for values in rows))
    (output / "debug_hart_tb.sv").write_text(harness())
    shutil.copyfile(rtl, output / "DitDahE2DebugHart.sv")
    for command in (["iverilog", "-g2012", "-s", "DebugHartBench", "-o", "debug-hart-sim", "DitDahE2DebugHart.sv", "debug_hart_tb.sv"],
                    ["vvp", "debug-hart-sim"]):
        result = subprocess.run(command, cwd=output, capture_output=True, text=True)
        commands.append({"directory": output.name, "argv": command, "exitStatus": result.returncode})
        (output / "commands.json").write_text(json.dumps(commands[-2:], indent=2) + "\n")
        (output / ("compile.log" if command[0] == "iverilog" else "simulation.log")).write_text(result.stdout + result.stderr)
        if result.returncode:
            raise RuntimeError(result.stdout + result.stderr)
    (output / "simulation.log").write_text(result.stdout)
    trace = "\n".join(line for line in result.stdout.splitlines() if line and line[0].isdigit()) + "\n"
    (output / "debug-hart.trace").write_text(trace)
    return trace


def stop_mutant(source):
    pattern = r"(assign\s+core_stop\s*=\s*)([^;]+)(;)"
    if len(re.findall(pattern, source)) != 1:
        raise ValueError("Debug stop assignment changed")
    return re.sub(pattern, r"\1(\2) & ~core_completed\3", source)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=Path("result/debug-hart"))
    parser.add_argument("--config", type=Path)
    args = parser.parse_args()
    if args.output.exists() and any(args.output.iterdir()):
        raise ValueError("Debug hart output must be empty")
    parameters = configuration(json.loads(args.config.read_text()) if args.config else {})
    report = build(args.output, parameters)
    commands, runs = [], []
    for seed in (1, 19, 83):
        rows = vectors(parameters, seed)
        directory = args.output / f"seed-{seed}"
        trace = simulate(directory, rows, args.output / "rtl/DitDahE2DebugHart.sv", commands)
        counts = check(rows, trace, parameters)
        assert counts["requests"] == counts["responses"] + counts["cancelled"], "Abstract ownership did not balance"
        assert all(counts[name] > 0 for name in ("abstractStalls", "responseStalls", "memoryStalls", "resetDrainCycles",
                                                "haltCause1", "haltCause3", "haltCause4", "haltCause5", "busFaults",
                                                "localMemoryFaults", "discardedMemoryResults")), "Debug hart coverage incomplete"
        runs.append({"seed": seed, "cycles": len(rows), **counts, "traceHash": digest(directory / "debug-hart.trace"),
                     "vectorsHash": digest(directory / "vectors.txt")})
    mutant = args.output / "stop-mutant.sv"
    mutant.write_text(stop_mutant((args.output / "rtl/DitDahE2DebugHart.sv").read_text()))
    rows = vectors(parameters)
    trace = simulate(args.output / "stop-mutant", rows, mutant, commands)
    try:
        check(rows, trace, parameters)
    except AssertionError as error:
        reason = str(error)
        assert "stop" in reason
    else:
        raise AssertionError("Debug checker accepted an extra step opportunity")
    target, _ = expected(rows, parameters)
    actual = parse_trace(trace)
    stop_index = 1 + next(index for index, item in enumerate(OUTPUTS) if item[0] == "stop")
    witness = next(index for index, (wanted, observed) in enumerate(zip(target, actual, strict=True))
                   if wanted[stop_index] and not observed[stop_index])
    control = {"mutation": "drop stop on instruction completion", "exitStatus": 0, "cycle": witness,
               "rejected": reason, "rtlHash": digest(mutant), "traceHash": digest(args.output / "stop-mutant/debug-hart.trace")}
    assert all(digest(args.output / "inputs" / name) == value for name, value in report["inputHashes"].items())
    assert all(digest(args.output / "rtl" / name) == value for name, value in report["rtlHashes"].items())
    summary = {"exitStatus": 0, "scope": "debug hart controller with independent core, register and native peers",
               "parameters": parameters, "buildHash": digest(args.output / "build.json"), "commands": commands,
               "runs": runs, "negativeControls": [control],
               "excluded": ["core integration", "instruction execution", "PMP implementation", "full Debug 1.0 conformance"]}
    (args.output / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    artifacts = {str(path.relative_to(args.output)): digest(path) for path in sorted(args.output.rglob("*")) if path.is_file()}
    (args.output / "artifacts.json").write_text(json.dumps(artifacts, indent=2) + "\n")
    print(f"PASS: {sum(run['cycles'] for run in runs)} debug hart cycles and one RTL negative control")


if __name__ == "__main__":
    main()
