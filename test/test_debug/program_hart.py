# SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
# SPDX-License-Identifier: MIT
"""Check Program Buffer sequencing in the standalone debug hart."""

import argparse
import json
import random
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from test.test_debug.debug_hart import (
    INPUTS,
    OUTPUTS,
    PROGRAM_OUTPUTS,
    build,
    digest,
    row,
    simulate,
    unpack,
)
from test.test_debug.debug_hart import Driver as BaseDriver
from test.test_debug.debug_hart import Reference as BaseReference

MASK = 0xFFFFFFFF
ALL_OUTPUTS = OUTPUTS + PROGRAM_OUTPUTS


class ProgramReference(BaseReference):
    def __init__(self, parameters=None):
        super().__init__(parameters)
        self.response_data_valid = False
        self.transfer_data = 0
        self.injecting = False
        self.cancel_injection = False
        self.pending_issue = False
        self.slot = 0
        self.program = [0, 0]

    def local_read(self, address):
        return self.status() if address == 0x7B0 else self.pc if address == 0x7B1 else 0

    def local_write(self, address, value):
        if address == 0x7B0:
            self.step_enabled = bool(value & 4)
            self.ebreak_m = bool(value & 0x8000)
            self.ebreak_u = bool(self.parameters["protectedMode"] and value & 0x1000)
            self.user = bool(self.parameters["protectedMode"] and value & 3 == 0)
        elif address == 0x7B1:
            self.pc = value & (0xFFFFFFFE if self.parameters["enableC"] else 0xFFFFFFFC)

    def decode(self):
        if self.slot == 4:
            return 0x00100073, 4, self.slot, 0
        if not self.parameters["enableC"]:
            return self.program[self.slot // 2], 4, self.slot, int(self.slot in (1, 3))
        halves = [self.program[0] & 0xFFFF, self.program[0] >> 16,
                  self.program[1] & 0xFFFF, self.program[1] >> 16]
        raw = halves[self.slot]
        words = [self.program[0], (self.program[1] & 0xFFFF) << 16 | halves[1], self.program[1], raw]
        return words[self.slot] if raw & 3 == 3 else raw, 4 if raw & 3 == 3 else 2, self.slot, int(self.slot == 3 and raw & 3 == 3)

    def step(self, values, cycle):
        assert len(values) == len(INPUTS)
        state = dict(zip((name for name, _, _ in INPUTS), values, strict=True))
        active = bool(state["active"])
        halted = self.halted
        injecting = self.injecting
        response = self.response
        response_data_valid = self.response_data_valid and response is not None and active
        issue = self.decode() if self.pending_issue and not self.cancel_injection else (0, 0, 0, 0)
        reset_busy = bool(active and state["warm_reset"] or self.reset_phase is not None)
        reasons = [] if self.pending_halt is None else [self.pending_halt]
        if self.stepping and state["completed"]:
            reasons.append("step")
        if state["breakpoint"]:
            reasons.append("breakpoint")
        if active and state["halt"]:
            reasons.append("halt")
        entry = not halted and bool(reasons) and not reset_busy and state["empty"] and state["fetch_idle"]

        local_address = state["local_address"]
        local_read = self.local_read(local_address)
        local_value = state["local_operand"]
        if state["local_operation"] == 2:
            local_value |= local_read
        elif state["local_operation"] == 3:
            local_value = local_read & ~local_value & MASK
        local_written = local_read
        local_mask = 0
        if state["local_commit"]:
            if local_address == 0x7B0:
                local_mask = 0x9007 if self.parameters["protectedMode"] else 0x8004
                local_written = local_read & ~local_mask | local_value & local_mask & 0xFFFFFFFC
                local_written |= (0 if self.parameters["protectedMode"] and local_value & 3 == 0 else 3)
            elif local_address == 0x7B1:
                local_mask = 0xFFFFFFFE if self.parameters["enableC"] else 0xFFFFFFFC
                local_written = local_value & local_mask
        extras = (int(response_data_valid), int(entry), int(injecting),
                  int(self.pending_issue and not self.cancel_injection), *issue,
                  local_read, local_mask, local_written)

        pending_issue = self.pending_issue
        base_values = values
        if injecting:
            base_values = list(values)
            base_values[13] = 0
            base_values[3] = 0
            if reset_busy:
                base_values[6] = 0
            base_values = tuple(base_values)
        observed = unpack(super().step(base_values, cycle))
        accepted = observed["ready"] and state["valid"] and not injecting
        if injecting:
            observed["ready"] = 0
            observed["resume"] = 0
        if not state["transfer"]:
            observed["write_pulse"] = 0

        if accepted:
            self.response_data_valid = False
            if self.response is not None and state["transfer"] and not state["write"] and self.response[1] == 0:
                self.response_data_valid = not state["memory"]
        local = state["register"] in (0x7B0, 0x7B1)
        transfer_error = bool(state["transfer"] and not local and state["backend_error"])
        legal_format = (state["size"] != 3 and not state["post_exec"]) if state["memory"] else not state["transfer"] or state["size"] == 2
        start = accepted and halted and legal_format and not state["memory"] and state["post_exec"] and not transfer_error
        if start:
            self.transfer_data = self.response[0] if self.response is not None else 0
            self.response = None
            self.injecting = True
            self.cancel_injection = False
            self.pending_issue = True
            self.slot = 0
            self.program = [state["program0"], state["program1"]]
            self.counts["postexec"] += 1

        fired = pending_issue and not self.cancel_injection and state["injection_ready"]
        if fired:
            self.pending_issue = False
            self.counts["issues"] += 1
            self.counts["crossWord"] += int(self.slot == 1 and issue[1] == 4)
            self.counts["truncated"] += int(bool(issue[3]))
        if state["done_valid"] and self.injecting and state["done_sequence"] == self.slot:
            self.pending_issue = False
            if not self.cancel_injection:
                if state["done_fault"] or state["done_ebreak"] or self.slot == 4:
                    self.injecting = False
                    self.counts["implicit"] += int(self.slot == 4)
                    self.counts["explicit"] += int(state["done_ebreak"] and self.slot != 4)
                    self.counts["faults"] += int(state["done_fault"])
                    if self.owner and active:
                        self.response = (self.transfer_data, 3 if state["done_fault"] else 0)
                else:
                    self.slot += 1 if self.decode()[1] == 2 else 2
                    self.pending_issue = True
        finishing = (state["done_valid"] and self.injecting and state["done_sequence"] == self.slot and
                     (state["done_fault"] or state["done_ebreak"] or self.slot == 4))
        if (not active or reset_busy) and not finishing:
            if self.injecting:
                self.cancel_injection = True
            self.pending_issue = False
        if self.injecting and self.cancel_injection and not self.pending_issue and state["injected_idle"] and not fired:
            self.injecting = False
            self.cancel_injection = False
            self.counts["cancelledInjection"] += 1
            if self.owner and active:
                self.response = (self.transfer_data, 4)

        if state["local_commit"] and state["local_write"]:
            self.local_write(local_address, local_value)
            self.counts["localCommits"] += 1
        if response is not None and state["ready"]:
            self.response_data_valid = False
        if not active:
            self.response_data_valid = False
        return (cycle, *[observed[name] for name, _, _ in OUTPUTS], *extras)


def expected(rows, parameters=None):
    reference = ProgramReference(parameters)
    samples = [reference.step(values, cycle) for cycle, values in enumerate(rows)]
    pending = (reference.owner or reference.response is not None or reference.native is not None or
               reference.injecting or reference.pending_issue)
    return samples, dict(reference.counts) | {"pending": int(pending)}


def parse_trace(trace):
    result = []
    for line in trace.splitlines():
        fields = line.split()
        assert len(fields) == len(ALL_OUTPUTS) + 1, "Program hart trace width mismatch"
        result.append(tuple([int(fields[0])] + [int(value, 16) for value in fields[1:]]))
    return result


def check(rows, trace, parameters=None):
    wanted, counts = expected(rows, parameters)
    observed = parse_trace(trace)
    assert len(wanted) == len(observed), "Program hart trace length mismatch"
    for actual, target in zip(observed, wanted, strict=True):
        if actual != target:
            names = [name for index, (name, _, _) in enumerate(ALL_OUTPUTS, 1) if actual[index] != target[index]]
            raise AssertionError(f"Program hart mismatch at cycle {target[0]}: {','.join(names)}")
    assert not counts["pending"], "Program hart command did not drain"
    return counts


class Driver(BaseDriver):
    def __init__(self, parameters=None, seed=1):
        self.reference = ProgramReference(parameters)
        self.random = random.Random(seed)
        self.rows = []
        self.inputs = {"active": 1, "pc": 0x1000, "user": 0, "bus_ready": 1}
        self.registers = {index: (index * 0x10101) & MASK for index in range(0x1000, 0x1020)}
        self.registers[0x1000] = 0
        self.registers.update({0x300: 0x1800, 0xF11: 0})
        self.memory = {0x400 + lane: byte for lane, byte in enumerate(bytes.fromhex("017fff80"))}
        self.peer = None
        self.delay = 5
        self.random_stalls = False
        self.injection_peer = None
        self.injection_delay = 4
        self.next_injection_fault = False
        self.injection_runs = []
        self.last_data_valid = 0
        self.tick(reset=1, active=0)

    def tick(self, **overrides):
        values = dict(self.inputs)
        if self.random_stalls:
            values["bus_ready"] = int(self.random.randrange(4) != 0)
        values["injected_idle"] = int(self.injection_peer is None)
        if self.injection_peer is not None and len(self.rows) >= self.injection_peer["due"]:
            values.update(done_valid=1, done_sequence=self.injection_peer["sequence"],
                          done_fault=self.injection_peer["fault"], done_ebreak=self.injection_peer["ebreak"])
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
        observed = dict(zip((name for name, _, _ in ALL_OUTPUTS), output[1:], strict=True))
        if observed["write_pulse"] and register != 0x1000:
            self.registers[register] = observed["write_data"]
        if observed["bus_ready"] and stimulus[26]:
            self.peer = None
        if observed["bus_valid"] and stimulus[25]:
            assert self.peer is None
            address = observed["bus_address"]
            aligned = address & ~3
            fault = int(address >= 0xFFFF0000)
            if observed["bus_write"] and not fault:
                for lane in range(4):
                    if observed["bus_mask"] >> lane & 1:
                        self.memory[aligned + lane] = observed["bus_data"] >> (8 * lane) & 255
            data = sum(self.memory.get(aligned + lane, 0) << (8 * lane) for lane in range(4))
            self.peer = {"data": data, "fault": fault, "due": len(self.rows) - 1 + self.delay}
        if self.injection_peer is not None and len(self.rows) > self.injection_peer["due"]:
            self.injection_peer = None
        if observed["issue_valid"] and stimulus[34]:
            issue = {name: observed[name] for name in ("issue_word", "issue_length", "issue_sequence", "issue_truncated")}
            self.injection_runs.append(issue)
            fault = bool(issue["issue_truncated"] or self.next_injection_fault)
            self.next_injection_fault = False
            ebreak = bool(issue["issue_word"] == 0x00100073 or
                          issue["issue_length"] == 2 and issue["issue_word"] & 0xFFFF == 0x9002)
            self.injection_peer = {"sequence": issue["issue_sequence"], "fault": int(fault), "ebreak": int(ebreak),
                                   "due": len(self.rows) - 1 + self.injection_delay}
        if observed["valid"]:
            self.last_data_valid = observed["response_data_valid"]
        return observed

    def command(self, *, expected_result=None, stall=0, **request):
        result = super().command(expected_result=expected_result, stall=stall, **request)
        return result


def program_vectors(parameters):
    driver = Driver(parameters)
    driver.halt()
    driver.command(register=0xFFFF, size=0, transfer=0, post_exec=1,
                   program0=0x00100073, program1=0xDEADBEEF, expected_result=(0, 0))
    assert len(driver.injection_runs) == 1 and driver.injection_runs[0]["issue_word"] == 0x00100073

    driver.registers[0x1001] = 0x13579BDF
    driver.next_injection_fault = True
    driver.command(register=0x1001, post_exec=1, program0=0x00000013, program1=0x00100073,
                   expected_result=(0x13579BDF, 3))
    assert driver.last_data_valid == 1
    executions = len(driver.injection_runs)
    driver.command(register=0xFFFF, post_exec=1, backend_error=1, expected_result=(0, 3))
    assert len(driver.injection_runs) == executions

    if parameters["enableC"]:
        driver.command(transfer=0, post_exec=1, program0=0x00010001, program1=0x00010001, expected_result=(0, 0))
        actual = [run["issue_sequence"] for run in driver.injection_runs[-5:]]
        assert actual == [0, 1, 2, 3, 4], driver.injection_runs
        driver.command(transfer=0, post_exec=1, program0=0x00930001, program1=0x90020123, expected_result=(0, 0))
        cross = driver.injection_runs[-2]
        assert cross["issue_sequence"] == 1 and cross["issue_word"] == 0x01230093 and cross["issue_length"] == 4
        driver.command(transfer=0, post_exec=1, program0=0x00010001, program1=0x00030001, expected_result=(0, 3))
        assert driver.injection_runs[-1]["issue_truncated"]
    else:
        driver.command(transfer=0, post_exec=1, program0=0x00000013, program1=0x00100073, expected_result=(0, 0))
        assert [run["issue_sequence"] for run in driver.injection_runs[-2:]] == [0, 2]

    driver.tick(local_address=0x7B1, local_operand=0x12345679, local_operation=1, local_write=1, local_commit=1)
    result = driver.tick(local_address=0x7B1)
    assert result["local_read_data"] == 0x12345678
    driver.tick(local_address=0x7B0, local_operand=MASK, local_operation=1, local_write=1, local_commit=1)
    result = driver.tick(local_address=0x7B0)
    mask = 0x9004 if parameters.get("protectedMode", False) else 0x8004
    assert result["local_read_data"] & mask == mask, hex(result["local_read_data"])

    driver.injection_delay = 8
    driver.tick(valid=1, transfer=0, post_exec=1, program0=0x00000013, program1=0x00100073)
    driver.tick()
    driver.tick(active=0)
    for _ in range(12):
        driver.tick(active=0)
    assert not driver.reference.injecting and not driver.reference.owner

    driver.inputs["active"] = 1
    driver.tick()
    driver.tick(valid=1, transfer=0, post_exec=1, program0=0x00000013, program1=0x00100073)
    driver.tick(warm_reset=1)
    for _ in range(20):
        driver.tick()
    assert not driver.reference.injecting
    return driver.rows


def mutant(source, name):
    if name == "no-issue":
        pattern = r"assign core_injection_valid = [^;]+;"
        replacement = "assign core_injection_valid = 1'h0;"
    elif name == "no-data-valid":
        pattern = r"assign debug_response_bits_dataValid = [^;]+;"
        replacement = "assign debug_response_bits_dataValid = 1'h0;"
    else:
        raise ValueError("Unknown program hart mutation")
    changed, count = re.subn(pattern, replacement, source)
    if count != 1:
        raise ValueError("Program hart mutation target changed: " + name)
    return changed


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--enable-c", action="store_true")
    args = parser.parse_args()
    if args.output.exists() and any(args.output.iterdir()):
        raise ValueError("Program hart output directory must be empty")
    parameters = {"resetVector": 0, "enableC": args.enable_c, "protectedMode": False}
    build(args.output, parameters)
    commands = []
    rows = program_vectors(parameters)
    trace = simulate(args.output / "positive", rows, args.output / "rtl/DitDahE2DebugHart.sv", commands, detailed=True)
    counts = check(rows, trace, parameters)
    for field in ("postexec", "crossWord" if args.enable_c else "issues", "faults", "cancelledInjection", "localCommits"):
        assert counts[field] > 0, f"Missing program hart coverage: {field}"
    controls = []
    for name in ("no-issue", "no-data-valid"):
        changed = args.output / f"{name}.sv"
        changed.write_text(mutant((args.output / "rtl/DitDahE2DebugHart.sv").read_text(), name))
        trace = simulate(args.output / name, rows, changed, commands, detailed=True)
        try:
            check(rows, trace, parameters)
        except AssertionError as error:
            reason = str(error)
        else:
            raise AssertionError("Program hart checker accepted mutation: " + name)
        controls.append({"mutation": name, "rejected": reason, "rtlHash": digest(changed)})
    summary = {"exitStatus": 0, "scope": "standalone Program Buffer hart with an independent injected core peer",
                   "parameters": parameters, "buildHash": digest(args.output / "build.json"),
                   "cycles": len(rows), "counts": counts, "commands": commands, "negativeControls": controls,
                   "excluded": ["full-core instruction semantics", "commercial proof", "OpenOCD"]}
    (args.output / "summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
    print(f"PASS: {len(rows)} Program Buffer hart cycles and {len(controls)} negative controls")


if __name__ == "__main__":
    main()
