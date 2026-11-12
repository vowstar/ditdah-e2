# SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
# SPDX-License-Identifier: MIT
"""Check real Program Buffer execution and architectural isolation through DMI."""

import argparse
import copy
import json
import os
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT), str(ROOT / "scripts")]
from build_rtl import digest, sources

from test.common.model import MASK, Model
from test.programs.debug_programs import (
    BUS_CONTROL,
    FINISH,
    IDLE,
    POLL,
    READ,
    WAIT_ACCEPT,
    WRITE,
)

DATA = 0x400
VALUE = 0x13579BDF
EBREAK = 0x00100073
NOP = 0x00000013
TRAP_SENTINELS = {0x341: 0x234, 0x342: 7, 0x343: 0xABCDEF}


@dataclass
class Case:
    name: str
    actions: list
    error: int = 0
    data0: int | None = None
    dpc: int | None = None
    registers: dict = field(default_factory=dict)
    memory: dict = field(default_factory=dict)
    required: list = field(default_factory=list)
    count: int | None = None
    image: dict = field(default_factory=lambda: {0: 0x0000006F})
    enable_c: bool = True
    protected_mode: bool = False
    data_fault: int | None = None
    conflicts: int = 0
    automatic: int = 0


def activate(actions):
    actions.extend(((WRITE, 0x10, 1, 0), (WRITE, 0x10, 0x80000001, 0), (POLL, 0x11, 0x300, 0x300)))


def abstract_register(actions, number, value=None):
    if value is not None:
        actions.append((WRITE, 4, value, 0))
    actions.extend(((WRITE, 0x17, 0x220000 | number | (int(value is not None) << 16), 0),
                    (POLL, 0x16, 0, 1 << 12)))
    if value is None:
        actions.append((READ, 4, 0, 0))


def command(actions, word0, word1, register=None, write=False):
    actions.extend(((WRITE, 0x20, word0, 0), (WRITE, 0x21, word1, 0)))
    if register is not None:
        actions.append((WRITE, 4, register[1], 0))
        actions.append((WRITE, 0x17, 0x260000 | (int(write) << 16) | register[0], 0))
    else:
        actions.append((WRITE, 0x17, 0x00040000, 0))
    actions.append((POLL, 0x16, 0, 1 << 12))


def sentinels(actions):
    for number, value in TRAP_SENTINELS.items():
        abstract_register(actions, number, value)


class ProgramReference:
    def __init__(self, case):
        self.case = case
        self.model = Model(case.image, enable_m=True, enable_c=case.enable_c,
                           protected_mode=case.protected_mode, data_fault=case.data_fault)
        self.active = self.halted = False
        self.halt_requested = False
        self.cycle = -1
        self.completion_cycle = -2
        self.previous_error = 0
        self.completion_busy = False
        self.data = [0, 0]
        self.program = [0, 0]
        self.auto = 0
        self.error = 0
        self.pending = None
        self.orphan = None
        self.reset_requested = False
        self.reset_event = False
        self.last_command = None
        self.dpc = 0
        self.control = 3
        self.cause = 3
        self.events = []
        self.memory_events = []
        self.conflicts = 0
        self.automatic = 0

    def register(self, number, value=None):
        if number == 0x7B1:
            if value is not None:
                self.dpc = value & ~(1 if self.model.enable_c else 3)
            return self.dpc
        if number == 0x7B0:
            if value is not None:
                self.control = ((value & (0x9004 if self.model.protected_mode else 0x8004)) |
                                (3 if value & 3 or not self.model.protected_mode else 0))
            return 0x40000410 | self.control | self.cause << 6
        if 0x1000 <= number <= 0x101F:
            if value is not None and number != 0x1000:
                self.model.registers[number - 0x1000] = value
            return self.model.registers[number - 0x1000]
        if value is not None:
            self.model.write_csr(number, value)
        return self.model.read_csr(number)

    def start(self, word):
        if self.pending is not None or self.error:
            return
        if word >> 24 or word & 0x880000 or (word & 0x20000 and word >> 20 & 7 != 2):
            self.error = 2
            return
        self.last_command = word
        transfer = bool(word & 0x20000)
        read_value = None
        data_valid = False
        if transfer:
            number = word & 0xFFFF
            write = bool(word & 0x10000)
            try:
                read_value = self.register(number, self.data[0] if write else None)
            except (AssertionError, KeyError, ValueError):
                self.error = 3
                return
            data_valid = not write
        if not word & 0x40000:
            if data_valid:
                self.data[0] = read_value
            if transfer:
                self.pending = {"simple": 1}
            return
        runtime = copy.deepcopy(self.model)
        runtime.pc = 0
        for lane in range(4):
            runtime.memory[lane] = self.program[0] >> (8 * lane) & 255
            runtime.memory[4 + lane] = self.program[1] >> (8 * lane) & 255
        self.pending = {"runtime": runtime, "slot": 0, "dataValid": data_valid, "readValue": read_value,
                        "command": word}

    def request(self, address, op, value):
        if op == 1:
            return
        if address == 0x10:
            if not value & 1:
                self.orphan = self.pending
                if self.orphan is not None:
                    self.orphan["deactivated"] = True
                self.pending = None
                self.active = False
                self.data = [0, 0]
                self.program = [0, 0]
                self.auto = 0
                self.error = 0
                return
            self.active = True
            if value & 2:
                self.reset_requested = True
                if self.pending is not None:
                    self.pending["aborted"] = True
            if value >> 31:
                self.halt_requested = 2
                self.halted = False
            if value & 1 << 30:
                self.halt_requested = False
                self.halted = False
        elif address in (4, 5):
            if self.pending is not None:
                self.conflicts += 1
                if not self.error:
                    self.error = 1
            else:
                self.data[address - 4] = value
        elif address in (0x20, 0x21):
            if self.pending is not None:
                self.conflicts += 1
                if not self.error:
                    self.error = 1
            else:
                self.program[address - 0x20] = value
        elif address == 0x18:
            if self.pending is not None:
                self.conflicts += 1
                if not self.error:
                    self.error = 1
            else:
                self.auto = value & 0x30003
        elif address == 0x16:
            self.error &= ~(value >> 8 & 7)
        elif address == 0x17:
            if self.pending is not None:
                self.conflicts += 1
                if not self.error:
                    self.error = 1
            elif not self.halted:
                self.error = 4
            else:
                self.start(value)
        else:
            raise AssertionError(f"Unexpected DMI write {address:#x}")

    def read(self, address):
        if not self.active:
            return 0
        if address in (4, 5):
            return 0 if self.pending is not None else self.data[address - 4]
        if address in (0x20, 0x21):
            return 0 if self.pending is not None else self.program[address - 0x20]
        if address == 0x10:
            return int(self.active)
        if address == 0x11:
            if self.halt_requested:
                status = 0x400000 | 0x4000A3 | 0xC00
                self.halt_requested -= 1
                if not self.halt_requested:
                    self.halted = True
            else:
                status = 0x400000 | 0x4000A3 | (int(self.halted) * 0x300) | (int(not self.halted) * 0xC00)
            return status | (0xC0000 if self.reset_event else 0)
        if address == 0x16:
            recent = self.completion_cycle <= self.cycle <= self.completion_cycle + 1
            error = self.previous_error if recent else self.error
            busy = self.completion_busy if recent else self.pending is not None
            return 0x2000002 | error << 8 | int(busy) << 12
        if address == 0x18:
            return self.auto
        return 0

    def automatic_access(self, address, op):
        if self.pending is not None or self.error or self.last_command is None:
            return
        selected = (address in (4, 5) and self.auto & (1 << (address - 4)) or
                    address in (0x20, 0x21) and self.auto & (1 << (address - 0x20 + 16)))
        if op in (1, 2) and selected:
            self.automatic += 1
            self.start(self.last_command)

    def local_csr(self, runtime, raw):
        address, rd, source = raw >> 20, raw >> 7 & 31, raw >> 15 & 31
        old = self.dpc if address == 0x7B1 else 0x40000410 | self.control | self.cause << 6
        function = raw >> 12 & 7
        operand = source if function >= 5 else runtime.registers[source]
        updated = operand if function & 3 == 1 else old | operand if function & 3 == 2 else old & ~operand
        if function & 3 == 1 or source:
            if address == 0x7B1:
                self.dpc = updated & ~(1 if runtime.enable_c else 3)
            else:
                self.control = ((updated & (0x9004 if runtime.protected_mode else 0x8004)) |
                                (3 if updated & 3 or not runtime.protected_mode else 0))
        expected = {"pc": runtime.pc, "word": raw, "length": 4, "rd": rd, "writes": bool(rd), "value": old,
                    "fault": False, "ebreak": False, "csr": True, "load": False, "store": False, "address": 0,
                    "next": runtime.pc + 4}
        runtime.pc = (runtime.pc + 4) & MASK
        return expected

    def instruction(self, values):
        sequence, pc, _word, _length, _rd, _writes, _value, _fault, _ebreak, _csr, _load, _store, _address = values
        pending = self.pending or self.orphan
        runtime = pending["runtime"]
        slot = pending["slot"]
        assert sequence == slot and pc == slot * 2, f"Injected sequence differs: {sequence} != {slot}"
        if slot == 4:
            expected = {"pc": 8, "word": EBREAK, "length": 4, "rd": 0, "writes": False, "value": 0,
                        "fault": False, "ebreak": True, "csr": False, "load": False, "store": False, "address": 0,
                        "next": 8}
            self.finish(pending, expected, fault=False)
            return
        raw = runtime.word(pc)
        truncated = slot == 3 and runtime.enable_c and raw & 3 == 3
        if truncated:
            expected = {"pc": pc, "word": raw, "length": 4, "rd": 0, "writes": False, "value": 0,
                        "fault": True, "ebreak": False, "csr": False, "load": False, "store": False, "address": 0,
                        "next": pc}
            self.finish(pending, expected, fault=True)
            return
        before = copy.deepcopy(runtime)
        if (raw >> 20) in (0x7B0, 0x7B1) and raw & 127 == 0x73 and raw >> 12 & 3:
            expected = self.local_csr(runtime, raw)
            event = None
        else:
            event = runtime.step()
            instruction = event.instruction
            rejected = (instruction in ("beq", "bne", "blt", "bge", "bltu", "bgeu", "jal", "jalr", "auipc", "mret", "fence.i") or
                        instruction.startswith(("c.j", "c.b")))
            if rejected:
                runtime = before
                expected = {"pc": pc, "word": event.word, "length": event.length, "rd": 0, "writes": False, "value": 0,
                            "fault": True, "ebreak": False, "csr": False, "load": False, "store": False, "address": 0,
                            "next": pc}
                self.finish(pending, expected, fault=True)
                return
            expected = {"pc": event.pc, "word": event.word, "length": event.length, "rd": event.rd,
                        "writes": bool(event.rd), "value": event.value, "fault": event.trap and instruction not in ("ebreak", "c.ebreak"),
                        "ebreak": event.instruction in ("ebreak", "c.ebreak"), "csr": instruction.startswith("csr"),
                        "load": bool(event.memory and not event.memory[1]), "store": bool(event.memory and event.memory[1]),
                        "address": event.memory[0] if event.memory else 0, "next": event.next_pc}
            if instruction == "wfi":
                runtime.sleeping = False
                expected["next"] = pc + event.length
            if event.trap:
                for number in (0x341, 0x342, 0x343):
                    runtime.csrs[number] = before.csrs[number]
                runtime.csrs[0x300] = before.csrs[0x300]
                runtime.user_mode = before.user_mode
        self.model = runtime
        expected["sequence"] = sequence
        actual = dict(zip(("sequence", "pc", "word", "length", "rd", "writes", "value", "fault", "ebreak",
                           "csr", "load", "store", "address"), values))
        for key in ("pc", "word", "length", "rd", "writes", "value", "fault", "ebreak", "csr", "load", "store", "address"):
            assert actual[key] == expected[key], f"Injected {key} differs at slot {slot}: {actual[key]} != {expected[key]}"
        if event is not None and event.memory:
            request = self.memory_events.pop(0)
            assert request[:5] == event.memory and request[5] == event.memory_machine, \
                f"Injected memory request differs: {request} != {event.memory} ({event.memory_machine})"
        self.finish(pending, expected, fault=expected["fault"], ebreak=expected["ebreak"], event=event)

    def finish(self, pending, expected, fault, ebreak=False, event=None):
        self.previous_error = self.error
        self.completion_cycle = self.cycle
        self.completion_busy = self.pending is not None
        if pending.get("deactivated"):
            self.orphan = None
            self.events.append(expected)
            return
        if pending.get("aborted"):
            self.error = 4
            self.reset_event = True
            self.halted = False
            self.pending = None
            self.events.append(expected)
            return
        expected["sequence"] = pending["slot"]
        actual_error = 3 if fault else 0
        if fault or ebreak or pending["slot"] == 4:
            if pending["dataValid"]:
                self.data[0] = pending["readValue"]
            self.error = actual_error
            self.pending = None
        else:
            pending["slot"] += 1 if expected["length"] == 2 else 2
        self.events.append(expected)
        if fault:
            self.pending = None
            self.error = 3

    def native_response(self, request, fault):
        if self.memory_events:
            expected = self.memory_events.pop(0)
            assert request == expected, f"Injected memory request differs: {request} != {expected}"


def check(case, trace):
    reference = ProgramReference(case)
    dmi = None
    final = False
    for line in trace.splitlines():
        fields = line.split()
        kind = fields[0]
        if kind != "W":
            reference.cycle = int(fields[1])
        if kind == "J":
            _, _, _, _, address, op, value = fields
            address, op, value = int(address), int(op), int(value)
            reference.request(address, op, value)
            snapshot = reference.read(address) if op == 1 else 0
            reference.automatic_access(address, op)
            dmi = (address, op, snapshot)
        elif kind == "K":
            _, _, _, status, data = fields
            assert int(status) == 0 and dmi is not None
            if dmi[0] == 0x16:
                assert int(data) & ~(1 << 12) == dmi[2] & ~(1 << 12), \
                    f"abstractcs differs: snapshot={dmi} response={fields}"
                if reference.pending is not None and "simple" in reference.pending:
                    reference.pending = None
            else:
                assert dmi[2] == int(data), f"DMI read {dmi[0]:#x} differs: {dmi[2]:#x} != {int(data):#x} at {fields}"
            dmi = None
        elif kind == "X":
            values = tuple(map(int, fields[2:]))
            assert reference.pending is not None or reference.orphan is not None, "Unowned injected execution"
            reference.instruction(values)
        elif kind == "R":
            assert not reference.halted, "Native instruction retired during injected execution"
        elif kind == "Q" and fields[2] == "D":
            reference.memory_events.append(tuple(map(int, fields[3:])))
        elif kind == "F":
            final = True
        elif kind in ("T", "P", "Q", "W", "L", "N", "S"):
            continue
        else:
            raise AssertionError(f"Unknown trace record {kind}")
    assert final and reference.pending is None and reference.orphan is None
    assert reference.error == case.error, f"cmderr differs: {reference.error} != {case.error}"
    if case.data0 is not None:
        assert reference.data[0] == case.data0, f"data0 differs: {reference.data[0]:#x} != {case.data0:#x}"
    if case.dpc is not None:
        assert reference.dpc == case.dpc, f"DPC differs: {reference.dpc:#x} != {case.dpc:#x}"
    for number, value in case.registers.items():
        observed = reference.model.registers[number]
        assert observed == value, f"x{number} differs: {observed:#x} != {value:#x}"
    for address, value in case.memory.items():
        observed = reference.model.word(address)
        assert observed == value, f"Memory {address:#x} differs: {observed:#x} != {value:#x}"
    for number, value in TRAP_SENTINELS.items():
        assert reference.model.read_csr(number) == value, f"Native trap CSR {number:#x} changed"
    if case.count is not None:
        assert len(reference.events) == case.count, f"Injected count differs: {len(reference.events)} != {case.count}"
    for required in case.required:
        assert any(all(event.get(key) == value for key, value in required.items()) for event in reference.events), \
            f"Missing injected event {required}"
    assert reference.conflicts == case.conflicts
    assert reference.automatic == case.automatic
    return {"events": len(reference.events), "dmiTransactions": sum(line.startswith("J ") for line in trace.splitlines())}


def case(name, actions, **values):
    full = []
    activate(full)
    sentinels(full)
    full.extend(actions)
    full.append((FINISH, 0, 0, 0))
    return Case(name, full, **values)


def cases():
    result = []
    result.append(case("explicit", [(WRITE, 0x20, EBREAK, 0), (WRITE, 0x21, 0xDEADBEEF, 0),
                                    (WRITE, 4, 0xA5A55A5A, 0), (WRITE, 0x17, 0x00040000, 0), (POLL, 0x16, 0, 1 << 12)],
                       data0=0xA5A55A5A, count=1, required=[{"sequence": 0, "ebreak": True}]))
    result.append(case("read_then_fault", [(WRITE, 4, 0x13579BDF, 0), (WRITE, 0x17, 0x00231001, 0), (POLL, 0x16, 0, 1 << 12),
                                           (WRITE, 4, 0xA5A55A5A, 0), (WRITE, 0x20, 0xFFFFFFFF, 0), (WRITE, 0x21, EBREAK, 0),
                                           (WRITE, 0x17, 0x00261001, 0), (POLL, 0x16, 0, 1 << 12), (READ, 4, 0, 0)],
                       error=3, data0=0x13579BDF, count=1, required=[{"fault": True}]))
    result.append(case("cross", [(WRITE, 0x20, 0x00930001, 0), (WRITE, 0x21, 0x90021230, 0),
                                 (WRITE, 0x17, 0x00040000, 0), (POLL, 0x16, 0, 1 << 12)],
                       registers={1: 0x123}, required=[{"sequence": 1, "word": 0x12300093, "length": 4}]))
    result.append(case("implicit", [(WRITE, 0x20, 0x00010001, 0), (WRITE, 0x21, 0x00010001, 0),
                                    (WRITE, 0x17, 0x00040000, 0), (POLL, 0x16, 0, 1 << 12)],
                       count=5, required=[{"sequence": 4, "ebreak": True}]))
    result.append(case("truncated", [(WRITE, 0x20, 0x00010001, 0), (WRITE, 0x21, 0x00030001, 0),
                                     (WRITE, 0x17, 0x00040000, 0), (POLL, 0x16, 0, 1 << 12)],
                       error=3, required=[{"sequence": 3, "fault": True}]))
    for name, word in (("wfi", 0x10500073), ("branch", 0x0000006F), ("auipc", 0x00000097),
                       ("mret", 0x30200073), ("fence_i", 0x0000100F)):
        result.append(case(name, [(WRITE, 0x20, word, 0), (WRITE, 0x21, EBREAK, 0),
                                  (WRITE, 0x17, 0x00040000, 0), (POLL, 0x16, 0, 1 << 12)],
                           error=0 if name in ("wfi", "branch") else 3, count=2 if name == "wfi" else 1))
        if name == "branch":
            result[-1].actions[-1:-1] = [(WRITE, 0x16, 0x700, 0), (POLL, 0x16, 0, 1 << 12)]
            for number in TRAP_SENTINELS:
                result[-1].actions[-1:-1] = [(WRITE, 0x17, 0x220000 | number, 0),
                                             (POLL, 0x16, 0, 1 << 12), (READ, 4, 0, 0)]
    result.append(case("local_dpc", [(WRITE, 4, 0x12345679, 0), (WRITE, 0x17, 0x00231001, 0), (POLL, 0x16, 0, 1 << 12),
                                     (WRITE, 0x20, 0x7B109073, 0), (WRITE, 0x21, EBREAK, 0),
                                     (WRITE, 0x17, 0x00040000, 0), (POLL, 0x16, 0, 1 << 12)],
                       dpc=0x12345678, required=[{"csr": True}]))
    result.append(case("load_store", [(WRITE, 4, DATA, 0), (WRITE, 0x17, 0x00231001, 0), (POLL, 0x16, 0, 1 << 12),
                                      (WRITE, 0x20, 0x0000A103, 0), (WRITE, 0x21, 0x0020A223, 0),
                                      (WRITE, 0x17, 0x00040000, 0), (POLL, 0x16, 0, 1 << 12)],
                       registers={2: VALUE}, memory={DATA + 4: VALUE}, required=[{"load": True}, {"store": True}]))
    result[-1].image[DATA] = VALUE
    result.append(case("automatic", [(WRITE, 0x20, EBREAK, 0), (WRITE, 0x21, NOP, 0),
                                     (WRITE, 0x17, 0x00040000, 0), (POLL, 0x16, 0, 1 << 12),
                                     (WRITE, 0x18, 1 << 16, 0), (WRITE, 0x20, NOP, 0), (POLL, 0x16, 0, 1 << 12),
                                     (WRITE, 0x18, 1 << 17, 0), (WRITE, 0x21, EBREAK, 0), (POLL, 0x16, 0, 1 << 12),
                                     (WRITE, 0x18, 3 << 16, 0), (READ, 0x20, 0, 0), (POLL, 0x16, 0, 1 << 12),
                                     (WRITE, 0x18, 0, 0)], automatic=3))
    result.append(case("busy_conflict", [(WRITE, 4, DATA, 0), (WRITE, 0x17, 0x00231001, 0), (POLL, 0x16, 0, 1 << 12),
                                         (WRITE, 0x20, 0x0000A103, 0), (WRITE, 0x21, EBREAK, 0),
                                         (WRITE, 0x17, 0x00040000, 0), (WRITE, 0x20, 0xDEADBEEF, 0),
                                         (READ, 0x16, 0, 0), (WRITE, 0x16, 0x700, 0), (POLL, 0x16, 0, 1 << 12)],
                       conflicts=1, required=[{"load": True}]))
    result[-1].image[DATA] = VALUE
    result.append(case("explicit_nc", [(WRITE, 0x20, NOP, 0), (WRITE, 0x21, EBREAK, 0),
                                       (WRITE, 0x17, 0x00040000, 0), (POLL, 0x16, 0, 1 << 12)],
                       enable_c=False, count=2, required=[{"sequence": 2, "ebreak": True}]))
    result.append(case("implicit_nc", [(WRITE, 0x20, NOP, 0), (WRITE, 0x21, NOP, 0),
                                       (WRITE, 0x17, 0x00040000, 0), (POLL, 0x16, 0, 1 << 12)],
                       enable_c=False, count=3, required=[{"sequence": 4, "ebreak": True}]))
    result.append(case("reset_store", [(WRITE, 4, DATA, 0), (WRITE, 0x17, 0x00231001, 0), (POLL, 0x16, 0, 1 << 12),
                                       (WRITE, 4, VALUE, 0), (WRITE, 0x17, 0x00231002, 0), (POLL, 0x16, 0, 1 << 12),
                                       (WRITE, 0x20, 0x0020A223, 0), (WRITE, 0x21, EBREAK, 0),
                                       (WRITE, 0x17, 0x00040000, 0), (BUS_CONTROL, 8, 2, 24),
                                       (WAIT_ACCEPT, DATA + 4, 0, 0), (WRITE, 0x10, 3, 0), (IDLE, 0, 32, 0),
                                       (BUS_CONTROL, 0, 0, 0), (IDLE, 0, 32, 0), (WRITE, 0x10, 1, 0),
                                       (POLL, 0x11, 0xC0000, 0xC0000), (POLL, 0x16, 0, 1 << 12)],
                       error=4, memory={DATA + 4: VALUE}, required=[{"store": True}]))
    result[-1].image[DATA] = VALUE
    result.append(case("deactivate_store", [(WRITE, 4, DATA, 0), (WRITE, 0x17, 0x00231001, 0), (POLL, 0x16, 0, 1 << 12),
                                            (WRITE, 4, VALUE, 0), (WRITE, 0x17, 0x00231002, 0), (POLL, 0x16, 0, 1 << 12),
                                            (WRITE, 0x20, 0x0020A223, 0), (WRITE, 0x21, EBREAK, 0),
                                            (WRITE, 0x17, 0x00040000, 0), (BUS_CONTROL, 8, 2, 24),
                                            (WAIT_ACCEPT, DATA + 4, 0, 0), (WRITE, 0x10, 0, 0),
                                            (BUS_CONTROL, 0, 0, 0), (IDLE, 0, 32, 0), (WRITE, 0x10, 1, 0),
                                            (IDLE, 0, 32, 0)],
                       memory={DATA + 4: VALUE}, required=[{"store": True}]))
    result[-1].image[DATA] = VALUE
    return result


def mutate(source, name):
    if name == "no-issue":
        pattern = r"wire\s+injectExecution =\n?[\s\S]*?;"
        replacement = "wire injectExecution = 1'h0;"
    elif name == "native-trap":
        pattern = r"if \(trap\) begin\n        mepc <= _GEN_198;"
        replacement = "if (trap | debugAccess) begin\n        mepc <= 32'hdeadbeef;"
    elif name == "drop-writeback":
        pattern = r"wire\s+actualWriteback =\n?[\s\S]*?;"
        replacement = "wire actualWriteback = 1'h0;"
    elif name == "drop-data-valid":
        pattern = r"assign debug_response_bits_dataValid = response_dataValid;"
        replacement = "assign debug_response_bits_dataValid = 1'h0;"
    else:
        raise ValueError("Unknown Program Buffer mutation")
    changed, count = re.subn(pattern, replacement, source)
    if count != 1:
        raise ValueError("Program Buffer mutation target changed: " + name)
    return changed


def compile_rtl(rtl, manifest, tool, output):
    command = [str(tool), "--cc", "--exe", "--build", "-j", "2", "--top-module", "DitDahE2",
               "--Mdir", str(output.resolve()), "-CFLAGS", "-std=c++17 -I" + str((output.parent / "inputs/test/common").resolve()),
               *[str((rtl / name).resolve()) for name in manifest["rtlHashes"]],
               str((output.parent / "inputs/test/test_debug/debug_sim.cpp").resolve())]
    result = subprocess.run(command, check=False, capture_output=True, text=True)
    (output / "compile.log").write_text(result.stdout + result.stderr)
    if result.returncode:
        raise RuntimeError("Program Buffer simulator compilation failed")
    return output / "VDitDahE2"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rtl", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--case", action="append", default=[])
    parser.add_argument("--delay", type=int, default=9)
    args = parser.parse_args()
    os.chdir(ROOT)
    manifest_hash = digest(args.rtl / "manifest.json")
    manifest = json.loads((args.rtl / "manifest.json").read_text())
    assert manifest["parameters"]["enableDebug"] and manifest["sourceHashes"] == sources()
    selected = cases()
    if args.case:
        assert set(args.case) <= {case.name for case in selected}
        selected = [case for case in selected if case.name in args.case]
    args.output.mkdir(parents=True, exist_ok=False)
    inputs = ["test/test_debug/verify_program_buffer.py", "test/test_debug/debug_sim.cpp", "test/common/model.py",
              "test/common/rvfi_trace.hpp", "test/common/compressed_model.py", "test/common/bit_model.py", "test/units/compressed_unit.py",
              "test/programs/debug_programs.py", "test/programs/programs.py"]
    for name in inputs + list(manifest["sourceHashes"]):
        target = args.output / "inputs" / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / name, target)
    tool = Path(shutil.which("verilator")).resolve()
    binary = compile_rtl(args.output / "rtl" if (args.output / "rtl").exists() else args.rtl, manifest, tool, args.output / "build")
    runs = []
    for case in selected:
        directory = args.output / case.name
        directory.mkdir()
        (directory / "image.hex").write_text("".join(f"{address:08x} {value:08x}\n" for address, value in sorted(case.image.items())))
        (directory / "actions.txt").write_text("".join(" ".join(map(str, action)) + "\n" for action in case.actions))
        command = [str(binary.resolve()), str((directory / "image.hex").resolve()), str((directory / "actions.txt").resolve()),
                   "0", str(args.delay), "100000", str(1 << 32 if case.data_fault is None else case.data_fault)]
        environment = dict(os.environ, DITDAH_E2_DEBUG_INJECTION="1")
        result = subprocess.run(command, check=False, capture_output=True, text=True, env=environment)
        (directory / "trace.txt").write_text(result.stdout)
        (directory / "stderr.txt").write_text(result.stderr)
        if result.returncode:
            raise RuntimeError(f"{case.name} simulator failed: {result.stderr}")
        counts = check(case, result.stdout)
        runs.append({"case": case.name, "exitStatus": result.returncode, "traceHash": digest(directory / "trace.txt"), **counts})
    negative_controls = []
    for name, case_name, expected in (() if args.case else (("no-issue", "explicit", "Debug execution exceeded cycle limit"),
                                      ("native-trap", "branch", "DMI read 0x4 differs"),
                                      ("drop-writeback", "cross", "Injected rd differs"),
                                      ("drop-data-valid", "read_then_fault", "DMI read 0x4 differs"))):
        case = next(item for item in selected if item.name == case_name)
        directory = args.output / (name + "-rtl")
        shutil.copytree(args.rtl, directory)
        target = directory / ("DitDahE2DebugHart.sv" if name == "drop-data-valid" else
                              "DitDahE2Csr.sv" if name == "native-trap" else "DitDahE2.sv")
        target.write_text(mutate(target.read_text(), name))
        mutant_binary = compile_rtl(directory, manifest, tool, args.output / (name + "-build"))
        run_directory = args.output / name
        run_directory.mkdir()
        (run_directory / "image.hex").write_text("".join(f"{address:08x} {value:08x}\n" for address, value in sorted(case.image.items())))
        (run_directory / "actions.txt").write_text("".join(" ".join(map(str, action)) + "\n" for action in case.actions))
        command = [str(mutant_binary.resolve()), str((run_directory / "image.hex").resolve()),
                   str((run_directory / "actions.txt").resolve()), "0", str(args.delay), "100000",
                   str(1 << 32 if case.data_fault is None else case.data_fault)]
        result = subprocess.run(command, check=False, capture_output=True, text=True,
                                env=dict(os.environ, DITDAH_E2_DEBUG_INJECTION="1"))
        (run_directory / "trace.txt").write_text(result.stdout)
        (run_directory / "stderr.txt").write_text(result.stderr)
        if name == "no-issue":
            assert result.returncode != 0 and expected in result.stderr, result.stderr
            reason = result.stderr.strip()
        else:
            assert result.returncode == 0, result.stderr
            try:
                check(case, result.stdout)
            except AssertionError as error:
                reason = str(error)
                assert expected in reason, reason
            else:
                raise AssertionError("Program Buffer checker accepted mutation: " + name)
        negative_controls.append({"mutation": name, "case": case_name, "rejected": reason,
                                  "rtlHash": digest(target), "traceHash": digest(run_directory / "trace.txt")})
    report = {"exitStatus": 0, "scope": "real DMI-driven Program Buffer execution with independent instruction semantics",
              "parameters": manifest["parameters"], "manifestHash": manifest_hash, "runs": runs,
              "negativeControls": negative_controls, "excluded": ["OpenOCD", "commercial proof", "full Debug 1.0 conformance"]}
    (args.output / "summary.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(f"PASS: {len(runs)} Program Buffer core scenarios")


if __name__ == "__main__":
    main()
