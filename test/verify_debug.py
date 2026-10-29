# SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
# SPDX-License-Identifier: MIT
"""Check processor retirement and abstract commands through synchronous DMI."""

import argparse
from collections import Counter, deque
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys

from debug_programs import cases, WAIT_RETIRE, READ, WRITE, POLL, IDLE, FINISH, BUS_CONTROL, WAIT_ACCEPT, WAIT_OFFER, INTERRUPTS, WAIT_IRQ
from model import Model, MASK

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from build_rtl import configuration, digest, sources


class DebugReference:
    def __init__(self, model):
        self.model = model
        self.active = self.halted = self.resume_ack = False
        self.data = [0, 0]
        self.pending = None
        self.dpc = 0
        self.control = 3
        self.cause = 3
        self.halts = self.resumes = self.steps = 0
        self.step_start = None
        self.step_requested = None
        self.register_reads = Counter()
        self.register_writes = Counter()
        self.error = 0
        self.counter_value = None
        self.counter_reads = 0
        self.memory_commands = self.memory_denials = 0
        self.reset_requested = False
        self.reset_expected = False
        self.resets = self.cancellations = 0
        self.orphan = None
        self.cycle = -1
        self.run_control = None
        self.latencies = []
        self.halt_states = []
        self.memory_faults = []
        self.halt_on_reset = self.reset_halt_pending = False
        self.reset_halts = 0
        self.reset_events = []

    def register(self, number, value=None):
        if number == 0x7B1:
            if value is not None:
                self.dpc = value & ~(1 if self.model.enable_c else 3)
            return self.dpc
        if number == 0x7B0:
            if value is not None:
                self.control = (value & (0x9004 if self.model.protected_mode else 0x8004)) | (3 if value & 3 or not self.model.protected_mode else 0)
            return 0x40000410 | self.control | (self.cause << 6)
        if 0x1000 <= number <= 0x101F:
            index = number - 0x1000
            if value is not None and index:
                self.model.registers[index] = value
            return self.model.registers[index]
        assert number in self.model.csrs or self.model.pmp is not None and self.model.pmp.read(number)[0], "Unsupported abstract register"
        if number == 0xB00 and value is None:
            return None
        assert number not in (0xB80, 0xC00, 0xC80), "Unsupported cycle register"
        if value is not None:
            self.model.write_csr(number, value)
        return self.model.read_csr(number)

    def request(self, address, op, value, retirements):
        assert op in (1, 2), "Invalid DMI operation"
        if op == 1:
            return
        if address == 0x10:
            if not value & 1:
                assert self.active and self.pending is not None and "request" in self.pending, "Unexpected DM deactivation"
                self.orphan, self.pending = self.pending, None
                self.active = False
                self.data = [0, 0]
                self.error = 0
                self.cancellations += 1
                return
            if not self.active:
                self.active = True
                return
            if self.pending is None:
                if value & 8:
                    self.halt_on_reset = True
                if value & 4:
                    self.halt_on_reset = False
            if value & (1 << 31):
                self.run_control = ("halt", self.cycle)
            if value & (1 << 30):
                assert self.halted and self.pending is None, "Resume without a completed halt"
                self.model.sleeping = False
                self.model.pc = self.dpc
                self.model.user_mode = self.control & 3 == 0
                if self.model.user_mode:
                    self.model.csrs[0x300] &= ~(1 << 17)
                self.halted = False
                self.resume_ack = False
                self.resumes += 1
                self.step_start = retirements if self.control & 4 else None
                self.step_requested = self.cycle if self.control & 4 else None
                self.counter_value = None
                self.run_control = ("resume", self.cycle)
            self.reset_requested = bool(value & 2)
            self.reset_expected |= self.reset_requested
            if self.reset_requested and self.pending is not None:
                assert "request" in self.pending, "Reset interrupted an unsupported command"
                self.pending["aborted"] = True
        elif address in (4, 5):
            assert self.pending is None, "Data write while an abstract command is busy"
            self.data[address - 4] = value
        elif address == 0x17:
            assert self.halted and self.pending is None, "Abstract command without an idle halted hart"
            assert self.error == 0, "Command submitted before error clearance"
            assert not value & ((1 << 18) | (1 << 19)), "Unsupported abstract execution"
            if value >> 24 == 0:
                assert value >> 20 & 7 == 2 and value & (1 << 17), "Unsupported abstract register command"
                self.pending = {"number": value & 0xFFFF, "write": bool(value & (1 << 16)), "data": self.data[0]}
            else:
                assert value >> 24 == 2 and value & 0xEFFFF == 0, "Unsupported abstract memory command"
                size, address = value >> 20 & 7, self.data[1]
                assert size <= 2, "Unsupported abstract memory size"
                write = bool(value & (1 << 16))
                machine = not (self.model.csrs[0x300] & (1 << 17) and self.model.csrs[0x300] & 0x1800 == 0)
                denied = bool(address % (1 << size)) or (self.model.pmp is not None and
                         not self.model.pmp.allowed((address, size, int(machine), int(write))))
                lane = address % 4
                request = (address, int(write), (self.data[0] << (8 * lane)) & MASK,
                           ((1 << (1 << size)) - 1) << lane if write else 0, size, int(machine))
                self.pending = {"request": request, "denied": denied, "completed": False}
                self.memory_commands += 1
                self.memory_denials += denied
        elif address == 0x16:
            self.error &= ~(value >> 8 & 7)
        else:
            raise AssertionError("Unexpected DMI write")

    def response(self, address, op, value, status, data, snapshot):
        assert status == 0, "DMI transport failed"
        if op == 2:
            return
        if address == 0x11:
            assert data & 0xFF == 0xA3, "Unexpected debug module version or authentication"
            halted, running = data >> 8 & 3, data >> 10 & 3
            unavailable = data >> 12 & 3
            assert data >> 14 & 3 == 0, "Hart is absent"
            if unavailable:
                assert unavailable == 3 and halted == running == 0 and snapshot.get("resetPending"), "Unexpected unavailable hart"
            else:
                assert halted in (0, 3) and running in (0, 3) and halted != running, "Inconsistent single hart status"
            awaiting_resume = self.run_control is not None and self.run_control[0] == "resume" and data >> 16 & 3 != 3
            if halted and not awaiting_resume:
                assert not snapshot["outstanding"] and not snapshot["completed"] and not snapshot.get("offered"), "Halt crossed unfinished memory"
                if not self.halted:
                    self.halts += 1
                    self.halt_states.append({"pc": snapshot["pc"], "user": snapshot["user"],
                                             "mepc": self.model.read_csr(0x341), "mstatus": self.model.read_csr(0x300),
                                             "mcause": self.model.read_csr(0x342)})
                    self.dpc = snapshot["pc"]
                    self.control = (self.control & ~3) | (0 if snapshot["user"] else 3)
                    self.cause = 1 if self.model.word(snapshot["pc"]) == 0x100073 and self.control & (1 << (12 if snapshot["user"] else 15)) else 3
                    if self.reset_halt_pending:
                        assert snapshot["pc"] == 0 and not snapshot["user"], "Reset halt lost its initial boundary"
                        self.cause = 5
                        self.reset_halts += 1
                        self.reset_halt_pending = False
                    if self.step_start is not None:
                        assert snapshot["retirements"] - self.step_start == 1, "Single step retired an incorrect instruction count"
                        self.steps += 1
                        self.cause = 4
                        self.step_start = None
                        self.latencies.append({"operation": "step", "acceptedCycle": self.step_requested,
                                              "observedCycle": self.cycle, "cycles": self.cycle - self.step_requested})
                        self.step_requested = None
                self.halted = True
                self.model.sleeping = False
            self.resume_ack = data >> 16 & 3 == 3
            if self.resume_ack:
                assert not snapshot.get("orphan"), "Resume acknowledged before orphan memory completion"
            if self.run_control is not None:
                operation, accepted = self.run_control
                if operation == "halt" and halted or operation == "resume" and self.resume_ack:
                    self.latencies.append({"operation": operation, "acceptedCycle": accepted,
                                          "observedCycle": self.cycle, "cycles": self.cycle - accepted})
                    self.run_control = None
        elif address == 0x16:
            assert data & 15 == 2 and data >> 24 & 31 == 0, "Unexpected abstract command capabilities"
            if not data & (1 << 12) and self.pending is not None:
                pending = self.pending
                if "request" in pending:
                    self.error = 4 if pending.get("aborted") else 3 if pending["denied"] else 5 if pending.get("fault") else 0
                    assert pending["completed"] == (not pending["denied"]), "Abstract memory completion differs"
                    if not self.error and not pending["request"][1]:
                        address, _, _, _, size, _ = pending["request"]
                        self.data[0] = sum(self.model.memory.get(address + lane, 0) << (8 * lane) for lane in range(1 << size))
                else:
                    number, write, value = pending["number"], pending["write"], pending["data"]
                    result = self.register(number, value if write else None)
                    (self.register_writes if write else self.register_reads)[number] += 1
                    if not write:
                        self.data[0] = result
                self.pending = None
            assert data >> 8 & 7 == self.error, "Abstract command error differs"
        elif address in (4, 5):
            assert self.pending is None, "Abstract result read before completion"
            if self.data[address - 4] is None:
                assert self.halted, "Counter sample outside a confirmed halt"
                assert self.counter_value is None or data == self.counter_value, "Cycle counter advanced while halted with stopcount set"
                self.counter_value = data
                self.counter_reads += 1
                self.data[address - 4] = data
            else:
                assert data == self.data[address - 4], "Abstract register result mismatch"
        else:
            raise AssertionError("Unexpected DMI read")


def check(case, trace):
    parameters = {"data_fault": case.data_fault, "enable_m": case.enable_m, "enable_c": case.enable_c, "protected_mode": case.protected_mode, "enable_a": case.enable_a,
                  "enable_zba": case.enable_zba, "enable_zbb": case.enable_zbb, "enable_zbs": case.enable_zbs}
    model = Model(case.image, **parameters)
    debug = DebugReference(model)
    physical = dict(case.image)
    offered, outstanding = {}, {}
    abstract_owner = None
    orphans, data_history = [], []
    completed = deque()
    dmi = None
    cycle, events, sequence, action_index = -1, 0, 0, 0
    action_eligible = False
    action_start = 0
    final = None
    words = {}
    coverage = Counter()
    resetting = False
    interrupt_mask = 0
    first_offer = {}
    maximum = Counter()
    interrupts, steps, returns = [], [], []
    retired_cycle = -1
    for line in trace.splitlines():
        fields = line.split()
        kind = fields[0]
        assert final is None or kind == "W", "Event after final metrics"
        if kind == "T":
            values = list(map(int, fields[1:]))
            assert len(values) in (3, 4), "Invalid input record"
            now, time, reset = values[:3]
            observed_mask = values[3] if len(values) == 4 else 0
            action = case.actions[action_index]
            if action[0] == INTERRUPTS:
                interrupt_mask = action[2]
            assert observed_mask == interrupt_mask and 0 <= interrupt_mask <= 7, "Interrupt input differs"
            assert now == cycle + 1 and time == now, "Invalid input clock"
            if reset and not resetting:
                assert debug.reset_expected and not outstanding and not completed and not offered, "System reset crossed unfinished native ownership"
                debug.reset_expected = False
                model = Model(physical, **parameters)
                model.cycle = now - 1
                debug.model = model
                debug.halted = False
                debug.resets += 1
                debug.control, debug.cause, debug.dpc = 3, 0, 0
                debug.reset_halt_pending = False
                debug.reset_events.append({"assertCycle": now})
            if not reset and resetting:
                debug.reset_halt_pending = debug.active and debug.halt_on_reset
                debug.reset_events[-1].update({"releaseCycle": now, "haltOnReset": debug.reset_halt_pending})
            resetting = bool(reset)
            model.clock(now, interrupt_mask)
            model.time = time
            cycle = now
            debug.cycle = now
            continue
        if kind not in ("F", "W"):
            assert int(fields[1]) == cycle, "Event lacks input clock"
        if kind == "P":
            port, request = fields[2], tuple(map(int, fields[3:]))
            assert port in ("I", "D") and port not in offered and len(request) == 6, "Invalid first offer"
            address, write, data, mask, size, machine = request
            assert size <= 2 and address % (1 << size) == 0, "Invalid memory size or alignment"
            mprv_user = bool(model.csrs[0x300] & (1 << 17) and model.csrs[0x300] & 0x1800 == 0)
            effective_user = model.user_mode if port == "I" else mprv_user if debug.halted else model.user_mode or mprv_user
            assert machine == int(not effective_user), "Native privilege differs"
            assert model.pmp is None or model.pmp.allowed((address, size, machine, 2 if port == "I" else write)), "Denied native offer"
            assert mask == (((1 << (1 << size)) - 1) << (address % 4) if write else 0), "Invalid byte mask"
            assert port != "I" or (write, size) == (0, 2), "Invalid instruction request"
            offered[port] = request
            first_offer[port] = cycle
            if port == "D" and debug.halted:
                pending = debug.pending or debug.orphan
                assert pending is not None and "request" in pending and not pending["denied"], "Unowned debug memory offer"
                expected = pending["request"]
                assert request[:2] + request[3:] == expected[:2] + expected[3:] and (not write or data == expected[2]), "Abstract memory request differs"
                assert abstract_owner is None, "Abstract native owner overwritten"
                abstract_owner = pending
                pending["offeredCycle"] = cycle
        elif kind == "Q":
            port, request = fields[2], tuple(map(int, fields[3:]))
            assert port not in outstanding and offered.pop(port) == request, "Native request ownership differs"
            maximum[port + "OfferToAcceptance"] = max(maximum[port + "OfferToAcceptance"], cycle - first_offer.pop(port))
            outstanding[port] = (cycle, request, physical.get(request[0] & ~3, 0))
            physical.setdefault(request[0] & ~3, 0)
            if port == "D":
                data_history.append({"acceptedCycle": cycle, "request": request, "abstract": abstract_owner is not None})
                if abstract_owner is not None:
                    abstract_owner["acceptedCycle"] = cycle
        elif kind == "S":
            port, value, fault = fields[2], int(fields[3]), int(fields[4])
            assert port in outstanding, "Unowned native response"
            accepted, request, expected_data = outstanding.pop(port)
            maximum[port + "AcceptanceToCompletion"] = max(maximum[port + "AcceptanceToCompletion"], cycle - accepted)
            assert cycle > accepted and (value, fault) == (expected_data, int(port == "D" and request[0] == case.data_fault)), "Native response differs"
            address, write, data, mask, size, machine = request
            if write and not fault:
                old = physical[address & ~3]
                for lane in range(4):
                    if mask >> lane & 1:
                        old = (old & ~(255 << (8 * lane))) | (data & (255 << (8 * lane)))
                physical[address & ~3] = old
            if port == "D":
                data_history[-1]["completedCycle"] = cycle
                if abstract_owner is not None:
                    pending = abstract_owner
                    assert pending is not None and "request" in pending and not pending["completed"], "Duplicate abstract memory completion"
                    pending["completed"] = True
                    pending["completedCycle"] = cycle
                    pending["fault"] = bool(fault)
                    if fault:
                        debug.memory_faults.append({"cycle": cycle, "address": address, "write": bool(write)})
                    if write and not fault:
                        for lane in range(4):
                            if mask >> lane & 1:
                                model.memory[(address & ~3) + lane] = data >> (8 * lane) & 255
                    if debug.orphan is pending:
                        debug.orphan = None
                    abstract_owner = None
                else:
                    completed.append(request)
        elif kind == "R":
            assert not debug.halted, "Instruction retired during a confirmed halt"
            assert debug.orphan is None, "Instruction completed before orphan memory"
            assert not resetting and not debug.reset_halt_pending, "Instruction retired before reset halt"
            values = list(map(int, fields[2:]))
            expected = model.step()
            pc, word, target, rd, writes, value, trap, cause, tval, user = values
            assert (pc, word, target, bool(trap), bool(user)) == (expected.pc, expected.word, expected.next_pc, expected.trap, expected.user_mode), "Retirement identity differs"
            assert bool(writes) == bool(expected.rd) and value == expected.value and (not writes or rd == expected.rd), "Retirement register result differs"
            assert not trap or (cause, tval) == (expected.cause, expected.tval), "Trap metadata differs"
            if expected.memory:
                assert completed, "Retirement preceded memory completion"
                request = completed.popleft()
                assert request[:5] == expected.memory and request[5] == expected.memory_machine, "Retired memory request differs"
            else:
                assert not completed, "Unexpected completed data transaction"
            events += 1
            retired_cycle = cycle
            if debug.step_start is not None:
                steps.append({"cycle": cycle, "pc": pc, "nextPc": target, "trap": bool(trap),
                              "cause": cause if trap else 0, "user": bool(user), "nextUser": model.user_mode})
            if expected.instruction == "mret" and not trap:
                returns.append({"cycle": cycle, "pc": pc, "target": target, "user": model.user_mode})
            coverage[expected.instruction] += 1
            action = case.actions[action_index]
            action_eligible |= action[0] == WAIT_RETIRE and action[1] == pc
        elif kind == "N":
            assert cycle != retired_cycle, "Interrupt and instruction completed together"
            assert not debug.halted and debug.step_start is None, "Interrupt entered during debug halt or step"
            assert "D" not in outstanding and "D" not in offered and not completed, "Interrupt crossed unfinished data memory"
            user = model.user_mode
            observed = tuple(map(int, fields[2:]))
            assert observed == model.interrupt(), "Interrupt metadata differs"
            interrupts.append({"cycle": cycle, "pc": observed[0], "target": observed[1],
                               "cause": observed[2], "user": user})
        elif kind == "J":
            seq, index, address, op, value = map(int, fields[2:])
            assert dmi is None and seq == sequence and index == action_index, "DMI ownership differs"
            action = case.actions[index]
            assert action[0] in (READ, WRITE, POLL), "DMI request lacks a script action"
            assert (address, op, value) == (action[1], 2 if action[0] == WRITE else 1, action[2] if action[0] == WRITE else 0), "DMI request differs from script"
            snapshot = {"pc": model.pc, "user": model.user_mode, "outstanding": bool(outstanding),
                        "completed": bool(completed), "retirements": events, "offered": bool(offered),
                        "orphan": debug.orphan is not None,
                        "resetPending": debug.reset_expected or debug.reset_requested or resetting}
            debug.request(address, op, value, events)
            if case.orphan_step and (address, op, value) == (0x10, 2, 0):
                assert debug.orphan is not None and not debug.orphan["completed"], "Deactivation missed old memory"
                expected_offered = "offered" in case.name
                assert ("D" in offered) == expected_offered and ("D" in outstanding) != expected_offered, "Wrong deactivation ownership boundary"
                debug.orphan["deactivatedCycle"] = cycle
                orphans.append(debug.orphan)
            if case.orphan_step and (address, op, value) == (0x10, 2, 0x40000001) and len(orphans) == 1 and "resumeCycle" not in orphans[0]:
                assert debug.orphan is orphans[0] and not debug.orphan["completed"], "Resume waited for old memory"
                debug.orphan["resumeCycle"] = cycle
            dmi = (seq, cycle, address, op, value, snapshot)
            sequence += 1
        elif kind == "K":
            seq, status, data = map(int, fields[2:])
            assert dmi is not None and seq == dmi[0] and cycle > dmi[1], "DMI response lacks an accepted owner"
            maximum["dmiAcceptanceToCompletion"] = max(maximum["dmiAcceptanceToCompletion"], cycle - dmi[1])
            debug.response(*dmi[2:5], status, data, dmi[5])
            action = case.actions[action_index]
            action_eligible = action[0] != POLL or data & action[3] == action[2]
            dmi = None
        elif kind == "L":
            assert int(fields[2]) == action_index, "Script action completed out of order"
            action = case.actions[action_index]
            eligible = action_eligible or action[0] == IDLE and cycle - action_start >= action[2] or action[0] in (BUS_CONTROL, INTERRUPTS)
            eligible |= action[0] == WAIT_ACCEPT and "D" in outstanding and outstanding["D"][1][0] == action[1]
            eligible |= action[0] == WAIT_OFFER and "D" in offered and offered["D"][0] == action[1]
            eligible |= action[0] == WAIT_IRQ and action[2] > 0 and len(interrupts) >= action[2] and interrupts[-1]["cause"] == action[1]
            assert eligible, "Script action completed before its condition"
            action_index += 1
            action_start = cycle + 1
            action_eligible = False
        elif kind == "F":
            cycles, index = map(int, fields[1:])
            assert cycles == cycle + 1 and index == action_index == len(case.actions) - 1, "Incomplete script"
            assert case.actions[index][0] == FINISH and cycles - action_start >= 8, "Missing completion window"
            assert not outstanding and not completed and abstract_owner is None and dmi is None and debug.pending is None and debug.orphan is None, "Unfinished transaction"
            final = {"cycles": cycles, "retirements": events, "dmiTransactions": sequence}
        elif kind == "W":
            address, value = map(int, fields[1:])
            assert address not in words, "Duplicate final memory word"
            words[address] = value
        else:
            raise AssertionError("Unknown trace record")
    assert final is not None and words == physical, "Missing or incorrect final memory"
    for address, value in case.signature.items():
        assert words[address] == value & MASK and model.word(address) == value & MASK, "Program signature differs"
    assert debug.steps == case.steps and debug.halts == case.halts and debug.resumes == (case.halts if case.resumes is None else case.resumes), "Missing halt or resume"
    assert (debug.resets, debug.cancellations) == (case.resets, case.cancellations), "Missing reset or command cancellation"
    assert len(debug.memory_faults) == case.bus_faults, "Missing abstract memory fault"
    assert debug.reset_halts == case.reset_halts, "Missing reset halt"
    assert all(debug.register_reads[0x1000 + index] for index in range(32)), "Incomplete GPR readback"
    assert debug.counter_reads == 2, "Missing stable halt counter samples"
    assert len(interrupts) == case.interrupts, "Unexpected interrupt count"
    if case.step_outcome is not None:
        assert len(steps) == 1, "Missing directed step event"
        assert tuple(steps[0][key] for key in ("pc", "nextPc", "trap", "cause", "user")) == case.step_outcome, "Directed step outcome differs"
    timing = None
    if case.orphan_step:
        assert len(orphans) == 1 and orphans[0]["resumeCycle"] < orphans[0]["completedCycle"] < steps[0]["cycle"], "Step did not include orphan drain"
        assert len([item for item in data_history if item["abstract"]]) == 1, "Old abstract transfer completed more than once"
        assert tuple(model.read_csr(number) for number in (0x341, 0x342, 0x343)) == (0x234, 7, 0xABCDEF), "Orphan step changed trap state"
        assert all(maximum[port + "OfferToAcceptance"] <= 8 and maximum[port + "AcceptanceToCompletion"] <= 24 for port in ("I", "D")), "Native service exceeded the declared bound"
        assert maximum["dmiAcceptanceToCompletion"] <= 8, "DMI service exceeded the declared bound"
        general = 38 + (3 + int(case.enable_c)) * 32 + 34 * int(case.enable_m) + 16
        observed = next(item for item in debug.latencies if item["operation"] == "step")
        assert observed["cycles"] <= general + 20, "Orphan step exceeded its observation bound"
        timing = {"nativeAcceptBound": 8, "nativeResponseBound": 24, "dmiResponseBound": 8,
                  "elapsedConvention": "Q cycle minus first P cycle is at most eight. S cycle minus Q cycle is at most 24. The formal acceptance assumption instead forces the eighth sampled edge, which is seven elapsed cycles.",
                  "resumeBoundCycles": 38, "generalStepBoundCycles": general, "pollBoundCycles": 20,
                  "minimumClockHz": 1000, "generalStepObservationMilliseconds": general + 20,
                  "physicalFrequencyClaim": False, "observation": observed}
    if case.name == "user_irq_handler_halt":
        assert interrupts[0]["user"] and interrupts[0]["pc"] == 0x200, "Interrupt did not preserve the U boundary"
        stopped = debug.halt_states[-1]
        assert stopped["pc"] in (0x180, 0x184) and not stopped["user"], "Halt missed the M handler"
        assert (stopped["mepc"], stopped["mstatus"], stopped["mcause"]) == (0x200, 0, 0x8000000B), "Halt lost U trap state"
        assert len(returns) == 1 and returns[0]["target"] == 0x200 and returns[0]["user"] and model.user_mode, "Handler did not return to U"
    return {**final, "halts": debug.halts, "resumes": debug.resumes, "steps": debug.steps,
            "interruptEvents": interrupts, "stepEvents": steps, "returnEvents": returns, "haltStates": debug.halt_states,
            "instructions": dict(coverage), "registerReads": dict(debug.register_reads),
            "registerWrites": dict(debug.register_writes), "stableCounterSamples": debug.counter_reads,
            "abstractMemoryCommands": debug.memory_commands, "abstractMemoryDenials": debug.memory_denials,
            "abstractMemoryFaults": debug.memory_faults, "resetHalts": debug.reset_halts, "resetEvents": debug.reset_events,
            "resets": debug.resets, "commandCancellations": debug.cancellations,
            "orphanTransfers": orphans, "dataHistory": data_history if case.orphan_step else [], "orphanStepTiming": timing,
            "runControlObservations": debug.latencies, "maximumObservedCycles": dict(maximum)}


def mutate_register_write(text):
    pattern = r"(assign backend_writePulse\s*=)([^;]+);"
    matches = list(re.finditer(pattern, text))
    assert len(matches) == 1, "Abstract write mutation target changed"
    return re.sub(pattern, lambda match: match[1] + " (" + match[2] + ") & (debug_request_bits_register != 16'h100A);", text)


def mutate_protection(text):
    target = "& protection_allowed;"
    assert text.count(target) == 1, "Debug protection mutation target changed"
    return text.replace(target, "& 1'b1;")


def mutate_reset(text):
    target = "assign core_coreReset = resetting;"
    assert text.count(target) == 1 and "wire        resetRequest =" in text, "Debug reset mutation target changed"
    return text.replace(target, "assign core_coreReset = resetting | resetRequest;")


def mutate_trap_pc(text):
    pattern = r"(mepc <= )(\{trapPc\[[^\n]+)(;)"
    assert len(re.findall(pattern, text)) == 1, "Trap PC mutation target changed"
    return re.sub(pattern, r"\1(\2) + 32'd4\3", text)


def mutate_mret_privilege(text):
    pattern = r"(_GEN_\d+ \? )mppUser( : userMode_0)"
    assert len(re.findall(pattern, text)) == 1, "MRET privilege mutation target changed"
    return re.sub(pattern, r"\g<1>1'h0\2", text)


def mutate_step_pc(text):
    target = ": core_architecturalPc;"
    assert text.count(target) == 1, "Step PC mutation target changed"
    return text.replace(target, ": core_architecturalPc + (entryCause == 3'h4 ? 32'd4 : 32'd0);")


def mutate_memory_fault(text):
    target = "memory_response_bits_fault ? 3'h5 : 3'h0"
    assert text.count(target) == 1, "Debug memory fault mutation target changed"
    return text.replace(target, "memory_response_bits_fault ? 3'h0 : 3'h0")


def mutate_reset_halt(text):
    target = "debug_control_active & debug_control_haltOnReset"
    assert text.count(target) == 1, "Reset halt mutation target changed"
    return text.replace(target, "debug_control_active & 1'h0")


def mutate_orphan_resume(text):
    pattern = r"(wire\s+resume\s*=\s*)([^;]+);"
    matches = list(re.finditer(pattern, text))
    assert len(matches) == 1, "Orphan resume mutation target changed"
    expression = matches[0][2]
    changed, count = re.subn(r"\s*&\s*~(?:sending|waiting)\b", "", expression)
    assert count == 2, "Orphan resume ownership target changed"
    return text[:matches[0].start(2)] + changed + text[matches[0].end(2):]


def checker_inputs():
    names = ("test/debug_programs.py", "test/debug_sim.cpp", "test/rvfi_trace.hpp", "test/verify_debug.py", "test/test_debug.py",
             "test/model.py", "test/bit_model.py", "test/programs.py", "test/compressed_model.py", "test/compressed_unit.py", "test/pmp.py",
             "scripts/build_rtl.py")
    return {name: digest(Path(name)) for name in names}


def preserve(destination, source, hashes):
    for name, expected in hashes.items():
        data = (source / name).read_bytes()
        assert hashlib.sha256(data).hexdigest() == expected, "Input changed before preservation"
        path = destination / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rtl", type=Path, default=Path("result/debug-rtl"))
    parser.add_argument("--output", type=Path, default=Path("result/debug-verification"))
    parser.add_argument("--case", action="append", default=[])
    args = parser.parse_args()
    manifest_hash = digest(args.rtl / "manifest.json")
    manifest = json.loads((args.rtl / "manifest.json").read_text())
    parameters = manifest["parameters"]
    assert parameters == configuration(parameters), "Incomplete debug configuration"
    assert parameters["resetVector"] == 0 and parameters["enableDebug"] is True, "Unsupported debug reset or interface"
    assert all(type(parameters[key]) is bool for key in ("enableM", "enableC", "protectedMode")), "Invalid debug configuration type"
    workloads = cases(parameters["enableM"], parameters["enableC"], parameters["protectedMode"],
                      enable_a=parameters["enableA"], enable_zba=parameters["enableZba"],
                      enable_zbb=parameters["enableZbb"], enable_zbs=parameters["enableZbs"])
    all_workloads = workloads
    if args.case:
        names = {case.name for case in workloads}
        assert set(args.case) <= names, "Unknown debug case"
        workloads = [case for case in workloads if case.name in args.case]
    assert manifest["sourceHashes"] == sources(), "Stale RTL source inputs"
    assert all(digest(args.rtl / name) == value for name, value in manifest["rtlHashes"].items()), "RTL changed"
    initial = checker_inputs()
    args.output.mkdir(parents=True, exist_ok=False)
    preserve(args.output / "inputs", Path("."), initial | manifest["sourceHashes"])
    preserve(args.output / "rtl", args.rtl, manifest["rtlHashes"] | {"manifest.json": manifest_hash})
    tool = Path(shutil.which("verilator")).resolve()
    tool_info = {}
    for name in ("verilator", "g++", "make", "python3"):
        executable = Path(sys.executable if name == "python3" else shutil.which(name)).resolve()
        tool_info[name] = {"hash": digest(executable), "version": subprocess.check_output([str(executable), "--version"], text=True).splitlines()[0]}
    report = {"parameters": manifest["parameters"], "command": ["python3", "test/verify_debug.py", "--rtl", "rtl", "--output", "verification",
              *[part for name in args.case for part in ("--case", name)]],
              "scope": "DMI halt, registers, resume, step, EBREAK, abstract memory and U return on the processor",
              "checkerHashes": initial, "sourceHashes": manifest["sourceHashes"], "rtlHashes": manifest["rtlHashes"],
              "manifestHash": manifest_hash, "simulatorHash": digest(tool),
              "simulator": subprocess.check_output([str(tool), "--version"], text=True).strip(), "runs": [], "negativeControls": []}
    report["tools"] = tool_info
    report["environment"] = {"clock": "one rising edge per trace cycle", "cycleLimit": 100000,
        "nativeRequestReady": "At least once in eight cycles when no request is outstanding and the script permits acceptance",
        "nativeResponseOffer": "One through delay cycles after acceptance, or one cycle when delay is zero, except explicit script holds",
        "dmiResponseReady": "At least once in eight cycles", "runControlTiming": "Observed bounds for these workloads, not unbounded hardware guarantees"}
    report["environment"]["boundedScriptHolds"] = "For orphan step cases, data acceptance occurs within eight cycles and response within 24 cycles. DMI ready stays high during this bounded hold. Other phases retain the normal peer timing."

    def compile_rtl(rtl, name):
        build = args.output / name
        command = [str(tool), "--cc", "--exe", "--build", "-j", "2", "--top-module", "DitDahE2",
                   "--Mdir", str(build.resolve()), "-CFLAGS", "-std=c++17",
                   *[str((rtl / file).resolve()) for file in manifest["rtlHashes"]],
                   str((args.output / "inputs/test/debug_sim.cpp").resolve())]
        result = subprocess.run(command, capture_output=True, text=True)
        (args.output / f"{name}.log").write_text(result.stdout + result.stderr)
        assert result.returncode == 0, "Debug simulator compilation failed"
        return build / "VDitDahE2"

    def execute(binary, case, seed, delay, name, expected_failure=None):
        directory = args.output / name
        directory.mkdir()
        image, script = directory / "image.hex", directory / "actions.txt"
        image.write_text("".join(f"{address:08x} {value:08x}\n" for address, value in sorted(case.image.items())))
        script.write_text("".join(" ".join(map(str, action)) + "\n" for action in case.actions))
        command = [str(binary.resolve()), str(image.resolve()), str(script.resolve()), str(seed), str(delay), "100000",
                   str(1 << 32 if case.data_fault is None else case.data_fault)]
        result = subprocess.run(command, capture_output=True, text=True)
        (directory / "trace.txt").write_text(result.stdout)
        (directory / "stderr.txt").write_text(result.stderr)
        record = {"case": case.name, "seed": seed, "delay": delay, "exitStatus": result.returncode,
                  "command": [str(binary.relative_to(args.output)), name + "/image.hex", name + "/actions.txt",
                              str(seed), str(delay), "100000", str(1 << 32 if case.data_fault is None else case.data_fault)],
                  "imageHash": digest(image), "actionsHash": digest(script), "traceHash": digest(directory / "trace.txt"),
                  "binaryHash": digest(binary)}
        if expected_failure is None:
            assert result.returncode == 0, result.stderr
        else:
            assert result.returncode != 0 and expected_failure in result.stderr, "RTL mutant did not violate its protocol check"
            record["rejected"] = result.stderr.strip()
        return result.stdout, record

    try:
        binary = compile_rtl(args.output / "rtl", "build")
        for case in workloads:
            for seed, delay in ((0, 0), (1, 9), (19, 24)):
                trace, record = execute(binary, case, seed, delay, f"{case.name}-s{seed}-d{delay}")
                record.update(check(case, trace))
                report["runs"].append(record)
        changed = args.output / "changed-rtl"
        shutil.copytree(args.output / "rtl", changed)
        path = changed / "DitDahE2DebugHart.sv"
        path.write_text(mutate_register_write(path.read_text()))
        binary = compile_rtl(changed, "changed-build")
        case = workloads[0]
        trace, record = execute(binary, case, 0, 0, "changed-register-write")
        try:
            check(case, trace)
        except AssertionError as error:
            assert str(error) == "Abstract register result mismatch", "Mutation failed outside the intended check"
            record.update({"rejected": str(error), "rtlHash": digest(path)})
            report["negativeControls"].append(record)
        else:
            raise AssertionError("Suppressed abstract write passed the checker")
        for name, mutation, case_name, failure in (
                ("reset", mutate_reset, "reset_accepted_memory", "System reset preceded accepted memory completion"),
                *(([("protection", mutate_protection, "abstract_memory_user", None)] if parameters["protectedMode"] else []))):
            if not any(case.name == case_name for case in workloads):
                continue
            changed = args.output / (name + "-rtl")
            shutil.copytree(args.output / "rtl", changed)
            path = changed / "DitDahE2DebugHart.sv"
            path.write_text(mutation(path.read_text()))
            binary = compile_rtl(changed, name + "-build")
            case = next(item for item in all_workloads if item.name == case_name)
            trace, record = execute(binary, case, 0, 0, "changed-" + name, failure)
            if failure is None:
                try:
                    check(case, trace)
                except AssertionError as error:
                    assert str(error) == "Denied native offer", "Protection mutation failed outside the intended check"
                    record["rejected"] = str(error)
                else:
                    raise AssertionError("Bypassed protection passed the checker")
            record["rtlHash"] = digest(path)
            report["negativeControls"].append(record)
        for name, mutation, module, case_name, failure in (
                ("memory-fault", mutate_memory_fault, "DitDahE2DebugHart.sv", "abstract_read_fault", "Abstract command error differs"),
                ("reset-halt", mutate_reset_halt, "DitDahE2DebugHart.sv", "reset_halt_accepted_memory", "Instruction retired before reset halt"),
                ("orphan-resume", mutate_orphan_resume, "DitDahE2DebugHart.sv", "orphan_accepted_step_load", "Resume acknowledged before orphan memory completion"),
                ("step-pc", mutate_step_pc, "DitDahE2DebugHart.sv", "step_taken_branch", "Abstract register result mismatch"),
                ("trap-pc", mutate_trap_pc, "DitDahE2Csr.sv", "user_irq_handler_halt", "Abstract register result mismatch"),
                ("mret-privilege", mutate_mret_privilege, "DitDahE2Csr.sv", "step_mret_user", "Abstract register result mismatch")):
            selected = [case for case in workloads if case.name == case_name]
            if not selected:
                continue
            changed = args.output / (name + "-rtl")
            shutil.copytree(args.output / "rtl", changed)
            path = changed / module
            path.write_text(mutation(path.read_text()))
            binary = compile_rtl(changed, name + "-build")
            trace, record = execute(binary, selected[0], 0, 0, "changed-" + name,
                                    "Debug execution exceeded cycle limit" if name == "reset-halt" else None)
            try:
                check(selected[0], trace)
            except AssertionError as error:
                assert str(error) == failure, "Mutation failed outside the intended check"
                record.update({"rejected": str(error), "rtlHash": digest(path)})
                report["negativeControls"].append(record)
            else:
                raise AssertionError("Changed debug boundary passed the checker")
        assert checker_inputs() == initial and sources() == manifest["sourceHashes"], "Verification inputs changed"
        assert digest(args.rtl / "manifest.json") == manifest_hash, "RTL manifest changed"
        assert all(digest(args.rtl / name) == value for name, value in manifest["rtlHashes"].items()), "RTL inputs changed"
        assert all(digest(args.output / "inputs" / name) == value for name, value in (initial | manifest["sourceHashes"]).items()), "Preserved inputs changed"
        report["exitStatus"] = 0
    except Exception as error:
        report["exitStatus"] = 1
        report["failure"] = str(error)
        raise
    finally:
        (args.output / "summary.json").write_text(json.dumps(report, indent=2) + "\n")
    print(f"PASS: {len(report['runs'])} processor debug runs, {len(report['negativeControls'])} RTL negative control")


if __name__ == "__main__":
    main()
