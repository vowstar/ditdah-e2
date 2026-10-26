# SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
# SPDX-License-Identifier: MIT
"""Check atomic processor execution against shared SRAM history and ISA semantics."""

import argparse
from collections import Counter, deque
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys

from atomic_memory import Reference, PORTS
from atomic_programs import cases, RAM, HALT_ATOMIC
from model import Model
from verify_debug import DebugReference
from console import Reference as ConsoleReference

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from build_rtl import digest


def observer(rtl, ram_size):
    top = (rtl / "DitDahE2AtomicPlatformTop.sv").read_text()
    ports = re.search(r"module DitDahE2AtomicPlatformTop\((.*?)\);", top, re.S)
    assert ports and len(re.findall(r"DitDahE2AtomicPlatform\s+platform\s*\(", top)) == 1, "Changed atomic platform hierarchy"
    declarations, assignments = [], []

    def expose(name, width, source):
        declarations.append(f"output {'[' + str(width - 1) + ':0] ' if width > 1 else ''}{name}")
        assignments.append(f"assign {name} = {source};")

    widths = {"request_valid": 1, "request_ready": 1, "request_bits_address": 32,
              "request_bits_write": 1, "request_bits_data": 32, "request_bits_mask": 4,
              "request_bits_size": 2, "request_bits_machine": 1, "request_bits_operation": 4,
              "response_valid": 1, "response_ready": 1, "response_bits_data": 32, "response_bits_fault": 1}
    for group, instance, port in (("i", "core", "instruction"), ("d", "core", "data"),
                                  ("console", "console", "memory"), ("timer", "timer", "memory")):
        for field, width in widths.items():
            expose(f"o_{group}_{field}", width, f"dut.platform.{instance}.{port}_{field}")
    for port in PORTS:
        for field, width in widths.items():
            expose(f"o_s_{port}_{field}", width, f"dut.platform.atomic.{port}_{field}")
    expose("o_reset", 1, "dut.platform.shared.reset")
    expose("o_clear", 1, "dut.platform.core.reservationClear")
    expose("o_debug", 1, "dut.platform.core.dataDebug")
    expose("o_halt", 1, "dut.platform.core.dm.hart_control_halt" if "dmi_request_valid" in ports[1] else "1'b0")
    expose("o_sram_read", 1, "dut.platform.atomic.memory.readEnable")
    width = max(1, (ram_size // 4 - 1).bit_length())
    expose("o_sram_address", 32, f"{{{32 - width}'b0, dut.platform.atomic.memory.address}}")
    expose("o_sram_mask", 4, "dut.platform.atomic.memory.writeMask")
    expose("o_sram_data", 32, "dut.platform.atomic.memory.writeData")
    notice = "// SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>\n// SPDX-License-Identifier: MIT\n"
    return (notice + "module AtomicBench(" + ports[1] + ",\n" + ",\n".join(declarations) +
            ");\nDitDahE2AtomicPlatformTop dut(.*);\n" + "\n".join(assignments) + "\nendmodule\n")


def trace_cycles(trace, partial=False):
    groups = []
    total = None
    for line in trace.splitlines():
        fields = line.split()
        assert fields and total is None, "Record after atomic completion"
        if fields[0] == "T":
            assert len(fields) == 9 and int(fields[1]) == len(groups), "Missing atomic clock record"
            groups.append([fields])
        elif fields[0] == "F":
            assert len(fields) == 2 and int(fields[1]) == len(groups), "Invalid atomic completion"
            total = int(fields[1])
        else:
            assert fields[0] in ("B", "C", "P", "Q", "S", "R", "N", "A", "V", "J", "K", "L", "H"), "Unknown atomic trace record"
            assert groups and int(fields[1]) == len(groups) - 1, "Atomic event lacks a clock"
            groups[-1].append(fields)
    assert total is not None or partial and groups, "Atomic program did not finish"
    return groups


def boundary_witness(case, groups):
    if case.boundary is None:
        return None
    control, pc, operation = case.boundary
    rows = [fields for group in groups for fields in group]
    requests = [fields for fields in rows if fields[0] == "Q" and fields[2] == "D" and int(fields[-1]) == operation]
    assert requests, "Missing boundary atomic acceptance"
    accepted = int(requests[0][1])
    response = next((int(fields[1]) for fields in rows if fields[0] == "S" and fields[2] == "D" and int(fields[1]) > accepted), None)
    assert response is not None, "Missing boundary atomic response"
    controls = [int(group[0][1]) for group in groups if int(group[0][-1])] if control == "interrupt" else [
        int(fields[1]) for fields in rows if fields[0] == "H" and int(fields[2])]
    assert controls and accepted < controls[0] < response, "Control did not arrive during an accepted atomic operation"
    if control == "halt":
        assert all(sum(fields[0] == "H" for fields in group) == 1 for group in groups), "Missing halt level sample"
        commands = [fields for fields in rows if fields[0] == "J" and tuple(map(int, fields[4:])) == (16, 2, 0x80000001)]
        assert len(commands) == 1 and int(commands[0][1]) + 1 == controls[0], "Halt level lacks its accepted DMI command"
    entries = [int(fields[1]) for fields in rows if fields[0] == "N"] if control == "interrupt" else [
        int(group[0][1]) for group in groups if int(group[0][5])]
    assert entries and entries[0] > response, "Control entry preceded atomic completion"
    entry = entries[0]
    assert not any(int(group[0][4]) for group in groups[accepted:entry]), "Reservation cleared before atomic completion and control entry"
    assert int(groups[entry][0][4]), "Control entry did not clear the reservation"
    retirements = [fields for fields in rows if fields[0] == "R" and accepted <= int(fields[1]) < entry]
    assert len(retirements) == 1 and int(retirements[0][2]) == pc and int(retirements[0][1]) == response, "Atomic retirement boundary differs"
    assert not any(fields[0] == "Q" and fields[2] == "D" and accepted < int(fields[1]) < entry for fields in rows), "Younger data request crossed the atomic control boundary"
    if control == "interrupt":
        event = next(fields for fields in rows if fields[0] == "N")
        assert tuple(map(int, event[2:])) == (pc + 4, 0x800, 0x8000000B), "Atomic interrupt saved the wrong PC"
        returns = [fields for fields in rows if fields[0] == "R" and int(fields[3]) == 0x30200073 and int(fields[1]) > entry]
        assert len(returns) == 1 and int(returns[0][4]) == pc + 4, "Atomic interrupt return differs"
        resumed = int(returns[0][1])
    else:
        resumed = entry
    resumed_events = [fields for fields in rows if fields[0] == "R" and int(fields[1]) > resumed]
    assert resumed_events and int(resumed_events[0][2]) == pc + 4, "Atomic resume executed the wrong instruction"
    return {"operation": operation, "control": control, "requestCycle": accepted,
            "controlCycle": controls[0], "responseCycle": response, "retireCycle": response,
            "entryCycle": entry, "resumePc": pc + 4}


def check(case, parameters, regions, trace, partial=False):
    assert parameters["enableDebug"] or not case.debug, "DMI actions require debug support"
    groups = trace_cycles(trace, partial)
    boundary = boundary_witness(case, groups)
    memory = Reference({"baseAddress": regions["sram"]["base"], "sizeBytes": regions["sram"]["size"]})
    memory_events = {port: deque() for port in PORTS}
    completed = deque()
    offers, outstanding = {}, {}
    rom_completions = deque()
    axi = None
    signatures = {}
    coverage = Counter()
    causes = []
    events = 0
    finish_cycle = None
    response_overlap = 0
    external = False
    interrupt_index = 0
    interrupts = []
    resetting = False
    warm_writes = 0
    debug_index = debug_start = sequence = 0
    debug_eligible = False
    dmi = None
    forwarded = None
    atomic_forwards = []
    console = ConsoleReference()
    console_offer = console_owner = None
    console_completed = deque()
    fence_cycles = []

    def complete(event):
        assert completed, "ISA memory instruction preceded independent completion"
        request, history = completed.popleft()
        expected = event.memory + (int(event.memory_machine), event.memory_operation)
        assert request[:2] + request[3:] == expected[:2] + expected[3:] and (not request[1] or request[2] == expected[2]), "ISA memory operation differs from shared transaction"
        if history["response"][1]:
            return 0, True
        return (history["response"][0] if event.memory_operation == 2 else
                history["oldValue"] if history["oldValue"] is not None else 0), False

    model = Model(case.image, parameters["resetVector"], enable_a=True, enable_m=parameters["enableM"], enable_c=parameters["enableC"],
                  protected_mode=parameters["protectedMode"], memory_access=complete,
                  enable_zba=parameters.get("enableZba", False), enable_zbb=parameters.get("enableZbb", False),
                  enable_zbs=parameters.get("enableZbs", False))
    debugger = DebugReference(model)
    for cycle, group in enumerate(groups):
        _, _, time, reset, clear, debug, load_use, forward, irq = map(int, ("0", *group[0][1:]))
        assert time == 0, "Unexpected atomic platform time"
        assert parameters["enableDebug"] or not (reset or debug or any(fields[0] in ("J", "K", "L") for fields in group)), "Debug activity in a configuration without debug support"
        if reset and not resetting:
            assert debugger.reset_expected and not outstanding and not offers and not completed and axi is None and not rom_completions, "Warm reset crossed unfinished core traffic"
            model = Model(case.image, parameters["resetVector"], enable_a=True, enable_m=parameters["enableM"], enable_c=parameters["enableC"],
                          protected_mode=parameters["protectedMode"], memory_access=complete,
                          enable_zba=parameters.get("enableZba", False), enable_zbb=parameters.get("enableZbb", False),
                          enable_zbs=parameters.get("enableZbs", False))
            model.cycle = cycle - 1
            debugger.model = model
            debugger.reset_expected = debugger.halted = False
            debugger.control, debugger.cause, debugger.dpc = 3, 0, 0
            debugger.resets += 1
        resetting = bool(reset)
        debugger.cycle = cycle
        assert bool(irq) == external, "Interrupt differs from the fixed schedule"
        assert sum(fields[0] in ("R", "N") for fields in group) <= 1, "Multiple architectural events in one cycle"
        model.clock(cycle, int(external) << 2)
        model.time = time
        coverage["loadUseCycles"] += load_use
        coverage["forwardCycles"] += forward
        samples = [fields for fields in group if fields[0] == "B"]
        assert len(samples) == 1, "Missing SRAM cycle sample"
        sample = list(map(int, samples[0][2:]))
        assert len(sample) == 57 and sample[0] == clear, "Invalid SRAM cycle sample"
        inputs, observed = [0, clear], [cycle]
        for index in range(4):
            start = 1 + index * 13
            inputs.extend(sample[start:start + 9])
            observed.extend(sample[start + 9:start + 13])
        observed.extend(sample[-4:])
        history_start = len(memory.history)
        held_competitor = memory.responses[3] is not None
        expected = memory.step(tuple(inputs), cycle)
        assert tuple(observed) == expected, "Shared SRAM arbitration, response or write differs"
        device_samples = [fields for fields in group if fields[0] == "C"]
        if device_samples:
            assert len(device_samples) == 1 and len(device_samples[0]) == 17, "Invalid console cycle sample"
            device_row = tuple(map(int, device_samples[0][2:11]))
            device_expected = console.step(device_row, cycle)
            assert (cycle, *map(int, device_samples[0][11:])) == device_expected, "Console response or transmitted byte differs"
        else:
            assert not case.console, "Console workload lacks independent samples"
        for fields in group:
            if fields[0] not in ("P", "Q", "S") or fields[2] != "C":
                continue
            values = tuple(map(int, fields[3:]))
            if fields[0] == "P":
                assert console_offer is None and len(values) == 7, "Unexpected console offer"
                console_offer = values
            elif fields[0] == "Q":
                assert console_owner is None and console_offer == values and values[-1] == 0, "Console owner differs"
                console_owner, console_offer = values, None
            else:
                assert console_owner is not None and values == device_expected[3:5], "Console completion lacks independent result"
                console_completed.append((console_owner, values))
                console_owner = None
        for history in memory.history[history_start:]:
            memory_events[history["port"]].append(history)
            if held_competitor and history["port"] == "data" and history["writeValue"] is not None:
                response_overlap += 1
            if reset and history["port"] == "competitor" and history["writeValue"] is not None:
                warm_writes += 1
        for fields in group:
            if fields[0] != "A":
                continue
            kind = fields[2]
            if kind == "AR":
                assert axi is None, "Overlapping AXI ROM owner"
                address, protection = map(int, fields[3:])
                assert regions["rom"]["base"] <= address < regions["rom"]["base"] + regions["rom"]["size"], "SRAM access escaped to AXI"
                axi = (cycle, address, protection, case.image.get(address, 0))
            else:
                assert kind == "R" and axi is not None and cycle > axi[0], "Unowned AXI ROM response"
                assert tuple(map(int, fields[3:])) == (axi[3], 0), "AXI ROM value differs"
                rom_completions.append(axi)
                axi = None
        must_clear = bool(reset)
        for fields in group:
            kind = fields[0]
            if kind in ("T", "B", "C", "A", "H") or kind in ("P", "Q", "S") and fields[2] == "C":
                continue
            if kind == "P":
                port, request = fields[2], tuple(map(int, fields[3:]))
                assert port in ("I", "D") and port not in offers and len(request) == 7, "Unexpected native first offer"
                address, write, data, mask, size, machine, operation = request
                effective_user = model.user_mode if port == "I" else (model.user_mode and not debug) or bool(model.csrs[0x300] & (1 << 17) and model.csrs[0x300] & 0x1800 == 0)
                assert machine == int(not effective_user), "Native privilege differs"
                kinds = (2,) if port == "I" else (0, 1) if operation >= 3 else (write,)
                assert model.pmp is None or all(model.pmp.allowed((address, size, machine, access)) for access in kinds), "Denied atomic request reached memory"
                offers[port] = request, bool(port == "D" and debug)
            elif kind == "Q":
                port, request = fields[2], tuple(map(int, fields[3:]))
                owner = request, bool(port == "D" and debug)
                assert port not in outstanding and offers.pop(port) == owner, "Native transaction ownership differs"
                outstanding[port] = owner
                if case.boundary and case.boundary[0] == "interrupt" and port == "D" and cycle == boundary["requestCycle"]:
                    external = True
                if port == "D" and request[-1] and not debug and forwarded is not None:
                    assert "requestCycle" not in forwarded, "Forwarded atomic instruction issued twice"
                    forwarded.update(requestCycle=cycle, address=request[0], data=request[2], operation=request[-1])
            elif kind == "S":
                port = fields[2]
                assert port in outstanding, "Native response lacks an owner"
                request, debug_owner = outstanding.pop(port)
                response = tuple(map(int, fields[3:]))
                address, write, data, mask, size, machine, operation = request
                if regions["sram"]["base"] <= address < regions["sram"]["base"] + regions["sram"]["size"]:
                    queue = memory_events["instruction" if port == "I" else "debug" if debug_owner else "data"]
                    assert queue, "Native response preceded SRAM history"
                    history = queue.popleft()
                    assert history["request"] == (address, machine, write, data, mask, size, operation), "SRAM transaction lost its native owner"
                    assert response == history["response"], "Native response differs from independent SRAM result"
                    if port == "D":
                        if debug_owner:
                            pending = debugger.pending
                            assert debugger.halted and pending is not None and "request" in pending and not pending["completed"], "Unowned debug SRAM completion"
                            wanted = pending["request"]
                            assert request[:2] + request[3:6] == wanted[:2] + wanted[3:] and operation == 0 and (not write or data == wanted[2]), "Debug SRAM command differs"
                            pending["completed"] = True
                            if history["oldValue"] is not None:
                                for lane in range(4):
                                    model.memory[(address & ~3) + lane] = history["oldValue"] >> (8 * lane) & 255
                            if history["writeValue"] is not None:
                                for lane in range(4):
                                    if mask >> lane & 1:
                                        model.memory[(address & ~3) + lane] = history["writeValue"] >> (8 * lane) & 255
                        else:
                            completed.append((request, history))
                else:
                    if port == "D" and operation:
                        assert not debug_owner and response == (0, 1), "Non-SRAM atomic access did not fault"
                        completed.append((request, {"oldValue": None, "response": (0, True)}))
                    elif port == "D" and regions["console"]["base"] <= address < regions["console"]["base"] + regions["console"]["size"]:
                        assert not debug_owner and console_completed, "Console response preceded device completion"
                        original, device_response = console_completed.popleft()
                        assert original == (address - regions["console"]["base"], *request[1:]) and response == device_response, "Console transaction lost its native owner"
                        completed.append((request, {"oldValue": response[0], "response": response}))
                    else:
                        assert port in ("I", "D") and not write and not operation and not debug_owner and rom_completions, "Unexpected non-SRAM response"
                        original = rom_completions.popleft()
                        protection = (4 if port == "I" else 0) | machine
                        assert (original[1], original[2], original[3]) == (address & ~3, protection, response[0]) and response[1] == 0, "ROM transaction lost its native owner"
                        if port == "D":
                            completed.append((request, {"oldValue": response[0], "response": response}))
            elif kind == "R":
                assert not debugger.halted and not reset, "Instruction retired during a confirmed halt or reset"
                expected = model.step()
                pc, word, target, rd, writes, value, trap, cause, tval, user = map(int, fields[2:])
                assert (pc, word, target, bool(trap), bool(user)) == (expected.pc, expected.word, expected.next_pc, expected.trap, expected.user_mode), "Atomic retirement identity differs"
                assert bool(writes) == bool(expected.rd) and value == expected.value and (not writes or rd == expected.rd), "Atomic retirement value differs"
                assert not trap or (cause, tval) == (expected.cause, expected.tval), "Atomic exception metadata differs"
                assert not completed, "Extra completed data transaction"
                if forwarded is not None:
                    assert pc == forwarded["pc"], "Forwarded instruction lost its retirement owner"
                    if expected.memory_operation:
                        assert "requestCycle" in forwarded, "Forwarded atomic instruction lacks a native request"
                        atomic_forwards.append({**forwarded, "retireCycle": cycle, "result": expected.value})
                    forwarded = None
                coverage[expected.instruction] += 1
                coverage["sramRetirements"] += regions["sram"]["base"] <= pc < regions["sram"]["base"] + regions["sram"]["size"]
                coverage["userRetirements"] += user
                if expected.instruction == "fence.i":
                    assert "I" not in outstanding and "I" not in offers and not rom_completions, "FENCE.I preceded old instruction completion"
                if expected.instruction == "fence":
                    assert "D" not in outstanding and "D" not in offers and not completed and not console_completed and console.owner is None, "FENCE preceded data or device completion"
                    fence_cycles.append(cycle)
                if expected.memory_operation:
                    coverage[f"ordering{int(expected.acquire) * 2 + int(expected.release)}"] += 1
                events += 1
                if expected.trap:
                    causes.append(expected.cause)
                csr_address, source, operation = word >> 20, word >> 15 & 31, word >> 12 & 7
                permission_write = word & 127 == 0x73 and operation in (1, 2, 3, 5, 6, 7) and (operation in (1, 5) or source) and (
                    csr_address == 0x300 or 0x3A0 <= csr_address <= 0x3A3 or 0x3B0 <= csr_address <= 0x3BF)
                must_clear = expected.trap or expected.instruction == "mret" or bool(permission_write)
                if pc == case.completion_pc and finish_cycle is None:
                    assert word == 0x6F and not trap
                    finish_cycle = cycle
                if interrupt_index < len(case.interrupts) and pc == case.interrupts[interrupt_index]:
                    interrupt_index += 1
                    external = True
                if debug_index < len(case.debug):
                    action = case.debug[debug_index]
                    debug_eligible |= action[0] == 0 and action[1] == pc
            elif kind == "N":
                assert "D" not in outstanding and not completed, "Interrupt crossed unfinished atomic data work"
                observed = tuple(map(int, fields[2:]))
                assert observed == model.interrupt(), "Atomic interrupt boundary differs"
                interrupts.append(observed[2])
                must_clear = True
                external = False
            elif kind == "J":
                seq, index, address, op, value = map(int, fields[2:])
                assert dmi is None and seq == sequence and index == debug_index and index < len(case.debug), "DMI owner differs"
                action = case.debug[index]
                assert action[0] in (1, 2, 3, HALT_ATOMIC) and (address, op, value) == (action[1], 2 if action[0] in (2, HALT_ATOMIC) else 1, action[2] if action[0] in (2, HALT_ATOMIC) else 0), "DMI request differs from fixed actions"
                snapshot = {"pc": model.pc, "user": model.user_mode, "outstanding": bool(outstanding),
                            "completed": bool(completed), "offered": bool(offers), "retirements": events,
                            "resetPending": debugger.reset_expected or debugger.reset_requested or resetting}
                debugger.request(address, op, value, events)
                dmi = seq, cycle, address, op, value, snapshot
                sequence += 1
            elif kind == "K":
                seq, status, data = map(int, fields[2:])
                assert dmi is not None and seq == dmi[0] and cycle > dmi[1], "DMI response lacks an owner"
                if dmi[2:4] == (0x11, 1) and data >> 8 & 3 == 3:
                    assert dmi[5]["retirements"] == events, "Hart retired after its halted status sample"
                debugger.response(*dmi[2:5], status, data, dmi[5])
                if debugger.halted:
                    model.reservation = None
                action = case.debug[debug_index]
                debug_eligible = action[0] != 3 or data & action[3] == action[2]
                dmi = None
            elif kind == "L":
                assert int(fields[2]) == debug_index and debug_index < len(case.debug), "DMI actions completed out of order"
                action = case.debug[debug_index]
                assert debug_eligible or action[0] == 4 and cycle - debug_start >= action[2], "DMI action completed before its condition"
                debug_index += 1
                debug_start, debug_eligible = cycle + 1, False
            elif kind == "V":
                address, value, fault = map(int, fields[2:])
                assert finish_cycle is not None and address in case.signature and address not in signatures, "Unexpected SRAM signature read"
                assert fault == 0 and value == case.signature[address], "Atomic program signature differs"
                assert memory_events["competitor"], "Signature lacks a real competing read"
                history = memory_events["competitor"].pop()
                assert history["request"] == (address, 1, 0, 0, 0, 2, 0) and history["response"] == (value, 0), "Signature read lacks independent memory evidence"
                signatures[address] = value
            else:
                raise AssertionError("Unexpected atomic cycle event")
        debug_interval = bool(debug or debugger.halted or debugger.run_control is not None or debugger.reset_expected or debugger.reset_requested)
        assert not clear or must_clear or debug_interval, "Unexplained reservation clear"
        stable_halt = debugger.halted and not debugger.reset_requested and not debugger.reset_expected
        assert not (must_clear or debug or stable_halt) or clear, "Missing reservation clear"
        if forward:
            assert forwarded is None, "Overlapping forwarded instruction owners"
            forwarded = {"pc": model.pc, "forwardCycle": cycle}
    assert finish_cycle is not None and len(groups) - finish_cycle >= 8, "Missing atomic completion window"
    assert not outstanding and not completed and axi is None and not rom_completions, "Native or AXI transaction did not drain"
    assert memory.pending is None and not any(memory.responses), "SRAM transaction did not drain"
    assert console.owner is None and console_offer is None and console_owner is None and not console_completed, "Console transaction did not drain"
    assert tuple(console.bytes) == case.console, "Console output differs from fixed program"
    assert len(fence_cycles) == case.expected_fences, "FENCE coverage differs from fixed program"
    assert tuple(causes) == case.expected_causes and signatures == case.signature, "Incomplete atomic outcome"
    assert tuple(interrupts) == case.expected_interrupts and interrupt_index == len(case.interrupts), "Incomplete atomic interrupt outcome"
    assert not case.requires_response_overlap or response_overlap > 0, "Missing write during a held competing response"
    assert not case.requires_warm_write or warm_writes > 0, "Missing SRAM write during warm reset"
    assert not case.requires_sram_fetch or memory.counts["port0"] >= 3 and coverage["sramRetirements"] >= 3, "Missing SRAM instruction execution"
    assert not case.requires_atomic_forward or atomic_forwards, "Missing input forwarding to an atomic instruction"
    assert (debugger.halts, debugger.resumes, debugger.resets) == (case.expected_halts, case.expected_resumes, case.expected_resets), "Missing atomic debug transition"
    assert debug_index == len(case.debug) and dmi is None and debugger.pending is None, "Unfinished atomic DMI command"
    for port in ("instruction", "data", "debug"):
        assert not memory_events[port], "Unclaimed SRAM transaction"
    competitor_checks = check_competitors(case, list(memory_events["competitor"]))
    if case.expected_sc_failures is not None:
        assert memory.counts["scFailure"] == case.expected_sc_failures and memory.counts["scSuccess"] == 1, "Retry did not fail for each interference and then succeed"
    if case.requires_lock_contention:
        lock_reads = [event["oldValue"] for event in memory.history if event["port"] == "data" and event["request"][-1] == 1]
        assert 1 in lock_reads and lock_reads[-1] == 0 and memory.counts["scSuccess"] == 1, "Lock did not wait for release and acquire"
    return {"cycles": len(groups), "retirements": events, "instructions": dict(coverage),
            "memory": dict(memory.counts), "sharedHistory": memory.history,
            "writesWhileCompetitorResponseHeld": response_overlap, "writesDuringWarmReset": warm_writes,
            "interrupts": interrupts, "debugHalts": debugger.halts, "debugResumes": debugger.resumes,
            "warmResets": debugger.resets, "dmiTransactions": sequence, "forwardedAtomicRequests": atomic_forwards,
            "competitorChecks": competitor_checks, "fenceCycles": fence_cycles, "console": console.bytes,
            "atomicControlBoundary": boundary}


def check_competitors(case, history):
    index = retries = 0
    for event in history:
        assert index < len(case.competitors), "Extra competing transaction"
        scheduled = case.competitors[index]
        address, size, write = scheduled["address"], scheduled["size"], int(scheduled["write"])
        mask = ((1 << (1 << size)) - 1) << (address % 4) if write else 0
        assert event["request"] == (address, 1, write, scheduled["data"], mask, size, 0), "Competitor payload differs from schedule"
        assert event["response"][1] == 0, "Competing access faulted"
        if "expectedRead" in scheduled:
            assert not write and event["response"][0] == scheduled["expectedRead"], "Competing reader observed a wrong message"
        if "pollUntil" in scheduled and event["response"][0] != scheduled["pollUntil"]:
            assert not write, "Polling a competing write"
            retries += 1
        else:
            index += 1
    assert index == len(case.competitors), "Competing sequence did not finish"
    return {"transactions": len(history), "actions": index, "pollRetries": retries}


def inputs():
    names = ("test/model.py", "test/atomic_programs.py", "test/test_atomic_core.py", "test/verify_atomic.py", "test/atomic_sim.cpp",
             "test/atomic_memory.py", "test/programs.py", "test/pmp.py", "test/compressed_model.py", "test/compressed_unit.py", "scripts/build_rtl.py")
    names += ("test/verify_debug.py", "test/debug_programs.py", "test/bit_model.py", "test/bit_operations.py", "test/console.py")
    return {name: digest(ROOT / name) for name in names}


def atomic_write_witness(trace, kind):
    samples = [(int(fields[1]), list(map(int, fields[2:]))) for line in trace.splitlines()
               if (fields := line.split()) and fields[0] == "B"]
    assert samples and all(len(sample) == 57 for _, sample in samples), "Missing memory witness samples"
    accepted = [(cycle, sample) for cycle, sample in samples if sample[14] and sample[23] and sample[21] == 4]
    assert len(accepted) == 1, "Expected one AMOADD witness"
    read_cycle, request = accepted[0]
    address, operand = request[15], request[18]
    writes = [(cycle, RAM + sample[-3] * 4, sample[-2], sample[-1])
              for cycle, sample in samples if sample[-2]]
    prior = [item for item in writes if item[0] < read_cycle and item[1:3] == (address, 15)]
    assert prior and request[-4] and RAM + request[-3] * 4 == address, "AMO witness lacks an initialized read"
    result = (prior[-1][3] + operand) & 0xFFFFFFFF
    following = [item for item in writes if item[0] > read_cycle and item[1] == address]
    assert len(following) >= 2, "Missing faulty write effects"
    if kind == "split":
        competing = [(cycle, sample) for cycle, sample in samples if sample[40] and sample[49] and sample[43]]
        assert len(competing) == 1, "Missing competing write witness"
        cycle, payload = competing[0]
        assert following[0] == (cycle, payload[41], payload[45], payload[44])
        assert read_cycle < cycle < following[1][0] and following[1][1:] == (address, 15, result), "Competing write did not split the AMO"
    else:
        assert kind == "duplicate" and following[0][1:] == following[1][1:] == (address, 15, result), "Missing duplicate AMO write"
        assert following[0][0] == read_cycle + 1 and following[1][0] == read_cycle + 2, "Duplicate write timing differs"
    return {"atomicReadCycle": read_cycle, "firstWriteCycle": following[0][0],
            "secondWriteCycle": following[1][0], "oldValue": prior[-1][3], "operand": operand}


def selected_cases(parameters, requested=None):
    available = cases(*(parameters.get(name, False) for name in ("enableZba", "enableZbb", "enableZbs")), enable_m=parameters["enableM"])
    supported = [case for case in available if (parameters["enableM"] or not case.enable_m)
                 and (parameters["enableC"] or not case.enable_c)
                 and (parameters["protectedMode"] or not case.protected_mode)
                 and (parameters["enableDebug"] or not case.debug)]
    selected = [case for case in supported if requested is None or case.name in requested]
    assert selected and (requested is None or set(requested) == {case.name for case in selected}), "Unknown atomic case or disabled required feature"
    return selected


def mutate_atomic(text, kind):
    if kind in ("early-irq-clear", "early-halt-clear"):
        pattern = r"(assign reservationClear\s*=)(.*?);"
        matches = list(re.finditer(pattern, text, re.S))
        assert len(matches) == 1, "Atomic control mutation target changed"
        signal = "eligibleInterrupt" if kind == "early-irq-clear" else "_dm_hart_control_halt"
        assert signal in text, "Atomic control mutation target changed"
        return re.sub(pattern, lambda match: match[1] + match[2] + " | " + signal + ";", text, count=1, flags=re.S)
    if kind in ("split", "duplicate"):
        data_pattern = r"(\.writeData\s*\n\s*\()(.*?)(\),\s*\n\s*\.readData)"
        matches = list(re.finditer(data_pattern, text, re.S))
        assert len(matches) == 1, "Atomic write data mutation target changed"
        write_data = matches[0][2]
        address = "busy ? request_address[15:2] : _GEN_1[selected][15:2]"
        mask = "write & ~reset ? request_mask : 4'h0"
        assert text.count(address) == text.count(mask) == 1, "Atomic memory mutation target changed"
        if kind == "duplicate":
            injected = """  reg replay;
  reg [13:0] replay_address;
  reg [3:0] replay_mask;
  reg [31:0] replay_data;
  always @(posedge clock) begin
    if (reset) replay <= 1'b0;
    else replay <= write && owner == 2'h1 && request_operation >= 4'h3;
    if (write && owner == 2'h1 && request_operation >= 4'h3) begin
      replay_address <= request_address[15:2];
      replay_mask <= request_mask;
      replay_data <= """ + write_data + """;
    end
  end
"""
            text = text.replace(address, "replay ? replay_address : (" + address + ")")
            text = text.replace(mask, "replay & ~reset ? replay_mask : (" + mask + ")")
            text = re.sub(data_pattern, lambda match: match[1] + "replay ? replay_data : (" + match[2] + ")" + match[3], text, flags=re.S)
        else:
            injected = """  wire split_amo = !reset && busy && owner == 2'h1 &&
    request_operation >= 4'h3 && competitor_request_valid &&
    competitor_request_bits_write && competitor_request_bits_operation == 0 && !responding_2;
"""
            replacements = {
                "busy <= ~busy & (accepted | busy);": "busy <= split_amo | (~busy & (accepted | busy));",
                "responding_0 <= _GEN_13 |": "responding_0 <= (_GEN_13 & ~split_amo) |",
                "_GEN_18 | ~(responding_2": "split_amo | _GEN_18 | ~(responding_2",
                "if (_GEN_13) begin": "if (_GEN_13 & ~split_amo) begin",
                "if (_GEN_18) begin": "if (_GEN_18 | split_amo) begin",
                "responses_data_2 <=\n        fault": "responses_data_2 <=\n        split_amo ? 32'h0 : fault",
                "responses_fault_2 <= fault;": "responses_fault_2 <= split_amo ? 1'b0 : fault;",
                "assign competitor_request_ready = ~busy": "assign competitor_request_ready = split_amo | ~busy",
            }
            for before, after in replacements.items():
                assert text.count(before) == 1, "Atomic split mutation target changed"
                text = text.replace(before, after)
            text = text.replace(address, "split_amo ? competitor_request_bits_address[15:2] : (" + address + ")")
            text = text.replace(mask, "split_amo ? competitor_request_bits_mask : (" + mask + ")")
            text = re.sub(data_pattern, lambda match: match[1] + "split_amo ? competitor_request_bits_data : (" + match[2] + ")" + match[3], text, flags=re.S)
        assert text.count("  always @(posedge clock) begin") == 1, "Atomic sequential mutation target changed"
        return text.replace("  always @(posedge clock) begin", injected + "  always @(posedge clock) begin", 1)
    changes = {"amo": ("_memory_readData + request_data", "_memory_readData ^ request_data"),
               "invalidation": ("~(write & success)", "~(write & success & (owner != 2'h3))"),
               "forward": ("match2 & ~m_load ? m_value", "match2 & ~m_load & ~isAtomic ? m_value"),
               "response": ("assign competitor_response_bits_data = responses_data_2;",
                            "assign competitor_response_bits_data = _memory_readData;")}
    if kind in changes:
        before, after = changes[kind]
        assert text.count(before) == 1, "Atomic mutation target changed"
        return text.replace(before, after)
    if kind == "clear":
        pattern = r"(reserved <=\s*)~clearReservation(\s*&)"
        assert len(re.findall(pattern, text)) == 1, "Atomic clear mutation target changed"
        return re.sub(pattern, r"\g<1>1'b1\2", text)
    assert kind == "reset", "Unknown atomic mutation"
    pattern = r"(DitDahE2AtomicMemory\s+atomic\s*\(\s*\.clock\s*\(clock\),\s*\.reset\s*\()reset(\))"
    assert len(re.findall(pattern, text)) == 1, "Atomic reset mutation target changed"
    return re.sub(pattern, r"\1platformReset\2", text)


def preserve(destination, source, hashes):
    for name, value in hashes.items():
        data = (source / name).read_bytes()
        assert hashlib.sha256(data).hexdigest() == value, "Input changed before preservation"
        target = destination / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--design", type=Path, default=Path("result/atomic-platform-connected"))
    parser.add_argument("--output", type=Path, default=Path("result/atomic-verification"))
    parser.add_argument("--case", action="append")
    parser.add_argument("--frozen-worker", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args()
    if not args.frozen_worker:
        initial = inputs()
        args.output.mkdir(parents=True, exist_ok=False)
        execution = args.output / "execution"
        preserve(execution, ROOT, initial)
        command = [sys.executable, str((execution / "test/verify_atomic.py").resolve()), "--frozen-worker",
                   "--design", str(args.design.resolve()), "--output", str(args.output.resolve())]
        for name in args.case or []:
            command.extend(("--case", name))
        result = subprocess.run(command)
        raise SystemExit(result.returncode)
    assert ROOT == (args.output / "execution").resolve() and not (args.output / "summary.json").exists(), "Invalid frozen checker execution"
    manifest = json.loads((args.design / "manifest.json").read_text())
    manifest_hash = digest(args.design / "manifest.json")
    parameters, regions = manifest["parameters"]["core"], manifest["regions"]
    assert parameters["enableA"] and parameters["resetVector"] == 0, "Atomic platform tests require A and a zero reset vector"
    assert regions["rom"]["base"] == 0 and regions["rom"]["size"] == 65536 and regions["sram"]["base"] == RAM, "Atomic workload memory map differs"
    initial = inputs()
    preserve(args.output / "inputs/checker", ROOT, initial)
    preserve(args.output / "inputs/design", args.design / "inputs", manifest["sourceHashes"])
    preserve(args.output / "rtl", args.design / "rtl", manifest["rtlHashes"])
    shutil.copyfile(args.design / "manifest.json", args.output / "manifest.json")
    tools = {}
    for name in ("verilator", "g++", "make", "python3"):
        path = Path(shutil.which(name)).resolve()
        tools[name] = {"hash": digest(path), "version": subprocess.check_output([str(path), "--version"], text=True).splitlines()[0]}
    wrapper = args.output / "AtomicBench.sv"
    wrapper.write_text(observer(args.output / "rtl", regions["sram"]["size"]))
    selected = selected_cases(parameters, args.case)
    compile_flags = "-std=c++17 -DDITDAH_E2_ENABLE_DEBUG=" + str(int(parameters["enableDebug"]))
    report = {"scope": "Atomic instruction execution on a real shared SRAM with competing transactions",
              "parameters": parameters, "regions": regions, "checkerHashes": initial, "tools": tools,
              "manifestHash": manifest_hash, "sourceHashes": manifest["sourceHashes"], "rtlHashes": manifest["rtlHashes"],
              "wrapperHash": digest(wrapper), "compileFlags": compile_flags, "runs": [], "negativeControls": [], "harnessControls": [], "command": "python3 test/verify_atomic.py",
              "limits": ["Core data responses are consumed without injected backpressure in this platform.",
                         "Competing responses are held while the core accesses SRAM.",
                         "Every SRAM word is written through a real port before a read or atomic operation.",
                         "Retry completion is measured for the finite competing traffic in these programs."]}
    try:
        build = args.output / "build"
        command = ["verilator", "--cc", "--exe", "--build", "-j", "2", "--top-module", "AtomicBench",
                   "--Mdir", str(build.resolve()), "-CFLAGS", compile_flags, str(wrapper.resolve()),
                   *[str((args.output / "rtl" / name).resolve()) for name in manifest["rtlHashes"]],
                   str((args.output / "inputs/checker/test/atomic_sim.cpp").resolve())]
        compiled = subprocess.run(command, capture_output=True, text=True)
        (args.output / "build.log").write_text(compiled.stdout + compiled.stderr)
        assert compiled.returncode == 0, "Atomic simulator compilation failed"
        binary = build / "VAtomicBench"
        for case in selected:
            for seed, delay in ((0, 0), (1, 9), (19, 24)):
                name = f"{case.name}-s{seed}-d{delay}"
                output = args.output / name
                output.mkdir()
                image, events = output / "image.hex", output / "events.txt"
                image.write_text("".join(f"{address:08x} {value:08x}\n" for address, value in sorted(case.image.items())))
                stimulus = str(len(case.competitors)) + "\n"
                for item in case.competitors:
                    stimulus += " ".join(str(int(item[key])) for key in ("triggerPc", "address", "size", "write", "data", "holdResponse")) + "\n"
                stimulus += str(len(case.signature)) + "\n" + "\n".join(map(str, sorted(case.signature))) + "\n"
                stimulus += str(len(case.interrupts)) + "\n" + "\n".join(map(str, case.interrupts)) + "\n"
                stimulus += str(len(case.debug)) + "\n" + "".join(" ".join(map(str, action)) + "\n" for action in case.debug)
                policies = [(index, 1 if item.get("afterPrevious") else 2 if item.get("trigger") == "amo_accept" else 0,
                             int("pollUntil" in item), item.get("pollUntil", 0))
                            for index, item in enumerate(case.competitors)
                            if item.get("afterPrevious") or item.get("trigger") == "amo_accept" or "pollUntil" in item]
                if policies or case.boundary and case.boundary[0] == "interrupt":
                    stimulus += str(len(policies)) + "\n" + "".join(" ".join(map(str, policy)) + "\n" for policy in policies)
                if case.boundary and case.boundary[0] == "interrupt":
                    stimulus += str(case.boundary[2]) + "\n"
                events.write_text(stimulus)
                command = [str(binary.resolve()), str(image.resolve()), str(events.resolve()), str(seed), str(delay), str(case.completion_pc)]
                run = subprocess.run(command, capture_output=True, text=True)
                (output / "trace.txt").write_text(run.stdout)
                (output / "stderr.txt").write_text(run.stderr)
                assert run.returncode == 0, run.stderr
                metrics = check(case, parameters, regions, run.stdout)
                history = metrics.pop("sharedHistory")
                (output / "history.json").write_text(json.dumps(history, indent=2) + "\n")
                report["runs"].append({"case": case.name, "seed": seed, "delay": delay, "exitStatus": run.returncode,
                    "command": ["build/VAtomicBench", name + "/image.hex", name + "/events.txt", *command[-3:]],
                    "imageHash": digest(image), "eventsHash": digest(events), "binaryHash": digest(binary),
                    "traceHash": digest(output / "trace.txt"), "historyHash": digest(output / "history.json"), **metrics})
        if not parameters["enableDebug"]:
            original = args.output / (selected[0].name + "-s0-d0")
            output = args.output / "disabled-debug"
            output.mkdir()
            shutil.copyfile(original / "image.hex", output / "image.hex")
            stimulus = [line for line in (original / "events.txt").read_text().splitlines() if line]
            at = 3 + len(selected[0].competitors) + len(selected[0].signature) + len(selected[0].interrupts)
            assert stimulus[at] == "0", "Unexpected DMI schedule in a disabled configuration"
            stimulus[at:at + 1] = ["1", "2 16 1 0"]
            (output / "events.txt").write_text("\n".join(stimulus) + "\n")
            command = [str(binary.resolve()), str((output / "image.hex").resolve()), str((output / "events.txt").resolve()),
                       "0", "0", str(selected[0].completion_pc)]
            run = subprocess.run(command, capture_output=True, text=True)
            (output / "trace.txt").write_text(run.stdout)
            (output / "stderr.txt").write_text(run.stderr)
            assert run.returncode != 0 and not run.stdout and run.stderr.strip() == "DMI actions require debug support", "Disabled debug actions were not rejected before execution"
            report["harnessControls"].append({"name": "disabled-debug", "exitStatus": run.returncode,
                "rejected": run.stderr.strip(), "binaryHash": digest(binary), "imageHash": digest(output / "image.hex"),
                "eventsHash": digest(output / "events.txt"), "traceHash": digest(output / "trace.txt"),
                "stderrHash": digest(output / "stderr.txt"),
                "command": ["build/VAtomicBench", "disabled-debug/image.hex", "disabled-debug/events.txt", *command[-3:]]})
        controls = (("amo", "amoadd_w_0_x0"), ("invalidation", "competing_store_1_2"),
                    ("clear", "reservation_csr_300"), ("response", "held_competitor_read"),
                    ("reset", "warm_reset_competitor"), ("forward", "atomic_input_forward"),
                    ("split", "amo_competing_boundary"), ("duplicate", "amo_competing_boundary"),
                    ("early-irq-clear", "pending_sc_w_interrupt"), ("early-halt-clear", "pending_sc_w_halt"))
        by_name = {case.name: case for case in selected}
        for kind, case_name in controls:
            if case_name not in by_name:
                continue
            changed = args.output / (kind + "-rtl")
            shutil.copytree(args.output / "rtl", changed)
            module = {"reset": "DitDahE2AtomicPlatform.sv", "forward": "DitDahE2.sv",
                      "early-irq-clear": "DitDahE2.sv", "early-halt-clear": "DitDahE2.sv"}.get(kind, "DitDahE2AtomicMemory.sv")
            path = changed / module
            path.write_text(mutate_atomic(path.read_text(), kind))
            build = args.output / (kind + "-build")
            command = ["verilator", "--cc", "--exe", "--build", "-j", "2", "--top-module", "AtomicBench",
                       "--Mdir", str(build.resolve()), "-CFLAGS", compile_flags, str(wrapper.resolve()),
                       *[str((changed / name).resolve()) for name in manifest["rtlHashes"]],
                       str((args.output / "inputs/checker/test/atomic_sim.cpp").resolve())]
            compiled = subprocess.run(command, capture_output=True, text=True)
            (args.output / (kind + "-build.log")).write_text(compiled.stdout + compiled.stderr)
            assert compiled.returncode == 0, "Atomic mutant did not compile"
            output = args.output / ("changed-" + kind)
            output.mkdir()
            original = args.output / (case_name + "-s0-d0")
            for name in ("image.hex", "events.txt"):
                shutil.copyfile(original / name, output / name)
            binary = build / "VAtomicBench"
            command = [str(binary.resolve()), str((output / "image.hex").resolve()), str((output / "events.txt").resolve()),
                       "0", "0", str(by_name[case_name].completion_pc)]
            run = subprocess.run(command, capture_output=True, text=True)
            (output / "trace.txt").write_text(run.stdout)
            (output / "stderr.txt").write_text(run.stderr)
            if kind == "reset":
                assert run.returncode != 0 and run.stderr.strip() == "Competitor completion missing after accepted SRAM access", "Warm reset mutant lacks its protocol counterexample"
            else:
                assert run.returncode == 0, "Atomic mutant did not execute the program"
            try:
                check(by_name[case_name], parameters, regions, run.stdout, partial=kind == "reset")
            except AssertionError as error:
                expected_error = ("Reservation cleared before atomic completion and control entry" if kind.startswith("early-") else
                                  "ISA memory operation differs from shared transaction" if kind == "forward" else
                                  "Shared SRAM arbitration, response or write differs")
                assert str(error) == expected_error, "Atomic mutant failed outside its memory contract"
                record = {"name": kind, "case": case_name, "exitStatus": run.returncode, "rejected": str(error),
                          "command": [kind + "-build/VAtomicBench", "changed-" + kind + "/image.hex", "changed-" + kind + "/events.txt", *command[-3:]],
                          "binaryHash": digest(binary), "imageHash": digest(output / "image.hex"), "eventsHash": digest(output / "events.txt"),
                          "traceHash": digest(output / "trace.txt"), "stderrHash": digest(output / "stderr.txt"),
                          "rtlHashes": {name: digest(changed / name) for name in manifest["rtlHashes"]}}
                if kind.startswith("early-"):
                    rows = [line.split() for line in run.stdout.splitlines()]
                    fault = next(fields for fields in rows if fields[0] == "R" and int(fields[2]) == by_name[case_name].boundary[1])
                    assert int(fault[7]) == 1, "Early clear mutant did not change the SC result"
                    record["semanticWitness"] = {"scRetireCycle": int(fault[1]), "scResult": int(fault[7])}
                    record["compileExitStatus"] = compiled.returncode
                if kind in ("split", "duplicate"):
                    record["semanticWitness"] = atomic_write_witness(run.stdout, kind)
                    record["compileExitStatus"] = compiled.returncode
                report["negativeControls"].append(record)
            else:
                raise AssertionError("Atomic RTL mutation passed the checker")
        assert inputs() == initial, "Atomic checker inputs changed"
        assert all(digest(args.output / "inputs/checker" / name) == value for name, value in initial.items()), "Preserved checker inputs changed"
        assert all(digest(args.output / "inputs/design" / name) == value for name, value in manifest["sourceHashes"].items()), "Preserved design sources changed"
        assert all(digest(args.output / "rtl" / name) == value for name, value in manifest["rtlHashes"].items()), "Preserved RTL changed"
        assert digest(wrapper) == report["wrapperHash"], "Atomic observer changed"
        assert digest(args.design / "manifest.json") == manifest_hash, "Atomic design manifest changed"
        assert all(digest(args.design / "rtl" / name) == value for name, value in manifest["rtlHashes"].items()), "Atomic RTL changed"
        report["exitStatus"] = 0
    except Exception as error:
        report["exitStatus"] = 1
        report["failure"] = str(error)
        raise
    finally:
        (args.output / "summary.json").write_text(json.dumps(report, indent=2) + "\n")
    print(f"PASS: {len(report['runs'])} atomic processor RTL runs, {len(report['negativeControls'])} RTL negative controls")


if __name__ == "__main__":
    main()
