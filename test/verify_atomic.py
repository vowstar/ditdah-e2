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
from atomic_programs import cases, RAM
from model import Model
from verify_debug import DebugReference

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
    expose("o_reset", 1, "dut.platform.core.systemReset")
    expose("o_clear", 1, "dut.platform.core.reservationClear")
    expose("o_debug", 1, "dut.platform.core.dataDebug")
    expose("o_sram_read", 1, "dut.platform.atomic.memory.readEnable")
    width = max(1, (ram_size // 4 - 1).bit_length())
    expose("o_sram_address", 32, f"{{{32 - width}'b0, dut.platform.atomic.memory.address}}")
    expose("o_sram_mask", 4, "dut.platform.atomic.memory.writeMask")
    expose("o_sram_data", 32, "dut.platform.atomic.memory.writeData")
    notice = "// SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>\n// SPDX-License-Identifier: MIT\n"
    return (notice + "module AtomicBench(" + ports[1] + ",\n" + ",\n".join(declarations) +
            ");\nDitDahE2AtomicPlatformTop dut(.*);\n" + "\n".join(assignments) + "\nendmodule\n")


def trace_cycles(trace):
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
            assert fields[0] in ("B", "P", "Q", "S", "R", "N", "A", "V", "J", "K", "L"), "Unknown atomic trace record"
            assert groups and int(fields[1]) == len(groups) - 1, "Atomic event lacks a clock"
            groups[-1].append(fields)
    assert total is not None, "Atomic program did not finish"
    return groups


def check(case, parameters, regions, trace):
    groups = trace_cycles(trace)
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

    def complete(event):
        assert completed, "ISA memory instruction preceded independent completion"
        request, history = completed.popleft()
        expected = event.memory + (int(event.memory_machine), event.memory_operation)
        assert request[:2] + request[3:] == expected[:2] + expected[3:] and (not request[1] or request[2] == expected[2]), "ISA memory operation differs from shared transaction"
        if history["response"][1]:
            return 0, True
        return (history["response"][0] if event.memory_operation == 2 else
                history["oldValue"] if history["oldValue"] is not None else 0), False

    model = Model(case.image, enable_a=True, enable_m=parameters["enableM"], enable_c=parameters["enableC"],
                  protected_mode=parameters["protectedMode"], memory_access=complete)
    debugger = DebugReference(model)
    for cycle, group in enumerate(groups):
        _, _, time, reset, clear, debug, load_use, forward, irq = map(int, ("0", *group[0][1:]))
        assert time == 0, "Unexpected atomic platform time"
        if reset and not resetting:
            assert debugger.reset_expected and not outstanding and not offers and not completed and axi is None and not rom_completions, "Warm reset crossed unfinished core traffic"
            model = Model(case.image, enable_a=True, enable_m=parameters["enableM"], enable_c=parameters["enableC"],
                          protected_mode=parameters["protectedMode"], memory_access=complete)
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
            if kind in ("T", "B", "A"):
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
                    assert port == "I" and rom_completions, "Unexpected non-SRAM data response"
                    original = rom_completions.popleft()
                    assert (original[1], original[2], original[3]) == (address, 4 | machine, response[0]) and response[1] == 0, "ROM transaction lost its native owner"
            elif kind == "R":
                assert not debugger.halted and not reset, "Instruction retired during a confirmed halt or reset"
                expected = model.step()
                pc, word, target, rd, writes, value, trap, cause, tval, user = map(int, fields[2:])
                assert (pc, word, target, bool(trap), bool(user)) == (expected.pc, expected.word, expected.next_pc, expected.trap, expected.user_mode), "Atomic retirement identity differs"
                assert bool(writes) == bool(expected.rd) and value == expected.value and (not writes or rd == expected.rd), "Atomic retirement value differs"
                assert not trap or (cause, tval) == (expected.cause, expected.tval), "Atomic exception metadata differs"
                assert not completed, "Extra completed data transaction"
                coverage[expected.instruction] += 1
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
                assert action[0] in (1, 2, 3) and (address, op, value) == (action[1], 2 if action[0] == 2 else 1, action[2] if action[0] == 2 else 0), "DMI request differs from fixed actions"
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
    assert finish_cycle is not None and len(groups) - finish_cycle >= 8, "Missing atomic completion window"
    assert not outstanding and not completed and axi is None and not rom_completions, "Native or AXI transaction did not drain"
    assert memory.pending is None and not any(memory.responses), "SRAM transaction did not drain"
    assert tuple(causes) == case.expected_causes and signatures == case.signature, "Incomplete atomic outcome"
    assert tuple(interrupts) == case.expected_interrupts and interrupt_index == len(case.interrupts), "Incomplete atomic interrupt outcome"
    assert not case.requires_response_overlap or response_overlap > 0, "Missing write during a held competing response"
    assert not case.requires_warm_write or warm_writes > 0, "Missing SRAM write during warm reset"
    assert (debugger.halts, debugger.resumes, debugger.resets) == (case.expected_halts, case.expected_resumes, case.expected_resets), "Missing atomic debug transition"
    assert debug_index == len(case.debug) and dmi is None and debugger.pending is None, "Unfinished atomic DMI command"
    for port in ("instruction", "data", "debug"):
        assert not memory_events[port], "Unclaimed SRAM transaction"
    assert len(memory_events["competitor"]) == len(case.competitors), "Competitor count differs from schedule"
    return {"cycles": len(groups), "retirements": events, "instructions": dict(coverage),
            "memory": dict(memory.counts), "sharedHistory": memory.history,
            "writesWhileCompetitorResponseHeld": response_overlap, "writesDuringWarmReset": warm_writes,
            "interrupts": interrupts, "debugHalts": debugger.halts, "debugResumes": debugger.resumes,
            "warmResets": debugger.resets, "dmiTransactions": sequence}


def inputs():
    names = ("test/model.py", "test/atomic_programs.py", "test/test_atomic_core.py", "test/verify_atomic.py", "test/atomic_sim.cpp",
             "test/atomic_memory.py", "test/programs.py", "test/pmp.py", "test/compressed_model.py", "test/compressed_unit.py", "scripts/build_rtl.py")
    names += ("test/verify_debug.py", "test/debug_programs.py")
    return {name: digest(ROOT / name) for name in names}


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
    assert parameters["enableA"] and parameters["enableDebug"] and parameters["resetVector"] == 0, "Unsupported atomic platform configuration"
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
    report = {"scope": "Atomic instruction execution on a real shared SRAM with competing transactions",
              "parameters": parameters, "regions": regions, "checkerHashes": initial, "tools": tools,
              "manifestHash": manifest_hash, "sourceHashes": manifest["sourceHashes"], "rtlHashes": manifest["rtlHashes"],
              "wrapperHash": digest(wrapper), "runs": [], "command": "python3 test/verify_atomic.py"}
    try:
        build = args.output / "build"
        command = ["verilator", "--cc", "--exe", "--build", "-j", "2", "--top-module", "AtomicBench",
                   "--Mdir", str(build.resolve()), "-CFLAGS", "-std=c++17", str(wrapper.resolve()),
                   *[str((args.output / "rtl" / name).resolve()) for name in manifest["rtlHashes"]],
                   str((args.output / "inputs/checker/test/atomic_sim.cpp").resolve())]
        compiled = subprocess.run(command, capture_output=True, text=True)
        (args.output / "build.log").write_text(compiled.stdout + compiled.stderr)
        assert compiled.returncode == 0, "Atomic simulator compilation failed"
        binary = build / "VAtomicBench"
        selected = [case for case in cases() if args.case is None or case.name in args.case]
        assert selected and (args.case is None or set(args.case) == {case.name for case in selected}), "Unknown atomic case"
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
    print(f"PASS: {len(report['runs'])} atomic processor RTL runs")


if __name__ == "__main__":
    main()
