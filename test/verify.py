# SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
# SPDX-License-Identifier: MIT
"""Compile generated RTL, run delayed buses, and independently check every event."""

import argparse
from collections import Counter, deque
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

from model import Model, TIME_BASE, MASK64, M_INSTRUCTIONS, multiply_divide
from programs import cases

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from build_rtl import digest, sources


def checker_inputs():
    paths = ("test/model.py", "test/programs.py", "test/compressed_model.py", "test/compressed_programs.py",
             "test/compressed_unit.py", "test/sim.cpp", "test/inactive_debug.hpp", "test/verify.py", "scripts/build_rtl.py")
    return {name: digest(Path(name)) for name in paths}


class InputSchedule:
    def __init__(self, entries):
        self.entries = entries
        self.fired = set()
        self.mask = 0
        self.pending = None
        self.cycle = -1
        self.delayed = []

    def event(self, kind, key):
        for index, entry in enumerate(self.entries):
            trigger, value, mask, *delay = entry
            if index not in self.fired and (trigger, value) == (kind, key):
                self.fired.add(index)
                if kind == "M":
                    self.delayed.append((self.cycle + delay[0], index, mask))
                elif kind == "C":
                    self.mask = mask
                else:
                    self.pending = mask

    def clock(self, cycle):
        self.cycle = cycle
        if self.pending is not None:
            self.mask, self.pending = self.pending, None
        for due, _, mask in sorted(self.delayed):
            if due == cycle:
                self.mask = mask
        self.delayed = [entry for entry in self.delayed if entry[0] > cycle]
        self.event("C", cycle)
        return self.mask


def check(case, text):
    model = Model(case.words(), case.reset, case.instruction_fault, case.data_fault,
                  enable_m=getattr(case, "enable_m", False), enable_c=getattr(case, "enable_c", False),
                  protected_mode=getattr(case, "protected_mode", False))
    outstanding = {}
    offered = {}
    completed = deque()
    observed_memory = {}
    metrics = None
    events = 0
    causes = []
    completion_cycle = None
    last_response = -1
    held = None
    observations = []
    schedule = InputSchedule(case.interrupt_schedule)
    input_cycle = -1
    architectural_event = -1
    interrupts = []
    sleep_cycles = 0
    interrupt_deadline = None
    coverage = Counter()
    arithmetic = None
    arithmetic_done = deque()
    arithmetic_counts = Counter()
    arithmetic_cycle = -1
    cancel_due = None
    restart_pcs = set()
    for line in text.splitlines():
        fields = line.split()
        kind = fields[0]
        assert metrics is None or kind == "W", "Execution record after final metrics"
        if kind == "T":
            cycle, mask, time = map(int, fields[1:])
            assert cancel_due is None, "Arithmetic operation survived cancellation"
            if arithmetic:
                assert arithmetic["resultCycle"] is not None or cycle - arithmetic["start"] <= 34, "Arithmetic result exceeded latency bound"
                if arithmetic["resultCycle"] is not None:
                    assert arithmetic_cycle == input_cycle, "Arithmetic result valid was withdrawn"
                if "D" in outstanding:
                    arithmetic_counts["mulDivMemoryOverlapCycles"] += 1
            assert cycle == input_cycle + 1, "Missing input clock record"
            assert interrupt_deadline is None or cycle <= interrupt_deadline, "Interrupt missed its commit boundary"
            assert mask == schedule.clock(cycle), "Interrupt input differs from schedule"
            assert time == (TIME_BASE + cycle) & MASK64, "Time input differs from clock schedule"
            sleep_cycles += model.sleeping
            model.clock(cycle, mask)
            if model.interrupt_cause() is None:
                interrupt_deadline = None
            input_cycle = cycle
            continue
        if kind not in ("C", "W"):
            assert int(fields[1]) == input_cycle, "Event lacks its input clock record"
        if kind == "P":
            port, request = fields[2], tuple(map(int, fields[3:]))
            assert port in ("I", "D") and port not in offered and len(request) == 6, "Invalid first request offer"
            status = model.csrs[0x300]
            effective_user = model.user_mode or bool(status & (1 << 17) and status >> 11 & 3 == 0)
            machine = not (model.user_mode if port == "I" else effective_user)
            assert request[5] == int(machine), "Offered request privilege differs"
            if model.protected_mode:
                assert model.pmp.allowed((request[0], request[4], int(machine), 2 if port == "I" else request[1])), "Denied request reached external memory"
            offered[port] = request
        elif kind == "Q":
            cycle, port = int(fields[1]), fields[2]
            assert port in ("I", "D"), "Unknown memory port"
            assert completion_cycle is None or cycle <= completion_cycle, "Request accepted after completion"
            assert port not in outstanding, "Outstanding request overwritten"
            request = tuple(map(int, fields[3:]))
            if len(request) == 6:
                assert offered.pop(port) == request, "Accepted request differs from its first offer"
            else:
                assert not model.protected_mode and len(request) == 5
            outstanding[port] = (cycle, request)
            if port == "D":
                schedule.event("D", int(fields[3]))
        elif kind == "S":
            cycle, port = int(fields[1]), fields[2]
            assert port in outstanding, "Response without request"
            start, request = outstanding.pop(port)
            assert cycle > start, "Response must follow request acceptance"
            last_response = cycle
            if port == "D":
                completed.append((request, tuple(map(int, fields[3:]))))
        elif kind == "R":
            cycle, pc, word, next_pc, rd, writes, value, trap, cause, tval = map(int, fields[1:11])
            assert architectural_event != cycle, "Multiple architectural events in one cycle"
            assert interrupt_deadline != cycle, "Instruction crossed an interrupt boundary"
            architectural_event = cycle
            expected = model.step()
            if getattr(case, "protected_mode", False):
                assert len(fields) == 12 and int(fields[11]) == int(expected.user_mode), "Instruction privilege mismatch"
            coverage[expected.instruction] += 1
            if expected.instruction == "fence.i" and not expected.trap:
                assert "I" not in outstanding, "FENCE.I retired before old fetch completion"
            assert (pc, word, next_pc, bool(trap)) == (expected.pc, expected.word, expected.next_pc, expected.trap), "Instruction/PC/trap mismatch"
            assert bool(writes) == bool(expected.rd), "Register write enable mismatch"
            assert value == expected.value and (not writes or rd == expected.rd), "Register result mismatch"
            if trap:
                assert (cause, tval) == (expected.cause, expected.tval), "Fault metadata mismatch"
                causes.append(cause)
                if arithmetic:
                    cancel_due = (cycle, "trap")
            if expected.instruction in M_INSTRUCTIONS:
                assert arithmetic_done and arithmetic_done.popleft() == pc, "Arithmetic retirement lacks a completed operation"
            if expected.memory:
                assert completed, "Memory instruction retired before response"
                request, response = completed.popleft()
                address, write, data, mask, size = request[:5]
                if len(request) == 6:
                    assert request[5] == int(expected.memory_machine), "Data request privilege differs"
                exp_address, exp_write, exp_data, exp_mask, exp_size = expected.memory
                assert (address, write, mask, size) == (exp_address, exp_write, exp_mask, exp_size), "Memory request mismatch"
                assert not write or data == exp_data, "Store data mismatch"
                assert bool(response[1]) == (address == case.data_fault), "Memory fault mismatch"
                if not write and not response[1]:
                    assert response[0] == model.word(address & ~3), "Load response mismatch"
            else:
                assert not completed, "Unexpected data transaction"
            events += 1
            schedule.event("R", pc)
            interrupt_deadline = cycle + 1 if model.interrupt_cause() is not None else None
            if pc == case.completion_pc:
                assert not trap and word == 0x6F and next_pc == pc, "Invalid completion instruction"
                if completion_cycle is None:
                    completion_cycle = cycle
        elif kind == "N":
            cycle, pc, target, cause = map(int, fields[1:])
            assert architectural_event != cycle, "Multiple architectural events in one cycle"
            assert "D" not in outstanding and not completed, "Interrupt crossed unfinished data work"
            assert (pc, target, cause) == model.interrupt(), "Interrupt PC, target or cause mismatch"
            architectural_event = cycle
            interrupt_deadline = None
            interrupts.append(cause)
            schedule.event("N", len(interrupts))
            if arithmetic:
                cancel_due = (cycle, "interrupt")
        elif kind == "U":
            cycle, pc, start, valid, finish, cancel, value = map(int, fields[1:])
            assert getattr(case, "enable_m", False), "Arithmetic event with M disabled"
            assert arithmetic_cycle != cycle, "Repeated arithmetic event"
            arithmetic_cycle = cycle
            assert all(bit in (0, 1) for bit in (start, valid, finish, cancel)), "Invalid arithmetic control"
            assert start or valid or finish or cancel, "Empty arithmetic event"
            if cancel:
                assert arithmetic and cancel_due and cancel_due[0] == cycle, "Unowned arithmetic cancellation"
                assert not start and not valid and not finish and pc == arithmetic["pc"], "Cancel did not suppress arithmetic completion"
                arithmetic_counts["mulDivCancels"] += 1
                arithmetic_counts["mulDivInterruptCancels" if cancel_due[1] == "interrupt" else "mulDivTrapCancels"] += 1
                if cancel_due[1] == "interrupt":
                    restart_pcs.add(pc)
                arithmetic, cancel_due = None, None
                continue
            assert cancel_due is None, "Arithmetic completion crossed cancellation"
            if start:
                assert arithmetic is None and not arithmetic_done, "Arithmetic operation started before prior completion"
                assert not valid and not finish, "Arithmetic start also completed"
                addresses = {pc & ~3, ((pc + 2) & 0xFFFFFFFF) & ~3}
                assert case.instruction_fault not in addresses, "Faulting instruction started arithmetic"
                word = model.word(pc)
                assert word & 0xFE00007F == 0x02000033, "Arithmetic start has a different instruction"
                operation = (word >> 12) & 7
                left, right = model.registers[(word >> 15) & 31], model.registers[(word >> 20) & 31]
                arithmetic = {"pc": pc, "start": cycle, "resultCycle": None,
                              "value": multiply_divide(operation, left, right)}
                arithmetic_counts["mulDivStarts"] += 1
                schedule.event("M", arithmetic_counts["mulDivStarts"])
                if pc in restart_pcs:
                    arithmetic_counts["mulDivRestarts"] += 1
                    restart_pcs.remove(pc)
            if valid:
                assert arithmetic and pc == arithmetic["pc"], "Unowned arithmetic result"
                assert value == arithmetic["value"], "Arithmetic value differs from operands"
                assert cycle > arithmetic["start"], "Arithmetic result precedes its request"
                if arithmetic["resultCycle"] is None:
                    arithmetic["resultCycle"] = cycle
                    arithmetic_counts["mulDivMaximumLatency"] = max(arithmetic_counts["mulDivMaximumLatency"], cycle - arithmetic["start"])
                if not finish:
                    arithmetic_counts["mulDivResultStalls"] += 1
            if finish:
                assert valid, "Arithmetic result accepted without valid"
                arithmetic_done.append(pc)
                arithmetic = None
                arithmetic_counts["mulDivFinishes"] += 1
        elif kind == "H":
            assert held is None and completion_cycle is not None, "Unexpected final held offer"
            cycle, address, write, data, mask, size = map(int, fields[1:])
            assert not address % 4 and (write, data, mask, size) == (0, 0, 0, 2), "Invalid held instruction request"
            assert cycle >= completion_cycle, "Held offer precedes completion"
            held = (cycle, (1, address, write, data, mask, size))
        elif kind == "O":
            cycle, valid, address, write, data, mask, size = map(int, fields[1:])
            assert completion_cycle is not None and cycle >= completion_cycle, "Observation precedes completion"
            assert not outstanding and not completed, "Observation contains unfinished transactions"
            assert valid in (0, 1), "Invalid observation valid bit"
            if valid:
                assert not address % 4 and (write, data, mask, size) == (0, 0, 0, 2), "Invalid observed instruction offer"
            assert not observations or cycle == observations[-1][0] + 1, "Missing observation cycle"
            state = (valid, address, write, data, mask, size) if valid else (0,)
            observations.append((cycle, state))
        elif kind == "C":
            names = ("cycles", "retired", "traps", "forwards", "loadUseCycles", "redirects",
                     "memoryWaitCycles", "blockedFetchRedirects", "fetchDrainsAfterCompletion", "interrupts", "sleepCycles")
            assert metrics is None, "Duplicate metrics"
            metrics = dict(zip(names, map(int, fields[1:]), strict=True))
        elif kind == "W":
            observed_memory[int(fields[1])] = int(fields[2])
        else:
            raise AssertionError("Unknown simulation record")
    assert metrics and events and completion_cycle is not None, "Missing checked program completion"
    assert model.pc == case.completion_pc, "Execution left the completion loop"
    assert tuple(causes) == case.expected_causes, "Unexpected exception sequence"
    assert tuple(interrupts) == case.expected_interrupts, "Unexpected interrupt sequence"
    assert metrics["interrupts"] == len(interrupts), "Interrupt metric mismatch"
    assert metrics["sleepCycles"] == sleep_cycles, "Sleep metric mismatch"
    assert metrics["cycles"] == input_cycle + 1, "Clock count differs from input records"
    assert metrics["traps"] == len(causes) and metrics["retired"] + len(causes) == events, "Event count mismatch"
    assert metrics["cycles"] >= max(completion_cycle, last_response) + 8, "Incomplete observation window"
    assert held is None or held[0] == metrics["cycles"] - 1, "Held offer is not from the final cycle"
    assert len(observations) >= 8, "Missing stable observation window"
    window = observations[-8:]
    assert [cycle for cycle, _ in window] == list(range(metrics["cycles"] - 8, metrics["cycles"])), "Observation window does not end at completion"
    assert all(state == window[-1][1] for _, state in window), "Final instruction offer is unstable"
    if window[-1][1][0]:
        assert held == window[-1], "Held offer differs from final observation"
    else:
        assert held is None, "Held offer differs from final observation"
    assert not outstanding and not completed, "Unfinished or unretired transaction"
    assert set(offered) <= {"I"}, "Unaccepted data request at completion"
    if offered:
        assert held is not None and offered["I"][:5] == held[1][1:], "Final offer lost its request identity"
    assert arithmetic is None and not arithmetic_done and cancel_due is None, "Unfinished arithmetic operation"
    if case.name.startswith("m_interrupt_restart_") or (case.name == "protected_user_compute" and case.enable_m):
        assert not restart_pcs and arithmetic_counts["mulDivRestarts"] == 1, "Interrupted arithmetic operation did not restart"
    if case.name == "protected_user_compute" and case.enable_m:
        assert arithmetic_counts["mulDivInterruptCancels"] == 1, "Missing protected arithmetic interrupt cancellation"
        assert arithmetic_counts["mulDivFinishes"] == 8, "Protected arithmetic completed more than once"
    assert {address & ~3 for address in model.memory} <= observed_memory.keys(), "Missing final memory word"
    for address, value in observed_memory.items():
        assert value == model.word(address), "Final memory mismatch"
    for address, expected in case.signature.items():
        assert observed_memory.get(address, 0) == expected, "Program signature mismatch"
    metrics["cpi"] = round(metrics["cycles"] / max(1, metrics["retired"]), 4)
    metrics["instructions"] = dict(coverage)
    metrics.update(arithmetic_counts)
    return metrics


def negative_controls(case, text):
    lines = text.splitlines()
    changed = []
    for field in (2, 7):
        copy = lines.copy()
        index = next(i for i, line in enumerate(lines) if line.startswith("R ") and line.split()[6] == "1")
        words = copy[index].split()
        words[field] = str(int(words[field]) ^ 4)
        copy[index] = " ".join(words)
        changed.append("\n".join(copy))
    copy = lines.copy()
    index = next(i for i, line in enumerate(lines) if line.startswith("Q ") and " D " in line and line.split()[4] == "1")
    words = copy[index].split()
    words[5] = str(int(words[5]) ^ 1)
    copy[index] = " ".join(words)
    changed.append("\n".join(copy))
    for field in (2, 3):
        copy = lines.copy()
        index = next(i for i, line in enumerate(lines) if line.startswith("T "))
        words = copy[index].split()
        words[field] = str(int(words[field]) ^ 1)
        copy[index] = " ".join(words)
        changed.append("\n".join(copy))
    for field in (4, 9):
        copy = lines.copy()
        index = next(i for i, line in enumerate(lines) if line.startswith("R ") and line.split()[8] == "1")
        words = copy[index].split()
        words[field] = str(int(words[field]) ^ 4)
        copy[index] = " ".join(words)
        changed.append("\n".join(copy))
    copy = lines.copy()
    index = next(i for i, line in enumerate(lines) if line.startswith("R ")
                 and int(line.split()[3]) & 127 == 0x73 and line.split()[6] == "1")
    words = copy[index].split()
    words[7] = str(int(words[7]) ^ 1)
    copy[index] = " ".join(words)
    changed.append("\n".join(copy))
    if any(line.startswith("H ") for line in lines):
        copy = lines.copy()
        index = next(i for i, line in enumerate(lines) if line.startswith("H "))
        words = copy[index].split()
        words[5] = "1"
        copy[index] = " ".join(words)
        changed.append("\n".join(copy))
    copy = lines.copy()
    index = [i for i, line in enumerate(lines) if line.startswith("O ")][-4]
    del copy[index]
    changed.append("\n".join(copy))
    copy = lines.copy()
    words = copy[index].split()
    words[2] = str(int(words[2]) ^ 1)
    copy[index] = " ".join(words)
    changed.append("\n".join(copy))
    for mutation in changed:
        try:
            check(case, mutation)
        except AssertionError:
            continue
        raise AssertionError("Checker accepted a corrupted execution")
    return len(changed)


def feature_negative_controls(case, text):
    if case.name in ("halfword_jump", "crossing_second_fault", "first_fault_upper"):
        lines = text.splitlines()
        link = case.name == "halfword_jump"
        index = next(i for i, line in enumerate(lines) if line.startswith("R ") and
                     (int(line.split()[3]) == 0x2011 if link else line.split()[8] == "1"))
        parts = lines[index].split()
        pc = int(parts[2])
        parts[7 if link else 10] = str((pc + 4) & 0xFFFFFFFF if link else
                                      pc if case.name == "crossing_second_fault" else pc & ~3)
        lines[index] = " ".join(parts)
        try:
            check(case, "\n".join(lines))
        except AssertionError as error:
            expected = "Register result mismatch" if link else "Fault metadata mismatch"
            assert expected in str(error), "Compressed negative control failed for a different reason"
            return 1
        raise AssertionError("Checker accepted a changed compressed link or fetch fault address")
    if case.name in ("m_mulh_boundaries", "m_div_boundaries"):
        lines = text.splitlines()
        offset = 3 * 24 + 16 if case.name == "m_mulh_boundaries" else 16
        pc = case.program_pc + offset
        index = next(i for i, line in enumerate(lines) if line.startswith("R ") and int(line.split()[2]) == pc)
        parts = lines[index].split()
        parts[7] = str(0x7FFFFFFF if case.name == "m_mulh_boundaries" else 0)
        lines[index] = " ".join(parts)
        try:
            check(case, "\n".join(lines))
        except AssertionError as error:
            assert "Register result mismatch" in str(error), "Arithmetic negative control failed for a different reason"
            return 1
        raise AssertionError("Checker accepted a changed multiply sign or divide by zero result")
    if case.name == "irq_external":
        selected = lambda line: line.startswith("N ")
        fields = (2, 3, 4)
    elif case.name in ("counter_aliases", "counter_cycle_wrap", "counter_time",
                       "counter_self_retirement", "counter_inhibit_boundary"):
        addresses = {"counter_time": 0xC01, "counter_self_retirement": 0xC02,
                     "counter_inhibit_boundary": 0xC02}
        address = addresses.get(case.name, 0xC00)
        selected = lambda line: (line.startswith("R ") and int(line.split()[3]) >> 20 == address
                                 and line.split()[6] == "1")
        fields = (7,)
    else:
        return 0
    lines = text.splitlines()
    index = next(i for i, line in enumerate(lines) if selected(line))
    for field in fields:
        copy = lines.copy()
        parts = copy[index].split()
        parts[field] = str(int(parts[field]) ^ 4)
        copy[index] = " ".join(parts)
        try:
            check(case, "\n".join(copy))
        except AssertionError:
            continue
        raise AssertionError("Checker accepted a changed interrupt or counter event")
    return len(fields)


def without_instruction_sync(text):
    changes = (("m_fenceI <= isFenceI;", "m_fenceI <= 1'h0;"),
               ("| advance\n       & isFenceI & ~fault", "| 1'h0"))
    for original, replacement in changes:
        assert text.count(original) == 1, "Cannot identify instruction synchronization logic"
        text = text.replace(original, replacement)
    return text


def fence_negative_control(case, rtl, manifest, command, work, output):
    mutant = work / "fence-mutant"
    mutant.mkdir()
    for name in manifest["rtlHashes"]:
        text = (rtl / name).read_text()
        if name == "DitDahE2.sv":
            text = without_instruction_sync(text)
        (mutant / name).write_text(text)
    compile_command = [str(mutant / Path(argument).name) if argument.endswith(".sv") else argument
                       for argument in command]
    compile_command[compile_command.index("--Mdir") + 1] = str(work / "mutant-obj")
    compiled = subprocess.run(compile_command, capture_output=True, text=True)
    if compiled.returncode:
        raise RuntimeError(compiled.stdout + compiled.stderr)
    image = work / "fence-negative.hex"
    image.write_text("".join(f"{address:08x} {word:08x}\n" for address, word in sorted(case.words().items())))
    run = subprocess.run([str(work / "mutant-obj/VDitDahE2"), str(image), "1", "24",
                          str(1 << 32), str(1 << 32), "20000", str(case.completion_pc)],
                         capture_output=True, text=True)
    assert run.returncode == 0, "Instruction synchronization mutant did not complete"
    pc = case.program_pc + 24
    assert any(line.startswith("R ") and int(line.split()[2]) == pc and
               int(line.split()[3]) == case.words()[pc] for line in run.stdout.splitlines()), "Mutant did not execute stale code"
    try:
        check(case, run.stdout)
    except AssertionError as error:
        reason = str(error)
    else:
        raise AssertionError("Checker accepted stale code after FENCE.I")
    (output / "fence-stale.trace").write_text(run.stdout)
    return {"mutation": "disable instruction synchronization", "exitStatus": 0,
            "failure": reason, "rtlHashes": {name: digest(mutant / name) for name in manifest["rtlHashes"]},
            "traceHash": hashlib.sha256(run.stdout.encode()).hexdigest()}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rtl", type=Path, default=Path("result/rtl"))
    parser.add_argument("--output", type=Path, default=Path("result/verification"))
    parser.add_argument("--case", action="append", default=[])
    args = parser.parse_args()
    manifest_data = (args.rtl / "manifest.json").read_bytes()
    manifest_hash = hashlib.sha256(manifest_data).hexdigest()
    manifest = json.loads(manifest_data)
    if manifest["parameters"].get("protectedMode", False):
        subprocess.run([sys.executable, str(Path(__file__).with_name("verify_protected.py")),
                        "--rtl", str(args.rtl), "--output", str(args.output),
                        *[value for name in args.case for value in ("--case", name)]], check=True)
        return
    assert manifest["sourceHashes"] == sources(), "Stale RTL source inputs"
    for name, value in manifest["rtlHashes"].items():
        assert digest(args.rtl / name) == value, "Generated RTL changed"
    inputs = checker_inputs()
    args.output.mkdir(parents=True, exist_ok=True)
    selected = [case for case in cases(manifest["parameters"]["resetVector"],
                                       enable_m=manifest["parameters"].get("enableM", False),
                                       enable_c=manifest["parameters"].get("enableC", False))
                if not args.case or case.name in args.case]
    assert selected and set(args.case) <= {case.name for case in selected}, "Unknown case"
    scratch = "/data/tmp" if os.access("/data/tmp", os.W_OK) else None
    results, controls, rtl_controls = [], 0, []
    with tempfile.TemporaryDirectory(prefix="ditdah-e2-sim-", dir=scratch) as directory:
        work = Path(directory)
        command = ["verilator", "--cc", "--exe", "--build", "-j", "2", "--top-module", "DitDahE2",
                   "--Mdir", str(work / "obj"), "-CFLAGS", "-std=c++17",
                   *[str((args.rtl / name).resolve()) for name in manifest["rtlHashes"]],
                   str(Path("test/sim.cpp").resolve())]
        compiled = subprocess.run(command, capture_output=True, text=True)
        if compiled.returncode:
            raise RuntimeError(compiled.stdout + compiled.stderr)
        for case in selected:
            timings = ((0, 0), (1, 24), (19, 40))
            if case.name.startswith("m_older_"):
                timings += ((7, 128),)
            for seed, delay in timings:
                image = work / "image.hex"
                image.write_text("".join(f"{address:08x} {word:08x}\n" for address, word in sorted(case.words().items())))
                args_run = [str(work / "obj/VDitDahE2"), str(image), str(seed), str(delay),
                            str(case.instruction_fault if case.instruction_fault is not None else 1 << 32),
                            str(case.data_fault if case.data_fault is not None else 1 << 32), "20000",
                            str(case.completion_pc)]
                if case.interrupt_schedule:
                    schedule_path = work / "interrupts.txt"
                    schedule_path.write_text("".join(" ".join(map(str, entry)) + "\n" for entry in case.interrupt_schedule))
                    args_run.append(str(schedule_path))
                run = subprocess.run(args_run, capture_output=True, text=True)
                name = f"{case.name}-s{seed}-d{delay}"
                (args.output / f"{name}.trace").write_text(run.stdout)
                assert run.returncode == 0, f"{name}: {run.stderr}"
                try:
                    metrics = check(case, run.stdout)
                except AssertionError as error:
                    raise AssertionError(f"{name}: {error}") from error
                control_case = "reset_entry" if manifest["parameters"]["resetVector"] else "sum_loop"
                if case.name == control_case and seed == 0:
                    controls += negative_controls(case, run.stdout)
                if seed == 0:
                    controls += feature_negative_controls(case, run.stdout)
                results.append({"case": case.name, "seed": seed, "delay": delay,
                                "exitStatus": run.returncode, **metrics,
                                "imageHash": digest(image),
                                "traceHash": hashlib.sha256(run.stdout.encode()).hexdigest()})
        for case in selected:
            if case.name == "fence_i_self_modify":
                rtl_controls.append(fence_negative_control(case, args.rtl, manifest, command, work, args.output))
                controls += 1
        assert manifest["sourceHashes"] == sources(), "Inputs changed during verification"
        assert inputs == checker_inputs(), "Checker inputs changed"
        assert digest(args.rtl / "manifest.json") == manifest_hash, "RTL manifest changed"
        for name, value in manifest["rtlHashes"].items():
            assert digest(args.rtl / name) == value, "Generated RTL changed during verification"
    if not args.case:
        if not manifest["parameters"]["resetVector"]:
            for metric in ("forwards", "loadUseCycles", "redirects", "memoryWaitCycles", "blockedFetchRedirects", "fetchDrainsAfterCompletion"):
                assert sum(result[metric] for result in results), f"Unreached coverage: {metric}"
            if manifest["parameters"].get("enableM", False):
                for metric in ("mulDivStarts", "mulDivFinishes", "mulDivMemoryOverlapCycles", "mulDivResultStalls",
                               "mulDivTrapCancels", "mulDivInterruptCancels", "mulDivRestarts"):
                    assert sum(result.get(metric, 0) for result in results), f"Unreached arithmetic coverage: {metric}"
        observed = set().union(*(set(result["instructions"]) for result in results))
        required = {"lui", "auipc", "addi", "sw", "jal", "csrrw", "csrrs", "csrrwi", "ecall", "ebreak", "mret"}
        if not manifest["parameters"]["resetVector"]:
            required = set(manifest["instructions"])
        assert required <= observed, f"Unexecuted instructions: {required - observed}"
    summary = {"scope": "integer instructions, native memory, machine traps, interrupts, counters and WFI",
               "command": "python3 test/verify.py", "exitStatus": 0,
               "parameters": manifest["parameters"], "instructions": manifest["instructions"],
               "rtlManifestHash": manifest_hash, "checkerHashes": inputs,
               "simulator": subprocess.check_output(["verilator", "--version"], text=True).strip(),
               "negativeControls": controls, "rtlNegativeControls": rtl_controls, "runs": results,
               "formal": "not run", "isaCompliance": "not run", "physicalSignoff": "not run"}
    (args.output / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    print(f"PASS: {len(results)} RTL runs, {controls} semantic negative controls")


if __name__ == "__main__":
    main()
