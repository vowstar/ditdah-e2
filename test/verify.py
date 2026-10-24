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

from model import Model, TIME_BASE, MASK64
from programs import cases

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from build_rtl import INSTRUCTIONS, digest, sources


def checker_inputs():
    paths = ("test/model.py", "test/programs.py", "test/sim.cpp", "test/verify.py", "scripts/build_rtl.py")
    return {name: digest(Path(name)) for name in paths}


class InputSchedule:
    def __init__(self, entries):
        self.entries = entries
        self.fired = set()
        self.mask = 0
        self.pending = None

    def event(self, kind, key):
        for index, (trigger, value, mask) in enumerate(self.entries):
            if index not in self.fired and (trigger, value) == (kind, key):
                self.fired.add(index)
                if kind == "C":
                    self.mask = mask
                else:
                    self.pending = mask

    def clock(self, cycle):
        if self.pending is not None:
            self.mask, self.pending = self.pending, None
        self.event("C", cycle)
        return self.mask


def check(case, text):
    model = Model(case.words(), case.reset, case.instruction_fault, case.data_fault)
    outstanding = {}
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
    for line in text.splitlines():
        fields = line.split()
        kind = fields[0]
        assert metrics is None or kind == "W", "Execution record after final metrics"
        if kind == "T":
            cycle, mask, time = map(int, fields[1:])
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
        if kind == "Q":
            cycle, port = int(fields[1]), fields[2]
            assert port in ("I", "D"), "Unknown memory port"
            assert completion_cycle is None or cycle <= completion_cycle, "Request accepted after completion"
            assert port not in outstanding, "Outstanding request overwritten"
            outstanding[port] = (cycle, tuple(map(int, fields[3:])))
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
            cycle, pc, word, next_pc, rd, writes, value, trap, cause, tval = map(int, fields[1:])
            assert architectural_event != cycle, "Multiple architectural events in one cycle"
            assert interrupt_deadline != cycle, "Instruction crossed an interrupt boundary"
            architectural_event = cycle
            expected = model.step()
            coverage[expected.instruction] += 1
            if expected.instruction == "fence.i" and not expected.trap:
                assert "I" not in outstanding, "FENCE.I retired before old fetch completion"
            assert (pc, word, next_pc, bool(trap)) == (expected.pc, expected.word, expected.next_pc, expected.trap), "Instruction/PC/trap mismatch"
            assert bool(writes) == bool(expected.rd), "Register write enable mismatch"
            assert value == expected.value and (not writes or rd == expected.rd), "Register result mismatch"
            if trap:
                assert (cause, tval) == (expected.cause, expected.tval), "Fault metadata mismatch"
                causes.append(cause)
            if expected.memory:
                assert completed, "Memory instruction retired before response"
                request, response = completed.popleft()
                address, write, data, mask, size = request
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
    assert {address & ~3 for address in model.memory} <= observed_memory.keys(), "Missing final memory word"
    for address, value in observed_memory.items():
        assert value == model.word(address), "Final memory mismatch"
    for address, expected in case.signature.items():
        assert observed_memory.get(address, 0) == expected, "Program signature mismatch"
    metrics["cpi"] = round(metrics["cycles"] / max(1, metrics["retired"]), 4)
    metrics["instructions"] = dict(coverage)
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
    assert manifest["sourceHashes"] == sources(), "Stale RTL source inputs"
    for name, value in manifest["rtlHashes"].items():
        assert digest(args.rtl / name) == value, "Generated RTL changed"
    inputs = checker_inputs()
    args.output.mkdir(parents=True, exist_ok=True)
    selected = [case for case in cases(manifest["parameters"]["resetVector"])
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
            for seed, delay in ((0, 0), (1, 24), (19, 40)):
                image = work / "image.hex"
                image.write_text("".join(f"{address:08x} {word:08x}\n" for address, word in sorted(case.words().items())))
                args_run = [str(work / "obj/VDitDahE2"), str(image), str(seed), str(delay),
                            str(case.instruction_fault if case.instruction_fault is not None else 1 << 32),
                            str(case.data_fault if case.data_fault is not None else 1 << 32), "20000",
                            str(case.completion_pc)]
                if case.interrupt_schedule:
                    schedule_path = work / "interrupts.txt"
                    schedule_path.write_text("".join(f"{kind} {key} {mask}\n" for kind, key, mask in case.interrupt_schedule))
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
        observed = set().union(*(set(result["instructions"]) for result in results))
        required = {"lui", "auipc", "addi", "sw", "jal", "csrrw", "csrrs", "csrrwi", "ecall", "ebreak", "mret"}
        if not manifest["parameters"]["resetVector"]:
            required = set(INSTRUCTIONS)
        assert required <= observed, f"Unexecuted instructions: {required - observed}"
    summary = {"scope": "integer instructions, native memory, machine traps, interrupts, counters and WFI",
               "command": "python3 test/verify.py", "exitStatus": 0,
               "rtlManifestHash": manifest_hash, "checkerHashes": inputs,
               "simulator": subprocess.check_output(["verilator", "--version"], text=True).strip(),
               "negativeControls": controls, "rtlNegativeControls": rtl_controls, "runs": results,
               "formal": "not run", "isaCompliance": "not run", "physicalSignoff": "not run"}
    (args.output / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    print(f"PASS: {len(results)} RTL runs, {controls} semantic negative controls")


if __name__ == "__main__":
    main()
