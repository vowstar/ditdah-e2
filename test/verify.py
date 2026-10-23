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

from model import Model
from programs import cases

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from build_rtl import INSTRUCTIONS, digest, sources


def checker_inputs():
    paths = ("test/model.py", "test/programs.py", "test/sim.cpp", "test/verify.py", "scripts/build_rtl.py")
    return {name: digest(Path(name)) for name in paths}


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
    coverage = Counter()
    for line in text.splitlines():
        fields = line.split()
        kind = fields[0]
        assert metrics is None or kind == "W", "Execution record after final metrics"
        if kind == "Q":
            cycle, port = int(fields[1]), fields[2]
            assert port in ("I", "D"), "Unknown memory port"
            assert completion_cycle is None or cycle <= completion_cycle, "Request accepted after completion"
            assert port not in outstanding, "Outstanding request overwritten"
            outstanding[port] = (cycle, tuple(map(int, fields[3:])))
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
            expected = model.step()
            coverage[expected.instruction] += 1
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
            if pc == case.completion_pc:
                assert not trap and word == 0x6F and next_pc == pc, "Invalid completion instruction"
                if completion_cycle is None:
                    completion_cycle = cycle
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
                     "memoryWaitCycles", "blockedFetchRedirects", "fetchDrainsAfterCompletion")
            assert metrics is None, "Duplicate metrics"
            metrics = dict(zip(names, map(int, fields[1:]), strict=True))
        elif kind == "W":
            observed_memory[int(fields[1])] = int(fields[2])
        else:
            raise AssertionError("Unknown simulation record")
    assert metrics and events and completion_cycle is not None, "Missing checked program completion"
    assert model.pc == case.completion_pc, "Execution left the completion loop"
    assert tuple(causes) == case.expected_causes, "Unexpected exception sequence"
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


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rtl", type=Path, default=Path("result/rtl"))
    parser.add_argument("--output", type=Path, default=Path("result/verification"))
    parser.add_argument("--case", action="append", default=[])
    args = parser.parse_args()
    manifest = json.loads((args.rtl / "manifest.json").read_text())
    assert manifest["sourceHashes"] == sources(), "Stale RTL source inputs"
    for name, value in manifest["rtlHashes"].items():
        assert digest(args.rtl / name) == value, "Generated RTL changed"
    inputs = checker_inputs()
    args.output.mkdir(parents=True, exist_ok=True)
    selected = [case for case in cases(manifest["parameters"]["resetVector"])
                if not args.case or case.name in args.case]
    assert selected and set(args.case) <= {case.name for case in selected}, "Unknown case"
    scratch = "/data/tmp" if os.access("/data/tmp", os.W_OK) else None
    results, controls = [], 0
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
                    controls = negative_controls(case, run.stdout)
                results.append({"case": case.name, "seed": seed, "delay": delay,
                                "exitStatus": run.returncode, **metrics,
                                "imageHash": digest(image),
                                "traceHash": hashlib.sha256(run.stdout.encode()).hexdigest()})
        assert manifest["sourceHashes"] == sources(), "Inputs changed during verification"
        assert inputs == checker_inputs(), "Checker inputs changed"
    if not args.case:
        if not manifest["parameters"]["resetVector"]:
            for metric in ("forwards", "loadUseCycles", "redirects", "memoryWaitCycles", "blockedFetchRedirects", "fetchDrainsAfterCompletion"):
                assert sum(result[metric] for result in results), f"Unreached coverage: {metric}"
        observed = set().union(*(set(result["instructions"]) for result in results))
        required = {"lui", "auipc", "addi", "sw", "jal", "csrrw", "csrrs", "csrrwi", "ecall", "ebreak", "mret"}
        if not manifest["parameters"]["resetVector"]:
            required = set(INSTRUCTIONS)
        assert required <= observed, f"Unexecuted instructions: {required - observed}"
    summary = {"scope": "base integer instructions, native memory, machine CSRs and traps",
               "command": "python3 test/verify.py", "exitStatus": 0,
               "rtlManifestHash": digest(args.rtl / "manifest.json"), "checkerHashes": inputs,
               "simulator": subprocess.check_output(["verilator", "--version"], text=True).strip(),
               "negativeControls": controls, "runs": results,
               "formal": "not run", "isaCompliance": "not run", "physicalSignoff": "not run"}
    (args.output / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    print(f"PASS: {len(results)} RTL runs; {controls} semantic negative controls")


if __name__ == "__main__":
    main()
