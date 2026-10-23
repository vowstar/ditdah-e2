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


def check(case, text):
    model = Model(case.words(), case.reset, case.instruction_fault, case.data_fault)
    outstanding = {}
    completed = deque()
    observed_memory = {}
    metrics = None
    events = 0
    last_cause = None
    coverage = Counter()
    for line in text.splitlines():
        fields = line.split()
        kind = fields[0]
        if kind == "Q":
            cycle, port = int(fields[1]), fields[2]
            assert port not in outstanding, "Outstanding request overwritten"
            outstanding[port] = (cycle, tuple(map(int, fields[3:])))
        elif kind == "S":
            cycle, port = int(fields[1]), fields[2]
            assert port in outstanding, "Response without request"
            start, request = outstanding.pop(port)
            assert cycle > start, "Response must follow request acceptance"
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
                last_cause = cause
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
        elif kind == "C":
            names = ("cycles", "retired", "traps", "forwards", "loadUseCycles", "redirects",
                     "memoryWaitCycles", "blockedFetchRedirects", "fetchDrainsAfterHalt")
            metrics = dict(zip(names, map(int, fields[1:]), strict=True))
        elif kind == "W":
            observed_memory[int(fields[1])] = int(fields[2])
        else:
            raise AssertionError("Unknown simulation record")
    assert metrics and events and model.stopped, "Missing execution or terminal fault"
    assert last_cause == case.cause, "Unexpected terminal cause"
    assert metrics["traps"] == 1 and metrics["retired"] + 1 == events, "Event count mismatch"
    assert not outstanding and not completed, "Unfinished or unretired transaction"
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
    words = copy[index].split(); words[5] = str(int(words[5]) ^ 1)
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
    inputs = {str(p): digest(p) for p in sorted(Path("test").glob("*")) if p.is_file()}
    args.output.mkdir(parents=True, exist_ok=True)
    selected = [case for case in cases() if not args.case or case.name in args.case]
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
                            str(case.data_fault if case.data_fault is not None else 1 << 32), "20000"]
                run = subprocess.run(args_run, capture_output=True, text=True)
                name = f"{case.name}-s{seed}-d{delay}"
                (args.output / f"{name}.trace").write_text(run.stdout)
                assert run.returncode == 0, f"{name}: {run.stderr}"
                try:
                    metrics = check(case, run.stdout)
                except AssertionError as error:
                    raise AssertionError(f"{name}: {error}") from error
                if case.name == "sum_loop" and seed == 0:
                    controls = negative_controls(case, run.stdout)
                results.append({"case": case.name, "seed": seed, "delay": delay,
                                "exitStatus": run.returncode, **metrics,
                                "imageHash": digest(image),
                                "traceHash": hashlib.sha256(run.stdout.encode()).hexdigest()})
        assert manifest["sourceHashes"] == sources(), "Inputs changed during verification"
        assert inputs == {str(p): digest(p) for p in sorted(Path("test").glob("*")) if p.is_file()}, "Checker inputs changed"
    if not args.case:
        for metric in ("forwards", "loadUseCycles", "redirects", "memoryWaitCycles", "blockedFetchRedirects", "fetchDrainsAfterHalt"):
            assert sum(result[metric] for result in results), f"Unreached coverage: {metric}"
        observed = set().union(*(set(result["instructions"]) for result in results))
        assert set(INSTRUCTIONS) <= observed, f"Unexecuted instructions: {set(INSTRUCTIONS) - observed}"
    summary = {"scope": "base integer instructions, native memory, terminal faults",
               "command": "python3 test/verify.py", "exitStatus": 0,
               "rtlManifestHash": digest(args.rtl / "manifest.json"), "checkerHashes": inputs,
               "simulator": subprocess.check_output(["verilator", "--version"], text=True).strip(),
               "negativeControls": controls, "runs": results,
               "formal": "not run", "isaCompliance": "not run", "physicalSignoff": "not run"}
    (args.output / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    print(f"PASS: {len(results)} RTL runs; {controls} semantic negative controls")


if __name__ == "__main__":
    main()
