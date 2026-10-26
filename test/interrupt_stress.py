# SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
# SPDX-License-Identifier: MIT
"""Check interrupt boundaries, WFI masks and fixed randomized programs on RTL."""

import argparse
from dataclasses import replace
import hashlib
import json
import os
from pathlib import Path
import random
import re
import shutil
import subprocess
import tempfile

from model import Model, TIME_BASE, MASK64
from programs import Case, PROGRAM_PC, COMPLETION_PC, MRET, WFI, constant, csr, immediate, store, branch, finish
from verify import InputSchedule, check, checker_inputs
from build_rtl import sources, digest


TIMINGS = ((0, 0), (1, 24), (19, 40))
COUNTER_READS = (0xC00, 0xC80, 0xC01, 0xC81, 0xC02, 0xC82, 0xB00, 0xB80, 0xB02, 0xB82)


def interrupt_bits(mask):
    return sum(((mask >> lane) & 1) << bit for lane, bit in enumerate((3, 7, 11)))


def cause(mask):
    return 0x8000000B if mask & 4 else 0x80000003 if mask & 1 else 0x80000007


def recovery_handler():
    # Skip synchronous faults. Interrupts retain the saved next instruction.
    return [csr(26, 0x342), branch(26, 0, 16, funct3=4), csr(27, 0x341),
            immediate(27, 27, 4), csr(0, 0x341, 27, 1), MRET]


def wfi_case(pending, enabled, global_enable):
    code = constant(1, interrupt_bits(enabled))
    code += [csr(0, 0x304, 1, 1), csr(3, 0x304), csr(0, 0x300, global_enable * 8, 5)]
    wfi_pc = PROGRAM_PC + len(code) * 4
    code += [WFI, immediate(7, 0, 73), store(7, 0, 768), csr(4, 0x344)]
    active = pending & enabled
    entry = bool(active and global_enable)
    case = Case(f"wfi_p{pending}_e{enabled}_g{global_enable}", finish(code), signature={768: 73},
                expected_causes=(), handler=[MRET],
                interrupt_schedule=(("R", wfi_pc, pending), ("N", 1, 0)),
                expected_interrupts=(cause(active),) if entry else ())
    return case, {"group": "wfi", "pending": pending, "enabled": enabled, "globalEnable": global_enable,
                  "localWake": bool(active), "interruptEntry": entry, "wfiPc": wfi_pc,
                  "boundedObservation": not active, "minimumObservationCycles": 64}


def boundary_case(write, failed):
    code = constant(1, 0x888) + [csr(0, 0x304, 1, 1), csr(0, 0x300, 8, 6), immediate(2, 0, 29)]
    pc = PROGRAM_PC + len(code) * 4
    code += [store(2, 0, 768) if write else immediate(2, 0, 768, 3, 2), store(2, 0, 772), csr(3, 0xC02)]
    case = Case(f"boundary_{'store' if write else 'load'}_{'fault' if failed else 'success'}", finish(code),
                data={768: 17}, data_fault=768 if failed else None,
                signature={768: 29 if write and not failed else 17, 772: 17 if not write and not failed else 29},
                handler=recovery_handler(), expected_causes=(7 if write else 5,) if failed else ())
    return case, {"group": "boundary", "write": write, "fault": failed, "address": 768, "pc": pc}


def random_case(seed):
    rng = random.Random(0xE2000000 + seed)
    code = constant(1, 0x888) + [csr(0, 0x304, 1, 1), csr(0, 0x300, 8, 6)]
    data, signature, schedule, masks, accesses, triggers = {}, {}, [], [], [], []
    fault_index = rng.randrange(6) if seed % 2 else None
    fault_cause = None
    for index in range(6):
        address = 768 + index * 4
        initial, value = rng.randrange(1, 1024), rng.randrange(1, 1024)
        write, mask = bool(rng.randrange(2)), rng.randrange(1, 8)
        data[address] = initial
        code += [immediate(2, 0, value)]
        counter = rng.choice(COUNTER_READS)
        accesses.append(counter)
        code += [csr(3, counter)]
        if index % 2:
            code += [csr(0, 0x320, rng.choice((0, 1, 4, 5)), 5)]
        if index == 2:
            code += [csr(0, rng.choice((0xB00, 0xB80, 0xB02, 0xB82)), rng.randrange(32), 5)]
        pc = PROGRAM_PC + len(code) * 4
        code += [store(2, 0, address) if write else immediate(2, 0, address, 3, 2)]
        trigger = ("D", address, mask) if index % 2 else ("R", pc, mask)
        schedule += [trigger, ("N", index + 1, 0)]
        triggers.append({"trigger": trigger[0], "key": trigger[1], "mask": mask, "memoryPc": pc,
                         "address": address, "write": write, "fault": index == fault_index})
        masks.append(mask)
        tail_counter = rng.choice(COUNTER_READS)
        accesses.append(tail_counter)
        code += [store(2, 0, 896 + index * 4), csr(4, tail_counter)]
        failed = index == fault_index
        signature[address] = value if write and not failed else initial
        signature[896 + index * 4] = initial if not write and not failed else value
        if failed:
            fault_cause = 7 if write else 5
    code += [csr(0, 0x320, 0, 5)]
    case = Case(f"interrupt_random_{seed}", finish(code), data=data, signature=signature,
                data_fault=768 + fault_index * 4 if fault_index is not None else None,
                handler=recovery_handler(), expected_causes=(fault_cause,) if fault_cause else (),
                interrupt_schedule=tuple(schedule), expected_interrupts=tuple(cause(mask) for mask in masks))
    return case, {"group": "random", "programSeed": seed, "faultIndex": fault_index,
                  "counterReads": accesses, "triggers": triggers}


def sleep_observations(case, text, bounded=False):
    model = Model(case.words(), case.reset, case.instruction_fault, case.data_fault,
                  enable_m=case.enable_m, enable_c=case.enable_c)
    schedule = InputSchedule(case.interrupt_schedule)
    expected_sleep = None
    input_cycle = -1
    observed = []
    outstanding, offered = {}, {}
    wfi_cycles, retirements, interrupts = [], [], []
    for line in text.splitlines():
        fields = line.split()
        kind = fields[0]
        if kind == "T":
            cycle, mask, time = map(int, fields[1:])
            assert cycle == input_cycle + 1, "Missing observed clock"
            assert expected_sleep is None, "Missing sleep observation"
            assert mask == schedule.clock(cycle), "Interrupt input differs from schedule"
            assert time == (TIME_BASE + cycle) & MASK64, "Time input differs"
            expected_sleep = int(model.sleeping)
            model.clock(cycle, mask)
            input_cycle = cycle
        elif kind == "L":
            cycle, sleeping = map(int, fields[1:])
            assert cycle == input_cycle and expected_sleep is not None, "Unowned sleep observation"
            assert sleeping == expected_sleep, "Sleep state differs from architectural wake rule"
            observed.append((cycle, sleeping))
            expected_sleep = None
        elif kind == "P":
            port, request = fields[2], tuple(map(int, fields[3:]))
            assert port not in offered, "Repeated request offer"
            offered[port] = request
            if bounded:
                assert port == "I", "Data effect in bounded WFI observation"
        elif kind == "Q":
            port, request = fields[2], tuple(map(int, fields[3:]))
            assert port not in outstanding and offered.pop(port) == request, "Request ownership differs"
            outstanding[port] = (input_cycle, request)
            if port == "D":
                schedule.event("D", request[0])
        elif kind == "S":
            port = fields[2]
            assert port in outstanding and outstanding[port][0] < input_cycle, "Response ownership differs"
            outstanding.pop(port)
        elif kind == "R":
            cycle, pc, word, next_pc, rd, writes, value, trap, code, tval = map(int, fields[1:11])
            event = model.step()
            assert (pc, word, next_pc, bool(trap)) == (event.pc, event.word, event.next_pc, event.trap), "Observed instruction differs"
            assert (bool(writes), value) == (bool(event.rd), event.value), "Observed register result differs"
            assert not writes or rd == event.rd, "Observed register destination differs"
            if trap:
                assert (code, tval) == (event.cause, event.tval), "Observed trap differs"
            if event.instruction == "wfi":
                wfi_cycles.append(cycle)
            retirements.append((cycle, pc))
            schedule.event("R", pc)
        elif kind == "N":
            cycle, pc, target, code = map(int, fields[1:])
            assert "D" not in outstanding, "Interrupt crossed unfinished data work"
            assert (pc, target, code) == model.interrupt(), "Observed interrupt differs"
            interrupts.append((cycle, pc, code))
            schedule.event("N", len(interrupts))
    assert expected_sleep is None and len(observed) == input_cycle + 1, "Incomplete sleep observations"
    if bounded:
        assert len(wfi_cycles) == 1 and not interrupts, "Bounded observation did not reach one WFI"
        assert retirements[-1][0] == wfi_cycles[0], "Instruction retired after sleeping WFI"
        assert model.sleeping and model.pc == retirements[-1][1] + 4, "Bounded WFI lost its resume PC"
        assert not outstanding and not offered, "Bounded WFI fetch did not drain"
        assert len(observed) - wfi_cycles[0] - 1 >= 64, "Bounded WFI observation is too short"
        assert all(sleeping for _, sleeping in observed[-64:]), "Bounded WFI did not remain asleep"
        assert not any(line.startswith(("C ", "W ")) for line in text.splitlines()), "Bounded observation claims program completion"
    return {"wfiCycles": wfi_cycles, "sleepCycles": sum(value for _, value in observed),
            "lastCycle": input_cycle, "interruptEvents": interrupts,
            "sleepTransitions": [(cycle, value) for index, (cycle, value) in enumerate(observed)
                                 if not index or value != observed[index - 1][1]]}


def without_observations(text):
    return "\n".join(line for line in text.splitlines() if not line.startswith("L ")) + "\n"


def memory_times(text, address):
    pending = None
    result = []
    for line in text.splitlines():
        fields = line.split()
        if fields[0] == "Q" and fields[2] == "D":
            assert pending is None, "Memory request overlaps"
            pending = (int(fields[1]), int(fields[3]))
        elif fields[0] == "S" and fields[2] == "D":
            assert pending is not None, "Memory response lacks owner"
            if pending[1] == address:
                result.append({"requestCycle": pending[0], "responseCycle": int(fields[1]), "fault": int(fields[4])})
            pending = None
    assert len(result) == 1, "Expected one selected memory transaction"
    return result[0]


def check_boundary(text, address, injection, offset):
    times = memory_times(text, address)
    masks = [(int(f[1]), int(f[2])) for line in text.splitlines() if (f := line.split())[0] == "T"]
    changed = [cycle for index, (cycle, mask) in enumerate(masks) if mask and (not index or not masks[index - 1][1])]
    assert changed == [injection], "Boundary interrupt did not use its scheduled clock"
    assert injection - times["responseCycle"] == offset, "Interrupt response boundary differs"
    assert injection > times["requestCycle"] or offset == -1, "Boundary injection precedes memory ownership"
    return {**times, "injectionCycle": injection, "responseOffset": offset}


def random_observations(text, triggers):
    rows = [line.split() for line in text.splitlines()]
    inputs = {int(row[1]): int(row[2]) for row in rows if row[0] == "T"}
    interrupts = [int(row[1]) for row in rows if row[0] == "N"]
    assert len(interrupts) == len(triggers), "Random interrupt coverage differs"
    result = []
    for index, item in enumerate(triggers):
        matches = [int(row[1]) for row in rows if
                   (item["trigger"] == "D" and row[0] == "Q" and row[2] == "D" and int(row[3]) == item["key"]) or
                   (item["trigger"] == "R" and row[0] == "R" and int(row[2]) == item["key"])]
        assert len(matches) == 1, "Random trigger was missing or repeated"
        injected = matches[0] + 1
        assert inputs[injected] == item["mask"], "Random interrupt input missed its trigger"
        memory = memory_times(text, item["address"])
        result.append({**item, **memory, "triggerCycle": matches[0], "injectionCycle": injected,
                       "responseOffset": injected - memory["responseCycle"], "interruptCycle": interrupts[index]})
    return result


def coverage(runs, groups, timings, seeds):
    keys = [(item["case"], item["timingSeed"], item["delay"]) for item in runs]
    assert len(keys) == len(set(keys)) and all(item["checkerAccepted"] for item in runs), "Repeated or unchecked stress execution"
    counts = {}
    for group in groups:
        selected = [item for item in runs if item["group"] == group]
        if group == "wfi":
            expected = {(p, e, g, s, d) for p in range(8) for e in range(8) for g in range(2) for s, d in timings}
            actual = {(x["pending"], x["enabled"], x["globalEnable"], x["timingSeed"], x["delay"]) for x in selected}
        elif group == "boundary":
            expected = {(w, f, q, o, s, d) for w in (False, True) for f in (False, True)
                        for q in (1, 2, 4) for o in (-1, 0, 1) for s, d in timings}
            actual = {(x["write"], x["fault"], x["source"], x["responseOffset"], x["timingSeed"], x["delay"]) for x in selected}
        else:
            expected = {(p, s, d) for p in seeds for s, d in timings}
            actual = {(x["programSeed"], x["timingSeed"], x["delay"]) for x in selected}
        assert actual == expected, f"Incomplete {group} coverage"
        counts[group] = len(selected)
    return {"groups": counts, "runs": len(runs),
            "completedPrograms": sum(not item.get("boundedObservation", False) for item in runs),
            "boundedSleepObservations": sum(item.get("boundedObservation", False) for item in runs),
            "randomProgramSeeds": sorted({item["programSeed"] for item in runs if item["group"] == "random"}),
            "randomCounterReads": sorted({address for item in runs if item["group"] == "random" for address in item["counterReads"]}),
            "randomFaultKinds": sorted({"store" if trigger["write"] else "load" for item in runs if item["group"] == "random"
                                         for trigger in item["triggers"] if trigger["fault"]})}


def reject(function, expected):
    try:
        function()
    except AssertionError as error:
        assert expected in str(error), f"Negative control failed another check: {error}"
        return str(error)
    raise AssertionError("Negative control was accepted")


def masked_wake_mutant(content):
    changed, count = re.subn(r"(wire\s+waking\s*=\s*sleeping_\d+)\s*& localWake;",
                            r"\1 & (interrupts_software | interrupts_timer | interrupts_external);", content)
    assert count == 1, "Wake mutation no longer matches RTL"
    return changed


def trace_controls(case, text, details, existing):
    controls = []
    if details["group"] == "wfi" and details["boundedObservation"] and "sleep-observation" not in existing:
        lines = text.splitlines()
        index = next(i for i, line in enumerate(lines) if line.startswith("L ") and line.split()[2] == "1")
        changed = lines.copy()
        changed[index] = changed[index][:-1] + "0"
        controls.append({"name": "sleep-observation", "trace": "\n".join(changed), "reason": reject(
            lambda: sleep_observations(case, "\n".join(changed), True), "Sleep state differs")})
    if details["group"] == "boundary" and "response-boundary" not in existing:
        controls.append({"name": "response-boundary", "trace": text, "wrongInjectionCycle": details["injectionCycle"] + 1, "reason": reject(
            lambda: check_boundary(text, details["address"], details["injectionCycle"] + 1, details["responseOffset"]),
            "scheduled clock")})
    if details["group"] == "random" and "counter-read" not in existing:
        lines = text.splitlines()
        index = next(i for i, line in enumerate(lines) if line.startswith("R ") and
                     int(line.split()[3]) >> 20 in COUNTER_READS and line.split()[6] == "1")
        parts = lines[index].split()
        parts[7] = str(int(parts[7]) ^ 1)
        lines[index] = " ".join(parts)
        controls.append({"name": "counter-read", "trace": "\n".join(lines), "reason": reject(
            lambda: check(case, without_observations("\n".join(lines))), "Register result mismatch")})
    if details["group"] == "random" and case.data_fault is not None and "failed-response" not in existing:
        lines = text.splitlines()
        index = next(i for i, line in enumerate(lines) if line.startswith("S ") and line.split()[2] == "D" and line.split()[4] == "1")
        parts = lines[index].split()
        parts[4] = "0"
        lines[index] = " ".join(parts)
        controls.append({"name": "failed-response", "trace": "\n".join(lines), "reason": reject(
            lambda: check(case, without_observations("\n".join(lines))), "Memory fault mismatch")})
    return controls


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rtl", type=Path, default=Path("result/rtl"))
    parser.add_argument("--output", type=Path, default=Path("result/interrupt-stress"))
    parser.add_argument("--group", action="append", choices=("wfi", "boundary", "random"))
    parser.add_argument("--seed", action="append", type=int)
    parser.add_argument("--timing", action="append", type=int, choices=(0, 1, 2))
    args = parser.parse_args()
    assert not args.output.exists(), "Output already exists"
    assert not args.seed or all(0 <= seed < 64 for seed in args.seed), "Program seed is outside the fixed set"
    args.output.mkdir(parents=True)
    manifest = json.loads((args.rtl / "manifest.json").read_text())
    assert manifest["sourceHashes"] == sources(), "Stale RTL inputs"
    assert manifest["parameters"]["resetVector"] == 0 and not any(manifest["parameters"].get(name, False)
        for name in ("protectedMode", "enableDebug", "enableA", "enableZba", "enableZbb", "enableZbs")), "Unsupported stress configuration"
    inputs = checker_inputs() | {"test/interrupt_stress.py": digest(Path(__file__)),
                                "test/test_interrupt_stress.py": digest(Path("test/test_interrupt_stress.py")),
                                "test/pmp.py": digest(Path("test/pmp.py"))}
    for name, expected in (manifest["sourceHashes"] | inputs).items():
        contents = Path(name).read_bytes()
        assert hashlib.sha256(contents).hexdigest() == expected
        path = args.output / "inputs" / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(contents)
    for name, expected in manifest["rtlHashes"].items():
        assert digest(args.rtl / name) == expected, "RTL changed"
        target = args.output / "rtl" / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(args.rtl / name, target)
    groups = args.group or ["wfi", "boundary", "random"]
    timings = [TIMINGS[index] for index in args.timing] if args.timing else TIMINGS
    seeds = args.seed or list(range(64))
    plan = {"groups": groups, "timings": timings, "programSeeds": seeds,
            "wfiMatrix": {"pending": list(range(8)), "enabled": list(range(8)), "globalEnable": [0, 1],
                          "observation": "local wake and interrupt entry checked separately after WFI commit",
                          "noWake": "512-clock bounded observation, at least 64 clocks after WFI, no completed-program claim"},
            "boundaries": {"sourceMasks": [1, 2, 4], "responseOffsets": [-1, 0, 1],
                           "write": [False, True], "fault": [False, True],
                           "calibration": "same image, seed and delays without interrupt input"},
            "history": "The earlier four-seed regression retains its original scope."}
    (args.output / "plan.json").write_text(json.dumps(plan, indent=2) + "\n")
    report = {"scope": "machine interrupt boundaries, WFI enable matrix and 64 fixed random programs",
              "parameters": manifest["parameters"], "sourceHashes": manifest["sourceHashes"], "checkerHashes": inputs,
              "rtlHashes": manifest["rtlHashes"], "planHash": digest(args.output / "plan.json"),
              "command": "python3 test/interrupt_stress.py", "runs": [], "calibrations": [], "negativeControls": [], "exitStatus": None}
    tools = {name: Path(shutil.which(name)).resolve() for name in ("verilator", "verilator_bin", "c++")}
    report["toolHashes"] = {name: digest(path) for name, path in tools.items()}
    report["tools"] = {name: subprocess.check_output([name, "--version"], text=True).splitlines()[0]
                       for name in ("verilator", "c++")}

    def save():
        (args.output / "summary.json").write_text(json.dumps(report, indent=2) + "\n")

    save()
    scratch = "/data/tmp" if os.access("/data/tmp", os.W_OK) else None
    with tempfile.TemporaryDirectory(prefix="ditdah-e2-interrupt-native-", dir=scratch) as directory:
        work = Path(directory)
        command = ["verilator", "--cc", "--exe", "--build", "-j", "2", "--top-module", "DitDahE2",
                   "--Mdir", str(work / "obj"), "-CFLAGS", "-std=c++17",
                   *[str((args.rtl / name).resolve()) for name in manifest["rtlHashes"]], str(Path("test/sim.cpp").resolve())]
        compiled = subprocess.run(command, capture_output=True, text=True)
        (args.output / "build.log").write_text((compiled.stdout + compiled.stderr).replace(str(Path.cwd()), "<source>").replace(str(work), "<work>"))
        assert compiled.returncode == 0, "Stress harness compilation failed"
        executable = work / "obj/VDitDahE2"
        report["build"] = {"exitStatus": compiled.returncode, "logHash": digest(args.output / "build.log"),
                           "binaryHash": digest(executable), "command": [part.replace(str(Path.cwd()), "<source>").replace(str(work), "<work>") for part in command]}

        def execute(case, details, timing, calibration=False):
            seed, delay = timing
            case.enable_m = manifest["parameters"].get("enableM", False)
            case.enable_c = manifest["parameters"].get("enableC", False)
            name = f"{case.name}-s{seed}-d{delay}"
            output = args.output / name
            output.mkdir()
            image, schedule = output / "image.hex", output / "schedule.txt"
            image.write_text("".join(f"{address:08x} {word:08x}\n" for address, word in sorted(case.words().items())))
            schedule.write_text("".join(" ".join(map(str, entry)) + "\n" for entry in case.interrupt_schedule))
            bounded = details.get("boundedObservation", False)
            argv = [str(executable), str(image.resolve()), str(seed), str(delay), str(1 << 32),
                    str(case.data_fault if case.data_fault is not None else 1 << 32), "512" if bounded else "50000",
                    str(case.completion_pc), str(schedule.resolve()), "--observe-sleep"]
            run = subprocess.run(argv, capture_output=True, text=True)
            (output / "execution.trace").write_text(run.stdout)
            (output / "stderr.txt").write_text(run.stderr)
            record = {"case": case.name, "timingSeed": seed, "delay": delay, **details,
                      "harnessExitStatus": run.returncode, "imageHash": digest(image), "scheduleHash": digest(schedule),
                      "traceHash": digest(output / "execution.trace"), "stderrHash": digest(output / "stderr.txt"),
                      "command": [part.replace(str(Path.cwd()), "<source>").replace(str(work), "<work>") for part in argv],
                      "checkerAccepted": False}
            collection = report["calibrations"] if calibration else report["runs"]
            collection.append(record)
            save()
            try:
                observations = sleep_observations(case, run.stdout, bounded)
                if bounded:
                    assert run.returncode == 1 and run.stderr.strip() == "Execution timeout", "Wrong bounded observation exit"
                    record["completion"] = "bounded sleep observation only"
                else:
                    assert run.returncode == 0, f"Program did not complete: {run.stderr}"
                    record["metrics"] = check(case, without_observations(run.stdout))
                    record["completion"] = "independently checked completion loop and transaction drain"
                record["observations"] = observations
                if details["group"] == "boundary" and not calibration:
                    record["boundary"] = check_boundary(run.stdout, details["address"], details["injectionCycle"], details["responseOffset"])
                if details["group"] == "random":
                    record["transactions"] = random_observations(run.stdout, details["triggers"])
                if not calibration and seed == timings[0][0]:
                    controls = trace_controls(case, run.stdout, details, {item["name"] for item in report["negativeControls"]})
                    for item in controls:
                        path = output / (item["name"] + ".trace")
                        path.write_text(item.pop("trace"))
                        report["negativeControls"].append({"group": details["group"], "kind": "trace", "case": case.name,
                                                          "traceHash": digest(path), **item})
                record["checkerAccepted"] = True
                save()
            except Exception as error:
                record["checkerError"] = str(error)
                report["exitStatus"] = 1
                save()
                raise
            return run.stdout

        if "wfi" in groups:
            for pending in range(8):
                for enabled in range(8):
                    for global_enable in range(2):
                        case, details = wfi_case(pending, enabled, global_enable)
                        for timing in timings:
                            execute(case, details, timing)
            print("WFI matrix checked", flush=True)
        if "boundary" in groups:
            for write in (False, True):
                for failed in (False, True):
                    base, details = boundary_case(write, failed)
                    for timing in timings:
                        reference = execute(replace(base, name=base.name + "_calibration"), details, timing, True)
                        response = memory_times(reference, details["address"])["responseCycle"]
                        for source in (1, 2, 4):
                            for offset in (-1, 0, 1):
                                injection = response + offset
                                case = replace(base, name=f"{base.name}_source{source}_offset{offset}",
                                    interrupt_schedule=(("C", injection, source), ("N", 1, 0)), expected_interrupts=(cause(source),))
                                execute(case, {**details, "source": source, "injectionCycle": injection, "responseOffset": offset}, timing)
            print("Interrupt response boundaries checked", flush=True)
        if "random" in groups:
            for seed in seeds:
                case, details = random_case(seed)
                for timing in timings:
                    execute(case, details, timing)
            print(f"{len(seeds)} random programs checked in {len(timings)} timing modes", flush=True)
        if "wfi" in groups:
            negative = args.output / "masked-wake-rtl"
            negative.mkdir()
            for name in manifest["rtlHashes"]:
                value = (args.rtl / name).read_text()
                if name == "DitDahE2.sv":
                    value = masked_wake_mutant(value)
                (negative / name).write_text(value)
            bad_command = ["verilator", "--cc", "--exe", "--build", "-j", "2", "--top-module", "DitDahE2",
                           "--Mdir", str(work / "bad-obj"), "-CFLAGS", "-std=c++17",
                           *[str((negative / name).resolve()) for name in manifest["rtlHashes"]], str(Path("test/sim.cpp").resolve())]
            build = subprocess.run(bad_command, capture_output=True, text=True)
            (negative / "build.log").write_text((build.stdout + build.stderr).replace(str(Path.cwd()), "<source>").replace(str(work), "<work>"))
            assert build.returncode == 0, "Wake mutant did not compile"
            case, _ = wfi_case(1, 0, 0)
            case.enable_m = manifest["parameters"].get("enableM", False)
            case.enable_c = manifest["parameters"].get("enableC", False)
            image, schedule = negative / "image.hex", negative / "schedule.txt"
            image.write_text("".join(f"{address:08x} {word:08x}\n" for address, word in sorted(case.words().items())))
            schedule.write_text("".join(" ".join(map(str, entry)) + "\n" for entry in case.interrupt_schedule))
            bad_run = [str(work / "bad-obj/VDitDahE2"), str(image.resolve()), "0", "0", str(1 << 32), str(1 << 32),
                       "512", str(case.completion_pc), str(schedule.resolve()), "--observe-sleep"]
            result = subprocess.run(bad_run, capture_output=True, text=True)
            (negative / "execution.trace").write_text(result.stdout)
            (negative / "stderr.txt").write_text(result.stderr)
            assert result.returncode == 0, "Wake mutant failed before the architectural check"
            reason = reject(lambda: sleep_observations(case, result.stdout, True), "Sleep state differs")
            report["negativeControls"].append({"name": "masked-wake", "group": "wfi", "kind": "rtl", "reason": reason,
                "buildExitStatus": build.returncode, "harnessExitStatus": result.returncode,
                "rtlHashes": {name: digest(negative / name) for name in manifest["rtlHashes"]},
                "traceHash": digest(negative / "execution.trace"), "imageHash": digest(image), "scheduleHash": digest(schedule),
                "command": [part.replace(str(Path.cwd()), "<source>").replace(str(work), "<work>") for part in bad_run]})
            save()
    assert inputs == checker_inputs() | {"test/interrupt_stress.py": digest(Path(__file__)),
        "test/test_interrupt_stress.py": digest(Path("test/test_interrupt_stress.py")), "test/pmp.py": digest(Path("test/pmp.py"))}, "Stress checker inputs changed"
    assert manifest["sourceHashes"] == sources(), "RTL source inputs changed"
    assert all(digest(args.rtl / name) == value for name, value in manifest["rtlHashes"].items()), "RTL inputs changed"
    assert all(digest(path) == report["toolHashes"][name] for name, path in tools.items()), "Tools changed"
    report["coverage"] = {**coverage(report["runs"], groups, timings, seeds), "calibrations": len(report["calibrations"])}
    report["exitStatus"] = 0
    save()
    print(f"PASS: {len(report['runs'])} checked executions and bounded observations", flush=True)


if __name__ == "__main__":
    main()
