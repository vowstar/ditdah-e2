# SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
# SPDX-License-Identifier: MIT
"""Exercise CPU fault precision and instruction synchronization with AXI overlap."""

import argparse
from collections import Counter, deque
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "scripts"))
from build_rtl import digest
from build_software import tool
from test.common.model import Model
from test.programs.programs import constant, csr, immediate, jump, store
from test.test_platform.verify_platform import observer, verify_platform_inputs


def workloads(parameters, regions):
    reset, ram = parameters["resetVector"], regions["sram"]["base"]
    done, handler, signature, bad = reset + 0x180, reset + 0x100, ram + 0x500, ram + 0x400
    result = []

    def put(words, at, code):
        words.update((at + 4 * index, word) for index, word in enumerate(code))

    for write in (False, True):
        code = constant(1, bad) + [immediate(2, 0, 55)] + constant(3, handler) + [csr(0, 0x305, 3, 1)]
        fault_pc = reset + len(code) * 4
        code += [store(2, 1) if write else immediate(4, 1, 0, 3, 2),
                 immediate(5, 0, 99), store(5, 1, 4)]
        words = {done: 0x10500073, bad: 0x11223344, bad + 4: 0}
        put(words, reset, code)
        trap_code = [csr(5, 0x342), csr(6, 0x341), csr(7, 0x343)] + constant(8, signature)
        trap_code += [store(5, 8), store(6, 8, 4), store(7, 8, 8), immediate(9, 0, 77), store(9, 8, 12)]
        trap_code += [jump(0, done - handler - len(trap_code) * 4)]
        put(words, handler, trap_code)
        result.append({"name": "store_fault" if write else "load_fault", "words": words,
                       "done": done, "dataFault": bad, "instructionFault": fault_pc + 8,
                       "slowInstruction": fault_pc + 8,
                       "faultPc": fault_pc, "signature": signature,
                       "expected": {bad: 0x11223344, bad + 4: 0, signature: 7 if write else 5,
                                    signature + 4: fault_pc, signature + 8: bad, signature + 12: 77}})

    start = ram + 0x1000
    target = start + 9 * 4
    new_word = immediate(5, 0, 2)
    code = constant(4, signature) + constant(1, target) + constant(2, new_word)
    code += [store(2, 1), 0x0FF0000F, 0x0000100F, immediate(5, 0, 1), store(5, 4),
             immediate(10, 4, 0, 3, 2), store(10, 4, 4)] + constant(6, done) + [immediate(0, 6, 0, 0x67)]
    words = {done: 0x10500073}
    put(words, reset, constant(1, start) + [immediate(0, 1, 0, 0x67)])
    put(words, start, code)
    result.append({"name": "fence_i", "words": words, "done": done, "dataFault": 0xFFFFFFFF,
                   "instructionFault": 0xFFFFFFFF, "target": target, "signature": signature,
                   "slowInstruction": target,
                   "fencePc": start + 8 * 4,
                   "expected": {target: new_word, signature: 2, signature + 4: 2}})
    return result


def check(trace, case, parameters):
    model = Model(case["words"], parameters["resetVector"], case["instructionFault"], case["dataFault"],
                  enable_m=parameters["enableM"], enable_c=parameters["enableC"])
    memory = dict(case["words"])
    native, completed, responses, reads, writes = {}, deque(), {}, deque(), {}
    counts, traps, groups, observed = Counter(), [], [], {}
    first_write = None
    for line in trace.splitlines():
        fields = line.split()
        if fields[0] == "T":
            assert int(fields[1]) == len(groups), "Missing ordering clock"
            groups.append([])
        elif fields[0] == "W":
            at, value = map(int, fields[1:])
            assert at not in observed, "Duplicate final word"
            observed[at] = value
        elif fields[0] == "F":
            assert int(fields[1]) == len(groups), "Invalid completion clock"
            counts["finished"] += 1
        else:
            assert fields[0] in ("Q", "S", "A", "R") and int(fields[1]) == len(groups) - 1
            groups[-1].append(fields)
    target_reads, target_responses = [], []
    data_finish, fault_response, trap_cycle, fence_cycle = None, None, None, None
    order = {"A": 0, "S": 1, "Q": 2, "R": 3}
    for cycle, events in enumerate(groups):
        model.clock(cycle, 0)
        for fields in sorted(events, key=lambda row: order[row[0]]):
            kind = fields[0]
            if kind == "Q":
                port, request = fields[2], tuple(map(int, fields[3:]))
                assert port not in native and len(request) == 6, "Native owner overwritten"
                assert request[5] == 1 and request[0] % 4 == 0 and request[4] == 2
                assert request[3] == (15 if request[1] else 0), "Native mask differs"
                if port == "I":
                    assert request[1:5] == (0, 0, 0, 2), "Instruction request has side effects"
                native[port] = (cycle, request)
            elif kind == "S":
                port, value = fields[2], tuple(map(int, fields[3:]))
                accepted, request = native.pop(port)
                assert accepted < cycle and responses.pop(port) == value, "Native completion differs from AXI"
                if port == "D":
                    completed.append((request, value))
                    if request[0] == case["dataFault"]:
                        data_finish = cycle
            elif kind == "A":
                channel, value = fields[2], tuple(map(int, fields[3:]))
                if channel == "AR":
                    at, protection = value
                    port = "I" if protection & 4 else "D"
                    assert protection == (5 if port == "I" else 1), "AXI read protection differs"
                    request = native[port][1]
                    assert request[0] == at and not request[1], "AXI read differs from native request"
                    assert not any(read[0] == port for read in reads), "Duplicate issued native read"
                    fault = at == case["instructionFault" if port == "I" else "dataFault"]
                    data = memory.setdefault(at, 0)
                    reads.append((port, at, data, 3 if fault else 0))
                    assert len(reads) <= 2, "Read credit overflow"
                    counts["twoReads"] += len(reads) == 2
                    if port == "I" and at == case.get("target"):
                        target_reads.append((cycle, data))
                    if port == "I" and fault:
                        counts["youngerFaultIssued"] += 1
                        counts["youngerFaultDuringData"] += "D" in native
                elif channel in ("AW", "W"):
                    assert channel not in writes and native["D"][1][1], "Write association differs"
                    request = native["D"][1]
                    assert value == ((request[0], 1) if channel == "AW" else (request[2], request[3]))
                    writes[channel] = value
                    if len(writes) == 1:
                        first_write = channel, cycle
                    else:
                        first, accepted = first_write
                        counts["awTogether" if accepted == cycle else "awFirst" if first == "AW" else "wFirst"] += 1
                elif channel == "R":
                    port, at, data, response = reads.popleft()
                    assert value == (data, response), "AXI read changed its accepted snapshot"
                    assert port not in responses, "Duplicate native response"
                    responses[port] = (data, int(response != 0))
                    counts["readDuringWrite"] += bool(writes)
                    if port == "I" and at == case["instructionFault"]:
                        fault_response = cycle
                    if port == "I" and at == case.get("target"):
                        target_responses.append((cycle, data))
                        counts["staleTargetAfterWrite"] += data != memory[at]
                elif channel == "B":
                    assert set(writes) == {"AW", "W"}, "Write response preceded independent AW/W"
                    at = writes["AW"][0]
                    fault = at == case["dataFault"]
                    assert value == (2 if fault else 0,), "AXI write fault differs"
                    data, mask = writes["W"]
                    old = memory.setdefault(at, 0)
                    if not fault:
                        for lane in range(4):
                            if mask >> lane & 1:
                                old = (old & ~(255 << (8 * lane))) | (data & (255 << (8 * lane)))
                        memory[at] = old
                    responses["D"] = (0, int(fault))
                    writes.clear()
                    if at == case.get("target"):
                        counts["staleTargetBeforeWrite"] += any(data != memory[at] for _, data in target_reads)
                else:
                    raise AssertionError("Unknown AXI channel")
            elif kind == "R":
                pc, word, next_pc, rd, writes_register, value, trap, cause, tval = map(int, fields[2:])
                expected = model.step()
                assert (pc, word, next_pc, bool(trap)) == (expected.pc, expected.word, expected.next_pc, expected.trap), "Architectural order differs"
                assert (bool(writes_register), value) == (bool(expected.rd), expected.value), "Register result differs"
                assert not writes_register or rd == expected.rd
                if trap:
                    assert (cause, tval) == (expected.cause, expected.tval), "Precise fault metadata differs"
                    traps.append((pc, cause, tval))
                    trap_cycle = cycle
                if expected.memory:
                    request, response = completed.popleft()
                    assert request[:5] == expected.memory, "Retired memory instruction differs"
                    assert response[1] == int(request[0] == case["dataFault"])
                else:
                    assert not completed, "Data response lacks its retiring instruction"
                counts[expected.instruction] += 1
                counts["done"] += pc == case["done"]
                if pc == case.get("fencePc"):
                    fence_cycle = cycle
        counts["nativeOverlap"] += set(native) == {"I", "D"}
    assert counts["finished"] == 1 and counts["done"] and not native and not reads and not responses and not writes and not completed
    assert observed == memory, "Final byte memory differs from endpoint model"
    assert all(value == model.word(at) for at, value in observed.items()), "Final memory differs from architectural model"
    assert all(observed[at] == value for at, value in case["expected"].items()), "Ordering signature differs"
    assert counts["nativeOverlap"], "No real CPU instruction/data overlap"
    if case["name"] == "fence_i":
        assert not traps and counts["fence"] == 1 and counts["fence.i"] == 1
        assert counts["staleTargetBeforeWrite"] and counts["readDuringWrite"], "Missing stale prefetch/write overlap"
        assert len(target_reads) == len(target_responses) == 2
        assert target_responses[0][0] < fence_cycle < target_reads[1][0], "FENCE.I did not drain and restart fetch"
    else:
        assert traps == [(case["faultPc"], 7 if case["name"] == "store_fault" else 5, case["dataFault"])], "Younger fetch fault escaped cancellation"
        assert counts["youngerFaultIssued"] and counts["youngerFaultDuringData"] and fault_response is not None
        assert data_finish == trap_cycle, "Data fault did not retire at actual response"
        counts["youngerFaultAfterTrap" if fault_response > trap_cycle else "youngerFaultBeforeTrap"] += 1
        if case["name"] == "load_fault":
            assert counts["twoReads"], "No instruction/data read overlap"
    return dict(sorted(counts.items()))


def compile_sim(directory, platform, manifest, harness):
    directory.mkdir(parents=True, exist_ok=True)
    wrapper = directory / "PlatformBench.sv"
    wrapper.write_text(observer(platform / "rtl"))
    command = ["verilator", "--cc", "--exe", "--build", "-j", "2", "--top-module", "PlatformBench",
               "--Mdir", str((directory / "obj").resolve()), "-CFLAGS", "-std=c++17", str(wrapper.resolve()),
               *[str((platform / "rtl" / name).resolve()) for name in manifest["rtlHashes"]], str(harness.resolve())]
    compiled = subprocess.run(command, capture_output=True, text=True)
    (directory / "compile.log").write_text(compiled.stdout + compiled.stderr)
    assert compiled.returncode == 0, "Ordering simulation did not compile"
    return {"argv": command, "exitStatus": compiled.returncode}


def suppress_data_fault(content):
    # Follow the trap cone through CSE aliases, preserving unrelated fault uses.
    clean = re.sub(r"//[^\n]*|/\*.*?\*/", lambda match: re.sub(r"[^\n]", " ", match[0]), content, flags=re.S)
    definitions = {}
    for match in re.finditer(r"\b(?:wire|assign)\s+(?:\[[^\]]+\]\s+)?([A-Za-z_]\w*)\s*=\s*([^;]+);", clean):
        definitions.setdefault(match[1], []).append((match[2], match.start(2)))
    assert "trap" in definitions, "Missing trap definition for data fault mutation"
    pending, visited, candidates = ["trap"], set(), []
    while pending:
        name = pending.pop()
        if name in visited or name not in definitions:
            continue
        visited.add(name)
        drivers = definitions[name]
        assert len(drivers) == 1, "Ambiguous combinational driver in data fault mutation"
        expression, start = drivers[0]
        for token in re.finditer(r"\b[A-Za-z_]\w*\b", expression):
            if token[0] == "data_response_bits_fault":
                candidates.append((start + token.start(), start + token.end()))
            else:
                pending.append(token[0])
    assert len(candidates) == 1, "Data fault mutation no longer matches RTL"
    start, end = candidates[0]
    return content[:start] + "1'h0" + content[end:]


def fault_suppression_witness(trace, case):
    pending, completions, retirements = None, [], []
    for line in trace.splitlines():
        fields = line.split()
        if fields[:1] == ["Q"] and fields[2] == "D":
            assert pending is None, "Overlapping mutant data owners"
            pending = int(fields[3])
        elif fields[:1] == ["S"] and fields[2] == "D":
            assert pending is not None, "Mutant data response lacks an owner"
            if pending == case["dataFault"]:
                assert int(fields[4]) == 1, "Mutant did not receive the injected data fault"
                completions.append(int(fields[1]))
            pending = None
        elif fields[:1] == ["R"] and int(fields[2]) == case["faultPc"]:
            assert int(fields[3]) == case["words"][case["faultPc"]], "Mutant retired another instruction"
            assert int(fields[8]) == 0, "Mutant did not suppress the architectural data fault"
            retirements.append(int(fields[1]))
    assert len(completions) == len(retirements) == 1 and completions == retirements, \
        "Data fault suppression lacks a matching native completion and retirement"
    return {"pc": case["faultPc"], "responseCycle": completions[0], "retireCycle": retirements[0]}


def suppress_fence_pause(content):
    clean = re.sub(r"//[^\n]*|/\*.*?\*/", lambda match: re.sub(r"[^\n]", " ", match[0]), content, flags=re.S)
    instances = list(re.finditer(r"\bDitDahE2Fetch\s+fetch\s*\(", clean))
    assert len(instances) == 1, "Missing or ambiguous fetch instance for fence mutation"
    start, depth = instances[0].end(), 1
    end = start
    while end < len(clean) and depth:
        depth += (clean[end] == "(") - (clean[end] == ")")
        end += 1
    assert depth == 0, "Unclosed fetch instance for fence mutation"
    pauses = list(re.finditer(r"\.pause\s*\(", clean[start:end - 1]))
    assert len(pauses) == 1, "Missing or ambiguous fetch pause for fence mutation"
    begin = start + pauses[0].end()
    finish, depth = begin, 1
    while finish < end - 1 and depth:
        depth += (clean[finish] == "(") - (clean[finish] == ")")
        finish += 1
    assert depth == 0, "Unclosed fetch pause for fence mutation"
    drivers = {}
    for match in re.finditer(r"\b(?:wire|assign)\s+(?:\[[^\]]+\]\s+)?([A-Za-z_]\w*)\s*=\s*([^;]+);", clean):
        drivers.setdefault(match[1], []).append(match[2])
    factors = [r"advance\s*&\s*isFenceI"]
    for name, expressions in drivers.items():
        if any(re.fullmatch(factors[0], expression.strip()) for expression in expressions):
            assert len(expressions) == 1, "Ambiguous fence alias driver"
            factors.append(re.escape(name))
    pattern = r"\b(?:" + "|".join(factors) + r")\s*&\s*~fault\b"
    targets = []
    for clause in re.finditer(r"[^|]+", clean[begin:finish - 1]):
        if re.fullmatch(pattern, clause[0].strip()):
            target = re.search(pattern, clause[0])
            targets.append((clause.start() + target.start(), clause.start() + target.end()))
    assert len(targets) == 1, "Fence pause mutation no longer matches RTL"
    first, last = targets[0]
    return content[:begin + first] + "1'h0" + content[begin + last:]


def mutate(content, name):
    if name == "ignored-data-fault":
        return suppress_data_fault(content)
    assert name == "fence-i-as-nop"
    assert content.count("m_fenceI <= isFenceI;") == 1, "Fence state mutation no longer matches RTL"
    content = content.replace("m_fenceI <= isFenceI;", "m_fenceI <= 1'h0;")
    return suppress_fence_pause(content)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--platform", type=Path, default=Path("result/platform"))
    parser.add_argument("--output", type=Path, default=Path("result/axi-ordering"))
    args = parser.parse_args()
    if args.output.exists() and any(args.output.iterdir()):
        raise ValueError("Ordering output directory must be empty")
    manifest = json.loads((args.platform / "manifest.json").read_text())
    verify_platform_inputs(args.platform, manifest)
    parameters = manifest["parameters"]["core"]
    assert manifest["exitStatus"] == 0 and manifest["top"] == "DitDahE2PlatformTop"
    assert not any(parameters.get(name) for name in ("protectedMode", "enableA", "enableDebug"))
    assert all(region.get("backend", "axi") == "axi" for region in manifest["regions"].values())
    args.output.mkdir(parents=True)
    shutil.copytree(args.platform, args.output / "platform")
    for name in ("test/test_platform/axi_ordering.py", "test/test_platform/axi_ordering_sim.cpp",
                 "test/test_platform/verify_platform.py", "test/common/model.py", "test/common/bit_model.py",
                 "test/common/compressed_model.py", "test/units/compressed_unit.py", "test/programs/programs.py",
                 "test/test_platform/console.py", "test/test_platform/timer.py", "test/common/elf.py",
                 "scripts/build_rtl.py", "scripts/build_software.py", "scripts/build_platform_block.py"):
        destination = args.output / "inputs" / name
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / name, destination)
    harness = args.output / "inputs/test/test_platform/axi_ordering_sim.cpp"
    commands = [compile_sim(args.output, args.output / "platform", manifest, harness)]
    runs, controls, images = [], [], {}
    cases = workloads(parameters, manifest["regions"])
    for case in cases:
        image = args.output / (case["name"] + ".hex")
        image.write_text(" ".join(f"{case[name]:x}" for name in ("done", "dataFault", "instructionFault", "slowInstruction")) + "\n" +
                         "".join(f"{at:08x} {value:08x}\n" for at, value in sorted(case["words"].items())))
        images[case["name"]] = {"hash": digest(image), "configuration": {key: value for key, value in case.items() if key != "words"}}
        for schedule in range(3):
            command = [str((args.output / "obj/VPlatformBench").resolve()), str(image.resolve()), str(schedule)]
            run = subprocess.run(command, capture_output=True, text=True)
            commands.append({"argv": command, "exitStatus": run.returncode})
            trace = args.output / f"{case['name']}-{schedule}.trace"
            trace.write_text(run.stdout)
            assert run.returncode == 0, run.stderr
            counts = check(run.stdout, case, parameters)
            runs.append({"case": case["name"], "schedule": schedule, "counts": counts, "traceHash": digest(trace)})
            # One incorrect architectural result must invalidate a real accepted trace.
            lines = run.stdout.splitlines()
            witness = next(index for index, line in enumerate(lines) if line.startswith("R ") and int(line.split()[6]))
            fields = lines[witness].split()
            fields[7] = str(int(fields[7]) ^ 1)
            lines[witness] = " ".join(fields)
            try:
                check("\n".join(lines), case, parameters)
            except AssertionError as error:
                controls.append({"case": case["name"], "schedule": schedule, "result": "rejected", "diagnostic": str(error)})
            else:
                raise AssertionError("Ordering checker accepted a corrupted register result")
    assert any(run["counts"].get("youngerFaultAfterTrap") for run in runs)
    assert any(run["counts"].get("youngerFaultBeforeTrap") for run in runs)
    assert any(run["counts"].get("staleTargetAfterWrite") for run in runs)
    assert any(run["counts"].get("awFirst") for run in runs) and any(run["counts"].get("wFirst") for run in runs)
    rtl_controls = []
    for name, case_name in (("ignored-data-fault", "load_fault"), ("fence-i-as-nop", "fence_i")):
        directory = args.output / "negative-controls" / name
        platform = directory / "platform"
        shutil.copytree(args.output / "platform/rtl", platform / "rtl")
        source = platform / "rtl/DitDahE2.sv"
        source.write_text(mutate(source.read_text(), name))
        commands.append(compile_sim(directory, platform, manifest, harness))
        command = [str((directory / "obj/VPlatformBench").resolve()), str((args.output / f"{case_name}.hex").resolve()), "0"]
        run = subprocess.run(command, capture_output=True, text=True)
        commands.append({"argv": command, "exitStatus": run.returncode})
        (directory / "mutant.trace").write_text(run.stdout)
        assert run.returncode == 0, "Mutated workload did not complete for architectural checking"
        case = next(case for case in cases if case["name"] == case_name)
        witness = fault_suppression_witness(run.stdout, case) if name == "ignored-data-fault" else None
        try:
            check(run.stdout, case, parameters)
        except AssertionError as error:
            rtl_controls.append({"name": name, "result": "rejected", "diagnostic": str(error),
                                 **({"faultSuppressionWitness": witness} if witness else {}),
                                 "mutantHash": digest(source), "traceHash": digest(directory / "mutant.trace")})
        else:
            raise AssertionError("Ordering checker accepted a semantic RTL mutation")
    commands = [{**command, "argv": [item.replace(str(args.output.resolve()), "<output>") for item in command["argv"]]}
                for command in commands]
    record = {"scope": "Directed CPU/AXI ordering simulation, not an unbounded CPU proof", "exitStatus": 0,
              "platformManifestHash": digest(args.output / "platform/manifest.json"),
              "inputHashes": {str(path.relative_to(args.output / "inputs")): digest(path)
                              for path in (args.output / "inputs").rglob("*") if path.is_file()},
              "tools": {name: tool(name)[1] for name in ("verilator", "g++", "make")},
              "commands": commands, "images": images, "runs": runs, "negativeControls": controls,
              "rtlNegativeControls": rtl_controls}
    (args.output / "summary.json").write_text(json.dumps(record, indent=2) + "\n")
    print(f"PASS: {len(runs)} CPU/AXI ordering cases with architectural and byte-memory checks")


if __name__ == "__main__":
    main()
