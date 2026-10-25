# SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
# SPDX-License-Identifier: MIT
"""Execute the platform timer workload against independent device and ISA models."""

import argparse
from collections import Counter, deque
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from build_rtl import digest
from build_software import tool
from console import Reference as ConsoleReference
from elf import Region, load_elf
from model import Model
from timer import expected as timer_expected


def observer(rtl):
    top = (rtl / "DitDahE2PlatformTop.sv").read_text()
    platform = (rtl / "DitDahE2Platform.sv").read_text()
    ports = re.search(r"module DitDahE2PlatformTop\((.*?)\);", top, re.S)
    assert ports, "Missing platform port declarations"
    assert len(re.findall(r"DitDahE2Platform\s+platform\s*\(", top)) == 1
    for module, instance in (("DitDahE2", "core"), ("DitDahE2Console", "console"),
                             ("DitDahE2MachineTimer", "timer")):
        assert len(re.findall(rf"{module}\s+{instance}\s*\(", platform)) == 1, "Changed platform hierarchy"
    declarations, assignments = [], []
    widths = {"request_valid": 1, "request_ready": 1, "request_bits_address": 32,
              "request_bits_write": 1, "request_bits_data": 32, "request_bits_mask": 4,
              "request_bits_size": 2, "response_valid": 1, "response_ready": 1,
              "response_bits_data": 32, "response_bits_fault": 1}
    for group, instance, port in (("i", "core", "instruction"), ("d", "core", "data"),
                                  ("console", "console", "memory"), ("timer", "timer", "memory")):
        for field, width in widths.items():
            name = f"o_{group}_{field}"
            declarations.append(f"output {'[' + str(width - 1) + ':0] ' if width > 1 else ''}{name}")
            assignments.append(f"assign {name} = dut.platform.{instance}.{port}_{field};")
    notice = """// SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
// SPDX-License-Identifier: MIT
"""
    return (notice + "module PlatformBench(" + ports[1] + ",\n" +
            ",\n".join(declarations) + ");\nDitDahE2PlatformTop dut(.*);\n" +
            "\n".join(assignments) + "\nendmodule\n")


def workload(destination, generated, parameters, regions):
    destination.mkdir(parents=True)
    for name in ("start.S", "timer.c"):
        shutil.copyfile(ROOT / "software" / name, destination / name)
    for name in ("platform.h", "memory.ld"):
        shutil.copyfile(generated / name, destination / name)
    linker = (ROOT / "software/link.ld").read_text()
    linker, count = re.subn(r"MEMORY\s*\{[^}]*\}", "INCLUDE memory.ld", linker, count=1)
    assert count == 1, "Missing software memory declaration"
    segments = sorted(((regions["rom"]["base"], "text", 5), (regions["sram"]["base"], "data", 6)))
    phdrs = "PHDRS\n{\n" + "".join(f"    {name} PT_LOAD FLAGS({flags});\n" for _, name, flags in segments) + "}\n"
    linker, count = re.subn(r"PHDRS\s*\{[^}]*\}", lambda _: phdrs, linker, count=1)
    assert count == 1, "Missing software segment declaration"
    (destination / "link.ld").write_text(re.sub(r"\bRAM\b", "SRAM", linker))
    cc, compiler = tool("riscv32-none-elf-gcc")
    objdump, disassembler = tool("riscv32-none-elf-objdump")
    isa = "rv32i" + ("m" if parameters["enableM"] else "") + ("c" if parameters["enableC"] else "") + "_zicsr_zifencei"
    command = [str(cc), "-Os", "-std=c11", f"-march={isa}", "-mabi=ilp32", "-mno-relax",
               "-msmall-data-limit=0", "-ffreestanding", "-fno-builtin", "-fno-pic", "-fno-pie",
               "-fno-ident", "-nostdlib", "-nostartfiles", "-static", "-Wl,--build-id=none",
               "-Wl,--no-relax", f"-Wl,--defsym=__reset_vector={parameters['resetVector']}",
               "-T", "link.ld", "start.S", "timer.c", "-o", "program.elf"]
    environment = dict(os.environ, SOURCE_DATE_EPOCH="0", LC_ALL="C")
    result = subprocess.run(command, cwd=destination, env=environment, capture_output=True, text=True)
    (destination / "compile.log").write_text(result.stdout + result.stderr)
    assert result.returncode == 0, "Timer workload did not compile"
    listing = subprocess.check_output([str(objdump), "-d", "-M", "no-aliases", "program.elf"],
                                      cwd=destination, env=environment, text=True)
    (destination / "program.dis").write_text(listing)
    memory_regions = tuple(Region(name, regions[name]["base"], regions[name]["size"], flags)
                           for name, flags in (("rom", 5), ("sram", 7)))
    image = load_elf(destination / "program.elf", reset_vector=parameters["resetVector"],
                     regions=memory_regions, enable_c=parameters["enableC"])
    for symbol in ("software_done", "timer_events", "timer_errors", "timer_observations"):
        assert symbol in image.symbols, "Missing timer workload symbol"
    assert image.words()[image.symbols["software_done"]] == 0x6F
    record = {"isa": isa, "command": [compiler["name"], *command[1:]], "exitStatus": 0,
              "tools": {"compiler": compiler, "objdump": disassembler},
              "artifactHashes": {name: digest(destination / name) for name in ("program.elf", "program.dis")}}
    (destination / "manifest.json").write_text(json.dumps(record, indent=2) + "\n")
    return image, record


def cycles(trace):
    groups, words, total = [], {}, None
    for line in trace.splitlines():
        fields = line.split()
        assert fields, "Empty platform record"
        kind = fields[0]
        if kind == "T":
            assert total is None and int(fields[1]) == len(groups), "Missing platform clock"
            assert len(fields) == 8, "Invalid platform inputs"
            groups.append([fields])
        elif kind == "F":
            assert len(fields) == 2 and total is None and int(fields[1]) == len(groups), "Invalid platform completion count"
            total = int(fields[1])
        elif kind == "W":
            assert total is not None and len(fields) == 3
            address, value = map(int, fields[1:])
            assert address not in words, "Duplicate final memory word"
            words[address] = value
        else:
            assert kind in ("Q", "S", "A", "X", "R", "N") and total is None
            assert groups and int(fields[1]) == len(groups) - 1, "Event has no clock record"
            if kind in ("R", "N"):
                assert not any(item[0] in ("R", "N") for item in groups[-1]), "Multiple architectural events in one cycle"
            groups[-1].append(fields)
    assert total and words, "Missing platform completion"
    return groups, words


def device_expectations(groups):
    rows, console_rows = [(1, 0, 0, 0, 0, 0, 0, 0, 2)], []
    for group in groups:
        _, cycle, tick, tx_ready, *_ = map(int, ("0", *group[0][1:]))
        assert tick == int(cycle % 100 == 99), "Timer tick differs from declared divider"
        requests, responses = {}, {}
        for fields in group[1:]:
            if fields[0] in ("Q", "S") and fields[2] in ("C", "T"):
                target = requests if fields[0] == "Q" else responses
                assert fields[2] not in target, "Duplicate device event"
                target[fields[2]] = tuple(map(int, fields[3:]))
        rows.append((0, tick, int("T" in requests), int("T" in responses),
                     *requests.get("T", (0, 0, 0, 0, 2))))
        console_rows.append((0, int("C" in requests), int("C" in responses), tx_ready,
                             *requests.get("C", (0, 0, 0, 0, 2))))
    timer, timer_counts = timer_expected(rows)
    console = ConsoleReference()
    expected_responses = {}
    for cycle, group in enumerate(groups):
        state = timer[cycle]
        _, _, _, tx_ready, time, timer_irq, software_irq, _ = group[0]
        assert (int(time), int(timer_irq), int(software_irq)) == state[5:], "Timer state or interrupt differs"
        console_state = console.step(console_rows[cycle], cycle)
        wanted_bytes = [console_state[6]] if console_state[5] and int(tx_ready) else []
        actual_bytes = [int(fields[2]) for fields in group if fields[0] == "X"]
        assert actual_bytes == wanted_bytes, "Console transfer differs from accepted writes"
        for fields in group:
            if fields[0] == "S" and fields[2] in ("C", "T"):
                wanted = state if fields[2] == "T" else console_state
                assert wanted[2] and tuple(map(int, fields[3:])) == wanted[3:5], "Device response differs"
                expected_responses[cycle, fields[2]] = wanted[3:5]
    assert not console.owner and not timer[-1][2], "Device did not drain"
    assert bytes(console.bytes) == b"E23\n", "Timer workload output differs"
    return timer, expected_responses, timer_counts, console.counts


def check(image, parameters, regions, trace):
    groups, observed = cycles(trace)
    timer, device_results, timer_counts, console_counts = device_expectations(groups)
    model = Model(image.words(), image.entry, enable_m=parameters["enableM"], enable_c=parameters["enableC"])
    outstanding, issued, external_results = {}, {}, {}
    completed = deque()
    instructions = Counter()
    memory_addresses = set(image.words())
    interrupts, completion, memory_count, sleep = 0, None, 0, 0
    writes = {}

    def region_at(address):
        return next((name for name, entry in regions.items()
                     if entry["base"] <= address < entry["base"] + entry["size"]), None)

    for cycle, group in enumerate(groups):
        assert int(group[0][7]) == int(model.sleeping), "Sleep state differs from retired WFI"
        sleep += model.sleeping
        model.clock(cycle, timer[cycle][7] | (timer[cycle][6] << 1))
        model.time = timer[cycle][5]
        for fields in group[1:]:
            kind = fields[0]
            if kind == "Q":
                port, request = fields[2], tuple(map(int, fields[3:]))
                assert port in ("I", "D", "C", "T"), "Unknown native port"
                assert port not in outstanding, "Native request overwrote its owner"
                outstanding[port] = (cycle, request)
                if port in ("C", "T"):
                    assert "D" in outstanding and outstanding["D"][0] == cycle
                    original = outstanding["D"][1]
                    name = "console" if port == "C" else "timer"
                    assert region_at(original[0]) == name and request == (
                        original[0] - regions[name]["base"], *original[1:]), "Device route differs"
                elif port == "I":
                    assert region_at(request[0]) in ("rom", "sram")
                    assert request[1:] == (0, 0, 0, 2) and request[0] % 4 == 0
                else:
                    address, write, data, mask, size = request
                    assert size <= 2 and not address % (1 << size)
                    assert mask == (((1 << (1 << size)) - 1) << (address % 4) if write else 0)
                    assert region_at(address) in ("sram", "console", "timer", "rom")
                    assert not write or region_at(address) != "rom"
                    assert region_at(address) not in ("console", "timer") or size == 2
            elif kind == "S":
                port, response = fields[2], tuple(map(int, fields[3:]))
                start, request = outstanding.pop(port)
                assert start < cycle, "Native response preceded acceptance"
                if port in ("I", "D"):
                    name = region_at(request[0])
                    if name in ("rom", "sram"):
                        assert external_results.pop(port) == response, "Native response differs from AXI"
                    else:
                        endpoint = "C" if name == "console" else "T"
                        assert device_results[cycle, endpoint] == response, "Native response differs from device"
                    if port == "D":
                        completed.append((request, response))
                        memory_count += 1
                else:
                    assert device_results[cycle, port] == response
            elif kind == "A":
                channel = fields[2]
                value = tuple(map(int, fields[3:]))
                if channel == "AR":
                    address, protection = value
                    memory_addresses.add(address)
                    assert protection in (1, 5)
                    port = "I" if protection == 5 else "D"
                    assert port in outstanding and port not in issued
                    request = outstanding[port][1]
                    assert not request[1] and address == request[0] & ~3
                    assert region_at(address) in ("rom", "sram")
                    issued[port] = ("read", address)
                elif channel in ("AW", "W"):
                    assert channel not in writes and "D" in outstanding
                    request = outstanding["D"][1]
                    assert request[1] and region_at(request[0]) == "sram"
                    assert value == ((request[0] & ~3, 1) if channel == "AW" else (request[2], request[3]))
                    writes[channel] = value
                    if channel == "AW":
                        memory_addresses.add(value[0])
                elif channel == "R":
                    assert len(issued) == 1, "Unowned AXI read response"
                    port = next(iter(issued))
                    _, address = issued.pop(port)
                    assert value == (model.word(address), 0), "AXI memory read differs"
                    external_results[port] = (value[0], 0)
                elif channel == "B":
                    assert set(writes) == {"AW", "W"} and value == (0,), "Invalid AXI write completion"
                    writes.clear()
                    external_results["D"] = (0, 0)
                else:
                    raise AssertionError("Unknown AXI channel")
            elif kind == "R":
                pc, word, next_pc, rd, writes_register, value, trap, cause, tval = map(int, fields[2:])
                if completed:
                    request, response = completed[0]
                    if not request[1] and region_at(request[0]) in ("console", "timer"):
                        for lane in range(4):
                            model.memory[(request[0] & ~3) + lane] = response[0] >> (8 * lane) & 255
                expected = model.step()
                assert (pc, word, next_pc, bool(trap)) == (expected.pc, expected.word, expected.next_pc, expected.trap)
                assert not trap, "Timer workload raised a synchronous exception"
                assert (bool(writes_register), value) == (bool(expected.rd), expected.value)
                assert not writes_register or rd == expected.rd
                instructions[expected.instruction] += 1
                if expected.memory:
                    request, response = completed.popleft()
                    assert (request[:2], request[3:]) == (expected.memory[:2], expected.memory[3:]) and not response[1], "Memory instruction differs"
                    assert not request[1] or request[2] == expected.memory[2], "Store data differs"
                    if not request[1]:
                        assert response[0] == model.word(request[0] & ~3), "Load data differs"
                else:
                    assert not completed, "Data response lacks a memory instruction"
                if pc == image.symbols["software_done"]:
                    assert word == 0x6F and next_pc == pc
                    completion = cycle if completion is None else completion
            elif kind == "N":
                assert "D" not in outstanding and not completed
                assert tuple(map(int, fields[2:])) == model.interrupt(), "Timer interrupt entry differs"
                assert int(fields[4]) == 0x80000007
                interrupts += 1
            elif kind != "X":
                raise AssertionError("Unknown platform event")
    assert completion is not None and len(groups) > completion + 8
    assert not outstanding and not completed and not issued and not external_results and not writes
    assert interrupts == 3 and sleep > 0 and instructions["mret"] == 3
    assert observed.keys() == memory_addresses, "Final memory snapshot is incomplete or has extra words"
    for address, value in observed.items():
        assert value == model.word(address), "Final platform memory differs"
    assert observed[image.symbols["timer_events"]] == 3 and observed[image.symbols["timer_errors"]] == 0
    times = [observed[image.symbols["timer_observations"] + 4 * index] for index in range(3)]
    assert all(later >= earlier + 20 for earlier, later in zip(times, times[1:])), "Timer interrupt interval is too short"
    return {"cycles": len(groups), "interrupts": interrupts, "sleepCycles": sleep,
            "memoryInstructions": memory_count, "instructions": dict(sorted(instructions.items())),
            "timer": timer_counts, "console": console_counts, "observations": times}


def rejected(action):
    try:
        action()
    except AssertionError as error:
        return str(error)
    raise AssertionError("Platform checker accepted an injected error")


def timer_comparator_mutant(content):
    before = "assign timerInterrupt = time_0 >= compare;"
    assert content.count(before) == 1, "Timer comparator mutation no longer matches RTL"
    return content.replace(before, "assign timerInterrupt = time_0 > compare;")


def verify_platform_inputs(directory, manifest):
    bindings = {directory / "manifest.json": digest(directory / "manifest.json")}
    bindings.update({directory / "inputs" / name: value for name, value in manifest["sourceHashes"].items()})
    bindings[directory / "inputs/platform.json"] = manifest["platformHash"]
    for subdir, key in (("rtl", "rtlHashes"), ("inputs/generated", "generatedHashes"), ("", "artifactHashes")):
        bindings.update({directory / subdir / name: value for name, value in manifest[key].items()})
    assert all(path.is_file() and digest(path) == value for path, value in bindings.items()), "Platform inputs differ from their manifest"
    return bindings


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--platform", type=Path, default=Path("result/platform"))
    parser.add_argument("--output", type=Path, default=Path("result/platform-verification"))
    args = parser.parse_args()
    if args.output.exists() and any(args.output.iterdir()):
        raise ValueError("Platform verification output directory must be empty")
    manifest = json.loads((args.platform / "manifest.json").read_text())
    assert manifest["exitStatus"] == 0
    platform_inputs = verify_platform_inputs(args.platform, manifest)
    args.output.mkdir(parents=True, exist_ok=True)
    shutil.copytree(args.platform, args.output / "platform", dirs_exist_ok=True)
    copied_inputs = verify_platform_inputs(args.output / "platform", manifest)
    source_names = ("test/verify_platform.py", "test/test_platform.py", "test/platform_sim.cpp", "test/model.py", "test/compressed_model.py",
                    "test/compressed_unit.py", "test/console.py", "test/timer.py", "test/elf.py",
                    "scripts/build_software.py", "scripts/build_rtl.py", "software/start.S", "software/link.ld", "software/timer.c")
    inputs = {name: (ROOT / name).read_bytes() for name in source_names}
    for name, value in inputs.items():
        path = args.output / "inputs" / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(value)
    parameters, regions = manifest["parameters"]["core"], manifest["regions"]
    image, first = workload(args.output / "software", args.platform, parameters, regions)
    _, second = workload(args.output / "software-repeat", args.platform, parameters, regions)
    assert first == second, "Timer ELF build is not reproducible"
    commands, runs, controls = [], [], []
    tools = {name: tool(name)[1] for name in ("verilator", "g++", "make")}
    scratch = "/data/tmp" if os.access("/data/tmp", os.W_OK) else None
    with tempfile.TemporaryDirectory(prefix="ditdah-e2-platform-sim-", dir=scratch) as directory:
        work = Path(directory)
        def diagnostic(value):
            return value.replace(str(work), "<workspace>").replace(str(args.output.resolve()), "<output>").replace(str(ROOT), "<source>")

        wrapper = observer(args.output / "platform/rtl")
        (work / "PlatformBench.sv").write_text(wrapper)
        (args.output / "PlatformBench.sv").write_text(wrapper)
        command = ["verilator", "--cc", "--exe", "--build", "-j", "2", "--top-module", "PlatformBench",
                   "--Mdir", "obj", "-CFLAGS", "-std=c++17", str(work / "PlatformBench.sv"),
                   *[str((args.output / "platform/rtl" / name).resolve()) for name in manifest["rtlHashes"]],
                   str((args.output / "inputs/test/platform_sim.cpp").resolve())]
        result = subprocess.run(command, cwd=work, capture_output=True, text=True)
        (args.output / "compile.log").write_text(diagnostic(result.stdout + result.stderr))
        assert result.returncode == 0, "Platform simulation did not compile"
        commands.append({"argv": [diagnostic(item) for item in command], "exitStatus": 0})
        (work / "image.hex").write_text(" ".join(f"{regions[name][field]:x}" for name in ("rom", "sram")
                                                for field in ("base", "size")) + "\n" +
                                       "".join(f"{address:08x} {value:08x}\n" for address, value in sorted(image.words().items())))
        shutil.copyfile(work / "image.hex", args.output / "image.hex")
        for seed, delay in ((0, 0), (1, 9), (19, 24)):
            command = [str(work / "obj/VPlatformBench"), "image.hex", str(seed), str(delay),
                       str(image.symbols["software_done"])]
            result = subprocess.run(command, cwd=work, capture_output=True, text=True)
            commands.append({"argv": [diagnostic(item) for item in command], "exitStatus": result.returncode})
            name = f"timer-s{seed}-d{delay}"
            (args.output / f"{name}.trace").write_text(result.stdout)
            (args.output / f"{name}.log").write_text(result.stderr)
            assert result.returncode == 0, "Platform simulation did not complete"
            metrics = check(image, parameters, regions, result.stdout)
            runs.append({"seed": seed, "delay": delay, "exitStatus": 0, **metrics,
                         "traceHash": hashlib.sha256(result.stdout.encode()).hexdigest()})
            if seed == 0:
                for kind in ("console", "interrupt", "timer-read"):
                    lines = result.stdout.splitlines()
                    prefix = "X " if kind == "console" else "N " if kind == "interrupt" else "S "
                    index = next(index for index, line in enumerate(lines) if line.startswith(prefix)
                                 and (kind != "timer-read" or line.split()[2] == "T"))
                    if kind == "console":
                        del lines[index]
                    else:
                        fields = lines[index].split()
                        field = 4 if kind == "interrupt" else 3
                        fields[field] = str(int(fields[field]) ^ 1)
                        lines[index] = " ".join(fields)
                    changed = "\n".join(lines) + "\n"
                    (args.output / f"negative-{kind}.trace").write_text(changed)
                    reason = rejected(lambda: check(image, parameters, regions, changed))
                    controls.append({"name": kind, "kind": "trace", "reason": reason,
                                     "traceHash": hashlib.sha256(changed.encode()).hexdigest()})
        original = (args.output / "platform/rtl/DitDahE2MachineTimer.sv").resolve()
        mutant = timer_comparator_mutant(original.read_text())
        (work / original.name).write_text(mutant)
        (args.output / "timer-mutant.sv").write_text(mutant)
        negative_command = ["verilator", "--cc", "--exe", "--build", "-j", "2", "--top-module", "PlatformBench",
                            "--Mdir", "negative-obj", "-CFLAGS", "-std=c++17", str(work / "PlatformBench.sv"),
                            *[str(work / name) if name == original.name else str((args.output / "platform/rtl" / name).resolve())
                              for name in manifest["rtlHashes"]], str((args.output / "inputs/test/platform_sim.cpp").resolve())]
        result = subprocess.run(negative_command, cwd=work, capture_output=True, text=True)
        (args.output / "compile-negative.log").write_text(diagnostic(result.stdout + result.stderr))
        commands.append({"argv": [diagnostic(item) for item in negative_command], "exitStatus": result.returncode})
        assert result.returncode == 0, "Timer mutant did not compile"
        negative_run = [str(work / "negative-obj/VPlatformBench"), "image.hex", "0", "0", str(image.symbols["software_done"])]
        result = subprocess.run(negative_run, cwd=work, capture_output=True, text=True)
        commands.append({"argv": [diagnostic(item) for item in negative_run], "exitStatus": result.returncode})
        (args.output / "timer-mutant.trace").write_text(result.stdout)
        (args.output / "timer-mutant.log").write_text(result.stderr)
        assert result.returncode == 0, "Timer mutant did not reach checked completion"
        reason = rejected(lambda: check(image, parameters, regions, result.stdout))
        assert reason == "Timer state or interrupt differs", "Timer mutant failed outside its changed contract"
        controls.append({"name": "timer-comparison", "kind": "rtl", "reason": reason,
                         "rtlHash": hashlib.sha256(mutant.encode()).hexdigest(),
                         "traceHash": hashlib.sha256(result.stdout.encode()).hexdigest()})
    assert all((ROOT / name).read_bytes() == value for name, value in inputs.items()), "Platform checker inputs changed"
    assert all(digest(path) == value for path, value in (platform_inputs | copied_inputs).items()), "Platform inputs changed during execution"
    assert tools == {name: tool(name)[1] for name in tools}, "Platform simulation tools changed"
    report = {"scope": "processor, memory routing, AXI, console and three timer interrupts",
              "exitStatus": 0, "parameters": parameters, "regions": regions,
              "platformManifestHash": digest(args.output / "platform/manifest.json"),
              "inputHashes": {name: hashlib.sha256(value).hexdigest() for name, value in inputs.items()},
              "observerHash": digest(args.output / "PlatformBench.sv"), "imageHash": digest(args.output / "image.hex"),
              "software": first, "runs": runs, "commands": commands, "negativeControls": controls, "tools": tools,
              "simulator": subprocess.check_output(["verilator", "--version"], text=True).strip(),
              "simulatorHash": digest(Path(shutil.which("verilator")))}
    (args.output / "summary.json").write_text(json.dumps(report, indent=2) + "\n")
    print(f"PASS: {len(runs)} platform RTL runs with independent device and instruction checks")


if __name__ == "__main__":
    main()
