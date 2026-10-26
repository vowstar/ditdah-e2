# SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
# SPDX-License-Identifier: MIT
"""Compare fixed instruction streams on frozen and current native and AXI designs."""

import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import tempfile

from model import Model


NOTICE = "// SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>\n// SPDX-License-Identifier: MIT\n"
DONE = 0x3000
DEFINITIONS = {
    "window": "Retirements 33 through 288; cycles include both endpoint retirements.",
    "fetchStarvationCycles": "Fetch output ready and not valid, excluding pause and redirect, within the retirement window.",
    "fetchBackpressureCycles": "Fetch output valid and not ready, excluding pause and redirect, within the retirement window.",
    "instructionRequestBlockedCycles": "Native instruction request valid and not ready within the retirement window.",
    "retirementRecoveryCycles": "Taken conditional branch retirement to its next target retirement, for branches within the window.",
    "totalCycles": "All observed cycles, including startup, completion and transaction draining.",
}


def digest(value):
    return hashlib.sha256(value).hexdigest()


def ports(text, module):
    match = re.search(rf"module {module}\((.*?)\);", text, re.S)
    assert match, "Missing module ports"
    result, direction, width = {}, None, ""
    for item in match[1].split(","):
        found = re.fullmatch(r"\s*(?:(input|output)\s*)?(\[\d+:\d+\]\s*)?(\w+)\s*", item)
        assert found, "Unsupported port declaration"
        if found[1]:
            direction, width = found[1], (found[2] or "").strip()
        assert direction and found[3] not in result, "Invalid port list"
        result[found[3]] = (direction, width)
    return result


def wrapper(rtl, transport):
    module = "DitDahE2" if transport == "native" else "DitDahE2PlatformTop"
    declared = ports((rtl / (module + ".sv")).read_text(), module)
    core = "dut" if transport == "native" else "dut.platform.core"
    assert "DitDahE2Fetch fetch (" in (rtl / "DitDahE2.sv").read_text(), "Changed fetch hierarchy"
    if transport == "axi":
        assert "DitDahE2 core (" in (rtl / "DitDahE2Platform.sv").read_text(), "Changed core hierarchy"
    pins = ["input clock", "input reset", "input n_i_ready", "input n_i_valid", "input [31:0] n_i_data",
            "input n_i_fault", "input a_ar_ready", "input a_r_valid", "input [31:0] a_r_data",
            "input [1:0] a_r_response"]
    aliases = {"f_valid": (1, core + ".fetch.output_valid"), "f_ready": (1, core + ".fetch.output_ready"),
               "f_pause": (1, core + ".fetch.pause"), "f_redirect": (1, core + ".fetch.redirect"),
               "f_pc": (32, core + ".fetch.output_bits_pc"), "d_valid": (1, core + ".data_request_valid")}
    core_ports = ports((rtl / "DitDahE2.sv").read_text(), "DitDahE2")
    for short, field, width in (("valid", "request_valid", 1), ("ready", "request_ready", 1),
                                ("address", "request_bits_address", 32), ("write", "request_bits_write", 1),
                                ("data", "request_bits_data", 32), ("mask", "request_bits_mask", 4),
                                ("size", "request_bits_size", 2), ("machine", "request_bits_machine", 1),
                                ("operation", "request_bits_operation", 4), ("rv", "response_valid", 1),
                                ("rr", "response_ready", 1), ("rd", "response_bits_data", 32),
                                ("fault", "response_bits_fault", 1)):
        name = "instruction_" + field
        expression = core + "." + name if name in core_ports else ("1'b1" if short == "machine" else "'0")
        aliases["i_" + short] = width, expression
    for name, width in (("valid", 1), ("pc", 32), ("word", 32), ("nextPc", 32), ("rd", 5),
                        ("writes", 1), ("value", 32), ("trap", 1), ("cause", 32), ("tval", 32), ("userMode", 1)):
        field = "retire_" + name
        aliases[field] = width, core + "." + field if field in core_ports else "'0"
    aliases["interrupt_valid"] = 1, core + ".interrupt_valid"
    for short, field, width in (("ar_valid", "ar_valid", 1), ("ar_address", "ar_bits_address", 32),
                                ("ar_protection", "ar_bits_protection", 3), ("r_ready", "r_ready", 1),
                                ("aw_valid", "aw_valid", 1), ("w_valid", "w_valid", 1)):
        aliases["a_" + short] = width, "raw_axi_" + field if transport == "axi" else "'0"
    for name, (width, _) in aliases.items():
        pins.append(f"output {'[' + str(width - 1) + ':0] ' if width > 1 else ''}{name}")
    driven = {"clock": "clock", "reset": "reset", "instruction_request_ready": "n_i_ready",
              "instruction_response_valid": "n_i_valid", "instruction_response_bits_data": "n_i_data",
              "instruction_response_bits_fault": "n_i_fault", "axi_ar_ready": "a_ar_ready",
              "axi_r_valid": "a_r_valid", "axi_r_bits_data": "a_r_data", "axi_r_bits_response": "a_r_response",
              "transmit_ready": "1'b1"}
    wires, connections = [], []
    for name, (direction, width) in declared.items():
        if direction == "input":
            expression = driven.get(name, "'0")
        else:
            expression = "raw_" + name
            wires.append(f"wire {width} {expression};")
        connections.append(f".{name}({expression})")
    return (NOTICE + "module FetchPerformanceBench(\n" + ",\n".join(pins) + ");\n" + "\n".join(wires) +
            f"\n{module} dut(" + ",\n".join(connections) + ");\n" +
            "\n".join(f"assign {name} = {expression};" for name, (_, expression) in aliases.items()) + "\nendmodule\n")


def workload(name):
    words = {}
    for index in range(320):
        pc = index * (12 if name == "branch" else 4)
        words[pc] = 0x00140413  # ADDI x8, x8, 1.
        if name == "branch":
            words[pc + 4] = 0x00000463  # BEQ x0, x0, 8.
            words[pc + 8] = 0x00148493  # A skipped increment of x9.
    end = 320 * (12 if name == "branch" else 4)
    offset = DONE - end
    words[end] = (((offset >> 20) & 1) << 31 | ((offset >> 1) & 1023) << 21 |
                  ((offset >> 11) & 1) << 20 | ((offset >> 12) & 255) << 12 | 0x6F)
    words[DONE] = 0x6F
    assert name in ("straight", "branch"), "Unknown workload"
    return words


def stable(previous, valid, ready, payload, message):
    assert previous is None or (valid and payload == previous), message
    return payload if valid and not ready else None


def check(words, text, transport, parameters=None):
    parameters = parameters or {}
    model = Model(words, enable_m=parameters.get("enableM", False), enable_c=parameters.get("enableC", False))
    samples, retired, accepted = {}, [], 0
    owner = bus = bus_result = held = response_held = ar_held = axi_response_held = None
    last_cycle, final, completion = -1, None, None
    seen = set()
    for line in text.splitlines():
        fields = line.split()
        assert fields, "Empty trace record"
        tag = fields[0]
        values = list(map(int, fields[1:]))
        assert final is None, "Record after final observation"
        if tag == "T":
            cycle, valid, ready, pause, redirect, pc = values
            assert cycle == last_cycle + 1 and (last_cycle < 0 or {"I", "A"} <= seen), "Missing cycle observation"
            samples[cycle] = (valid, ready, pause, redirect, pc)
            last_cycle, seen = cycle, set()
        elif tag == "F":
            assert len(values) == 1 and values[0] == last_cycle + 1, "Invalid final cycle"
            final = values[0]
        else:
            cycle = values[0]
            assert cycle == last_cycle and tag not in seen, "Duplicate or unclocked trace record"
            seen.add(tag)
            if tag == "I":
                _, valid, ready, address, write, data, mask, size, machine, operation, rv, rr, rd, fault = values
                payload = address, write, data, mask, size, machine, operation
                held = stable(held, valid, ready, payload, "Instruction offer changed while blocked")
                response_held = stable(response_held, rv, rr, (rd, fault), "Instruction response changed while blocked")
                if rv:
                    assert owner is not None and cycle > owner[0], "Instruction response has no earlier owner"
                    assert not fault and rd == words.get(owner[1], 0), "Instruction response differs from memory"
                    if transport == "axi":
                        assert bus_result == (rd, fault), "Native response lacks its AXI result"
                if rv and rr:
                    owner, bus_result = None, None
                if valid and ready:
                    assert owner is None, "Instruction request overwrote an owner"
                    assert (address & 3, write, data, mask, size, machine, operation) == (0, 0, 0, 0, 2, 1, 0), "Invalid instruction request"
                    owner = cycle, address
                    accepted += 1
            elif tag == "A":
                _, av, ar, address, protection, rv, rr, data, response = values
                if transport == "native":
                    assert not av and not rv, "AXI activity in native execution"
                    continue
                ar_held = stable(ar_held, av, ar, (address, protection), "AXI address changed while blocked")
                axi_response_held = stable(axi_response_held, rv, rr, (data, response), "AXI response changed while blocked")
                if rv:
                    assert bus is not None and cycle > bus[0], "AXI response has no earlier owner"
                    assert response == 0 and data == words.get(bus[1], 0), "AXI response differs from memory"
                if rv and rr:
                    bus, bus_result = None, (data, response)
                if av and ar:
                    assert bus is None and bus_result is None and owner is not None, "AXI read ownership mismatch"
                    assert address == owner[1] and protection == 5, "AXI address or attributes differ from native request"
                    bus = cycle, address
            elif tag == "R":
                _, pc, word, next_pc, rd, writes, value, trap, cause, tval, user = values
                expected = model.step()
                assert (pc, word, next_pc, rd if writes else 0, bool(writes), value if writes else 0, bool(trap), bool(user)) == (
                    expected.pc, expected.word, expected.next_pc, expected.rd, bool(expected.rd), expected.value if expected.rd else 0,
                    expected.trap, expected.user_mode), "Retirement differs from independent instruction model"
                assert not trap, "Unexpected trap"
                retired.append((cycle, pc, word, next_pc))
                if pc == DONE and completion is None:
                    completion = len(retired)
            else:
                raise AssertionError("Unknown trace record")
    assert final is not None and completion is not None and {"I", "A"} <= seen, "Incomplete execution"
    assert owner is None and bus is None and bus_result is None, "Accepted request did not drain"
    assert model.registers[8] == 320 and model.registers[9] == 0, "Fixed program signature differs"
    window = retired[32:288]
    assert len(window) == 256 and completion > 288, "Incomplete retirement window"
    first, last = window[0][0], window[-1][0]
    recovery = []
    for index in range(32, 288):
        cycle, pc, word, target = retired[index]
        if word & 0x7F == 0x63 and target != pc + 4:
            following = retired[index + 1]
            assert following[1] == target, "Branch target retirement is missing"
            recovery.append(following[0] - cycle)
    observed = [samples[cycle] for cycle in range(first, last + 1)]
    blocked = 0
    for line in text.splitlines():
        fields = line.split()
        if fields[0] == "I" and first <= int(fields[1]) <= last:
            blocked += int(fields[2]) and not int(fields[3])
    return {"windowRetirements": 256, "windowCycles": last - first + 1,
            "firstRetirementCycle": first, "lastRetirementCycle": last,
            "fetchStarvationCycles": sum(ready and not valid and not pause and not redirect for valid, ready, pause, redirect, _ in observed),
            "fetchBackpressureCycles": sum(valid and not ready and not pause and not redirect for valid, ready, pause, redirect, _ in observed),
            "instructionRequestBlockedCycles": blocked,
            "retirementRecoveryCycles": {str(value): recovery.count(value) for value in sorted(set(recovery))},
            "takenBranchesInWindow": len(recovery), "totalCycles": final,
            "retirementsThroughCompletion": completion, "checkedRetirements": len(retired),
            "acceptedInstructionRequests": accepted, "finalHeldOffer": list(held) if held else None}


def design(manifest_path, rtl, source):
    raw = manifest_path.read_bytes()
    manifest = json.loads(raw)
    params = manifest["parameters"].get("core", manifest["parameters"])
    normalized = {name: params.get(name, default) for name, default in (
        ("resetVector", 0), ("enableM", False), ("enableC", False), ("protectedMode", False),
        ("enableDebug", False), ("enableA", False), ("enableZba", False), ("enableZbb", False), ("enableZbs", False))}
    assert normalized["resetVector"] == 0 and not any(value for name, value in normalized.items()
        if name not in ("enableM", "enableC")), "Performance comparison requires machine mode at zero without optional protection, debug, atomic or bit configuration"
    assert manifest.get("exitStatus") == 0, "Design generation did not pass"
    inputs = {manifest_path: digest(raw)}
    if "platformHash" in manifest:
        path = source / "platform.json"
        assert digest(path.read_bytes()) == manifest["platformHash"], "Platform description changed"
        inputs[path] = manifest["platformHash"]
    for key, base in (("sourceHashes", source), ("rtlHashes", rtl)):
        for name, expected in manifest[key].items():
            path = base / name
            assert digest(path.read_bytes()) == expected, "Frozen design input changed"
            inputs[path] = expected
    return manifest, normalized, inputs


def negative_controls(words, text, transport, parameters=None):
    controls = []
    variants = [("register-value", "R", 7, "Retirement differs"),
                ("response-owner", "I", 11, "earlier owner")]
    if transport == "axi":
        variants.append(("axi-attributes", "A", 5, "attributes"))
    for name, tag, field, expected in variants:
        lines = text.splitlines()
        for index, line in enumerate(lines):
            fields = line.split()
            selected = fields[0] == tag
            if name == "register-value":
                selected = selected and fields[6] == "1"
            if name == "axi-attributes":
                selected = selected and fields[2:4] == ["1", "1"]
            if selected:
                fields[field] = str(int(fields[field]) ^ 1)
                lines[index] = " ".join(fields)
                break
        else:
            raise AssertionError("Missing negative-control witness")
        try:
            check(words, "\n".join(lines), transport, parameters)
        except AssertionError as error:
            assert expected in str(error), "Negative control failed for a different reason"
            controls.append({"name": name, "reason": str(error)})
        else:
            raise AssertionError("Performance checker accepted a corrupted trace")
    return controls


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--current-core", type=Path, required=True)
    parser.add_argument("--current-platform", type=Path, required=True)
    parser.add_argument("--baseline-native", type=Path)
    parser.add_argument("--baseline-platform-root", type=Path)
    parser.add_argument("--source-root", type=Path, default=Path("."))
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--jobs", type=int, default=2)
    args = parser.parse_args()
    output = args.output.resolve()
    assert not output.exists() or not any(output.iterdir()), "Performance output must be empty"
    output.mkdir(parents=True, exist_ok=True)
    assert bool(args.baseline_native) == bool(args.baseline_platform_root), "Supply both frozen baseline directories"
    selected = {("current", "native"): (args.current_core / "manifest.json", args.current_core, args.source_root),
                ("current", "axi"): (args.current_platform / "manifest.json", args.current_platform / "rtl", args.source_root)}
    if args.baseline_native:
        baseline_platform = args.baseline_platform_root / "result/platform/design"
        selected = {("baseline", "native"): (args.baseline_native / "manifest.json", args.baseline_native / "rtl", args.baseline_native / "source"),
                    ("baseline", "axi"): (baseline_platform / "manifest.json", baseline_platform / "rtl", args.baseline_platform_root), **selected}
    frozen, report = {}, {"scope": "Fixed RV32I streams on native and shared AXI memory", "definitions": DEFINITIONS,
                         "runs": [], "comparisons": [], "exitStatus": None}
    prepared = {key: design(*paths) for key, paths in selected.items()}
    configurations = [params for _, params, _ in prepared.values()]
    assert all(value == configurations[0] for value in configurations), "Compared core configurations differ"
    platforms = [{**manifest["parameters"], "core": params}
                 for (_, transport), (manifest, params, _) in prepared.items() if transport == "axi"]
    assert all(value == platforms[0] for value in platforms), "Compared platform configurations differ"
    report["parameters"], report["platformParameters"] = configurations[0], platforms[0]
    for _, _, inputs in prepared.values():
        frozen.update(inputs)
    checker_paths = [Path(__file__), Path(__file__).with_name("fetch_performance_sim.cpp"),
                     *[Path(__file__).with_name(name) for name in ("model.py", "compressed_model.py", "bit_model.py")]]
    for path in checker_paths:
        frozen[path] = digest(path.read_bytes())
    report["checkerHashes"] = {path.name: frozen[path] for path in checker_paths}
    inputs_dir = output / "inputs"
    inputs_dir.mkdir()
    for path in checker_paths:
        (inputs_dir / path.name).write_bytes(path.read_bytes())
    tools = {name: Path(shutil.which(name)).resolve() for name in ("verilator", "verilator_bin", "c++")}
    report["tools"] = {name: {"sha256": digest(path.read_bytes())} for name, path in tools.items()}
    report["tools"]["verilator"]["version"] = subprocess.check_output(["verilator", "--version"], text=True).strip()
    report["tools"]["c++"]["version"] = subprocess.check_output(["c++", "--version"], text=True).splitlines()[0]
    report["limits"] = ["Fixed RV32I workloads at reset address zero. M and C follow the recorded configuration.",
                        "No user mode, debug, atomics, bit extensions, data, device, interrupt or fault traffic.",
                        "Recovery observes retirements. It does not measure fetch delivery latency.",
                        "AXI peer response timing starts at AXI address acceptance, before the platform returns its native response."]
    (output / "summary.json").write_text(json.dumps(report, indent=2) + "\n")
    scratch = Path("/data/tmp")
    with tempfile.TemporaryDirectory(prefix="ditdah-e2-fetch-performance-", dir=scratch if scratch.is_dir() else None) as directory:
        work = Path(directory)
        for (revision, transport), (manifest_path, rtl, source) in selected.items():
            manifest, params, _ = prepared[revision, transport]
            destination = output / revision / transport
            destination.mkdir(parents=True)
            (destination / "manifest.json").write_bytes(manifest_path.read_bytes())
            for name in manifest["rtlHashes"]:
                (destination / name).write_bytes((rtl / name).read_bytes())
            bench = destination / "FetchPerformanceBench.sv"
            bench.write_text(wrapper(rtl, transport))
            harness = destination / "fetch_performance_sim.cpp"
            harness.write_bytes(Path(__file__).with_name(harness.name).read_bytes())
            obj = work / revision / transport
            obj.mkdir(parents=True)
            build_command = ["verilator", "--cc", "--exe", "--build", "-j", str(args.jobs), "--top-module", "FetchPerformanceBench",
                       "--Mdir", str(obj), "-CFLAGS", "-std=c++17", *[str(destination / name) for name in manifest["rtlHashes"]], str(bench), str(harness)]
            run = subprocess.run(build_command, capture_output=True, text=True)
            (destination / "build.log").write_text((run.stdout + run.stderr).replace(str(output), "<evidence>").replace(str(work), "<work>"))
            assert run.returncode == 0, "Performance harness compilation failed"
            binary = obj / "VFetchPerformanceBench"
            for name in ("straight", "branch"):
                words = workload(name)
                image = destination / (name + ".hex")
                image.write_text("".join(f"{address:08x} {word:08x}\n" for address, word in sorted(words.items())))
                for delay in (0, 3):
                    command = [str(binary), str(image), transport, str(delay), str(DONE)]
                    run = subprocess.run(command, capture_output=True, text=True)
                    trace = destination / f"{name}-d{delay}.trace"
                    trace.write_text(run.stdout)
                    trace.with_suffix(".stderr").write_text(run.stderr)
                    assert run.returncode == 0, "Performance program did not complete"
                    metrics = check(words, run.stdout, transport, params)
                    if revision == "current" and transport == "native" and name == "straight" and delay == 0:
                        assert metrics["windowCycles"] == 256, "Native straight-line throughput regressed"
                    if name == "branch":
                        assert metrics["takenBranchesInWindow"] == 128, "Branch window was not exercised"
                    controls = negative_controls(words, run.stdout, transport, params)
                    report["runs"].append({"revision": revision, "transport": transport, "program": name,
                        "timing": {"peerResponseDelayCycles": delay + 1, "acceptance": "always" if delay == 0 else "cycles not divisible by three"},
                        "parameters": params, "metrics": metrics, "manifestSha256": digest(manifest_path.read_bytes()),
                        "rtlHashes": manifest["rtlHashes"], "wrapperSha256": digest(bench.read_bytes()),
                        "binarySha256": digest(binary.read_bytes()), "imageSha256": digest(image.read_bytes()),
                        "traceSha256": digest(trace.read_bytes()), "exitStatus": run.returncode,
                        "negativeControls": controls,
                        "buildCommand": [part.replace(str(output), "<evidence>").replace(str(work), "<work>") for part in build_command],
                        "command": ["<binary>", "<image>", *command[2:]]})
                    (output / "summary.json").write_text(json.dumps(report, indent=2) + "\n")
                    print(revision, transport, name, delay, metrics["windowCycles"], flush=True)
    for current in [run for run in report["runs"] if run["revision"] == "current" and args.baseline_native]:
        baseline = next(run for run in report["runs"] if run["revision"] == "baseline" and
                        all(run[key] == current[key] for key in ("transport", "program", "timing", "parameters", "imageSha256")))
        metrics = ("windowCycles", "windowRetirements", "fetchStarvationCycles", "fetchBackpressureCycles", "instructionRequestBlockedCycles", "totalCycles", "retirementsThroughCompletion")
        report["comparisons"].append({"transport": current["transport"], "program": current["program"], "timing": current["timing"],
            "currentMinusBaseline": {key: current["metrics"][key] - baseline["metrics"][key] for key in metrics},
            "baselineRetirementRecoveryCycles": baseline["metrics"]["retirementRecoveryCycles"],
            "currentRetirementRecoveryCycles": current["metrics"]["retirementRecoveryCycles"]})
    assert all(digest(path.read_bytes()) == expected for path, expected in frozen.items()), "Performance inputs changed during execution"
    assert all(digest(path.read_bytes()) == report["tools"][name]["sha256"] for name, path in tools.items()), "Performance tools changed"
    report["exitStatus"] = 0
    (output / "summary.json").write_text(json.dumps(report, indent=2) + "\n")


if __name__ == "__main__":
    main()
