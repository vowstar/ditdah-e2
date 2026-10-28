# SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
# SPDX-License-Identifier: MIT
"""Generate checked platform activity from an accepted timer workload."""

import argparse
import hashlib
import json
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import sys

from elf import Region, load_elf
from verify_platform import check, verify_platform_inputs


ROOT = Path(__file__).resolve().parents[1]


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def instrument(text):
    replacements = (
        ('#include "verilated.h"', '#include "verilated.h"\n#include "verilated_vcd_c.h"'),
        ('if (argc != 5) throw std::runtime_error("Expected image seed delay completion-pc");',
         'if (argc != 7) throw std::runtime_error("Expected image seed delay completion-pc VCD period-ps");'),
        ('        VPlatformBench dut{&context};', '''        context.traceEverOn(true);
        VPlatformBench dut{&context};
        const uint64_t period = std::stoull(argv[6]);
        if (!period || period % 2) throw std::runtime_error("Expected a positive even period");
        VerilatedVcdC waveform;
        dut.trace(&waveform, 99);
        waveform.set_time_unit("1ps");
        waveform.set_time_resolution("1ps");
        waveform.open(argv[5]);
        auto evaluate = [&]() {
            dut.eval();
            waveform.dump(context.time());
            context.timeInc(period / 2);
        };'''),
        ('        dut.final();', '        dut.clock = 0;\n        evaluate();\n        waveform.close();\n        dut.final();'),
    )
    assert text.count("dut.eval();") == 3, "Platform evaluation sites changed"
    text = text.replace("dut.eval();", "evaluate();")
    for before, after in replacements:
        assert text.count(before) == 1, "Platform instrumentation target changed"
        text = text.replace(before, after)
    return text


def core_hierarchy(rtl):
    result = {}

    def visit(module, path):
        text = (rtl / (module + ".sv")).read_text()
        registers = {}
        for declaration in re.findall(r"\breg\s+([^;]+);", text):
            match = re.fullmatch(r"(?:\[(\d+):0\]\s*)?([A-Za-z_]\w*)", declaration.strip())
            assert match, "Unsupported register declaration"
            registers[match[2]] = int(match[1]) + 1 if match[1] else 1
        result[path] = {"module": module, "registers": registers}
        for child, instance in re.findall(r"(?m)^\s*(DitDahE2\w+)\s+(\w+)\s*\(", text):
            visit(child, path + "/" + instance)

    visit("DitDahE2", "")
    return result


def inspect_vcd(path, cycles, period, hierarchy):
    assert type(period) is int and period > 0 and period % 2 == 0, "Invalid clock period"
    stack, declarations, scopes, header = [], {}, set(), []
    times, values, histories = [], {}, {}
    body = False
    with path.open() as stream:
        for raw in stream:
            line = raw.strip()
            if not body:
                header.append(line)
                fields = line.split()
                if line.startswith("$scope "):
                    stack.append(fields[2])
                    scopes.add("/".join(stack))
                elif line.startswith("$upscope "):
                    assert stack, "Unbalanced VCD scope"
                    stack.pop()
                elif line.startswith("$var "):
                    name = "/".join(stack + [fields[4]])
                    assert name not in declarations, "Duplicate VCD declaration"
                    declarations[name] = (fields[3], int(fields[2]))
                elif line.startswith("$enddefinitions "):
                    assert not stack, "Unclosed VCD scope"
                    body = True
                continue
            if not line or line.startswith("$"):
                continue
            if line.startswith("#"):
                time = int(line[1:])
                assert not times or time > times[-1], "VCD times are not increasing"
                times.append(time)
                continue
            assert times, "VCD value precedes its timestamp"
            if line[0] in "01xXzZ":
                value, code = line[0].lower(), line[1:]
            elif line[0] in "bB":
                value, code = line[1:].split()
                value = value.lower()
            else:
                raise AssertionError("Unsupported VCD value")
            values[code] = value
            histories.setdefault(code, []).append((times[-1], value))
    assert body and re.search(r"\$timescale\s+1\s*ps\s+\$end", " ".join(header)), "Expected a one ps VCD timescale"
    core_paths = [scope for scope in scopes if scope.endswith("/dut/platform/core")]
    assert len(core_paths) == 1, "Missing unique Core hierarchy"
    core = core_paths[0]
    half = period // 2
    expected_samples = 2 * cycles + 5
    assert times == [index * half for index in range(expected_samples)], "VCD sample range differs"
    clock, reset = declarations[core + "/clock"][0], declarations[core + "/reset"][0]
    assert histories[clock] == [(time, str(index % 2)) for index, time in enumerate(times)], "VCD clock differs"
    assert histories[reset] == [(0, "1"), (2 * period, "0")], "VCD reset differs"
    register_count = register_bits = 0
    for suffix, info in hierarchy.items():
        prefix = core + suffix
        assert prefix in scopes, "Missing Core module scope"
        for name, width in info["registers"].items():
            signal = prefix + "/" + name
            assert signal in declarations and declarations[signal][1] == width, "Missing Core register"
            assert declarations[signal][0] in values, "Core register lacks a sample"
            register_count += 1
            register_bits += width
    core_signals = {name: data for name, data in declarations.items() if name.startswith(core + "/")}
    codes = {data[0] for data in core_signals.values()}
    assert all(code in histories for code in codes), "Core signal lacks a sample"
    assert all(re.fullmatch("[01]+", value) for code in codes for _, value in histories[code]), "Unknown Core value"
    return {"timescalePs": 1, "periodPs": period, "samples": len(times), "startPs": times[0],
            "endPs": times[-1], "durationPs": times[-1] - times[0], "resetCycles": 2,
            "workloadWindowPs": [2 * period, times[-1]], "workloadDurationPs": cycles * period,
            "clockRisingEdges": cycles + 2, "coreStripPath": core,
            "coreModules": {core + suffix: info["module"] for suffix, info in hierarchy.items()},
            "coreDeclarations": len(core_signals), "coreUniqueSignals": len(codes),
            "coreRegisters": register_count, "coreRegisterBits": register_bits, "unknownCoreValues": 0}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--verification", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--core-hash", required=True)
    parser.add_argument("--period-ps", type=int, default=1500)
    parser.add_argument("--seed", type=int, default=0)
    parser.add_argument("--delay", type=int, default=0)
    args = parser.parse_args()
    assert re.fullmatch("[0-9a-f]{64}", args.core_hash), "Invalid Core hash"
    assert args.period_ps > 0 and args.period_ps % 2 == 0, "Invalid clock period"
    accepted = args.verification.resolve()
    previous = json.loads((accepted / "summary.json").read_text())
    platform = json.loads((accepted / "platform/manifest.json").read_text())
    assert previous["exitStatus"] == 0 and previous["workload"] == "timer", "Expected accepted timer execution"
    assert digest(accepted / "platform/manifest.json") == previous["platformManifestHash"]
    assert platform["rtlHashes"]["DitDahE2.sv"] == args.core_hash, "Core hash differs"
    reference = next(run for run in previous["runs"] if (run["seed"], run["delay"]) == (args.seed, args.delay))
    bindings = verify_platform_inputs(accepted / "platform", platform)
    for name, value in previous["inputHashes"].items():
        assert digest(ROOT / name) == value == digest(accepted / "inputs" / name), "Accepted checker input differs"
        bindings[ROOT / name] = value
    for name, value in previous["software"]["artifactHashes"].items():
        assert digest(accepted / "software" / name) == value, "Accepted software artifact differs"
        bindings[accepted / "software" / name] = value
    assert digest(accepted / "image.hex") == previous["imageHash"]
    args.output.mkdir(parents=True, exist_ok=False)
    output = args.output.resolve()
    shutil.copytree(accepted / "platform", output / "platform")
    shutil.copytree(accepted / "inputs", output / "inputs")
    shutil.copytree(accepted / "software", output / "software")
    for name in ("image.hex", "PlatformBench.sv", "summary.json"):
        shutil.copy2(accepted / name, output / ("accepted.json" if name == "summary.json" else name))
    for name in ("test/platform_activity.py", "test/test_platform_activity.py"):
        shutil.copy2(ROOT / name, output / "inputs" / name)
        bindings[ROOT / name] = digest(ROOT / name)
    harness = output / "activity_sim.cpp"
    harness.write_text(instrument((accepted / "inputs/test/platform_sim.cpp").read_text()))
    report = {"scope": "RTL activity from checked timer and console execution", "exitStatus": 1,
              "command": ["python3", "test/platform_activity.py", "--verification", "accepted", "--output", "activity",
                          "--core-hash", args.core_hash, "--period-ps", str(args.period_ps),
                          "--seed", str(args.seed), "--delay", str(args.delay)],
              "parameters": previous["parameters"], "coreRtlHash": args.core_hash,
              "seed": args.seed, "delay": args.delay, "sourceHashes": platform["sourceHashes"],
              "rtlHashes": platform["rtlHashes"], "software": previous["software"],
              "inputHashes": previous["inputHashes"] | {name: digest(ROOT / name) for name in
                              ("test/platform_activity.py", "test/test_platform_activity.py")},
              "acceptedReportHash": digest(accepted / "summary.json"), "harnessHash": digest(harness),
              "platformManifestHash": previous["platformManifestHash"], "commands": [], "tools": {},
              "limits": ["RTL activity has no gate delays or glitch model.",
                         "A different clock period requires a recorded time scale change or a new run.",
                         "Final gate annotation coverage and power analysis are separate checks."]}
    for name in ("verilator", "g++", "make", "python3"):
        tool = Path(sys.executable if name == "python3" else shutil.which(name)).resolve()
        report["tools"][name] = {"hash": digest(tool), "version": subprocess.check_output([str(tool), "--version"], text=True).splitlines()[0]}

    def execute(command, log):
        result = subprocess.run(command, cwd=output, capture_output=True, text=True)
        (output / (log + ".stdout")).write_text(result.stdout)
        (output / (log + ".stderr")).write_text(result.stderr)
        report["commands"].append({"argv": [arg.replace(str(output), "<output>") for arg in command], "exitStatus": result.returncode})
        assert result.returncode == 0, "Activity command failed"
        return result.stdout

    try:
        command = ["verilator", "--cc", "--exe", "--build", "-j", "2", "--trace", "--trace-underscore",
                   "--trace-max-array", "4096", "--trace-max-width", "65536", "--timescale-override", "1ps/1ps",
                   "--top-module", "PlatformBench", "--Mdir", "build", "-CFLAGS", "-std=c++17 -I" + shlex.quote(str(output / "inputs/test")),
                   "PlatformBench.sv", *[str(output / "platform/rtl" / name) for name in platform["rtlHashes"]], str(harness)]
        execute(command, "compile")
        regions, parameters = previous["regions"], previous["parameters"]
        image = load_elf(output / "software/program.elf", reset_vector=parameters["resetVector"],
                         regions=tuple(Region(name, regions[name]["base"], regions[name]["size"], flags)
                                       for name, flags in (("rom", 5), ("sram", 7))), enable_c=parameters["enableC"])
        trace = execute([str(output / "build/VPlatformBench"), "image.hex", str(args.seed), str(args.delay),
                         str(image.symbols["software_done"]), "activity.vcd", str(args.period_ps)], "execution")
        old_trace = accepted / f"timer-s{args.seed}-d{args.delay}.trace"
        assert digest(old_trace) == reference["traceHash"] and trace == old_trace.read_text(), "Instrumented execution trace differs"
        metrics = json.loads(json.dumps(check(image, parameters, regions, trace)))
        assert all(reference[name] == value for name, value in metrics.items()), "Activity workload metrics differ"
        report["workload"] = metrics
        report["activity"] = inspect_vcd(output / "activity.vcd", metrics["cycles"], args.period_ps, core_hierarchy(output / "platform/rtl"))
        report["artifactHashes"] = {name: digest(output / name) for name in
                                   ("activity.vcd", "execution.stdout", "activity_sim.cpp", "PlatformBench.sv", "image.hex", "software/program.elf", "build/VPlatformBench")}
        assert all(digest(path) == value for path, value in bindings.items()), "Activity inputs changed"
        report["exitStatus"] = 0
    finally:
        (output / "summary.json").write_text(json.dumps(report, indent=2) + "\n")
    print("PASS: checked platform VCD")


if __name__ == "__main__":
    main()
