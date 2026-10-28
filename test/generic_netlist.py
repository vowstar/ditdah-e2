# SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
# SPDX-License-Identifier: MIT
"""Execute generic logic with the independent instruction and protocol checks."""

import argparse
import json
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import sys

from programs import Case, cases as ordinary_cases, immediate, jump
from protected_programs import cases as protected_cases
from verify import check, checker_inputs, digest, feature_negative_controls, retirement_coverage


ROOT = Path(__file__).resolve().parents[1]
TIMINGS = ((0, 0), (1, 24), (19, 40))


class WritebackControl(Case):
    def words(self):
        data = {}
        for offset, word in ((0, immediate(1, 0, 7)), (4, jump(0, 0))):
            for lane in range(4):
                data[(self.reset + offset + lane) & 0xffffffff] = (word >> (lane * 8)) & 255
        result = {}
        for address, value in data.items():
            base = address & ~3
            result[base] = result.get(base, 0) | (value << ((address & 3) * 8))
        return result


def mutate_writeback(text):
    result, count = re.subn(r"(?m)^(\s*assign\s+retire_writes\s*=\s*)([^;]+);",
                            r"\1~(\2);", text)
    assert count == 1, "Changed netlist writeback output"
    return result


def simulation_netlist(text):
    header = re.search(r"(?ms)^module DitDahE2\b.*?;", text)
    assert header, "Missing processor netlist header"
    private = "simulation_interrupt_cause"
    assert private not in text, "Conflicting simulation alias"
    head, body = text[:header.end()], text[header.end():]
    body = re.sub(r"\binterrupt_cause\b", private, body)
    body, count = re.subn(r"\boutput\s+\[31:0\]\s+" + private + r"\s*;",
                         "output [31:0] interrupt_cause;", body)
    assert count == 1, "Changed interrupt cause output"
    # A private alias permits bit splitting on this output.
    body, count = re.subn(r"\bwire\s+\[31:0\]\s+" + private + r"\s*;",
                         "wire [31:0] " + private + " /* verilator split_var */;", body)
    assert count == 1 and body.count("endmodule") == 1, "Changed netlist wire declarations"
    return head + body.replace("endmodule", "assign interrupt_cause = " + private + ";\nendmodule")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--synthesis", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--reference", type=Path)
    args = parser.parse_args()
    assert Path.cwd() == ROOT, "Run from the project root"
    synthesis = args.synthesis.resolve()
    summary_file = synthesis / "summary.json"
    summary = json.loads(summary_file.read_text())
    assert summary["exitStatus"] == 0 and summary["toolExitStatus"] == 0, "Synthesis did not pass"
    for name, value in summary["artifactHashes"].items():
        assert digest(synthesis / name) == value, "Synthesized artifact changed"
    parameters = summary["parameters"]
    factory = protected_cases if parameters["protectedMode"] else ordinary_cases
    selected = factory(parameters["resetVector"], parameters["enableM"], parameters["enableC"],
                       enable_a=parameters["enableA"], enable_zba=parameters["enableZba"],
                       enable_zbb=parameters["enableZbb"], enable_zbs=parameters["enableZbs"])
    inputs = checker_inputs() | {name: digest(ROOT / name) for name in
             ("test/protected_programs.py", "test/pmp.py", "test/generic_netlist.py", "scripts/synthesize.py")}
    reference, prior = {}, None
    if args.reference:
        prior = json.loads((args.reference / "verification/summary.json").read_text())
        original = args.reference / "rtl/manifest.json"
        design = json.loads(original.read_text())
        assert prior["exitStatus"] == 0 and prior["parameters"] == parameters, "Reference configuration differs"
        assert prior["rtlManifestHash"] == digest(original), "Reference manifest changed"
        assert design["rtlHashes"] == summary["rtlHashes"], "Reference RTL differs"
        assert prior["checkerHashes"]["test/sim.cpp"] == inputs["test/sim.cpp"], "Reference driver differs"
        reference = {(run["case"], run["seed"], run["delay"]): run for run in prior["runs"]}
    args.output.mkdir(parents=True, exist_ok=False)
    output = args.output.resolve()
    for name in inputs:
        target = output / "inputs" / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(ROOT / name, target)
    shutil.copy2(summary_file, output / "synthesis.json")
    shutil.copy2(synthesis / "generic.v", output / "generic.v")
    (output / "simulation.v").write_text(simulation_netlist((output / "generic.v").read_text()))
    report = {"scope": "ordinary instruction execution on generic logic", "exitStatus": 1,
              "parameters": parameters, "synthesisHash": digest(summary_file), "checkerHashes": inputs,
              "rtlHashes": summary["rtlHashes"], "netlistHash": digest(output / "generic.v"),
              "simulationNetlistHash": digest(output / "simulation.v"),
              "simulationNormalization": "private alias and bit splitting for interrupt_cause",
              "activeDebug": False, "atomicInstructions": False, "runs": [], "commands": [], "tools": {},
              "referenceReportHash": digest(args.reference / "verification/summary.json") if prior else None}
    for name in ("verilator", "g++", "make", "python3"):
        tool = Path(sys.executable if name == "python3" else shutil.which(name)).resolve()
        report["tools"][name] = {"hash": digest(tool), "version": subprocess.check_output([str(tool), "--version"], text=True).splitlines()[0]}

    def execute(command, prefix):
        result = subprocess.run(command, cwd=output, capture_output=True, text=True)
        (output / (prefix + ".stdout")).write_text(result.stdout)
        (output / (prefix + ".stderr")).write_text(result.stderr)
        report["commands"].append({"argv": [arg.replace(str(output), "<output>") for arg in command], "exitStatus": result.returncode})
        assert result.returncode == 0, "Netlist command failed"
        return result.stdout

    def run(case, seed, delay, executable, prefix):
        image = output / (prefix + ".hex")
        image.write_text("".join(f"{address:08x} {word:08x}\n" for address, word in sorted(case.words().items())))
        command = [str(executable), str(image), str(seed), str(delay),
                   str(case.instruction_fault if case.instruction_fault is not None else 1 << 32),
                   str(case.data_fault if case.data_fault is not None else 1 << 32), "50000", str(case.completion_pc)]
        if case.interrupt_schedule:
            schedule = output / (prefix + ".inputs")
            schedule.write_text("".join(" ".join(map(str, entry)) + "\n" for entry in case.interrupt_schedule))
            command.append(str(schedule))
        trace = execute(command, prefix)
        return trace, digest(image)

    try:
        command = ["verilator", "--cc", "--exe", "--build", "-j", "2", "--top-module", "DitDahE2",
                   "--Mdir", "build", "-CFLAGS", "-std=c++17 -I" + shlex.quote(str(output / "inputs/test")),
                   "simulation.v", str(output / "inputs/test/sim.cpp")]
        execute(command, "compile")
        report["executableHash"] = digest(output / "build/VDitDahE2")
        controls = 0
        for case in selected:
            timings = TIMINGS + (((7, 128),) if case.name.startswith("m_older_") or
                                 (case.name.startswith("bit_") and "_older_" in case.name) else ())
            for seed, delay in timings:
                prefix = f"{case.name}-s{seed}-d{delay}"
                trace, image_hash = run(case, seed, delay, output / "build/VDitDahE2", prefix)
                metrics = check(case, trace)
                if seed == 0:
                    controls += feature_negative_controls(case, trace)
                if prior:
                    previous = reference[(case.name, seed, delay)]
                    old = args.reference / "verification" / (prefix + ".trace")
                    assert image_hash == previous["imageHash"], "Reference program differs"
                    assert digest(old) == previous["traceHash"], "Reference trace changed"
                    assert trace == old.read_text(), "Generic logic differs from accepted RTL execution"
                report["runs"].append({"case": case.name, "seed": seed, "delay": delay, "imageHash": image_hash,
                                       "traceHash": digest(output / (prefix + ".stdout")), "exitStatus": 0, **metrics})
        required, excluded = retirement_coverage(summary["instructions"], parameters["enableA"])
        observed = set().union(*(set(run["instructions"]) for run in report["runs"]))
        if not parameters["resetVector"] and not parameters["protectedMode"]:
            assert required <= observed, "Unexecuted generic instructions"
        report["excludedInstructions"] = excluded
        report["semanticControls"] = controls
        case = WritebackControl("writeback_control", [], expected_causes=(), reset=parameters["resetVector"],
                                completion_pc=(parameters["resetVector"] + 4) & 0xffffffff,
                                enable_m=parameters["enableM"], enable_c=parameters["enableC"],
                                enable_a=parameters["enableA"], enable_zba=parameters["enableZba"],
                                enable_zbb=parameters["enableZbb"], enable_zbs=parameters["enableZbs"])
        trace, image_hash = run(case, 0, 0, output / "build/VDitDahE2", "control")
        report["writebackControl"] = {"imageHash": image_hash, "traceHash": digest(output / "control.stdout"),
                                      **check(case, trace)}
        mutant = output / "mutant.v"
        mutant.write_text(mutate_writeback((output / "simulation.v").read_text()))
        mutant_command = ["mutant.v" if arg == "simulation.v" else "mutant-build" if arg == "build" else arg for arg in command]
        execute(mutant_command, "mutant-compile")
        trace, _ = run(case, 0, 0, output / "mutant-build/VDitDahE2", "mutant")
        try:
            check(case, trace)
        except AssertionError as error:
            assert "Register write enable mismatch" in str(error), "Netlist mutant failed for another reason"
            report["netlistNegativeControl"] = {"failure": str(error), "netlistHash": digest(mutant),
                                               "traceHash": digest(output / "mutant.stdout")}
        else:
            raise AssertionError("Checker accepted corrupted netlist writeback")
        assert all(digest(ROOT / name) == value for name, value in inputs.items()), "Netlist checker changed"
        assert all(digest(output / "inputs" / name) == value for name, value in inputs.items()), "Frozen checker changed"
        assert digest(summary_file) == report["synthesisHash"], "Synthesis report changed"
        assert digest(synthesis / "generic.v") == report["netlistHash"] == digest(output / "generic.v"), "Netlist changed"
        assert digest(output / "simulation.v") == report["simulationNetlistHash"], "Simulation netlist changed"
        assert digest(output / "build/VDitDahE2") == report["executableHash"], "Netlist simulator changed"
        report["artifactHashes"] = {name: digest(output / name) for name in
                                    ("generic.v", "simulation.v", "build/VDitDahE2", "mutant.v", "mutant-build/VDitDahE2")}
        report["exitStatus"] = 0
    finally:
        (output / "summary.json").write_text(json.dumps(report, indent=2) + "\n")
    print(f"PASS: {len(report['runs'])} generic netlist executions")


if __name__ == "__main__":
    main()
