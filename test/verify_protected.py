# SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
# SPDX-License-Identifier: MIT
"""Check protected execution against fixed programs and an independent model."""

import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import tempfile

from protected_programs import cases
from verify import check, checker_inputs, digest, sources


def inputs():
    return checker_inputs() | {name: digest(Path(name)) for name in
        ("test/pmp.py", "test/protected_programs.py", "test/verify_protected.py")}


def negative_controls(case, trace):
    records = trace.splitlines()
    controls = []
    for name, prefix, field, match in (
            ("retirement privilege", "R ", 11, lambda fields: fields[11] == "1"),
            ("instruction privilege", "P ", 8, lambda fields: fields[2] == "I" and fields[8] == "0"),
            ("data privilege", "P ", 8, lambda fields: fields[2] == "D" and fields[8] == "0"),
            ("trap cause", "R ", 9, lambda fields: fields[8] == "1")):
        selected = next((index for index, line in enumerate(records)
                         if line.startswith(prefix) and match(line.split())), None)
        if selected is None:
            continue
        changed = records.copy()
        fields = changed[selected].split()
        fields[field] = str(int(fields[field]) ^ 1)
        changed[selected] = " ".join(fields)
        try:
            check(case, "\n".join(changed))
        except AssertionError as error:
            controls.append({"mutation": name, "failure": str(error)})
        else:
            raise AssertionError(f"Checker accepted changed {name}")
    return controls


def without_menvcfg(text):
    changed, count = re.subn(r"12'h30[aA]\b", "12'h30B", text)
    if count != 1:
        raise ValueError("Expected one menvcfg address comparison")
    return changed


def menvcfg_negative_control(case, rtl, manifest, command, work, output):
    directory = output / "menvcfg-negative"
    mutant = directory / "rtl"
    mutant.mkdir(parents=True)
    for name in manifest["rtlHashes"]:
        text = (rtl / name).read_text()
        (mutant / name).write_text(without_menvcfg(text) if name == "DitDahE2Csr.sv" else text)
    build_command = [str((mutant / Path(item).name).resolve()) if item.endswith(".sv") else item
                     for item in command]
    build_command[build_command.index("--Mdir") + 1] = str(work / "menvcfg-obj")
    normalize = lambda text: text.replace(str(work), "$WORK").replace(str(Path.cwd()), "$SOURCE")
    build = subprocess.run(build_command, capture_output=True, text=True)
    (directory / "compile.log").write_text(normalize(build.stdout + build.stderr))
    assert build.returncode == 0, "menvcfg mutant build failed"
    image = directory / "image.hex"
    image.write_text("".join(f"{address:08x} {word:08x}\n" for address, word in sorted(case.words().items())))
    invocation = [str(work / "menvcfg-obj/VDitDahE2"), str(image.resolve()), "1", "24",
                  str(1 << 32), str(1 << 32), "50000", str(case.completion_pc)]
    run = subprocess.run(invocation, capture_output=True, text=True)
    (directory / "execution.trace").write_text(run.stdout)
    (directory / "execution.log").write_text(normalize(run.stderr))
    assert run.returncode == 0, "menvcfg mutant did not complete"
    observed = [list(map(int, line.split()[1:])) for line in run.stdout.splitlines() if line.startswith("R ")]
    assert any(row[2] >> 20 == 0x30A and row[7:10] == [1, 2, row[2]] for row in observed), \
        "menvcfg mutant did not produce the intended illegal instruction"
    try:
        check(case, run.stdout)
    except AssertionError as error:
        assert str(error) == "Instruction/PC/trap mismatch", "menvcfg mutant failed for a different reason"
        reason = str(error)
    else:
        raise AssertionError("Checker accepted a rejected menvcfg access")
    result = {"mutation": "reject menvcfg", "case": case.name, "compileExitStatus": build.returncode,
              "exitStatus": run.returncode, "failure": reason,
              "compileCommand": [normalize(item) for item in build_command],
              "command": [normalize(item) for item in invocation],
              "rtlHashes": {name: digest(mutant / name) for name in manifest["rtlHashes"]},
              "imageHash": digest(image), "traceHash": digest(directory / "execution.trace")}
    (directory / "summary.json").write_text(json.dumps(result, indent=2) + "\n")
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rtl", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--case", action="append", default=[])
    args = parser.parse_args()
    assert not args.output.exists(), "Output already exists"
    manifest_path = args.rtl / "manifest.json"
    manifest_hash = digest(manifest_path)
    manifest = json.loads(manifest_path.read_text())
    parameters = manifest["parameters"]
    assert parameters["protectedMode"], "Protected configuration required"
    assert manifest["sourceHashes"] == sources(), "Stale source inputs"
    for name, expected in manifest["rtlHashes"].items():
        assert digest(args.rtl / name) == expected, "RTL changed"
    hashes = inputs()
    selected = [case for case in cases(parameters["resetVector"], parameters["enableM"], parameters["enableC"],
                                      enable_a=parameters["enableA"], enable_zba=parameters["enableZba"],
                                      enable_zbb=parameters["enableZbb"], enable_zbs=parameters["enableZbs"])
                if not args.case or case.name in args.case]
    assert selected and set(args.case) <= {case.name for case in selected}, "Unknown case"
    args.output.mkdir(parents=True)
    frozen = args.output / "inputs"
    for name in hashes:
        target = frozen / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(name, target)
    tools = {}
    for name, option in (("verilator", "--version"), ("g++", "--version"), ("make", "--version"), ("python3", "--version")):
        executable = Path(shutil.which(name))
        tools[name] = {"hash": digest(executable), "version": subprocess.check_output([name, option], text=True).splitlines()[0]}
    results, controls, rtl_controls = [], [], []
    with tempfile.TemporaryDirectory(prefix="ditdah-e2-protected-", dir="/data/tmp") as directory:
        work = Path(directory)
        command = ["verilator", "--cc", "--exe", "--build", "-j", "2", "--top-module", "DitDahE2",
                   "--Mdir", str(work / "obj"), "-CFLAGS", "-std=c++17",
                   *[str((args.rtl / name).resolve()) for name in manifest["rtlHashes"]],
                   str(Path("test/sim.cpp").resolve())]
        build = subprocess.run(command, capture_output=True, text=True)
        normalize = lambda text: text.replace(str(work), "$WORK").replace(str(Path.cwd()), "$SOURCE")
        (args.output / "compile.log").write_text(normalize(build.stdout + build.stderr))
        assert build.returncode == 0, "Protected simulator build failed"
        for case in selected:
            image = work / "image.hex"
            image.write_text("".join(f"{address:08x} {word:08x}\n" for address, word in sorted(case.words().items())))
            for seed, delay in ((0, 0), (1, 24), (19, 40)):
                invocation = [str(work / "obj/VDitDahE2"), str(image), str(seed), str(delay),
                              str(case.instruction_fault if case.instruction_fault is not None else 1 << 32),
                              str(case.data_fault if case.data_fault is not None else 1 << 32),
                              "50000", str(case.completion_pc)]
                if case.interrupt_schedule:
                    schedule = work / "interrupts.txt"
                    schedule.write_text("".join(" ".join(map(str, entry)) + "\n" for entry in case.interrupt_schedule))
                    invocation.append(str(schedule))
                run = subprocess.run(invocation, capture_output=True, text=True)
                name = f"{case.name}-s{seed}-d{delay}"
                (args.output / f"{name}.trace").write_text(run.stdout)
                (args.output / f"{name}.log").write_text(normalize(run.stderr))
                assert run.returncode == 0, f"{name}: simulation did not complete"
                try:
                    metrics = check(case, run.stdout)
                except AssertionError as error:
                    raise AssertionError(f"{name}: {error}") from error
                if seed == 0:
                    controls.extend({"case": case.name, **item} for item in negative_controls(case, run.stdout))
                results.append({"case": case.name, "seed": seed, "delay": delay, "exitStatus": 0,
                                "command": [normalize(item) for item in invocation], **metrics,
                                "imageHash": digest(image), "traceHash": hashlib.sha256(run.stdout.encode()).hexdigest()})
        environment_case = next((case for case in selected if case.name == "protected_menvcfg_zero"), None)
        if environment_case is not None:
            rtl_controls.append(menvcfg_negative_control(environment_case, args.rtl, manifest, command,
                                                        work, args.output))
        assert manifest["sourceHashes"] == sources(), "Source inputs changed"
        assert hashes == inputs(), "Checker inputs changed"
        assert manifest_hash == digest(manifest_path), "Manifest changed"
        for name, expected in manifest["rtlHashes"].items():
            assert digest(args.rtl / name) == expected, "RTL changed"
        summary = {"scope": "protected execution with fixed signatures and native request privilege",
                   "exitStatus": 0, "parameters": parameters, "rtlManifestHash": manifest_hash,
                   "sourceHashes": manifest["sourceHashes"], "checkerHashes": hashes, "tools": tools,
                   "compileCommand": [normalize(item) for item in command],
                   "negativeControls": controls, "rtlNegativeControls": rtl_controls, "runs": results}
        (args.output / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    print(f"PASS: {len(results)} protected RTL runs, {len(controls)} trace controls")


if __name__ == "__main__":
    main()
