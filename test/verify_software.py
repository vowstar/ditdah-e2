# SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
# SPDX-License-Identifier: MIT
"""Execute the freestanding ELF and check retirement and completed console stores."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile

from elf import load_elf
from verify import check, checker_inputs
from build_rtl import digest, sources
from build_software import build


CONSOLE = 0x10000000
EXPECTED_CONSOLE = b"E2\n"


class SoftwareCase:
    name = "software"
    instruction_fault = data_fault = None
    expected_causes = expected_interrupts = interrupt_schedule = ()

    def __init__(self, image):
        self.image = image
        self.reset = image.entry
        self.completion_pc = image.symbols["software_done"]
        self.signature = {image.symbols["software_signature"]: 0xECA86420}

    def words(self):
        return self.image.words()


def console_stores(trace):
    pending = None
    output = bytearray()
    for line in trace.splitlines():
        fields = line.split()
        if fields[0] == "Q" and fields[2] == "D":
            assert pending is None, "Overlapping data requests"
            pending = tuple(map(int, fields[3:]))
        elif fields[0] == "S" and fields[2] == "D":
            assert pending is not None, "Data response without request"
            address, write, data, mask, size = pending
            if CONSOLE <= address < CONSOLE + 0x1000:
                assert (address, write, mask, size) == (CONSOLE, 1, 15, 2), "Invalid console store"
                assert int(fields[4]) == 0, "Failed console store"
                output.append(data & 255)
            pending = None
    assert pending is None, "Unfinished data request"
    return bytes(output)


def check_console(trace, output):
    assert output == console_stores(trace), "Console output differs from completed stores"
    assert output == EXPECTED_CONSOLE, "Unexpected console output"


def inputs():
    paths = ("test/verify_software.py", "test/elf.py", "scripts/build_software.py")
    return checker_inputs() | {name: digest(Path(name)) for name in paths}


def rejected(function, message):
    try:
        function()
    except AssertionError:
        return
    raise AssertionError(message)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rtl", type=Path, default=Path("result/rtl"))
    parser.add_argument("--output", type=Path, default=Path("result/software-verification"))
    args = parser.parse_args()
    manifest_path = args.rtl / "manifest.json"
    manifest_hash = digest(manifest_path)
    manifest = json.loads(manifest_path.read_text())
    assert manifest["sourceHashes"] == sources(), "Stale RTL source inputs"
    assert all(digest(args.rtl / name) == value for name, value in manifest["rtlHashes"].items()), "Generated RTL changed"
    initial = inputs()
    args.output.mkdir(parents=True, exist_ok=True)
    software = args.output / "software"
    build(software, reset_vector=manifest["parameters"]["resetVector"])
    software_hash = digest(software / "manifest.json")
    elf_hash = digest(software / "program.elf")
    case = SoftwareCase(load_elf(software / "program.elf", reset_vector=manifest["parameters"]["resetVector"]))
    scratch = "/data/tmp" if os.access("/data/tmp", os.W_OK) else None
    results = []
    controls = 0
    with tempfile.TemporaryDirectory(prefix="ditdah-e2-software-sim-", dir=scratch) as directory:
        work = Path(directory)
        command = ["verilator", "--cc", "--exe", "--build", "-j", "2", "--top-module", "DitDahE2",
                   "--Mdir", str(work / "obj"), "-CFLAGS", "-std=c++17",
                   *[str((args.rtl / name).resolve()) for name in manifest["rtlHashes"]],
                   str(Path("test/sim.cpp").resolve())]
        compiled = subprocess.run(command, capture_output=True, text=True)
        if compiled.returncode:
            raise RuntimeError(compiled.stdout + compiled.stderr)
        image = work / "image.hex"

        def execute(words, seed, delay):
            image.write_text("".join(f"{address:08x} {word:08x}\n" for address, word in sorted(words.items())))
            run_command = [str(work / "obj/VDitDahE2"), str(image), str(seed), str(delay),
                           str(1 << 32), str(1 << 32), "50000", str(case.completion_pc)]
            result = subprocess.run(run_command, capture_output=True, text=True)
            assert result.returncode == 0, result.stderr
            return result.stdout

        for seed, delay in ((0, 0), (1, 24), (19, 40)):
            trace = execute(case.words(), seed, delay)
            metrics = check(case, trace)
            output = console_stores(trace)
            check_console(trace, output)
            name = f"software-s{seed}-d{delay}"
            (args.output / f"{name}.trace").write_text(trace)
            (args.output / f"{name}.txt").write_bytes(output)
            results.append({"seed": seed, "delay": delay, "exitStatus": 0, **metrics,
                            "imageHash": digest(image), "traceHash": hashlib.sha256(trace.encode()).hexdigest(),
                            "consoleHash": hashlib.sha256(output).hexdigest()})
            if seed == 0:
                for changed in (output[1:], bytes([output[0] ^ 1]) + output[1:]):
                    rejected(lambda: check_console(trace, changed), "Checker accepted changed console output")
                    controls += 1
                changed_words = case.words()
                changed_words[case.image.symbols["software_seed"]] ^= 1
                changed_trace = execute(changed_words, seed, delay)
                (args.output / "changed-load.trace").write_text(changed_trace)
                rejected(lambda: check(case, changed_trace), "Checker accepted a changed ELF load")
                controls += 1
    assert initial == inputs() and manifest["sourceHashes"] == sources(), "Verification inputs changed"
    assert manifest_hash == digest(manifest_path), "RTL manifest changed"
    assert all(digest(args.rtl / name) == value for name, value in manifest["rtlHashes"].items()), "Generated RTL changed"
    assert software_hash == digest(software / "manifest.json") and elf_hash == digest(software / "program.elf"), "Software inputs changed"
    summary = {"scope": "RV32I ELF execution, retirement, signature and completed console stores",
               "command": "python3 test/verify_software.py", "exitStatus": 0,
               "rtlManifestHash": manifest_hash, "softwareManifestHash": software_hash,
               "elfHash": elf_hash, "checkerHashes": initial,
               "simulator": subprocess.check_output(["verilator", "--version"], text=True).strip(),
               "negativeControls": controls, "runs": results,
               "consoleDevice": "not implemented", "timerPlatform": "not implemented"}
    (args.output / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    print(f"PASS: {len(results)} ELF RTL runs, {controls} negative controls")


if __name__ == "__main__":
    main()
