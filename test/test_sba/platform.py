# SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
# SPDX-License-Identifier: MIT
"""Exercise SBA through complete native/AXI and shared atomic platforms."""

import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess

from test.programs.atomic_programs import atomic
from test.programs.programs import branch, constant, immediate, jump, store

ROOT = Path(__file__).resolve().parents[2]
NOTICE = """// SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
// SPDX-License-Identifier: MIT
"""


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def firmware():
    words = [0x13] * 32
    words += constant(1, 0x20000000) + constant(2, 0x55667788)
    words += [immediate(3, 0, 1)]
    words += [immediate(4, 1, 0x40, 3, 2), branch(4, 3, -4, unequal=True)]
    words += [atomic("lr.w", 5, 1), immediate(3, 0, 2), store(3, 1, 0x40), immediate(3, 0, 3)]
    words += [immediate(4, 1, 0x40, 3, 2), branch(4, 3, -4, unequal=True)]
    words += [atomic("sc.w", 6, 1, 2), store(5, 1, 0x84), store(6, 1, 0x80), jump(0, 0)]
    return {index * 4: word for index, word in enumerate(words)}


def observer(rtl, top, atomic_enabled):
    source = (rtl / f"{top}.sv").read_text()
    ports = re.search(r"module " + top + r"\((.*?)\);", source, re.S)
    if not ports:
        raise ValueError("Generated platform ports are unavailable")
    widths = {"request_valid": 1, "request_ready": 1, "request_bits_address": 32,
              "request_bits_machine": 1, "request_bits_write": 1, "request_bits_data": 32,
              "request_bits_mask": 4, "request_bits_size": 2, "request_bits_operation": 4,
              "response_valid": 1, "response_ready": 1, "response_bits_data": 32,
              "response_bits_fault": 1}
    declarations, assignments = [], []
    for field, width in widths.items():
        name = "o_s_" + field
        declarations.append(f"output {'[' + str(width - 1) + ':0] ' if width > 1 else ''}{name}")
        assignments.append(f"assign {name} = dut.platform.core.systemBus_{field};")
    declarations += ["output o_systemReset", "output o_clear"]
    assignments += ["assign o_systemReset = dut.platform.core.systemReset;",
                    "assign o_clear = " + ("dut.platform.core.reservationClear;" if atomic_enabled else "1'b0;")]
    return (NOTICE + "module SbaPlatformBench(" + ports[1] + ",\n" +
            ",\n".join(declarations) + ");\n" + top + " dut(.*);\n" +
            "\n".join(assignments) + "\nendmodule\n")


def check(trace, atomic_enabled):
    rows = [line.split() for line in trace.splitlines()]
    if not rows or rows[-1][0] != "F" or any(row[0] not in {"Q", "S", "R", "N", "C", "A", "F"} for row in rows):
        raise ValueError("Missing platform completion or unknown trace record")
    pending = None
    accepted = completed = 0
    for row in rows:
        if row[0] == "Q":
            if pending is not None or len(row) != 9:
                raise ValueError("Overlapping or malformed SBA platform request")
            pending = int(row[1])
            address, machine, write, _, mask, size, operation = map(int, row[2:])
            if not machine or operation or size not in (0, 1, 2) or address % (1 << size):
                raise ValueError("Invalid SBA platform request shape")
            if mask != (((1 << (1 << size)) - 1) << (address % 4) if write else 0):
                raise ValueError("Invalid SBA write lanes")
            accepted += 1
        elif row[0] == "S":
            if pending is None or int(row[1]) <= pending:
                raise ValueError("Unowned or early SBA platform response")
            pending = None
            completed += 1
        elif row[0] == "N" and pending is not None:
            raise ValueError("Warm reset crossed an accepted SBA transfer")
    if pending is not None or accepted != completed or list(map(int, rows[-1][2:4])) != [accepted, completed]:
        raise ValueError("Incomplete SBA platform traffic")
    intervals = [list(map(int, row[1:])) for row in rows if row[0] == "A"]
    if atomic_enabled:
        if len(intervals) != 2 or [item[0] for item in intervals] != [0, 1]:
            raise ValueError("Missing same-word and different-word reservation tests")
        for conflict, start, end in intervals:
            reservations = [int(row[1]) for row in rows if row[0] == "R" and int(row[1]) < start
                            and int(row[4]) == 5 and int(row[3]) & 0x7f == 0x2f]
            if not reservations:
                raise ValueError("Missing executed LR before the tested SBA writer")
            reserved = reservations[-1]
            if any(row[0] == "C" and reserved < int(row[1]) <= end for row in rows):
                raise ValueError("Hart control cleared the tested LR reservation")
            results = [row for row in rows if row[0] == "R" and start <= int(row[1]) <= end
                       and int(row[4]) == 6 and int(row[3]) & 0x7f == 0x2f]
            if len(results) != 1 or int(results[0][5]) != conflict:
                raise ValueError("SC retirement differs from the independent expected result")
    elif intervals:
        raise ValueError("Atomic result in a platform without atomic memory")
    return {"cycles": int(rows[-1][1]), "requests": accepted, "responses": completed,
            "warmResets": int(rows[-1][4]), "reservationCases": len(intervals)}


def reservation_negative(command, rtl, output, image):
    original = rtl / "DitDahE2AtomicMemory.sv"
    source = original.read_text()
    pattern = "~(write & success)"
    if source.count(pattern) != 1:
        raise ValueError("Reservation mutation site changed")
    directory = output / "negative-reservation"
    directory.mkdir()
    mutated = directory / original.name
    mutated.write_text(source.replace(pattern, "1'h1"))
    arguments = [str(mutated) if value == str(original) else value for value in command]
    arguments[arguments.index("--Mdir") + 1] = str(directory / "build")
    built = subprocess.run(arguments, capture_output=True, text=True)
    (directory / "build.log").write_text(built.stdout + built.stderr)
    if built.returncode:
        raise RuntimeError("Reservation negative control did not compile")
    ran = subprocess.run([str(directory / "build/VSbaPlatformBench"), str(image)],
                         capture_output=True, text=True, timeout=120)
    (directory / "trace.txt").write_text(ran.stdout)
    (directory / "stderr.txt").write_text(ran.stderr)
    # The mutant must reach and retire a wrongly successful conflicting SC.
    lr = [line for line in ran.stdout.splitlines() if line.startswith("A 0 ")]
    sc = [list(map(int, line.split()[1:])) for line in ran.stdout.splitlines() if line.startswith("R ")]
    wrong = [row for row in sc if row[3] == 6 and row[2] & 0x7f == 0x2f and row[4] == 0]
    if ran.returncode != 1 or not lr or len(wrong) != 2 or ran.stderr.strip() != "Firmware memory handshake timed out":
        raise ValueError("Reservation negative control lacks its architectural counterexample")
    return {"mutation": "preserve-reservation-after-write", "rejected": True,
            "compiledExitStatus": built.returncode, "executionExitStatus": ran.returncode,
            "wrongScRetireCycle": wrong[-1][0], "traceSha256": digest(directory / "trace.txt"),
            "mutatedRtlSha256": digest(mutated)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--platform", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    manifest = json.loads((args.platform / "manifest.json").read_text())
    params = manifest["parameters"]["core"]
    if not params.get("enableSba") or not params.get("enableDebug") or params.get("enableJtag"):
        raise ValueError("Platform SBA acceptance requires synchronous DMI with SBA")
    atomic_enabled = params["enableA"]
    top = "DitDahE2AtomicPlatformTop" if atomic_enabled else "DitDahE2PlatformTop"
    if manifest["top"] != top:
        raise ValueError("Unexpected platform topology")
    rtl = args.platform / "rtl"
    rtl_hashes = {p.name: digest(p) for p in rtl.glob("*.sv")}
    if rtl_hashes != manifest["rtlHashes"]:
        raise ValueError("Generated platform RTL changed")
    if any(not (ROOT / name).is_file() or digest(ROOT / name) != value
           for name, value in manifest["sourceHashes"].items()):
        raise ValueError("Platform source inputs changed")
    output = args.output.resolve()
    if output.exists() and any(output.iterdir()):
        raise ValueError("Platform SBA output must be empty")
    output.mkdir(parents=True, exist_ok=True)
    wrapper = output / "SbaPlatformBench.sv"
    wrapper.write_text(observer(rtl, top, atomic_enabled))
    image = output / "image.txt"
    program = firmware()
    image.write_text("".join(f"{address:08x} {program.get(address, 0x13):08x}\n" for address in range(0, 65536, 4)))
    tool = shutil.which("verilator")
    if not tool:
        raise ValueError("Verilator is unavailable")
    command = [tool, "--cc", "--exe", "--build", "-j", "4", "-Wno-fatal", "--top-module", "SbaPlatformBench",
               "--Mdir", str(output / "build"), "-CFLAGS", f"-DDITDAH_E2_SBA_ATOMIC={int(atomic_enabled)}",
               str(wrapper), *map(str, sorted(rtl.glob("*.sv"))), str(ROOT / "test/test_sba/platform_sim.cpp")]
    built = subprocess.run(command, capture_output=True, text=True)
    (output / "build.log").write_text(built.stdout + built.stderr)
    if built.returncode:
        raise RuntimeError("SBA platform simulator compilation failed")
    ran = subprocess.run([str(output / "build/VSbaPlatformBench"), str(image)], capture_output=True, text=True, timeout=120)
    (output / "trace.txt").write_text(ran.stdout)
    (output / "stderr.txt").write_text(ran.stderr)
    if ran.returncode:
        raise RuntimeError("SBA platform execution failed: " + ran.stderr.strip())
    metrics = check(ran.stdout, atomic_enabled)
    negatives = [reservation_negative(command, rtl, output, image)] if atomic_enabled else []
    report = {"scope": "SBA platform routing, warm reset, activation epochs" +
              (" and same-word/different-word LR/SC" if atomic_enabled else ""), "exitStatus": 0,
              "parameters": params, "metrics": metrics, "rtlHashes": rtl_hashes,
              "sourceHashes": manifest["sourceHashes"], "manifestSha256": digest(args.platform / "manifest.json"),
              "consumerHashes": {str(p.relative_to(ROOT)): digest(p) for p in
                                 [Path(__file__), ROOT / "test/test_sba/platform_sim.cpp",
                                  ROOT / "test/programs/atomic_programs.py", ROOT / "test/programs/programs.py"]},
              "tool": {"version": subprocess.check_output([tool, "--version"], text=True).strip(), "sha256": digest(Path(tool).resolve())},
              "command": command, "negativeControls": negatives,
              "traceSha256": digest(output / "trace.txt"), "fullCoreProven": False}
    (output / "summary.json").write_text(json.dumps(report, indent=2) + "\n")
    print("PASS: SBA platform " + ("with shared atomic memory" if atomic_enabled else "with AXI memory"))


if __name__ == "__main__":
    main()
