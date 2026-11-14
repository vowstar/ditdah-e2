# SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
# SPDX-License-Identifier: MIT
"""Check shared local SRAM through SBA, hart abstract memory and instruction fetch."""

import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess

from test.programs.programs import branch, constant, immediate, jump, store
from test.test_sba.platform import ROOT, check as check_protocol, digest, observer


def firmware(itcm, dtcm):
    words = constant(1, dtcm + 0x100) + [immediate(2, 0, 0)]
    start = len(words) * 4
    words += [immediate(2, 2, 1), store(2, 1, 0), immediate(3, 1, 0, 3, 2),
              branch(3, 2, 8, unequal=True)]
    words += [jump(0, start - len(words) * 4), 0]
    return {itcm + index * 4: word for index, word in enumerate(words)}


def local_observer(rtl):
    source = observer(rtl, "DitDahE2PlatformTop", False)
    header = re.search(r"module SbaPlatformBench\((.*?)\);", source, re.S)
    declarations, assignments = [], []
    for bank, short in (("itcm", "it"), ("dtcm", "dt")):
        for port, tag in (("instruction", "i"), ("data", "d")):
            name = f"o_{short}_{tag}"
            declarations.append("output " + name)
            path = f"dut.platform.{bank}.{port}_request"
            assignments.append(f"assign {name} = {path}_valid && {path}_ready;")
    source = source[:header.end(1)] + ",\n" + ",\n".join(declarations) + source[header.end(1):]
    return source.replace("endmodule", "\n".join(assignments) + "\nendmodule")


def check(trace, banks):
    rows = [line.split() for line in trace.splitlines()]
    base = "\n".join(" ".join(row) for row in rows if row[0] in {"Q", "S", "R", "N", "C", "A", "F"}) + "\n"
    metrics = check_protocol(base, False)
    assert all(row[0] in {"Q", "S", "R", "N", "C", "A", "F", "M", "T", "P", "L"} for row in rows), "Unknown local record"
    memory, pending, phase, cases = {}, None, None, []
    running_retirements = running_requests = 0
    running_banks = set()
    volatile = banks[1][0] + 0x100
    boundaries = {start + size for start, size in banks}
    def local(address):
        return any(start <= address < start + size for start, size in banks)
    def write(address, value, mask):
        for lane in range(4):
            if mask >> lane & 1:
                memory[(address & ~3) + lane] = value >> (lane * 8) & 255
    def read(address, width):
        assert all(address + lane in memory for lane in range(width)), "Local read precedes explicit initialization"
        return sum(memory[address + lane] << (lane * 8) for lane in range(width))
    for row in rows:
        tag = row[0]
        if tag == "P":
            phase = row[1]
        elif tag == "Q":
            pending = list(map(int, row[2:]))
            address = pending[0]
            if phase == "running" and local(address):
                running_requests += 1
                running_banks.add(next(start for start, size in banks if start <= address < start + size))
        elif tag == "S":
            assert pending is not None
            address, _, store, data, mask, _, _ = pending
            value, fault = map(int, row[2:])
            if local(address):
                assert not fault, "Local SBA access faulted"
                if store:
                    write(address, data, mask)
                elif (address & ~3) != volatile:
                    assert value == read(address & ~3, 4), "SBA read differs from shared byte memory"
            else:
                assert (address == 4 and not store and not fault) or (
                    address in boundaries and not store and fault), "Unexpected external SBA access"
            pending = None
        elif tag == "M":
            store, address, size, data, value, error = map(int, row[1:])
            if local(address):
                assert not error, "Local abstract access faulted"
                if store:
                    write(address, (data & ((1 << (8 << size)) - 1)) << ((address & 3) * 8), ((1 << (1 << size)) - 1) << (address & 3))
                else:
                    assert value == read(address, 1 << size), "Abstract read differs from shared byte memory"
            else:
                assert address in boundaries and not store and error == 5, "Unmapped abstract boundary did not report a bus error"
        elif tag == "T":
            cases.append(tuple(map(int, row[1:])))
        elif tag == "R" and phase == "running":
            if banks[0][0] <= int(row[2]) < banks[0][0] + banks[0][1]:
                running_retirements += 1
    expected = [(start, word + lane, size) for start, length in banks for size in range(3)
                for word in (start, start + length - 4) for lane in range(0, 4, 1 << size)]
    assert cases == expected, "Local width/boundary cases are incomplete"
    assert running_retirements > 10 and running_requests >= 16 and len(running_banks) == 2, "Concurrent local traffic was not reached"
    counters = [list(map(int, row[1:])) for row in rows if row[0] == "L"]
    assert len(counters) == 1 and counters[0][0] > 0 and counters[0][3] > 0, "Missing native local fetch/data observations"
    assert metrics["warmResets"] == 1, "Missing warm-reset drain"
    return {**metrics, "widthBoundaryCases": len(cases), "localFetchRetirementsDuringSba": running_retirements,
            "localSbaRequestsDuringExecution": running_requests, "sampledLocalTransfers": counters[0]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--platform", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    manifest_path = args.platform / "manifest.json"
    manifest = json.loads(manifest_path.read_text())
    params = manifest["parameters"]
    core = params["core"]
    if manifest["exitStatus"] != 0 or manifest["top"] != "DitDahE2PlatformTop" or core["enableA"] or not core["enableDebug"] or not core["enableSba"] or core.get("enableJtag", False):
        raise ValueError("Use an accepted A-disabled synchronous-DMI platform with Debug and SBA")
    banks = []
    for name in ("itcm", "dtcm"):
        bank = params.get(name)
        if not isinstance(bank, dict) or not bank["useSram"] or bank["sizeBytes"] < 1024:
            raise ValueError("The local SBA scenario needs two SRAM banks of at least 1 KiB")
        banks.append((bank["baseAddress"], bank["sizeBytes"]))
    regions = manifest["regions"]
    if any(regions[name] != shape for name, shape in (("rom", {"base": 0, "size": 65536}), ("sram", {"base": 0x20000000, "size": 65536}))):
        raise ValueError("The reused external-memory driver requires the default ROM/external RAM map")
    for start, length in banks:
        if any(region["base"] <= start + length < region["base"] + region["size"] for region in regions.values()):
            raise ValueError("The upper-boundary fault stimulus requires an unmapped address after each bank")
    rtl = args.platform / "rtl"
    if {p.name: digest(p) for p in rtl.glob("*.sv")} != manifest["rtlHashes"]:
        raise ValueError("Frozen platform RTL differs from its manifest")
    if json.loads((args.platform / "parameters.json").read_text()) != params:
        raise ValueError("Platform parameter file differs from its manifest")
    for name, expected in manifest["generatedHashes"].items():
        if digest(args.platform / "inputs/generated" / name) != expected:
            raise ValueError("Frozen generated source or parameter snapshot changed")
    for name, expected in manifest["sourceHashes"].items():
        if digest(args.platform / "inputs" / name) != expected:
            raise ValueError("Frozen platform source snapshot changed")
    output = args.output.resolve()
    if output.exists() and any(output.iterdir()):
        raise ValueError("Local SBA output must be empty")
    output.mkdir(parents=True, exist_ok=True)
    files = [Path(__file__), ROOT / "test/test_sba/local_sim.cpp", ROOT / "test/test_sba/platform.py",
             ROOT / "test/test_sba/platform_sim.cpp", ROOT / "test/programs/programs.py", ROOT / "test/programs/atomic_programs.py"]
    frozen = {str(p.relative_to(ROOT)): digest(p) for p in files}
    for p in files:
        destination = output / "inputs" / p.relative_to(ROOT)
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(p, destination)
    wrapper = output / "SbaPlatformBench.sv"
    wrapper.write_text(local_observer(rtl))
    image, code = output / "rom.txt", output / "local-code.txt"
    image.write_text("".join(f"{address:08x} {jump(0, 0) if address == 0 else 0x13:08x}\n" for address in range(0, 65536, 4)))
    code.write_text("".join(f"{address:08x} {word:08x}\n" for address, word in firmware(banks[0][0], banks[1][0]).items()))
    tool = shutil.which("verilator")
    if not tool:
        raise ValueError("Verilator is unavailable")
    command = [tool, "--cc", "--exe", "--build", "-j", "4", "--top-module", "SbaPlatformBench", "--Mdir", str(output / "build"),
               "-CFLAGS", "-DDITDAH_E2_SBA_ATOMIC=0", str(wrapper), *map(str, sorted(rtl.glob("*.sv"))),
               str(output / "inputs/test/test_sba/local_sim.cpp")]
    built = subprocess.run(command, capture_output=True, text=True)
    (output / "build.log").write_text(built.stdout + built.stderr)
    if built.returncode:
        raise RuntimeError("Local SBA simulator compilation failed")
    run_command = [str(output / "build/VSbaPlatformBench"), str(image), str(code), *(str(value) for bank in banks for value in bank)]
    ran = subprocess.run(run_command, capture_output=True, text=True, timeout=120)
    (output / "trace.txt").write_text(ran.stdout)
    (output / "stderr.txt").write_text(ran.stderr)
    if ran.returncode:
        raise RuntimeError("Local SBA execution failed: " + ran.stderr.strip())
    metrics = check(ran.stdout, banks)
    negatives = []
    for tag, field in (("M", 5), ("S", 2)):
        rows = ran.stdout.splitlines()
        request = None
        for index, line in enumerate(rows):
            parts = line.split()
            if parts[0] == "Q":
                request = list(map(int, parts[2:]))
            eligible = (tag == "M" and parts[0] == "M" and parts[1] == "0" and parts[-1] == "0") or (
                tag == "S" and parts[0] == "S" and request is not None and not request[2] and
                any(start <= request[0] < start + size for start, size in banks))
            if eligible:
                parts[field] = str(int(parts[field]) ^ 1)
                rows[index] = " ".join(parts)
                break
        try:
            check("\n".join(rows), banks)
        except AssertionError as error:
            negatives.append({"record": tag, "rejected": str(error)})
        else:
            raise AssertionError("Local shared-memory checker accepted a corrupted read")
    if any(digest(ROOT / name) != value for name, value in frozen.items()) or {p.name: digest(p) for p in rtl.glob("*.sv")} != manifest["rtlHashes"]:
        raise ValueError("Local SBA inputs changed during execution")
    report = {"SPDX-FileCopyrightText": "2026 Huang Rui <vowstar@gmail.com>", "SPDX-License-Identifier": "MIT",
              "exitStatus": 0, "scope": "SBA/hart abstract shared local storage and reachable warm-reset drain", "parameters": params,
              "metrics": metrics, "manifestSha256": digest(manifest_path), "rtlHashes": manifest["rtlHashes"],
              "sourceHashes": manifest["sourceHashes"], "consumerHashes": frozen, "command": command, "runCommand": run_command,
              "tools": {name: {"sha256": digest(Path(shutil.which(name)).resolve())} for name in ("verilator", "g++", "make")},
              "verilatorVersion": subprocess.check_output([tool, "--version"], text=True).strip(),
              "traceSha256": digest(output / "trace.txt"), "traceNegativeControls": negatives,
              "limits": ["frozen two-bank map and SRAM latencies", "instruction program loaded through SBA while halted",
                         "warm reset overlaps an accepted delayed external SBA read, not an artificially stalled local primitive",
                         "independent general boot and architectural retirement checks are separate", "no technology macro or full-core proof"]}
    (output / "summary.json").write_text(json.dumps(report, indent=2) + "\n")
    print("PASS: shared local SRAM through SBA and hart abstract memory")


if __name__ == "__main__":
    main()
