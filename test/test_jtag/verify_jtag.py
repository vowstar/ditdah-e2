# SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
# SPDX-License-Identifier: MIT
"""Generate or bind transport RTL and run asynchronous JTAG checks."""

import argparse
import hashlib
import json
from pathlib import Path
import resource
import subprocess


ROOT = Path(__file__).resolve().parents[2]
TEST_IDCODE = 0xE2000001  # Test-only scan value, not a product identity.
TOPS = (("dtm", "DitDahE2JtagDtm"), ("bridge", "DitDahE2DmiBridge"))
SCHEDULES = ((2, 17), (5, 73), (19, 109), (83, 271))
TEST_SOURCES = tuple(Path("test/test_jtag") / name for name in
                     ("verify_jtag.py", "jtag_tb.sv", "test_jtag.py"))


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def run(command, log, timeout=600):
    command = list(map(str, command))
    with log.open("w") as stream:
        result = subprocess.run(command, cwd=ROOT, stdout=stream,
                                stderr=subprocess.STDOUT, timeout=timeout)
    if result.returncode:
        with log.open("rb") as stream:
            stream.seek(max(0, log.stat().st_size - 10000))
            tail = stream.read().decode(errors="replace")
        raise RuntimeError(f"{command[0]} failed; see {log}\n{tail}")


def configuration():
    return {"enableDebug": True, "enableJtag": True, "jtagIdcode": TEST_IDCODE}


def load_design(rtl_root, name, top):
    rtl = rtl_root / name
    manifests = [rtl / filename for filename in ("ditdah_e2_config.json", "manifest.json")]
    manifest_path = next((path for path in manifests if path.is_file()), None)
    if manifest_path is None:
        raise RuntimeError(f"Missing generated manifest in {rtl}")
    manifest = json.loads(manifest_path.read_text())
    if manifest.get("top") != top:
        raise RuntimeError(f"Unexpected top in {manifest_path}: {manifest.get('top')}")
    parameters = manifest.get("parameters", {})
    if parameters.get("enableDebug") is not True or parameters.get("enableJtag") is not True:
        raise RuntimeError(f"JTAG debug is not enabled in {manifest_path}")
    if parameters.get("jtagIdcode") != TEST_IDCODE:
        raise RuntimeError(f"Explicit test IDCODE differs in {manifest_path}")
    for filename, expected in manifest.get("sourceHashes", {}).items():
        source = Path(filename)
        if not source.is_absolute():
            source = ROOT / source
        if not source.is_file() or digest(source) != expected:
            raise RuntimeError(f"Stale source input {filename} for {rtl}")
    for filename, expected in manifest.get("rtlHashes", {}).items():
        if not (rtl / filename).is_file() or digest(rtl / filename) != expected:
            raise RuntimeError(f"Stale generated input {filename} for {rtl}")
    filelist = rtl / "filelist.f"
    if not filelist.is_file():
        raise RuntimeError(f"Missing {filelist}")
    files = [(rtl / line.strip()).resolve() for line in filelist.read_text().splitlines()
             if line.strip()]
    if not files or any(not path.is_file() for path in files):
        raise RuntimeError(f"Incomplete generated file list for {rtl}")
    return files, manifest


def simulation_passed(text):
    lines = text.splitlines()
    return "PASS" in lines and "FAIL" not in lines


def main():
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rtl", type=Path,
                        help="Generated directory containing dtm and bridge subdirectories")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    output = args.output
    output.mkdir(parents=True, exist_ok=True)
    config = output / "input.json"
    config.write_text(json.dumps(configuration()) + "\n")
    hashes = {str(path): digest(ROOT / path) for path in TEST_SOURCES}
    files, manifests = [], {}
    for name, top in TOPS:
        rtl = args.rtl / name if args.rtl else output / name
        if args.rtl is None:
            run(["python3", "scripts/build_rtl.py", "--top", top,
                 "--config", config.resolve(), "--output", rtl.resolve()],
                output / f"{name}-build.log")
        design_files, manifest = load_design(rtl.parent, name, top)
        files.extend(design_files)
        manifests[name] = manifest
    build = (output / "native").resolve()
    testbench = ROOT / "test/test_jtag/jtag_tb.sv"
    compile_command = ["verilator", "--binary", "--timing", "--assert", "-j", "2",
                       "--top-module", "jtag_tb", "-Wno-fatal", "--Mdir", build,
                       *files, testbench]
    run(compile_command, output / "native-compile.log")
    binary = build / "Vjtag_tb"
    results = []
    for half, seed in SCHEDULES:
        log = output / f"clock-{half}-seed-{seed}.log"
        command = [binary, f"+SYSTEM_HALF={half}", f"+SEED={seed}",
                   f"+IDCODE={TEST_IDCODE:x}"]
        run(command, log, timeout=60)
        if not simulation_passed(log.read_text()):
            raise RuntimeError(f"Simulation did not report completion; see {log}")
        results.append({"systemHalf": half, "seed": seed, "log": log.name,
                        "command": list(map(str, command)), "exitStatus": 0})
    if any(digest(ROOT / path) != expected for path, expected in hashes.items()):
        raise RuntimeError("Test sources changed during execution")
    report = {"status": "passed", "configuration": configuration(),
              "manifests": manifests, "schedules": results,
              "compileCommand": list(map(str, compile_command)),
              "verilator": subprocess.check_output(["verilator", "--version"], text=True).strip(),
              "testSourceHashes": hashes}
    (output / "summary.json").write_text(json.dumps(report, indent=2) + "\n")
    print(f"JTAG transport checks passed: {len(results)} asynchronous clock schedules")


if __name__ == "__main__":
    main()
