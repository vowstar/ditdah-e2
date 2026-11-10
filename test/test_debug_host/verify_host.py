# SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
# SPDX-License-Identifier: MIT
"""Accept RV32IMC JTAG debugging with real OpenOCD and GDB processes."""

import argparse
import hashlib
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT), str(ROOT / "scripts")]
from build_rtl import digest, sources
from build_software import build as build_software

from test.common.elf import load_elf
from test.common.model import Model

READY = "E2_OPENOCD_READY"
ABSTRACT_ONLY = "E2_MEM_ACCESS_ABSTRACT_ONLY"
GDB_ACCEPTED = "E2_GDB_ACCEPTED"
CONSOLE = 0x10000000
SCRATCH = 0x20008000


def resolve_tool(value, environment, default):
    selected = value or os.environ.get(environment) or default
    located = shutil.which(str(selected))
    if not located:
        raise ValueError(f"Required tool is unavailable: {selected}")
    executable = Path(located).resolve()
    version = subprocess.check_output([str(executable), "--version"], stderr=subprocess.STDOUT,
                                      text=True, timeout=15).splitlines()[0]
    return executable, {"version": version, "sha256": digest(executable)}


def validate_manifest(manifest):
    if manifest.get("top") != "DitDahE2":
        raise ValueError("Unexpected generated top-level module")
    parameters = manifest.get("parameters")
    if not isinstance(parameters, dict):
        raise TypeError("Generated parameters must be a dictionary")
    required = {"resetVector": 0, "enableDebug": True, "enableJtag": True,
                "enableM": True, "enableC": True, "protectedMode": False,
                "enableA": False, "enableZba": False, "enableZbb": False, "enableZbs": False}
    for name, expected in required.items():
        if parameters.get(name, False) is not expected:
            raise ValueError(f"Host acceptance requires {name}={expected}")
    idcode = parameters.get("jtagIdcode")
    if type(idcode) is not int or not 0 < idcode < 1 << 32 or not idcode & 1:
        raise ValueError("JTAG IDCODE must be odd, nonzero and unsigned 32-bit")
    return idcode


def openocd_configuration(bitbang_port, gdb_port, idcode, strict_idcode=False):
    commands = [
        "adapter driver remote_bitbang",
        "transport select jtag",
        "remote_bitbang host 127.0.0.1",
        f"remote_bitbang port {bitbang_port}",
        f"if {{[catch {{gdb port {gdb_port}}}]}} {{gdb_port {gdb_port}}}",
        "if {[catch {tcl port disabled}]} {tcl_port disabled}",
        "if {[catch {telnet port disabled}]} {telnet_port disabled}",
        "reset_config none",
        f"jtag newtap ditdah cpu -irlen 5 -expected-id 0x{idcode:08x}",
        "target create ditdah.cpu riscv -chain-position ditdah.cpu -coreid 0",
        "riscv expose_csrs 832",
        "riscv set_mem_access abstract",
        f"echo {ABSTRACT_ONLY}",
        "riscv set_command_timeout_sec 30",
        "ditdah.cpu configure -event resume-end {poll on}",
        "ditdah.cpu configure -event halted {poll off}",
        "init",
    ]
    if strict_idcode:
        commands += [
            "poll off",
            "irscan ditdah.cpu 1",
            "set e2_observed_idcode [drscan ditdah.cpu 32 0]",
            f"if {{$e2_observed_idcode != 0x{idcode:08x}}} {{error \"E2_IDCODE_MISMATCH actual=$e2_observed_idcode expected=0x{idcode:08x}\"}}",
        ]
    commands += ["reset halt", "poll off", f"echo {READY}"]
    return commands


def gdb_commands(elf, gdb_port, expected):
    done = expected["done"]
    lines = [
        "set confirm off",
        "set pagination off",
        "set remotetimeout 60",
        "python",
        "import gdb",
        "def reg(name):",
        "    return int(gdb.parse_and_eval('$' + name)) & 0xffffffff",
        "def word(address):",
        "    return int(gdb.parse_and_eval('*(unsigned int*)' + hex(address))) & 0xffffffff",
        "def flush():",
        "    gdb.execute('maintenance flush register-cache', to_string=True)",
        "def require(condition, message):",
        "    if not condition:",
        "        raise RuntimeError(message)",
        "try:",
        f"    gdb.execute('file ' + {str(elf)!r}, to_string=True)",
        f"    gdb.execute('target extended-remote 127.0.0.1:{gdb_port}', to_string=True)",
        "    require(reg('zero') == 0, 'zero register changed')",
        "    gdb.execute('set $s0 = 0x89abcdef')",
        "    flush()",
        "    require(reg('s0') == 0x89abcdef, 's0 write/read failed')",
        "    gdb.execute('set $a0 = 0x13579bdf')",
        "    flush()",
        "    require(reg('a0') == 0x13579bdf, 'a0 write/read failed')",
        "    gdb.execute('set $mscratch = 0x51a7c0de')",
        "    flush()",
        "    require(reg('mscratch') == 0x51a7c0de, 'mscratch write/read failed')",
        "    gdb.execute('set $mscratch = 0xa5a55a5a')",
        "    flush()",
        "    require(reg('mscratch') == 0xa5a55a5a, 'second mscratch write/read failed')",
        f"    gdb.execute('set {{unsigned int}}{SCRATCH:#x} = 0xc001d00d')",
        f"    require(word({SCRATCH:#x}) == 0xc001d00d, 'abstract memory write/read failed')",
        f"    gdb.execute('set {{unsigned int}}{SCRATCH + 4:#x} = 0x10293847')",
        f"    require(word({SCRATCH + 4:#x}) == 0x10293847, 'second abstract memory write/read failed')",
        "    gdb.write(gdb.execute('load', to_string=True))",
        "    comparison = gdb.execute('compare-sections', to_string=True)",
        "    gdb.write(comparison)",
        "    require('matched.' in comparison.lower() and 'mis-matched' not in comparison.lower(), 'ELF compare-sections failed')",
        "    gdb.execute('monitor reset halt', to_string=True)",
        "    flush()",
        "    require(reg('pc') == 0, 'reset halt did not restore the reset vector')",
        "    gdb.execute('stepi', to_string=True)",
        f"    require(reg('pc') == {expected['stepPc']:#x}, 'stepi advanced to the wrong PC')",
    ]
    if expected["stepRd"]:
        lines.append(f"    require(reg({expected['stepRegister']!r}) == {expected['stepValue']:#x}, 'stepi register result differs')")
    lines += [
        f"    gdb.execute('break *{done:#x}', to_string=True)",
        "    gdb.execute('continue', to_string=True)",
        "    flush()",
        f"    require(reg('pc') == {done:#x}, 'continue did not reach the loaded completion breakpoint')",
        f"    require(word({expected['signatureAddress']:#x}) == {expected['signature']:#x}, 'loaded code signature is not visible')",
        f"    require(word({expected['productAddress']:#x}) == {expected['product']:#x}, 'loaded M-extension result is not visible')",
        "    gdb.execute('delete breakpoints', to_string=True)",
        f"    gdb.write('{GDB_ACCEPTED}\\n')",
        "except Exception as error:",
        "    gdb.write('E2_GDB_FAILURE: ' + str(error) + '\\n')",
        "    gdb.execute('quit 1')",
        "end",
        "disconnect",
        "quit",
    ]
    return "\n".join(lines) + "\n"


def workload_expectations(image):
    initial = Model(image.memory, enable_m=True, enable_c=True)
    event = initial.step()
    if event.trap or not event.rd:
        raise ValueError("Workload entry does not provide a visible single-step result")
    registers = ["zero", "ra", "sp", "gp", "tp", "t0", "t1", "t2", "s0", "s1",
                 "a0", "a1", "a2", "a3", "a4", "a5", "a6", "a7", "s2", "s3",
                 "s4", "s5", "s6", "s7", "s8", "s9", "s10", "s11", "t3", "t4", "t5", "t6"]
    model = Model(image.memory, enable_m=True, enable_c=True)
    for _ in range(100000):
        if model.pc == image.symbols["software_done"]:
            break
        model.step()
    else:
        raise ValueError("Independent workload model did not complete")
    return {"entry": image.entry, "stepPc": event.next_pc, "stepWord": event.word,
            "stepRd": event.rd, "stepRegister": registers[event.rd], "stepValue": event.value,
            "done": image.symbols["software_done"],
            "signatureAddress": image.symbols["software_signature"],
            "signature": model.word(image.symbols["software_signature"]),
            "productAddress": image.symbols["software_product"],
            "product": model.word(image.symbols["software_product"]),
            "console": list(b"E2\n")}


def check_abstract_evidence(openocd_log, trace):
    if ABSTRACT_ONLY not in openocd_log or READY not in openocd_log:
        raise ValueError("OpenOCD did not confirm abstract-only configuration and readiness")
    if re.search(r"riscv\s+(?:set_)?mem_access\s+(?:progbuf|sysbus)\b", openocd_log, re.IGNORECASE):
        raise ValueError("OpenOCD log selected a forbidden memory access method")
    if re.search(r"Succeeded to (?:read|write) memory via (?:progbuf|sysbus)", openocd_log, re.IGNORECASE):
        raise ValueError("OpenOCD used a forbidden memory access fallback")
    for direction in ("read", "write"):
        if not re.search(rf"Succeeded to {direction} memory via abstract access\b", openocd_log, re.IGNORECASE):
            raise ValueError(f"OpenOCD log lacks a successful abstract memory {direction}")
    reads = writes = 0
    for line in trace.splitlines():
        fields = line.split()
        if not fields or fields[0] != "J":
            continue
        if len(fields) != 5:
            raise ValueError("Malformed DMI observation")
        _, _, address, operation, data = fields
        address, operation, data = int(address), int(operation), int(data)
        if operation != 2:
            continue
        if 0x20 <= address <= 0x2F or 0x38 <= address <= 0x3F:
            raise ValueError(f"Forbidden debug memory transport write at DMI {address:#x}")
        if address == 0x17 and data >> 24 == 2:
            writes += bool(data & (1 << 16))
            reads += not bool(data & (1 << 16))
    if not reads or not writes:
        raise ValueError("No observed abstract memory read/write command pair")
    return {"abstractMemoryReads": reads, "abstractMemoryWrites": writes,
            "programBufferWrites": 0, "systemBusWrites": 0}


def check_wrong_idcode(log, status, ready, actual, expected):
    if ready or status == 0:
        raise ValueError("Wrong IDCODE reached readiness or exited successfully")
    if status is None:
        raise ValueError("Wrong IDCODE did not terminate OpenOCD")
    match = re.search(r"E2_IDCODE_MISMATCH actual=(?:0x)?([0-9a-f]+) expected=(0x[0-9a-f]+)",
                      log, re.IGNORECASE)
    if not match or (int(match[1], 16), int(match[2], 16)) != (actual, expected):
        raise ValueError("Tool failure was not the requested IDCODE rejection")


def check_execution(trace, expected):
    retirements, console, words = [], [], {}
    resets = tdo = None
    for line in trace.splitlines():
        fields = line.split()
        if not fields:
            continue
        if fields[0] == "R" and len(fields) == 12:
            values = list(map(int, fields[1:]))
            retirements.append({"cycle": values[0], "pc": values[1], "word": values[2],
                                "nextPc": values[3], "rd": values[4], "value": values[6],
                                "trap": values[7]})
        elif fields[0] == "S" and len(fields) == 10:
            _, _, port, address, write, data, mask, _, _, fault = fields
            if port == "D" and int(address) == CONSOLE and int(write) and not int(fault):
                if int(mask) != 0xF:
                    raise ValueError("Console output is not a 32-bit MMIO write")
                console.append(int(data) & 0xFF)
        elif fields[0] == "W" and len(fields) == 3:
            words[int(fields[1])] = int(fields[2])
        elif fields[0] == "F" and len(fields) == 4:
            if resets is not None:
                raise ValueError("Duplicate simulator completion record")
            resets = int(fields[2]), int(fields[3])
        elif fields[0] == "E" and len(fields) == 3:
            if tdo is not None:
                raise ValueError("Duplicate TDO observation record")
            tdo = int(fields[1]), int(fields[2])
    if resets is None or resets[1] < 2:
        raise ValueError("Both requested reset-halt operations lacked systemReset evidence")
    if tdo is None or not tdo[0] or not tdo[1]:
        raise ValueError("No enabled jtag_tdoEnable sample was observed")
    if not any(item["pc"] == expected["entry"] and item["nextPc"] == expected["stepPc"] and
               item["word"] == expected["stepWord"] and item["rd"] == expected["stepRd"] and
               item["value"] == expected["stepValue"] and not item["trap"] for item in retirements):
        raise ValueError("Native retirement trace does not match the GDB single step")
    if console != expected["console"]:
        raise ValueError(f"Loaded code console writes differ: {console!r}")
    for key, address_key in (("signature", "signatureAddress"), ("product", "productAddress")):
        address = expected[address_key] & ~3
        if words.get(address) != expected[key]:
            raise ValueError(f"Final native memory does not contain the loaded code {key}")
    return {"externalResetPulses": resets[0], "debugResetPulses": resets[1],
            "tdoSamples": tdo[0], "tdoEnabledSamples": tdo[1],
            "retirements": len(retirements), "console": bytes(console).decode("ascii"),
            "finalSignature": expected["signature"], "finalProduct": expected["product"]}


def reserve_port():
    with socket.socket() as reservation:
        reservation.bind(("127.0.0.1", 0))
        return reservation.getsockname()[1]


def wait_for_simulator(process, trace, timeout):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError("Simulator exited before remote bitbang readiness")
        match = re.search(r"^B (\d+)$", trace.read_text(), re.MULTILINE)
        if match:
            return int(match[1])
        time.sleep(0.02)
    raise TimeoutError("Simulator remote bitbang listener timed out")


def wait_for_openocd(process, simulator, log, timeout):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if READY in log.read_text():
            return True
        if process.poll() is not None:
            return False
        if simulator.poll() is not None:
            raise RuntimeError("Simulator exited while OpenOCD was starting")
        time.sleep(0.05)
    return False


def stop_process(process, timeout=5):
    if process is None or process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout)


def run_case(binary, image, tools, directory, idcode, args, expected=None, wrong_idcode=None):
    directory.mkdir()
    trace, errors = directory / "simulator.trace", directory / "simulator.stderr"
    openocd_log, gdb_log = directory / "openocd.log", directory / "gdb.log"
    selected_idcode = idcode if wrong_idcode is None else wrong_idcode
    simulator = openocd = None
    with trace.open("w") as trace_output, errors.open("w") as error_output, openocd_log.open("w") as openocd_output:
        try:
            simulator = subprocess.Popen([str(binary), str(image), str(args.seed), str(args.delay),
                                          str(args.cycle_limit), "0"], stdout=trace_output,
                                         stderr=error_output, text=True)
            bitbang_port = wait_for_simulator(simulator, trace, args.timeout)
            gdb_port = reserve_port()
            configuration = openocd_configuration(bitbang_port, gdb_port, selected_idcode,
                                                  strict_idcode=wrong_idcode is not None)
            (directory / "openocd.cfg").write_text("\n".join(configuration) + "\n")
            openocd = subprocess.Popen([str(tools["openocd"][0]), "-d", "-f", str(directory / "openocd.cfg")],
                                       stdout=openocd_output, stderr=subprocess.STDOUT, text=True)
            ready = wait_for_openocd(openocd, simulator, openocd_log,
                                     args.timeout if wrong_idcode is None else min(args.timeout, 30))
            if wrong_idcode is not None:
                check_wrong_idcode(openocd_log.read_text(), openocd.poll(), ready, idcode, selected_idcode)
            else:
                if not ready:
                    raise RuntimeError("OpenOCD did not reach debug readiness: " + openocd_log.read_text()[-4000:])
                script = gdb_commands(expected["elf"], gdb_port, expected)
                (directory / "gdb.commands").write_text(script)
                with gdb_log.open("w") as gdb_output:
                    completed = subprocess.run([str(tools["gdb"][0]), "-q", "-nx", "-batch", "-x",
                                                str(directory / "gdb.commands")], check=False, stdout=gdb_output,
                                               stderr=subprocess.STDOUT, text=True, timeout=args.timeout)
                output = gdb_log.read_text()
                if completed.returncode or output.count(GDB_ACCEPTED) != 1 or "E2_GDB_FAILURE" in output:
                    raise RuntimeError(f"GDB acceptance failed with status {completed.returncode}: {output[-4000:]}")
                if "matched." not in output.lower() or "mis-matched" in output.lower():
                    raise RuntimeError("GDB log lacks successful section comparison")
        finally:
            stop_process(openocd)
            if simulator is not None:
                try:
                    simulator.wait(10)
                except subprocess.TimeoutExpired:
                    stop_process(simulator)
    if simulator is None or simulator.returncode:
        raise RuntimeError(f"Simulator failed: {errors.read_text()} {trace.read_text()[-2000:]}")
    trace_text = trace.read_text()
    record = {"simulatorExitStatus": simulator.returncode,
              "openocdExitStatus": None if openocd is None else openocd.returncode,
              "traceSha256": digest(trace), "openocdLogSha256": digest(openocd_log)}
    if wrong_idcode is not None:
        record.update({"rejectedIdcode": selected_idcode, "actualIdcode": idcode, "rejected": True})
        return record
    record.update(check_abstract_evidence(openocd_log.read_text(), trace_text))
    record.update(check_execution(trace_text, expected))
    record["gdbLogSha256"] = digest(gdb_log)
    return record


def compile_simulator(rtl, manifest, tool, output):
    command = [str(tool), "--cc", "--exe", "--build", "-j", "2", "--top-module", "DitDahE2",
               "--Mdir", str(output / "build"), "-CFLAGS", "-std=c++17",
               *[str(rtl / name) for name in manifest["rtlHashes"]],
               str(ROOT / "test/test_debug_host/jtag_sim.cpp")]
    result = subprocess.run(command, check=False, cwd=ROOT, capture_output=True, text=True)
    (output / "compile.log").write_text(result.stdout + result.stderr)
    if result.returncode:
        raise RuntimeError("Host simulator compilation failed; no functional acceptance was run")
    return output / "build/VDitDahE2"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rtl", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--openocd")
    parser.add_argument("--gdb")
    parser.add_argument("--compiler")
    parser.add_argument("--objdump")
    parser.add_argument("--verilator")
    parser.add_argument("--seed", type=lambda value: int(value, 0), default=1)
    parser.add_argument("--delay", type=lambda value: int(value, 0), default=3)
    parser.add_argument("--cycle-limit", type=lambda value: int(value, 0), default=50000000)
    parser.add_argument("--timeout", type=float, default=180)
    args = parser.parse_args()
    if args.seed < 0 or args.seed > 0xFFFFFFFF or args.delay < 0 or args.cycle_limit <= 0 or args.timeout <= 0:
        parser.error("Invalid seed, delay, cycle limit or timeout")
    os.chdir(ROOT)
    rtl, output = args.rtl.resolve(), args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    report = {"scope": "real OpenOCD and GDB over JTAG remote_bitbang using abstract memory only",
              "exitStatus": 1, "runs": [], "negativeControls": []}
    try:
        manifest_data = (rtl / "manifest.json").read_bytes()
        manifest = json.loads(manifest_data)
        idcode = validate_manifest(manifest)
        if manifest["sourceHashes"] != sources():
            raise ValueError("Generated RTL source inputs are stale")
        for name, value in manifest["rtlHashes"].items():
            if digest(rtl / name) != value:
                raise ValueError(f"Generated RTL changed: {name}")
        report.update({"parameters": manifest["parameters"],
                       "rtlManifestSha256": hashlib.sha256(manifest_data).hexdigest(),
                       "sourceHashes": manifest["sourceHashes"], "rtlHashes": manifest["rtlHashes"]})
        tools = {}
        for name, value, environment, default in (
                ("openocd", args.openocd, "E2_DEBUG_OPENOCD", "openocd"),
                ("gdb", args.gdb, "E2_DEBUG_GDB", "riscv32-none-elf-gdb"),
                ("compiler", args.compiler, "E2_DEBUG_CC", "riscv32-none-elf-gcc"),
                ("objdump", args.objdump, "E2_DEBUG_OBJDUMP", "riscv32-none-elf-objdump"),
                ("verilator", args.verilator, "E2_DEBUG_VERILATOR", "verilator")):
            tools[name] = resolve_tool(value, environment, default)
        report["tools"] = {name: info for name, (_, info) in tools.items()}
        software = build_software(output / "software", str(tools["compiler"][0]), str(tools["objdump"][0]),
                                  reset_vector=0, enable_m=True, enable_c=True)
        elf = (output / "software/program.elf").resolve()
        image = load_elf(elf, reset_vector=0, enable_c=True)
        expected = workload_expectations(image) | {"elf": elf}
        binary = compile_simulator(rtl, manifest, tools["verilator"][0], output)
        initial = output / "initial.hex"
        initial.write_text("00000000 0000006f\n")
        report["workload"] = {"elfSha256": digest(elf), "softwareManifestSha256": digest(output / "software/manifest.json"),
                              "isa": software["isa"], "expectedSignature": expected["signature"],
                              "expectedProduct": expected["product"]}
        positive = run_case(binary, initial, tools, output / "openocd-gdb", idcode, args, expected=expected)
        report["runs"].append(positive)
        negative = run_case(binary, initial, tools, output / "wrong-idcode", idcode, args,
                            wrong_idcode=idcode ^ 1)
        report["negativeControls"].append(negative)
        if sources() != manifest["sourceHashes"]:
            raise RuntimeError("Source inputs changed during host acceptance")
        for name, value in manifest["rtlHashes"].items():
            if digest(rtl / name) != value:
                raise RuntimeError("Generated RTL changed during host acceptance")
        report["exitStatus"] = 0
    except Exception as error:
        report["failure"] = str(error)
        raise
    finally:
        (output / "summary.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print("PASS: OpenOCD/GDB abstract JTAG acceptance and wrong-IDCODE rejection")


if __name__ == "__main__":
    main()
