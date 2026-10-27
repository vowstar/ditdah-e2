# SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
# SPDX-License-Identifier: MIT
"""Compare fixed atomic signatures through the shared SRAM platform."""

import argparse
from dataclasses import replace
import hashlib
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
LOCAL = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "test"))
sys.path.insert(0, str(ROOT / "scripts"))
from atomic_programs import AtomicCase
from elf import Region, load_elf
from isa_checks import compare_signatures, digest, normalize_elf, signature_words
import platform_map
import verify_atomic
from build_rtl import configuration

REVISION = "fc32e41d49480fd99ba0a192dfff9c3319b44873"
TESTS = ("amoadd.w", "amoand.w", "amomax.w", "amomaxu.w", "amomin.w",
         "amominu.w", "amoor.w", "amoswap.w", "amoxor.w")


def selected_tests(requested):
    selected = list(TESTS) if requested is None else requested
    if "amoadd.w" not in selected or len(set(selected)) != len(selected):
        raise ValueError("Select unique atomic tests including amoadd.w for the RTL control")
    return ["amoadd.w", *[name for name in selected if name != "amoadd.w"]]


def validate_profile(manifest):
    parameters, regions = manifest["parameters"]["core"], manifest["regions"]
    if parameters != configuration(parameters):
        raise ValueError("Incomplete atomic core configuration")
    if not parameters["enableA"] or any(parameters.get(name, False) for name in
            ("protectedMode", "enableDebug", "enableZba", "enableZbb", "enableZbs")):
        raise ValueError("Atomic ISA tests require the machine atomic profile")
    if parameters["resetVector"] != regions["rom"]["base"]:
        raise ValueError("Atomic boot must start at the ROM base")
    if any(type(regions[name][key]) is not int for name in ("rom", "sram") for key in ("base", "size")):
        raise ValueError("Invalid atomic memory map")
    return parameters, regions


def atomic_specification(parameters):
    text = (LOCAL / "isa.yaml").read_text()
    isa = "RV32I" + ("M" if parameters["enableM"] else "") + "A" + ("C" if parameters["enableC"] else "") + "Zicsr"
    extensions = 0x101 | (0x1000 if parameters["enableM"] else 0) | (4 if parameters["enableC"] else 0)
    for old, new in (("RV32IZicsr", isa), ("0x40000100", hex(0x40000000 | extensions)),
                     ("[0x100]", f"[{hex(extensions)}]")):
        if text.count(old) != 1:
            raise ValueError("Architectural ISA template changed")
        text = text.replace(old, new)
    return text


def check_specification(parameters, output):
    from riscv_config.checker import check_isa_specs
    from riscv_config.errors import ValidationError
    import riscv_config.constants as constants

    specification = atomic_specification(parameters)
    path = output / "isa.yaml"
    path.write_text(specification)
    check_isa_specs(str(path), str(output), dump_yaml=False)
    bad = output / "misa-mismatch.yaml"
    value = 0x40000101 | (0x1000 if parameters["enableM"] else 0) | (4 if parameters["enableC"] else 0)
    bad.write_text(specification.replace(f"reset-val: {value:#x}", f"reset-val: {value ^ 1:#x}"))
    try:
        check_isa_specs(str(bad), str(output), dump_yaml=False)
    except ValidationError as error:
        if "reset value does not match with extensions enabled" not in str(error):
            raise
    else:
        raise AssertionError("ISA validator accepted missing misa.A")
    package = Path(constants.__file__).parent
    return {"accepted": True, "misaMismatchRejected": True, "inputHash": digest(path),
            "negativeHash": digest(bad), "validatorHashes": {name: digest(package / name) for name in
                ("constants.py", "isa_validator.py", "schemaValidator.py")}}


def mutable_bytes(image, regions):
    ram = regions["sram"]
    result = {}
    for segment in image.segments:
        if not segment.flags & 2:
            continue
        if not (ram["base"] <= segment.address and segment.address + segment.memory_size <= ram["base"] + ram["size"]):
            raise ValueError("Writable ELF segment exceeds SRAM")
        if segment.address % 4 or segment.memory_size % 4:
            raise ValueError("Atomic boot requires complete SRAM words")
        for address in range(segment.address, segment.address + segment.memory_size):
            if address in result:
                raise ValueError("Overlapping SRAM initialization")
            result[address] = image.memory[address]
    if not result:
        raise ValueError("Missing SRAM initialization")
    return result


def init_pairs(contents):
    if not contents or any(address & ~3 not in contents for address in contents):
        raise ValueError("Incomplete initialization word")
    pairs = []
    for address in sorted({address & ~3 for address in contents}):
        if any(address + lane not in contents for lane in range(4)):
            raise ValueError("Incomplete initialization word")
        pairs.append((address, sum(contents[address + lane] << (8 * lane) for lane in range(4))))
    return pairs


def init_assembly(pairs):
    return ("""/* SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com> */
/* SPDX-License-Identifier: MIT */
.section .atomic_init,"a",@progbits
.balign 4
.global atomic_init_begin, atomic_init_end
atomic_init_begin:
""" +
            "".join(f".word 0x{address:08x}, 0x{value:08x}\n" for address, value in pairs) +
            "atomic_init_end:\n.word 0\n")


def image_at(path, parameters, regions):
    return load_elf(path, reset_vector=parameters["resetVector"], enable_c=parameters["enableC"],
                    regions=tuple(Region(name, regions[name]["base"], regions[name]["size"], flags)
                                  for name, flags in (("rom", 5), ("sram", 7))))


def check_initialization(layout, executable, regions, pairs):
    if mutable_bytes(layout, regions) != mutable_bytes(executable, regions):
        raise ValueError("Final link changed SRAM initialization")
    begin, end = (executable.symbols[name] for name in ("atomic_init_begin", "atomic_init_end"))
    expected = b"".join(struct.pack("<II", *item) for item in pairs)
    actual = bytes(executable.memory[address] for address in range(begin, end))
    if actual != expected:
        raise ValueError("Boot table differs from ELF SRAM bytes")


def rom_image(image, regions):
    base, size = (regions["rom"][name] for name in ("base", "size"))
    return {address: value for address, value in image.words().items() if base <= address < base + size}


def change_rom_word(data, address):
    changed = bytearray(data)
    offset, = struct.unpack_from("<I", data, 28)
    size, count = struct.unpack_from("<HH", data, 42)
    for index in range(count):
        kind, file_offset, virtual, physical, file_size, _, flags, _ = struct.unpack_from("<8I", data, offset + index * size)
        if kind == 1 and virtual <= address and address + 4 <= virtual + file_size:
            if virtual != physical or flags & 2 or address % 4:
                raise ValueError("Invalid initialization mutation location")
            changed[file_offset + address - virtual] ^= 1
            return bytes(changed)
    raise ValueError("Initialization mutation is outside ROM file data")


def run_command(command, directory, name, commands, *, timeout=300):
    try:
        process = subprocess.run(command, cwd=directory, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired as error:
        for suffix, value in (("stdout", error.stdout), ("stderr", error.stderr)):
            (directory / (name + "." + suffix)).write_bytes(value.encode() if isinstance(value, str) else value or b"")
        commands.append({"argv": list(map(str, command)), "exitStatus": None, "timeoutSeconds": timeout})
        raise
    (directory / (name + ".stdout")).write_text(process.stdout)
    (directory / (name + ".stderr")).write_text(process.stderr)
    commands.append({"argv": list(map(str, command)), "exitStatus": process.returncode})
    if process.returncode:
        raise RuntimeError(f"{name} exited with status {process.returncode}")
    return process.stdout


def compile_program(source, output, parameters, regions, commands):
    output.mkdir(parents=True)
    platform_map.write(regions, output)
    headers = {"data": "data PT_LOAD FLAGS(6);", "code": "code PT_LOAD FLAGS(5);", "init": "init PT_LOAD FLAGS(4);"}
    order = ("data", "code", "init") if regions["sram"]["base"] < regions["rom"]["base"] else ("code", "init", "data")
    template = (LOCAL / "atomic_env/link.ld").read_text()
    assert template.count("@PROGRAM_HEADERS@") == 1
    (output / "link.ld").write_text(template.replace("@PROGRAM_HEADERS@", " ".join(headers[name] for name in order)))
    march = "rv32i" + ("m" if parameters["enableM"] else "") + "a" + ("c" if parameters["enableC"] else "") + "_zicsr"
    compiler = ["riscv32-none-elf-gcc", "-march=" + march, "-mabi=ilp32", "-mcmodel=medany", "-mno-relax",
                "-nostdlib", "-nostartfiles", "-static", "-Wl,--build-id=none,--discard-all", "-T", "link.ld",
                "-DXLEN=32", "-DTEST_CASE_1=1", "-I", str(LOCAL / "env"), "-I", str(source.parents[3] / "env"),
                str(LOCAL / "atomic_env/boot.S"), str(source), "initialization.S"]
    (output / "initialization.S").write_text(init_assembly([]))
    run_command(compiler + ["-o", "layout.raw.elf"], output, "layout", commands)
    (output / "layout.elf").write_bytes(normalize_elf((output / "layout.raw.elf").read_bytes(), enable_c=parameters["enableC"]))
    layout = image_at(output / "layout.elf", parameters, regions)
    pairs = init_pairs(mutable_bytes(layout, regions))
    (output / "initialization.S").write_text(init_assembly(pairs))
    run_command(compiler + ["-o", "test.raw.elf"], output, "compile", commands)
    (output / "test.elf").write_bytes(normalize_elf((output / "test.raw.elf").read_bytes(), enable_c=parameters["enableC"]))
    image = image_at(output / "test.elf", parameters, regions)
    check_initialization(layout, image, regions, pairs)
    (output / "initialization.json").write_text(json.dumps({"pairs": pairs, "wordCount": len(pairs),
        "layoutElfHash": digest(output / "layout.elf"), "elfHash": digest(output / "test.elf")}, indent=2) + "\n")
    return image, march, pairs


def stimulus(case, output):
    (output / "image.hex").write_text("".join(f"{address:08x} {value:08x}\n" for address, value in sorted(case.image.items())))
    (output / "events.txt").write_text("0\n" + str(len(case.signature)) + "\n" +
                                      "\n".join(map(str, sorted(case.signature))) + "\n0\n0\n")


def check_execution(binary, case, parameters, regions, output, commands, seed, delay):
    output.mkdir()
    stimulus(case, output)
    trace = run_command([str(binary), "image.hex", "events.txt", str(seed), str(delay), str(case.completion_pc)],
                        output, "rtl", commands, timeout=900)
    metrics = verify_atomic.check(case, parameters, regions, trace)
    values = {int(fields[2]): int(fields[3]) for line in trace.splitlines()
              if (fields := line.split())[0] == "V"}
    return trace, metrics, values


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--design", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--test", choices=TESTS, action="append", help="Include amoadd.w for the RTL negative control")
    parser.add_argument("--delay", type=int, action="append")
    args = parser.parse_args()
    design, output = args.design.resolve(), args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    manifest = json.loads((design / "manifest.json").read_text())
    parameters, regions = validate_profile(manifest)
    selected = selected_tests(args.test)
    delays = args.delay if args.delay is not None else [0, 9, 24]
    if not delays or any(value < 0 or value > 40 for value in delays):
        raise ValueError("Invalid atomic response delay")
    suite = Path(os.environ["ARCH_TEST_SOURCE"]) / "riscv-test-suite"
    available = {p.name for p in (suite / "rv32i_m/A/src").glob("*.S")}
    if available != {name + "-01.S" for name in TESTS}:
        raise ValueError("Fixed atomic test collection changed")
    checker = verify_atomic.inputs()
    for path in [Path(__file__), ROOT / "test/elf.py", ROOT / "test/test_atomic_isa.py",
                 *sorted((LOCAL / "atomic_env").glob("*")), *sorted(LOCAL.glob("*.py")),
                 LOCAL / "env/model_test.h", LOCAL / "isa.yaml", ROOT / "nix/isa-tools.nix", ROOT / "flake.lock"]:
        checker[str(path.relative_to(ROOT))] = digest(path)
    verify_atomic.preserve(output / "inputs/checker", ROOT, checker)
    verify_atomic.preserve(output / "design/inputs", design / "inputs", manifest["sourceHashes"])
    verify_atomic.preserve(output / "design/rtl", design / "rtl", manifest["rtlHashes"])
    shutil.copyfile(design / "manifest.json", output / "design/manifest.json")
    shutil.copyfile(design / "map.json", output / "design/map.json")
    wrapper = output / "AtomicBench.sv"
    wrapper.write_text(verify_atomic.observer(output / "design/rtl", regions["sram"]["size"]))
    flags = ("-std=c++17 -DDITDAH_E2_ENABLE_DEBUG=0 " +
             f"-DDITDAH_E2_ROM_BASE={regions['rom']['base']}ULL -DDITDAH_E2_ROM_SIZE={regions['rom']['size']}ULL " +
             "-DDITDAH_E2_MAX_CYCLES=1000000")
    report = {"revision": REVISION, "parameters": parameters, "regions": regions, "tests": [],
              "checkerHashes": checker, "manifestHash": digest(design / "manifest.json"), "tools": {},
              "compileFlags": flags, "wrapperHash": digest(wrapper), "commands": [], "exitStatus": None,
              "environmentHashes": {str(p.relative_to(suite)): digest(p) for p in sorted((suite / "env").rglob("*")) if p.is_file()},
              "scope": "Nine AMO signature tests on shared SRAM, without external LR/SC coverage"}
    try:
        commands = report["commands"]
        report["isaValidation"] = check_specification(parameters, output)
        for tool in ("verilator", "riscv32-none-elf-gcc", "spike", "python3"):
            option = "--help" if tool == "spike" else "--version"
            run_command([tool, option], output, tool + "-identity", commands)
            text = (output / (tool + "-identity.stdout")).read_text() + (output / (tool + "-identity.stderr")).read_text()
            report["tools"][tool] = {"sha256": digest(Path(shutil.which(tool))), "version": text.splitlines()[0]}
        run_command(["verilator", "--cc", "--exe", "--build", "-j", "2", "--top-module", "AtomicBench",
                     "--Mdir", str(output / "build"), "-CFLAGS", flags, str(wrapper),
                     *[str(output / "design/rtl" / name) for name in manifest["rtlHashes"]],
                     str(output / "inputs/checker/test/atomic_sim.cpp")], output, "build", commands, timeout=900)
        binary = output / "build/VAtomicBench"
        report["binaryHash"] = digest(binary)
        first_case = None
        for name in selected:
            source = suite / "rv32i_m/A/src" / (name + "-01.S")
            text = source.read_text()
            if text.count('RVTEST_ISA("RV32IA")') != 1 or text.count("TEST_AMO_OP(") != 69:
                raise ValueError("Fixed atomic source contract changed")
            work = output / name
            image, march, pairs = compile_program(source, work, parameters, regions, commands)
            begin, end, complete, tohost = (image.symbols[key] for key in
                ("begin_signature", "end_signature", "test_complete", "tohost"))
            if begin % 4 or end <= begin or end % 4 or image.words().get(complete) != 0x6F or complete % 4:
                raise ValueError("Invalid signature or completion boundary")
            memory = ",".join(f"{regions[key]['base']:#x}:{regions[key]['size']:#x}" for key in ("sram", "rom"))
            run_command(["spike", "--isa=" + march, "--priv=m", "-m" + memory,
                         "+signature=" + str(work / "spike.signature"), "+signature-granularity=4", str(work / "test.elf")],
                        work, "spike", commands)
            words = signature_words((work / "spike.signature").read_text())
            if len(words) != (end - begin) // 4:
                raise ValueError("Incomplete reference signature")
            signature = dict(zip(range(begin, end, 4), words))
            case = AtomicCase(name, rom_image(image, regions), signature | {tohost: 1}, completion_pc=complete)
            if first_case is None:
                first_case = case
            record = {"name": name, "sourceHash": digest(source), "elfHash": digest(work / "test.elf"),
                      "rawElfHash": digest(work / "test.raw.elf"), "initializationWords": len(pairs),
                      "signatureWords": len(words), "referenceSignatureHash": digest(work / "spike.signature"), "runs": []}
            report["tests"].append(record)
            for seed, delay in enumerate(delays):
                run = work / f"run-{seed}-{delay}"
                trace, metrics, values = check_execution(binary, case, parameters, regions, run, commands, seed, delay)
                actual = "".join(f"{values[address]:08x}\n" for address in range(begin, end, 4))
                (run / "rtl.signature").write_text(actual)
                compare_signatures((work / "spike.signature").read_text(), actual)
                if metrics["instructions"].get(name) != 69:
                    raise ValueError("Official AMO instances did not execute")
                record["runs"].append({"seed": seed, "delay": delay, "metrics": metrics,
                                       "traceHash": digest(run / "rtl.stdout"), "signatureHash": digest(run / "rtl.signature")})
            altered = dict(case.signature)
            altered[begin] ^= 1
            try:
                verify_atomic.check(replace(case, signature=altered), parameters, regions, trace)
            except AssertionError as error:
                if str(error) != "Atomic program signature differs":
                    raise
            else:
                raise AssertionError("Changed signature was accepted")
            record["signatureNegativeControl"] = True
            if name == selected[0]:
                table = image.symbols["atomic_init_begin"]
                index = next(i for i, pair in enumerate(pairs) if pair[0] == begin)
                changed = change_rom_word((work / "test.elf").read_bytes(), table + index * 8 + 4)
                (work / "bad-initialization.elf").write_bytes(changed)
                bad = image_at(work / "bad-initialization.elf", parameters, regions)
                bad_case = replace(case, image=rom_image(bad, regions))
                bad_run = work / "bad-initialization"
                bad_run.mkdir()
                stimulus(bad_case, bad_run)
                bad_trace = run_command([str(binary), "image.hex", "events.txt", "0", "0", str(complete)],
                                        bad_run, "rtl", commands, timeout=900)
                observed = {int(f[2]): int(f[3]) for line in bad_trace.splitlines() if (f := line.split())[0] == "V"}
                if observed.get(begin) != case.signature[begin] ^ 1:
                    raise AssertionError("Initialization fault did not reach SRAM")
                try:
                    verify_atomic.check(bad_case, parameters, regions, bad_trace)
                except AssertionError as error:
                    if str(error) != "Atomic program signature differs":
                        raise
                else:
                    raise AssertionError("Incorrect SRAM initialization was accepted")
                record["initializationNegativeControl"] = {"elfHash": digest(work / "bad-initialization.elf"),
                    "traceHash": digest(bad_run / "rtl.stdout"), "exitStatus": 0, "observedWrongWord": observed[begin]}
        negative = output / "rtl-negative"
        shutil.copytree(output / "design/rtl", negative / "rtl")
        changed_rtl = negative / "rtl/DitDahE2AtomicMemory.sv"
        changed_rtl.write_text(verify_atomic.mutate_atomic(changed_rtl.read_text(), "amo"))
        run_command(["verilator", "--cc", "--exe", "--build", "-j", "2", "--top-module", "AtomicBench",
                     "--Mdir", str(negative / "build"), "-CFLAGS", flags, str(wrapper),
                     *[str(negative / "rtl" / name) for name in manifest["rtlHashes"]],
                     str(output / "inputs/checker/test/atomic_sim.cpp")], negative, "build", commands, timeout=900)
        stimulus(first_case, negative)
        faulty_trace = run_command([str(negative / "build/VAtomicBench"), "image.hex", "events.txt", "0", "0",
                                    str(first_case.completion_pc)], negative, "rtl", commands, timeout=900)
        try:
            verify_atomic.check(first_case, parameters, regions, faulty_trace)
        except AssertionError as error:
            if str(error) != "Shared SRAM arbitration, response or write differs":
                raise
        else:
            raise AssertionError("Incorrect AMO RTL was accepted")
        report["rtlNegativeControl"] = {"kind": "amo-add-as-xor", "exitStatus": 0,
            "changedRtlHash": digest(changed_rtl), "traceHash": digest(negative / "rtl.stdout"),
            "binaryHash": digest(negative / "build/VAtomicBench")}
        if any(digest(ROOT / name) != value for name, value in checker.items()):
            raise ValueError("Atomic ISA checker inputs changed")
        if any(digest(output / "inputs/checker" / name) != value for name, value in checker.items()):
            raise ValueError("Frozen atomic ISA checker inputs changed")
        if any(digest(design / "rtl" / name) != value for name, value in manifest["rtlHashes"].items()):
            raise ValueError("Atomic RTL inputs changed")
        if digest(design / "manifest.json") != report["manifestHash"] or digest(wrapper) != report["wrapperHash"] or digest(binary) != report["binaryHash"]:
            raise ValueError("Atomic executable inputs changed")
        for record in report["tests"]:
            for key, path in (("elfHash", output / record["name"] / "test.elf"),
                              ("rawElfHash", output / record["name"] / "test.raw.elf"),
                              ("referenceSignatureHash", output / record["name"] / "spike.signature"),
                              ("sourceHash", suite / "rv32i_m/A/src" / (record["name"] + "-01.S"))):
                if digest(path) != record[key]:
                    raise ValueError("Atomic test artifact changed")
        report["exitStatus"] = 0
    except Exception:
        report["exitStatus"] = 1
        raise
    finally:
        for command in report["commands"]:
            command["argv"] = [value.replace(str(output), "<run>").replace(str(ROOT), "<source>").replace(str(suite), "<arch-tests>")
                               for value in command["argv"]]
        (output / "summary.json").write_text(json.dumps(report, indent=2) + "\n")
    print(f"PASS: {len(selected)} atomic tests and {69 * len(selected)} AMO instances per delay")


if __name__ == "__main__":
    main()
