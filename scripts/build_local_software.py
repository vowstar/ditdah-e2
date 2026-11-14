# SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
# SPDX-License-Identifier: MIT
"""Wrap a local-bank payload in a ROM-only executable that copies its images."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from test.common.elf import Region, load_elf
from build_software import tool
import platform_map


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def bank_images(payload, regions):
    """Include PT_LOAD zero-fill and address gaps through each bank's used extent."""
    raw = Path(payload).read_bytes()
    if len(raw) < 52 or raw[:7] != b"\x7fELF\x01\x01\x01":
        raise ValueError("Expected a little-endian ELF32 payload")
    entry, phoff = struct.unpack_from("<II", raw, 24)
    flags = struct.unpack_from("<I", raw, 36)[0]
    phsize, count = struct.unpack_from("<HH", raw, 42)
    if phsize != 32 or not count or phoff < 52 or phoff + count * phsize > len(raw):
        raise ValueError("Invalid payload program table")
    extents = dict.fromkeys(platform_map.LOCAL_REGIONS, 0)
    for index in range(count):
        kind, _, virtual, address, _, size, _, _ = struct.unpack_from("<8I", raw, phoff + index * phsize)
        if kind != 1:
            continue
        name = next((key for key in extents if regions[key]["base"] <= address
                     and address + size <= regions[key]["base"] + regions[key]["size"]), None)
        if name is None or virtual != address:
            raise ValueError("Payload load segments must use matching physical addresses inside local banks")
        extents[name] = max(extents[name], (address + size - regions[name]["base"] + 3) & ~3)
    if sum(extents.values()) > regions["rom"]["size"]:
        raise ValueError("Payload bank images exceed ROM capacity")
    memory_regions = tuple(Region(key, regions[key]["base"], regions[key]["size"], 7) for key in extents)
    image = load_elf(payload, reset_vector=entry, regions=memory_regions, enable_c=bool(flags & 1))
    banks = {key: bytearray(size) for key, size in extents.items()}
    for segment in image.segments:
        name = next(key for key in banks if regions[key]["base"] <= segment.address
                    < regions[key]["base"] + regions[key]["size"])
        offset = segment.address - regions[name]["base"]
        banks[name][offset:offset + len(segment.data)] = segment.data
    return image, {key: bytes(value) for key, value in banks.items()}


def linker(regions, entry):
    rom = regions["rom"]
    return f"""/* SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com> */
/* SPDX-License-Identifier: MIT */
OUTPUT_ARCH(riscv)
ENTRY(_start)
MEMORY {{ ROM (rx) : ORIGIN = 0x{rom['base']:08x}, LENGTH = 0x{rom['size']:x} }}
PHDRS {{ boot PT_LOAD FLAGS(5); }}
SECTIONS
{{
    .text ORIGIN(ROM) : {{ KEEP(*(.text.start)) *(.text .text.*) }} > ROM :boot
    .rodata ALIGN(4) : {{ *(.rodata.itcm) *(.rodata.dtcm) }} > ROM :boot
    /DISCARD/ : {{ *(.comment) *(.note*) *(.eh_frame*) }}
    __itcm_destination = 0x{regions['itcm']['base']:08x};
    __dtcm_destination = 0x{regions['dtcm']['base']:08x};
    __payload_entry = 0x{entry:08x};
}}
"""


def image_assembly():
    text = "# SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>\n# SPDX-License-Identifier: MIT\n"
    for key in platform_map.LOCAL_REGIONS:
        text += (f'.section .rodata.{key}, "a", @progbits\n.balign 4\n'
                 f'.globl __{key}_image_start, __{key}_image_end\n__{key}_image_start:\n'
                 f'.incbin "{key}.bin"\n__{key}_image_end:\n')
    return text


def build(payload, platform, output, compiler="riscv32-none-elf-gcc", objdump="riscv32-none-elf-objdump"):
    payload, platform, output = Path(payload), Path(platform), Path(output)
    if output.exists():
        raise ValueError("Local software output must not exist")
    regions = platform_map.validate(json.loads(platform.read_text()))
    if not set(platform_map.LOCAL_REGIONS) <= regions.keys():
        raise ValueError("Local software requires both itcm and dtcm regions")
    source_paths = {"payload.elf": payload, "platform.json": platform,
                    **{name: ROOT / name for name in ("software/local-start.S", "scripts/build_local_software.py",
                       "scripts/build_software.py", "scripts/platform_map.py", "test/common/elf.py", "flake.lock")}}
    source_hashes = {name: digest(path) for name, path in source_paths.items()}
    image, banks = bank_images(payload, regions)
    cc, cc_info = tool(compiler)
    disassembler, disassembler_info = tool(objdump)
    scratch = "/data/tmp" if os.access("/data/tmp", os.W_OK) else None
    with tempfile.TemporaryDirectory(prefix="ditdah-e2-local-software-", dir=scratch) as directory:
        work = Path(directory)
        shutil.copyfile(ROOT / "software/local-start.S", work / "local-start.S")
        for name, contents in banks.items():
            (work / f"{name}.bin").write_bytes(contents)
        (work / "bank-images.S").write_text(image_assembly())
        (work / "boot.ld").write_text(linker(regions, image.entry))
        flags = ["-march=rv32i_zifencei", "-mabi=ilp32", "-mno-relax", "-fno-pic", "-fno-pie",
                 "-nostdlib", "-nostartfiles", "-static", "-Wl,--build-id=none", "-Wl,--no-relax",
                 "-T", "boot.ld", "local-start.S", "bank-images.S", "-o", "program.elf"]
        environment = dict(os.environ, SOURCE_DATE_EPOCH="0", LC_ALL="C", TMPDIR=str(work))
        commands = [[cc_info["name"], *flags], [disassembler_info["name"], "-d", "-M", "no-aliases", "program.elf"]]
        result = subprocess.run([str(cc), *flags], cwd=work, env=environment,
                                capture_output=True, text=True)
        if result.returncode:
            raise ValueError("ROM wrapper assembly or link failed")
        listing = subprocess.check_output([str(disassembler), *commands[1][1:]], cwd=work,
                                          env=environment, text=True)
        (work / "program.dis").write_text(listing)
        rom = regions["rom"]
        boot = load_elf(work / "program.elf", reset_vector=rom["base"],
                        regions=(Region("rom", rom["base"], rom["size"], 5),))
        if len(boot.segments) != 1 or boot.symbols.get("__payload_entry") != image.entry:
            raise ValueError("ROM wrapper does not bind the payload entry")
        if any(digest(path) != source_hashes[name] for name, path in source_paths.items()):
            raise RuntimeError("Local software build inputs changed")
        if tool(compiler)[1] != cc_info or tool(objdump)[1] != disassembler_info:
            raise RuntimeError("Local software build tools changed")
        output.mkdir(parents=True)
        for name, path in source_paths.items():
            destination = output / "inputs" / name
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(path, destination)
        if any(digest(output / "inputs" / name) != value for name, value in source_hashes.items()):
            raise RuntimeError("Local software source snapshot changed")
        artifacts = ("program.elf", "program.dis", "itcm.bin", "dtcm.bin", "local-start.S", "bank-images.S", "boot.ld")
        for name in artifacts:
            shutil.copyfile(work / name, output / name)
        manifest = {"scope": "ROM-only software packing and ELF validation", "exitStatus": 0,
                    "resetVector": boot.entry, "payloadEntry": image.entry, "payloadElfFlags": image.flags,
                    "payloadSymbols": image.symbols,
                    "payloadSegments": [{"address": segment.address, "fileSize": len(segment.data),
                                         "memorySize": segment.memory_size, "flags": segment.flags}
                                        for segment in image.segments],
                    "regions": regions, "sourceHashes": source_hashes,
                    "tools": {"compiler": cc_info, "objdump": disassembler_info}, "commands": commands,
                    "banks": {key: {"address": regions[key]["base"], "imageBytes": len(value),
                                    "sha256": hashlib.sha256(value).hexdigest()} for key, value in banks.items()},
                    "segments": [{"address": segment.address, "fileSize": len(segment.data),
                                  "memorySize": segment.memory_size, "flags": segment.flags}
                                 for segment in boot.segments],
                    "artifactHashes": {name: digest(output / name) for name in artifacts},
                    "environment": {"SOURCE_DATE_EPOCH": "0", "LC_ALL": "C"}}
        (output / "manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    return manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--payload-elf", type=Path, required=True)
    parser.add_argument("--platform", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--compiler", default="riscv32-none-elf-gcc")
    parser.add_argument("--objdump", default="riscv32-none-elf-objdump")
    args = parser.parse_args()
    build(args.payload_elf, args.platform, args.output, args.compiler, args.objdump)
    print("Built ROM-only local-bank boot ELF")


if __name__ == "__main__":
    main()
