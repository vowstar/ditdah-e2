# SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
# SPDX-License-Identifier: MIT
"""Validate platform regions and generate software and simulation maps."""

import argparse
import json
from pathlib import Path

from build_rtl import configuration


ROOT = Path(__file__).resolve().parents[1]
REGIONS = ("rom", "sram", "console", "timer")
LOCAL_REGIONS = ("itcm", "dtcm")
NOTICE = "SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>\nSPDX-License-Identifier: MIT"


def validate(value):
    if (not isinstance(value, dict) or not set(REGIONS) <= set(value)
            or not set(value) <= set(REGIONS + LOCAL_REGIONS)):
        raise ValueError("Platform requires rom, sram, console and timer, with optional itcm and dtcm")
    result = {}
    for name in (*REGIONS, *(key for key in LOCAL_REGIONS if key in value)):
        region = value[name]
        local = name in LOCAL_REGIONS
        allowed = {"base", "size", "readLatency", "backend"} if local else {"base", "size"}
        if (not isinstance(region, dict) or not {"base", "size"} <= set(region)
                or not set(region) <= allowed):
            raise ValueError(f"{name} requires base and size")
        base, size = region["base"], region["size"]
        if type(base) is not int or type(size) is not int or not (
                0 <= base <= 0xFFFFFFFF and 4 <= size <= 0x100000000
                and base % 4 == size % 4 == 0 and base + size <= 0x100000000):
            raise ValueError(f"{name} must fit RV32 and contain whole words")
        if name == "console" and size < 8 or name == "timer" and size < 20:
            raise ValueError(f"{name} must contain its registers")
        if any(base < other["base"] + other["size"] and other["base"] < base + size
               for other in result.values()):
            raise ValueError("Platform regions must not overlap")
        result[name] = {"base": base, "size": size}
        if local:
            if size > 0x7FFFFFFF:
                raise ValueError(f"{name} size exceeds the supported SRAM geometry")
            latency = region.get("readLatency", 1)
            backend = region.get("backend", "sram")
            if type(latency) is not int or latency not in (1, 2):
                raise ValueError(f"{name} requires one or two read cycles")
            if backend not in ("sram", "axi"):
                raise ValueError(f"{name} backend must be sram or axi")
            result[name].update(readLatency=latency, backend=backend)
    return result


def parameters(regions, core):
    regions = validate(regions)
    core = configuration(core)
    rom = regions["rom"]
    if not rom["base"] <= core["resetVector"] < rom["base"] + rom["size"]:
        raise ValueError("Platform reset vector must be inside ROM")
    result = {"core": core}
    for name, region in regions.items():
        if name in LOCAL_REGIONS:
            result[name] = {"baseAddress": region["base"], "sizeBytes": region["size"],
                            "readLatency": region["readLatency"], "useSram": region["backend"] == "sram"}
            continue
        prefix = "ram" if name == "sram" else name
        result[prefix + "Base"] = region["base"]
        result[prefix + "Size"] = region["size"]
    if core["enableA"] and any(name in regions for name in LOCAL_REGIONS):
        raise ValueError("Local banks require the ordinary platform")
    return result


def artifacts(value):
    regions = validate(value)
    header = "/* " + NOTICE.replace("\n", "\n * ") + " */\n#ifndef DITDAH_PLATFORM_H\n#define DITDAH_PLATFORM_H\n\n"
    for name, region in regions.items():
        for field, value in region.items():
            if field == "backend":
                header += f"#define DITDAH_{name.upper()}_LOCAL {int(value == 'sram')}\n"
                continue
            header += f"#define DITDAH_{name.upper()}_{field.upper()} 0x{value:08x}UL\n"
    header += "\n#endif\n"
    linker = "/* " + NOTICE.replace("\n", "\n * ") + " */\nMEMORY\n{\n"
    for name, permissions in (("rom", "rx"), ("sram", "rwx"),
                              *((key, "rwx") for key in LOCAL_REGIONS if key in regions)):
        region = regions[name]
        linker += f"  {name.upper()} ({permissions}) : ORIGIN = 0x{region['base']:08x}, LENGTH = 0x{region['size']:x}\n"
    linker += "}\n"
    return {"platform.h": header, "memory.ld": linker,
            "map.json": json.dumps(regions, indent=2) + "\n"}


def write(value, output):
    contents = artifacts(value)
    output.mkdir(parents=True, exist_ok=True)
    for name, content in contents.items():
        (output / name).write_text(content)
    return contents


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--platform", type=Path, default=ROOT / "platform.json")
    parser.add_argument("--output", type=Path, default=Path("result/platform-map"))
    args = parser.parse_args()
    write(json.loads(args.platform.read_text()), args.output)
    print("Generated platform address maps")


if __name__ == "__main__":
    main()
