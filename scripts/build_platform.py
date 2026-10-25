# SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
# SPDX-License-Identifier: MIT
"""Generate platform RTL and bind its source, map, configuration and tools."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile

from build_rtl import digest
import platform_map


ROOT = Path(__file__).resolve().parents[1]
TOP = "DitDahE2PlatformTop"
WRAPPER = """// SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
// SPDX-License-Identifier: MIT
package ditdah_e2
import me.jiuyang.zaozi.*
import me.jiuyang.zaozi.default.{*, given}
import me.jiuyang.zaozi.reftpe.*
import me.jiuyang.zaozi.valuetpe.*
@generator
object DitDahE2 extends Generator[PlatformParameters, PlatformLayers, PlatformIO, PlatformProbe]:
  override def moduleName(p: PlatformParameters): String = "DitDahE2PlatformTop"
  def architecture(p: PlatformParameters) =
    val io = summon[Interface[PlatformIO]]
    val platform = DitDahE2Platform.instantiate(p)
    platform.io.clock := io.clock
    platform.io.reset := io.reset
    if p.core.enableDebug then platform.io.dmi.get :<>= io.dmi.get
    platform.io.tick := io.tick
    platform.io.externalInterrupt := io.externalInterrupt
    io.transmit :<>= platform.io.transmit
    io.axi :<>= platform.io.axi
    io.retire :<= platform.io.retire
    io.interrupt :<= platform.io.interrupt
    io.mulDiv :<= platform.io.mulDiv
    io.sleeping := platform.io.sleeping
    io.loadUse := platform.io.loadUse
    io.forward := platform.io.forward
    io.redirect := platform.io.redirect
    io.memoryWait := platform.io.memoryWait
    io.timeValue := platform.io.timeValue
    io.timerInterrupt := platform.io.timerInterrupt
    io.softwareInterrupt := platform.io.softwareInterrupt
"""


def compilation_sources(contents, atomic=False):
    result = dict(contents)
    substitutions = [("DitDahE2.scala", "object DitDahE2 extends", "object CoreImplementation extends")]
    for name in ("DitDahE2Platform.scala", "DitDahE2AtomicPlatform.scala"):
        if name in result:
            substitutions.append((name, "DitDahE2.instantiate(p.core)", "CoreImplementation.instantiate(p.core)"))
    for name, before, after in substitutions:
        if result[name].count(before) != 1:
            raise ValueError(f"Expected one generator reference in {name}")
        result[name] = result[name].replace(before, after)
    if "PlatformEntry.scala" in result:
        raise ValueError("PlatformEntry.scala is reserved for the generated wrapper")
    result["PlatformEntry.scala"] = (WRAPPER.replace("PlatformIO", "AtomicPlatformIO")
        .replace("DitDahE2Platform", "DitDahE2AtomicPlatform") +
        "    platform.io.competitor :<>= io.competitor\n") if atomic else WRAPPER
    return result


def build(output, platform_path=ROOT / "platform.json", core=None, *, atomic=False):
    output, platform_path = Path(output), Path(platform_path)
    if output.exists() and any(output.iterdir()):
        raise ValueError("Platform output directory must be empty")
    raw_map = platform_path.read_bytes()
    regions = platform_map.validate(json.loads(raw_map))
    params = platform_map.parameters(regions, {} if core is None else core)
    if params["core"]["enableA"] != atomic:
        raise ValueError("A instructions require the atomic platform")
    top = "DitDahE2AtomicPlatformTop" if atomic else TOP
    paths = sorted((ROOT / "ditdah_e2/src").glob("*.scala")) + sorted((ROOT / "nix").glob("*.nix"))
    paths += [ROOT / name for name in ("flake.nix", "flake.lock", "scripts/build_rtl.py",
                                      "scripts/build_platform.py", "scripts/platform_map.py", "test/test_platform_map.py")]
    if atomic:
        paths += [ROOT / "ditdah_e2/src/AtomicSram.sv", ROOT / "scripts/build_atomic_platform.py"]
    originals = {str(path.relative_to(ROOT)): path.read_bytes() for path in paths}
    compiled = compilation_sources({path.name: originals[str(path.relative_to(ROOT))].decode()
                                    for path in paths if path.suffix == ".scala"}, atomic)
    output.mkdir(parents=True, exist_ok=True)
    inputs = output / "inputs"
    for name, content in {**originals, "platform.json": raw_map}.items():
        destination = inputs / name
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(content)
    generated = inputs / "generated"
    (generated / "src").mkdir(parents=True)
    for name, content in compiled.items():
        (generated / "src" / name).write_text(content)
    platform_map.write(regions, output)
    (output / "parameters.json").write_text(json.dumps(params, indent=2) + "\n")
    for name in ("parameters.json", "map.json", "memory.ld", "platform.h"):
        shutil.copyfile(output / name, generated / name)
    tools = ("elaborate-ditdah-e2", "firld", "firtool")
    tool_hashes = {name: digest(Path(shutil.which(name))) for name in tools}
    commands = []
    report = {"top": top, "parameters": params, "regions": regions, "exitStatus": None,
              "scope": "platform RTL generation", "commands": commands,
              "sourceHashes": {name: hashlib.sha256(content).hexdigest() for name, content in originals.items()},
              "platformHash": hashlib.sha256(raw_map).hexdigest(),
              "generatedHashes": {str(path.relative_to(generated)): digest(path)
                                  for path in sorted(generated.rglob("*")) if path.is_file()},
              "toolHashes": tool_hashes,
              "firtool": subprocess.check_output(["firtool", "--version"], text=True).strip()}
    (output / "manifest.json").write_text(json.dumps(report, indent=2) + "\n")
    scratch = "/data/tmp" if os.access("/data/tmp", os.W_OK) else None
    with tempfile.TemporaryDirectory(prefix="ditdah-e2-platform-", dir=scratch) as directory:
        work = Path(directory)
        shutil.copytree(generated / "src", work / "src")
        shutil.copyfile(output / "parameters.json", work / "parameters.json")
        environment = dict(os.environ, DITDAH_E2_SOURCE=str(work / "src"))

        def run(command):
            result = subprocess.run(command, cwd=work, env=environment, capture_output=True, text=True)
            commands.append({"argv": command, "exitStatus": result.returncode})
            log = re.sub(r"\x1b\[[0-9;]*m", "", result.stdout + result.stderr)
            for private, public in ((str(work), "<work>"), (str(ROOT), "<source>")):
                log = log.replace(private, public)
            (output / f"command-{len(commands)}.log").write_text(log)
            (output / "commands.json").write_text(json.dumps(commands, indent=2) + "\n")
            report["exitStatus"] = result.returncode if result.returncode else None
            (output / "manifest.json").write_text(json.dumps(report, indent=2) + "\n")
            if result.returncode:
                raise RuntimeError(f"{command[0]} failed with status {result.returncode}")

        run(["elaborate-ditdah-e2", "design", "parameters.json"])
        run(["firld", *[path.name for path in sorted(work.glob("*.mlirbc"))], "--base-circuit", top,
             "--no-mangle", "--emit-bytecode", "-o", "linked.mlirbc"])
        run(["firtool", "linked.mlirbc", "--split-verilog", "-disable-all-randomization",
             "--lowering-options=noAlwaysComb,disallowLocalVariables,locationInfoStyle=none", "-o", "rtl"])
        if atomic:
            (work / "rtl/AtomicSram.sv").write_bytes(originals["ditdah_e2/src/AtomicSram.sv"])
        if not (work / "rtl" / f"{top}.sv").is_file() or not (work / "rtl/DitDahE2.sv").is_file():
            raise RuntimeError("Missing generated platform or core RTL")
        shutil.copytree(work / "rtl", output / "rtl")
        shutil.copyfile(work / "linked.mlirbc", output / "linked.mlirbc")
    if any((ROOT / name).read_bytes() != content for name, content in originals.items()) or platform_path.read_bytes() != raw_map:
        raise RuntimeError("Platform inputs changed during generation")
    rtl = sorted((output / "rtl").glob("*.sv"))
    (output / "rtl/filelist.f").write_text("\n".join(path.name for path in rtl) + "\n")
    report.update({"exitStatus": 0, "rtlHashes": {path.name: digest(path) for path in rtl},
                   "artifactHashes": {name: digest(output / name) for name in
                                      ("parameters.json", "map.json", "memory.ld", "platform.h", "linked.mlirbc")}})
    (output / "manifest.json").write_text(json.dumps(report, indent=2) + "\n")
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--platform", type=Path, default=ROOT / "platform.json")
    parser.add_argument("--config", type=Path)
    parser.add_argument("--output", type=Path, default=Path("result/platform-rtl"))
    args = parser.parse_args()
    build(args.output, args.platform, json.loads(args.config.read_text()) if args.config else {})
    print("Generated DitDahE2 platform RTL")


if __name__ == "__main__":
    main()
