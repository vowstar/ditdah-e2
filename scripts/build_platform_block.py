# SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
# SPDX-License-Identifier: MIT
"""Wrap a frozen ordinary platform build with a functional block interface."""

import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import shutil
import sys


TOP = "DitDahE2PlatformTop"
BLOCK = "DitDahE2PlatformBlock"
OBSERVATION_OUTPUTS = frozenset("""
retire_order retire_length retire_insn retire_intr retire_rs1 retire_rs1Data
retire_rs2 retire_rs2Data retire_memoryAddress retire_memoryReadMask
retire_memoryWriteMask retire_memoryReadData retire_memoryWriteData
retire_memoryOperation retire_memoryResponse retire_memoryOperand retire_memoryFault
retire_faultReadMask retire_faultWriteMask retire_misa retire_csr_valid
retire_csr_address retire_csr_readMask retire_csr_writeMask retire_csr_readData
retire_csr_writeData retire_csrMstatus_before retire_csrMstatus_after
retire_csrMstatus_writeMask retire_csrMepc_before retire_csrMepc_after
retire_csrMepc_writeMask retire_csrMcause_before retire_csrMcause_after
retire_csrMcause_writeMask retire_csrMtval_before retire_csrMtval_after
retire_csrMtval_writeMask retire_csrCycle_before retire_csrCycle_after
retire_csrCycle_writeMask retire_csrInstret_before retire_csrInstret_after
retire_csrInstret_writeMask retire_csrTime retire_valid retire_userMode retire_pc
retire_word retire_nextPc retire_rd retire_writes retire_value retire_trap
retire_cause retire_tval interrupt_valid interrupt_userMode
interrupt_csrMstatus_before interrupt_csrMstatus_after interrupt_csrMstatus_writeMask
interrupt_csrMepc_before interrupt_csrMepc_after interrupt_csrMepc_writeMask
interrupt_csrMcause_before interrupt_csrMcause_after interrupt_csrMcause_writeMask
interrupt_csrMtval_before interrupt_csrMtval_after interrupt_csrMtval_writeMask
interrupt_pc interrupt_target interrupt_cause mulDiv_start mulDiv_resultValid
mulDiv_finish mulDiv_cancel mulDiv_pc mulDiv_value loadUse forward redirect
memoryWait timeValue timerInterrupt softwareInterrupt
""".split())


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def emit_wrapper(top):
    """Accept the generated ANSI header; export every unlisted port unchanged."""
    headers = re.findall(rf"\bmodule\s+{TOP}\s*\((.*?)\);", top, re.S)
    if len(headers) != 1:
        raise ValueError("Expected one ordinary platform module header")
    ports, direction, width = [], None, None
    for token in headers[0].split(","):
        token = " ".join(token.split())
        explicit = re.fullmatch(r"(input|output)\s*(\[\d+\s*:\s*\d+\])?\s*([A-Za-z_]\w*)", token)
        if explicit:
            direction, width, name = explicit.groups()
            width = width or ""
        elif direction and re.fullmatch(r"[A-Za-z_]\w*", token):
            name = token
        else:
            raise ValueError("Unsupported generated platform port declaration")
        ports.append({"direction": direction, "width": width, "name": name})
    names = {p["name"] for p in ports}
    if len(names) != len(ports):
        raise ValueError("Duplicate platform port")

    def functional(port):
        return port["direction"] != "output" or port["name"] not in OBSERVATION_OUTPUTS

    kept = [p for p in ports if functional(p)]
    hidden = [p for p in ports if not functional(p)]
    if "fullTop" in names or any("observed_" + p["name"] in names for p in hidden):
        raise ValueError("Platform port conflicts with an internal wrapper name")
    notice = "// SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>\n// SPDX-License-Identifier: MIT\n"
    declarations = [f"  {p['direction']} {p['width']} {p['name']}" for p in kept]
    text = notice + f"module {BLOCK}(\n" + ",\n".join(declarations) + "\n);\n"
    text += "\n".join(f"wire {p['width']} observed_{p['name']};" for p in hidden) + "\n"
    text += f"{TOP} fullTop(\n" + ",\n".join(
        f"  .{p['name']}({p['name'] if functional(p) else 'observed_' + p['name']})"
        for p in ports) + "\n);\nendmodule\n"
    return text, kept, hidden


def tree_hashes(directory):
    paths = sorted(directory.rglob("*"))
    if any(path.is_symlink() for path in paths):
        raise ValueError("Platform build must not contain symbolic links")
    return {path.relative_to(directory).as_posix(): digest(path) for path in paths if path.is_file()}


def validate_build(directory):
    manifest = json.loads((directory / "manifest.json").read_bytes())
    if manifest.get("top") != TOP or type(manifest.get("exitStatus")) is not int or manifest["exitStatus"] != 0:
        raise ValueError("Expected a successful ordinary platform build")
    if manifest.get("parameters", {}).get("core", {}).get("enableA") is not False:
        raise ValueError("Block interface supports only the ordinary platform")
    groups = (("sourceHashes", "inputs"), ("generatedHashes", "inputs/generated"),
              ("rtlHashes", "rtl"), ("artifactHashes", ""))
    for key, base in groups:
        hashes = manifest.get(key)
        if not isinstance(hashes, dict) or not hashes:
            raise ValueError(f"Missing {key}")
        for name, expected in hashes.items():
            path = PurePosixPath(name)
            if path.is_absolute() or ".." in path.parts or path.as_posix() != name or name == ".":
                raise ValueError(f"Unsafe {key} path")
            actual = directory / base / name
            if not isinstance(expected, str) or not re.fullmatch(r"[0-9a-f]{64}", expected):
                raise ValueError(f"Invalid {key} digest")
            if not actual.is_file() or digest(actual) != expected:
                raise ValueError(f"{key} mismatch: {name}")
    if digest(directory / "inputs/platform.json") != manifest.get("platformHash"):
        raise ValueError("Platform map input hash mismatch")
    source_files = {path.relative_to(directory / "inputs").as_posix()
                    for path in (directory / "inputs").rglob("*") if path.is_file()
                    and not path.is_relative_to(directory / "inputs/generated")}
    if source_files != set(manifest["sourceHashes"]) | {"platform.json"}:
        raise ValueError("Unbound platform source input")
    generated = tree_hashes(directory / "inputs/generated")
    if generated != manifest["generatedHashes"]:
        raise ValueError("Unbound generated platform input")
    rtl_files = tree_hashes(directory / "rtl")
    rtl_names = set(manifest["rtlHashes"])
    if (set(rtl_files) != rtl_names | {"filelist.f"} or "filelist.f" in rtl_names
            or f"{TOP}.sv" not in rtl_names):
        raise ValueError("RTL files differ from their manifest")
    if (directory / "rtl/filelist.f").read_text().splitlines() != sorted(rtl_names):
        raise ValueError("RTL file list differs from its manifest")
    required = {"parameters.json", "map.json", "memory.ld", "platform.h", "linked.mlirbc"}
    if not required <= manifest["artifactHashes"].keys():
        raise ValueError("Missing platform artifact hashes")
    for name in ("parameters.json", "map.json", "memory.ld", "platform.h"):
        if name not in manifest["generatedHashes"] or (directory / name).read_bytes() != (directory / "inputs/generated" / name).read_bytes():
            raise ValueError(f"Platform artifact differs from its generated snapshot: {name}")
    if json.loads((directory / "parameters.json").read_bytes()) != manifest["parameters"]:
        raise ValueError("Platform parameters differ from their manifest")
    if json.loads((directory / "map.json").read_bytes()) != manifest["regions"]:
        raise ValueError("Platform regions differ from their manifest")
    return manifest


def build(platform_build, output):
    platform_build, output = Path(platform_build).resolve(), Path(output).resolve()
    if output.exists() or output.is_relative_to(platform_build):
        raise ValueError("Block output must be a new directory outside the platform build")
    before = tree_hashes(platform_build)
    manifest = validate_build(platform_build)
    wrapper, _, hidden = emit_wrapper((platform_build / "rtl" / f"{TOP}.sv").read_text())
    reserved = ("original-manifest.json", "original-filelist.f", f"rtl/{BLOCK}.sv",
                f"inputs/generated/{BLOCK}.sv", "inputs/scripts/build_platform_block.py")
    if any((platform_build / name).exists() for name in reserved):
        raise ValueError("Platform build contains a reserved block artifact")
    original_manifest = (platform_build / "manifest.json").read_bytes()
    shutil.copytree(platform_build, output)
    if tree_hashes(output) != before or tree_hashes(platform_build) != before:
        raise ValueError("Platform build changed while copying")
    (output / "original-manifest.json").write_bytes(original_manifest)
    (output / "original-filelist.f").write_bytes((output / "rtl/filelist.f").read_bytes())
    script = output / "inputs/scripts/build_platform_block.py"
    script.parent.mkdir(parents=True, exist_ok=True)
    script.write_bytes(Path(__file__).read_bytes())
    for destination in (output / "rtl" / f"{BLOCK}.sv", output / "inputs/generated" / f"{BLOCK}.sv"):
        destination.write_text(wrapper)
    manifest.update({"top": BLOCK, "wrappedTop": TOP,
                     "scope": "platform block RTL wrapper; linked.mlirbc retains the wrapped top",
                     "wrappedManifestHash": digest(output / "original-manifest.json"),
                     "internalObservationOutputs": [p["name"] for p in hidden]})
    manifest["sourceHashes"]["scripts/build_platform_block.py"] = digest(script)
    manifest["generatedHashes"][f"{BLOCK}.sv"] = digest(output / "rtl" / f"{BLOCK}.sv")
    manifest["rtlHashes"][f"{BLOCK}.sv"] = digest(output / "rtl" / f"{BLOCK}.sv")
    for name in ("original-manifest.json", "original-filelist.f"):
        manifest["artifactHashes"][name] = digest(output / name)
    (output / "rtl/filelist.f").write_text("\n".join(sorted(manifest["rtlHashes"])) + "\n")
    if "rtl/filelist.f" in manifest["artifactHashes"]:
        manifest["artifactHashes"]["rtl/filelist.f"] = digest(output / "rtl/filelist.f")
    manifest["derivation"] = {
        "argv": ["python3", "scripts/build_platform_block.py", "--platform-build", "<parent>", "--output", "<output>"],
        "python": {"version": ".".join(map(str, sys.version_info[:3])), "executableSha256": digest(Path(sys.executable))},
        "sourceHash": digest(script), "inputManifestHash": manifest["wrappedManifestHash"], "exitStatus": 0}
    (output / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    return manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--platform-build", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    build(args.platform_build, args.output)
    print("Generated DitDahE2 platform block RTL")


if __name__ == "__main__":
    main()
