# SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
# SPDX-License-Identifier: MIT
"""Recheck frozen Sail evidence without running a simulator or local ISA model."""

import argparse
import hashlib
import json
from pathlib import Path
import sys


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def replay(base):
    manifest = json.loads((base / "artifact-manifest.json").read_text())
    if manifest["schema"] != "ditdah-e2.sail-evidence.v1" or manifest["summary"] != "summary.json":
        raise ValueError("Unsupported evidence manifest")
    for name, row in manifest["artifacts"].items():
        relative = Path(name)
        if relative.is_absolute() or ".." in relative.parts:
            raise ValueError("Artifact escapes the evidence directory")
        path = base / relative
        if path.is_symlink() or not path.is_file() or path.stat().st_size != row["bytes"] or digest(path) != row["sha256"]:
            raise ValueError("Frozen artifact differs: " + name)
    summary = json.loads((base / manifest["summary"]).read_text())
    for name, expected in summary["sourceHashes"].items():
        if digest(base / "inputs" / name) != expected:
            raise ValueError("Frozen runner source differs")
    sys.path[:0] = [str(base / "inputs/test/isa"), str(base / "inputs/test")]
    from elf import Region, load_elf
    from retirement import bind_native_trace, read_trace
    from sail_compare import compare, compare_signature
    from sail_program import RAM, RAM_SIZE
    from sail_run import corruption_controls, signature_control, signature_from_memory, workload_coverage
    from sail_trace import parse_signature, parse_trace
    profiles = []
    for original in summary["profiles"]:
        directory = base / original["profile"]
        rtl_manifest = directory / "rtl/manifest.json"
        if digest(rtl_manifest) != original["rtlManifestHash"]:
            raise ValueError("RTL manifest differs")
        inputs = json.loads(rtl_manifest.read_text())
        for name, expected in inputs["sourceHashes"].items():
            if digest(directory / "inputs" / name) != expected:
                raise ValueError("Frozen hardware source differs")
        for name, expected in inputs["rtlHashes"].items():
            if digest(directory / "rtl" / name) != expected:
                raise ValueError("Frozen RTL differs")
        parameters = original["parameters"]
        actual_parameters = inputs["parameters"]["core"] if parameters["enableA"] else inputs["parameters"]
        if parameters != actual_parameters:
            raise ValueError("Selected RTL parameters differ")
        image = load_elf(directory / "program.elf", reset_vector=parameters["resetVector"], enable_c=parameters["enableC"],
                         regions=(Region("code", parameters["resetVector"], 65536, 5), Region("data", RAM, RAM_SIZE, 6)))
        begin, end = image.symbols["begin_signature"], image.symbols["end_signature"]
        records = read_trace(directory / "dut.jsonl")
        stdout = (directory / "dut.stdout").read_text()
        bind_native_trace(records, stdout)
        steps = parse_trace((directory / "sail.trace").read_text())
        expected = parse_signature((directory / "sail.signature").read_text(), (end - begin) // 4)
        boundaries = {"checked_end": image.symbols["checked_end"], "completion_pc": image.symbols["software_done"],
                      "tohost": image.symbols["tohost"]}
        if parameters["enableA"]:
            from sail_atomic_samples import sample_atomic_witnesses
            from sail_atomic_compare import corruption_controls as atomic_controls, memory_checker, signature_from_samples
            samples = sample_atomic_witnesses(records, stdout, sram_base=RAM, sram_size=RAM_SIZE)
            if samples != json.loads((directory / "actual-atomic-samples.json").read_text()):
                raise ValueError("Reparsed actual atomic ownership differs")
            boundaries["memory_checker"] = memory_checker(samples)
            actual = signature_from_samples(samples, begin, end)
        else:
            actual = signature_from_memory(stdout, begin, end)
        result = compare(records, steps, parameters, **boundaries)
        compare_signature(actual, expected)
        controls = corruption_controls(records, steps, parameters, boundaries, image.symbols["checked_start"])
        if parameters["enableA"]:
            controls += atomic_controls(records, steps, parameters, samples, boundaries, stdout, begin, end, expected,
                                        sram_base=RAM, sram_size=RAM_SIZE)
        else:
            controls.append(signature_control(stdout, begin, end, expected))
        if controls != original["negativeControls"] or result != original["externalComparison"]:
            raise ValueError("Replayed acceptance or controls differ")
        if workload_coverage(image, steps, parameters) != original["workloadCoverage"]:
            raise ValueError("Replayed workload coverage differs")
        profiles.append({"profile": original["profile"], "events": len(steps), "signatureWords": len(actual),
                         "effectiveControls": len(controls), "atomicEndpoint": parameters["enableA"]})
    if any(name in sys.modules for name in ("model", "bit_model", "compressed_model", "atomic_memory", "pmp")):
        raise ValueError("A local architectural execution model was imported")
    return {"exitStatus": 0, "profiles": profiles, "artifactsChecked": len(manifest["artifacts"]),
            "nativeRerun": False, "localIsaModelUsed": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence", type=Path, default=Path(__file__).resolve().parent)
    args = parser.parse_args()
    print(json.dumps(replay(args.evidence.resolve()), indent=2))


if __name__ == "__main__":
    main()
