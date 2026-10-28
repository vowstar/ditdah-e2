# SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
# SPDX-License-Identifier: MIT
"""Place a proven mapping and insert its clock tree."""

import argparse
import base64
import hashlib
import io
import json
import math
import os
from pathlib import Path
import re
import shutil
import sys
import tarfile
import time
import traceback

sys.dont_write_bytecode = True
from run_synthesis import (TransportFailure, digest, execute_worker, library_snapshot,
                           load_site, relative_name, remote, status, transport_record,
                           worker, write_json)


ROOT = Path(__file__).resolve().parents[1]


def run_name(receipt, tool):
    value = json.loads(receipt.read_text())["relativeRun"]
    if not re.fullmatch(r"runs/[a-z0-9-]+/" + tool + r"/[0-9TZ]+-[a-f0-9]{12}", value):
        raise ValueError("Invalid run receipt")
    return value


def validate_limits(period, threads, timeout, power_net, ground_net, hold_margin=0.0):
    if (type(threads) is not int or not 1 <= threads <= 16
            or type(period) not in (int, float) or not math.isfinite(period) or period <= 0
            or type(timeout) not in (int, float) or not math.isfinite(timeout) or not 0 < timeout <= 86400):
        raise ValueError("Invalid physical run budget")
    if (type(hold_margin) not in (int, float) or not math.isfinite(hold_margin)
            or hold_margin < 0 or hold_margin >= period):
        raise ValueError("Invalid hold margin")
    if power_net == ground_net or any(not isinstance(name, str) or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name)
                                      for name in (power_net, ground_net)):
        raise ValueError("Invalid supply net names")


def check_files(root, manifest):
    for name, expected in manifest.items():
        path = root / relative_name(name)
        if path.is_symlink() or digest(path) != expected:
            raise ValueError("Frozen source changed")


def freeze_physical(source, proof, run, period, threads, timeout, power_net, ground_net, hold_margin=0.0):
    validate_limits(period, threads, timeout, power_net, ground_net, hold_margin)
    synthesis = json.loads((source / "summary.json").read_text())
    verification = json.loads((proof / "summary.json").read_text())
    points = verification.get("proof", {})
    if (synthesis.get("flowSucceeded") is not True
            or verification.get("mappedEquivalence") != "passed"
            or verification.get("flowSucceeded") is not True
            or verification.get("frozenInputsStable") is not True
            or points.get("toolResult") != 1 or not points.get("passing", 0)
            or any(points.get(key) != 0 for key in ("failing", "aborted", "unverified", "blackBoxes"))):
        raise ValueError("Mapped equivalence is required")
    source_inputs = json.loads((source / "inputs.json").read_text())
    source_outputs = json.loads((source / "output-manifest.json").read_text())
    check_files(source, source_inputs)
    check_files(source, source_outputs)
    check_files(proof, json.loads((proof / "inputs.json").read_text()))
    check_files(proof, json.loads((proof / "output-manifest.json").read_text()))
    if (verification.get("mappedNetlistHash") != digest(source / "outputs/mapped.v")
            or verification.get("constraintsHash") != digest(source / "outputs/mapped.sdc")
            or digest(proof / "evidence/synthesis-inputs.json") != digest(source / "inputs.json")
            or digest(proof / "evidence/synthesis-outputs.json") != digest(source / "output-manifest.json")
            or (proof / "outputs/result.txt").read_text().strip() != "1"):
        raise ValueError("Proof does not bind this mapping")
    libraries = json.loads((source / "library-inputs.json").read_text())
    if library_snapshot() != libraries:
        raise ValueError("Selected library inputs changed")
    checkpoint_files = {name: value for name, value in source_outputs.items()
                        if name.startswith("outputs/design.ndm/")}
    actual_checkpoint = {str(path.relative_to(source))
                         for path in (source / "outputs/design.ndm").rglob("*")
                         if path.is_file()}
    if not checkpoint_files or actual_checkpoint != set(checkpoint_files):
        raise ValueError("A saved mapped checkpoint is required")
    config = json.loads((source / "configuration.json").read_text())
    input_label = (source / "outputs/complete").read_text().strip()
    if input_label != "logic_opto":
        raise ValueError("Clock optimization requires a mapping checkpoint and cannot be repeated")
    if hold_margin and re.search(r"(?m)^\s*set_path_margin\s", (source / "outputs/mapped.sdc").read_text()):
        raise ValueError("Existing path margins require an explicit preservation plan")
    guidance = config.get("guidance_outputs", ["mapping.svf"])
    if (not isinstance(guidance, list) or not guidance
            or any(not isinstance(name, str) or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_-]*\.svf", name) for name in guidance)
            or len(guidance) != len(set(guidance))):
        raise ValueError("Invalid guidance sequence")
    if verification.get("guidanceHashes") != [digest(source / "outputs" / name) for name in guidance]:
        raise ValueError("Proof guidance does not bind this checkpoint")
    guidance_name = "physical"
    if guidance_name + ".svf" in guidance:
        raise ValueError("Guidance output already exists")
    output_label = "clock_opt"
    for directory in ("rtl", "evidence"):
        shutil.copytree(source / directory, run / directory)
    shutil.copytree(source / "outputs/design.ndm", run / "checkpoint/design.ndm")
    for name in guidance:
        shutil.copyfile(source / "outputs" / name, run / "checkpoint" / name)
    for parent, name, target in ((source, "summary.json", "mapping-result.json"),
                                 (source, "inputs.json", "mapping-inputs.json"),
                                 (source, "output-manifest.json", "mapping-outputs.json"),
                                 (proof, "summary.json", "mapping-equivalence.json")):
        shutil.copyfile(parent / name, run / "evidence" / target)
    shutil.copyfile(source / "flow/synthesis_constraints.tcl", run / "flow/synthesis_constraints.tcl")
    config.update(period_ns=period, threads=threads, timeout_seconds=timeout,
                  power_net=power_net, ground_net=ground_net,
                  hold_margin_ns=hold_margin, input_label=input_label, output_label=output_label,
                  guidance_name=guidance_name, guidance_outputs=guidance + [guidance_name + ".svf"])
    write_json(run / "configuration.json", config)
    write_json(run / "source-binding.json", {
        "mappedNetlistHash": verification["mappedNetlistHash"],
        "sourceInputManifestHash": digest(source / "inputs.json"),
        "proofInputManifestHash": digest(proof / "inputs.json"),
        "checkpointFiles": len(checkpoint_files),
    })
    write_json(run / "inputs.json", {str(path.relative_to(run)): digest(path)
               for path in sorted(run.rglob("*")) if path.is_file()})


def submit(source_receipt, proof_receipt, name, output, period, threads, timeout,
           power_net, ground_net, hold_margin=0.0):
    validate_limits(period, threads, timeout, power_net, ground_net, hold_margin)
    source = run_name(source_receipt, "fc")
    proof = run_name(proof_receipt, "fm")
    if not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,47}", name):
        raise ValueError("Invalid run name")
    files = {"run_physical.py": Path(__file__), "run_synthesis.py": ROOT / "scripts/run_synthesis.py",
             "flow/physical.tcl": ROOT / "flow/physical.tcl",
             "flow/report_metrics.tcl": ROOT / "flow/report_metrics.tcl"}
    archive = io.BytesIO()
    with tarfile.open(fileobj=archive, mode="w:gz") as stream:
        for target, path in files.items():
            stream.add(str(path), arcname=target)
    stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    relative = "runs/" + name + "/fc/" + stamp + "-" + hashlib.sha256(archive.getvalue()).hexdigest()[:12]
    body = 'module load "$FC_MODULE"\nmodule load "$LC_MODULE"\nexport PYTHONDONTWRITEBYTECODE=1\n'
    body += "python3 - <<'E2_PYTHON'\nimport base64, io, json, os, subprocess, sys, tarfile\nfrom pathlib import Path\n"
    body += "relative = " + repr(relative) + "\n"
    body += "run = Path(os.environ['EDA_WORK_ROOT']) / relative\nrun.mkdir(parents=True)\n"
    body += "data = base64.b64decode(" + repr(base64.b64encode(archive.getvalue()).decode()) + ")\n"
    body += "with tarfile.open(fileobj=io.BytesIO(data), mode='r:gz') as archive:\n"
    body += " for member in archive.getmembers():\n  assert member.name in " + repr(set(files)) + " and member.isfile()\n archive.extractall(str(run))\n"
    body += "sys.path.insert(0, str(run))\nfrom run_physical import freeze_physical\n"
    body += "freeze_physical(Path(os.environ['EDA_WORK_ROOT']) / " + repr(source)
    body += ", Path(os.environ['EDA_WORK_ROOT']) / " + repr(proof)
    body += ", run, " + ", ".join(repr(value) for value in (period, threads, timeout, power_net, ground_net, hold_margin)) + ")\n"
    body += "log = (run / 'supervisor.log').open('w')\n"
    body += "process = subprocess.Popen(['python3', 'run_physical.py', 'worker'], cwd=str(run), stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT, start_new_session=True)\n"
    body += "print('E2_RESULT ' + json.dumps({'relativeRun': relative, 'supervisorPid': process.pid}))\nE2_PYTHON\n"
    output.parent.mkdir(parents=True, exist_ok=True)
    write_json(output, {"relativeRun": relative, "state": "submission_pending"})
    result = remote(load_site(), body)
    if (set(result) != {"relativeRun", "supervisorPid"} or result["relativeRun"] != relative
            or type(result["supervisorPid"]) is not int):
        raise ValueError("Invalid submission reply")
    write_json(output, result)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command")
    launch = commands.add_parser("submit")
    launch.add_argument("--source", type=Path, required=True)
    launch.add_argument("--proof", type=Path, required=True)
    launch.add_argument("--name", required=True)
    launch.add_argument("--output", type=Path, required=True)
    launch.add_argument("--period-ns", type=float, default=1.5)
    launch.add_argument("--threads", type=int, default=16)
    launch.add_argument("--timeout-seconds", type=float, default=3600.0)
    launch.add_argument("--power-net", default="VDD")
    launch.add_argument("--ground-net", default="VSS")
    launch.add_argument("--hold-margin-ns", type=float, default=0.0)
    query = commands.add_parser("status")
    query.add_argument("--receipt", type=Path, required=True)
    commands.add_parser("worker")
    args = parser.parse_args()
    if args.command is None:
        parser.error("A command is required")
    if args.command == "worker":
        worker(lambda: execute_worker("flow/physical.tcl"))
        return
    if args.command == "status":
        result = status(args.receipt)
    else:
        result = submit(args.source, args.proof, args.name, args.output, args.period_ns,
                        args.threads, args.timeout_seconds, args.power_net, args.ground_net, args.hold_margin_ns)
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    try:
        main()
    except TransportFailure as error:
        print(json.dumps({"error": error.category, "exitStatus": error.exit_status}), file=sys.stderr)
        sys.exit(1)
    except Exception:
        transport_record(exception=traceback.format_exc())
        print(json.dumps({"error": "local_request", "exitStatus": None}), file=sys.stderr)
        sys.exit(1)
