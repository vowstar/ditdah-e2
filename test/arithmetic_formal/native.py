# SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
# SPDX-License-Identifier: MIT
"""Collect and check native formal results without accepting exit status alone."""

import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import tempfile
import time


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def index(directory):
    return {
        p.relative_to(directory).as_posix(): digest(p)
        for p in sorted(directory.rglob("*"))
        if p.is_file()
    }


def read_records(path):
    result = {}
    for line in path.read_text().splitlines():
        fields = line.split("\t")
        if len(fields) != 3:
            raise ValueError("Malformed native record")
        group, name, value = (bytes.fromhex(field).decode("utf-8") for field in fields)
        key = (group, name)
        if key in result:
            raise ValueError("Duplicate native record")
        result[key] = value
    return result


def check_records(records, plan):
    if records.get(("run", "state")) != "complete":
        raise ValueError("Native collection did not finish")
    if any(
        records.get(("setup", key)) != "0"
        for key in ("bbox_inst", "bbox_mod", "bbox_out", "stopat")
    ):
        raise ValueError("Native design contains an abstraction")
    for field in ("clock", "reset", "assumptions", "global", "reset_assumptions"):
        if records.get(("before", field)) != records.get(("after", field)):
            raise ValueError("Native proof scope changed")
    if any(records.get(("before", key)) != "" for key in ("global", "reset_assumptions")):
        raise ValueError("Unexpected native environment assumption")
    if records.get(("before", "clock"), "").strip() != "{clock clock 1 1}":
        raise ValueError("Native clock does not match the source clock")
    reset = records.get(("before", "reset"), "").strip()
    expected_reset = (
        "expression reset file_type {} sequence {} file_name {} hier_path {} "
        "time {} start_time {} end_time {} time_scale {} non_resettable_regs {} "
        "formal false bound 0 max_iterations {} none false reset_declared true"
    )
    if reset != expected_reset:
        raise ValueError("Native initial reset scope differs")
    expected_names = " ".join(sorted(plan["assumptions"]))
    if records.get(("before", "assumptions")) != expected_names:
        raise ValueError("Native input assumptions differ")
    established = set()
    for label, dependencies in plan["goals"]:
        if set(dependencies) - established:
            raise ValueError("Native proof uses an unproved dependency")
        prefix = "final." + label
        required = {
            "name": plan["top"] + "." + label,
            "type": "assert",
            "command": "assert",
            "disabled": "0",
            "run_status": "processed",
            "validity_status": plan["expected"],
        }
        if any(records.get((prefix, key)) != value for key, value in required.items()):
            raise ValueError("Native assertion has no matching proof verdict")
        if (
            records.get((prefix, "expression")) != label
            or records.get((prefix, "precondition")) != "0"
        ):
            raise ValueError("Native assertion expression differs")
        for key in ("name", "type", "command", "disabled"):
            if records.get(("before." + label, key)) != required[key]:
                raise ValueError("Native assertion identity differs before proof")
        for tag in ("before." + label, prefix):
            if records.get((tag, "clock")) not in (None, "", "clock") or records.get(
                (tag, "edge")
            ) not in (None, "", "posedge"):
                raise ValueError("Native assertion uses an unexpected clock edge")
        for key in ("expression", "precondition", "clock", "edge"):
            if records.get(("before." + label, key)) != records.get((prefix, key)):
                raise ValueError("Native assertion identity changed")
        if plan["expected"] == "proven":
            established.add(label)
    for label in plan["covers"]:
        prefix = "cover." + label
        required = {
            "name": plan["top"] + "." + label,
            "type": "cover",
            "command": "cover",
            "disabled": "0",
            "run_status": "processed",
            "validity_status": "covered",
        }
        if any(records.get((prefix, key)) != value for key, value in required.items()):
            raise ValueError("Missing native cover")
    return {
        "nativeGoals": len(plan["goals"]),
        "nativeCovers": len(plan["covers"]),
        "verdict": plan["expected"],
    }


def tcl_plan(plan):
    names = [plan["top"], *plan["assumptions"], *plan["covers"]]
    names += [name for name, _ in plan["goals"]]
    names += [name for _, deps in plan["goals"] for name in deps]
    if any(not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.]*", name) for name in names):
        raise ValueError("Unsafe native property name")
    if any(not re.fullmatch(r"[A-Za-z0-9_./-]+", name) for name in plan["sources"]):
        raise ValueError("Unsafe native source name")
    goals = " ".join("{" + name + " {" + " ".join(deps) + "}}" for name, deps in plan["goals"])
    return (
        f"set top {plan['top']}\nset sources {{{' '.join(plan['sources'])}}}\n"
        f"set goals {{{goals}}}\nset expected {plan['expected']}\n"
        f"set covers {{{' '.join(plan['covers'])}}}\n"
        f"set expected_assumptions {{{' '.join(plan['assumptions'])}}}\n"
        f"set time_limit {plan['timeLimitSeconds']}s\n"
    )


def collect(case, executable, private_root, timeout):
    plan = json.loads((case / "plan.json").read_text())
    inputs = {name: digest(case / name) for name in plan["inputs"]}
    if (case / "receipt.json").exists():
        raise ValueError("Native attempt already exists")
    label = case.parent.name + "/" + case.name
    try:
        executable = Path(shutil.which(executable) or executable).resolve(strict=True)
    except OSError:
        raise ValueError(label + ": native executable was not found") from None
    private = Path(tempfile.mkdtemp(prefix="arithmetic-native-", dir=private_root))
    cpu = min(os.sched_getaffinity(0)) if hasattr(os, "sched_getaffinity") else None
    environment = dict(os.environ, OMP_NUM_THREADS="1")
    command = [str(executable), "-no_gui", "-fpv", "-tcl", "collect.tcl"]
    started = time.monotonic()
    with (private / "native.log").open("wb") as log:

        def affinity():
            if cpu is not None:
                os.sched_setaffinity(0, {cpu})

        try:
            process = subprocess.Popen(
                command,
                cwd=case,
                env=environment,
                stdin=subprocess.DEVNULL,
                stdout=log,
                stderr=subprocess.STDOUT,
                start_new_session=True,
                preexec_fn=affinity,
            )
        except OSError:
            raise ValueError(
                label + ": native process failed to start. Log: " + str(private / "native.log")
            ) from None
        receipt = {
            "pid": process.pid,
            "launcherSha256": digest(executable),
            "command": ["jg", *command[1:]],
            "cpu": cpu,
            "inputHashes": inputs,
            "timeoutSeconds": timeout,
        }
        (case / "receipt.json").write_text(json.dumps(receipt, indent=2) + "\n")
        timed_out = False
        try:
            process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
            os.killpg(process.pid, signal.SIGTERM)
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait()
    try:
        unchanged = all(digest(case / name) == value for name, value in inputs.items())
    except OSError:
        unchanged = False
    native_identity = case / "executable.private"
    identity = None
    if native_identity.exists():
        try:
            identity = digest(Path(native_identity.read_text().strip()))
        except OSError:
            identity = None
        shutil.move(str(native_identity), private / "executable.txt")
    outcome = {
        "exitStatus": process.returncode,
        "timedOut": timed_out,
        "elapsedSeconds": round(time.monotonic() - started, 6),
        "inputsUnchanged": unchanged,
        "nativeExecutableSha256": identity,
        "outputHashes": {
            p.name: digest(p)
            for p in case.iterdir()
            if p.is_file() and (p.name == "native.tsv" or p.suffix == ".vcd")
        },
    }
    (case / "completion.json").write_text(json.dumps(outcome, indent=2) + "\n")
    label = case.parent.name + "/" + case.name
    location = str(private / "native.log")
    if timed_out:
        raise ValueError(label + ": native process timed out. Log: " + location)
    if process.returncode:
        raise ValueError(
            label + ": native exit status " + str(process.returncode) + ". Log: " + location
        )
    if not unchanged:
        raise ValueError(label + ": native inputs changed. Log: " + location)
    if not identity:
        raise ValueError(label + ": native executable identity is missing. Log: " + location)
    try:
        return check_records(read_records(case / "native.tsv"), plan)
    except (OSError, ValueError) as error:
        raise ValueError(label + ": " + str(error) + ". Log: " + location) from None


def validate_case(case, plan):
    receipt = json.loads((case / "receipt.json").read_text())
    completion = json.loads((case / "completion.json").read_text())
    expected_inputs = {name: digest(case / name) for name in plan["inputs"]}
    if (
        receipt.get("command") != ["jg", "-no_gui", "-fpv", "-tcl", "collect.tcl"]
        or type(receipt.get("pid")) is not int
        or receipt["pid"] <= 0
        or type(receipt.get("cpu")) is not int
        or receipt["cpu"] < 0
        or type(receipt.get("timeoutSeconds")) is not int
        or receipt["timeoutSeconds"] < 1
    ):
        raise ValueError("Native invocation identity differs")
    if receipt.get("inputHashes") != expected_inputs:
        raise ValueError("Native receipt does not bind the complete proof inputs")
    if (
        completion.get("exitStatus") != 0
        or completion.get("timedOut") is not False
        or completion.get("inputsUnchanged") is not True
    ):
        raise ValueError("Native execution did not finish with unchanged inputs")
    for field in (receipt.get("launcherSha256"), completion.get("nativeExecutableSha256")):
        if (
            not isinstance(field, str)
            or len(field) != 64
            or any(c not in "0123456789abcdef" for c in field)
        ):
            raise ValueError("Native tool identity is missing")
    outputs = {
        p.name: digest(p)
        for p in case.iterdir()
        if p.is_file() and (p.name == "native.tsv" or p.suffix == ".vcd")
    }
    if completion.get("outputHashes") != outputs:
        raise ValueError("Native results changed after completion")
    return check_records(read_records(case / "native.tsv"), plan)
