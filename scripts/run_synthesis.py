# SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
# SPDX-License-Identifier: MIT
"""Freeze accepted RTL and run exploratory technology synthesis."""

import argparse
import base64
import hashlib
import io
import json
import math
import os
from pathlib import Path, PurePosixPath
import re
import shlex
import shutil
import signal
import subprocess
import sys
import tarfile
import tempfile
import time
import traceback


ROOT = Path(__file__).resolve().parents[1]
SITE_KEYS = ("EDA_WORK_ROOT", "TECH_LIB_DIR", "TECH_PDK_DIR", "FC_MODULE",
             "PT_MODULE", "LC_MODULE", "E2_NDM_LIBS", "E2_RC_FILE")
MARKER = "E2_RESULT "
METRICS = {
    "standard_cell_area_um2", "memory_area_um2", "other_macro_area_um2", "standard_cells",
    "memory_cells", "leaf_cells", "unmapped_cells", "registers", "clocked_registers",
    "latches", "clocks", "period_ns", "output_load_pf", "floorplan_utilization_target",
    "setup_worst_slack_ns", "setup_wns_ns", "setup_tns_ns", "setup_violating_paths",
    "hold_worst_slack_ns", "hold_wns_ns", "hold_tns_ns", "hold_violating_paths",
    "unconstrained_endpoints",
    "timing_check_errors", "timing_check_warnings",
}
METRICS.update(label + "_" + kind + "_" + suffix
               for label in ("setup", "hold")
               for kind in ("input_to_register", "register_to_register", "register_to_output", "input_to_output")
               for suffix in ("paths", "wns_ns"))


class TransportFailure(RuntimeError):
    def __init__(self, category, exit_status, record):
        super().__init__(category)
        self.category = category
        self.exit_status = exit_status
        self.record = record


def transport_record(stdout="", stderr="", exception=""):
    scratch = "/data/tmp" if os.access("/data/tmp", os.W_OK) else "/tmp"
    directory = Path(tempfile.mkdtemp(prefix="ditdah-e2-transport-", dir=scratch))
    for name, value in (("stdout.txt", stdout), ("stderr.txt", stderr), ("exception.txt", exception)):
        if isinstance(value, bytes):
            value = value.decode(errors="replace")
        path = directory / name
        path.write_text(value or "")
        path.chmod(0o600)
    return directory


def transport_category(stderr):
    for text, category in (("Could not resolve hostname", "name_resolution"),
                           ("Connection reset", "connection_reset"),
                           ("Connection refused", "connection_refused"),
                           ("Connection timed out", "timeout"),
                           ("Permission denied", "authentication"),
                           ("Host key verification failed", "host_key")):
        if text in stderr:
            return category
    return "remote_exit"


def digest(path):
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(block)
    return value.hexdigest()


def write_json(path, value):
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value, indent=2) + "\n")
    temporary.replace(path)


def relative_name(name):
    if not isinstance(name, str):
        raise ValueError("Invalid input name")
    path = PurePosixPath(name)
    if (not name or path.is_absolute()
            or ".." in path.parts or "\\" in name or any(ord(c) < 32 for c in name)):
        raise ValueError("Invalid input name")
    return path


def settings(values):
    result = dict(values)
    for key, value in result.items():
        if key == "threads":
            if type(value) is not int or not 1 <= value <= 16:
                raise ValueError("Thread count must be between 1 and 16")
        elif type(value) not in (int, float) or not math.isfinite(value) or value < 0:
            raise ValueError("Timing and load budgets must be finite and nonnegative")
    if result["period_ns"] <= 0 or result["timeout_seconds"] <= 0:
        raise ValueError("Period and timeout must be positive")
    return result


def freeze(rtl, acceptance_path, output, budgets):
    manifest_path = rtl / "manifest.json"
    manifest = json.loads(manifest_path.read_text())
    acceptance = json.loads(acceptance_path.read_text())
    if (type(manifest.get("exitStatus")) is not int or manifest["exitStatus"] != 0
            or type(acceptance.get("exitStatus")) is not int or acceptance["exitStatus"] != 0):
        raise ValueError("Successful generation and acceptance records are required")
    if manifest.get("sourceHashes") != acceptance.get("sourceHashes"):
        raise ValueError("Acceptance source hashes differ from the RTL manifest")
    source_root = acceptance_path.parent / relative_name(acceptance["sourceSnapshot"])
    for name, expected in manifest["sourceHashes"].items():
        if digest(source_root / relative_name(name)) != expected:
            raise ValueError("Accepted source snapshot differs")
    top = manifest.get("top", "")
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", top):
        raise ValueError("Invalid top module name")
    files = (rtl / "filelist.f").read_text().splitlines()
    hashes = manifest.get("rtlHashes", {})
    if (not files or len(files) != len(set(files)) or set(files) != set(hashes)
            or top + ".sv" not in files):
        raise ValueError("RTL file list differs from the manifest")
    for name in files:
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*\.sv", name):
            raise ValueError("Invalid RTL file name")
        if digest(rtl / name) != hashes[name]:
            raise ValueError("RTL input digest differs")
    report_path = rtl.parent / "verification/summary.json"
    report = json.loads(report_path.read_text())
    accepted = [row for row in acceptance.get("checks", [])
                if row.get("configuration") == rtl.parent.name]
    if (len(accepted) != 1 or accepted[0].get("reportHash") != digest(report_path)
            or report.get("rtlManifestHash") != digest(manifest_path)
            or report.get("exitStatus") != 0):
        raise ValueError("Verification evidence does not bind this RTL")
    budgets = settings(budgets)
    if output.exists():
        raise ValueError("Bundle destination already exists")
    output.mkdir(parents=True)
    for directory in ("rtl", "flow", "evidence"):
        (output / directory).mkdir()
    for name in files:
        shutil.copyfile(rtl / name, output / "rtl" / name)
    shutil.copyfile(rtl / "filelist.f", output / "rtl/filelist.f")
    for source, name in ((manifest_path, "manifest.json"),
                         (acceptance_path, "acceptance.json"),
                         (report_path, "verification.json")):
        shutil.copyfile(source, output / "evidence" / name)
    for name in ("synthesis.tcl", "synthesis_constraints.tcl", "report_metrics.tcl"):
        shutil.copyfile(ROOT / "flow" / name, output / "flow" / name)
    shutil.copyfile(Path(__file__), output / "runner.py")
    configuration = dict(budgets, top=top, rtl_files=files, exploratory=True)
    write_json(output / "configuration.json", configuration)
    inputs = {str(path.relative_to(output)): digest(path)
              for path in sorted(output.rglob("*")) if path.is_file()}
    write_json(output / "inputs.json", inputs)
    return {"inputFiles": len(inputs), "inputManifestHash": digest(output / "inputs.json")}


def validate_bundle(bundle, allowed_extra=()):
    inputs = json.loads((bundle / "inputs.json").read_text())
    if not inputs:
        raise ValueError("Empty input manifest")
    actual = {str(path.relative_to(bundle)) for path in bundle.rglob("*") if path.is_file()}
    if actual - set(allowed_extra) != set(inputs) | {"inputs.json"}:
        raise ValueError("Unexpected bundle files")
    for name, expected in inputs.items():
        path = bundle / relative_name(name)
        if path.is_symlink() or digest(path) != expected:
            raise ValueError("Frozen input digest differs")
    return inputs


def load_site():
    path = Path(os.environ["EDA_SITE_ENV"]).resolve()
    if ROOT == path.parent or ROOT in path.parents:
        raise ValueError("The site declaration must be outside the repository")
    process = subprocess.run(["bash", "-c", 'set -a\nsource "$1" >/dev/null\nenv -0',
                              "bash", str(path)], stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE)
    if process.returncode:
        raise RuntimeError("Site declaration could not be loaded")
    environment = dict(item.split("=", 1) for item in process.stdout.decode().split("\0")
                       if "=" in item)
    if any(not environment.get(key) for key in SITE_KEYS + ("EDA_SSH_TARGET",)):
        raise ValueError("Required site settings are missing")
    return environment


def run_transport(environment, body, extra_keys=()):
    if set(extra_keys) - {"FM_MODULE", "E2_TIMING_DBS"}:
        raise ValueError("Unsupported remote setting")
    exports = "\n".join("export " + key + "=" + shlex.quote(environment[key])
                        for key in SITE_KEYS + tuple(extra_keys))
    try:
        process = subprocess.run(["ssh", "-T", "-o", "ConnectTimeout=20", "--",
                                  environment["EDA_SSH_TARGET"], "bash", "-l", "-s"],
                                 input=exports + "\nset -eu\n" + body,
                                 universal_newlines=True, stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE, timeout=60)
    except Exception as error:
        record = transport_record(getattr(error, "stdout", ""), getattr(error, "stderr", ""),
                                  traceback.format_exc())
        category = "timeout" if isinstance(error, subprocess.TimeoutExpired) else "transport_exception"
        raise TransportFailure(category, getattr(error, "returncode", None), record) from None
    record = transport_record(process.stdout, process.stderr)
    if process.returncode:
        raise TransportFailure(transport_category(process.stderr), process.returncode, record)
    return process, record


def remote(environment, body, extra_keys=()):
    process, record = run_transport(environment, body, extra_keys=extra_keys)
    try:
        replies = [json.loads(line[len(MARKER):]) for line in process.stdout.splitlines()
                   if line.startswith(MARKER)]
    except (ValueError, TypeError):
        (record / "exception.txt").write_text(traceback.format_exc())
        raise TransportFailure("invalid_reply", process.returncode, record) from None
    if len(replies) != 1:
        raise TransportFailure("invalid_reply", process.returncode, record)
    return replies[0]


def submit(bundle, name, receipt):
    validate_bundle(bundle)
    if not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,47}", name):
        raise ValueError("Invalid run name")
    stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    relative = "runs/" + name + "/fc/" + stamp + "-" + digest(bundle / "inputs.json")[:12]
    archive = io.BytesIO()
    with tarfile.open(fileobj=archive, mode="w:gz") as stream:
        for path in sorted(bundle.rglob("*")):
            if path.is_file():
                stream.add(str(path), arcname=str(path.relative_to(bundle)))
    validate_bundle(bundle)
    encoded = base64.b64encode(archive.getvalue()).decode()
    body = 'module load "$FC_MODULE"\nmodule load "$PT_MODULE"\nmodule load "$LC_MODULE"\n'
    body += "python3 - <<'E2_PYTHON'\nimport base64, io, json, os, subprocess, tarfile\nfrom pathlib import Path\n"
    body += "relative = " + repr(relative) + "\n"
    body += "run = Path(os.environ['EDA_WORK_ROOT']) / relative\nrun.mkdir(parents=True)\n"
    body += "data = base64.b64decode(" + repr(encoded) + ")\n"
    body += "with tarfile.open(fileobj=io.BytesIO(data), mode='r:gz') as archive:\n"
    body += " for member in archive.getmembers():\n  path = Path(member.name)\n  assert not path.is_absolute() and '..' not in path.parts and member.isfile()\n archive.extractall(str(run))\n"
    body += "log = (run / 'supervisor.log').open('w')\n"
    body += "process = subprocess.Popen(['python3', 'runner.py', 'worker'], cwd=str(run), stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT, start_new_session=True)\n"
    body += "print('E2_RESULT ' + json.dumps({'relativeRun': relative, 'supervisorPid': process.pid}))\nE2_PYTHON\n"
    receipt.parent.mkdir(parents=True, exist_ok=True)
    write_json(receipt, {"relativeRun": relative, "inputManifestHash": digest(bundle / "inputs.json"),
                        "state": "submission_pending"})
    result = remote(load_site(), body)
    if (set(result) != {"relativeRun", "supervisorPid"} or result["relativeRun"] != relative
            or type(result["supervisorPid"]) is not int):
        raise ValueError("Invalid submission reply")
    result["inputManifestHash"] = digest(bundle / "inputs.json")
    receipt.parent.mkdir(parents=True, exist_ok=True)
    write_json(receipt, result)
    return result


def synthesis_run(receipt):
    value = json.loads(receipt.read_text())["relativeRun"]
    if not re.fullmatch(r"runs/[a-z0-9-]+/fc/[0-9TZ]+-[a-f0-9]{12}", value):
        raise ValueError("Invalid synthesis receipt")
    return value


def submit_equivalence(receipt, output, threads, timeout):
    source = synthesis_run(receipt)
    if type(threads) is not int or not 1 <= threads <= 16 or not 0 < timeout <= 86400:
        raise ValueError("Invalid proof resource budget")
    archive = io.BytesIO()
    with tarfile.open(fileobj=archive, mode="w:gz") as stream:
        stream.add(str(Path(__file__)), arcname="runner.py")
        stream.add(str(ROOT / "flow/equivalence.tcl"), arcname="flow/equivalence.tcl")
    stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    relative = source.split("/fc/")[0] + "/fm/" + stamp + "-" + hashlib.sha256(archive.getvalue()).hexdigest()[:12]
    body = 'module load "$FM_MODULE"\n'
    body += "python3 - <<'E2_PYTHON'\nimport base64, io, json, os, subprocess, sys, tarfile\nfrom pathlib import Path\n"
    body += "relative = " + repr(relative) + "\n"
    body += "run = Path(os.environ['EDA_WORK_ROOT']) / relative\nrun.mkdir(parents=True)\n"
    body += "data = base64.b64decode(" + repr(base64.b64encode(archive.getvalue()).decode()) + ")\n"
    body += "with tarfile.open(fileobj=io.BytesIO(data), mode='r:gz') as archive:\n"
    body += " for member in archive.getmembers():\n  assert member.name in {'runner.py', 'flow/equivalence.tcl'} and member.isfile()\n archive.extractall(str(run))\n"
    body += "sys.path.insert(0, str(run))\nfrom runner import freeze_equivalence\n"
    body += "freeze_equivalence(Path(os.environ['EDA_WORK_ROOT']) / " + repr(source) + ", run, " + repr(threads) + ", " + repr(timeout) + ")\n"
    body += "log = (run / 'supervisor.log').open('w')\n"
    body += "process = subprocess.Popen(['python3', 'runner.py', 'equivalence-worker'], cwd=str(run), stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT, start_new_session=True)\n"
    body += "print('E2_RESULT ' + json.dumps({'relativeRun': relative, 'supervisorPid': process.pid}))\nE2_PYTHON\n"
    output.parent.mkdir(parents=True, exist_ok=True)
    write_json(output, {"relativeRun": relative, "state": "submission_pending"})
    result = remote(load_site(), body, extra_keys=("FM_MODULE", "E2_TIMING_DBS"))
    if (set(result) != {"relativeRun", "supervisorPid"} or result["relativeRun"] != relative
            or type(result["supervisorPid"]) is not int):
        raise ValueError("Invalid proof submission reply")
    write_json(output, result)
    return result


def freeze_equivalence(source, run, threads, timeout):
    result = json.loads((source / "summary.json").read_text())
    if result.get("flowSucceeded") is not True:
        raise ValueError("Completed mapping is required")
    inputs = json.loads((source / "inputs.json").read_text())
    outputs = json.loads((source / "output-manifest.json").read_text())
    for name, expected in inputs.items():
        if digest(source / relative_name(name)) != expected:
            raise ValueError("Synthesis input changed")
    config = json.loads((source / "configuration.json").read_text())
    guidance = config.get("guidance_outputs", ["mapping.svf"])
    if (not isinstance(guidance, list) or not guidance
            or any(not isinstance(name, str) or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_-]*\.svf", name) for name in guidance)
            or len(guidance) != len(set(guidance))):
        raise ValueError("Invalid guidance input list")
    for directory in ("rtl", "evidence"):
        shutil.copytree(source / directory, run / directory)
    (run / "implementation").mkdir()
    for name in ["mapped.v", "mapped.sdc"] + guidance:
        path = "outputs/" + name
        if digest(source / path) != outputs[path]:
            raise ValueError("Mapping output changed")
        shutil.copyfile(source / path, run / "implementation" / name)
    for src, dst in (("inputs.json", "synthesis-inputs.json"),
                     ("output-manifest.json", "synthesis-outputs.json"),
                     ("summary.json", "synthesis-result.json")):
        shutil.copyfile(source / src, run / "evidence" / dst)
    (run / "libraries").mkdir()
    libraries = []
    library_files = []
    for index, entry in enumerate(os.environ["E2_TIMING_DBS"].splitlines()):
        path = Path(entry)
        name = "libraries/model-" + str(index) + ".db"
        expected = digest(path)
        shutil.copyfile(path, run / name)
        if digest(run / name) != expected:
            raise ValueError("Library copy changed")
        libraries.append({"path": entry, "sha256": expected})
        library_files.append(name)
    if not libraries:
        raise ValueError("Logic library models are required")
    write_json(run / "library-inputs.json", libraries)
    config.update(threads=threads, timeout_seconds=timeout, library_files=library_files,
                  guidance_files=["implementation/" + name for name in guidance])
    write_json(run / "configuration.json", config)
    write_json(run / "inputs.json", {str(path.relative_to(run)): digest(path)
               for path in sorted(run.rglob("*")) if path.is_file()})


def status(receipt):
    record = json.loads(receipt.read_text())
    relative = record["relativeRun"]
    if not re.fullmatch(r"runs/[a-z0-9-]+/(?:fc|fm)/[0-9TZ]+-[a-f0-9]{12}", relative):
        raise ValueError("Invalid run receipt")
    body = "python3 - <<'E2_PYTHON'\nimport json, os\nfrom pathlib import Path\n"
    body += "run = Path(os.environ['EDA_WORK_ROOT']) / " + repr(relative) + "\n"
    body += "path = run / 'summary.json'\nvalue = json.loads(path.read_text()) if path.exists() else {'state': 'pending'}\nprint('E2_RESULT ' + json.dumps(value))\nE2_PYTHON\n"
    return checked_status(remote(load_site(), body))


def checked_status(result):
    fields = {"state", "reason", "started", "ended", "threads", "exitStatus", "scriptStarted",
              "scriptCompleted", "scriptErrors", "flowSucceeded", "messageCodes", "startupExpiration",
              "toolVersion", "exploratory", "cleanAcceptance", "mappedEquivalence", "frozenInputsStable",
              "libraryInputsStable", "mappedNetlistHash", "constraintsHash", "guidanceHash",
              "inputManifestHash", "libraryModelHashes", "guidanceHashes", "metrics", "proof"}
    if set(result) - fields:
        raise ValueError("Unexpected status field")
    if "metrics" in result and set(result["metrics"]) - METRICS:
        raise ValueError("Unexpected metric field")
    if "proof" in result and set(result["proof"]) - {"toolResult", "passing", "failing", "aborted", "unverified", "blackBoxes", "unusedLibraryModels"}:
        raise ValueError("Unexpected proof field")
    enums = {"state": {"pending", "running", "finished", "failed"},
             "reason": {"Worker setup or execution failed"},
             "mappedEquivalence": {"not run", "not established", "passed"}}
    booleans = {"scriptStarted", "scriptCompleted", "flowSucceeded", "startupExpiration",
                "exploratory", "cleanAcceptance", "frozenInputsStable", "libraryInputsStable"}
    for key, value in result.items():
        if key in enums and value not in enums[key]:
            raise ValueError("Unexpected status value")
        if key in booleans and type(value) is not bool:
            raise ValueError("Invalid status flag")
        if key in {"started", "ended", "threads", "exitStatus", "scriptErrors"}:
            if type(value) not in (int, float) or not math.isfinite(value):
                raise ValueError("Invalid status number")
        if key in {"mappedNetlistHash", "constraintsHash", "guidanceHash", "inputManifestHash"}:
            if value is not None and (not isinstance(value, str) or not re.fullmatch("[a-f0-9]{64}", value)):
                raise ValueError("Invalid result digest")
        if key in {"libraryModelHashes", "guidanceHashes"}:
            if not isinstance(value, list) or any(not isinstance(item, str) or not re.fullmatch("[a-f0-9]{64}", item) for item in value):
                raise ValueError("Invalid library digest")
        if key == "toolVersion" and value is not None:
            if not isinstance(value, str) or not re.fullmatch(r"[A-Z]-20\d\d\.\d+(?:-SP\d+)?", value):
                raise ValueError("Invalid tool version")
        if key == "messageCodes":
            if not isinstance(value, list) or any(not isinstance(code, str) or not re.fullmatch(r"[A-Z]+-\d+", code) for code in value):
                raise ValueError("Invalid tool message code")
        if key in {"metrics", "proof"}:
            for number in value.values():
                if number is not None and (type(number) not in (int, float) or not math.isfinite(number)):
                    raise ValueError("Invalid measurement")
    return result


def log_result(log, exit_status, complete):
    parts = log.split("\nE2_SCRIPT_BEGIN\n", 1)
    startup, script = (parts[0], parts[1]) if len(parts) == 2 else (log, "")
    errors = len(re.findall(r"^\s*Error:", script, re.M))
    versions = re.findall(r"Version\s*:?\s*([A-Z]-20\d\d\.\d+(?:-SP\d+)?)", log)
    return {"exitStatus": exit_status, "scriptStarted": len(parts) == 2,
            "scriptCompleted": complete, "scriptErrors": errors,
            "flowSucceeded": exit_status == 0 and len(parts) == 2 and complete and errors == 0,
            "messageCodes": sorted(set(re.findall(r"\(([A-Z]+-\d+)\)", script))),
            "startupExpiration": "This script has expired" in startup,
            "toolVersion": versions[0] if versions else None,
            "exploratory": True, "cleanAcceptance": False, "mappedEquivalence": "not run"}


def read_metrics(path, timing_check=None):
    values = {"unconstrained_endpoints": None}
    for line in path.read_text().splitlines():
        name, value = line.split("\t", 1)
        if name not in METRICS:
            raise ValueError("Unexpected report field")
        number = None if value == "unavailable" else float(value)
        if number is not None and not math.isfinite(number):
            raise ValueError("Invalid report value")
        values[name] = number
    if timing_check is not None:
        for label in ("Errors", "Warnings"):
            matches = re.findall(label + r"\s*:\s*(\d+)", timing_check)
            values["timing_check_" + label.lower()] = int(matches[-1]) if matches else None
        if values["timing_check_errors"] == 0 and values["timing_check_warnings"] == 0:
            values["unconstrained_endpoints"] = 0
    return values


def library_snapshot():
    libraries = []
    for entry in os.environ["E2_NDM_LIBS"].splitlines() + [os.environ["E2_RC_FILE"]]:
        path = Path(entry)
        files = sorted(item for item in path.rglob("*") if item.is_file()) if path.is_dir() else [path]
        libraries.extend({"path": str(item), "sha256": digest(item)} for item in files)
    return libraries


def write_settings(path, config, threads):
    scalar_names = {"period_ns", "input_delay_ns", "output_delay_ns", "uncertainty_ns",
                    "input_transition_ns", "output_load_ff", "timeout_seconds"}
    lines = ["set " + key + " " + str(config[key]) for key in sorted(scalar_names)]
    for key in ("top", "power_net", "ground_net"):
        if key in config:
            if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", config[key]):
                raise ValueError("Invalid flow identifier")
            lines.append("set " + key + " " + config[key])
    lines += ["set threads " + str(threads), "set rtl_files {" + " ".join(config["rtl_files"]) + "}"]
    path.write_text("\n".join(lines) + "\n")


def execute_worker(tool_script="flow/synthesis.tcl"):
    if tool_script not in {"flow/synthesis.tcl", "flow/physical.tcl"}:
        raise ValueError("Unsupported tool script")
    run = Path.cwd()
    inputs = validate_bundle(run, allowed_extra=("supervisor.log",))
    config = json.loads((run / "configuration.json").read_text())
    memory = Path("/proc/meminfo").read_text()
    available = int(re.search(r"MemAvailable:\s+(\d+)", memory).group(1)) * 1024
    if available < 16 * 1024 ** 3:
        raise RuntimeError("Insufficient available memory")
    threads = min(config["threads"], os.cpu_count() or 1)
    if os.getloadavg()[0] > 0.9 * (os.cpu_count() or 1):
        threads = min(threads, 4)
    (run / "reports").mkdir()
    (run / "outputs").mkdir()
    resources = {"logicalCpus": os.cpu_count(), "load": os.getloadavg(),
                 "availableMemoryBytes": available, "diskFreeBytes": shutil.disk_usage(str(run)).free,
                 "threads": threads, "accountId": os.getuid()}
    write_json(run / "resources.json", resources)
    libraries = library_snapshot()
    write_json(run / "library-inputs.json", libraries)
    write_settings(run / "settings.tcl", config, threads)
    environment = dict(os.environ, E2_SYNTH_RUN=str(run))
    started = time.time()
    write_json(run / "summary.json", {"state": "running", "started": started, "threads": threads})
    with (run / "tool.log").open("w") as log:
        process = subprocess.Popen(["fc_shell", "-f", tool_script], env=environment,
                                   stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
        write_json(run / "process.json", {"pid": process.pid, "start": started,
                   "command": ["fc_shell", "-f", tool_script]})
        try:
            code = process.wait(timeout=config["timeout_seconds"])
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGTERM)
            try:
                process.wait(timeout=30)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait()
            code = 124
    result = log_result((run / "tool.log").read_text(errors="replace"), code,
                        (run / "outputs/complete").exists())
    result.update(state="finished", started=started, ended=time.time(), threads=threads)
    write_json(run / "process-result.json", result)
    result["frozenInputsStable"] = all(digest(run / name) == value for name, value in inputs.items())
    result["libraryInputsStable"] = all(digest(Path(item["path"])) == item["sha256"]
                                        for item in libraries)
    result["flowSucceeded"] = (result["flowSucceeded"] and result["frozenInputsStable"]
                               and result["libraryInputsStable"])
    outputs = {str(path.relative_to(run)): digest(path)
               for path in sorted((run / "outputs").rglob("*")) if path.is_file()}
    write_json(run / "output-manifest.json", outputs)
    result["mappedNetlistHash"] = outputs.get("outputs/mapped.v")
    result["constraintsHash"] = outputs.get("outputs/mapped.sdc")
    metrics = run / "reports/metrics.tsv"
    if metrics.exists():
        result["metrics"] = read_metrics(metrics, (run / "reports/timing-check.txt").read_text())
    write_json(run / "summary.json", result)


def worker(operation=execute_worker):
    try:
        operation()
    except Exception:
        traceback.print_exc()
        write_json(Path.cwd() / "summary.json", {"state": "failed", "cleanAcceptance": False,
                   "reason": "Worker setup or execution failed"})
        raise


def read_proof(status_text, black_box_text, tool_result, mapped_netlist="", point_reports=None):
    result = {"toolResult": tool_result}
    for key, label in (("passing", "Passing"), ("failing", "Failing"),
                       ("aborted", "Aborted"), ("unverified", "Unverified")):
        matches = re.findall(r"(\d+)\s+" + label + r" compare points", status_text, re.I)
        if not matches:
            matches = re.findall(label + r" Points:\s*(\d+)", status_text, re.I)
        result[key] = int(matches[-1]) if matches else None
        if result[key] is None and point_reports and key in point_reports:
            empty = r"\bno\s+(?:\w+\s+){0,2}" + key + r"(?:\s+compare)?\s+points\b"
            if re.search(empty, point_reports[key], re.I):
                result[key] = 0
    result["blackBoxes"] = 0 if re.search(r"No black.boxes", black_box_text, re.I) else None
    models = re.findall(r"^[ \t]*([A-Za-z]{1,8})[ \t]+(\S+)[ \t]*$", black_box_text, re.M)
    power_model = lambda flags, name: flags == "m" and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*#PWR_FM_BBOX", name)
    empty_model = lambda flags, name: flags == "e" and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name)
    if (models and mapped_netlist and all(power_model(flags, name) or empty_model(flags, name)
                                         for flags, name in models)):
        names = {name.split("#", 1)[0] for flags, name in models}
        result["blackBoxes"] = sum(bool(re.search(r"\b" + re.escape(name) + r"\b", mapped_netlist)) for name in names)
        result["unusedLibraryModels"] = len(names) - result["blackBoxes"]
    return result


def equivalence_worker():
    run = Path.cwd()
    inputs = validate_bundle(run, allowed_extra=("supervisor.log",))
    config = json.loads((run / "configuration.json").read_text())
    available = int(re.search(r"MemAvailable:\s+(\d+)", Path("/proc/meminfo").read_text()).group(1)) * 1024
    if available < 16 * 1024 ** 3:
        raise RuntimeError("Insufficient available memory")
    threads = min(config["threads"], os.cpu_count() or 1)
    if os.getloadavg()[0] > 0.9 * (os.cpu_count() or 1):
        threads = min(threads, 4)
    (run / "reports").mkdir()
    (run / "outputs").mkdir()
    write_json(run / "resources.json", {"logicalCpus": os.cpu_count(), "load": os.getloadavg(),
               "availableMemoryBytes": available, "threads": threads, "accountId": os.getuid(),
               "diskFreeBytes": shutil.disk_usage(str(run)).free})
    lines = ["set top " + config["top"], "set threads " + str(threads),
             "set rtl_files {" + " ".join(config["rtl_files"]) + "}",
             "set library_files {" + " ".join(config["library_files"]) + "}",
             "set guidance_files {" + " ".join(config["guidance_files"]) + "}"]
    (run / "settings.tcl").write_text("\n".join(lines) + "\n")
    started = time.time()
    write_json(run / "summary.json", {"state": "running", "started": started, "threads": threads})
    command = ["fm_shell", "-f", "flow/equivalence.tcl"]
    with (run / "tool.log").open("w") as log:
        process = subprocess.Popen(command, stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
        write_json(run / "process.json", {"pid": process.pid, "start": started, "command": command})
        try:
            code = process.wait(timeout=config["timeout_seconds"])
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGTERM)
            try:
                process.wait(timeout=30)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait()
            code = 124
    result = log_result((run / "tool.log").read_text(errors="replace"), code,
                        (run / "outputs/complete").exists())
    result.update(state="finished", started=started, ended=time.time(), threads=threads)
    write_json(run / "process-result.json", result)
    result["frozenInputsStable"] = all(digest(run / name) == value for name, value in inputs.items())
    result["mappedNetlistHash"] = digest(run / "implementation/mapped.v")
    result["constraintsHash"] = digest(run / "implementation/mapped.sdc")
    result["guidanceHash"] = digest(run / config["guidance_files"][0])
    result["guidanceHashes"] = [digest(run / name) for name in config["guidance_files"]]
    result["inputManifestHash"] = digest(run / "inputs.json")
    result["libraryModelHashes"] = [digest(run / name) for name in config["library_files"]]
    read_report = lambda name: (run / name).read_text() if (run / name).exists() else ""
    raw = read_report("outputs/result.txt").strip()
    design_text = (run / "implementation/mapped.v").read_text()
    design_text += "\n".join((run / "rtl" / name).read_text() for name in config["rtl_files"])
    result["proof"] = read_proof(read_report("reports/status.txt"),
                                  read_report("reports/black-boxes.txt"), int(raw) if raw in {"0", "1"} else None,
                                  design_text,
                                  {name: read_report("reports/" + name + ".txt")
                                   for name in ("failing", "aborted", "unverified")})
    proof = result["proof"]
    accepted = (result["flowSucceeded"] and result["frozenInputsStable"] and proof["toolResult"] == 1
                and proof["passing"] is not None and proof["passing"] > 0
                and all(proof[key] == 0 for key in ("failing", "aborted", "unverified", "blackBoxes")))
    result["mappedEquivalence"] = "passed" if accepted else "not established"
    write_json(run / "output-manifest.json", {str(path.relative_to(run)): digest(path)
               for path in sorted((run / "outputs").rglob("*")) if path.is_file()})
    write_json(run / "summary.json", result)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command")
    prepare = commands.add_parser("freeze")
    prepare.add_argument("--rtl", type=Path, required=True)
    prepare.add_argument("--acceptance", type=Path, required=True)
    prepare.add_argument("--output", type=Path, required=True)
    for name, default in (("period-ns", 1.0), ("input-delay-ns", 0.2), ("output-delay-ns", 0.2),
                          ("uncertainty-ns", 0.05), ("input-transition-ns", 0.05),
                          ("output-load-ff", 2.0), ("timeout-seconds", 3600.0)):
        prepare.add_argument("--" + name, type=float, default=default)
    prepare.add_argument("--threads", type=int, default=16)
    launch = commands.add_parser("submit")
    launch.add_argument("--bundle", type=Path, required=True)
    launch.add_argument("--name", required=True)
    launch.add_argument("--receipt", type=Path, required=True)
    query = commands.add_parser("status")
    query.add_argument("--receipt", type=Path, required=True)
    commands.add_parser("worker")
    commands.add_parser("equivalence-worker")
    proof = commands.add_parser("equivalence")
    proof.add_argument("--receipt", type=Path, required=True)
    proof.add_argument("--output", type=Path, required=True)
    proof.add_argument("--threads", type=int, default=16)
    proof.add_argument("--timeout-seconds", type=float, default=3600.0)
    args = parser.parse_args()
    if args.command is None:
        parser.error("A command is required")
    if args.command == "freeze":
        budgets = {key: value for key, value in vars(args).items()
                   if key not in ("command", "rtl", "acceptance", "output")}
        result = freeze(args.rtl, args.acceptance, args.output, budgets)
    elif args.command == "submit":
        result = submit(args.bundle, args.name, args.receipt)
    elif args.command == "status":
        result = status(args.receipt)
    elif args.command == "equivalence":
        result = submit_equivalence(args.receipt, args.output, args.threads, args.timeout_seconds)
    elif args.command == "equivalence-worker":
        worker(equivalence_worker)
        return
    else:
        worker()
        return
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
