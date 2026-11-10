# SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
# SPDX-License-Identifier: MIT
"""Freeze transport RTL, run commercial proofs, or run bounded reference checks."""

import argparse
import hashlib
import json
import os
import re
import shutil
import signal
import subprocess
import tempfile
import time
from pathlib import Path, PurePosixPath

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
SCHEMA = "ditdah-e2.debug-transport.v1"
REFERENCE_SCHEMA = "ditdah-e2.debug-transport.reference.v1"
TOP = "dmi_bridge_formal"
RTL_NAME = "DitDahE2DmiBridge.sv"
WRAPPER_NAME = "dmi_bridge_formal.sv"
ASSERTIONS = (
    "upstream_response_valid_stable",
    "upstream_response_payload_stable",
    "upstream_single_outstanding",
    "upstream_backpressure_while_owned",
    "upstream_response_has_owner",
    "upstream_response_has_downstream_reply",
    "upstream_response_payload",
    "downstream_request_valid_stable",
    "downstream_request_payload_stable",
    "downstream_response_ready_only_with_debt",
    "downstream_request_has_owner",
    "downstream_request_once",
    "downstream_request_payload",
    "downstream_reply_has_owner",
)
ASSUMPTIONS = (
    "initial_common_cold_reset",
    "no_later_cold_reset",
    "upstream_request_valid_stable",
    "upstream_request_payload_stable",
    "downstream_response_valid_stable",
    "downstream_response_payload_stable",
    "downstream_response_has_request",
)
COVERS = (
    "cover_upstream_request_backpressure",
    "cover_upstream_stalled_error_response",
    "cover_upstream_second_response",
    "cover_downstream_stalled_accept",
    "cover_downstream_zero_latency_reply",
)
MUTATIONS = {
    "payload": "downstream_request_payload",
    "early-ack": "upstream_response_has_downstream_reply",
    "reset-admission": "upstream_backpressure_while_owned",
}
CASES = ("safety", "covers", *("negative-" + name for name in MUTATIONS))
EXPECTED_RESET = (
    "expression reset file_type {} sequence {} file_name {} hier_path {} "
    "time {} start_time {} end_time {} time_scale {} non_resettable_regs {} "
    "formal false bound 0 max_iterations {} none false reset_declared true"
)


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def sha(value):
    return hashlib.sha256(value).hexdigest()


def write_json(path, value):
    Path(path).write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def labels(text, kind):
    return set(
        re.findall(
            r"\b([A-Za-z_][A-Za-z0-9_]*)\s*:\s*" + kind + r"\s*(?:property\s*)?\(", text
        )
    )


def check_wrapper(value):
    text = value.decode()
    if (
        labels(text, "assert") != set(ASSERTIONS)
        or labels(text, "assume") != set(ASSUMPTIONS)
        or labels(text, "cover") != set(COVERS)
    ):
        raise ValueError("Formal property inventory differs from the runner")
    if text.count("DitDahE2DmiBridge dut (.*);") != 1:
        raise ValueError("Formal DUT binding differs")


def ports(rtl_bytes):
    text = rtl_bytes.decode()
    if text.count("module DitDahE2DmiBridge(") != 1:
        raise ValueError("Unexpected transport module identity")
    header = text.split("module DitDahE2DmiBridge(", 1)[1].split(");", 1)[0]
    result = {}
    direction = width = None
    for item in header.split(","):
        item = item.strip()
        match = re.fullmatch(r"(input|output)\s+(?:\[(\d+):(\d+)\]\s+)?(\w+)", item)
        if match:
            direction, high, low, name = match.groups()
            width = int(high) - int(low) + 1 if high else 1
        elif re.fullmatch(r"\w+", item) and direction:
            name = item
        else:
            raise ValueError("Unexpected generated transport port declaration")
        if name in result:
            raise ValueError("Duplicate transport port")
        result[name] = (direction, width)
    expected = {"clock": ("input", 1), "tck": ("input", 1), "reset": ("input", 1)}
    for side, request_direction in (("upstream", "input"), ("downstream", "output")):
        response_direction = "output" if side == "upstream" else "input"
        expected.update(
            {
                side + "_request_valid": (request_direction, 1),
                side + "_request_ready": (
                    "output" if request_direction == "input" else "input",
                    1,
                ),
                side + "_request_bits_address": (request_direction, 7),
                side + "_request_bits_data": (request_direction, 32),
                side + "_request_bits_op": (request_direction, 2),
                side + "_response_valid": (response_direction, 1),
                side + "_response_ready": (
                    "output" if response_direction == "input" else "input",
                    1,
                ),
                side + "_response_bits_data": (response_direction, 32),
                side + "_response_bits_status": (response_direction, 2),
            }
        )
    if result != expected:
        raise ValueError(
            "Transport interface differs from the frozen 41/34-bit contract"
        )


def relative(name):
    path = PurePosixPath(name)
    if not name or path.is_absolute() or ".." in path.parts or "\\" in name:
        raise ValueError("Unsafe source name")
    return path


def load_candidate(rtl, source_root, expected_hash):
    if not re.fullmatch(r"[0-9a-f]{64}", expected_hash):
        raise ValueError("Expected RTL SHA256 must be lowercase hexadecimal")
    build = json.loads((rtl / "manifest.json").read_text())
    if (
        build.get("top") != "DitDahE2DmiBridge"
        or build.get("exitStatus") != 0
        or build.get("parameters", {}).get("enableJtag", False) is not False
        or build.get("parameters", {}).get("jtagIdcode") is not None
    ):
        raise ValueError("RTL build is not the frozen independent bridge configuration")
    hashes = build.get("rtlHashes", {})
    filelist = rtl / "filelist.f"
    files = filelist.read_text().splitlines() if filelist.exists() else sorted(hashes)
    if (
        not files
        or len(files) != len(set(files))
        or set(files) != set(hashes)
        or RTL_NAME not in files
        or hashes.get(RTL_NAME) != expected_hash
    ):
        raise ValueError("RTL file list or expected digest differs")
    contents = {}
    for name in files:
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*\.sv", name):
            raise ValueError("Unsafe RTL filename")
        value = (rtl / name).read_bytes()
        if sha(value) != hashes[name]:
            raise ValueError("Generated RTL digest differs from its build manifest")
        contents[name] = value
    ports(contents[RTL_NAME])
    for name, expected in build.get("sourceHashes", {}).items():
        path = relative(name)
        if digest(source_root / path) != expected:
            raise ValueError("Generation source digest differs: " + path.as_posix())
    return build, contents


def mutate(value, name):
    text = value.decode()
    if name == "payload":
        pattern = r"(\bassign\s+downstream_request_bits_data\s*=\s*)([^;]+);"
        text, count = re.subn(pattern, lambda m: m[1] + "32'h1 ^ (" + m[2] + ");", text)
    elif name == "early-ack":
        if not re.search(r"\baccepted\b", text):
            raise ValueError(
                "Early acknowledgement mutation lacks its acceptance signal"
            )
        pattern = r"if\s*\(([^()]+)\)(\s*begin\s*\n\s*ack\s*<=\s*requestSync;)"
        text, count = re.subn(
            pattern, lambda m: "if (accepted || (" + m[1] + "))" + m[2], text
        )
    elif name == "reset-admission":
        if not re.search(r"\bbusy\b", text):
            raise ValueError("Reset admission mutation lacks its busy signal")
        pattern = r"\bassign\s+upstream_request_ready\s*=\s*[^;]+;"
        text, count = re.subn(pattern, "assign upstream_request_ready = ~busy;", text)
    else:
        raise ValueError("Unknown transport mutation")
    if count != 1 or text == value.decode():
        raise ValueError("Transport mutation anchor is missing or ambiguous: " + name)
    return text.encode()


def tcl_plan(plan):
    names = [plan["top"], *plan["goals"], *plan["covers"], *plan["assumptions"]]
    if any(not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.]*", name) for name in names):
        raise ValueError("Unsafe native property name")
    if any(not re.fullmatch(r"[A-Za-z0-9_./-]+", name) for name in plan["sources"]):
        raise ValueError("Unsafe native source name")
    return (
        "set top "
        + plan["top"]
        + "\n"
        + "set sources {"
        + " ".join(plan["sources"])
        + "}\n"
        + "set goals {"
        + " ".join(plan["goals"])
        + "}\n"
        + "set expected "
        + plan["expected"]
        + "\n"
        + "set covers {"
        + " ".join(plan["covers"])
        + "}\n"
        + "set expected_assumptions {"
        + " ".join(plan["assumptions"])
        + "}\n"
        + "set time_limit "
        + str(plan["timeLimitSeconds"])
        + "s\n"
    ).encode()


def case_definition(name, rtl, wrapper, collector, time_limit):
    negative = name.startswith("negative-")
    mutation = name.removeprefix("negative-") if negative else None
    target = MUTATIONS.get(mutation)
    contents = dict(rtl)
    if mutation:
        contents[RTL_NAME] = mutate(contents[RTL_NAME], mutation)
    contents[WRAPPER_NAME] = wrapper
    plan = {
        "top": TOP,
        "sources": [*rtl, WRAPPER_NAME],
        "goals": [target] if negative else list(ASSERTIONS) if name == "safety" else [],
        "covers": list(COVERS) if name == "covers" else [],
        "expected": "cex" if negative else "proven",
        "assumptions": [TOP + "." + label for label in ASSUMPTIONS],
        "timeLimitSeconds": time_limit,
        "mutation": mutation,
        "negativeTarget": target,
    }
    contents["collect.tcl"] = collector
    contents["plan.tcl"] = tcl_plan(plan)
    plan["inputs"] = sorted(contents)
    return plan, contents


def prepare_bundle(args):
    build, rtl = load_candidate(args.rtl, args.source_root, args.expected_rtl_sha256)
    wrapper = (HERE / WRAPPER_NAME).read_bytes()
    collector = (HERE / "collect.tcl").read_bytes()
    runner = Path(__file__).read_bytes()
    time_limit = getattr(args, "time_limit", 60)
    check_wrapper(wrapper)
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    output.chmod(0o700)
    (output / "rtl").mkdir()
    for name, value in rtl.items():
        (output / "rtl" / name).write_bytes(value)
    for name, value in (
        (WRAPPER_NAME, wrapper),
        ("collect.tcl", collector),
        ("runner.py", runner),
    ):
        (output / name).write_bytes(value)
    (output / "rtl-build.json").write_text(
        json.dumps(build, indent=2, sort_keys=True) + "\n"
    )
    manifest = {
        "schema": SCHEMA,
        "top": "DitDahE2DmiBridge",
        "rtlSha256": args.expected_rtl_sha256,
        "rtlHashes": {name: sha(value) for name, value in rtl.items()},
        "verificationHashes": {
            WRAPPER_NAME: sha(wrapper),
            "collect.tcl": sha(collector),
            "run.py": sha(runner),
        },
        "requestPayloadBits": 41,
        "responsePayloadBits": 34,
        "outstanding": 1,
        "resetScope": "initial_common_cold_reset",
        "clockScope": "arbitrary_independent_digital",
        "timeLimitSeconds": time_limit,
        "cases": list(CASES),
        "fullCoreProven": False,
    }
    write_json(output / "manifest.json", manifest)
    for name in CASES:
        case = output / "cases" / name
        case.mkdir(parents=True)
        plan, contents = case_definition(name, rtl, wrapper, collector, time_limit)
        for filename, value in contents.items():
            (case / filename).write_bytes(value)
        write_json(case / "plan.json", plan)
    return manifest


def validate_frozen(evidence):
    manifest = json.loads((evidence / "manifest.json").read_text())
    if (
        manifest.get("schema") != SCHEMA
        or manifest.get("top") != "DitDahE2DmiBridge"
        or manifest.get("requestPayloadBits") != 41
        or manifest.get("responsePayloadBits") != 34
        or manifest.get("outstanding") != 1
        or manifest.get("resetScope") != "initial_common_cold_reset"
        or manifest.get("clockScope") != "arbitrary_independent_digital"
        or manifest.get("cases") != list(CASES)
        or manifest.get("fullCoreProven") is not False
        or type(manifest.get("timeLimitSeconds")) is not int
        or manifest["timeLimitSeconds"] < 1
    ):
        raise ValueError("Transport evidence configuration differs")
    recorded = manifest.get("verificationHashes", {})
    for name in (WRAPPER_NAME, "collect.tcl", "runner.py"):
        key = "run.py" if name == "runner.py" else name
        if digest(evidence / name) != recorded.get(key):
            raise ValueError("Frozen verification source differs")
    if digest(Path(__file__)) != recorded.get("run.py"):
        raise ValueError("Running verifier differs from the frozen verifier")
    build = json.loads((evidence / "rtl-build.json").read_text())
    if build.get("rtlHashes") != manifest.get("rtlHashes"):
        raise ValueError("Frozen RTL build manifest differs")
    rtl = {}
    for name, expected in manifest["rtlHashes"].items():
        value = (evidence / "rtl" / name).read_bytes()
        if sha(value) != expected:
            raise ValueError("Frozen RTL input differs")
        rtl[name] = value
    if sha(rtl[RTL_NAME]) != manifest.get("rtlSha256"):
        raise ValueError("Frozen bridge identity differs")
    wrapper = (evidence / WRAPPER_NAME).read_bytes()
    collector = (evidence / "collect.tcl").read_bytes()
    check_wrapper(wrapper)
    for name in CASES:
        case = evidence / "cases" / name
        plan, contents = case_definition(
            name, rtl, wrapper, collector, manifest["timeLimitSeconds"]
        )
        if json.loads((case / "plan.json").read_text()) != plan:
            raise ValueError("Frozen native query plan differs")
        for filename, value in contents.items():
            if (case / filename).read_bytes() != value:
                raise ValueError("Frozen native proof input differs")
    return manifest


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
    if records.get(("setup", "clock_mode")) != "free_running":
        raise ValueError("Native clock environment is not free-running")
    for field in ("clock", "reset", "assumptions", "global", "reset_assumptions"):
        if records.get(("before", field)) != records.get(("after", field)):
            raise ValueError("Native proof scope changed")
    if records.get(("before", "clock"), "").strip():
        raise ValueError("Free-running clock environment gained a constrained clock")
    if any(
        records.get(("before", key)) != "" for key in ("global", "reset_assumptions")
    ):
        raise ValueError("Unexpected native environment assumption")
    if records.get(("before", "reset"), "").strip() != EXPECTED_RESET:
        raise ValueError("Native initial reset scope differs")
    expected_assumptions = " ".join(sorted(plan["assumptions"]))
    if records.get(("before", "assumptions")) != expected_assumptions:
        raise ValueError("Native input assumptions differ")
    for label in plan["goals"]:
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
        expected_clock = "tck" if label.startswith("upstream_") else "clock"
        for key in ("name", "type", "command", "disabled"):
            if records.get(("before." + label, key)) != required[key]:
                raise ValueError("Native assertion identity differs before proof")
        for tag in ("before." + label, prefix):
            if records.get((tag, "clock")) not in (None, "", expected_clock):
                raise ValueError("Native assertion clock differs")
            if records.get((tag, "edge")) not in (None, "", "posedge"):
                raise ValueError("Native assertion edge differs")
        for key in ("expression", "precondition", "clock", "edge"):
            if records.get(("before." + label, key)) != records.get((prefix, key)):
                raise ValueError("Native assertion identity changed")
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
        "goals": len(plan["goals"]),
        "covers": len(plan["covers"]),
        "verdict": plan["expected"],
    }


def output_hashes(case):
    return {
        p.name: digest(p)
        for p in case.iterdir()
        if p.is_file() and (p.name == "native.tsv" or p.suffix == ".vcd")
    }


def collect_case(case, executable, private_root, timeout):
    plan = json.loads((case / "plan.json").read_text())
    inputs = {name: digest(case / name) for name in plan["inputs"]}
    if (case / "receipt.json").exists() or (case / "completion.json").exists():
        raise ValueError("Native attempt already exists")
    try:
        executable = Path(shutil.which(executable) or executable).resolve(strict=True)
    except OSError:
        raise ValueError(case.name + ": native executable was not found") from None
    private = Path(tempfile.mkdtemp(prefix="debug-transport-", dir=private_root))
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
                preexec_fn=affinity,  # noqa: PLW1509
            )
        except OSError:
            raise ValueError(case.name + ": native process failed to start") from None
        receipt = {
            "pid": process.pid,
            "launcherSha256": digest(executable),
            "command": ["jg", *command[1:]],
            "cpu": cpu,
            "inputHashes": inputs,
            "timeoutSeconds": timeout,
            "startedUtc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }
        write_json(case / "receipt.json", receipt)
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
    identity = None
    native_identity = case / "executable.private"
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
        "endedUtc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "inputsUnchanged": unchanged,
        "nativeExecutableSha256": identity,
        "outputHashes": output_hashes(case),
    }
    write_json(case / "completion.json", outcome)
    if timed_out or process.returncode or not unchanged or not identity:
        raise ValueError(case.name + ": native execution did not complete cleanly")
    return check_records(read_records(case / "native.tsv"), plan)


def validate_commercial(evidence):
    validate_frozen(evidence)
    outcomes = []
    for name in CASES:
        case = evidence / "cases" / name
        plan = json.loads((case / "plan.json").read_text())
        receipt = json.loads((case / "receipt.json").read_text())
        completion = json.loads((case / "completion.json").read_text())
        expected_inputs = {
            filename: digest(case / filename) for filename in plan["inputs"]
        }
        if (
            receipt.get("command") != ["jg", "-no_gui", "-fpv", "-tcl", "collect.tcl"]
            or type(receipt.get("pid")) is not int
            or receipt["pid"] <= 0
            or type(receipt.get("cpu")) is not int
            or receipt["cpu"] < 0
            or receipt.get("inputHashes") != expected_inputs
        ):
            raise ValueError("Native receipt does not bind the proof inputs")
        if (
            completion.get("exitStatus") != 0
            or completion.get("timedOut") is not False
            or completion.get("inputsUnchanged") is not True
        ):
            raise ValueError("Native execution did not finish with unchanged inputs")
        for value in (
            receipt.get("launcherSha256"),
            completion.get("nativeExecutableSha256"),
        ):
            if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value):
                raise ValueError("Native tool identity is missing")
        outputs = output_hashes(case)
        if completion.get("outputHashes") != outputs:
            raise ValueError("Native results changed after completion")
        required_traces = set(
            plan["goals"] if plan["expected"] == "cex" else plan["covers"]
        )
        if any(label + ".vcd" not in outputs for label in required_traces):
            raise ValueError("Required native witness is missing")
        result = check_records(read_records(case / "native.tsv"), plan)
        outcomes.append(
            {
                "case": name,
                "mutation": plan["mutation"],
                "negativeTarget": plan["negativeTarget"],
                **result,
            }
        )
    summary = {
        "schema": SCHEMA,
        "exitStatus": 0,
        "commercialGate": "passed",
        "proofScope": "unbounded_transport_safety",
        "rtlSha256": json.loads((evidence / "manifest.json").read_text())["rtlSha256"],
        "outcomes": outcomes,
        "assertionsProven": len(ASSERTIONS),
        "coversReached": len(COVERS),
        "negativeCounterexamples": len(MUTATIONS),
        "assumptions": list(ASSUMPTIONS),
        "abstractions": [
            "ideal_digital_cdc",
            "single_common_cold_reset",
            "arbitrary_clocks_and_backpressure",
        ],
        "excluded": [
            "physical_metastability_mtbf",
            "unilateral_or_transaction_reset",
            "progress_without_fairness",
            "full_core_proof",
        ],
        "fullCoreProven": False,
    }
    write_json(evidence / "summary.json", summary)
    return summary


def selected_assertion(wrapper, target):
    text = wrapper.decode()
    pattern = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*:\s*assert\s*\([^;]*\);")
    seen = []

    def replace(match):
        label = match.group(1)
        seen.append(label)
        return match.group(0) if label == target else label + ": assert(1'b1);"

    changed = pattern.sub(replace, text)
    if set(seen) != set(ASSERTIONS) or seen.count(target) != 1:
        raise ValueError("Reference assertion selection differs")
    return changed.encode()


def reference(evidence, depth, timeout):
    validate_frozen(evidence)
    outcomes = []
    for name in CASES:
        source = evidence / "cases" / name
        plan = json.loads((source / "plan.json").read_text())
        work = evidence / "reference-work" / name
        work.mkdir(parents=True)
        for filename in plan["inputs"]:
            if filename not in ("collect.tcl", "plan.tcl"):
                shutil.copyfile(source / filename, work / filename)
        if plan["negativeTarget"]:
            (work / WRAPPER_NAME).write_bytes(
                selected_assertion(
                    (source / WRAPPER_NAME).read_bytes(), plan["negativeTarget"]
                )
            )
        mode = "cover" if name == "covers" else "bmc"
        case_depth = 2 * depth if name == "covers" else depth
        files = [*plan["sources"]]
        config = (
            "[options]\nmode "
            + mode
            + "\ndepth "
            + str(case_depth)
            + "\ntimeout "
            + str(timeout)
            + "\nmulticlock on\n[engines]\nsmtbmc z3\n[script]\nread -formal -sv -noautowire "
            + " ".join(files)
            + "\nprep -top "
            + TOP
            + " -flatten\n[files]\n"
            + "\n".join(files)
            + "\n"
        )
        (work / "run.sby").write_text(config)
        frozen = {p.name: digest(p) for p in work.iterdir() if p.is_file()}
        try:
            process = subprocess.run(
                ["sby", "-f", "run.sby"],
                check=False,
                cwd=work,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                timeout=timeout + 30,
            )
            log = process.stdout
            returncode = process.returncode
            timed_out = False
        except subprocess.TimeoutExpired as error:
            log = (
                (error.stdout or b"").decode()
                if isinstance(error.stdout, bytes)
                else error.stdout or ""
            )
            returncode = None
            timed_out = True
        (work / "run.log").write_text(log)
        status_path = work / "run" / "status"
        status = (
            "TIMEOUT"
            if timed_out
            else status_path.read_text().split()[0]
            if status_path.exists()
            else "ERROR"
        )
        traces = list((work / "run" / "engine_0").glob("trace*.vcd"))
        negative = plan["negativeTarget"] is not None
        accepted = status == ("FAIL" if negative else "PASS") and returncode == (
            2 if negative else 0
        )
        if accepted and negative:
            accepted = (
                bool(traces)
                and plan["negativeTarget"] in log
                and "Assert failed" in log
            )
        if accepted and name == "covers":
            accepted = log.count("Reached cover statement") == len(COVERS) and len(
                traces
            ) >= len(COVERS)
        if any(digest(work / filename) != value for filename, value in frozen.items()):
            raise ValueError("Reference inputs changed during execution")
        outcomes.append(
            {
                "case": name,
                "mode": mode,
                "depth": case_depth,
                "status": status,
                "exitStatus": returncode,
                "timedOut": timed_out,
                "accepted": accepted,
                "negativeTarget": plan["negativeTarget"],
                "inputHashes": frozen,
                "traceHashes": {p.name: digest(p) for p in traces},
            }
        )
        write_json(evidence / "reference-outcomes.json", outcomes)
        if not accepted:
            break
    accepted = len(outcomes) == len(CASES) and all(row["accepted"] for row in outcomes)
    summary = {
        "schema": REFERENCE_SCHEMA,
        "exitStatus": 0 if accepted else 1,
        "accepted": accepted,
        "proofScope": "bounded_open_source_reference",
        "commercialGate": "not_evaluated",
        "depth": depth,
        "coverDepth": 2 * depth,
        "outcomes": outcomes,
        "fullCoreProven": False,
    }
    write_json(evidence / "reference-summary.json", summary)
    return summary


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    candidate = argparse.ArgumentParser(add_help=False)
    candidate.add_argument("--rtl", type=Path, required=True)
    candidate.add_argument("--source-root", type=Path, default=ROOT)
    candidate.add_argument("--expected-rtl-sha256", required=True)
    candidate.add_argument("--output", type=Path, required=True)
    command = commands.add_parser("prepare", parents=[candidate])
    command.add_argument("--time-limit", type=int, default=60)
    command = commands.add_parser("collect")
    command.add_argument("--evidence", type=Path, required=True)
    command.add_argument("--private-output", type=Path, required=True)
    command.add_argument("--jg")
    command.add_argument("--timeout", type=int, default=1800)
    command = commands.add_parser("validate")
    command.add_argument("--evidence", type=Path, required=True)
    command = commands.add_parser("reference", parents=[candidate])
    command.add_argument("--depth", type=int, default=24)
    command.add_argument("--timeout", type=int, default=120)
    args = parser.parse_args()
    if (
        getattr(args, "time_limit", 1) < 1
        or getattr(args, "timeout", 1) < 1
        or getattr(args, "depth", 24) < 24
    ):
        parser.error("Tool limits must be positive and reference depth at least 24")
    try:
        if args.command == "prepare":
            manifest = prepare_bundle(args)
            result = {
                "prepared": True,
                "cases": len(CASES),
                "rtlSha256": manifest["rtlSha256"],
            }
        elif args.command == "collect":
            evidence = args.evidence.resolve()
            validate_frozen(evidence)
            args.private_output.resolve().mkdir(parents=True, exist_ok=True)
            executable = args.jg or os.environ.get("JG_BIN", "jg")
            for name in CASES:
                collect_case(
                    evidence / "cases" / name,
                    executable,
                    args.private_output.resolve(),
                    args.timeout,
                )
            result = validate_commercial(evidence)
        elif args.command == "validate":
            result = validate_commercial(args.evidence.resolve())
        else:
            evidence = args.output.resolve()
            prepare_bundle(args)
            result = reference(evidence, args.depth, args.timeout)
        print(json.dumps(result, sort_keys=True))
        if args.command == "reference" and not result["accepted"]:
            raise ValueError("Bounded reference checks failed")
    except (OSError, ValueError, KeyError) as error:
        parser.exit(1, "Debug transport verification failed: " + str(error) + "\n")


if __name__ == "__main__":
    main()
