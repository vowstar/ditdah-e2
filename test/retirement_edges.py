# SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
# SPDX-License-Identifier: MIT
"""Check fault and reset retirement boundaries against independently driven RTL."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile


CASES = ("fetch-fault-atomic", "reset-irq")
SCHEMA = "ditdah-e2.retirement-edges.v1"
RETIREMENT_KEYS = set("pc raw insn order length trap cause tval rd writes value rs1 rs1_data rs2 rs2_data "
                      "memory_address read_mask write_mask read_data write_data operation operand response fault "
                      "fault_read_mask fault_write_mask csr_valid csr_read_mask csr_write_mask "
                      "status_before status_after status_mask".split())
INTERRUPT_KEYS = set("valid retire_valid sleeping pc target cause status_before status_after epc_before epc_after "
                     "cause_before cause_after value_before value_after".split())


class FixtureError(ValueError):
    """The requested stimulus or observation was not established."""


class EdgeFailure(AssertionError):
    """A reached edge violates its observation contract."""


def require(condition, message):
    if not condition:
        raise FixtureError(message)


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def exact(value, keys, label):
    require(type(value) is dict and set(value) == set(keys), f"{label}: unexpected fields")


def sample(value, keys, label):
    exact(value, keys, label)
    for key, number in value.items():
        require(type(number) is int and 0 <= number < 1 << (64 if key == "order" else 32),
                f"{label}.{key}: invalid unsigned observation")
        if key in {"valid", "retire_valid", "sleeping", "trap", "writes", "fault", "csr_valid"}:
            require(number in (0, 1), f"{label}.{key}: invalid flag")
        if key in {"rd", "rs1", "rs2"}:
            require(number < 32, f"{label}.{key}: invalid register")


def setup(rows, expected):
    require(type(rows) is list and len(rows) == len(expected), "Unexpected setup retirement count")
    for index, (row, (word, rd, value)) in enumerate(zip(rows, expected)):
        sample(row, RETIREMENT_KEYS, f"setup {index}")
        require((row["pc"], row["raw"], row["insn"], row["order"], row["length"], row["trap"]) ==
                (index * 4, word, word, index, 4, 0), "Setup instruction/order/trap differs")
        require((row["rd"], row["writes"], row["value"]) == (rd, int(rd != 0), value),
                "Setup GPR write differs")


def check_observation(record):
    require(type(record) is dict and record.get("schema") == SCHEMA, "Unknown edge schema")
    case = record.get("case")
    if case == "fetch-fault-atomic":
        exact(record, {"schema", "case", "retired", "data_offers", "fault_responses"}, case)
        require(type(record["retired"]) is list and len(record["retired"]) == 3, "Fetch-fault packet missing")
        setup(record["retired"][:2], [(0x10000093, 1, 0x100), (0x05500113, 2, 0x55)])
        event = record["retired"][2]
        sample(event, RETIREMENT_KEYS, "fetch fault")
        require(type(record["fault_responses"]) is int and type(record["data_offers"]) is int and
                record["data_offers"] >= 0, "Invalid native handshake counts")
        require(record["fault_responses"] == 1, "Fault response was not accepted exactly once")
        require((event["pc"], event["raw"], event["order"], event["length"], event["trap"],
                 event["cause"], event["tval"], event["fault"]) == (8, 0x0020A1AF, 2, 4, 1, 1, 8, 1),
                "Required AMO-bearing instruction access fault was not observed")
        inactive = ("insn", "rd", "writes", "value", "rs1", "rs1_data", "rs2", "rs2_data",
                    "memory_address", "read_mask", "write_mask", "read_data", "write_data", "operation",
                    "operand", "response", "fault_read_mask", "fault_write_mask", "csr_valid",
                    "csr_read_mask", "csr_write_mask")
        bad = [key for key in inactive if event[key] != 0]
        if record["data_offers"] != 0:
            bad.append("data_offers")
        if bad:
            raise EdgeFailure("fetch-fault inactive observations: " + ", ".join(bad))
        return {"case": case, "faultPackets": 1, "zeroInactiveFields": len(inactive), "dataRequests": 0}
    require(case == "reset-irq", "Unknown edge case")
    exact(record, {"schema", "case", "positive", "reset"}, case)
    for name in ("positive", "reset"):
        run = record[name]
        exact(run, {"retired", "eligible", "observed", "stored", "data_offers"}, name)
        setup(run["retired"], [(0x08000093, 1, 0x80), (0x30409073, 0, 0),
                               (0x00800093, 1, 8), (0x30009073, 0, 0), (0x10500073, 0, 0)])
        require(run["data_offers"] == 0, "IRQ setup unexpectedly requested data memory")
        require(type(run["data_offers"]) is int, "Invalid native handshake count")
        for phase in ("eligible", "observed", "stored"):
            sample(run[phase], INTERRUPT_KEYS, name + "." + phase)
        before = run["eligible"]
        require((before["valid"], before["retire_valid"], before["sleeping"], before["pc"],
                 before["target"], before["cause"], before["status_before"], before["epc_after"],
                 before["cause_after"], before["value_after"]) ==
                (1, 0, 1, 20, 0, 0x80000007, 0x1808, 20, 0x80000007, 0),
                "Pending enabled timer interrupt at empty M boundary was not established")
        require(before["status_after"] == 0x1880, "IRQ trap status transition differs")
    positive, reset = record["positive"], record["reset"]
    require(positive["observed"] == positive["eligible"], "Positive IRQ stimulus changed")
    require((positive["stored"]["status_before"], positive["stored"]["epc_before"],
             positive["stored"]["cause_before"], positive["stored"]["value_before"]) ==
            (0x1880, 20, 0x80000007, 0), "Positive IRQ did not update actual CSR storage")
    require((reset["stored"]["status_before"], reset["stored"]["epc_before"],
             reset["stored"]["cause_before"], reset["stored"]["value_before"]) ==
            (0x1800, 0, 0, 0), "Actual reset storage was not observed")
    if reset["observed"]["valid"] != 0 or reset["observed"]["retire_valid"] != 0:
        raise EdgeFailure("reset-active architectural event was not suppressed")
    return {"case": case, "positiveIrqEntries": 1, "resetSuppressedEvents": 1}


def parse_observation(text):
    def members(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, "Duplicate observation field")
            result[key] = value
        return result
    try:
        return json.loads(text, object_pairs_hook=members)
    except json.JSONDecodeError as error:
        raise FixtureError("Malformed edge JSON") from error


def validate_inputs(rtl, source_root, selected):
    manifest_path = rtl / "manifest.json"
    manifest = json.loads(manifest_path.read_text())
    parameters = manifest["parameters"]
    require(parameters["resetVector"] == 0 and not parameters["enableC"] and
            not parameters["protectedMode"] and not parameters["enableDebug"],
            "Edge fixture requires reset=0, C=false, protectedMode=false, Debug=false")
    require("fetch-fault-atomic" not in selected or parameters["enableA"], "Fetch-fault fixture requires A=true")
    require(manifest["top"] == "DitDahE2" and manifest["exitStatus"] == 0, "RTL generation did not complete")
    for name, expected in manifest["rtlHashes"].items():
        require(Path(name).name == name and name.endswith(".sv"), "Invalid RTL input name")
        require(digest(rtl / name) == expected, "RTL input changed: " + name)
    for name, expected in manifest["sourceHashes"].items():
        require(not Path(name).is_absolute() and ".." not in Path(name).parts, "Invalid source input name")
        require(digest(source_root / name) == expected, "Source input changed: " + name)
    return manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rtl", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--source-root", type=Path, default=Path.cwd())
    parser.add_argument("--case", action="append", choices=CASES)
    args = parser.parse_args()
    selected = args.case or list(CASES)
    require(len(set(selected)) == len(selected), "Duplicate case")
    require(not args.output.exists(), "Output already exists")
    manifest = validate_inputs(args.rtl, args.source_root, selected)
    args.output.mkdir(parents=True)
    own = Path(__file__).resolve().parent
    inputs = args.output / "inputs"
    for name in manifest["sourceHashes"]:
        target = inputs / "source" / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(args.source_root / name, target)
    for name in manifest["rtlHashes"] | {"manifest.json": None}:
        target = inputs / "rtl" / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(args.rtl / name, target)
    harness_files = ("retirement_edges.cpp", "retirement_edges.py", "test_retirement_edges.py")
    for name in harness_files:
        shutil.copyfile(own / name, inputs / name)
    tools = {}
    for name in ("verilator", "g++", "make", "python3"):
        executable = shutil.which(name)
        require(executable is not None, "Required tool unavailable: " + name)
        tools[name] = {"sha256": digest(Path(executable)),
                       "version": subprocess.check_output([name, "--version"], text=True).splitlines()[0]}
    summary = {"schema": SCHEMA, "parameters": manifest["parameters"], "sourceHashes": manifest["sourceHashes"],
               "rtlHashes": manifest["rtlHashes"], "manifestSha256": digest(inputs / "rtl/manifest.json"),
               "checkerHashes": {name: digest(inputs / name) for name in harness_files}, "tools": tools,
               "results": [], "compileExitStatus": None, "fullSignoff": False}
    scratch = "/data/tmp" if os.access("/data/tmp", os.W_OK) else None
    with tempfile.TemporaryDirectory(prefix="ditdah-e2-retirement-edges-", dir=scratch) as directory:
        work = Path(directory)
        normalize = lambda text: text.replace(str(work), "$WORK").replace(str(args.output.resolve()), "$OUTPUT")
        command = ["verilator", "--cc", "--exe", "--build", "-j", "1", "--top-module", "DitDahE2",
                   "--Mdir", str(work / "obj"), "-CFLAGS", "-std=c++17",
                   *[str((inputs / "rtl" / name).resolve()) for name in manifest["rtlHashes"]],
                   str((inputs / "retirement_edges.cpp").resolve())]
        build = subprocess.run(command, capture_output=True, text=True, timeout=180)
        (args.output / "compile.log").write_text(normalize(build.stdout + build.stderr))
        summary.update(compileCommand=[normalize(item) for item in command], compileExitStatus=build.returncode)
        if build.returncode == 0:
            for case in selected:
                invocation = [str(work / "obj/VDitDahE2"), case]
                run = subprocess.run(invocation, capture_output=True, text=True, timeout=20)
                (args.output / f"{case}.json").write_text(run.stdout)
                (args.output / f"{case}.log").write_text(normalize(run.stderr))
                result = {"case": case, "command": [normalize(item) for item in invocation],
                          "exitStatus": run.returncode, "observationSha256": digest(args.output / f"{case}.json")}
                if run.returncode:
                    result.update(status="process-failure", reason="Fixture process did not complete")
                else:
                    try:
                        observed = parse_observation(run.stdout)
                        require(type(observed) is dict and observed.get("case") == case,
                                "Observed case differs from selected case")
                        result.update(check_observation(observed), status="pass")
                    except EdgeFailure as error:
                        result.update(status="behavior-failure", reason=str(error))
                    except (FixtureError, TypeError, KeyError) as error:
                        result.update(status="fixture-failure", reason=str(error))
                summary["results"].append(result)
    validate_inputs(args.rtl, args.source_root, selected)
    require(all(digest(own / name) == summary["checkerHashes"][name] for name in harness_files),
            "Checker inputs changed during execution")
    passed = summary["compileExitStatus"] == 0 and len(summary["results"]) == len(selected) and \
        all(result["status"] == "pass" for result in summary["results"])
    summary["exitStatus"] = 0 if passed else 1
    (args.output / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    print(json.dumps({"compileExitStatus": summary["compileExitStatus"], "results": summary["results"],
                      "exitStatus": summary["exitStatus"]}))
    return summary["exitStatus"]


if __name__ == "__main__":
    raise SystemExit(main())
