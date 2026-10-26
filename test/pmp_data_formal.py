# SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
# SPDX-License-Identifier: MIT
"""Check local PMP data faults in the complete core with a fixed program."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import time

from core_formal import check_inputs, digest, freeze_design, freeze_tools, tool_versions, write_snapshot
from model import Model

SCENARIOS = ("user-load", "user-store", "machine-load", "machine-store")
DEPENDENCIES = {"bank": (), "decode": (), "hold": ("bank", "decode"), "query": (),
                "busy": ("bank", "decode", "hold", "query"), "denial": ("bank",),
                "retention": ("bank", "decode", "hold", "query", "busy")}
TASKS = (*DEPENDENCIES, "cover", "negative")
PROOF_ENGINE = "smtbmc --unroll z3 -- --noincr --logic QF_BV"
CONTRACT_PATTERN = re.compile(r"      // BEGIN CONTRACT (\w+)\n(.*?)      // END CONTRACT \1", re.S)


def select_contracts(wrapper, kind):
    blocks = dict(CONTRACT_PATTERN.findall(wrapper))
    assert tuple(blocks) == tuple(DEPENDENCIES), "Changed proof contracts"
    assert all("assume(" not in block for block in blocks.values()), "Unproved source assumption"
    required = DEPENDENCIES.get(kind, ())
    selected = (kind,) if kind in DEPENDENCIES else ("bank", "denial") if kind == "negative" else ()

    def replace(match):
        name, text = match.groups()
        if name in selected:
            return text
        return text.replace("assert(", "assume(") if name in required else ""

    return CONTRACT_PATTERN.sub(replace, wrapper), {
        name: hashlib.sha256(blocks[name].encode()).hexdigest() for name in (*required, *selected)}


def add_outputs(source, module, fields, assignments):
    match = re.search(r"module " + module + r"\((.*?)\n\);", source, re.S)
    assert match and source.count("endmodule") == 1, "Changed module boundary"
    declarations = ["  output " + (f"[{width-1}:0] " if width != 1 else "") + name for name, width in fields.items()]
    result = source[:match.end(1)] + ",\n" + ",\n".join(declarations) + source[match.end(1):]
    return result.replace("endmodule", "\n".join(f"  assign {name} = {value};" for name, value in assignments.items()) + "\nendmodule")


def connect_outputs(source, module, fields):
    pattern = r"(" + module + r"\s+\w+\s*\()(.*?)(\n\s*\);)"
    matches = list(re.finditer(pattern, source, re.S))
    assert len(matches) == 1, "Changed observation instance"
    match = matches[0]
    ports = ",\n".join(f"    .{name} ({name})" for name in fields)
    return source[:match.end(2)] + ",\n" + ports + source[match.end(2):]


def observe_rtl(rtl):
    result = dict(rtl)
    bank = {"observed_configs": 128, "observed_addresses": 480}
    assignments = {"observed_" + stem: "{" + ", ".join(stem if index == 0 else stem + "_" + str(index-1)
                        for index in reversed(range(16))) + "}" for stem in ("configs", "addresses")}
    pmp = result["DitDahE2Pmp.sv"].decode()
    for stem, width in (("configs", 7), ("addresses", 29)):
        assert len(re.findall(r"reg\s+\[" + str(width) + r":0\]\s+" + stem + r"(?:_\d+)?\s*;", pmp)) == 16, "Changed PMP bank"
    result["DitDahE2Pmp.sv"] = add_outputs(pmp, "DitDahE2Pmp", bank, assignments).encode()
    csr_fields = {**bank, "observed_csr_write": 1, "observed_csr_data": 32, "observed_mtvec": 32,
                  "observed_user": 1, "observed_mpp_user": 1, "observed_mprv": 1}
    csr = add_outputs(result["DitDahE2Csr.sv"].decode(), "DitDahE2Csr", csr_fields,
                      {"observed_csr_write": "write", "observed_csr_data": "writeData", "observed_mtvec": "mtvec & 32'hfffffffc",
                       "observed_user": "userMode_0", "observed_mpp_user": "mppUser", "observed_mprv": "mprv"})
    result["DitDahE2Csr.sv"] = connect_outputs(csr, "DitDahE2Pmp", bank).encode()
    core_assignments = {"observed_csr_address": "m_csrAddress", "observed_trap": "trap",
                        "observed_mret": "returning", "observed_machine": "_csr_dataMachine",
                        "observed_active": "mValid & memory & ~m_trap", "observed_address": "m_address",
                        "observed_size": "m_size", "observed_store": "m_store", "observed_pc": "m_instruction_pc",
                        "observed_sent": "sent", "observed_m_valid": "mValid", "observed_m_csr": "m_csr",
                        "observed_m_word": "m_instruction_word", "observed_m_system": "m_csr | m_mret | m_wfi | m_fenceI",
                        "observed_m_return": "m_mret", "observed_complete": "complete", "observed_advance": "advance",
                        "observed_allowed": "_csr_dataProtection_allowed"}
    core_fields = {**csr_fields, **{name: width for name, width in zip(core_assignments, (12, 1, 1, 1, 1, 32, 2, 1, 32, 1, 1, 1, 32, 1, 1, 1, 1, 1))}}
    core = add_outputs(result["DitDahE2.sv"].decode(), "DitDahE2", core_fields, core_assignments)
    result["DitDahE2.sv"] = connect_outputs(core, "DitDahE2Csr", csr_fields).encode()
    return result


def mutate_denial(content):
    pattern = r"(wire\s+\w+\s*=\s*[^;\n]*?\b\w+\s*&\s*~m_trap\s*&\s*)~(_csr\w*_dataProtection_allowed)(\s*;)"
    assert len(re.findall(pattern, content)) == 1, "PMP denial mutation target changed"
    return re.sub(pattern, r"\g<1>1'b0\3", content)


def trace_frames(content, wanted):
    identifiers, scopes, values = {}, [], {}
    frames = []
    for line in content.splitlines():
        fields = line.split()
        if fields[:1] == ["$scope"]:
            scopes.append(fields[2])
        elif fields[:1] == ["$upscope"]:
            scopes.pop()
        elif fields[:1] == ["$var"] and len(scopes) == 1 and fields[4] in wanted:
            identifiers[fields[3]] = fields[4]
        elif line.startswith("#"):
            if values:
                frames.append(values.copy())
        elif fields and fields[0].startswith("b") and len(fields) == 2 and fields[1] in identifiers:
            bits = fields[0][1:]
            values[identifiers[fields[1]]] = int(bits, 2) if set(bits) <= {"0", "1"} else None
        elif line[:1] in ("0", "1") and line[1:] in identifiers:
            values[identifiers[line[1:]]] = int(line[0])
    frames.append(values.copy())
    assert set(identifiers.values()) == wanted, "Counterexample observations missing"
    return frames


def forbidden_witness(content):
    frames = trace_frames(content, {"reset", "data_request_valid", "data_request_bits_address", "forbidden_request",
                                    "shadow_configured", "shadow_denied", "observed_pc"})
    for frame in frames:
        if (frame.get("reset") == 0 and frame.get("data_request_valid") == 1
                and frame.get("data_request_bits_address") == 4096 and frame.get("forbidden_request") == 1
                and frame.get("shadow_configured") == 1 and frame.get("shadow_denied") == 1 and frame.get("observed_pc") == 68):
            return frame
    raise AssertionError("No forbidden native request in counterexample")


def completion_witness(content):
    frames = trace_frames(content, {"reset", "saw_allowed", "saw_denied", "finished", "retire_pc"})
    for frame in frames:
        if (frame.get("reset") == 0 and frame.get("finished") == 1 and frame.get("saw_allowed") == 1
                and frame.get("saw_denied") == 1 and frame.get("retire_pc") == 148):
            return frame
    raise AssertionError("No complete PMP fault program in witness")


def program_words(wrapper, scenario):
    result = {148: 0x6f, 4092: 0x12345678}
    for address, expression in re.findall(r"^\s+(\d+): rom = ([^;]+);", wrapper, re.M):
        values = [int(word, 16) for word in re.findall(r"32'h([0-9a-f]+)", expression)]
        choice = scenario >= 2 if "MACHINE" in expression else scenario % 2 if "STORE" in expression else True
        result[int(address)] = values[0 if choice else 1]
    return result


def replay_completion(content, wrapper, scenario, log, replacement=False):
    target = "assert(!(finished && saw_replacement));" if replacement else "assert(!finished);"
    lines = [index for index, line in enumerate(wrapper.splitlines(), 1) if target in line]
    failures = re.findall(r"failed assertion .* at pmp_data_formal.sv:(\d+)\.", log)
    assert len(lines) == 1 and failures == [str(lines[0])], "Unexpected reachability assertion failure"
    fields = {"clock", "reset", "retire_valid", "retire_pc", "retire_word", "retire_nextPc", "retire_rd",
              "retire_value", "retire_writes", "retire_userMode", "retire_trap", "retire_cause", "retire_tval",
              "data_request_valid", "data_request_ready", "data_request_bits_address", "data_request_bits_data", "data_request_bits_write",
              "data_request_bits_size", "data_request_bits_mask", "data_request_bits_operation", "data_request_bits_machine",
              "data_response_valid", "data_response_ready", "observed_csr_write", "observed_csr_address", "observed_csr_data",
              "instruction_request_valid", "instruction_request_ready", "instruction_request_bits_address",
              "instruction_response_valid", "instruction_response_ready", "instruction_response_bits_data",
              "instruction_response_bits_fault"}
    words = program_words(wrapper, scenario)
    model = Model(words, protected_mode=True)
    expected_csr = {4: (0x305, 128), 16: (0x3b0, 1024), 20: (0x3b1, 1024),
                    32: (0x3a0, 0x900f if scenario >= 2 else 0x100f)}
    if scenario < 2:
        expected_csr.update({40: (0x300, 0), 48: (0x341, 64)})
    owner, requests, responses, events, traps, writes = False, 0, 0, 0, 0, []
    instruction_owner, instruction_requests, instruction_responses, replacements = None, 0, 0, 0
    held_payload, held_cycles = None, 0
    completed = False
    for frame in trace_frames(content, fields):
        if frame.get("clock") != 1 or frame.get("reset") != 0:
            continue
        payload = tuple(frame["data_request_bits_" + name] for name in
                        ("address", "data", "write", "size", "mask", "operation", "machine"))
        if held_payload is not None:
            assert frame["data_request_valid"] and payload == held_payload, "Held data request changed"
        held_payload = payload if frame["data_request_valid"] and not frame["data_request_ready"] else None
        held_cycles += held_payload is not None
        previous_instruction = instruction_owner
        instruction_response = frame["instruction_response_valid"] and frame["instruction_response_ready"]
        if frame["instruction_response_valid"]:
            assert instruction_owner is not None, "Instruction response lacks an owner"
            assert (frame["instruction_response_bits_data"], frame["instruction_response_bits_fault"]) == (
                words.get(instruction_owner, 0x6f), 0), "Instruction response differs from its owner"
        if instruction_response:
            instruction_owner = None
            instruction_responses += 1
        if frame["instruction_request_valid"] and frame["instruction_request_ready"]:
            assert instruction_owner is None, "Instruction request overlaps its owner"
            instruction_owner = frame["instruction_request_bits_address"]
            instruction_requests += 1
            if instruction_response and instruction_owner != previous_instruction:
                replacements += 1
        if frame["data_response_valid"] and frame["data_response_ready"]:
            assert owner, "Data response lacks an owner"
            owner = False
            responses += 1
        if frame["data_request_valid"]:
            assert not owner, "Data request overlaps its owner"
            assert tuple(frame["data_request_bits_" + name] for name in
                         ("address", "write", "size", "mask", "operation", "machine")) == (
                             4092, 0, 2, 0, 0, int(scenario >= 2)), "Unexpected program data request"
            if frame["data_request_ready"]:
                owner = True
                requests += 1
        if frame["observed_csr_write"]:
            pc = frame["retire_pc"]
            assert frame["retire_valid"] and not frame["retire_trap"], "CSR write lacks retirement"
            assert pc in expected_csr and pc not in writes, "Unexpected CSR write"
            assert (frame["observed_csr_address"], frame["observed_csr_data"]) == expected_csr[pc], "CSR write differs"
            writes.append(pc)
        if frame["retire_valid"]:
            event = model.step()
            events += 1
            assert tuple(frame["retire_" + name] for name in ("pc", "word", "nextPc", "trap", "userMode")) == (
                event.pc, event.word, event.next_pc, int(event.trap), int(event.user_mode)), "Retirement differs from the model"
            assert frame["retire_writes"] == int(event.rd != 0), "Register write enable differs"
            if event.rd:
                assert (frame["retire_rd"], frame["retire_value"]) == (event.rd, event.value), "Register result differs"
            if event.trap:
                traps += 1
                assert (event.pc, frame["retire_cause"], frame["retire_tval"]) == (
                    68, 7 if scenario % 2 else 5, 4096), "Trap cause or address differs"
            if event.pc == 148:
                completed = True
                break
    assert completed and not owner and requests == responses == traps == 1, "Incomplete fault program"
    assert held_cycles > 0, "No blocked data request in the complete program"
    assert set(writes) == set(expected_csr), "CSR setup is incomplete"
    assert not replacement or replacements > 0, "No instruction replacement in the complete program"
    assert (model.registers[4], model.registers[8], model.registers[9]) == (
        0x12345678, 90, 0x1800 if scenario >= 2 else 0), "Fixed program result differs"
    return {"retiredInstructions": events, "traps": traps, "acceptedDataRequests": requests,
            "completedDataResponses": responses, "csrWrites": len(writes), "completionPc": 148,
            "blockedDataRequestCycles": held_cycles,
            "instructionReplacements": replacements, "acceptedInstructionRequests": instruction_requests,
            "completedInstructionResponses": instruction_responses,
            "pendingInstructionTransactions": int(instruction_owner is not None)}


def configuration(names, scenario, kind, depth, induction_depth=3):
    assert kind in (*TASKS, "replacement"), "Unknown task kind"
    macro = "-DREACHABILITY " if kind in ("cover", "replacement") else ""
    if kind in DEPENDENCIES:
        macro += "-DUNRESTRICTED_PEER -DREPLACE_PEER -DSHADOW_CONTRACT "
    elif kind == "replacement":
        macro += "-DREPLACE_PEER -DREPLACEMENT_WITNESS "
    elif kind == "negative":
        macro += "-DSHADOW_CONTRACT "
    engine = PROOF_ENGINE if kind in DEPENDENCIES else "abc bmc3"
    mode, limit = ("prove", induction_depth) if kind in DEPENDENCIES else ("bmc", depth)
    text = (f"[options]\nmode {mode}\ndepth {limit}\nvcd_sim on\n[engines]\n{engine}\n"
            f"[script]\nread -formal -sv {macro}{' '.join(names)}\n"
            f"chparam -set SCENARIO {scenario} pmp_data_formal\nprep -top pmp_data_formal\n"
            "[files]\n" + "\n".join(names) + "\n")
    return text, engine


def run_task(output, rtl, wrapper, scenario, kind, depth, induction_depth, timeout, completed):
    directory = output / (SCENARIOS[scenario] + "-" + kind)
    directory.mkdir()
    for name, data in rtl.items():
        if kind == "negative" and name == "DitDahE2.sv":
            data = mutate_denial(data.decode()).encode()
        (directory / name).write_bytes(data)
    selected, contracts = select_contracts(wrapper.decode(), kind)
    dependencies = {}
    for name in DEPENDENCIES.get(kind, ()):
        previous = completed[name]
        assert previous["status"] == "PASS" and previous["exitStatus"] == 0, "Unproved dependency"
        assert previous["contracts"][name] == contracts[name], "Changed dependency contract"
        assert previous["wrapperSourceHash"] == hashlib.sha256(wrapper).hexdigest(), "Changed dependency wrapper"
        assert all(previous["inputHashes"][filename] == hashlib.sha256(data).hexdigest()
                   for filename, data in rtl.items()), "Changed dependency RTL"
        dependencies[name] = digest(output / (SCENARIOS[scenario] + "-" + name) / "outcome.json")
    (directory / "pmp_data_formal.sv").write_text(selected)
    script, engine = configuration([*rtl, "pmp_data_formal.sv"], scenario, kind, depth, induction_depth)
    (directory / "run.sby").write_text(script)
    frozen = {path: path.read_bytes() for path in directory.iterdir()}
    started = time.time()
    process = subprocess.Popen(["sby", "-f", "run.sby"], cwd=directory,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               text=True, start_new_session=True)
    try:
        stdout, stderr = process.communicate(timeout=timeout)
        status_path = directory / "run/status"
        status = status_path.read_text().split()[0] if status_path.exists() else "ERROR"
        code = process.returncode
    except subprocess.TimeoutExpired:
        os.killpg(process.pid, signal.SIGTERM)
        try:
            stdout, stderr = process.communicate(timeout=10)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            stdout, stderr = process.communicate()
        status, code = "TIMEOUT", 124
    (directory / "stdout.txt").write_text(stdout)
    (directory / "stderr.txt").write_text(stderr)
    check_inputs(frozen)
    traces = sorted((directory / "run/engine_0").glob("trace*.vcd"))
    outcome = {"scenario": SCENARIOS[scenario], "kind": kind, "mode": "bmc" if engine == "abc bmc3" else "prove", "engine": engine,
               "depth": induction_depth if kind in DEPENDENCIES else depth,
               "timeoutSeconds": timeout, "status": status, "exitStatus": code,
               "contracts": contracts, "dependencies": dependencies,
               "wrapperSourceHash": hashlib.sha256(wrapper).hexdigest(),
               "processId": process.pid,
               "elapsedSeconds": time.time() - started, "command": ["sby", "-f", "run.sby"],
               "inputHashes": {path.name: hashlib.sha256(data).hexdigest() for path, data in frozen.items()},
               "traceHashes": {str(path.relative_to(directory)): digest(path) for path in traces}}
    (directory / "outcome.json").write_text(json.dumps(outcome, indent=2) + "\n")
    assert (status, code) == (("PASS", 0) if kind in DEPENDENCIES else ("FAIL", 2)), "Formal task did not meet its acceptance"
    if kind == "negative":
        assert traces, "Counterexample trace missing"
        outcome["witness"] = forbidden_witness(traces[0].read_text())
    if kind in ("cover", "replacement"):
        assert traces, "Reachability trace missing"
        outcome["witness"] = completion_witness(traces[0].read_text())
        outcome["programReplay"] = replay_completion(traces[0].read_text(), selected, scenario, stdout, kind == "replacement")
    (directory / "outcome.json").write_text(json.dumps(outcome, indent=2) + "\n")
    return outcome


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rtl", type=Path, required=True)
    parser.add_argument("--source-root", type=Path, default=Path("."))
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--depth", type=int, default=128)
    parser.add_argument("--induction-depth", type=int, default=3)
    parser.add_argument("--timeout", type=int, default=1800)
    parser.add_argument("--scenario", choices=SCENARIOS, action="append")
    args = parser.parse_args()
    assert args.depth >= 96 and args.induction_depth >= 2 and args.timeout > 0, "Insufficient proof limits"
    assert not args.output.exists(), "Output must be new"
    runner = Path(__file__)
    wrapper = runner.with_suffix(".sv")
    manifest, contents, bindings = freeze_design(args.rtl, args.source_root, wrapper, runner)
    parameters = manifest["parameters"]
    assert parameters.get("protectedMode") and not any(parameters.get(name, False) for name in
        ("enableM", "enableC", "enableDebug", "enableA", "enableZba", "enableZbb", "enableZbs")), "Use the minimal protected configuration"
    for name in ("core_formal.py", "test_pmp_data_formal.py", "model.py", "pmp.py", "compressed_model.py", "compressed_unit.py", "bit_model.py"):
        contents["test/" + name] = runner.with_name(name).read_bytes()
    actual_inputs = {runner.with_name(name.removeprefix("test/")): data
                     for name, data in contents.items() if name.startswith("test/")}
    args.output.mkdir(parents=True)
    frozen = write_snapshot(args.output, contents)
    tools, bindings["toolHashes"] = freeze_tools()
    python = Path(sys.executable).resolve()
    tools[python] = python.read_bytes()
    bindings["toolHashes"]["python"] = hashlib.sha256(tools[python]).hexdigest()
    bindings["pythonVersion"] = list(sys.version_info[:3])
    selected = args.scenario or list(SCENARIOS)
    rtl = observe_rtl({name: contents["rtl/" + name] for name in manifest["rtlHashes"]})
    outcomes = []
    for name in selected:
        completed = {}
        for kind in (*TASKS, "replacement") if name == "user-load" else TASKS:
            outcome = run_task(args.output, rtl, contents["test/" + wrapper.name],
                               SCENARIOS.index(name), kind, args.depth, args.induction_depth, args.timeout, completed)
            completed[kind] = outcome
            outcomes.append(outcome)
            (args.output / "outcomes.json").write_text(json.dumps(outcomes, indent=2) + "\n")
            print(f"Accepted {name} {kind}", flush=True)
    check_inputs(frozen)
    check_inputs(actual_inputs)
    check_inputs(tools)
    report = {"scope": "whole-core local PMP denial and native request retention with separate complete program witnesses",
              **bindings, **tool_versions(), "exitStatus": 0, "outcomes": outcomes,
              "checkerHashes": {name: hashlib.sha256(data).hexdigest() for name, data in contents.items() if name.startswith("test/")},
              "selectedScenarios": selected, "selectedKinds": (*TASKS, "replacement") if "user-load" in selected else TASKS,
              "proofDependencies": DEPENDENCIES,
              "safetyUsesUnrestrictedPeer": True,
              "assumptions": ["initial synchronous reset", "fixed independent ROM",
                              "one ordered native response at least one cycle after acceptance",
                              "arbitrary request and response delays in safety tasks",
                              "safety peers permit response completion and new request acceptance in the same cycle",
                              "ordinary witnesses use prompt instruction peers, one to three blocked data request cycles and zero to three response delay cycles without replacement",
                              "the replacement witness uses prompt instruction responses with same-cycle replacement",
                              "no bus faults or interrupts"],
              "intervals": [{"base": 0, "bytes": 4096, "permissions": 7, "locked": False},
                            {"base": 4096, "bytes": 4, "permissions": 0, "locked": "machine scenarios"}],
              "limits": ["four fixed programs", "sixteen PMP entries remain present",
                         "independent interval permission applies to the declared bank contents",
                         "exact traps use complete bounded traces and independent instruction replay",
                         "only recorded prove tasks establish unbounded safety", "no memory liveness claim"]}
    (args.output / "summary.json").write_text(json.dumps(report, indent=2) + "\n")
    print("PASS: whole-core PMP data fault checks")


if __name__ == "__main__":
    main()
