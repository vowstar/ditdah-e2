# SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
# SPDX-License-Identifier: MIT
"""Check interrupt entry and WFI wakeup with fixed programs and arbitrary bus delays."""

import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import hashlib
import json
import os
from pathlib import Path
import re
import tempfile

from control_witness import witness

from core_formal import check_inputs, freeze_design, freeze_tools, run_case, tool_versions, write_snapshot


def replace_once(content, pattern, replacement):
    changed, count = re.subn(pattern, replacement, content)
    assert count == 1, "Interrupt mutation no longer matches RTL"
    return changed


def mutate_drain(content):
    return replace_once(content, r"wire\s+interrupt = ~mValid & eligibleInterrupt;",
                        "wire interrupt = eligibleInterrupt;")


def mutate_fault_priority(content):
    return replace_once(content, r"wire\s+interrupt = ~mValid & eligibleInterrupt;",
                        "wire interrupt = (~mValid | response & data_response_bits_fault) & eligibleInterrupt;")


def mutate_saved_pc(content):
    return replace_once(content, r"\.trapPc\s*\(interrupt \? architecturalPc : m_instruction_pc\)",
                        ".trapPc (interrupt ? architecturalPc + 32'h4 : m_instruction_pc)")


def mutate_local_wake(content):
    return replace_once(content, r"wire\s+waking = (sleeping_\d+) & localWake;",
                        r"wire waking = \1 & eligibleInterrupt;")


def mutate_source_priority(content):
    return replace_once(content, r"(_csr_interruptPending)\[11\](\s*\? 32'h8000000B)",
                        r"(\1[11] & ~\1[3])\2")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rtl", type=Path, default=Path("result/rtl"))
    parser.add_argument("--source-root", type=Path, default=Path("."))
    parser.add_argument("--output", type=Path, default=Path("result/interrupt-formal"))
    parser.add_argument("--depth", type=int, default=72)
    parser.add_argument("--jobs", type=int, default=2)
    parser.add_argument("--case", action="append", choices=("safety", "safety-load", "safety-fault", "safety-local-wake",
                        "safety-wfi-interrupt", "safety-store", "reachability", "drain", "fault-priority", "saved-pc", "local-wake", "source-priority"))
    args = parser.parse_args()
    if args.depth < 72:
        parser.error("Interrupt handler coverage requires at least 72 cycles")
    if args.jobs < 1:
        parser.error("At least one worker is required")
    wrapper = Path(__file__).with_suffix(".sv")
    manifest, contents, bindings = freeze_design(args.rtl, args.source_root, wrapper, Path(__file__))
    helper = Path(__file__).with_name("core_formal.py")
    contents["test/core_formal.py"] = helper.read_bytes()
    bindings["helperHash"] = hashlib.sha256(contents["test/core_formal.py"]).hexdigest()
    witness_path = Path(__file__).with_name("control_witness.py")
    contents["test/control_witness.py"] = witness_path.read_bytes()
    bindings["witnessHash"] = hashlib.sha256(contents["test/control_witness.py"]).hexdigest()
    tool_inputs, bindings["toolHashes"] = freeze_tools()
    args.output.mkdir(parents=True, exist_ok=True)
    archived = write_snapshot(args.output, contents)
    bindings["inputDirectory"] = "inputs"
    (args.output / "inputs.json").write_text(json.dumps(bindings, indent=2) + "\n")
    cases = (("safety-load", "bmc", "abc bmc3", None, 0),
             ("safety-fault", "bmc", "abc bmc3", None, 1),
             ("safety-local-wake", "bmc", "abc bmc3", None, 2),
             ("safety-wfi-interrupt", "bmc", "abc bmc3", None, 3),
             ("safety-store", "bmc", "abc bmc3", None, 4),
             ("reachability", "cover", "smtbmc z3", None, None),
             ("drain", "bmc", "abc bmc3", mutate_drain, 0),
             ("fault-priority", "bmc", "abc bmc3", mutate_fault_priority, 1),
             ("saved-pc", "bmc", "abc bmc3", mutate_saved_pc, 0),
             ("local-wake", "bmc", "abc bmc3", mutate_local_wake, 2),
             ("source-priority", "bmc", "abc bmc3", mutate_source_priority, 0))
    selected = [case for case in cases if not args.case or case[0] in args.case or
                ("safety" in args.case and case[0].startswith("safety-"))]
    outcomes = []
    scratch = "/data/tmp" if os.access("/data/tmp", os.W_OK) else None
    with tempfile.TemporaryDirectory(prefix="ditdah-e2-interrupt-formal-", dir=scratch) as directory:
        work = Path(directory)
        frozen = write_snapshot(work, contents)
        rtl = {name: contents["rtl/" + name] for name in manifest["rtlHashes"]}
        check_inputs(tool_inputs)
        with ThreadPoolExecutor(max_workers=args.jobs) as executor:
            futures = [executor.submit(run_case, work, args.output, rtl, wrapper.name,
                                       contents["test/" + wrapper.name], "interrupt_formal", name, mode,
                                       engine, args.depth, mutation, () if scenario is None else (("SCENARIO", scenario),))
                       for name, mode, engine, mutation, scenario in selected]
            for future in as_completed(futures):
                outcome = future.result()
                if outcome["name"] == "source-priority":
                    trace = next(args.output.glob("source-priority-*.vcd"))
                    outcome["witness"] = witness(trace.read_text(), "source-priority")
                    (args.output / "source-priority.json").write_text(json.dumps(outcome, indent=2) + "\n")
                outcomes.append(outcome)
                outcomes.sort(key=lambda result: next(index for index, case in enumerate(cases) if case[0] == result["name"]))
                (args.output / "outcomes.json").write_text(json.dumps(outcomes, indent=2) + "\n")
        check_inputs(frozen)
        check_inputs(tool_inputs)
        check_inputs(archived)
    report = {"scope": "bounded memory completion, interrupt priority, saved trap state and WFI wakeup",
              **bindings, "command": f"python3 test/interrupt_formal.py --depth {args.depth} --jobs {args.jobs}",
              "selectedCases": args.case, "exitStatus": 0, "outcomes": outcomes, **tool_versions(),
              "assumptions": ["initial synchronous reset", "five fixed ROM scenarios checked in separate safety tasks",
                              "one nonzero constant mask of software, timer and external inputs",
                              "interrupt levels asserted after data acceptance or two WFI sleep cycles",
                              "all three local enables set by the ROM",
                              "ordered memory peers with arbitrary request and response delays",
                              "data response at least four cycles after acceptance", "time input tied to zero",
                              "optional DMI requests tied inactive", "no eventual response assumption"],
              "covers": ["interrupt pending during memory wait", "software interrupt handler",
                         "timer interrupt handler", "external interrupt handler", "all sources pending",
                         "synchronous fault with all sources pending", "WFI local wake without global enable",
                         "WFI interrupt entry", "store completion before interrupt entry"],
              "coverSchedule": "ready requests, prompt fetch responses, data response after five cycles",
              "negativeControls": {"source-priority": "select software while external is also pending",
                                   "drain": "enter an interrupt with M occupied",
                                   "fault-priority": "enter an interrupt on a synchronous data fault",
                                   "saved-pc": "save the following instruction address in mepc",
                                   "local-wake": "require global enable for WFI wakeup"},
              "excluded": ["unbounded core proof", "debug entry and commands", "arbitrary programs", "all CSR enable combinations",
                           "interrupt pulse capture", "memory liveness", "nonzero reset vectors"]}
    (args.output / "summary.json").write_text(json.dumps(report, indent=2) + "\n")
    print(f"PASS: {len(outcomes)} interrupt formal checks at depth {args.depth}")


if __name__ == "__main__":
    main()
