# SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
# SPDX-License-Identifier: MIT
"""Exercise formal-wrapper setup, peer ownership and all four native programs."""

import argparse
import json
import re
import subprocess
from pathlib import Path

from formal.trigger.run import HERE, load_rtl, sha, write_json


def simulation_wrapper(text):
    text = text.replace("always @($global_clock)", "always @(posedge clock)")
    text = re.sub(r"\b\w+:\s*(?=(?:assert|assume|cover)\s*\()", "", text)
    text = text.replace("assume(reset);", "begin end").replace("assume(!reset);", "begin end")
    declarations = ("  reg [4:0] dmi_phase = 0;\n  reg dmi_pending = 0;\n"
                    "  wire [4:0] execution_phase = scenario == 1 ? 24 : 21;\n")
    if text.count(declarations) != 1:
        raise ValueError("Wrapper phase declarations changed")
    return text.replace(declarations, "").replace("  reg instruction_busy", declarations + "  reg instruction_busy")


def mutate(text, name):
    if name == "phase-gate":
        for expression in ("check && !instruction_busy", "check && instruction_busy",
                           "check && !data_busy", "check && data_busy"):
            if text.count(expression + ";") != 1:
                raise ValueError("Peer gate mutation anchor changed")
            text = text.replace(expression + ";", expression + " && dmi_phase >= execution_phase;")
    elif name == "clear-setup-debt":
        anchor = "if (reset || !initialized) begin\n      instruction_busy <= 0;"
        if text.count(anchor) != 1:
            raise ValueError("Peer debt mutation anchor changed")
        text = text.replace(anchor, "if (reset || !initialized || dmi_phase < execution_phase) begin\n      instruction_busy <= 0;")
    else:
        raise ValueError("Unknown peer mutation")
    return text


def bench(scenario):
    return r'''// SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
// SPDX-License-Identifier: MIT
module wrapper_progress_tb;
  reg clock=0, reset=1;
  trigger_core_formal #(.SCENARIO(SCENARIO_VALUE)) dut(clock,reset);
  always #5 clock=~clock;
  integer requests=0, responses=0, data_requests=0, data_responses=0;
  integer setup_requests=0, setup_responses=0, halted_ready=0, resumes=0;
  initial begin
    repeat(3) @(negedge clock); reset=0;
    repeat(600) @(negedge clock);
    if (!dut.finished || setup_requests==0 || setup_responses==0 || halted_ready==0 || resumes==0)
      $fatal(1,"wrapper progress missing");
    $display("WRAPPER_RESULT scenario=SCENARIO_VALUE finished=1 setup_requests=%0d setup_responses=%0d halted_ready=%0d resumes=%0d",
             setup_requests,setup_responses,halted_ready,resumes);
    $finish;
  end
  always @(posedge clock) if (!reset && dut.check) begin
    if (dut.instruction_accept) begin
      requests=requests+1;
      if(dut.dmi_phase<dut.execution_phase) setup_requests=setup_requests+1;
    end
    if (dut.instruction_return) begin
      responses=responses+1;
      if(dut.dmi_phase<dut.execution_phase) setup_responses=setup_responses+1;
    end
    if (dut.data_accept) data_requests=data_requests+1;
    if (dut.data_return) data_responses=data_responses+1;
    if (responses>requests || data_responses>data_requests || requests-responses>1 || data_requests-data_responses>1)
      $fatal(1,"peer ownership changed");
    if (dut.dmi_phase==2 && dut.dut.debug.halted && dut.dut.fetch.idle) halted_ready=halted_ready+1;
    if (dut.dut.debug.core_resume) begin
      resumes=resumes+1;
      if (dut.dut.debug.core_resumePc!==dut.resume_pc) $fatal(1,"resume PC changed");
    end
  end
  always @(negedge clock) if (!reset && dut.check) begin
    if ((requests-responses)!==dut.instruction_busy || (data_requests-data_responses)!==dut.data_busy)
      $fatal(1,"peer debt cleared before completion");
    if (dut.dmi_phase<dut.execution_phase &&
        (dut.target_trap || dut.target_normal || dut.older_seen || dut.completion_seen ||
         dut.metadata_epc || dut.metadata_cause || dut.metadata_tval || dut.metadata_control || dut.metadata_hit))
      $fatal(1,"scenario scoreboard changed during setup");
  end
endmodule
'''.replace("SCENARIO_VALUE", str(scenario))


def result(log, status, scenario):
    if status != 0 or re.search(r"(?m)^(?:ERROR|FATAL):", log):
        raise ValueError("Wrapper execution failed")
    pattern = (rf"WRAPPER_RESULT scenario={scenario} finished=1 setup_requests=([0-9]+) "
               r"setup_responses=([0-9]+) halted_ready=([0-9]+) resumes=([0-9]+)")
    rows = re.findall(pattern, log)
    if len(rows) != 1 or any(int(value) < 1 for value in rows[0]):
        raise ValueError("Wrapper progress evidence is missing")
    return dict(zip(("setupRequests", "setupResponses", "haltedReady", "resumes"), map(int, rows[0]), strict=True))


def run(rtl, output, source_root):
    _, sources = load_rtl(rtl, "DitDahE2", True, source_root)
    wrapper = (HERE / "trigger_core_formal.sv").read_text()
    output.mkdir(parents=True, exist_ok=False)
    runs, controls = [], []
    for scenario, mutation in [*((scenario, None) for scenario in range(4)), (0, "phase-gate"), (0, "clear-setup-debt")]:
        work = output / (mutation or f"scenario-{scenario}")
        work.mkdir()
        for name, value in sources.items():
            (work / name).write_bytes(value)
        (work / "wrapper.sv").write_text(simulation_wrapper(mutate(wrapper, mutation) if mutation else wrapper))
        (work / "bench.sv").write_text(bench(scenario))
        compiled = subprocess.run(["iverilog", "-g2012", "-s", "wrapper_progress_tb", "-o", "simulation",
                                   "wrapper.sv", "bench.sv", *sources], cwd=work, capture_output=True, text=True, check=False)
        (work / "compile.log").write_text(compiled.stdout + compiled.stderr)
        if compiled.returncode:
            raise ValueError("Wrapper compilation failed")
        simulated = subprocess.run(["vvp", "simulation"], cwd=work, capture_output=True, text=True, check=False)
        log = simulated.stdout + simulated.stderr
        (work / "simulation.log").write_text(log)
        if mutation:
            if simulated.returncode == 0 or not re.search(r"(?:wrapper progress missing|peer debt cleared before completion)", log):
                raise ValueError("Peer mutation was not rejected by its intended behavior")
            controls.append(mutation)
        else:
            runs.append({"scenario": scenario, **result(log, simulated.returncode, scenario)})
    summary = {"exitStatus": 0, "scope": "formal wrapper peer progress under a driven clock and cold reset",
               "wrapperSha256": sha(wrapper.encode()), "rtlHashes": {name: sha(value) for name, value in sources.items()},
               "runs": runs, "negativeControls": controls, "commercialGate": "not_evaluated"}
    write_json(output / "summary.json", summary)
    return summary


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rtl", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--source-root", default=HERE.parents[1], type=Path)
    args = parser.parse_args()
    print(json.dumps(run(args.rtl, args.output, args.source_root), sort_keys=True))


if __name__ == "__main__":
    main()
