# SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
# SPDX-License-Identifier: MIT
"""Check two memory owners, locked offers, response routing and round-robin grants."""

import argparse
import hashlib
import json
import random
import re
import shutil
import subprocess
from collections import Counter, deque
from pathlib import Path

FIELDS = ("reset", "first_valid", "first_payload", "first_debug", "first_ready", "second_valid", "second_payload", "second_ready",
          "request_ready", "response_valid", "response_data", "response_fault")
HEX_INPUT = (2, 6, 10)
HEX_OUTPUT = (4, 7, 10)
HARNESS = r"""// SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
// SPDX-License-Identifier: MIT
module ArbiterBench;
  reg clock = 0, reset = 1;
  reg first_request_valid = 0, second_request_valid = 0;
  reg [75:0] first_payload = 0, second_payload = 0;
  reg firstDebug = 0, first_response_ready = 0, second_response_ready = 0;
  reg output_request_ready = 0, output_response_valid = 0;
  reg [31:0] output_response_bits_data = 0;
  reg output_response_bits_fault = 0;
  wire first_request_ready, second_request_ready, first_response_valid, second_response_valid;
  wire [31:0] first_response_bits_data, second_response_bits_data;
  wire first_response_bits_fault, second_response_bits_fault;
  wire output_request_valid, output_response_ready, outputDebug;
  wire [31:0] output_request_bits_address, output_request_bits_data;
  wire output_request_bits_machine, output_request_bits_write;
  wire [3:0] output_request_bits_mask, output_request_bits_operation;
  wire [1:0] output_request_bits_size;
  wire [75:0] output_payload = {output_request_bits_address, output_request_bits_machine,
    output_request_bits_write, output_request_bits_data, output_request_bits_mask,
    output_request_bits_size, output_request_bits_operation};
  DitDahE2MemoryArbiter dut (
    .first_request_bits_address(first_payload[75:44]), .first_request_bits_machine(first_payload[43]),
    .first_request_bits_write(first_payload[42]), .first_request_bits_data(first_payload[41:10]),
    .first_request_bits_mask(first_payload[9:6]), .first_request_bits_size(first_payload[5:4]),
    .first_request_bits_operation(first_payload[3:0]),
    .second_request_bits_address(second_payload[75:44]), .second_request_bits_machine(second_payload[43]),
    .second_request_bits_write(second_payload[42]), .second_request_bits_data(second_payload[41:10]),
    .second_request_bits_mask(second_payload[9:6]), .second_request_bits_size(second_payload[5:4]),
    .second_request_bits_operation(second_payload[3:0]), .*);
  integer file, fields, sample = 0;
  initial begin
    #1 clock = 1; #1 clock = 0;
    file = $fopen("vectors.txt", "r");
    if (!file) $fatal(1, "Cannot open arbiter vectors");
    while (!$feof(file)) begin
      fields = $fscanf(file, "%d %d %h %d %d %d %h %d %d %d %h %d\n", reset,
        first_request_valid, first_payload, firstDebug, first_response_ready,
        second_request_valid, second_payload, second_response_ready,
        output_request_ready, output_response_valid, output_response_bits_data,
        output_response_bits_fault);
      if (fields == 12) begin
        #1 $display("%0d %0d %0d %0d %019h %0d %0d %08h %0d %0d %08h %0d %0d",
          sample, first_request_ready, second_request_ready, output_request_valid,
          output_request_valid ? output_payload : 0,
          (output_request_valid || first_response_valid || second_response_valid || output_response_ready) ? outputDebug : 0,
          first_response_valid, first_response_valid ? first_response_bits_data : 0,
          first_response_valid ? first_response_bits_fault : 0,
          second_response_valid, second_response_valid ? second_response_bits_data : 0,
          second_response_valid ? second_response_bits_fault : 0, output_response_ready);
        clock = 1; #1 clock = 0; sample = sample + 1;
      end else if (fields != -1) $fatal(1, "Incomplete arbiter vector");
    end
    $fclose(file); $finish(0);
  end
endmodule
"""


class Reference:
    """A grant owns one complete request/response, including the first stalled offer."""

    def __init__(self):
        self.owner = None
        self.accepted = False
        self.debug = False
        self.prefer_second = False
        self.counts = Counter()
        self.accepted_sources = []

    def step(self, values, cycle):
        state = dict(zip(FIELDS, values, strict=True))
        valid = [state["first_valid"], state["second_valid"]]
        payloads = [state["first_payload"], state["second_payload"]]
        selected = self.owner
        if selected is None:
            selected = int(bool(valid[1] and (not valid[0] or self.prefer_second)))
        offer = not self.accepted and bool(valid[selected])
        tag = self.debug if self.owner is not None else bool(selected or state["first_debug"])
        returning = self.accepted and bool(state["response_valid"])
        ready = self.accepted and bool(state["second_ready"] if self.owner else state["first_ready"])
        first = returning and self.owner == 0
        second = returning and self.owner == 1
        result = (cycle, int(not self.accepted and selected == 0 and bool(state["request_ready"])),
                  int(not self.accepted and selected == 1 and bool(state["request_ready"])), int(offer),
                  payloads[selected] if offer else 0, int(tag) if offer or returning or ready else 0,
                  int(first), state["response_data"] if first else 0, state["response_fault"] if first else 0,
                  int(second), state["response_data"] if second else 0, state["response_fault"] if second else 0, int(ready))
        if state["reset"]:
            self.owner, self.accepted, self.prefer_second, self.debug = None, False, False, False
            return result
        if offer and self.owner is None:
            self.owner, self.debug = selected, tag
        if offer and state["request_ready"]:
            self.accepted = True
            self.counts["requests"] += 1
            self.counts["secondRequests" if selected else "firstRequests"] += 1
            self.counts["bothValidGrants"] += int(all(valid))
            self.accepted_sources.append(selected)
        if offer and not state["request_ready"]:
            self.counts["requestBackpressure"] += 1
        if returning and not ready:
            self.counts["responseBackpressure"] += 1
        if returning and ready:
            self.counts["responses"] += 1
            self.prefer_second = not bool(self.owner)
            self.owner, self.accepted = None, False
        return result


def vectors(seed=1):
    randomizer = random.Random(seed)
    queues = [deque(randomizer.getrandbits(76) for _ in range(32)) for _ in range(2)]
    reference, rows, response = Reference(), [], None
    for cycle in range(10000):
        state = dict.fromkeys(FIELDS, 0)
        state.update(reset=int(cycle == 0), first_valid=int(bool(queues[0]) and cycle != 0),
                     first_payload=queues[0][0] if queues[0] else 0, first_debug=int(cycle % 3 == 0),
                     second_valid=int(bool(queues[1]) and cycle != 0), second_payload=queues[1][0] if queues[1] else 0,
                     first_ready=int(cycle % 5 == 0), second_ready=int(cycle % 7 == 0), request_ready=int(cycle % 4 == 0))
        if response is not None and cycle >= response["due"]:
            state.update(response_valid=1, response_data=response["data"], response_fault=response["fault"])
        values = tuple(state[name] for name in FIELDS)
        sample = reference.step(values, cycle)
        if sample[3] and state["request_ready"]:
            if response is not None:
                raise AssertionError("Arbiter reference overlapped two downstream owners")
            response = {"due": cycle + randomizer.randrange(1, 9), "data": randomizer.getrandbits(32), "fault": randomizer.randrange(2)}
            queues[int(bool(sample[2]))].popleft()
        if sample[12] and state["response_valid"]:
            response = None
        rows.append(values)
        if cycle and not any(queues) and reference.owner is None:
            break
    else:
        raise AssertionError("Arbiter vectors did not drain")
    if reference.accepted_sources != [number % 2 for number in range(64)]:
        raise AssertionError("Persistent equal-demand sources did not alternate")
    return rows


def check(rows, text):
    samples = [line.split() for line in text.splitlines() if line and line[0].isdigit()]
    if len(samples) != len(rows) or any(len(sample) != 13 for sample in samples):
        raise AssertionError("Arbiter trace dimensions differ")
    reference, held = Reference(), None
    for cycle, (values, fields) in enumerate(zip(rows, samples, strict=True)):
        actual = tuple(int(value, 16 if index in HEX_OUTPUT else 10) for index, value in enumerate(fields))
        wanted = reference.step(values, cycle)
        if actual != wanted:
            raise AssertionError(f"Arbiter transaction mismatch at cycle {cycle}: {actual} != {wanted}")
        if held is not None and (not actual[3] or actual[4:6] != held):
            raise AssertionError("Arbiter offer or tag changed under backpressure")
        held = actual[4:6] if actual[3] and not values[8] else None
    if reference.owner is not None or reference.counts["requests"] != reference.counts["responses"]:
        raise AssertionError("Arbiter response ownership did not drain")
    return dict(reference.counts)


def simulate(work, rtl, rows):
    work.mkdir()
    (work / "DitDahE2MemoryArbiter.sv").write_text(rtl)
    (work / "arbiter_tb.sv").write_text(HARNESS)
    (work / "vectors.txt").write_text("".join(" ".join(f"{value:x}" if index in HEX_INPUT else str(value)
                                                    for index, value in enumerate(row)) + "\n" for row in rows))
    commands = []
    for argv in (("iverilog", "-g2012", "-s", "ArbiterBench", "-o", "arbiter-sim", "DitDahE2MemoryArbiter.sv", "arbiter_tb.sv"),
                 ("vvp", "arbiter-sim")):
        result = subprocess.run(argv, cwd=work, capture_output=True, text=True, check=False)
        commands.append({"argv": list(argv), "exitStatus": result.returncode})
        (work / ("compile.log" if argv[0] == "iverilog" else "simulation.log")).write_text(result.stdout + result.stderr)
        if result.returncode:
            raise RuntimeError("Arbiter simulation command failed: " + argv[0])
    (work / "commands.json").write_text(json.dumps(commands, indent=2) + "\n")
    return result.stdout


def mutate(rtl, name):
    port, value = {"drop-debug-owner": ("outputDebug", "1'b0"),
                   "wrong-response-owner": ("first_response_valid", "output_response_valid")}[name]
    changed, count = re.subn(r"(assign\s+" + port + r"\s*=)[^;]+;", r"\g<1> " + value + ";", rtl)
    if count != 1 or changed == rtl:
        raise ValueError("Arbiter RTL mutation target differs: " + name)
    return changed


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rtl", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists():
        parser.error("Output directory must not exist")
    args.output.mkdir(parents=True)
    source = args.rtl / "DitDahE2MemoryArbiter.sv" if args.rtl.is_dir() else args.rtl
    rtl = source.read_text()
    digest = lambda path: hashlib.sha256(path.read_bytes()).hexdigest()
    frozen, runs = digest(source), []
    for seed in (1, 19, 83):
        rows = vectors(seed)
        work = args.output / f"seed-{seed}"
        counts = check(rows, simulate(work, rtl, rows))
        for field in ("firstRequests", "secondRequests", "bothValidGrants", "requestBackpressure", "responseBackpressure"):
            if not counts.get(field):
                raise AssertionError("Arbiter coverage is empty: " + field)
        runs.append({"seed": seed, "cycles": len(rows), "counts": counts, "traceSha256": digest(work / "simulation.log")})
    controls = []
    for name in ("drop-debug-owner", "wrong-response-owner"):
        work = args.output / name
        rows = vectors(1)
        trace = simulate(work, mutate(rtl, name), rows)
        try:
            check(rows, trace)
        except AssertionError as error:
            reason = str(error)
        else:
            raise AssertionError("Arbiter RTL mutation was accepted: " + name)
        controls.append({"mutation": name, "rejected": True, "reason": reason, "traceSha256": digest(work / "simulation.log")})
    if digest(source) != frozen:
        raise AssertionError("Arbiter RTL input changed")
    summary = {"exitStatus": 0, "scope": "two single-outstanding MemoryPort sources, locked offers and round-robin ownership",
               "rtlSha256": frozen, "runs": runs, "negativeControls": controls,
               "tools": {name: digest(Path(shutil.which(name)).resolve()) for name in ("iverilog", "vvp")}}
    (args.output / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    print(f"PASS: {sum(run['cycles'] for run in runs)} arbiter cycles and {len(controls)} RTL negative controls")


if __name__ == "__main__":
    main()
