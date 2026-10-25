# SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
# SPDX-License-Identifier: MIT
"""Check permission retention and ownership through a native memory filter."""

import argparse
from collections import Counter
import hashlib
import json
import os
from pathlib import Path
import random
import re
import shutil
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parents[1]
WRAPPER = """// SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
// SPDX-License-Identifier: MIT
package ditdah_e2
import me.jiuyang.zaozi.*
import me.jiuyang.zaozi.default.{*, given}
import me.jiuyang.zaozi.reftpe.*
import me.jiuyang.zaozi.valuetpe.*
@generator
object DitDahE2 extends Generator[Parameters, UnitLayers, MemoryProtectionIO, UnitProbe]:
  override def moduleName(p: Parameters): String = "DitDahE2MemoryProtectionTest"
  def architecture(p: Parameters) =
    val io = summon[Interface[MemoryProtectionIO]]
    val unit = MemoryProtection.instantiate(p)
    unit.io.clock := io.clock
    unit.io.reset := io.reset
    unit.io.allowed := io.allowed
    unit.io.input :<>= io.input
    io.output :<>= unit.io.output
"""
HARNESS = """// SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
// SPDX-License-Identifier: MIT
module ProtectionBench;
  reg clock = 0, reset = 1, allowed = 0;
  reg input_request_valid = 0, input_response_ready = 0;
  reg output_request_ready = 0, output_response_valid = 0, output_response_bits_fault = 0;
  reg [31:0] output_response_bits_data = 0;
  reg [31:0] input_request_bits_address = 0, input_request_bits_data = 0;
  reg input_request_bits_write = 0, input_request_bits_machine = 0;
  reg [3:0] input_request_bits_mask = 0;
  reg [1:0] input_request_bits_size = 2;
  wire input_request_ready, input_response_valid, input_response_bits_fault;
  wire [31:0] input_response_bits_data;
  wire output_request_valid, output_request_bits_write, output_response_ready, output_request_bits_machine;
  wire [31:0] output_request_bits_address, output_request_bits_data;
  wire [3:0] output_request_bits_mask;
  wire [1:0] output_request_bits_size;
  integer file, fields, sample = 0;
  DitDahE2MemoryProtection dut(.*);
  initial begin
    #1 clock = 1;
    #1 clock = 0;
    file = $fopen("vectors.txt", "r");
    if (!file) $fatal(1, "Cannot open protection vectors");
    while (!$feof(file)) begin
      fields = $fscanf(file, "%d %d %d %d %d %d %h %d %h %d %h %h %d %d\\n",
        reset, allowed, input_request_valid, input_response_ready, output_request_ready,
        output_response_valid, output_response_bits_data, output_response_bits_fault,
        input_request_bits_address, input_request_bits_write, input_request_bits_data,
        input_request_bits_mask, input_request_bits_size, input_request_bits_machine);
      if (fields == 14) begin
        #1 $display("%0d %0d %0d %08h %0d %0d %08h %0d %08h %h %0d %0d %0d", sample,
          input_request_ready, input_response_valid,
          input_response_valid ? input_response_bits_data : 0,
          input_response_valid ? input_response_bits_fault : 0, output_request_valid,
          output_request_valid ? output_request_bits_address : 0,
          output_request_valid ? output_request_bits_write : 0,
          output_request_valid ? output_request_bits_data : 0,
          output_request_valid ? output_request_bits_mask : 0,
          output_request_valid ? output_request_bits_size : 0,
          output_request_valid ? output_request_bits_machine : 0, output_response_ready);
        clock = 1;
        #1 clock = 0;
        sample = sample + 1;
      end else if (fields != -1) $fatal(1, "Incomplete protection vector");
    end
    $fclose(file);
    $finish(0);
  end
endmodule
"""


def response(request):
    address, write, data, mask, size, machine = request
    return ((address ^ data ^ (mask << 16) ^ (size << 8) ^ 0x5A71C903) & 0xFFFFFFFF,
            int((address >> 2) % 5 == 2))


class Reference:
    def __init__(self):
        self.owner = None
        self.offer = None
        self.response_held = None
        self.counts = Counter()

    def step(self, row, cycle):
        assert len(row) == 14, "Invalid protection stimulus width"
        reset, allowed, valid, ready, downstream_ready, bus_valid, data, fault, *payload = row
        request = tuple(payload)
        assert all(value in (0, 1) for value in (reset, allowed, valid, ready, downstream_ready, bus_valid, fault, request[1], request[5]))
        assert all(0 <= value < 1 << 32 for value in (data, request[0], request[2]))
        assert 0 <= request[3] < 16 and 0 <= request[4] < 4
        if reset:
            assert not valid and self.owner is None and self.offer is None and not bus_valid, "Reset with protection traffic"
        if self.offer is not None:
            assert valid and request == self.offer[0], "Upstream offer changed before acceptance"
            permission = self.offer[1]
            if permission != allowed:
                self.counts["grantRetained" if permission else "denialRetained"] += 1
        else:
            permission = bool(allowed)
        if self.response_held is not None:
            assert bus_valid and (data, fault) == self.response_held, "Peer response changed under backpressure"
        owner = self.owner
        if bus_valid:
            assert owner is not None and owner[1] and cycle > owner[2], "Peer response has no accepted request"
            assert (data, fault) == response(owner[0]), "Peer response differs from its request"
        returning = owner is not None and (not owner[1] or bus_valid)
        result = (data, fault) if owner is not None and owner[1] else (0, 1)
        finished = returning and ready
        room = owner is None or finished
        accepted = valid and room and (not permission or downstream_ready)
        external = valid and room and permission
        external_ready = owner is not None and owner[1] and ready
        output = (cycle, int(room and (not permission or downstream_ready)), int(returning),
                  *(result if returning else (0, 0)), int(external),
                  *(request if external else (0, 0, 0, 0, 0, 0)), int(external_ready))
        if reset:
            return output
        self.response_held = (data, fault) if bus_valid and not external_ready else None
        if finished:
            self.counts["responses"] += 1
            self.counts["externalResponses" if owner[1] else "deniedResponses"] += 1
            self.counts["busFaults"] += int(owner[1] and fault)
            self.owner = None
        if valid and owner is not None:
            self.counts["offersWhileActive"] += 1
        if valid and not accepted and self.offer is None:
            self.offer = (request, permission)
            self.counts["capturedWhileActive"] += int(owner is not None)
        if accepted:
            self.owner = (request, permission, cycle)
            self.offer = None
            self.counts["requests"] += 1
            self.counts["externalRequests" if permission else "deniedRequests"] += 1
            self.counts["replacements"] += int(finished)
        self.counts["upstreamRequestStalls"] += int(valid and not accepted)
        self.counts["downstreamRequestStalls"] += int(external and not downstream_ready)
        self.counts["responseStalls"] += int(returning and not ready)
        return output

    def finish(self):
        assert self.owner is None and self.offer is None and self.response_held is None, "Protection traffic did not drain"
        assert self.counts["requests"] == self.counts["responses"]
        assert self.counts["externalRequests"] == self.counts["externalResponses"]
        assert self.counts["deniedRequests"] == self.counts["deniedResponses"]


def vectors(seed, count=2048):
    rng = random.Random(seed)
    requests = []
    for index in range(count):
        size, write = rng.randrange(3), rng.randrange(2)
        address = (0x1000 + index * 4 + rng.randrange(4)) & ~((1 << size) - 1)
        mask = ((1 << (1 << size)) - 1) << (address % 4) if write else 0
        requests.append((address, write, rng.getrandbits(32), mask, size, index % 2))
    model = Reference()
    rows, position, offered_at, peer = [], 0, None, None
    while position < count or model.owner is not None:
        cycle = len(rows)
        valid = position < count
        if valid and offered_at is None:
            offered_at = cycle
        initial_permission = position % 3 != 1
        allowed = initial_permission if offered_at == cycle else bool((cycle - offered_at) % 2) if valid else False
        if valid and cycle > offered_at and cycle - offered_at < 4:
            allowed = not initial_permission
        ready = int(cycle % 7 in (4, 5, 6) if cycle < 24 else rng.randrange(3) == 0)
        downstream_ready = int(cycle >= 3 and (cycle < 24 or rng.randrange(3) == 0))
        bus_valid = peer is not None and cycle >= peer[1]
        bus_data, bus_fault = response(peer[0]) if bus_valid else (0, 0)
        request = requests[position] if valid else (0, 0, 0, 0, 2, 0)
        row = (0, int(allowed), int(valid), ready, downstream_ready, int(bus_valid), bus_data, bus_fault, *request)
        observed = model.step(row, cycle)
        rows.append(row)
        if bus_valid and observed[12]:
            peer = None
        if observed[5] and downstream_ready:
            assert peer is None
            peer = (request, cycle + 1 + rng.randrange(10))
        if valid and observed[1]:
            position += 1
            offered_at = None
        assert cycle < count * 100, "Protection stimulus did not finish"
    rows.append((0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 2, 0))
    model.step(rows[-1], len(rows) - 1)
    model.finish()
    return rows


def parse(trace):
    result = []
    for line in trace.splitlines():
        fields = line.split()
        assert len(fields) == 13, "Invalid protection observation width"
        result.append(tuple(int(value, 16 if index in (3, 6, 8, 9) else 10)
                            for index, value in enumerate(fields)))
    return result


def check(rows, trace):
    observed = parse(trace)
    assert len(observed) == len(rows), "Protection sample count differs"
    model = Reference()
    previous = None
    for cycle, (row, actual) in enumerate(zip(rows, observed, strict=True)):
        if previous is not None:
            before, before_row = previous
            if before[5] and not before_row[4]:
                assert actual[5] and actual[6:12] == before[6:12], f"Downstream offer changed at cycle {cycle}"
            if before[2] and not before_row[3]:
                assert actual[2] and actual[3:5] == before[3:5], f"Upstream response changed at cycle {cycle}"
        expected = model.step(row, cycle)
        assert actual == expected, f"Protection ownership or permission mismatch at cycle {cycle}"
        previous = (actual, row)
    model.finish()
    return dict(sorted(model.counts.items()))


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def build(output):
    names = ["ditdah_e2/src/Parameters.scala", "ditdah_e2/src/Interfaces.scala",
             "ditdah_e2/src/MemoryProtection.scala", "test/protection_port.py", "test/test_protection_port.py",
             "flake.nix", "flake.lock"]
    names += [str(path.relative_to(ROOT)) for path in sorted((ROOT / "nix").glob("*.nix"))]
    contents = {name: (ROOT / name).read_bytes() for name in names}
    for name, content in contents.items():
        destination = output / "inputs" / name
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(content)
    generated = output / "inputs/generated"
    generated.mkdir()
    (generated / "Top.scala").write_text(WRAPPER)
    (generated / "protection_tb.sv").write_text(HARNESS)
    (generated / "parameters.json").write_text("{}\n")
    report = {"exitStatus": None, "parameters": {}, "commands": [],
              "inputHashes": {name: hashlib.sha256(content).hexdigest() for name, content in contents.items()},
              "generatedHashes": {path.name: digest(path) for path in generated.iterdir()},
              "toolHashes": {name: digest(Path(shutil.which(name))) for name in
                             ("elaborate-ditdah-e2", "firld", "firtool", "iverilog", "vvp")},
              "firtool": subprocess.check_output(["firtool", "--version"], text=True).strip()}
    scratch = "/data/tmp" if os.access("/data/tmp", os.W_OK) else None
    with tempfile.TemporaryDirectory(prefix="ditdah-e2-protection-build-", dir=scratch) as directory:
        work = Path(directory)
        (work / "src").mkdir()
        for name, value in contents.items():
            if name.endswith(".scala"):
                (work / "src" / Path(name).name).write_bytes(value)
        shutil.copyfile(generated / "Top.scala", work / "src/Top.scala")
        shutil.copyfile(generated / "parameters.json", work / "parameters.json")
        environment = dict(os.environ, DITDAH_E2_SOURCE=str(work / "src"))

        def run(command):
            result = subprocess.run(command, cwd=work, env=environment, capture_output=True, text=True)
            report["commands"].append({"argv": command, "exitStatus": result.returncode})
            report["exitStatus"] = result.returncode if result.returncode else None
            (output / "build.json").write_text(json.dumps(report, indent=2) + "\n")
            log = re.sub(r"\x1b\[[0-9;]*m", "", result.stdout + result.stderr).replace(str(work), "<work>")
            (output / f"build-{len(report['commands'])}.log").write_text(log)
            assert result.returncode == 0, "Protection RTL generation failed"

        run(["elaborate-ditdah-e2", "design", "parameters.json"])
        run(["firld", *[path.name for path in sorted(work.glob("*.mlirbc"))], "--base-circuit",
             "DitDahE2MemoryProtectionTest", "--no-mangle", "--emit-bytecode", "-o", "linked.mlirbc"])
        run(["firtool", "linked.mlirbc", "--split-verilog", "-disable-all-randomization",
             "--lowering-options=noAlwaysComb,disallowLocalVariables,locationInfoStyle=none", "-o", "rtl"])
        shutil.copytree(work / "rtl", output / "rtl")
    assert all((ROOT / name).read_bytes() == content for name, content in contents.items()), "Protection source changed"
    report.update({"exitStatus": 0, "rtlHashes": {path.name: digest(path) for path in (output / "rtl").glob("*.sv")}})
    (output / "build.json").write_text(json.dumps(report, indent=2) + "\n")
    return report


def simulate(output, rows, rtl):
    output.mkdir(parents=True)
    (output / "vectors.txt").write_text("".join(" ".join(f"{value:x}" if index in (6, 8, 10, 11) else str(value)
                                                         for index, value in enumerate(row)) + "\n" for row in rows))
    (output / "protection_tb.sv").write_text(HARNESS)
    shutil.copyfile(rtl, output / "DitDahE2MemoryProtection.sv")
    commands = []
    for command in (["iverilog", "-g2012", "-s", "ProtectionBench", "-o", "protection-sim",
                     "DitDahE2MemoryProtection.sv", "protection_tb.sv"], ["vvp", "protection-sim"]):
        result = subprocess.run(command, cwd=output, capture_output=True, text=True)
        commands.append({"argv": command, "exitStatus": result.returncode})
        (output / f"command-{len(commands)}.log").write_text(result.stdout + result.stderr)
        assert result.returncode == 0, "Protection simulation failed"
    trace = "\n".join(line for line in result.stdout.splitlines() if line and line[0].isdigit()) + "\n"
    (output / "protection.trace").write_text(trace)
    (output / "commands.json").write_text(json.dumps(commands, indent=2) + "\n")
    return trace


def permission_mutant(content):
    pattern = r"(wire\s+permitted\s*=\s*)([^;]+);"
    found = re.findall(pattern, content)
    assert len(found) == 1 and "heldPermission" in found[0][1], "Permission mutation no longer matches RTL"
    return re.sub(pattern, r"\1allowed;", content)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=Path("result/protection-port"))
    args = parser.parse_args()
    assert not args.output.exists() or not any(args.output.iterdir()), "Protection output must be empty"
    build_report = build(args.output)
    runs = []
    for seed in (1, 19, 83):
        rows = vectors(seed)
        directory = args.output / f"seed-{seed}"
        trace = simulate(directory, rows, args.output / "rtl/DitDahE2MemoryProtection.sv")
        counts = check(rows, trace)
        for name in ("grantRetained", "denialRetained", "capturedWhileActive", "replacements", "busFaults",
                     "upstreamRequestStalls", "downstreamRequestStalls", "responseStalls", "deniedRequests"):
            assert counts.get(name, 0), f"Missing protection coverage: {name}"
        runs.append({"seed": seed, "cycles": len(rows), **counts, "traceHash": digest(directory / "protection.trace"),
                     "vectorsHash": digest(directory / "vectors.txt"), "commandsHash": digest(directory / "commands.json")})
    rows = vectors(1)
    mutant = args.output / "permission-mutant.sv"
    mutant.write_text(permission_mutant((args.output / "rtl/DitDahE2MemoryProtection.sv").read_text()))
    trace = simulate(args.output / "permission-mutant", rows, mutant)
    actual = parse(trace)
    witness = next((cycle for cycle in range(1, len(rows)) if actual[cycle - 1][5] and not rows[cycle - 1][4]
                    and not actual[cycle][5]), None)
    assert witness is not None, "Mutant did not withdraw a blocked external offer"
    try:
        check(rows, trace)
    except AssertionError as error:
        reason = str(error)
        assert reason.startswith("Downstream offer changed"), reason
    else:
        raise AssertionError("Protection checker accepted a changed permission")
    assert all(digest(ROOT / name) == value for name, value in build_report["inputHashes"].items()), "Protection source changed"
    report = {"scope": "native permission filter with retained offers and one transaction owner", "exitStatus": 0,
              "command": "python3 test/protection_port.py", "buildHash": digest(args.output / "build.json"), "runs": runs,
              "negativeControls": [{"name": "ignore retained permission", "cycle": witness, "reason": reason,
                                    "rtlHash": digest(mutant), "traceHash": digest(args.output / "permission-mutant/protection.trace")}],
              "excluded": ["PMP region decoding", "CPU privilege integration", "formal proof"]}
    (args.output / "summary.json").write_text(json.dumps(report, indent=2) + "\n")
    print(f"PASS: {sum(run['cycles'] for run in runs)} protection cycles and one RTL negative control")


if __name__ == "__main__":
    main()
