# SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
# SPDX-License-Identifier: MIT
"""Check iterative multiplication, division, backpressure and cancellation."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import random
import shutil
import subprocess
import tempfile


SEED = 0x4D444956
MASK = (1 << 32) - 1
BOUNDARY = (0, 1, 2, 3, 0x7FFFFFFF, 0x80000000, 0x80000001, 0xFFFFFFFE, MASK, 0xA5A5A5A5)
WRAPPER = """// SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
// SPDX-License-Identifier: MIT
package ditdah_e2
import me.jiuyang.zaozi.*
import me.jiuyang.zaozi.default.{*, given}
import me.jiuyang.zaozi.reftpe.*
import me.jiuyang.zaozi.valuetpe.*
@generator
object DitDahE2 extends Generator[Parameters, UnitLayers, MultiplyDivideIO, UnitProbe]:
  override def moduleName(p: Parameters): String = "DitDahE2MultiplyDivideTest"
  def architecture(p: Parameters) =
    val io = summon[Interface[MultiplyDivideIO]]
    val unit = MultiplyDivide.instantiate(p)
    unit.io.clock := io.clock
    unit.io.reset := io.reset
    unit.io.cancel := io.cancel
    unit.io.request :<>= io.request
    io.response :<>= unit.io.response
"""
HARNESS = """// SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
// SPDX-License-Identifier: MIT
module MultiplyDivideBench;
  reg clock = 0, reset = 1, cancel = 0;
  reg request_valid = 0, response_ready = 0;
  reg [2:0] request_bits_operation = 0;
  reg [31:0] request_bits_left = 0, request_bits_right = 0;
  wire request_ready, response_valid;
  wire [31:0] response_bits;
  integer file, fields, row = 0, cycle = 0, started = 0;
  integer hold_cycles, cancel_after, delay_count;
  integer accepted = 0, completed = 0, canceled = 0, rejected = 0;
  integer held_cycles = 0, maximum_latency = 0;
  reg outstanding = 0, first_seen = 0, held = 0, accepted_now;
  reg [31:0] held_value;
  DitDahE2MultiplyDivide dut(.*);

  task step;
    begin
      clock = 0;
      #1;
      accepted_now = 0;
      if (!reset) begin
        if (cancel) begin
          if (request_ready || response_valid) $fatal(1, "Cancel did not suppress channels");
          $display("K %0d %0d %0d %0d", row, cycle, outstanding, first_seen);
          if (outstanding) canceled = canceled + 1;
          else rejected = rejected + 1;
          outstanding = 0;
          first_seen = 0;
          held = 0;
        end else begin
          if (outstanding && request_ready) $fatal(1, "Request ready while occupied");
          if (held && (!response_valid || response_bits !== held_value))
            $fatal(1, "Result changed under backpressure");
          if (outstanding && !first_seen && cycle - started > 34)
            $fatal(1, "Result exceeded latency bound");
          if (response_valid) begin
            if (!outstanding) $fatal(1, "Unowned arithmetic result");
            if (!first_seen) begin
              if (cycle - started < 1 || cycle - started > 34)
                $fatal(1, "Invalid result latency");
              if (cycle - started > maximum_latency) maximum_latency = cycle - started;
              $display("V %0d %0d %08h", row, cycle, response_bits);
              first_seen = 1;
            end
            if (response_ready) begin
              $display("R %0d %0d %08h", row, cycle, response_bits);
              outstanding = 0;
              first_seen = 0;
              held = 0;
              completed = completed + 1;
            end else begin
              held = 1;
              held_value = response_bits;
              held_cycles = held_cycles + 1;
            end
          end
          if (request_valid && request_ready) begin
            if (outstanding) $fatal(1, "Arithmetic request overwritten");
            $display("Q %0d %0d %0d %08h %08h", row, cycle,
              request_bits_operation, request_bits_left, request_bits_right);
            outstanding = 1;
            first_seen = 0;
            started = cycle;
            accepted_now = 1;
            accepted = accepted + 1;
          end
        end
      end
      clock = 1;
      #1;
      cycle = cycle + 1;
    end
  endtask

  initial begin
    step;
    reset = 0;
    file = $fopen("vectors.txt", "r");
    if (!file) $fatal(1, "Cannot open arithmetic vectors");
    while (!$feof(file)) begin
      fields = $fscanf(file, "%d %h %h %d %d\\n", request_bits_operation,
        request_bits_left, request_bits_right, hold_cycles, cancel_after);
      if (fields == 5) begin
        request_valid = 1;
        response_ready = 0;
        cancel = cancel_after == 0;
        step;
        if (cancel_after != 0 && !accepted_now) $fatal(1, "Idle unit rejected a request");
        request_valid = 0;
        if (cancel_after >= 0) begin
          if (cancel_after != 0) begin
            while (cycle - started < cancel_after) step;
            cancel = 1;
            request_valid = 1;
            response_ready = 1;
            step;
          end
          cancel = 0;
          request_valid = 0;
          response_ready = 1;
          repeat (36) step;
        end else begin
          while (!response_valid) begin
            request_bits_operation = request_bits_operation + 1;
            request_bits_left = request_bits_left ^ 32'hdeadbeef;
            request_bits_right = request_bits_right + 1;
            step;
          end
          for (delay_count = 0; delay_count < hold_cycles; delay_count = delay_count + 1) step;
          response_ready = 1;
          step;
          if (outstanding) $fatal(1, "Result was not consumed");
        end
        row = row + 1;
      end else if (fields != -1) $fatal(1, "Incomplete arithmetic vector");
    end
    $fclose(file);
    repeat (40) step;
    $display("C %0d %0d %0d %0d %0d %0d %0d", cycle, accepted, completed,
      canceled, rejected, held_cycles, maximum_latency);
    $finish(0);
  end
endmodule
"""


def vectors():
    rows = []
    rng = random.Random(SEED)
    for operation in range(8):
        for left in BOUNDARY:
            for right in BOUNDARY:
                rows.append((operation, left, right, rng.randrange(9), -1))
        for _ in range(4096):
            rows.append((operation, rng.getrandbits(32), rng.getrandbits(32), rng.randrange(9), -1))
        for cancel_after in (0, 1, 17, 33, 34, 38):
            rows.append((operation, 0x87654321, 0xFEDCBA98, 0, cancel_after))
    return rows


def expected(operation, left, right):
    a = left - (1 << 32) if left & (1 << 31) else left
    b = right - (1 << 32) if right & (1 << 31) else right
    if operation == 0:
        return (left * right) & MASK
    if operation == 1:
        return ((a * b) >> 32) & MASK
    if operation == 2:
        return ((a * right) >> 32) & MASK
    if operation == 3:
        return ((left * right) >> 32) & MASK
    numerator, denominator = (a, b) if operation in (4, 6) else (left, right)
    if denominator == 0:
        return MASK if operation in (4, 5) else left
    quotient = abs(numerator) // abs(denominator)
    if (numerator < 0) != (denominator < 0):
        quotient = -quotient
    value = quotient if operation in (4, 5) else numerator - quotient * denominator
    return value & MASK


def check_oracle():
    cases = ((0, MASK, MASK, 1), (1, 0x80000000, 0x7FFFFFFF, 0xC0000000),
             (2, 0x80000000, MASK, 0x80000000), (3, MASK, MASK, 0xFFFFFFFE),
             (4, 0xFFFFFFF9, 3, 0xFFFFFFFE), (4, 7, 0xFFFFFFFD, 0xFFFFFFFE),
             (4, 0x80000000, MASK, 0x80000000), (5, MASK, 2, 0x7FFFFFFF),
             (6, 0xFFFFFFF9, 3, MASK), (6, 7, 0xFFFFFFFD, 1),
             (6, 0x80000000, MASK, 0), (7, MASK, 2, 1),
             (4, 7, 0, MASK), (5, 7, 0, MASK), (6, 0xFFFFFFF9, 0, 0xFFFFFFF9),
             (7, 0xFFFFFFF9, 0, 0xFFFFFFF9))
    for operation, left, right, result in cases:
        assert expected(operation, left, right) == result, "Arithmetic oracle self-check failed"
    return len(cases)


def check(rows, trace):
    pending = None
    seen = None
    finished = set()
    accepted = completed = canceled = rejected = held = maximum = 0
    metrics = None
    for line in trace.splitlines():
        fields = line.split()
        kind = fields[0]
        if kind == "C":
            assert metrics is None, "Repeated summary"
            metrics = tuple(map(int, fields[1:]))
            continue
        index, cycle = map(int, fields[1:3])
        assert 0 <= index < len(rows), "Unknown vector"
        operation, left, right, hold, cancel_after = rows[index]
        if kind == "Q":
            assert pending is None and index not in finished, "Repeated request"
            assert cancel_after != 0, "Canceled offer was accepted"
            actual = (int(fields[3]), int(fields[4], 16), int(fields[5], 16))
            assert actual == (operation, left, right), "Request operands differ"
            pending, seen = (index, cycle), None
            accepted += 1
        elif kind in ("V", "R"):
            assert pending is not None and pending[0] == index, "Result has no owner"
            assert int(fields[3], 16) == expected(operation, left, right), "Arithmetic result differs"
            if kind == "V":
                assert seen is None, "Result appeared twice"
                assert 1 <= cycle - pending[1] <= 34, "Invalid result latency"
                maximum = max(maximum, cycle - pending[1])
                seen = cycle
            else:
                assert cancel_after == -1, "Canceled operation completed"
                assert seen is not None and cycle - seen == hold, "Result hold interval differs"
                held += hold
                completed += 1
                finished.add(index)
                pending = seen = None
        elif kind == "K":
            assert cancel_after >= 0 and index not in finished, "Unexpected cancellation"
            active, visible = map(int, fields[3:])
            assert active == int(pending is not None), "Canceled request ownership differs"
            assert visible == int(seen is not None), "Canceled result state differs"
            if cancel_after == 0:
                assert pending is None, "Canceled offer acquired ownership"
                rejected += 1
            else:
                assert pending is not None and pending[0] == index, "Cancellation has no owner"
                assert cycle - pending[1] == cancel_after, "Cancellation timing differs"
                if seen is not None:
                    held += cycle - seen
                canceled += 1
            finished.add(index)
            pending = seen = None
        else:
            raise AssertionError("Unknown arithmetic record")
    assert pending is None and len(finished) == len(rows), "Unfinished arithmetic vector"
    assert metrics is not None and len(metrics) == 7, "Missing arithmetic summary"
    assert metrics[1:] == (accepted, completed, canceled, rejected, held, maximum), "Summary counts differ"
    assert all(value > 0 for value in metrics), "Unreached arithmetic coverage"
    return dict(zip(("cycles", "accepted", "completed", "canceled", "rejectedOffers",
                     "heldCycles", "maximumLatency"), metrics, strict=True))


def negative_controls(rows, trace):
    lines = trace.splitlines()
    controls = []
    for name, operation, zero in (("multiply_high_sign", 1, False), ("divide_by_zero", 4, True)):
        line_index = next(i for i, line in enumerate(lines) if line.startswith("R ") and
                          rows[int(line.split()[1])][0] == operation and
                          (rows[int(line.split()[1])][2] == 0 if zero else
                           rows[int(line.split()[1])][1] == 0x80000000 and
                           rows[int(line.split()[1])][2] == 0x7FFFFFFF))
        changed = lines.copy()
        fields = changed[line_index].split()
        fields[3] = f"{int(fields[3], 16) ^ 1:08x}"
        changed[line_index] = " ".join(fields)
        controls.append((name, line_index, changed[line_index], "\n".join(changed)))
    changed = lines.copy()
    line_index = next(i for i, line in enumerate(lines) if line.startswith("K ") and line.split()[3] == "1")
    fields = lines[line_index].split()
    index, cycle = map(int, fields[1:3])
    operation, left, right, _, _ = rows[index]
    inserted = f"R {index} {cycle + 1} {expected(operation, left, right):08x}"
    changed.insert(line_index + 1, inserted)
    controls.append(("result_after_cancel", line_index + 1, inserted, "\n".join(changed)))
    results = []
    for name, line_index, replacement, changed in controls:
        try:
            check(rows, changed)
        except AssertionError as error:
            results.append({"name": name, "line": line_index, "replacement": replacement,
                            "rejected": str(error), "traceHash": sha(changed.encode())})
        else:
            raise AssertionError(f"Checker accepted {name}")
    return results


def sha(data):
    return hashlib.sha256(data).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=Path("result/multiply-divide-unit"))
    args = parser.parse_args()
    oracle_checks = check_oracle()
    root = Path(__file__).resolve().parents[1]
    names = ["ditdah_e2/src/MultiplyDivide.scala", "ditdah_e2/src/Parameters.scala",
             "ditdah_e2/src/Interfaces.scala", "test/multiply_divide_unit.py", "flake.nix", "flake.lock"]
    names += [str(path.relative_to(root)) for path in sorted((root / "nix").glob("*.nix"))]
    contents = {name: (root / name).read_bytes() for name in names}
    hashes = {name: sha(data) for name, data in contents.items()}
    tools = {name: Path(shutil.which(name)) for name in ("elaborate-ditdah-e2", "firld", "firtool", "iverilog", "vvp")}
    tool_hashes = {name: sha(path.read_bytes()) for name, path in tools.items()}
    rows = vectors()
    vector_text = "".join(f"{op} {left:08x} {right:08x} {hold} {cancel}\n"
                          for op, left, right, hold, cancel in rows)
    commands = []
    scratch = "/data/tmp" if os.access("/data/tmp", os.W_OK) else None
    with tempfile.TemporaryDirectory(prefix="ditdah-e2-multiply-divide-", dir=scratch) as directory:
        work = Path(directory)
        for name, data in contents.items():
            target = work / "inputs" / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
        source = work / "inputs/ditdah_e2/src"
        (source / "ArithmeticTop.scala").write_text(WRAPPER)
        (work / "parameters.json").write_text('{"resetVector":0}\n')
        (work / "vectors.txt").write_text(vector_text)
        (work / "arithmetic_tb.sv").write_text(HARNESS)
        frozen = {path: sha(path.read_bytes()) for path in work.rglob("*") if path.is_file()}
        environment = dict(os.environ, DITDAH_E2_SOURCE=str(source))

        def verify_inputs():
            assert all(sha(path.read_bytes()) == value for path, value in frozen.items()), "Frozen arithmetic inputs changed"
            assert all(sha(path.read_bytes()) == tool_hashes[name] for name, path in tools.items()), "Arithmetic tools changed"

        def run(command):
            result = subprocess.run(command, cwd=work, env=environment, capture_output=True, text=True)
            commands.append({"argv": command, "exitStatus": result.returncode})
            if result.returncode:
                raise RuntimeError((result.stdout + result.stderr).replace(str(work), "<workspace>"))
            return result.stdout

        verify_inputs()
        run(["elaborate-ditdah-e2", "design", "parameters.json"])
        run(["firld", *[path.name for path in sorted(work.glob("*.mlirbc"))],
             "--base-circuit", "DitDahE2MultiplyDivideTest", "--no-mangle", "--emit-bytecode", "-o", "linked.mlirbc"])
        run(["firtool", "linked.mlirbc", "--split-verilog", "-disable-all-randomization",
             "--lowering-options=noAlwaysComb,disallowLocalVariables,locationInfoStyle=none", "-o", "rtl"])
        rtl = sorted((work / "rtl").glob("*.sv"))
        assert (work / "rtl/DitDahE2MultiplyDivide.sv").is_file(), "Missing arithmetic RTL"
        rtl_hashes = {path.name: sha(path.read_bytes()) for path in rtl}
        run(["iverilog", "-g2012", "-s", "MultiplyDivideBench", "-o", "arithmetic-sim",
             *[str(path.relative_to(work)) for path in rtl], "arithmetic_tb.sv"])
        trace = run(["vvp", "arithmetic-sim"])
        metrics = check(rows, trace)
        controls = negative_controls(rows, trace)
        verify_inputs()
        assert rtl_hashes == {path.name: sha(path.read_bytes()) for path in rtl}, "Arithmetic RTL changed"
        versions = {}
        for name in ("firtool", "firld", "iverilog", "vvp"):
            result = subprocess.run([name, "--version" if name in ("firtool", "firld") else "-V"],
                                    capture_output=True, text=True, check=True)
            version = (result.stdout + result.stderr).strip()
            versions[name] = version if name in ("firtool", "firld") else version.splitlines()[0]
        args.output.mkdir(parents=True, exist_ok=True)
        for path in rtl:
            shutil.copyfile(path, args.output / path.name)
        (args.output / "arithmetic.trace").write_text(trace)
        (args.output / "vectors.txt").write_text(vector_text)
        report = {"scope": "iterative RV32 multiply and divide unit", "parameters": {"resetVector": 0},
                  "command": "python3 test/multiply_divide_unit.py", "exitStatus": 0,
                  "inputHashes": hashes, "tools": versions, "toolHashes": tool_hashes, "commands": commands,
                  "rtlHashes": rtl_hashes, "wrapperHash": sha(WRAPPER.encode()), "harnessHash": sha(HARNESS.encode()),
                  "vectorHash": sha(vector_text.encode()), "traceHash": sha(trace.encode()),
                  "randomSeed": SEED, "randomPairsPerOperation": 4096, "boundaryValues": BOUNDARY,
                  "oracleChecks": oracle_checks,
                  "cancelCycles": [0, 1, 17, 33, 34, 38], "vectors": len(rows), **metrics,
                  "negativeControls": controls,
                  "integrationChecksRequired": ["operand forwarding", "X ownership", "M retirement", "trap and interrupt cancellation"]}
        (args.output / "summary.json").write_text(json.dumps(report, indent=2) + "\n")
    print(f"PASS: {len(rows)} arithmetic vectors and {len(controls)} semantic negative controls")


if __name__ == "__main__":
    main()
