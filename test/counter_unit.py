# SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
# SPDX-License-Identifier: MIT
"""Generate counter RTL and check every clock edge with an integer oracle."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import random
import shutil
import subprocess
import tempfile


SEED = 0x3200
FIELDS = ("reset", "retire", "inhibit", "writeCycle", "writeInstret", "high", "writeData")
WRAPPER = """// SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
// SPDX-License-Identifier: MIT
package ditdah_e2
import me.jiuyang.zaozi.*
import me.jiuyang.zaozi.default.{*, given}
import me.jiuyang.zaozi.reftpe.*
import me.jiuyang.zaozi.valuetpe.*
@generator
object DitDahE2 extends Generator[Parameters, UnitLayers, CounterIO, UnitProbe]:
  override def moduleName(p: Parameters): String = "DitDahE2CounterTest"
  def architecture(p: Parameters) =
    val io = summon[Interface[CounterIO]]
    val counters = Counters.instantiate(p)
    counters.io.clock := io.clock
    counters.io.reset := io.reset
    counters.io.retire := io.retire
    counters.io.inhibit := io.inhibit
    counters.io.writeCycle := io.writeCycle
    counters.io.writeInstret := io.writeInstret
    counters.io.high := io.high
    counters.io.writeData := io.writeData
    io.cycleCount := counters.io.cycleCount
    io.instretCount := counters.io.instretCount
"""
HARNESS = """// SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
// SPDX-License-Identifier: MIT
module CounterBench;
  reg clock = 0;
  reg reset, retire, writeCycle, writeInstret, high;
  reg [2:0] inhibit;
  reg [31:0] writeData;
  wire [63:0] cycleCount, instretCount;
  integer file, fields, sample = 0;
  DitDahE2Counters dut(.*);
  initial begin
    file = $fopen("vectors.txt", "r");
    if (!file) $fatal(1, "Cannot open vectors");
    while (!$feof(file)) begin
      clock = 0;
      fields = $fscanf(file, "%d %d %d %d %d %d %h\\n",
        reset, retire, inhibit, writeCycle, writeInstret, high, writeData);
      if (fields == 7) begin
        #1 clock = 1;
        #1 $display("%0d %016h %016h", sample, cycleCount, instretCount);
        sample = sample + 1;
      end else if (fields != -1) $fatal(1, "Incomplete vector");
    end
    $fclose(file);
    $finish(0);
  end
endmodule
"""


def vectors():
    rows = []

    def add(name, **values):
        rows.append({"name": name, **dict.fromkeys(FIELDS, 0), **values})

    add("reset_priority", reset=1, retire=1, writeCycle=1, writeInstret=1, writeData=0xFFFFFFFF)
    for name, retired in (("idle", 0), ("retire", 1), ("trap_input", 0), ("stall", 0), ("wfi", 0)):
        add(name, retire=retired)
    for inhibit in range(8):
        add(f"inhibit_{inhibit}", retire=1, inhibit=inhibit)
    add("inhibit_commit_old", retire=1)
    add("inhibit_commit_new", retire=1, inhibit=5)
    add("enable_commit_old", retire=1, inhibit=5)
    add("enable_commit_new", retire=1)
    for field, label in (("writeCycle", "cycle"), ("writeInstret", "instret")):
        add(f"{label}_upper", high=1, writeData=0x12345678, **{field: 1})
        add(f"{label}_lower", retire=1, writeData=0xFFFFFFFF, **{field: 1})
        add(f"{label}_carry", retire=1)
        add(f"{label}_wrap_upper", high=1, writeData=0xFFFFFFFF, **{field: 1})
        add(f"{label}_wrap_lower", retire=1, writeData=0xFFFFFFFF, **{field: 1})
        add(f"{label}_wrap", retire=1)
        add(f"{label}_priority_lower", retire=1, writeData=0xFFFFFFFF, **{field: 1})
        add(f"{label}_priority_upper", retire=1, high=1, writeData=7, **{field: 1})
        add(f"{label}_write_inhibited", retire=1, inhibit=5, writeData=19, **{field: 1})
    add("both_writes", retire=1, writeCycle=1, writeInstret=1, writeData=0xA5A55A5A)
    add("reset_inhibited", reset=1, retire=1, inhibit=5)
    rng = random.Random(SEED)
    for index in range(2048):
        add(f"random_{index}", reset=int(rng.randrange(128) == 0), retire=rng.randrange(2),
            inhibit=rng.randrange(8), writeCycle=int(rng.randrange(8) == 0),
            writeInstret=int(rng.randrange(8) == 0), high=rng.randrange(2),
            writeData=rng.randrange(1 << 32))
    return rows


def expected_counts(rows):
    cycle = instret = 0
    expected = []

    def update(value, write, high, data, increment):
        if write:
            upper, lower = divmod(value, 1 << 32)
            return data * (1 << 32) + lower if high else upper * (1 << 32) + data
        return (value + increment) % (1 << 64)

    for row in rows:
        if row["reset"]:
            cycle = instret = 0
        else:
            cycle = update(cycle, row["writeCycle"], row["high"], row["writeData"],
                           int((row["inhibit"] & 1) == 0))
            instret = update(instret, row["writeInstret"], row["high"], row["writeData"],
                             int(bool(row["retire"]) and (row["inhibit"] & 4) == 0))
        expected.append((cycle, instret))
    return expected


def check(rows, trace):
    lines = trace.splitlines()
    expected = expected_counts(rows)
    if len(lines) != len(rows):
        raise AssertionError(f"Counter samples differ: {len(lines)} actual, {len(rows)} expected")
    for index, (line, target) in enumerate(zip(lines, expected, strict=True)):
        sample, cycle, instret = line.split()
        if int(sample) != index or (int(cycle, 16), int(instret, 16)) != target:
            raise AssertionError(f"Counter mismatch at {rows[index]['name']}")


def sha(data):
    return hashlib.sha256(data).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=Path("result/counter-unit"))
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    names = ["ditdah_e2/src/Counters.scala", "ditdah_e2/src/Parameters.scala",
             "ditdah_e2/src/Interfaces.scala", "test/counter_unit.py", "flake.nix", "flake.lock"]
    names += [str(path.relative_to(root)) for path in sorted((root / "nix").glob("*.nix"))]
    contents = {name: (root / name).read_bytes() for name in names}
    hashes = {name: sha(data) for name, data in contents.items()}
    commands = []
    scratch = "/data/tmp" if os.access("/data/tmp", os.W_OK) else None
    with tempfile.TemporaryDirectory(prefix="ditdah-e2-counters-", dir=scratch) as directory:
        work = Path(directory)
        for name, data in contents.items():
            target = work / "inputs" / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
        source = work / "inputs/ditdah_e2/src"
        (source / "CounterTop.scala").write_text(WRAPPER)
        (work / "parameters.json").write_text('{"resetVector":0}\n')
        environment = dict(os.environ, DITDAH_E2_SOURCE=str(source))

        def run(command):
            result = subprocess.run(command, cwd=work, env=environment, capture_output=True, text=True)
            commands.append({"argv": command, "exitStatus": result.returncode})
            if result.returncode:
                raise RuntimeError(result.stdout + result.stderr)
            return result.stdout

        run(["elaborate-ditdah-e2", "design", "parameters.json"])
        run(["firld", *[path.name for path in sorted(work.glob("*.mlirbc"))],
             "--base-circuit", "DitDahE2CounterTest", "--no-mangle", "--emit-bytecode", "-o", "linked.mlirbc"])
        run(["firtool", "linked.mlirbc", "--split-verilog", "-disable-all-randomization",
             "--lowering-options=noAlwaysComb,disallowLocalVariables,locationInfoStyle=none", "-o", "rtl"])
        rows = vectors()
        vector_text = "".join(" ".join(str(row[field]) for field in FIELDS[:-1]) +
                              f" {row['writeData']:08x}\n" for row in rows)
        (work / "vectors.txt").write_text(vector_text)
        (work / "counter_tb.sv").write_text(HARNESS)
        rtl = sorted((work / "rtl").glob("*.sv"))
        run(["iverilog", "-g2012", "-s", "CounterBench", "-o", "counter-sim",
             *[str(path.relative_to(work)) for path in rtl], "counter_tb.sv"])
        trace = run(["vvp", "counter-sim"])
        check(rows, trace)
        controls = 0
        for field in (1, 2):
            lines = trace.splitlines()
            parts = lines[1].split()
            parts[field] = f"{int(parts[field], 16) ^ 1:016x}"
            lines[1] = " ".join(parts)
            try:
                check(rows, "\n".join(lines))
            except AssertionError:
                controls += 1
            else:
                raise AssertionError("Counter checker accepted a changed count")
        for name, value in hashes.items():
            if sha((work / "inputs" / name).read_bytes()) != value:
                raise AssertionError("Frozen counter inputs changed")
        args.output.mkdir(parents=True, exist_ok=True)
        for path in rtl:
            shutil.copyfile(path, args.output / path.name)
        (args.output / "counter.trace").write_text(trace)
        (args.output / "vectors.json").write_text(json.dumps(rows, indent=2) + "\n")
        versions = {}
        for name, command in (("firtool", ["firtool", "--version"]), ("firld", ["firld", "--version"]),
                              ("iverilog", ["iverilog", "-V"]), ("vvp", ["vvp", "-V"])):
            result = subprocess.run(command, capture_output=True, text=True, check=True)
            version = (result.stdout + result.stderr).strip()
            versions[name] = version if name in ("firtool", "firld") else version.splitlines()[0]
        elaborator = Path(shutil.which("elaborate-ditdah-e2"))
        report = {"scope": "64 bit cycle and retirement counter unit", "parameters": {"resetVector": 0},
                  "command": "python3 test/counter_unit.py", "exitStatus": 0, "inputHashes": hashes,
                  "tools": versions, "elaboratorHash": sha(elaborator.read_bytes()), "commands": commands,
                  "rtlHashes": {path.name: sha(path.read_bytes()) for path in rtl},
                  "wrapperHash": sha(WRAPPER.encode()), "harnessHash": sha(HARNESS.encode()),
                  "vectorHash": sha(vector_text.encode()), "traceHash": sha(trace.encode()),
                  "samples": len(rows), "randomSeed": SEED, "randomSamples": 2048,
                  "directedCases": [row["name"] for row in rows if not row["name"].startswith("random_")],
                  "negativeControls": controls,
                  "integrationChecksRequired": ["retire qualification", "mcountinhibit commit timing"]}
        (args.output / "summary.json").write_text(json.dumps(report, indent=2) + "\n")
    print(f"PASS: {len(rows)} counter samples and {controls} negative controls")


if __name__ == "__main__":
    main()
