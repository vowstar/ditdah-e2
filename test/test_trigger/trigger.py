# SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
# SPDX-License-Identifier: MIT
"""Check the standalone execute-trigger CSR bank and match arbitration."""

import argparse
import hashlib
import json
import random
import re
import shutil
import subprocess
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
from build_rtl import configuration, sources

FIELDS = ("reset", "address", "operand", "operation", "writeRequested", "commit", "debugAccess",
          "core_pc", "core_valid", "core_user", "core_debug", "core_ready", "core_trap", "core_mret")
OUTPUTS = ("implemented", "readData", "writeMask", "writtenData", "core_matched",
           "core_debugAction", "core_nativeAction")
CSR = {"tselect": 0x7A0, "tdata1": 0x7A1, "tdata2": 0x7A2, "tdata3": 0x7A3,
       "tinfo": 0x7A4, "tcontrol": 0x7A5, "mcontext": 0x7A8, "scontext": 0x7AA}
HARNESS = """// SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
// SPDX-License-Identifier: MIT
module TriggerBench;
  reg clock = 0, reset = 1;
  reg [11:0] address = 0;
  reg [31:0] operand = 0, core_pc = 0;
  reg [1:0] operation = 0;
  reg writeRequested = 0, commit = 0, debugAccess = 0;
  reg core_valid = 0, core_user = 0, core_debug = 0, core_ready = 0, core_trap = 0, core_mret = 0;
  wire implemented, core_matched, core_debugAction, core_nativeAction;
  wire [31:0] readData, writeMask, writtenData;
  wire observe_selected, observe_mte, observe_mpte;
  wire [1:0] observe_dmode, observe_hit, observe_debugAction, observe_machine, observe_user, observe_execute;
  wire [31:0] observe_address0, observe_address1;
  integer file, fields, sample = 0;
  DitDahE2Trigger dut(.*);
  initial begin
    #1 clock = 1; #1 clock = 0;
    file = $fopen("vectors.txt", "r");
    if (!file) $fatal(1, "Cannot open trigger vectors");
    while (!$feof(file)) begin
      fields = $fscanf(file, "%d %h %h %d %d %d %d %h %d %d %d %d %d %d\\n",
        reset, address, operand, operation, writeRequested, commit, debugAccess,
        core_pc, core_valid, core_user, core_debug, core_ready, core_trap, core_mret);
      if (fields == 14) begin
        #1 $display("%0d %0d %08h %08h %08h %0d %0d %0d", sample,
          implemented, readData, writeMask, writtenData,
          core_matched, core_debugAction, core_nativeAction);
        clock = 1; #1 clock = 0; sample = sample + 1;
      end else if (fields != -1) $fatal(1, "Incomplete trigger vector");
    end
    $fclose(file); $finish(0);
  end
endmodule
"""


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def row(**values):
    defaults = dict.fromkeys(FIELDS, 0)
    defaults.update(operation=1, core_ready=1)
    if values.keys() - defaults.keys():
        raise ValueError("Unknown trigger stimulus")
    defaults.update(values)
    return tuple(int(defaults[name]) for name in FIELDS)


def access(name, value=None, debug=True):
    values = {"address": CSR[name], "debugAccess": int(debug)}
    if value is not None:
        values.update(operand=value, writeRequested=1, commit=1)
    return row(**values)


class Reference:
    def __init__(self):
        self.selected = 0
        self.state = [{"dmode": 0, "hit": 0, "action": 0, "m": 0, "u": 0, "execute": 0, "address": 0}
                      for _ in range(2)]
        self.mte = self.mpte = 0
        self.counts = Counter()

    def read(self, address):
        if address == 0x7A0:
            return self.selected
        if address == 0x7A1:
            item = self.state[self.selected]
            return (0x20000000 | item["dmode"] << 27 | item["hit"] << 20 | item["action"] << 12 |
                    item["m"] << 6 | item["u"] << 3 | item["execute"] << 2)
        if address == 0x7A2:
            return self.state[self.selected]["address"]
        if address == 0x7A4:
            return 0x01000004
        if address == 0x7A5:
            return self.mpte << 7 | self.mte << 3
        return 0

    def step(self, values, cycle):
        state = dict(zip(FIELDS, values, strict=True))
        implemented = state["address"] in CSR.values()
        read = self.read(state["address"]) if implemented else 0
        mask = {0x7A1: 0x0810104C, 0x7A2: 0xFFFFFFFF, 0x7A5: 0x88}.get(state["address"], 0)
        matches = []
        for item in self.state:
            privilege = item["u"] if state["core_user"] else item["m"]
            native_enable = state["core_user"] or item["action"] or self.mte
            matches.append(bool(state["core_valid"] and not state["core_debug"] and item["execute"] and
                                privilege and native_enable and state["core_pc"] == item["address"]))
        debug_action = bool(state["core_ready"] and any(match and item["action"]
                            for match, item in zip(matches, self.state, strict=True)))
        native_action = bool(state["core_ready"] and any(matches) and not debug_action)
        write = state["commit"] and state["writeRequested"] and implemented
        operand = state["operand"]
        if state["operation"] == 2:
            operand |= read
        elif state["operation"] == 3:
            operand = read & ~operand
        item = self.state[self.selected]
        enabled = write and not (item["dmode"] and not state["debugAccess"])
        written = read
        if write and state["address"] == 0x7A0:
            written = operand & 1
        if write and state["address"] == 0x7A5:
            written = operand & 0x88
        if enabled and state["address"] == 0x7A1:
            next_dmode = operand >> 27 & 1 if state["debugAccess"] else item["dmode"]
            action = int(bool(next_dmode and operand >> 12 & 15 == 1))
            written = (0x20000000 | next_dmode << 27 | (operand >> 20 & 1) << 20 | action << 12 |
                       (operand >> 6 & 1) << 6 | (operand >> 3 & 1) << 3 | (operand >> 2 & 1) << 2)
        if enabled and state["address"] == 0x7A2:
            written = operand & 0xFFFFFFFF
        result = (cycle, int(implemented), read, mask, written, int(any(matches)), int(debug_action), int(native_action))
        if state["reset"]:
            counts = self.counts
            self.__init__()
            self.counts = counts
            return result
        if write and state["address"] == 0x7A0:
            self.selected = operand & 1
        if write and state["address"] == 0x7A5:
            self.mte, self.mpte = operand >> 3 & 1, operand >> 7 & 1
        if enabled and state["address"] == 0x7A1:
            next_dmode = operand >> 27 & 1 if state["debugAccess"] else item["dmode"]
            item.update(hit=operand >> 20 & 1, action=int(bool(next_dmode and operand >> 12 & 15 == 1)),
                        m=operand >> 6 & 1, u=operand >> 3 & 1, execute=operand >> 2 & 1,
                        dmode=next_dmode)
        if enabled and state["address"] == 0x7A2:
            item["address"] = operand & 0xFFFFFFFF
        if state["core_ready"]:
            for index, matched in enumerate(matches):
                if matched:
                    self.state[index]["hit"] = 1
                    self.counts["hit" + str(index)] += 1
        self.counts["debugAction"] += debug_action
        self.counts["nativeAction"] += native_action
        if state["core_mret"]:
            self.mte = self.mpte
            self.counts["mret"] += 1
        if state["core_trap"]:
            self.mpte, self.mte = self.mte, 0
            self.counts["trap"] += 1
        return result


def vectors():
    rows = [row(reset=1), row(reset=1)]
    for name in (*CSR,):
        rows.append(access(name))
    rows.append(row(address=0x7A6))
    for name in ("tinfo", "tdata3", "mcontext", "scontext"):
        rows += [access(name, 0xFFFFFFFF), access(name)]
    rows += [access("tdata1", 0xFFFFFFFF, debug=False), access("tdata1")]
    rows += [access("tdata1", 0x00001044), access("tdata1")]
    rows += [access("tdata1", 0x2800104C), access("tdata2", 0x40), access("tdata1"), access("tdata2")]
    rows += [access("tdata1", 0, debug=False), access("tdata2", 0x44, debug=False), access("tdata1"), access("tdata2")]
    rows += [row(core_pc=0x44, core_valid=1),
             row(core_pc=0x40, core_valid=1, core_ready=0), access("tdata1"),
             row(core_pc=0x40, core_valid=1), row(core_valid=0), access("tdata1")]
    rows += [access("tselect", 1), access("tdata1"), access("tselect", 2), access("tselect"),
             access("tselect", 3), access("tselect")]
    rows += [access("tdata2", 0x40), access("tdata1", 0x20000044), access("tcontrol", 8)]
    rows += [row(core_pc=0x40, core_valid=1), row(core_valid=0), access("tdata1"),
             access("tselect", 0), access("tdata1")]
    rows += [access("tdata1", 0x28000040), access("tselect", 1),
             row(core_pc=0x40, core_valid=1), row(core_valid=0, core_trap=1),
             row(core_pc=0x40, core_valid=1), row(core_valid=0, core_mret=1),
             row(core_pc=0x40, core_valid=1)]
    rows += [access("tdata2", 0x44), access("tdata1", 0x2000000C), row(core_valid=0, core_trap=1),
             row(core_pc=0x44, core_valid=1), row(core_pc=0x44, core_valid=1, core_user=1),
             row(core_valid=0, core_debug=1, core_pc=0x44, core_user=1)]
    randomizer = random.Random(0xE2)
    addresses = [*CSR.values(), 0x7A6, 0x341]
    for _ in range(300):
        address = randomizer.choice(addresses)
        values = {"address": address, "debugAccess": randomizer.randrange(2),
                  "core_pc": randomizer.choice((0, 0x40, 0x44, 0x48)),
                  "core_valid": randomizer.randrange(2), "core_user": randomizer.randrange(2),
                  "core_ready": randomizer.randrange(2), "core_trap": randomizer.randrange(16) == 0,
                  "core_mret": randomizer.randrange(16) == 0}
        if randomizer.randrange(3) == 0:
            values.update(writeRequested=1, commit=1, operand=randomizer.getrandbits(32),
                          operation=randomizer.choice((1, 1, 1, 2, 3)))
        rows.append(row(**values))
    return rows


def simulate(rtl, rows, output):
    output.mkdir(parents=True)
    (output / "vectors.txt").write_text("".join(f"{values[0]} {values[1]:x} {values[2]:x} " +
        " ".join(str(value) for value in values[3:6]) + f" {values[6]} {values[7]:x} " +
        " ".join(str(value) for value in values[8:]) + "\n" for values in rows))
    (output / "trigger_tb.sv").write_text(HARNESS)
    shutil.copyfile(rtl, output / "DitDahE2Trigger.sv")
    commands = (["iverilog", "-g2012", "-s", "TriggerBench", "-o", "trigger-sim",
                 "DitDahE2Trigger.sv", "trigger_tb.sv"], ["vvp", "trigger-sim"])
    for command in commands:
        result = subprocess.run(command, check=False, cwd=output, capture_output=True, text=True)
        (output / (command[0] + ".log")).write_text(result.stdout + result.stderr)
        if result.returncode:
            raise RuntimeError("Trigger simulation command failed: " + command[0])
    trace = "\n".join(line for line in result.stdout.splitlines() if line and line[0].isdigit()) + "\n"
    (output / "trigger.trace").write_text(trace)
    return trace


def check(rows, trace):
    reference = Reference()
    expected = [reference.step(values, cycle) for cycle, values in enumerate(rows)]
    observed = [tuple(int(value, 16 if index in (2, 3, 4) else 10) for index, value in enumerate(line.split()))
                for line in trace.splitlines()]
    if len(expected) != len(observed):
        raise AssertionError("Trigger trace length differs")
    for wanted, actual in zip(expected, observed, strict=True):
        if wanted != actual:
            raise AssertionError(f"Trigger mismatch at cycle {wanted[0]}: expected {wanted[1:]}, got {actual[1:]}")
    return reference.counts


def mutate(text, name):
    if name == "hit":
        pattern = r"hit <= core_ready & _GEN_\d+ \| \((_GEN_\d+) \? writeData\[20\] : hit\);"
        changed, count = re.subn(pattern, r"hit <= \1 ? writeData[20] : hit;", text)
        if count != 1:
            raise ValueError("Trigger mutation target changed: " + name)
        return changed
    if name == "priority":
        target = "assign core_nativeAction = core_ready & core_matched_0 & ~core_debugAction_0;"
        replacement = "assign core_nativeAction = core_ready & core_matched_0;"
    elif name == "address":
        target = "& (core_user | debugAction | mte) & core_pc == address_0;"
        replacement = "& (core_user | debugAction | mte) & 1'b1;"
    else:
        raise ValueError("Unknown trigger mutation")
    if text.count(target) != 1:
        raise ValueError("Trigger mutation target changed: " + name)
    return text.replace(target, replacement)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rtl", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    manifest = json.loads((args.rtl / "manifest.json").read_text())
    assert manifest["top"] == "DitDahE2Trigger" and manifest["parameters"]["triggerCount"] == 2
    assert manifest["parameters"] == configuration(manifest["parameters"])
    assert manifest["sourceHashes"] == sources(), "Stale trigger RTL"
    assert all(digest(args.rtl / name) == value for name, value in manifest["rtlHashes"].items())
    args.output.mkdir(parents=True, exist_ok=False)
    rows = vectors()
    rtl = args.rtl / "DitDahE2Trigger.sv"
    trace = simulate(rtl, rows, args.output / "normal")
    counts = check(rows, trace)
    assert all(counts[name] for name in ("hit0", "hit1", "debugAction", "nativeAction", "trap", "mret"))
    negatives = []
    for name in ("priority", "hit", "address"):
        changed = args.output / (name + ".sv")
        changed.write_text(mutate(rtl.read_text(), name))
        try:
            check(rows, simulate(changed, rows, args.output / name))
        except AssertionError as error:
            negatives.append({"name": name, "rejected": str(error), "rtlHash": digest(changed)})
        else:
            raise AssertionError("Trigger mutant passed: " + name)
    report = {"exitStatus": 0, "scope": "standalone two-entry execute-trigger CSR and match arbitration",
              "cycles": len(rows), "coverage": counts, "command": "python3 test/test_trigger/trigger.py",
              "rtlHashes": manifest["rtlHashes"], "sourceHashes": manifest["sourceHashes"],
              "traceHash": digest(args.output / "normal/trigger.trace"), "negativeControls": negatives,
              "excluded": ["core pipeline integration", "commercial proof"]}
    (args.output / "summary.json").write_text(json.dumps(report, indent=2, default=dict) + "\n")
    print(f"PASS: {len(rows)} trigger cycles and {len(negatives)} RTL negative controls")


if __name__ == "__main__":
    main()
