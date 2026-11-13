# SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
# SPDX-License-Identifier: MIT
"""Check SBA through real DMI response backpressure and independent hart traffic."""

import argparse
import hashlib
import json
import re
import shutil
import subprocess
from collections import Counter
from pathlib import Path

from test.test_debug.debug_module import HARNESS as DM_HARNESS
from test.test_sba.reference import (
    READ,
    SBADDRESS,
    SBCS,
    SBDATA,
    WRITE,
    ByteMemory,
    SbaModel,
)
from test.test_sba.verify_sba import control
from test.test_sba.verify_sba import step as sba_step

FIELDS = ("reset", "valid", "ready", "address", "operation", "value", "halted", "running", "unavailable",
          "reset_pending", "hart_ready", "hart_valid", "hart_data", "hart_error", "bus_ready", "bus_valid", "bus_data", "bus_fault", "reset_event")
HEX_INPUT = (3, 5, 12, 16)
HEX_OUTPUT = (3, 8, 11, 12, 18)


def harness():
    declarations = DM_HARNESS[:DM_HARNESS.index("  integer file")].replace("module DebugBench;", "module SbaDmBench;")
    return declarations + r"""
  wire systemBus_request_valid, systemBus_response_ready;
  wire [31:0] systemBus_request_bits_address, systemBus_request_bits_data;
  wire systemBus_request_bits_machine, systemBus_request_bits_write;
  wire [3:0] systemBus_request_bits_mask, systemBus_request_bits_operation;
  wire [1:0] systemBus_request_bits_size;
  reg systemBus_request_ready = 0, systemBus_response_valid = 0;
  reg [31:0] systemBus_response_bits_data = 0;
  reg systemBus_response_bits_fault = 0;
  DitDahE2DebugModule dut(.*);
  integer file, fields, sample = 0;
  initial begin
    #1 clock = 1; #1 clock = 0;
    file = $fopen("vectors.txt", "r");
    if (!file) $fatal(1, "Cannot open DM SBA vectors");
    while (!$feof(file)) begin
      fields = $fscanf(file, "%d %d %d %h %d %h %d %d %d %d %d %d %h %d %d %d %h %d %d\n",
        reset, dmi_request_valid, dmi_response_ready, dmi_request_bits_address,
        dmi_request_bits_op, dmi_request_bits_data, hart_status_halted,
        hart_status_running, hart_status_unavailable, hart_status_resetPending,
        hart_request_ready, hart_response_valid, hart_response_bits_data,
        hart_response_bits_error, systemBus_request_ready, systemBus_response_valid,
        systemBus_response_bits_data, systemBus_response_bits_fault, hart_status_resetEvent);
      if (fields == 19) begin
        #1 $display("%0d %0d %0d %08h %0d %0d %0d %0d %08h %0d %0d %08h %0h %0d %0d %0d %0d %0d %04h %0d %0d %0d",
          sample, dmi_request_ready, dmi_response_valid,
          dmi_response_valid ? dmi_response_bits_data : 0,
          dmi_response_valid ? dmi_response_bits_status : 0,
          hart_request_valid, hart_control_reset, systemBus_request_valid,
          systemBus_request_valid ? systemBus_request_bits_address : 0,
          systemBus_request_valid ? systemBus_request_bits_machine : 0,
          systemBus_request_valid ? systemBus_request_bits_write : 0,
          systemBus_request_valid ? systemBus_request_bits_data : 0,
          systemBus_request_valid ? systemBus_request_bits_mask : 0,
          systemBus_request_valid ? systemBus_request_bits_size : 0,
          systemBus_request_valid ? systemBus_request_bits_operation : 0,
          systemBus_response_ready, hart_response_ready, hart_control_active,
          hart_request_valid ? hart_request_bits_register : 0,
          hart_request_valid ? hart_request_bits_write : 0,
          hart_request_valid ? hart_request_bits_transfer : 0,
          hart_request_valid ? hart_request_bits_postExec : 0);
        clock = 1; #1 clock = 0; sample = sample + 1;
      end else if (fields != -1) $fatal(1, "Incomplete DM SBA vector");
    end
    $fclose(file); $finish(0);
  end
endmodule
"""


class Reference:
    def __init__(self):
        self.sba = SbaModel()
        self.active = self.activation_pending = self.ndmreset = False
        self.reset_waiting = self.have_reset = False
        self.response = None
        self.abstract = self.abstract_issued = False
        self.data = 0
        self.counts = Counter()

    def step(self, values, cycle):
        state = dict(zip(FIELDS, values, strict=True))
        ready = self.response is None
        accepted = bool(state["valid"] and ready)
        deactivate = accepted and state["address"] == 0x10 and state["operation"] == WRITE and not state["value"] & 1
        child_active = self.active and not deactivate
        child_accept = accepted and self.active and not self.ndmreset and not self.reset_waiting and not state["reset_pending"]
        bus_idle = self.sba.idle
        reset_delivery = self.active and bus_idle and (self.ndmreset or self.reset_waiting)
        child_row = (state["reset"], int(child_active), int(child_accept), state["address"], state["operation"], state["value"],
                     state["bus_ready"], state["bus_valid"], state["bus_data"], state["bus_fault"])
        child, child_masks = sba_step(self.sba, child_row, cycle)
        hart_offer = self.active and self.abstract and not self.abstract_issued
        expected = (cycle, int(ready), int(self.response is not None), *(self.response or (0, 0)), int(hart_offer),
                    int(reset_delivery), *child[3:12], 1, int(self.active),
                    0x1001 if hart_offer else 0, int(hart_offer), int(hart_offer), 0)
        masks = [0xFFFFFFFF] * len(expected)
        masks[11] = child_masks[7]
        if state["reset"]:
            self.active = self.activation_pending = self.ndmreset = False
            self.reset_waiting = self.have_reset = False
            self.abstract = self.abstract_issued = False
            self.response, self.data = None, 0
            return expected, masks
        old_abstract_issued = self.abstract_issued
        old_active = self.active
        old_reset_waiting = self.reset_waiting
        if reset_delivery:
            self.reset_waiting = False
            self.counts["resetDeliveryCycles"] += 1
        if state["valid"] and not ready:
            self.counts["requestBackpressure"] += 1
        if self.response is not None and state["ready"]:
            self.response = None
            self.counts["responses"] += 1
        elif self.response is not None:
            self.counts["responseBackpressure"] += 1
        if self.activation_pending and bus_idle:
            self.active, self.activation_pending = True, False
        if accepted:
            value = 0
            if state["operation"] == READ:
                if state["address"] == 0x10:
                    value = int(old_active) | int(self.ndmreset) << 1
                elif state["address"] == 0x11 and old_active:
                    value = 0x4000A3 | (int(bool(state["halted"] and not state["unavailable"])) * 0x300)
                    value |= int(bool(state["running"] and not state["unavailable"])) * 0xC00
                    value |= int(bool(state["unavailable"])) * 0x3000 | int(self.have_reset) * 0xC0000
                    value |= int(self.ndmreset or old_reset_waiting or state["reset_pending"]) << 24
                elif state["address"] in (SBCS, SBADDRESS, SBDATA):
                    value = child[1]
                    if state["address"] == SBDATA:
                        masks[3] = child_masks[1]
                elif state["address"] == 0x16 and old_active:
                    value = 0x02000002 | int(self.abstract) << 12
                elif state["address"] == 4 and old_active:
                    value = self.data
            self.response = (value, 0)
            self.counts["requests"] += 1
            if state["operation"] == WRITE and state["address"] == 0x10:
                if not state["value"] & 1:
                    self.active = self.activation_pending = self.ndmreset = False
                    self.reset_waiting = self.have_reset = False
                    self.data = 0
                    self.counts["deactivations"] += 1
                elif not old_active:
                    self.active = bus_idle
                    self.activation_pending = not bus_idle
                    self.counts["queuedActivations"] += int(not bus_idle)
                else:
                    self.ndmreset = bool(state["value"] & 2)
                    if self.ndmreset:
                        self.reset_waiting = True
            elif state["operation"] == WRITE and old_active:
                if state["address"] == 4:
                    self.data = state["value"]
                elif state["address"] == 0x17:
                    if state["value"] != 0x00231001 or not state["halted"] or self.abstract:
                        raise AssertionError("Unexpected abstract-command stimulus")
                    self.abstract, self.abstract_issued = True, False
        if hart_offer and state["hart_ready"]:
            self.abstract_issued = True
            self.counts["hartRequests"] += 1
        if old_abstract_issued and state["hart_valid"]:
            self.abstract = self.abstract_issued = False
            self.counts["hartResults"] += 1
        if self.active and state["reset_event"]:
            self.have_reset = True
            self.counts["resetEvents"] += 1
        if self.ndmreset and not bus_idle:
            self.counts["resetDeferredForBus"] += 1
        return expected, masks


class Driver:
    def __init__(self):
        self.reference, self.memory, self.rows = Reference(), ByteMemory(), []
        self.bus = self.hart = None
        self.bus_delay, self.hart_delay = 9, 90
        self.bus_block = False
        self.reset_ack = False
        self.reset_age = 0
        self.status = {"halted": 1, "running": 0, "unavailable": 0, "reset_pending": 0}
        self.tick(reset=1)
        self.tick()

    def tick(self, **changes):
        cycle = len(self.rows)
        state = dict.fromkeys(FIELDS, 0)
        state.update(self.status)
        if self.reset_ack:
            state["reset_pending"] = 1
            state["reset_event"] = int(self.reset_age >= 2 and not self.reference.ndmreset)
        state.update(ready=1, bus_ready=int(not self.bus_block and cycle % 4 != 0), hart_ready=1)
        if self.bus and cycle >= self.bus["due"]:
            state.update(bus_valid=1, bus_data=self.bus["data"])
        if self.hart and cycle >= self.hart:
            state.update(hart_valid=1)
        state.update(changes)
        if state.keys() - set(FIELDS):
            raise ValueError("Unknown DM SBA vector field")
        model = self.reference.sba
        finish = model.pending is not None and model.pending.accepted and state["bus_valid"]
        if model.offered and state["bus_ready"]:
            self.bus = {"due": cycle + self.bus_delay, "data": self.memory.response(model.pending.transfer)}
        if self.reference.abstract and not self.reference.abstract_issued and state["hart_ready"]:
            self.hart = cycle + self.hart_delay
        values = tuple(state[name] for name in FIELDS)
        expected = self.reference.step(values, cycle)
        # The synchronous hart captures an asserted reset on this edge. Its
        # registered pending status appears on the next sample, never combinationally.
        if expected[0][6] and not self.reset_ack:
            self.reset_ack, self.reset_age = True, 0
        elif self.reset_ack:
            self.reset_age += 1
        if state["reset_event"]:
            self.reset_ack = False
        if finish:
            self.bus = None
        if state["hart_valid"]:
            self.hart = None
        self.rows.append(values)
        return expected

    def dmi(self, address, operation=READ, value=0, stall=0):
        if self.reference.response is not None:
            raise AssertionError("Driver started DMI before the previous response")
        self.tick(valid=1, ready=0, address=address, operation=operation, value=value)
        for _ in range(stall):
            self.tick(ready=0)
        self.tick()

    def drain(self):
        for _ in range(512):
            if (self.reference.sba.idle and not self.reference.abstract and
                    not self.reference.activation_pending and not self.reference.reset_waiting):
                return
            self.tick()
        raise AssertionError("DM SBA transaction failed to drain")

    def pipeline(self, first, second, stall):
        self.tick(valid=1, ready=0, address=first[0], operation=first[1], value=first[2])
        for _ in range(stall):
            self.tick(valid=1, ready=0, address=second[0], operation=second[1], value=second[2])
        self.tick(valid=1, ready=1, address=second[0], operation=second[1], value=second[2])
        self.tick(valid=1, ready=0, address=second[0], operation=second[1], value=second[2])
        self.tick()


def vectors():
    driver = Driver()
    driver.dmi(0x10, WRITE, 1)
    for status in ((1, 0, 0), (0, 1, 0), (0, 0, 1)):
        driver.status.update(zip(("halted", "running", "unavailable"), status, strict=True))
        driver.dmi(SBCS, WRITE, control(read_address=True, increment=True))
        driver.dmi(SBADDRESS, WRITE, 0x100, stall=6)
        driver.drain()
        driver.dmi(SBDATA, stall=5)
        driver.dmi(SBADDRESS)
    driver.status.update(halted=1, running=0, unavailable=0)
    driver.dmi(SBCS, WRITE, control())
    driver.dmi(SBADDRESS, WRITE, 0x180)
    driver.pipeline((SBCS, READ, 0), (SBDATA, WRITE, 0xA8765432), stall=6)
    driver.drain()
    # Abstract access and SBA proceed on distinct ports and owners.
    driver.dmi(4, WRITE, 0x2468ACE0)
    driver.dmi(0x17, WRITE, 0x00231001)
    driver.dmi(0x16)
    driver.dmi(SBCS, WRITE, control())
    driver.dmi(SBADDRESS, WRITE, 0x200)
    driver.dmi(SBDATA, WRITE, 0xA55A1234, stall=4)
    driver.drain()
    driver.dmi(0x16)
    # Repeated response cycles must not repeat read-on-data transactions.
    driver.dmi(SBCS, WRITE, control(read_address=True, read_data=True, increment=True))
    driver.dmi(SBADDRESS, WRITE, 0x300)
    driver.drain()
    driver.dmi(SBDATA, stall=12)
    driver.drain()
    driver.dmi(SBCS, WRITE, control())
    # NDM reset waits for old physical ownership and blocks new SBA side effects.
    driver.bus_delay = 24
    driver.dmi(SBADDRESS, WRITE, 0x400)
    driver.dmi(SBDATA, WRITE, 0x01234567)
    driver.dmi(0x10, WRITE, 3)
    driver.dmi(SBADDRESS, WRITE, 0x404)
    driver.drain()
    driver.dmi(SBADDRESS)
    driver.dmi(0x10, WRITE, 1)
    driver.status["reset_pending"] = 1
    driver.dmi(SBDATA, WRITE, 0xDEADBEEF)
    driver.status["reset_pending"] = 0
    driver.dmi(SBADDRESS)
    # A legal short reset pulse is queued across a long SBA transfer. Clearing
    # its DMI level does not cancel delivery or allow another SBA operation.
    driver.bus_delay = 40
    driver.dmi(SBCS, WRITE, control(read_address=True))
    driver.dmi(SBADDRESS, WRITE, 0x480)
    driver.dmi(0x10, WRITE, 3)
    driver.dmi(0x10, WRITE, 1)
    driver.dmi(0x11)
    driver.dmi(SBADDRESS, WRITE, 0x484)
    driver.dmi(SBDATA, WRITE, 0x55AA55AA)
    driver.drain()
    driver.dmi(0x11)
    while driver.reset_ack:
        driver.tick()
    driver.dmi(0x11)
    driver.dmi(SBADDRESS)
    # An off/on epoch cannot expose the old response or start early.
    for blocked in (True, False):
        driver.bus_delay = 30
        driver.bus_block = blocked
        driver.dmi(SBCS, WRITE, control(read_address=True, increment=True))
        driver.dmi(SBADDRESS, WRITE, 0x500)
        driver.dmi(0x10, WRITE, 0, stall=3)
        driver.dmi(0x10, WRITE, 1)
        driver.dmi(0x10)
        driver.bus_block = False
        driver.drain()
        driver.dmi(0x10)
        driver.dmi(SBDATA)
        driver.dmi(SBADDRESS)
        driver.dmi(SBCS)
    return driver.rows


def check(rows, text):
    samples = [line.split() for line in text.splitlines() if line and line[0].isdigit()]
    if len(samples) != len(rows) or any(len(sample) != 22 for sample in samples):
        raise AssertionError("DM SBA trace dimensions differ")
    reference = Reference()
    for cycle, (values, fields) in enumerate(zip(rows, samples, strict=True)):
        actual = tuple(int(value, 16 if index in HEX_OUTPUT else 10) for index, value in enumerate(fields))
        wanted, masks = reference.step(values, cycle)
        if actual != wanted and any((a & m) != (b & m) for a, b, m in zip(actual, wanted, masks, strict=True)):
            raise AssertionError(f"DM SBA mismatch at cycle {cycle}: {actual} != {wanted}")
    if reference.response is not None or reference.sba.busy or reference.abstract:
        raise AssertionError("DM SBA owners did not drain")
    return {"dmi": dict(reference.counts), "sba": dict(reference.sba.counts)}


def mutate(rtl, name):
    if name == "unaccepted-dmi-effect":
        pattern = r"(\.accepted\s*\()accepted\b"
        changed, count = re.subn(pattern, r"\g<1>dmi_request_valid", rtl)
    elif name == "reset-before-bus-drain":
        pattern = r"(assign\s+hart_control_reset\s*=)([^;]+);"
        matches = list(re.finditer(pattern, rtl))
        if len(matches) != 1:
            raise ValueError("Reset control assignment is not unique")
        match = matches[0]
        expression = match[2].strip()
        if re.fullmatch(r"[A-Za-z_]\w*", expression):
            aliases = list(re.finditer(r"(wire\s+" + re.escape(expression) + r"\s*=)([^;]+);", rtl))
            if len(aliases) != 1:
                raise ValueError("Reset control wire alias is not unique")
            match = aliases[0]
        expression, count = re.subn(r"\b_bus_idle\b", "1'h1", match[2])
        if count != 1:
            raise ValueError("Reset drain ownership expression changed")
        changed = rtl[:match.start()] + match[1] + expression + ";" + rtl[match.end():]
    else:
        raise ValueError("Unknown DM SBA mutation")
    if count != 1 or changed == rtl:
        raise ValueError("DM SBA mutation target differs: " + name)
    return changed


def simulate_mutant(work, files, rows, name):
    work.mkdir()
    for path in files:
        content = path.read_text()
        if path.name == "DitDahE2DebugModule.sv":
            content = mutate(content, name)
        (work / path.name).write_text(content)
    (work / "vectors.txt").write_text("".join(" ".join(f"{value:x}" if index in HEX_INPUT else str(value)
                                                    for index, value in enumerate(row)) + "\n" for row in rows))
    (work / "dm_sba_tb.sv").write_text(harness())
    commands = []
    for argv in (("iverilog", "-g2012", "-s", "SbaDmBench", "-o", "dm-sba-sim", *[p.name for p in files], "dm_sba_tb.sv"),
                 ("vvp", "dm-sba-sim")):
        result = subprocess.run(argv, cwd=work, text=True, capture_output=True, check=False)
        commands.append({"argv": list(argv), "exitStatus": result.returncode})
        (work / ("compile.log" if argv[0] == "iverilog" else "simulation.log")).write_text(result.stdout + result.stderr)
        if result.returncode:
            raise RuntimeError("DM SBA RTL negative did not execute: " + name)
    (work / "commands.json").write_text(json.dumps(commands, indent=2) + "\n")
    return result.stdout


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rtl", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists():
        parser.error("Output directory must not exist")
    args.output.mkdir(parents=True)
    files = sorted(args.rtl.glob("*.sv"))
    if not files:
        raise ValueError("No generated DM RTL inputs")
    digest = lambda path: hashlib.sha256(path.read_bytes()).hexdigest()
    frozen = {p.name: digest(p) for p in files}
    for path in files:
        shutil.copyfile(path, args.output / path.name)
    rows = vectors()
    (args.output / "vectors.txt").write_text("".join(" ".join(f"{value:x}" if index in HEX_INPUT else str(value)
                                                      for index, value in enumerate(row)) + "\n" for row in rows))
    (args.output / "dm_sba_tb.sv").write_text(harness())
    commands = []
    for argv in (("iverilog", "-g2012", "-s", "SbaDmBench", "-o", "dm-sba-sim", *[p.name for p in files], "dm_sba_tb.sv"), ("vvp", "dm-sba-sim")):
        result = subprocess.run(argv, cwd=args.output, text=True, capture_output=True, check=False)
        commands.append({"argv": list(argv), "exitStatus": result.returncode})
        (args.output / ("compile.log" if argv[0] == "iverilog" else "simulation.log")).write_text(result.stdout + result.stderr)
        if result.returncode:
            raise RuntimeError("DM SBA simulation failed: " + argv[0])
    counts = check(rows, result.stdout)
    for key in ("requestBackpressure", "responseBackpressure", "queuedActivations", "resetDeferredForBus",
                "resetDeliveryCycles", "resetEvents", "hartRequests", "hartResults"):
        if not counts["dmi"].get(key):
            raise AssertionError("DM SBA coverage is empty: " + key)
    if frozen != {p.name: digest(p) for p in files}:
        raise AssertionError("DM SBA RTL inputs changed")
    controls = []
    for name in ("unaccepted-dmi-effect", "reset-before-bus-drain"):
        work = args.output / name
        trace = simulate_mutant(work, files, rows, name)
        try:
            check(rows, trace)
        except AssertionError as error:
            reason = str(error)
        else:
            raise AssertionError("DM SBA RTL mutation was accepted: " + name)
        controls.append({"mutation": name, "rejected": True, "reason": reason,
                         "rtlSha256": digest(work / "DitDahE2DebugModule.sv"), "traceSha256": digest(work / "simulation.log")})
    report = {"exitStatus": 0, "scope": "DM SBA with synthetic independent hart, DMI backpressure and reset/epoch ownership",
              "cycles": len(rows), "counts": counts, "commands": commands, "rtlHashes": frozen,
              "vectorsSha256": digest(args.output / "vectors.txt"), "traceSha256": digest(args.output / "simulation.log"),
              "negativeControls": controls, "excluded": ["core retirement", "platform arbitration", "real host", "commercial proof"]}
    (args.output / "summary.json").write_text(json.dumps(report, indent=2) + "\n")
    print(f"PASS: {len(rows)} integrated DM SBA cycles and {len(controls)} RTL negative controls")


if __name__ == "__main__":
    main()
