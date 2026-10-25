# SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
# SPDX-License-Identifier: MIT
"""Check processor retirement and abstract commands through synchronous DMI."""

import argparse
from collections import Counter, deque
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys

from debug_programs import cases, WAIT_RETIRE, READ, WRITE, POLL, IDLE, FINISH
from model import Model, MASK

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from build_rtl import digest, sources


class DebugReference:
    def __init__(self, model):
        self.model = model
        self.active = self.halted = self.resume_ack = False
        self.data = [0, 0]
        self.pending = None
        self.dpc = 0
        self.control = 3
        self.cause = 3
        self.halts = self.resumes = self.steps = 0
        self.step_start = None
        self.register_reads = Counter()
        self.register_writes = Counter()

    def register(self, number, value=None):
        if number == 0x7B1:
            if value is not None:
                self.dpc = value & ~1
            return self.dpc
        if number == 0x7B0:
            if value is not None:
                self.control = (value & 0x9004) | (3 if value & 3 else 0)
            return 0x40000410 | self.control | (self.cause << 6)
        if 0x1000 <= number <= 0x101F:
            index = number - 0x1000
            if value is not None and index:
                self.model.registers[index] = value
            return self.model.registers[index]
        assert number in self.model.csrs or self.model.pmp.read(number)[0], "Unsupported abstract register"
        assert number not in (0xB00, 0xB80, 0xC00, 0xC80), "Cycle reads require a halt interval check"
        if value is not None:
            self.model.write_csr(number, value)
        return self.model.read_csr(number)

    def request(self, address, op, value, retirements):
        assert op in (1, 2), "Invalid DMI operation"
        if op == 1:
            return
        if address == 0x10:
            assert value & 1, "DM deactivation is outside this workload"
            if not self.active:
                self.active = True
                return
            if value & (1 << 30):
                assert self.halted and self.pending is None, "Resume without a completed halt"
                self.model.pc = self.dpc
                self.model.user_mode = self.control & 3 == 0
                if self.model.user_mode:
                    self.model.csrs[0x300] &= ~(1 << 17)
                self.halted = False
                self.resume_ack = False
                self.resumes += 1
                self.step_start = retirements if self.control & 4 else None
            assert not value & 2, "System reset is outside this workload"
        elif address in (4, 5):
            assert self.pending is None, "Data write while an abstract command is busy"
            self.data[address - 4] = value
        elif address == 0x17:
            assert self.halted and self.pending is None, "Abstract command without an idle halted hart"
            assert value >> 24 == 0 and value >> 20 & 7 == 2 and value & (1 << 17), "Unsupported abstract command"
            assert not value & ((1 << 18) | (1 << 19)), "Unsupported abstract execution"
            self.pending = (value & 0xFFFF, bool(value & (1 << 16)), self.data[0])
        else:
            raise AssertionError("Unexpected DMI write")

    def response(self, address, op, value, status, data, snapshot):
        assert status == 0, "DMI transport failed"
        if op == 2:
            return
        if address == 0x11:
            assert data & 0xFF == 0xA3, "Unexpected debug module version or authentication"
            halted, running = data >> 8 & 3, data >> 10 & 3
            assert halted in (0, 3) and running in (0, 3) and halted != running, "Inconsistent single hart status"
            assert data >> 12 & 15 == 0, "Hart is unavailable or absent"
            if halted:
                assert not snapshot["outstanding"] and not snapshot["completed"], "Halt crossed unfinished memory"
                if not self.halted:
                    self.halts += 1
                    self.dpc = snapshot["pc"]
                    self.control = (self.control & ~3) | (0 if snapshot["user"] else 3)
                    self.cause = 3
                    if self.step_start is not None:
                        assert snapshot["retirements"] - self.step_start == 1, "Single step retired an incorrect instruction count"
                        self.steps += 1
                        self.cause = 4
                        self.step_start = None
                self.halted = True
            self.resume_ack = data >> 16 & 3 == 3
        elif address == 0x16:
            assert data & 15 == 2 and data >> 24 & 31 == 0, "Unexpected abstract command capabilities"
            assert data >> 8 & 7 == 0, "Abstract command failed"
            if not data & (1 << 12) and self.pending is not None:
                number, write, value = self.pending
                result = self.register(number, value if write else None)
                (self.register_writes if write else self.register_reads)[number] += 1
                if not write:
                    self.data[0] = result
                self.pending = None
        elif address in (4, 5):
            assert self.pending is None, "Abstract result read before completion"
            assert data == self.data[address - 4], "Abstract register result mismatch"
        else:
            raise AssertionError("Unexpected DMI read")


def check(case, trace):
    model = Model(case.image, enable_m=True, enable_c=True, protected_mode=True)
    debug = DebugReference(model)
    physical = dict(case.image)
    offered, outstanding = {}, {}
    completed = deque()
    dmi = None
    cycle, events, sequence, action_index = -1, 0, 0, 0
    action_eligible = False
    action_start = 0
    final = None
    words = {}
    coverage = Counter()
    for line in trace.splitlines():
        fields = line.split()
        kind = fields[0]
        assert final is None or kind == "W", "Event after final metrics"
        if kind == "T":
            now, time, reset = map(int, fields[1:])
            assert now == cycle + 1 and time == now, "Invalid input clock"
            assert not reset, "Unexpected system reset"
            model.clock(now)
            model.time = time
            cycle = now
            continue
        if kind not in ("F", "W"):
            assert int(fields[1]) == cycle, "Event lacks input clock"
        if kind == "P":
            port, request = fields[2], tuple(map(int, fields[3:]))
            assert port in ("I", "D") and port not in offered and len(request) == 6, "Invalid first offer"
            address, write, data, mask, size, machine = request
            assert size <= 2 and address % (1 << size) == 0, "Invalid memory size or alignment"
            effective_user = model.user_mode if port == "I" else model.user_mode or bool(model.csrs[0x300] & (1 << 17) and model.csrs[0x300] & 0x1800 == 0)
            assert machine == int(not effective_user), "Native privilege differs"
            assert model.pmp.allowed((address, size, machine, 2 if port == "I" else write)), "Denied native offer"
            assert mask == (((1 << (1 << size)) - 1) << (address % 4) if write else 0), "Invalid byte mask"
            assert port != "I" or (write, size) == (0, 2), "Invalid instruction request"
            offered[port] = request
        elif kind == "Q":
            port, request = fields[2], tuple(map(int, fields[3:]))
            assert port not in outstanding and offered.pop(port) == request, "Native request ownership differs"
            outstanding[port] = (cycle, request, physical.get(request[0] & ~3, 0))
            physical.setdefault(request[0] & ~3, 0)
        elif kind == "S":
            port, value, fault = fields[2], int(fields[3]), int(fields[4])
            assert port in outstanding, "Unowned native response"
            accepted, request, expected_data = outstanding.pop(port)
            assert cycle > accepted and (value, fault) == (expected_data, 0), "Native response differs"
            address, write, data, mask, size, machine = request
            if write:
                old = physical[address & ~3]
                for lane in range(4):
                    if mask >> lane & 1:
                        old = (old & ~(255 << (8 * lane))) | (data & (255 << (8 * lane)))
                physical[address & ~3] = old
            if port == "D":
                completed.append(request)
        elif kind == "R":
            assert not debug.halted, "Instruction retired during a confirmed halt"
            values = list(map(int, fields[2:]))
            expected = model.step()
            pc, word, target, rd, writes, value, trap, cause, tval, user = values
            assert (pc, word, target, bool(trap), bool(user)) == (expected.pc, expected.word, expected.next_pc, expected.trap, expected.user_mode), "Retirement identity differs"
            assert bool(writes) == bool(expected.rd) and value == expected.value and (not writes or rd == expected.rd), "Retirement register result differs"
            assert not trap or (cause, tval) == (expected.cause, expected.tval), "Trap metadata differs"
            if expected.memory:
                assert completed, "Retirement preceded memory completion"
                request = completed.popleft()
                assert request[:5] == expected.memory and request[5] == expected.memory_machine, "Retired memory request differs"
            else:
                assert not completed, "Unexpected completed data transaction"
            events += 1
            coverage[expected.instruction] += 1
            action = case.actions[action_index]
            action_eligible |= action[0] == WAIT_RETIRE and action[1] == pc
        elif kind == "J":
            seq, index, address, op, value = map(int, fields[2:])
            assert dmi is None and seq == sequence and index == action_index, "DMI ownership differs"
            action = case.actions[index]
            assert action[0] in (READ, WRITE, POLL), "DMI request lacks a script action"
            assert (address, op, value) == (action[1], 2 if action[0] == WRITE else 1, action[2] if action[0] == WRITE else 0), "DMI request differs from script"
            snapshot = {"pc": model.pc, "user": model.user_mode, "outstanding": bool(outstanding),
                        "completed": bool(completed), "retirements": events}
            debug.request(address, op, value, events)
            dmi = (seq, cycle, address, op, value, snapshot)
            sequence += 1
        elif kind == "K":
            seq, status, data = map(int, fields[2:])
            assert dmi is not None and seq == dmi[0] and cycle > dmi[1], "DMI response lacks an accepted owner"
            debug.response(*dmi[2:5], status, data, dmi[5])
            action = case.actions[action_index]
            action_eligible = action[0] != POLL or data & action[3] == action[2]
            dmi = None
        elif kind == "L":
            assert int(fields[2]) == action_index, "Script action completed out of order"
            action = case.actions[action_index]
            assert action_eligible or action[0] == IDLE and cycle - action_start >= action[2], "Script action completed before its condition"
            action_index += 1
            action_start = cycle + 1
            action_eligible = False
        elif kind == "F":
            cycles, index = map(int, fields[1:])
            assert cycles == cycle + 1 and index == action_index == len(case.actions) - 1, "Incomplete script"
            assert case.actions[index][0] == FINISH and cycles - action_start >= 8, "Missing completion window"
            assert not outstanding and not completed and dmi is None and debug.pending is None, "Unfinished transaction"
            final = {"cycles": cycles, "retirements": events, "dmiTransactions": sequence}
        elif kind == "W":
            address, value = map(int, fields[1:])
            assert address not in words, "Duplicate final memory word"
            words[address] = value
        else:
            raise AssertionError("Unknown trace record")
    assert final is not None and words == physical, "Missing or incorrect final memory"
    for address, value in case.signature.items():
        assert words[address] == value & MASK and model.word(address) == value & MASK, "Program signature differs"
    assert debug.steps == case.steps and debug.halts == debug.resumes == 1 + case.steps, "Missing halt or resume"
    assert all(debug.register_reads[0x1000 + index] for index in range(32)), "Incomplete GPR readback"
    return {**final, "halts": debug.halts, "resumes": debug.resumes, "steps": debug.steps,
            "instructions": dict(coverage), "registerReads": dict(debug.register_reads),
            "registerWrites": dict(debug.register_writes)}


def mutate_register_write(text):
    pattern = r"(assign backend_writePulse\s*=)([^;]+);"
    matches = list(re.finditer(pattern, text))
    assert len(matches) == 1, "Abstract write mutation target changed"
    return re.sub(pattern, lambda match: match[1] + " (" + match[2] + ") & (debug_request_bits_register != 16'h100A);", text)


def checker_inputs():
    names = ("test/debug_programs.py", "test/debug_sim.cpp", "test/verify_debug.py", "test/test_debug.py",
             "test/model.py", "test/programs.py", "test/compressed_model.py", "test/compressed_unit.py", "test/pmp.py",
             "scripts/build_rtl.py")
    return {name: digest(Path(name)) for name in names}


def preserve(destination, source, hashes):
    for name, expected in hashes.items():
        data = (source / name).read_bytes()
        assert hashlib.sha256(data).hexdigest() == expected, "Input changed before preservation"
        path = destination / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rtl", type=Path, default=Path("result/debug-rtl"))
    parser.add_argument("--output", type=Path, default=Path("result/debug-verification"))
    args = parser.parse_args()
    manifest_hash = digest(args.rtl / "manifest.json")
    manifest = json.loads((args.rtl / "manifest.json").read_text())
    assert manifest["parameters"] == {"resetVector": 0, "enableM": True, "enableC": True, "protectedMode": True, "enableDebug": True}, "Unsupported debug configuration"
    assert manifest["sourceHashes"] == sources(), "Stale RTL source inputs"
    assert all(digest(args.rtl / name) == value for name, value in manifest["rtlHashes"].items()), "RTL changed"
    initial = checker_inputs()
    args.output.mkdir(parents=True, exist_ok=False)
    preserve(args.output / "inputs", Path("."), initial | manifest["sourceHashes"])
    preserve(args.output / "rtl", args.rtl, manifest["rtlHashes"] | {"manifest.json": manifest_hash})
    tool = Path(shutil.which("verilator")).resolve()
    report = {"parameters": manifest["parameters"], "command": "python3 test/verify_debug.py",
              "scope": "DMI halt, GPR access, dpc, resume and single step on the processor",
              "checkerHashes": initial, "sourceHashes": manifest["sourceHashes"], "rtlHashes": manifest["rtlHashes"],
              "manifestHash": manifest_hash, "simulatorHash": digest(tool),
              "simulator": subprocess.check_output([str(tool), "--version"], text=True).strip(), "runs": [], "negativeControls": []}

    def compile_rtl(rtl, name):
        build = args.output / name
        command = [str(tool), "--cc", "--exe", "--build", "-j", "2", "--top-module", "DitDahE2",
                   "--Mdir", str(build.resolve()), "-CFLAGS", "-std=c++17",
                   *[str((rtl / file).resolve()) for file in manifest["rtlHashes"]],
                   str((args.output / "inputs/test/debug_sim.cpp").resolve())]
        result = subprocess.run(command, capture_output=True, text=True)
        (args.output / f"{name}.log").write_text(result.stdout + result.stderr)
        assert result.returncode == 0, "Debug simulator compilation failed"
        return build / "VDitDahE2"

    def execute(binary, case, seed, delay, name):
        directory = args.output / name
        directory.mkdir()
        image, script = directory / "image.hex", directory / "actions.txt"
        image.write_text("".join(f"{address:08x} {value:08x}\n" for address, value in sorted(case.image.items())))
        script.write_text("".join(" ".join(map(str, action)) + "\n" for action in case.actions))
        command = [str(binary.resolve()), str(image.resolve()), str(script.resolve()), str(seed), str(delay), "100000"]
        result = subprocess.run(command, capture_output=True, text=True)
        (directory / "trace.txt").write_text(result.stdout)
        (directory / "stderr.txt").write_text(result.stderr)
        record = {"case": case.name, "seed": seed, "delay": delay, "exitStatus": result.returncode,
                  "imageHash": digest(image), "actionsHash": digest(script), "traceHash": digest(directory / "trace.txt"),
                  "binaryHash": digest(binary)}
        assert result.returncode == 0, result.stderr
        return result.stdout, record

    try:
        binary = compile_rtl(args.output / "rtl", "build")
        for case in cases():
            for seed, delay in ((0, 0), (1, 9), (19, 24)):
                trace, record = execute(binary, case, seed, delay, f"{case.name}-s{seed}-d{delay}")
                record.update(check(case, trace))
                report["runs"].append(record)
        changed = args.output / "changed-rtl"
        shutil.copytree(args.output / "rtl", changed)
        path = changed / "DitDahE2DebugHart.sv"
        path.write_text(mutate_register_write(path.read_text()))
        binary = compile_rtl(changed, "changed-build")
        case = cases()[0]
        trace, record = execute(binary, case, 0, 0, "changed-register-write")
        try:
            check(case, trace)
        except AssertionError as error:
            assert str(error) == "Abstract register result mismatch", "Mutation failed outside the intended check"
            record.update({"rejected": str(error), "rtlHash": digest(path)})
            report["negativeControls"].append(record)
        else:
            raise AssertionError("Suppressed abstract write passed the checker")
        assert checker_inputs() == initial and sources() == manifest["sourceHashes"], "Verification inputs changed"
        assert digest(args.rtl / "manifest.json") == manifest_hash, "RTL manifest changed"
        assert all(digest(args.rtl / name) == value for name, value in manifest["rtlHashes"].items()), "RTL inputs changed"
        assert all(digest(args.output / "inputs" / name) == value for name, value in (initial | manifest["sourceHashes"]).items()), "Preserved inputs changed"
        report["exitStatus"] = 0
    except Exception as error:
        report["exitStatus"] = 1
        report["failure"] = str(error)
        raise
    finally:
        (args.output / "summary.json").write_text(json.dumps(report, indent=2) + "\n")
    print(f"PASS: {len(report['runs'])} processor debug runs, {len(report['negativeControls'])} RTL negative control")


if __name__ == "__main__":
    main()
