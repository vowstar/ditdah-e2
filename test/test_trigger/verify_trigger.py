# SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
# SPDX-License-Identifier: MIT
"""Verify precise execute triggers through the complete core and direct DMI."""

import argparse
import hashlib
import json
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
from build_rtl import configuration, sources

WAIT_RETIRE, READ, WRITE, POLL, IDLE, FINISH = range(6)
MASK = 0xFFFFFFFF
MCONTROL_M = 0x20000044
MCONTROL_U = 0x2000000C
DEBUG_M = 0x28001044
DEBUG_U = 0x2800100C


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def addi(rd, rs1, immediate):
    return (immediate & 0xFFF) << 20 | rs1 << 15 | rd << 7 | 0x13


def lui(rd, immediate):
    return immediate & 0xFFFFF000 | rd << 7 | 0x37


def load(rd, rs1, immediate=0):
    return (immediate & 0xFFF) << 20 | rs1 << 15 | 2 << 12 | rd << 7 | 3


def store(rs2, rs1=0, immediate=0):
    value = immediate & 0xFFF
    return (value >> 5) << 25 | rs2 << 20 | rs1 << 15 | 2 << 12 | (value & 31) << 7 | 0x23


def csr(kind, address, rs1, rd=0):
    return address << 20 | rs1 << 15 | kind << 12 | rd << 7 | 0x73


def multiply(rd, rs1, rs2):
    return 1 << 25 | rs2 << 20 | rs1 << 15 | rd << 7 | 0x33


def jump(offset):
    value = offset & 0x1FFFFF
    return ((value >> 20 & 1) << 31 | (value >> 1 & 0x3FF) << 21 |
            (value >> 11 & 1) << 20 | (value >> 12 & 0xFF) << 12) | 0x6F


def immediate(value):
    value &= MASK
    upper = (value + 0x800) >> 12
    lower = value - (upper << 12)
    words = []
    if upper:
        words.append(lui(1, upper << 12))
    if lower or not upper:
        words.append(addi(1, 1 if upper else 0, lower))
    return words


class Assembly:
    def __init__(self):
        self.items = []
        self.labels = {}

    @property
    def pc(self):
        return 4 * len(self.items)

    def emit(self, *words):
        self.items.extend(words)
        return self.pc - 4

    def label(self, name):
        self.labels[name] = self.pc
        return self.pc

    def addi_label(self, rd, name):
        self.items.append(("addi", rd, name))

    def jump_label(self, name):
        self.items.append(("jump", name))

    def image(self, initial=None):
        words = {}
        for index, item in enumerate(self.items):
            if isinstance(item, int):
                word = item
            elif item[0] == "addi":
                word = addi(item[1], 0, self.labels[item[2]])
            else:
                word = jump(self.labels[item[1]] - 4 * index)
            words[4 * index] = word & MASK
        if initial:
            words.update(initial)
        return words


class Actions:
    def __init__(self):
        self.rows = []
        self.expected = {}
        self.marks = {}

    def add(self, kind, address=0, value=0, mask=0):
        self.rows.append((kind, address, value & MASK, mask & MASK))
        return len(self.rows) - 1

    def mark(self, name):
        self.marks[name] = len(self.rows) - 1

    def write(self, address, value):
        return self.add(WRITE, address, value)

    def read(self, address, expected=None, mark=None):
        index = self.add(READ, address)
        if expected is not None:
            self.expected[index] = expected & MASK
        if mark:
            self.marks[mark] = index
        return index

    def poll(self, address, value, mask, mark=None):
        index = self.add(POLL, address, value, mask)
        if mark:
            self.marks[mark] = index
        return index

    def halt(self, name="halted"):
        self.write(0x10, 0x80000001)
        self.poll(0x11, 0x300, 0x300, name)

    def resume(self):
        self.write(0x10, 0x40000001)

    def register_write(self, register, value):
        self.write(4, value)
        self.write(0x17, 0x230000 | register)
        self.poll(0x16, 0, 0x1000)

    def register_read(self, register, expected=None, mark=None):
        self.write(0x17, 0x220000 | register)
        self.poll(0x16, 0, 0x1000)
        self.read(4, expected, mark)

    def trigger(self, index, address, control):
        self.register_write(0x7A0, index)
        self.register_write(0x7A2, address)
        self.register_write(0x7A1, control)

    def disable(self, index):
        self.register_write(0x7A0, index)
        self.register_write(0x7A1, 0)

    def hit(self, index, control):
        self.register_write(0x7A0, index)
        self.register_read(0x7A1, control | 1 << 20)

    def finish(self):
        self.add(FINISH)


@dataclass
class Trace:
    text: str
    actions: Actions

    def __post_init__(self):
        self.retire = []
        self.offers = []
        self.arithmetic = []
        self.words = {}
        self.responses = {}
        requests = {}
        for line in self.text.splitlines():
            fields = line.split()
            if not fields:
                continue
            kind = fields[0]
            if kind == "R":
                values = list(map(int, fields[1:]))
                self.retire.append({"cycle": values[0], "pc": values[1], "word": values[2], "nextPc": values[3],
                                    "rd": values[4], "writes": values[5], "value": values[6], "trap": values[7],
                                    "cause": values[8], "tval": values[9], "user": values[10]})
            elif kind == "P":
                values = list(map(int, fields[3:]))
                self.offers.append({"cycle": int(fields[1]), "port": fields[2], "address": values[0],
                                    "write": values[1], "data": values[2], "mask": values[3], "size": values[4]})
            elif kind == "A":
                self.arithmetic.append({"cycle": int(fields[1]), "start": int(fields[2]),
                                        "finish": int(fields[3]), "cancel": int(fields[4]), "pc": int(fields[5])})
            elif kind == "J":
                sequence, index, address, operation, data = map(int, fields[2:])
                requests[sequence] = (index, address, operation, data)
            elif kind == "K":
                sequence, status, data = map(int, fields[2:])
                index, address, operation, value = requests[sequence]
                assert status == 0
                self.responses[index] = (address, operation, value, data)
            elif kind == "W":
                self.words[int(fields[1])] = int(fields[2])
        for index, expected in self.actions.expected.items():
            assert index in self.responses, f"Missing DMI response for action {index}"
            actual = self.responses[index][3]
            assert actual == expected, f"DMI action {index}: expected {expected:#x}, got {actual:#x}"

    def response_cycle(self, mark):
        index = self.actions.marks[mark]
        assert index in self.responses
        matching = [int(line.split()[1]) for line in self.text.splitlines()
                    if line.startswith("L ") and int(line.split()[2]) == index]
        assert len(matching) == 1
        return matching[0]


def initial_debug(actions):
    actions.write(0x10, 1)
    actions.halt("initial")


def debug_store_case():
    a = Assembly()
    a.emit(addi(1, 0, 0x123), addi(2, 0, 0x200), load(3, 2))
    target = a.emit(store(1, 2))
    done = a.emit(jump(0))
    image = a.image({0x200: 0x11223344})
    actions = Actions()
    initial_debug(actions)
    for register, value in ((0x341, 0xDEADBEE0), (0x342, 0x55), (0x343, 0x66)):
        actions.register_write(register, value)
    actions.register_write(0x7A5, 8)
    actions.trigger(0, target, MCONTROL_M)
    actions.trigger(1, target, DEBUG_M)
    actions.resume()
    actions.poll(0x11, 0x300, 0x300, "triggered")
    actions.register_read(0x7B1, target)
    actions.hit(0, MCONTROL_M)
    actions.hit(1, DEBUG_M)
    for register, value in ((0x341, 0xDEADBEE0), (0x342, 0x55), (0x343, 0x66)):
        actions.register_read(register, value)
    actions.disable(0)
    actions.disable(1)
    actions.resume()
    actions.add(WAIT_RETIRE, done)
    actions.halt("final")
    actions.finish()

    def check(trace):
        first = trace.response_cycle("triggered")
        assert not any(event["pc"] == target and event["cycle"] < first for event in trace.retire)
        assert not any(event["trap"] and event["cause"] == 3 for event in trace.retire)
        assert sum(event["pc"] == target and not event["trap"] for event in trace.retire) == 1
        older = next(event for event in trace.retire if event["pc"] == 8)
        assert older["cycle"] <= first
        stores = [event for event in trace.offers if event["port"] == "D" and event["address"] == 0x200 and event["write"]]
        assert len(stores) == 1 and stores[0]["cycle"] > first and stores[0]["data"] == 0x123
        assert trace.words[0x200] == 0x123
    return "debug_store_priority", image, actions, check, {}


def debug_multiply_case():
    a = Assembly()
    a.emit(addi(1, 0, 7), addi(2, 0, 9))
    target = a.emit(multiply(3, 1, 2))
    a.emit(store(3, 0, 0x200))
    done = a.emit(jump(0))
    actions = Actions()
    initial_debug(actions)
    actions.trigger(0, target, DEBUG_M)
    actions.resume()
    actions.poll(0x11, 0x300, 0x300, "triggered")
    actions.register_read(0x7B1, target)
    actions.hit(0, DEBUG_M)
    actions.register_read(0x1003, 0)
    actions.disable(0)
    actions.resume()
    actions.add(WAIT_RETIRE, done)
    actions.halt("final")
    actions.register_read(0x1003, 63)
    actions.finish()

    def check(trace):
        first = trace.response_cycle("triggered")
        assert not any(event["start"] and event["cycle"] < first for event in trace.arithmetic)
        assert sum(event["start"] for event in trace.arithmetic) == 1
        assert sum(event["pc"] == target and not event["trap"] for event in trace.retire) == 1
        assert trace.words[0x200] == 63
    return "debug_multiply_suppression", a.image({0x200: 0x55}), actions, check, {}


def debug_csr_case():
    a = Assembly()
    a.emit(addi(1, 0, 0x55))
    target = a.emit(csr(1, 0x340, 1))
    done = a.emit(jump(0))
    actions = Actions()
    initial_debug(actions)
    actions.register_write(0x340, 0x12345678)
    actions.trigger(0, target, DEBUG_M)
    actions.resume()
    actions.poll(0x11, 0x300, 0x300, "triggered")
    actions.register_read(0x7B1, target)
    actions.hit(0, DEBUG_M)
    actions.register_read(0x340, 0x12345678)
    actions.disable(0)
    actions.resume()
    actions.add(WAIT_RETIRE, done)
    actions.halt("final")
    actions.register_read(0x340, 0x55)
    actions.finish()

    def check(trace):
        first = trace.response_cycle("triggered")
        assert not any(event["pc"] == target and event["cycle"] < first for event in trace.retire)
        assert sum(event["pc"] == target and not event["trap"] for event in trace.retire) == 1
    return "debug_csr_suppression", a.image(), actions, check, {}


def native_program(target_word, retry=False):
    a = Assembly()
    a.emit(addi(1, 0, 0))
    a.addi_label(1, "handler")
    a.emit(csr(1, 0x305, 1))
    a.emit(addi(1, 0, 8), csr(1, 0x7A5, 1))
    a.addi_label(1, "target")
    a.emit(csr(1, 0x7A2, 1))
    for word in immediate(MCONTROL_M):
        if word & 0x7F == 0x37:
            word = word & ~((0x1F) << 7) | 1 << 7
        a.emit(word)
    a.emit(csr(1, 0x7A1, 1))
    a.emit(addi(6, 0, 0x123), load(5, 0, 0x200))
    a.label("target")
    a.emit(target_word)
    done = a.emit(jump(0))
    a.label("handler")
    for address, source in ((0x210, 0x341), (0x214, 0x342), (0x218, 0x343),
                            (0x21C, 0x7A5), (0x220, 0x7A1)):
        a.emit(csr(2, source, 0, 7), store(7, 0, address))
    a.emit(csr(1, 0x7A1, 0), csr(2, 0x341, 0, 7))
    if not retry:
        a.emit(addi(7, 7, 4))
    a.emit(csr(1, 0x341, 7), 0x30200073)
    return a, done


def native_store_case():
    a, done = native_program(store(6, 0, 0x204), retry=True)
    target = a.labels["target"]
    handler = a.labels["handler"]
    actions = Actions()
    initial_debug(actions)
    actions.resume()
    actions.add(WAIT_RETIRE, done)
    actions.halt("final")
    actions.register_read(0x7A5, 0x88)
    actions.finish()

    def check(trace):
        events = [event for event in trace.retire if event["pc"] == target]
        assert len(events) == 2
        assert (events[0]["trap"], events[0]["cause"], events[0]["tval"], events[0]["nextPc"]) == (1, 3, target, handler)
        assert not events[1]["trap"]
        older = next(event for event in trace.retire if event["pc"] == target - 4)
        assert older["cycle"] < events[0]["cycle"]
        stores = [event for event in trace.offers if event["port"] == "D" and event["address"] == 0x204 and event["write"]]
        assert len(stores) == 1 and stores[0]["cycle"] > events[0]["cycle"]
        assert trace.words[0x204] == 0x123
        assert (trace.words[0x210], trace.words[0x214], trace.words[0x218]) == (target, 3, target)
        assert trace.words[0x21C] == 0x80 and trace.words[0x220] == (MCONTROL_M | 1 << 20)
    return "native_breakpoint_tcontrol", a.image({0x200: 0x11223344}), actions, check, {}


def native_multiply_case():
    a, done = native_program(multiply(5, 5, 6), retry=True)
    target = a.labels["target"]
    product = (0x11223344 * 0x123) & MASK
    actions = Actions()
    initial_debug(actions)
    actions.resume()
    actions.add(WAIT_RETIRE, done)
    actions.halt("final")
    actions.register_read(0x1005, product)
    actions.finish()

    def check(trace):
        events = [event for event in trace.retire if event["pc"] == target]
        assert len(events) == 2 and events[0]["trap"] and events[0]["cause"] == 3
        assert not events[1]["trap"]
        assert not any(event["start"] and event["cycle"] < events[0]["cycle"] for event in trace.arithmetic)
        assert sum(event["start"] for event in trace.arithmetic) == 1
        assert sum(event["finish"] for event in trace.arithmetic) == 1
    return "native_multiply_suppression", a.image({0x200: 0x11223344}), actions, check, {}


def native_illegal_case():
    a, done = native_program(0xFFFFFFFF)
    target = a.labels["target"]
    actions = Actions()
    initial_debug(actions)
    actions.resume()
    actions.add(WAIT_RETIRE, done)
    actions.halt("final")
    actions.finish()

    def check(trace):
        events = [event for event in trace.retire if event["pc"] == target]
        assert len(events) == 1
        assert (events[0]["trap"], events[0]["cause"], events[0]["tval"]) == (1, 3, target)
    return "native_precedes_illegal", a.image({0x200: 0x11223344}), actions, check, {}


def fetch_fault_case():
    a = Assembly()
    target = a.emit(addi(1, 0, 1))
    a.emit(jump(0))
    actions = Actions()
    initial_debug(actions)
    actions.register_write(0x341, 0xDEADBEE0)
    actions.register_write(0x342, 0x55)
    actions.register_write(0x343, 0x66)
    actions.trigger(0, target, DEBUG_M)
    actions.resume()
    actions.mark("resumed")
    actions.poll(0x11, 0x300, 0x300, "triggered")
    actions.register_read(0x7B1, target)
    actions.hit(0, DEBUG_M)
    for register, value in ((0x341, 0xDEADBEE0), (0x342, 0x55), (0x343, 0x66)):
        actions.register_read(register, value)
    actions.register_read(0x1001, 0)
    actions.finish()

    def check(trace):
        resumed = trace.response_cycle("resumed")
        assert not any(event["pc"] == target and event["cycle"] > resumed for event in trace.retire)
    return "debug_precedes_fetch_fault", a.image(), actions, check, {"instruction_fault": target}


def older_fault_case():
    a = Assembly()
    a.addi_label(1, "handler")
    a.emit(csr(1, 0x305, 1))
    older = a.emit(load(1, 0, 0x200))
    target = a.emit(store(1, 0, 0x204))
    a.label("handler")
    a.emit(jump(0))
    actions = Actions()
    initial_debug(actions)
    actions.trigger(0, target, DEBUG_M)
    actions.resume()
    actions.mark("resumed")
    actions.add(WAIT_RETIRE, older)
    actions.halt("older_fault")
    actions.register_write(0x7A0, 0)
    actions.register_read(0x7A1, DEBUG_M)
    actions.register_read(0x341, older)
    actions.register_read(0x342, 5)
    actions.register_read(0x343, 0x200)
    actions.register_read(0x7B1, a.labels["handler"])
    actions.finish()

    def check(trace):
        resumed = trace.response_cycle("resumed")
        assert not any(event["pc"] == target and event["cycle"] > resumed for event in trace.retire)
        assert not any(event["port"] == "D" and event["address"] == 0x204 and event["write"] and
                       event["cycle"] > resumed for event in trace.offers)
    return "older_machine_fault_priority", a.image(), actions, check, {"data_fault": 0x200}


def user_filter_case():
    a = Assembly()
    machine = a.emit(addi(1, 0, 1))
    a.emit(addi(2, 0, -1), csr(1, 0x3B0, 2), addi(2, 0, 0x1F), csr(1, 0x3A0, 2))
    a.addi_label(2, "user_target")
    a.emit(csr(1, 0x341, 2), csr(1, 0x300, 0), 0x30200073)
    a.label("user_target")
    target = a.emit(addi(1, 0, 2))
    done = a.emit(jump(0))
    actions = Actions()
    initial_debug(actions)
    actions.trigger(0, target, DEBUG_U)
    actions.resume()
    actions.poll(0x11, 0x300, 0x300, "triggered")
    actions.register_read(0x7B1, target)
    actions.hit(0, DEBUG_U)
    actions.register_read(0x1001, 1)
    actions.register_read(0x7B0, 0x40000450)
    actions.disable(0)
    actions.resume()
    actions.add(WAIT_RETIRE, done)
    actions.halt("final")
    actions.register_read(0x1001, 2)
    actions.finish()

    def check(trace):
        first = trace.response_cycle("triggered")
        assert any(event["pc"] == machine and not event["user"] and event["cycle"] < first for event in trace.retire)
        assert not any(event["pc"] == target and event["cycle"] < first for event in trace.retire)
        resumed = [event for event in trace.retire if event["pc"] == target]
        assert len(resumed) == 1 and resumed[0]["user"]
    return "user_mode_filter", a.image(), actions, check, {"protected": True}


def cases():
    return [debug_store_case(), debug_multiply_case(), debug_csr_case(), native_store_case(),
            native_multiply_case(), native_illegal_case(), fetch_fault_case(), older_fault_case(), user_filter_case()]


def compile_rtl(rtl, manifest, output):
    command = ["verilator", "--cc", "--exe", "--build", "-j", "2", "--top-module", "DitDahE2",
               "--Mdir", str(output.resolve()), "-CFLAGS", "-std=c++17 -I" + str((ROOT / "test/common").resolve()),
               *[str((rtl / name).resolve()) for name in manifest["rtlHashes"]],
               str((ROOT / "test/test_trigger/trigger_sim.cpp").resolve())]
    result = subprocess.run(command, check=False, capture_output=True, text=True)
    (output.parent / "compile.log").write_text(result.stdout + result.stderr)
    if result.returncode:
        raise RuntimeError("Trigger core simulator compilation failed")
    return output / "VDitDahE2"


def execute(binary, case, directory, seed=1, delay=3):
    name, image, actions, _, options = case
    directory.mkdir(parents=True)
    image_path, script_path = directory / "image.hex", directory / "actions.txt"
    image_path.write_text("".join(f"{address:08x} {value:08x}\n" for address, value in sorted(image.items())))
    script_path.write_text("".join(" ".join(map(str, row)) + "\n" for row in actions.rows))
    command = [str(binary.resolve()), str(image_path.resolve()), str(script_path.resolve()), str(seed), str(delay),
               "100000", str(options.get("data_fault", 1 << 32)), str(options.get("instruction_fault", 1 << 32))]
    result = subprocess.run(command, check=False, capture_output=True, text=True)
    (directory / "trace.txt").write_text(result.stdout)
    (directory / "stderr.txt").write_text(result.stderr)
    record = {"case": name, "command": command, "exitStatus": result.returncode,
              "imageHash": digest(image_path), "actionsHash": digest(script_path), "traceHash": digest(directory / "trace.txt")}
    return result, record


def raw_retirements(text):
    return [list(map(int, line.split()[1:])) for line in text.splitlines() if line.startswith("R ")]


def mutate_copy(source, destination, name):
    shutil.copytree(source, destination)
    if name == "priority":
        path = destination / "DitDahE2Trigger.sv"
        target = "assign core_nativeAction = core_ready & core_matched_0 & ~core_debugAction_0;"
        replacement = "assign core_nativeAction = core_ready & core_matched_0;"
    else:
        path = destination / "DitDahE2.sv"
        if name == "multiply-start":
            target = (r"& ~eligibleInterrupt & ~sleeping_0 & ~x_fault"
                      r"( & ~_debug_core_stop| & \(~_debug_core_stop \| xInjected\))"
                      r"\n    & ~_csr_trigger_matched;")
            replacement = r"& ~eligibleInterrupt & ~sleeping_0 & ~x_fault\1;"
        elif name == "native-trap":
            target = "m_trap <= fault;"
            replacement = "m_trap <= x_fault | ~legal | isBreak & ~isDebugBreak | isCall | badTarget | badData;"
        else:
            raise ValueError("Unknown core trigger mutation")
    text = path.read_text()
    if name == "multiply-start":
        text, count = re.subn(target, replacement, text)
        assert count == 1, "Core trigger mutation target changed"
    else:
        assert text.count(target) == 1, "Core trigger mutation target changed"
        text = text.replace(target, replacement)
    path.write_text(text)
    return path


def negative_controls(rtl, manifest, selected, output, report):
    specifications = (("priority", "debug_store_priority"), ("multiply-start", "native_multiply_suppression"),
                      ("native-trap", "native_breakpoint_tcontrol"))
    available = {case[0]: case for case in selected}
    for mutation, case_name in specifications:
        if case_name not in available:
            continue
        case = available[case_name]
        changed_rtl = output / (mutation + "-rtl")
        changed_path = mutate_copy(rtl, changed_rtl, mutation)
        binary = compile_rtl(changed_rtl, manifest, output / (mutation + "-build"))
        result, record = execute(binary, case, output / (mutation + "-negative"))
        trace = None
        try:
            trace = Trace(result.stdout, case[2])
            case[3](trace)
        except (AssertionError, LookupError, StopIteration, TypeError, ValueError) as error:
            reason = str(error)
        else:
            raise AssertionError("Core trigger mutant passed: " + mutation)
        events = raw_retirements(result.stdout)
        if mutation == "priority":
            target = case[2].expected[case[2].marks["triggered"] + 3]
            assert any(event[1] == target and event[7] and event[8] == 3 for event in events), "Missing priority mutant witness"
            witness = "coincident native breakpoint reached retirement"
        elif mutation == "multiply-start":
            target = native_program(multiply(5, 5, 6), retry=True)[0].labels["target"]
            trapped = next(event[0] for event in events if event[1] == target and event[7] and event[8] == 3)
            assert trace is not None
            assert any(event["start"] and event["cycle"] < trapped for event in trace.arithmetic), "Missing early multiply witness"
            witness = "multiply started before the native breakpoint"
        else:
            target = native_program(store(6, 0, 0x204), retry=True)[0].labels["target"]
            assert any(event[1] == target and not event[7] for event in events), "Missing normal-store mutant witness"
            assert not any(event[1] == target and event[7] and event[8] == 3 for event in events), "Unexpected native trap in mutant"
            witness = "native trigger instruction stored without a breakpoint"
        record.update({"mutation": mutation, "rejected": reason, "witness": witness,
                       "changedRtlHash": digest(changed_path)})
        report["negativeControls"].append(record)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rtl", type=Path, required=True)
    parser.add_argument("--user-rtl", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--case", action="append", default=[])
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    manifests = {}
    binaries = {}
    selected = cases()
    if args.case:
        selected = [case for case in selected if case[0] in args.case]
    assert selected
    report = {"exitStatus": 1, "runs": [], "negativeControls": [], "scope": "complete-core direct-DMI precise execute triggers"}
    try:
        for protected, rtl in ((False, args.rtl), (True, args.user_rtl)):
            manifest = json.loads((rtl / "manifest.json").read_text())
            assert manifest["parameters"] == configuration(manifest["parameters"])
            assert manifest["parameters"]["triggerCount"] == 2 and manifest["parameters"]["enableDebug"]
            assert manifest["parameters"]["protectedMode"] is protected
            assert manifest["sourceHashes"] == sources(), "Stale trigger core RTL"
            assert all(digest(rtl / name) == value for name, value in manifest["rtlHashes"].items())
            manifests[protected] = manifest
            binaries[protected] = compile_rtl(rtl, manifest, args.output / ("build-user" if protected else "build"))
        for case in selected:
            name, _, actions, check, options = case
            protected = options.get("protected", False)
            result, record = execute(binaries[protected], case, args.output / name)
            record["parameters"] = manifests[protected]["parameters"]
            if result.returncode:
                raise RuntimeError(f"{name} simulation failed: {result.stderr}")
            trace = Trace(result.stdout, actions)
            check(trace)
            record["accepted"] = True
            report["runs"].append(record)
        negative_controls(args.rtl, manifests[False], selected, args.output, report)
        report["exitStatus"] = 0
    except Exception as error:
        report["failure"] = str(error)
        raise
    finally:
        report["sourceHashes"] = sources()
        report["rtlHashes"] = {str(protected): manifest["rtlHashes"] for protected, manifest in manifests.items()}
        (args.output / "summary.json").write_text(json.dumps(report, indent=2) + "\n")
    print(f"PASS: {len(report['runs'])} complete-core trigger scenarios")


if __name__ == "__main__":
    main()
