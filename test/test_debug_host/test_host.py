# SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
# SPDX-License-Identifier: MIT
"""Check host acceptance configuration and evidence rejection paths."""

import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from test.test_debug_host.verify_host import (
    ABSTRACT_ONLY,
    GDB_ACCEPTED,
    PROGRAM_BUFFER_ONLY,
    READY,
    SCRATCH,
    SYSTEM_BUS_FAULT,
    SYSTEM_BUS_ONLY,
    abstract_metrics,
    check_abstract_evidence,
    check_execution,
    check_program_buffer_evidence,
    check_system_bus_evidence,
    check_trigger_evidence,
    check_wrong_idcode,
    compare_metrics,
    gdb_commands,
    openocd_configuration,
    resolve_tool,
    validate_manifest,
)


def manifest():
    return {"top": "DitDahE2", "parameters": {
        "resetVector": 0, "enableDebug": True, "enableJtag": True, "jtagIdcode": 3,
        "enableM": True, "enableC": True, "protectedMode": False, "enableA": False,
        "enableZba": False, "enableZbb": False, "enableZbs": False}}


def expectations():
    return {"elf": Path("program.elf"), "entry": 0, "stepPc": 4, "stepWord": 351,
            "stepRd": 3, "stepRegister": "gp", "stepValue": 0x20000800, "done": 0x80,
            "signatureAddress": 0x20000000, "signature": 0x12345678,
            "productAddress": 0x20000004, "product": 37, "console": list(b"E2\n")}


def dmi(address, data, cycle=1):
    return f"J {cycle} {address} 2 {data}"


def system_bus_trace():
    records = []
    cycle = 0

    def add(text):
        nonlocal cycle
        records.append(text.format(cycle=cycle))
        cycle += 1

    def status(halted):
        request = cycle
        add("J {cycle} 17 1 0")
        add("K {cycle} 17 0 " + str(0x300 if halted else 0xC00))
        records.append(f"H {cycle - 1} {request} {int(halted)} {int(not halted)}")

    def transfer(size, write, value, address, halted, fault=0):
        data = value << (8 * (address & 3))
        mask = ((1 << (1 << size)) - 1) << (address & 3) if write else 0
        add(f"Q {{cycle}} B {address} {write} {data if write else 0} {mask} {size} "
            f"{int(halted)} {int(not halted)}")
        add(f"S {{cycle}} B {address} {write} {data if write else 0} {mask} {size} {data} {fault}")

    add("J {cycle} 56 2 262144")
    for halted in (True, False):
        if not halted:
            add("J {cycle} 16 2 1073741825")
        status(halted)
        if not halted:
            add("R {cycle} 0 111 0 0 0 0 0 0 0 0")
        for size, offset, value in ((0, 1, 0x5A), (1, 2, 0x6B7C), (2, 4, 0x89ABCDEF)):
            for write in (1, 0):
                transfer(size, write, value, SCRATCH + offset, halted)
        status(halted)
    add("J {cycle} 16 2 2147483649")
    status(True)
    transfer(2, 0, 0, SYSTEM_BUS_FAULT, True, 1)
    transfer(2, 0, 0x89ABCDEF, SCRATCH + 4, True)
    status(True)
    return "\n".join(records) + "\n"


class HostEvidenceTests(unittest.TestCase):
    def test_manifest_requires_rv32imc_jtag(self):
        self.assertEqual(validate_manifest(manifest()), 3)
        for name, value in (("resetVector", 4), ("enableDebug", False), ("enableJtag", False),
                            ("enableM", False), ("enableC", False), ("enableA", True),
                            ("jtagIdcode", 0), ("jtagIdcode", 2), ("jtagIdcode", True),
                            ("jtagIdcode", 1 << 32)):
            with self.subTest(name=name, value=value):
                changed = manifest()
                changed["parameters"][name] = value
                with self.assertRaises(ValueError):
                    validate_manifest(changed)

    def test_openocd_configuration_is_abstract_only(self):
        text = "\n".join(openocd_configuration(1000, 1001, 0x12345679))
        self.assertIn("riscv set_mem_access abstract", text)
        self.assertIn(f"echo {ABSTRACT_ONLY}", text)
        self.assertIn("riscv expose_csrs 832", text)
        self.assertIn("reset halt", text)
        self.assertIn("-expected-id 0x12345679", text)
        self.assertNotRegex(text, r"riscv\s+(?:set_)?mem_access\s+(?:progbuf|sysbus)\b")
        strict = "\n".join(openocd_configuration(1000, 1001, 0x12345679, strict_idcode=True))
        self.assertIn("irscan ditdah.cpu 1", strict)
        self.assertIn("drscan ditdah.cpu 32 0", strict)
        self.assertLess(strict.index("E2_IDCODE_MISMATCH"), strict.index("reset halt"))
        self.assertNotIn("E2_IDCODE_MISMATCH", text)

    def test_abstract_evidence_requires_real_commands(self):
        log = (f"{ABSTRACT_ONLY}\n{READY}\n"
               "Succeeded to read memory via abstract access.\n"
               "Succeeded to write memory via abstract access.\n")
        trace = dmi(0x17, 0x02200000) + "\n" + dmi(0x17, 0x02210000, 2) + "\n"
        observed = check_abstract_evidence(log, trace)
        self.assertEqual(observed["abstractMemoryReads"], 1)
        self.assertEqual(observed["abstractMemoryWrites"], 1)
        with self.assertRaisesRegex(ValueError, "read/write"):
            check_abstract_evidence(log, dmi(0x17, 0x02200000))
        with self.assertRaisesRegex(ValueError, "read/write"):
            check_abstract_evidence(log, dmi(0x17, 0x02210000))
        register_program = "\n".join((trace, dmi(0x20, 0x7A002473, 3),
                                      dmi(0x21, 0x00100073, 4), dmi(0x17, 0x00241000, 5)))
        observed = check_abstract_evidence(log, register_program)
        self.assertEqual(observed["programBufferWrites"], 2)
        self.assertEqual(observed["programBufferLoads"], 0)
        memory_program = "\n".join((trace, dmi(0x20, 0x0000A103, 3),
                                    dmi(0x21, 0x00100073, 4), dmi(0x17, 0x00241000, 5)))
        with self.assertRaisesRegex(ValueError, "Forbidden"):
            check_abstract_evidence(log, memory_program)
        with self.assertRaisesRegex(ValueError, "Forbidden"):
            check_abstract_evidence(log, trace + dmi(0x38, 0, 3))
        with self.assertRaisesRegex(ValueError, "forbidden memory"):
            check_abstract_evidence(log + "riscv set_mem_access progbuf\n", trace)
        with self.assertRaisesRegex(ValueError, "readiness"):
            check_abstract_evidence("", trace)
        with self.assertRaisesRegex(ValueError, "successful abstract memory read"):
            check_abstract_evidence(log.replace("Succeeded to read memory via abstract access.\n", ""), trace)
        with self.assertRaisesRegex(ValueError, "fallback"):
            check_abstract_evidence(log + "Succeeded to read memory via progbuf\n", trace)

    def test_program_buffer_evidence_requires_both_words_and_real_postexec(self):
        text = "\n".join(openocd_configuration(1000, 1001, 3, program_buffer=True))
        self.assertIn("riscv set_mem_access progbuf", text)
        self.assertIn(f"echo {PROGRAM_BUFFER_ONLY}", text)
        log = (f"{PROGRAM_BUFFER_ONLY}\n{READY}\n"
               "Succeeded to read memory via program buffer.\n"
               "Succeeded to write memory via program buffer.\n")
        trace = "\n".join((dmi(0x20, 0x0000A103), dmi(0x21, 0x00100073, 2),
                           dmi(0x17, 0x00271008, 3), dmi(0x20, 0x00942023, 4),
                           dmi(0x17, 0x00241000, 5)))
        observed = check_program_buffer_evidence(log, trace)
        self.assertEqual(observed["programBufferWrites"], 3)
        self.assertEqual(observed["postexecCommands"], 2)
        self.assertEqual(observed["postexecOnlyCommands"], 1)
        self.assertEqual(observed["abstractMemoryReads"], 0)
        for label, changed in (
                ("readiness", ""),
                ("fallback", log + "Succeeded to read memory via abstract access.\n"),
                ("program", trace.replace(dmi(0x21, 0x00100073, 2), "")),
                ("postexec", trace.replace(dmi(0x17, 0x00271008, 3), dmi(0x17, 0x00231008, 3))),
                ("direction", trace.replace(dmi(0x20, 0x00942023, 4), "")),
                ("aam", trace + dmi(0x17, 0x02200000, 6))):
            with self.subTest(label=label), self.assertRaises(ValueError):
                check_program_buffer_evidence(changed if label in ("readiness", "fallback") else log,
                                              changed if label not in ("readiness", "fallback") else trace)

    def test_system_bus_configuration_requires_explicit_feature_and_no_fallback(self):
        with self.assertRaisesRegex(ValueError, "enableSba"):
            validate_manifest(manifest(), system_bus=True)
        selected = manifest()
        selected["parameters"]["enableSba"] = True
        self.assertEqual(validate_manifest(selected, system_bus=True), 3)
        selected["parameters"]["enableSba"] = 1
        with self.assertRaisesRegex(ValueError, "enableSba"):
            validate_manifest(selected, system_bus=True)
        configuration = "\n".join(openocd_configuration(1000, 1001, 3, system_bus=True))
        self.assertIn("riscv set_mem_access sysbus\n", configuration)
        self.assertIn(SYSTEM_BUS_ONLY, configuration)
        self.assertIn("gdb_report_data_abort enable", configuration)
        self.assertNotIn("set_mem_access abstract", configuration)
        self.assertNotIn("set_mem_access progbuf", configuration)
        with self.assertRaisesRegex(ValueError, "one host"):
            openocd_configuration(1000, 1001, 3, program_buffer=True, system_bus=True)
        script = gdb_commands(Path("program.elf"), 1234, expectations(), system_bus=True)
        for token in ("monitor riscv dmi_read 0x11", "monitor resume 0", "bus_probe(True)",
                      "bus_probe(False)", "inferior.write_memory", "inferior.read_memory",
                      "monitor wait_halt 10000", hex(SYSTEM_BUS_FAULT), "compare-sections", "stepi"):
            self.assertIn(token, script)

    def test_system_bus_evidence_requires_actual_owned_halted_running_widths(self):
        log = (f"{SYSTEM_BUS_ONLY}\n{READY}\n"
               "Succeeded to read memory via system bus.\n"
               "Succeeded to write memory via system bus.\n")
        trace = system_bus_trace()
        result = check_system_bus_evidence(log, trace)
        self.assertEqual(result["systemBusIntervals"]["halted"]["retirements"], 0)
        self.assertEqual(result["systemBusIntervals"]["running"]["retirements"], 1)
        self.assertEqual(result["systemBusFaults"], 1)
        self.assertTrue(result["systemBusFaultRecovery"])
        self.assertEqual(result["abstractMemoryReads"], 0)
        self.assertEqual(result["programBufferStores"], 0)
        mutations = {
            "missing-status": "\n".join(x for x in trace.splitlines() if not x.startswith("K ")),
            "missing-request": "\n".join(x for x in trace.splitlines() if not x.startswith("Q ")),
            "missing-response": "\n".join(x for x in trace.splitlines() if not x.startswith("S ")),
            "no-progress": "\n".join(x for x in trace.splitlines() if not x.startswith("R ")),
            "wrong-status": trace.replace("17 0 3072", "17 0 768"),
            "no-halfword": "\n".join(x for x in trace.splitlines()
                                        if not (x.startswith(("Q ", "S ")) and x.split()[3] == str(SCRATCH + 2))),
            "bad-lane": trace.replace(f"B {SCRATCH + 1} 1 23040 2 0", f"B {SCRATCH + 1} 1 23040 1 0"),
            "wrong-data": trace.replace("23040", "23296"),
            "wrong-owner": trace.replace(f"S 4 B {SCRATCH + 1}", f"S 4 B {SCRATCH + 2}"),
            "aam": dmi(0x17, 0x02200000, 0) + "\n" + trace,
            "pb": dmi(0x20, 0x0000A103, 0) + "\n" + dmi(0x17, 1 << 18, 0) + "\n" + trace,
            "compressed-pb": dmi(0x20, 0x4000, 0) + "\n" + dmi(0x17, 1 << 18, 0) + "\n" + trace,
        }
        for label, changed in mutations.items():
            with self.subTest(label=label), self.assertRaises(ValueError):
                check_system_bus_evidence(log, changed)
        for changed in ("", log.replace("Succeeded to read memory via system bus.\n", ""),
                        log + "Succeeded to read memory via abstract access.\n",
                        log + "riscv set_mem_access progbuf\n"):
            with self.subTest(log=changed), self.assertRaises(ValueError):
                check_system_bus_evidence(changed, trace)

    def test_system_bus_state_windows_reject_controls_and_outside_progress(self):
        log = (f"{SYSTEM_BUS_ONLY}\n{READY}\n"
               "Succeeded to read memory via system bus.\nSucceeded to write memory via system bus.\n")
        lines = system_bus_trace().splitlines()
        at = next(i for i, line in enumerate(lines) if line.startswith("R "))
        cycle = int(lines[at].split()[1])
        for event in (f"J {cycle} 16 2 2147483649", f"Z {cycle} 0 1"):
            changed = "\n".join(lines[:at] + [event] + lines[at:])
            with self.subTest(event=event), self.assertRaises(ValueError):
                check_system_bus_evidence(log, changed)
        moved = lines[:at] + lines[at + 1:]
        after = next(i for i, line in enumerate(moved) if line.startswith("J ") and line.endswith("2147483649"))
        late_cycle = int(moved[after].split()[1])
        moved.insert(after, f"R {late_cycle} 0 111 0 0 0 0 0 0 0 0")
        with self.assertRaisesRegex(ValueError, "no native retirements"):
            check_system_bus_evidence(log, "\n".join(moved))

    def test_tap_observer_decodes_actual_response_and_rejects_stale_state(self):
        source = (Path(__file__).parent / "jtag_sim.cpp").read_text()
        observer = source.split("class TapObserver {", 1)[1].split("static void sendByte", 1)[0]
        program = r'''
#include <sstream>
#include <iostream>
#include <stdexcept>
#include <cstdint>
class TapObserver {
OBSERVER
int main() {
    TapObserver tap;
    std::ostringstream out;
    uint64_t cycle = 0;
    auto tick = [&](bool tms, bool tdi = false, bool tdo = false) {
        tap.clock(tms, tdi, tdo, cycle++, out);
    };
    tap.resetNow(); tick(0);
    tick(1); tick(1); tick(0); tick(0);
    for (unsigned bit = 0; bit < 5; ++bit) tick(bit == 4, (0x11 >> bit) & 1);
    tick(1); tick(0);
    auto scan = [&](uint64_t request, uint64_t response) {
        tick(1); tick(0); tick(0);
        for (unsigned bit = 0; bit < 41; ++bit)
            tick(bit == 40, (request >> bit) & 1, (response >> bit) & 1);
        tick(1); tick(0);
    };
    const uint64_t statusRead = (uint64_t(0x11) << 34) | 1;
    const uint64_t halted = (uint64_t(0x11) << 34) | (uint64_t(0x300) << 2);
    const uint64_t running = (uint64_t(0x11) << 34) | (uint64_t(0xc00) << 2);
    scan(statusRead, 0);
    scan(0, halted);
    if (tap.hartHalted() != 1 || tap.hartRunning() != 0) return 1;
    scan(0, halted);
    scan((uint64_t(0x10) << 34) | (uint64_t(0x40000001) << 2) | 2, 0);
    if (tap.hartHalted() != -1) return 2;
    scan(statusRead, 0);
    scan(0, running | 3);
    if (tap.hartRunning() != -1) return 3;
    scan(0, running);
    if (tap.hartRunning() != 1 || tap.hartHalted() != 0) return 4;
    std::cout << out.str();
}
'''.replace("OBSERVER", observer)
        with tempfile.TemporaryDirectory(prefix="ditdah-e2-tap-", dir="/data/tmp") as directory:
            work = Path(directory)
            (work / "tap.cpp").write_text(program)
            subprocess.run([shutil.which("g++") or "g++", "-std=c++17", "-Wall", "-Wextra", "-Werror",
                            str(work / "tap.cpp"), "-o", str(work / "tap")], check=True, capture_output=True)
            result = subprocess.run([str(work / "tap")], check=True, capture_output=True, text=True)
        states = [line.split() for line in result.stdout.splitlines() if line.startswith("H ")]
        self.assertEqual([row[3:] for row in states], [["1", "0"], ["0", "1"]])
        self.assertTrue(all(int(row[2]) < int(row[1]) for row in states))

    def test_abstract_throughput_requires_postincrement_and_improvement(self):
        trace = ("J 10 23 2 36175872\n"
                 "J 20 24 2 1\n"
                 "J 30 4 2 42\n"
                 "J 40 23 2 36175872\n"
                 "J 40 4 1 0\n"
                 "F 50 0 2\n")
        current = abstract_metrics(trace)
        self.assertEqual(current["automaticDataAccesses"], 2)
        self.assertEqual(current["postincrementCommands"], 2)
        self.assertEqual(current["abstractWindowCycles"], 30)
        baseline = current | {"finalCycles": 100, "abstractWindowCycles": 60,
                              "dmiRequests": 10, "data1Writes": 5}
        comparison = compare_metrics(baseline, current)
        self.assertEqual(comparison["finalCycleReductionPercent"], 50)
        self.assertEqual(comparison["data1WriteReductionPercent"], 100)
        with self.assertRaisesRegex(ValueError, "postincrement"):
            compare_metrics(baseline, current | {"postincrementCommands": 0})
        with self.assertRaisesRegex(ValueError, "throughput"):
            compare_metrics(baseline, current | {"finalCycles": 100})

    def test_wrong_idcode_must_be_a_tool_rejection(self):
        log = "Error: E2_IDCODE_MISMATCH actual=00000003 expected=0x00000001"
        check_wrong_idcode(log, 1, False, 3, 1)
        for status, ready, changed in ((0, False, log), (1, True, log), (None, False, log),
                                       (1, False, "Error: adapter disconnected"),
                                       (None, False, "Error: adapter disconnected")):
            with self.subTest(status=status, ready=ready), self.assertRaises(ValueError):
                check_wrong_idcode(changed, status, ready, 3, 1)

    def test_execution_requires_reset_retirement_console_and_memory(self):
        expected = expectations()
        trace = ("R 10 0 351 4 3 1 536872960 0 0 0 0\n"
                 "S 20 D 268435456 1 69 15 2 0 0\n"
                 "S 21 D 268435456 1 50 15 2 0 0\n"
                 "S 22 D 268435456 1 10 15 2 0 0\n"
                 "F 100 0 2\n"
                 "E 10 1\n"
                 "W 536870912 305419896\n"
                 "W 536870916 37")
        observed = check_execution(trace, expected)
        self.assertEqual(observed["console"], "E2\n")
        self.assertEqual(observed["debugResetPulses"], 2)
        self.assertEqual(observed["tdoEnabledSamples"], 1)
        for label, changed in (
                ("reset", trace.replace("F 100 0 2", "F 100 0 1")),
                ("retirement", trace.replace("R 10 0 351 4", "R 10 0 351 8")),
                ("console", trace.replace("1 50 15", "1 51 15")),
                ("signature", trace.replace("W 536870912 305419896", "W 536870912 0")),
                ("tdo-enable", trace.replace("E 10 1", "E 10 0")),
                ("completion", trace.replace("F 100 0 2", ""))):
            with self.subTest(label=label), self.assertRaises(ValueError):
                check_execution(changed, expected)

    def test_gdb_script_covers_all_host_operations(self):
        text = gdb_commands(Path("program.elf"), 1234, expectations())
        for token in ("$s0", "$a0", "$mscratch", "load", "compare-sections", "stepi",
                      "continue", "monitor reset halt", GDB_ACCEPTED):
            self.assertIn(token, text)
        self.assertIn("mis-matched", text)
        self.assertIn("quit 1", text)

    def test_hardware_breakpoint_requires_two_triggers(self):
        selected = manifest()
        self.assertEqual(validate_manifest(selected, require_triggers=False), 3)
        with self.assertRaisesRegex(ValueError, "triggerCount=2"):
            validate_manifest(selected, require_triggers=True)
        selected["parameters"]["triggerCount"] = 2
        self.assertEqual(validate_manifest(selected, require_triggers=True), 3)
        configuration = "\n".join(openocd_configuration(1000, 1001, 3, triggers=True))
        self.assertIn("riscv expose_csrs 1952-1957 833-835", configuration)
        self.assertLess(configuration.index("expose_csrs 1952"), configuration.index("init"))

    def test_hardware_breakpoint_script_and_dmi_evidence(self):
        expected = expectations()
        text = gdb_commands(Path("program.elf"), 1234, expected, hardware=True)
        for token in ("hbreak *0x80", "$tselect", "reg('tdata1')", "reg('tdata2')", "reg('tinfo')", "stepi"):
            self.assertIn(token, text)
        done = expected["done"]
        trace = "\n".join((dmi(4, 0), dmi(0x17, 0x2307A0, 2), dmi(4, done, 3),
                           dmi(0x17, 0x2307A2, 4), dmi(4, 0x28001044, 5),
                           dmi(0x17, 0x2307A1, 6), dmi(0x17, 0x2207A4, 7)))
        observed = check_trigger_evidence(trace, done)
        self.assertEqual(observed["triggerReads"], [0x7A4])
        self.assertEqual(observed["triggerWrites"], 3)
        with self.assertRaisesRegex(ValueError, "address"):
            check_trigger_evidence(trace.replace(f"J 3 4 2 {done}", "J 3 4 2 0"), done)
        with self.assertRaisesRegex(ValueError, "enumerate"):
            check_trigger_evidence(trace.replace(dmi(0x17, 0x2207A4, 7), ""), done)

    def test_tool_resolution_rejects_missing_programs(self):
        executable, info = resolve_tool(sys.executable, "E2_DEBUG_TEST_UNUSED", "missing")
        self.assertTrue(executable.is_file())
        self.assertEqual(len(info["sha256"]), 64)
        with self.assertRaises(ValueError):
            resolve_tool("definitely-not-an-e2-debug-tool", "E2_DEBUG_TEST_UNUSED", "missing")

    def test_simulator_drives_jtag_without_direct_dmi(self):
        source = (Path(__file__).parent / "jtag_sim.cpp").read_text()
        for port in ("jtag_tck", "jtag_trstN", "jtag_tms", "jtag_tdi", "jtag_tdo", "jtag_tdoEnable"):
            self.assertIn("dut." + port, source)
        self.assertIn("instruction == 0x11", source)
        self.assertIn("bits == 41", source)
        self.assertNotIn("dmi_request", source)


if __name__ == "__main__":
    unittest.main()
