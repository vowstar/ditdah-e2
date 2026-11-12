# SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
# SPDX-License-Identifier: MIT
"""Check host acceptance configuration and evidence rejection paths."""

import sys
import unittest
from pathlib import Path

from test.test_debug_host.verify_host import (
    ABSTRACT_ONLY,
    GDB_ACCEPTED,
    PROGRAM_BUFFER_ONLY,
    READY,
    check_abstract_evidence,
    check_execution,
    check_program_buffer_evidence,
    check_trigger_evidence,
    check_wrong_idcode,
    abstract_metrics,
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
