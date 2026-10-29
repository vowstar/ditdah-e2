# SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
# SPDX-License-Identifier: MIT
"""Exercise strict Sail trace parsing and address/configuration boundaries."""

import unittest
import copy

from sail_config import configuration, parse_defaults
from sail_trace import SailTraceError, parse_signature, parse_trace


NORMAL = """mem[X,0x080000000] -> 0x0313
mem[X,0x080000002] -> 0x0010
[0] [M]: 0x80000000 (0x00100313) addi x6, x0, 0x1
x6 <- 0x00000001

"""
FAULT = """mem[X,0x080000000] -> 0x2573
mem[X,0x080000002] -> 0x31A0
[0] [U]: 0x80000000 (0x31A02573) csrrs x10, menvcfgh, x0
trapping from U to M to handle illegal-instruction
handling exc#illegal-instruction at priv M with tval 0x31A02573
CSR mstatus (0x300) <- 0x00000000
CSR mcause (0x342) <- 0x00000002
CSR mtval (0x343) <- 0x31A02573
CSR mepc (0x341) <- 0x80000000

"""


class TraceTests(unittest.TestCase):
    def test_native_register_and_fetch(self):
        step, = parse_trace(NORMAL)
        self.assertEqual((step.pc, step.instruction, step.length, step.mode), (0x80000000, 0x00100313, 4, 3))
        self.assertEqual(step.register_writes, ((6, 1),))
        self.assertEqual([(access.kind, access.width) for access in step.memory], [("X", 2), ("X", 2)])

    def test_trap_uses_native_numeric_state(self):
        step, = parse_trace(FAULT)
        self.assertEqual((step.trap, step.cause, step.tval, step.mode), (True, 2, 0x31A02573, 0))
        self.assertFalse(step.register_writes)

    def test_instructionless_fetch_fault_keeps_unknown_encoding(self):
        fault = """trapping from M to M to handle fetch-access-fault
handling exc#fetch-access-fault at priv M with tval 0x90000000
CSR mstatus (0x300) <- 0x00001800
CSR mstatush (0x310) <- 0x00000000
CSR mcause (0x342) <- 0x00000001
CSR mtval (0x343) <- 0x90000000
CSR mepc (0x341) <- 0x90000000

"""
        step, = parse_trace(fault)
        self.assertEqual((step.pc, step.cause, step.instruction, step.length), (0x90000000, 1, None, None))
        with self.assertRaises(SailTraceError):
            parse_trace(fault.replace("0x00000001", "0x00000005"))

    def test_bad_trap_evidence_fails(self):
        for original, replacement in [("0x00000002", "0x80000002"),
                                      ("at priv M", "at priv U"),
                                      ("CSR mepc (0x341) <- 0x80000000", "CSR mepc (0x341) <- 0x80000004"),
                                      ("CSR mtval (0x343) <- 0x31A02573", "CSR mtval (0x343) <- 0x00000000")]:
            with self.subTest(original=original), self.assertRaises(SailTraceError):
                parse_trace(FAULT.replace(original, replacement))

    def test_missing_or_duplicate_step_fails(self):
        for text in [NORMAL.replace("[0]", "[1]"), NORMAL + NORMAL, NORMAL.rstrip(), ""]:
            with self.subTest(text=text), self.assertRaises(SailTraceError):
                parse_trace(text)

    def test_unknown_or_misordered_record_fails(self):
        for text in [NORMAL.replace("x6 <-", "other <-"),
                     NORMAL.replace("x6 <- 0x00000001", "mem[X,0x080000004] -> 0x0000"),
                     NORMAL.replace("x6 <- 0x00000001", "x0 <- 0x00000001")]:
            with self.subTest(text=text), self.assertRaises(SailTraceError):
                parse_trace(text)

    def test_memory_preserves_byte_width(self):
        step, = parse_trace(NORMAL.replace("x6 <- 0x00000001", "mem[W,0x020000001] <- 0xA5"))
        access = step.memory[-1]
        self.assertEqual((access.address, access.width, access.value), (0x20000001, 1, 0xA5))
        with self.assertRaises(SailTraceError):
            parse_trace(NORMAL.replace("x6 <- 0x00000001", "mem[R,0x020000001] <- 0xA5"))

    def test_atomic_read_and_write_are_distinct(self):
        effects = "mem[RW,0x020000000] -> 0x00000009\nmem[RW,0x020000000] <- 0x00000012"
        step, = parse_trace(NORMAL.replace("x6 <- 0x00000001", effects))
        self.assertEqual([(effect.write, effect.value) for effect in step.memory[-2:]],
                         [(False, 9), (True, 18)])

    def test_compressed_and_return(self):
        step, = parse_trace(NORMAL.replace("0x00100313", "0x0001").replace("x6 <- 0x00000001", ""))
        self.assertEqual(step.length, 2)
        step, = parse_trace(NORMAL.replace("0x00100313", "0x30200073")
                           .replace("x6 <- 0x00000001", "ret-ing from M to U"))
        self.assertEqual(step.return_mode, 0)

    def test_exact_signature_extent(self):
        self.assertEqual(parse_signature("00000000\nffffffff\n", 2), [0, 0xffffffff])
        for text in ["00000000\n", "00000000\ninvalid\n", "00000000\nffffffff\n00000001\n"]:
            with self.subTest(text=text), self.assertRaises(SailTraceError):
                parse_signature(text, 2)


class ConfigurationTests(unittest.TestCase):
    def setUp(self):
        self.parameters = {"resetVector": 0x80000000, "enableM": True, "enableC": True,
                           "protectedMode": True, "enableDebug": False, "enableA": False,
                           "enableZba": False, "enableZbb": False, "enableZbs": False}
        extensions = {name: {"supported": True} for name in
                      ("M", "A", "B", "Zca", "Zicsr", "Zifencei", "Zicntr", "S", "U", "F", "D",
                       "Zba", "Zbb", "Zbs")}
        extensions["V"] = {"support_level": "Full"}
        extensions["Stateen"] = {"Smstateen": {"supported": True}}
        self.defaults = {"base": {"xlen": 32, "E": True, "mstatus": {}}, "extensions": extensions,
                         "memory": {"pmp": {}, "misaligned": {}, "regions": [
                             {"attributes": {"mem_type": "MainMemory"}},
                             {"attributes": {"mem_type": "IOMemory"}}]},
                         "platform": {"clint": {}, "simple_interrupt_generator": {}, "reservation": {}}}
        self.regions = [{"base": 0x80000000, "size": 0x10000, "read": True,
                         "write": False, "execute": True, "atomic": False}]

    def build(self):
        return configuration(self.defaults, self.parameters, self.regions, instruction_limit=1000)

    def test_profile_and_defaults_are_not_mutated(self):
        original = copy.deepcopy(self.defaults)
        result = self.build()
        self.assertEqual(self.defaults, original)
        self.assertFalse(result["base"]["E"])
        self.assertFalse(result["base"]["writable_misa"])
        self.assertFalse(result["extensions"]["S"]["supported"])
        self.assertFalse(result["extensions"]["Stateen"]["Smstateen"]["supported"])
        self.assertEqual(result["extensions"]["V"]["support_level"], "Disabled")
        self.assertEqual(result["memory"]["pmp"]["count"], 16)
        self.assertGreater(result["platform"]["instructions_per_tick"], 1000)

    def test_machine_only_has_no_pmp_or_user_mode(self):
        self.parameters["protectedMode"] = False
        result = self.build()
        self.assertFalse(result["extensions"]["U"]["supported"])
        self.assertEqual(result["memory"]["pmp"]["count"], 0)

    def test_individual_bit_group_does_not_enable_b(self):
        self.parameters["enableZba"] = True
        result = self.build()
        self.assertTrue(result["extensions"]["Zba"]["supported"])
        self.assertFalse(result["extensions"]["B"]["supported"])
        self.parameters.update(enableZbb=True, enableZbs=True)
        self.assertTrue(self.build()["extensions"]["B"]["supported"])

    def test_invalid_parameters_and_memory_fail(self):
        self.parameters["enableDebug"] = True
        with self.assertRaisesRegex(ValueError, "Debug"):
            self.build()
        self.parameters["enableDebug"] = False
        self.regions.append(dict(self.regions[0]))
        with self.assertRaisesRegex(ValueError, "overlap"):
            self.build()

    def test_default_printer_comments_preserve_strings(self):
        value = parse_defaults('// comment\n{"base":{"xlen":32},"note":"a//b"}\n')
        self.assertEqual(value["note"], "a//b")
        with self.assertRaisesRegex(ValueError, "RV32"):
            parse_defaults('{"base":{"xlen":64}}')


if __name__ == "__main__":
    unittest.main()
