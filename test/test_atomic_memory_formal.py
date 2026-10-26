# SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
# SPDX-License-Identifier: MIT
"""Check atomic proof geometry and physical port binding."""

from pathlib import Path
import unittest

from atomic_memory_formal import negative_trace, observe, ownership_trace, ownership_wrapper, wrapper


class AtomicFormalTests(unittest.TestCase):
    def test_complete_small_sram_binding(self):
        source = Path(__file__).with_name("atomic_memory_formal.sv").read_text()
        result = wrapper(source, {"baseAddress": 0xFFFFFFF4, "sizeBytes": 12})
        self.assertIn("WORDS = 3", result)
        self.assertIn("BASE = 32'hfffffff4", result)
        self.assertEqual(result.count("_request_bits_operation(payload["), 4)
        self.assertNotIn("@INSTANCE@", result)
        self.assertNotIn("assume(response_ready", result)
        self.assertNotIn("assume(source", result)
        self.assertIn("(* anyseq *) reg [303:0] source_payload", result)
        self.assertIn("assign source_payload[stimulus_port*76 +: 76]", result)
        self.assertIn("issued <= issued | accepted", result)

    def test_invalid_geometry_and_template_rejected(self):
        source = Path(__file__).with_name("atomic_memory_formal.sv").read_text()
        with self.assertRaises(ValueError):
            wrapper(source, {"sizeBytes": 20})
        with self.assertRaises(ValueError):
            wrapper(source.replace("@BASE@", "0"), {"sizeBytes": 4})

    def test_observer_adds_only_read_outputs(self):
        controller = "module DitDahE2AtomicMemory(input clock\n);\n  DitDahE2AtomicSram #(1) memory (\n" + ",\n".join(
            "." + name + "(" + value + ")" for name, value in (("address", "index"), ("readEnable", "valid"),
            ("writeMask", "mask"), ("writeData", "operand + (old)"), ("readData", "result"))) + "\n  );\nendmodule"
        storage = "module DitDahE2AtomicSram(\n  output reg [31:0] readData\n);\nendmodule"
        rtl, ram = observe(controller, storage, {"baseAddress": 0, "sizeBytes": 16})
        self.assertIn("assign formalWriteData = operand + (old);", rtl)
        self.assertIn(".writeData(operand + (old))", rtl)
        self.assertIn("assign formalMemory[word*32 +: 32] = memory[word];", ram)
        self.assertNotIn("input formal", rtl + ram)
        with self.assertRaises(ValueError):
            observe(rtl, ram, {"baseAddress": 0, "sizeBytes": 16})

    def test_ownership_witness_checks_both_goals_and_memory(self):
        content = "\n".join(("$var wire 2 a \\reach $end", "$var wire 4 b \\response_valid $end",
                            "$var wire 4 c \\response_ready $end", "$var wire 32 d \\coverMemory $end",
                            "b11 a", "b1111 b", "b0000 c", "b0001 d"))
        self.assertEqual(ownership_trace(content)["reach"], 3)
        for bad in (content.replace("b11 a", "b01 a"), content.replace("b0000 c", "b0001 c"),
                    content.replace("b0001 d", "bxxxx d")):
            with self.assertRaises(AssertionError):
                ownership_trace(bad)
        source = "module atomic_memory_formal(input clock);\nendmodule"
        self.assertIn("output [95:0] coverMemory", ownership_wrapper(source, {"sizeBytes": 12}))
        with self.assertRaises(AssertionError):
            ownership_wrapper("module changed;\nendmodule", {"sizeBytes": 12})

    def test_negative_witness_requires_a_physical_write(self):
        fields = {"initialized": (1, 1), "formalMask": (4, 15), "formalWriteData": (32, 9),
                  "commit_write": (1, 0), "mask": (4, 15), "new_value": (32, 9), "operation": (4, 2),
                  "address": (32, 4), "owner": (2, 1), "reservation": (1, 0)}
        declarations = [f"$var wire {width} v{index} \\{name} $end" for index, (name, (width, _)) in enumerate(fields.items())]
        values = [f"{value}v{index}" if width == 1 else f"b{value:b} v{index}" for index, (width, value) in enumerate(fields.values())]
        content = "\n".join([*declarations, "#7", *values])
        self.assertEqual(negative_trace(content, "stale-reservation")["expectedMask"], 0)
        with self.assertRaises(AssertionError):
            negative_trace(content.replace("b1111 v1", "b0 v1"), "stale-reservation")
        with self.assertRaises(AssertionError):
            negative_trace(content, "amo-subtract")


if __name__ == "__main__":
    unittest.main()
