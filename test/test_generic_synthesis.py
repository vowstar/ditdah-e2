# SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
# SPDX-License-Identifier: MIT
"""Reject missing logic, unresolved cells and ineffective netlist mutations."""

import unittest
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from generic_netlist import WritebackControl, mutate_writeback, simulation_netlist
from model import Model
from synthesize import script, structure


def design(*cells):
    return {"modules": {"DitDahE2": {"cells": {str(index): cell for index, cell in enumerate(cells)}}}}


class GenericSynthesisTests(unittest.TestCase):
    def test_logic_counts_exclude_scope_metadata(self):
        record = structure(design({"type": "$_AND_"}, {"type": "$_SDFFE_PP0P_"},
                                  {"type": "$scopeinfo", "parameters": {"TYPE": "module"}, "connections": {}}))
        self.assertEqual(record["cells"], 2)
        self.assertEqual(record["clockedCells"], 1)
        self.assertEqual(record["scopeMetadata"], 1)

    def test_rejects_connected_scope_metadata(self):
        with self.assertRaisesRegex(AssertionError, "Connected scope metadata"):
            structure(design({"type": "$scopeinfo", "connections": {"out": [2]}}))

    def test_rejects_black_box(self):
        value = design({"type": "$_AND_"})
        value["modules"]["DitDahE2"]["attributes"] = {"blackbox": "1"}
        with self.assertRaisesRegex(AssertionError, "Black box"):
            structure(value)

    def test_rejects_missing_or_unflattened_modules(self):
        for value in ({"modules": {}}, {"modules": {"DitDahE2": {}, "Child": {}}}):
            with self.subTest(value=value), self.assertRaisesRegex(AssertionError, "flattened"):
                structure(value)

    def test_rejects_empty_logic(self):
        with self.assertRaisesRegex(AssertionError, "Empty"):
            structure(design())

    def test_rejects_unmapped_cells_and_storage(self):
        for kind in ("Child", "$add", "$_DLATCH_P_", "$_TBUF_"):
            with self.subTest(kind=kind), self.assertRaises(AssertionError):
                structure(design({"type": kind}))

    def test_script_rejects_paths_and_commands(self):
        for name in ("../Core.sv", "Core.sv;stat", "Core.sv\nstat", "/Core.sv"):
            with self.subTest(name=name), self.assertRaisesRegex(AssertionError, "filename"):
                script([name])

    def test_mutation_changes_only_writeback_enable(self):
        original = "assign retire_writes = enable & complete;\nassign data_valid = busy;\n"
        changed = mutate_writeback(original)
        self.assertIn("retire_writes = ~(enable & complete);", changed)
        self.assertIn("assign data_valid = busy;", changed)

    def test_mutation_rejects_absent_or_multiple_outputs(self):
        for original in ("", "assign retire_writes = a;\nassign retire_writes = b;"):
            with self.subTest(original=original), self.assertRaisesRegex(AssertionError, "writeback"):
                mutate_writeback(original)

    def test_simulation_alias_preserves_external_port(self):
        original = ("module DitDahE2(interrupt_cause);\noutput [31:0] interrupt_cause;\n"
                    "wire [31:0] interrupt_cause;\nassign interrupt_cause[3] = external;\n"
                    "assign interrupt_cause[2] = ~interrupt_cause[3];\nendmodule\n")
        changed = simulation_netlist(original)
        self.assertIn("module DitDahE2(interrupt_cause);", changed)
        self.assertIn("output [31:0] interrupt_cause;", changed)
        self.assertIn("simulation_interrupt_cause[2] = ~simulation_interrupt_cause[3]", changed)
        self.assertIn("assign interrupt_cause = simulation_interrupt_cause;", changed)

    def test_simulation_alias_rejects_unknown_declarations(self):
        with self.assertRaisesRegex(AssertionError, "interrupt cause output"):
            simulation_netlist("module DitDahE2();\nendmodule\n")

    def test_writeback_control_handles_crossing_and_wrapping_fetch(self):
        for reset in (0, 2, 0xfffffffe):
            with self.subTest(reset=reset):
                case = WritebackControl("control", [], reset=reset, completion_pc=(reset + 4) & 0xffffffff,
                                        expected_causes=(), enable_c=True)
                model = Model(case.words(), reset, enable_c=True)
                self.assertEqual(model.step().value, 7)
                self.assertEqual(model.step().pc, case.completion_pc)


if __name__ == "__main__":
    unittest.main()
