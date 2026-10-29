# SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
# SPDX-License-Identifier: MIT
"""Check RVFI task acceptance and explicit profile boundaries."""

from pathlib import Path
import json
import sys
import tempfile
import unittest
from rvfi import ACTIVE_PROCESSES, check_task_set, configuration, configure_replay, counterexample_witness, csrc_identity_compatibility, csr_guard_wrapper, disabled_typed_cover_model, execute, fault_guard_wrapper, imem_fault_compatibility, m_operand_wrapper, mutation, reachability_failure, reachability_wrapper, select_isa, select_tasks, task_status, validate_cover_removal


class RvfiTests(unittest.TestCase):
    def parameters(self, **changes):
        return dict(enableM=False, enableC=False, enableA=False, enableDebug=False,
                    enableZba=False, enableZbb=False, enableZbs=False) | changes

    def typed_cover_model(self):
        def cell(flavor, enabled, value, source):
            return {"type": "$check", "parameters": {"FLAVOR": flavor},
                    "connections": {"EN": enabled, "A": value}, "attributes": {"src": source}}
        return {"modules": {"rvfi_testbench": {
            "netnames": {"rvfi_bus_insn": {"bits": ["1", "0"]},
                         "rvfi_bus_data": {"bits": ["0", "1"]}, "rvfi_bus_fault": {"bits": [2, 3]}},
            "cells": {"disabled": cell("cover", ["0"], [3], "rvfi_bus_imem_fault_check.sv:55.6-55.41"),
                      "active": cell("cover", [4], [2], "rvfi_bus_imem_fault_check.sv:55.6-55.41"),
                      "assertion": cell("assert", ["1"], [5], "checker.sv:2.1-2.2"),
                      "assumption": cell("assume", ["1"], [6], "checker.sv:3.1-3.2")}}}}

    def test_supported_profiles(self):
        for changes, isa in (({}, "rv32i"), ({"enableC": True}, "rv32ic"),
                             ({"enableM": True}, "rv32im"),
                             ({"enableM": True, "enableC": True}, "rv32imc"),
                             ({"enableZba": True, "enableZbb": True, "enableZbs": True}, "rv32ib")):
            self.assertEqual(select_isa(self.parameters(**changes)), isa)

    def test_unsupported_scope_is_not_a_pass(self):
        for changes in ({"enableA": True}, {"enableDebug": True}, {"enableZba": True}):
            with self.assertRaises(ValueError):
                select_isa(self.parameters(**changes))

    def test_status_requires_actual_pass_even_with_exit_zero(self):
        with tempfile.TemporaryDirectory() as name:
            path = Path(name)
            for status, code, accepted in (("PASS", 0, True), ("FAIL", 0, False), ("UNKNOWN", 0, False),
                                            ("PASS", 1, False), ("PASS", None, False)):
                (path / "status").write_text(status + "\n")
                self.assertEqual(task_status(path, code), (status, accepted))
            (path / "status").write_text("PASS 0 54\n")
            self.assertEqual(task_status(path, 0), ("PASS", True))
            for invalid in ("PASS unchecked", "PASS 0", "PASS 0 54 extra"):
                (path / "status").write_text(invalid)
                self.assertFalse(task_status(path, 0)[1])
            (path / "status").unlink()
            self.assertEqual(task_status(path, 0), ("MISSING", False))

    def test_task_manifest_is_exact_and_nonempty(self):
        check_task_set(["a", "b"], ["b", "a"])
        for expected, actual in (([], []), (["a"], []), (["a"], ["a", "b"]), (["a", "a"], ["a"])):
            with self.assertRaises(ValueError):
                check_task_set(expected, actual)

    def test_mutations_are_exact_or_rejected(self):
        text = "assign rvfi_order = retire_order;"
        self.assertIn("retire_order + 64'd1", mutation(text, "order"))
        for source in ("", text + text):
            with self.assertRaises(ValueError):
                mutation(source, "order")
        with self.assertRaises(ValueError):
            mutation(text, "unknown")

    def test_instruction_filter_does_not_omit_unrelated_families(self):
        config = configuration("rv32imc", "insn", 64, [Path("core.sv")], "addi")
        self.assertIn("+ insn_addi_ch0$", config)
        self.assertIn("`define RISCV_FORMAL_MEM_FAULT", config)
        self.assertNotIn("assume(!rvfi_trap", config)

    def test_negative_control_requires_an_actual_vcd_mismatch(self):
        with tempfile.TemporaryDirectory() as name:
            directory = Path(name)
            engine = directory / "engine_0"
            engine.mkdir()
            trace = engine / "trace.vcd"
            prefix = ("$scope module rvfi_testbench $end\n$scope module wrapper $end\n"
                      "$var wire 1 a rvfi_valid $end\n$var wire 64 b rvfi_order $end\n"
                      "$var wire 64 c expected_order $end\n$upscope $end\n$upscope $end\n"
                      "$enddefinitions $end\n#0\n1a\nb0 b\nb0 c\n#10\n")
            trace.write_text(prefix)
            with self.assertRaisesRegex(RuntimeError, "no intended mismatch"):
                counterexample_witness(directory, "order")
            trace.write_text(prefix + "b1 b\n#20\n")
            self.assertTrue(counterexample_witness(directory, "order")["mismatchObserved"])

    def test_contract_uses_a_general_register_anchor(self):
        config = configuration("rv32i", "contract", 16, [Path("core.sv")])
        self.assertIn("reg 1 16", config)
        self.assertIn("DITDAH_E2_RVFI_CONTRACT", config)
        self.assertNotIn("ill 16", config)

    def test_abc_compatibility_preserves_the_native_task(self):
        with tempfile.TemporaryDirectory() as name:
            directory = Path(name)
            path = directory / "task.sby"
            text = "[options]\nmode bmc\nskip 16\ndepth 17\n[engines]\nabc bmc3\n"
            path.write_text(text)
            configure_replay(directory, "bmc3")
            self.assertEqual(path.with_suffix(".upstream.sby").read_text(), text)
            self.assertIn("depth 17", path.read_text())
            self.assertIn("abc bmc3", path.read_text())
            self.assertIn("aigsmt z3", path.read_text())
            self.assertNotIn("skip 16", path.read_text())

    def test_protected_profiles_declare_real_user_mode(self):
        config = configuration("rv32imc", "csr", 32, [Path("core.sv")], user_mode=True)
        self.assertIn("RISCV_FORMAL_UMODE", config)
        self.assertIn("csrw_mscratch 32", config)
        self.assertNotIn("csrw_mstatus ", config)
        self.assertNotIn("31a m rw", config)
        machine = configuration("rv32i", "csr", 32, [Path("core.sv")])
        self.assertIn("31a m rw", machine)

    def test_arithmetic_models_use_a_separate_recorded_bound(self):
        config = configuration("rv32imc", "insn", 16, [Path("core.sv")], arithmetic_depth=64)
        self.assertIn("insn 16", config)
        self.assertIn("insn_(mul|mulh|mulhsu|mulhu|div|divu|rem|remu) 64", config)

    def test_exact_task_selection_rejects_unknown_and_duplicate_names(self):
        self.assertEqual(select_tasks(["bus_imem_ch0", "bus_dmem_ch0"], ["bus_imem_ch0"]), ["bus_imem_ch0"])
        for names in (["missing"], ["bus_imem_ch0", "bus_imem_ch0"]):
            with self.assertRaises(ValueError):
                select_tasks(["bus_imem_ch0"], names)

    def test_operand_bootstrap_keeps_real_rvfi_signals(self):
        source = (Path(__file__).parent / "rvfi_wrapper.sv").read_text()
        adapted, word = m_operand_wrapper(source, "mul")
        self.assertEqual(word, 0x022081b3)
        self.assertIn("assign rvfi_rs1_rdata = retire_rs1Data;", adapted)
        self.assertIn("assign rvfi_rd_wdata = retire_writes ? retire_value : 32'b0;", adapted)
        self.assertIn("assert(rvfi_rs1_rdata == m_operand_left)", adapted)
        self.assertNotIn("assume(", adapted)
        self.assertIn("rvfi_m_memory #(.DATA(1)) data_peer", adapted)
        for name, word in (("div", 0x0220c1b3), ("remu", 0x0220f1b3)):
            self.assertEqual(m_operand_wrapper(source, name)[1], word)
        for invalid in ("addi", "c_mul", None):
            with self.assertRaises(ValueError):
                m_operand_wrapper(source, invalid)
        with self.assertRaises(ValueError):
            m_operand_wrapper(source.replace("rvfi_memory data_peer (", ""), "mul")

    def test_csr_identity_fix_rejects_an_unknown_upstream_checker(self):
        with tempfile.TemporaryDirectory() as name:
            suite = Path(name)
            (suite / "checks").mkdir()
            path = suite / "checks/rvfi_csrc_any_check.sv"
            original = "wire csr_insn_under_test = (csr_insn_addr == changed);\n"
            path.write_text(original)
            with self.assertRaisesRegex(ValueError, "pinned original"):
                csrc_identity_compatibility(suite)
            self.assertEqual(path.read_text(), original)

    def test_timeout_reaps_the_child_and_records_incomplete_status(self):
        with tempfile.TemporaryDirectory() as name:
            directory = Path(name)
            record = execute([sys.executable, "-c", "import time; time.sleep(10)"],
                             directory, directory / "task", 0.05)
            self.assertIsNone(record["exitStatus"])
            self.assertNotIn(record["pid"], ACTIVE_PROCESSES)
            self.assertEqual(json.loads((directory / "task.completion.json").read_text()), record)
            self.assertFalse(task_status(directory, record["exitStatus"])[1])

    def test_csr_guard_and_controls_preserve_the_core_connection(self):
        source = (Path(__file__).parent / "rvfi_wrapper.sv").read_text()
        for control in (None, "legal-value", "illegal-write"):
            adapted = csr_guard_wrapper(source, control)
            self.assertIn(".retire_csr_readData(retire_csr_readData)", adapted)
            self.assertIn(".retire_csr_writeMask(retire_csr_writeMask)", adapted)
            self.assertIn("rvfi_csr_guard csr_guard", adapted)
            self.assertNotIn("assume(", adapted)
        with self.assertRaises(ValueError):
            csr_guard_wrapper(source, "unknown")

    def test_csr_counterexamples_require_the_intended_effect(self):
        with tempfile.TemporaryDirectory() as name:
            directory = Path(name)
            engine = directory / "engine_0"
            engine.mkdir()
            trace = engine / "trace.vcd"
            header = ("$scope module rvfi_testbench $end\n$scope module checker_inst $end\n"
                      "$var wire 1 a rvfi_valid $end\n$var wire 1 b rvfi_trap $end\n"
                      "$var wire 12 c csr_insn_addr $end\n$var wire 1 d check $end\n"
                      "$var wire 32 e csr_insn_rdata $end\n$var wire 32 f wdata_shadow $end\n"
                      "$var wire 32 g csr_insn_rmask $end\n$var wire 1 h csr_written $end\n"
                      "$upscope $end\n$upscope $end\n$enddefinitions $end\n#0\n")
            trace.write_text(header + "1a\n0b\nb1101000000 c\n1d\nb1 e\nb0 f\n"
                             "b11111111111111111111111111111111 g\n1h\n#10\n")
            self.assertTrue(counterexample_witness(directory, "csr-legal-value")["mismatchObserved"])
            with self.assertRaises(RuntimeError):
                counterexample_witness(directory, "csr-illegal-write")
            header = ("$scope module wrapper $end\n$scope module illegal_effects $end\n"
                      "$scope module csr_guard $end\n$var wire 1 a valid $end\n"
                      "$var wire 1 b trap $end\n$var wire 1 g csr_opcode $end\n"
                      "$var wire 32 h write_mask $end\n$upscope $end\n$upscope $end\n"
                      "$upscope $end\n$enddefinitions $end\n#0\n")
            trace.write_text(header + "1a\n1b\n1g\nb1 h\n#10\n")
            self.assertTrue(counterexample_witness(directory, "csr-illegal-write")["mismatchObserved"])

    def test_reachability_adapter_adds_a_goal_without_assumptions(self):
        source = (Path(__file__).parent / "rvfi_wrapper.sv").read_text()
        adapted = reachability_wrapper(source)
        self.assertIn("assert(!(rvfi_valid && !rvfi_trap))", adapted)
        self.assertIn("RISCV_FORMAL_CHECK_CYCLE", adapted)
        self.assertNotIn("assume(", adapted)
        self.assertIn("assign rvfi_insn = retire_insn;", adapted)

    def test_reachability_rejects_an_original_semantic_assertion_failure(self):
        with tempfile.TemporaryDirectory() as name:
            directory = Path(name)
            wrapper = directory / "rvfi_wrapper.sv"
            wrapper.write_text("assert(!(rvfi_valid && !rvfi_trap));\n")
            log = directory / "logfile.txt"
            log.write_text(f"Assert failed in rvfi_testbench: {wrapper}:1.1-1.40\n")
            self.assertTrue(reachability_failure(directory, wrapper)["onlyInjectedGoalFailed"])
            log.write_text(log.read_text() + "Assert failed in rvfi_testbench: rvfi_insn_check.sv:170.1-170.20\n")
            with self.assertRaisesRegex(RuntimeError, "original assertion"):
                reachability_failure(directory, wrapper)

    def test_fetch_fault_controls_preserve_the_real_core_signals(self):
        source = (Path(__file__).parent / "rvfi_wrapper.sv").read_text()
        for control in (None, "data-value", "fault-effect", "fault-cause"):
            adapted = fault_guard_wrapper(source, control)
            self.assertIn(".retire_memoryFault(retire_memoryFault)", adapted)
            self.assertIn(".retire_cause(retire_cause)", adapted)
            self.assertIn("rvfi_fault_guard fault_guard", adapted)
            self.assertNotIn("assume(", adapted)
        with self.assertRaises(ValueError):
            fault_guard_wrapper(source.replace("assign rvfi_insn = retire_insn;", ""), "data-value")
        with tempfile.TemporaryDirectory() as name:
            suite = Path(name)
            (suite / "checks").mkdir()
            path = suite / "checks/rvfi_bus_imem_check.sv"
            path.write_text("unknown source")
            with self.assertRaisesRegex(ValueError, "pinned original"):
                imem_fault_compatibility(suite)
            self.assertEqual(path.read_text(), "unknown source")

    def test_fetch_fault_counterexample_requires_typed_fault_and_bad_effect(self):
        with tempfile.TemporaryDirectory() as name:
            directory = Path(name)
            (directory / "engine_0").mkdir()
            trace = directory / "engine_0/trace.vcd"
            header = ("$scope module wrapper $end\n$scope module fault_guard $end\n"
                      "$var wire 1 a valid $end\n$var wire 1 b trap $end\n"
                      "$var wire 1 c typed_ifetch_fault $end\n$var wire 4 d normal_rmask $end\n"
                      "$var wire 32 e cause $end\n$upscope $end\n$upscope $end\n"
                      "$enddefinitions $end\n#0\n1a\n1b\n")
            trace.write_text(header + "0c\nb1 d\nb0 e\n#10\n")
            for control in ("ifetch-fault-effect", "ifetch-fault-cause"):
                with self.assertRaises(RuntimeError):
                    counterexample_witness(directory, control)
            trace.write_text(header + "1c\nb1 d\nb0 e\n#10\n")
            for control in ("ifetch-fault-effect", "ifetch-fault-cause"):
                self.assertTrue(counterexample_witness(directory, control)["mismatchObserved"])

    def test_disabled_cover_removal_preserves_all_other_model_objects(self):
        model = self.typed_cover_model()
        adjusted, record = disabled_typed_cover_model(model, "bus_imem_fault_ch0")
        self.assertEqual(record["configurationDisabled"], 1)
        self.assertEqual(record["coversAfter"], 1)
        self.assertIn("disabled", model["modules"]["rvfi_testbench"]["cells"])
        for name in ("active", "assertion", "assumption"):
            self.assertEqual(adjusted["modules"]["rvfi_testbench"]["cells"][name],
                             model["modules"]["rvfi_testbench"]["cells"][name])

    def test_disabled_cover_removal_rejects_unknown_points_and_wrong_channels(self):
        for change in ("unknown-source", "wrong-signal", "wrong-role", "extra-disabled"):
            model = self.typed_cover_model()
            top = model["modules"]["rvfi_testbench"]
            if change == "unknown-source":
                top["cells"]["disabled"]["attributes"]["src"] = "checker.sv:999.1-999.2"
            elif change == "wrong-signal":
                top["cells"]["disabled"]["connections"]["A"] = [2]
            elif change == "wrong-role":
                top["netnames"]["rvfi_bus_insn"]["bits"] = ["0", "1"]
            else:
                top["cells"]["active"]["connections"]["EN"] = ["0"]
            with self.assertRaises(ValueError):
                disabled_typed_cover_model(model, "bus_imem_fault_ch0")

    def test_disabled_cover_removal_cannot_delete_an_assertion_or_assumption(self):
        original = self.typed_cover_model()
        for name in ("assertion", "assumption"):
            candidate = json.loads(json.dumps(original))
            del candidate["modules"]["rvfi_testbench"]["cells"][name]
            with self.assertRaisesRegex(ValueError, "cannot delete"):
                validate_cover_removal(original, candidate, [name])


if __name__ == "__main__":
    unittest.main()
