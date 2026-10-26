# SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
# SPDX-License-Identifier: MIT
"""Check the PMP fault program and counterexample acceptance."""

from pathlib import Path
import re
import unittest
from unittest.mock import patch

from model import Model
from pmp_data_formal import (DEPENDENCIES, PROOF_ENGINE, completion_witness, configuration, forbidden_witness,
                             mutate_denial, observe_rtl, replay_completion, select_contracts)


def words(machine, store):
    content = Path(__file__).with_name("pmp_data_formal.sv").read_text()
    result = {}
    for address, expression in re.findall(r"^\s+(\d+): rom = ([^;]+);", content, re.MULTILINE):
        constants = [int(value, 16) for value in re.findall(r"32'h([0-9a-f]+)", expression)]
        if "MACHINE" in expression:
            word = constants[0 if machine else 1]
        elif "STORE" in expression:
            word = constants[0 if store else 1]
        else:
            word = constants[0]
        result[int(address)] = word
    result[148] = 0x6f
    result[4092] = 0x12345678
    return result


class ProgramTests(unittest.TestCase):
    def test_fixed_programs_reach_the_expected_local_fault(self):
        for machine in (False, True):
            for store in (False, True):
                with self.subTest(machine=machine, store=store):
                    model = Model(words(machine, store), protected_mode=True)
                    events = []
                    for _ in range(24):
                        event = model.step()
                        events.append(event)
                        if event.pc == 148:
                            break
                    faults = [event for event in events if event.trap]
                    self.assertEqual(len(faults), 1)
                    self.assertEqual((faults[0].pc, faults[0].cause, faults[0].tval), (68, 7 if store else 5, 4096))
                    self.assertEqual(faults[0].user_mode, not machine)
                    self.assertEqual(model.registers[4], 0x12345678)
                    self.assertEqual(model.registers[8], 90)
                    self.assertEqual(model.registers[9], 0x1800 if machine else 0)
                    self.assertEqual(events[-1].pc, 148)

    def test_cover_schedule_is_absent_from_safety(self):
        for mode in ("denial", "retention", "cover", "negative", "replacement"):
            text, engine = configuration(["core.sv", "wrapper.sv"], 3, mode, 128)
            self.assertEqual("-DREACHABILITY" in text, mode in ("cover", "replacement"))
            self.assertIn("chparam -set SCENARIO 3", text)
            self.assertEqual(engine, PROOF_ENGINE if mode in DEPENDENCIES else "abc bmc3")
            self.assertEqual("UNRESTRICTED_PEER" in text, mode in DEPENDENCIES)
            self.assertEqual("-DREPLACE_PEER" in text, mode in DEPENDENCIES or mode == "replacement")
            self.assertEqual("REPLACEMENT_WITNESS" in text, mode == "replacement")
            self.assertIn("mode prove\ndepth 3" if mode in DEPENDENCIES else "mode bmc\ndepth 128", text)

    def test_dependencies_use_the_proved_literal_contracts(self):
        wrapper = Path(__file__).with_name("pmp_data_formal.sv").read_text()
        completed = set()
        for name, dependencies in DEPENDENCIES.items():
            self.assertLessEqual(set(dependencies), completed)
            selected, hashes = select_contracts(wrapper, name)
            self.assertEqual(set(hashes), {name, *dependencies})
            self.assertEqual("assume(" in selected, bool(dependencies))
            for dependency in dependencies:
                _, earlier = select_contracts(wrapper, dependency)
                self.assertEqual(hashes[dependency], earlier[dependency])
            completed.add(name)
        with self.assertRaisesRegex(AssertionError, "Unproved source assumption"):
            select_contracts(wrapper.replace("assert(", "assume(", 1), "retention")

    def test_faulty_rtl_has_no_good_rtl_assumptions(self):
        wrapper = Path(__file__).with_name("pmp_data_formal.sv").read_text()
        selected, hashes = select_contracts(wrapper, "negative")
        self.assertEqual(set(hashes), {"bank", "denial"})
        self.assertNotIn("assume(", selected)
        self.assertIn("assert(!shadow_denied || !data_request_valid)", selected)

    def test_reachability_rejects_an_auxiliary_assertion_failure(self):
        wrapper = "assert(!finished);\nassert(retire_pc == expected_pc);\n"
        for log in ("", "failed assertion a at pmp_data_formal.sv:2.1-2.40",
                    "failed assertion a at pmp_data_formal.sv:1.1-1.20\n"
                    "failed assertion b at pmp_data_formal.sv:2.1-2.40"):
            with self.assertRaisesRegex(AssertionError, "Unexpected reachability"):
                replay_completion("", wrapper, 0, log)

    def test_instruction_replacement_keeps_the_old_response_owner(self):
        wrapper = "assert(!(finished && saw_replacement));\n  0: rom = 32'h08000093;\n  4: rom = 32'h30509073;\n"
        log = "failed assertion a at pmp_data_formal.sv:1.1-1.40"
        idle = dict.fromkeys(("reset", "instruction_request_valid", "instruction_request_ready",
                             "instruction_request_bits_address", "instruction_response_valid",
                             "instruction_response_ready", "instruction_response_bits_data",
                             "instruction_response_bits_fault", "data_response_valid", "data_response_ready",
                             "data_request_valid", "observed_csr_write", "retire_valid"), 0)
        idle["clock"] = 1
        idle.update(dict.fromkeys(("data_request_bits_" + name for name in
                                 ("address", "data", "write", "size", "mask", "operation", "machine")), 0))
        frames = [dict(idle, instruction_request_valid=1, instruction_request_ready=1),
                  dict(idle, instruction_request_valid=1, instruction_request_ready=1, instruction_request_bits_address=4,
                       instruction_response_valid=1, instruction_response_ready=1, instruction_response_bits_data=0x08000093),
                  dict(idle, instruction_response_valid=1, instruction_response_ready=1, instruction_response_bits_data=0x30509073)]
        with patch("pmp_data_formal.trace_frames", return_value=frames):
            with self.assertRaisesRegex(AssertionError, "Incomplete fault program"):
                replay_completion("", wrapper, 0, log, True)
        frames[1]["instruction_response_bits_data"] = 0x30509073
        with patch("pmp_data_formal.trace_frames", return_value=frames):
            with self.assertRaisesRegex(AssertionError, "Instruction response differs from its owner"):
                replay_completion("", wrapper, 0, log, True)
        with patch("pmp_data_formal.trace_frames", return_value=[frames[2]]):
            with self.assertRaisesRegex(AssertionError, "Instruction response lacks an owner"):
                replay_completion("", wrapper, 0, log, True)

    def test_blocked_data_request_must_keep_valid_and_payload(self):
        wrapper = "assert(!finished);\n"
        log = "failed assertion a at pmp_data_formal.sv:1.1-1.20"
        frame = dict.fromkeys(("reset", "instruction_request_valid", "instruction_request_ready",
                              "instruction_response_valid", "instruction_response_ready", "data_response_valid",
                              "data_response_ready", "data_request_ready", "observed_csr_write", "retire_valid"), 0)
        frame.update(clock=1, data_request_valid=1)
        frame.update({"data_request_bits_" + name: value for name, value in
                      zip(("address", "data", "write", "size", "mask", "operation", "machine"), (4092, 0, 0, 2, 0, 0, 0))})
        for changed in (dict(frame, data_request_valid=0), dict(frame, data_request_bits_data=1)):
            with patch("pmp_data_formal.trace_frames", return_value=[frame, changed]):
                with self.assertRaisesRegex(AssertionError, "Held data request changed"):
                    replay_completion("", wrapper, 0, log)

    def test_observers_add_outputs_and_preserve_original_logic(self):
        def module(name, body):
            return (f"module {name}(input clock\n);\n" + body + "\nendmodule\n").encode()
        declarations = "\n".join(f"reg [{width}:0] {stem}{'_' + str(index-1) if index else ''};"
            for stem, width in (("configs", 7), ("addresses", 29)) for index in range(16))
        rtl = {"DitDahE2.sv": module("DitDahE2", "DitDahE2Csr csr (.clock(clock)\n);\nwire preserve = clock;"),
               "DitDahE2Csr.sv": module("DitDahE2Csr", "DitDahE2Pmp pmp (.clock(clock)\n);\nwire preserve = clock;"),
               "DitDahE2Pmp.sv": module("DitDahE2Pmp", declarations + "\nwire preserve = clock;")}
        changed = observe_rtl(rtl)
        for name in rtl:
            self.assertIn(b"wire preserve = clock;", changed[name])
            self.assertEqual(changed[name].count(b"endmodule"), 1)
            self.assertIn(b"output [127:0] observed_configs", changed[name])
            self.assertNotIn(b"input observed_", changed[name])
        self.assertIn(b"assign observed_csr_data = writeData;", changed["DitDahE2Csr.sv"])
        self.assertIn(b"assign observed_active = mValid & memory & ~m_trap;", changed["DitDahE2.sv"])
        with self.assertRaisesRegex(AssertionError, "Changed PMP bank"):
            observe_rtl({**rtl, "DitDahE2Pmp.sv": rtl["DitDahE2Pmp.sv"].replace(b"configs_14;", b"missing;")})

    def test_mutant_changes_only_the_denial_decision(self):
        original = "wire denied_0 = denied & ~m_trap & ~_csr_dataProtection_allowed;\n"
        self.assertEqual(mutate_denial(original), "wire denied_0 = denied & ~m_trap & 1'b0;\n")
        for content in ("", original + original):
            with self.assertRaisesRegex(AssertionError, "target changed"):
                mutate_denial(content)

    def test_counterexample_requires_a_real_forbidden_offer(self):
        header = "$scope module pmp_data_formal $end\n" + "\n".join(
            "$var wire %d v%d %s $end" % (width, index, name) for index, (name, width) in enumerate(
                (("reset", 1), ("data_request_valid", 1), ("data_request_bits_address", 32), ("forbidden_request", 1))))
        header += "\n$var wire 1 v4 shadow_configured $end\n$var wire 1 v5 shadow_denied $end\n$var wire 32 v6 observed_pc $end"
        trace = header + "\n$upscope $end\n$enddefinitions $end\n#0\nb0 v0\nb1 v1\nb1000000000000 v2\nb1 v3\nb1 v4\nb1 v5\nb1000100 v6\n#10\n"
        self.assertEqual(forbidden_witness(trace)["data_request_bits_address"], 4096)
        for changed in (trace.replace("b0 v0", "b1 v0"), trace.replace("b1 v1", "b0 v1"),
                        trace.replace("b1000000000000 v2", "b1000000000100 v2"),
                        trace.replace("b1 v4", "b0 v4"), trace.replace("b1 v5", "b0 v5"),
                        trace.replace("b1000100 v6", "b1001000 v6")):
            with self.assertRaisesRegex(AssertionError, "No forbidden"):
                forbidden_witness(changed)

    def test_reachability_requires_the_allowed_read_and_completed_trap_handler(self):
        names = (("reset", 1), ("saw_allowed", 1), ("saw_denied", 1), ("finished", 1), ("retire_pc", 32))
        header = "$scope module pmp_data_formal $end\n" + "\n".join(
            "$var wire %d v%d %s $end" % (width, index, name) for index, (name, width) in enumerate(names))
        trace = header + "\n$upscope $end\n$enddefinitions $end\n#0\nb0 v0\nb1 v1\nb1 v2\nb1 v3\nb10010100 v4\n#10\n"
        self.assertEqual(completion_witness(trace)["retire_pc"], 148)
        for index in (1, 2, 3):
            with self.assertRaisesRegex(AssertionError, "No complete"):
                completion_witness(trace.replace(f"b1 v{index}", f"b0 v{index}"))


if __name__ == "__main__":
    unittest.main()
