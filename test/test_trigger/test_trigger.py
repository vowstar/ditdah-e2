# SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
# SPDX-License-Identifier: MIT
"""Check trigger vector, wrapper and mutation inventories."""

import tempfile
import unittest
from pathlib import Path

from formal.trigger.run import CASES, CORE_ASSERTIONS, UNIT_ASSERTIONS, check_wrappers
from test.test_trigger.trigger import Reference, mutate, vectors
from test.test_trigger.verify_trigger import (
    FINISH,
    cases,
    multiply,
    mutate_copy,
    native_program,
)


class TriggerTests(unittest.TestCase):
    def test_directed_vectors_cover_all_unit_events(self):
        rows = vectors()
        reference = Reference()
        for cycle, values in enumerate(rows):
            reference.step(values, cycle)
        for name in ("hit0", "hit1", "debugAction", "nativeAction", "trap", "mret"):
            self.assertGreater(reference.counts[name], 0)
        self.assertEqual(len(rows), 364)

    def test_unit_mutations_require_unique_anchors(self):
        source = ("assign core_nativeAction = core_ready & core_matched_0 & ~core_debugAction_0;\n"
                  "hit <= core_ready & _GEN_141 | (_GEN_96 ? writeData[20] : hit);\n"
                  "& (core_user | debugAction | mte) & core_pc == address_0;")
        self.assertIn("core_matched_0;", mutate(source, "priority"))
        self.assertNotIn("core_ready & _GEN_141", mutate(source, "hit"))
        self.assertIn("1'b1", mutate(source, "address"))
        for name in ("priority", "hit", "address"):
            with self.assertRaisesRegex(ValueError, "target changed"):
                mutate("", name)

    def test_complete_core_scenarios_are_unique_and_finished(self):
        selected = cases()
        self.assertEqual(len(selected), 9)
        self.assertEqual(len({case[0] for case in selected}), len(selected))
        for _, _, actions, _, options in selected:
            self.assertEqual(actions.rows[-1][0], FINISH)
            self.assertTrue(actions.rows)
        self.assertGreater(sum(len(case[2].expected) for case in selected), 0)
        self.assertEqual(sum(bool(case[4].get("protected")) for case in selected), 1)

    def test_native_multiply_has_real_instruction_and_retry(self):
        program, _ = native_program(multiply(5, 5, 6), retry=True)
        target = program.labels["target"]
        self.assertEqual(program.image()[target], 0x026282B3)
        self.assertNotIn(0x00438393, program.image().values())

    def test_multiply_mutation_supports_debug_gate_forms(self):
        suffix = "& ~eligibleInterrupt & ~sleeping_0 & ~x_fault"
        for gate in (" & ~_debug_core_stop", " & (~_debug_core_stop | xInjected)"):
            with self.subTest(gate=gate), tempfile.TemporaryDirectory() as directory:
                source = Path(directory) / "source"
                source.mkdir()
                (source / "DitDahE2.sv").write_text(
                    "wire multiplyDivide_request_valid =\n"
                    "    xValid & isMultiplyDivide" + suffix + gate + "\n"
                    "    & ~_csr_trigger_matched;\n")
                changed = mutate_copy(source, Path(directory) / "changed", "multiply-start")
                text = changed.read_text()
                self.assertIn(gate, text)
                self.assertNotIn("& ~_csr_trigger_matched;", text)

    def test_commercial_wrapper_inventories(self):
        unit, core = check_wrappers()
        self.assertEqual(len(UNIT_ASSERTIONS), 23)
        self.assertEqual(len(CORE_ASSERTIONS), 21)
        self.assertEqual(len(CASES), 17)
        self.assertIn(b"cover_simultaneous", unit)
        self.assertIn(b"cover_older_fault", core)

    def test_commercial_dpc_sampling_and_embedded_scope(self):
        from formal.debug_transport.run import EXPECTED_RESET
        from formal.trigger.run import HERE, check_native_records

        unit, core = check_wrappers()
        self.assertIn(b"initial_common_cold_reset: assume(reset)", unit)
        self.assertNotIn(b"dpc_resume_phase", core)
        self.assertIn(b"if (dmi_phase == execution_phase && dut.debug.core_resume) abstract_dpc_value", core)
        self.assertIn(b"cover(dmi_phase == execution_phase && dut.debug.core_resume", core)
        self.assertIn(b"cover(dmi_phase == 0 && first_check && dut.debug.dpc == 0)", core)
        self.assertIn(b"3: begin\n        dmi_request_bits_address = 7'h16;", core)
        self.assertIn(b"15: dmi_request_bits_data = scenario == 1 ? 32'h123 : handler;", core)
        self.assertIn(b"16: dmi_request_bits_data = scenario == 1 ? 32'h231006 : 32'h230305;", core)
        self.assertIn(b"24: dmi_request_bits_data = 32'h40000001;", core)
        self.assertIn(b"dmi_phase == 20 || dmi_phase == 23", core)
        self.assertIn(b"cover_target_breakpoint", core)
        self.assertIn(b"cover_older_load_accepted", core)
        self.assertIn(b"cover_metadata_complete", core)
        self.assertIn(b"dmi_response_bits_data[10:8] == 0", core)
        self.assertNotIn(b"32'h2307a0", core)
        collector = (HERE / "collect.tcl").read_text()
        self.assertIn("prove -property [list $item] -engine_mode B -iter 96", collector)
        for name in ("collect_safety.tcl", "collect_trace.tcl"):
            core_collector = (HERE / name).read_text()
            self.assertIn("dut.csr.mtvec == 0", core_collector)
            self.assertIn("dut.multiplyDivide.active == 0", core_collector)
            self.assertIn("dut.multiplyDivide.valid == 0", core_collector)
        safety_collector = (HERE / "collect_safety.tcl").read_text()
        self.assertIn("foreach group $proof_groups", safety_collector)
        self.assertIn("record group.$group_serial per_engine_max_jobs $jobs", safety_collector)
        self.assertIn("proof_seed group_serial bounds", safety_collector)
        self.assertIn("set failures {}", safety_collector)
        self.assertIn("attempt_group $configuration(labels) $configuration(bound)", safety_collector)
        top = "trigger_core_formal"
        plan = {"top": top, "assumptions": [top + ".no_later_cold_reset"],
                "goals": [], "covers": [], "expected": "proven"}
        scope = {"clock": "", "reset": EXPECTED_RESET,
                 "global": top + ".initial_common_cold_reset " + top + ".no_later_cold_reset",
                 "reset_initial": "assume:0", "initial_common_cold_reset": "1",
                 "assumptions": top + ".no_later_cold_reset", "reset_assumptions": ""}
        records = {("run", "state"): "complete", ("setup", "clock_mode"): "free_running"}
        records.update({("setup", key): "0" for key in ("bbox_inst", "bbox_mod", "bbox_out", "stopat")})
        records.update({(tag, key): value for tag in ("before", "after") for key, value in scope.items()})
        self.assertEqual(check_native_records(records, plan),
                         {"goals": 0, "covers": 0, "verdict": "proven"})
        records[("after", "global")] = top + ".no_later_cold_reset"
        with self.assertRaisesRegex(ValueError, "global embedded assumption set"):
            check_native_records(records, plan)

    def test_mixed_bounds_and_bounded_verdict(self):
        from formal.debug_transport.run import EXPECTED_RESET
        from formal.trigger.run import (
            SAFETY_STRATEGY,
            check_native_records,
            goal_bounds,
        )

        self.assertEqual(goal_bounds(1)[0], 352)
        self.assertEqual(goal_bounds(1)[1]["native_epc_metadata"], 176)
        self.assertEqual(goal_bounds(1)[1]["target_first_event_is_breakpoint"], 160)
        self.assertEqual(goal_bounds(1)[1]["abstract_dpc_value"], 128)
        self.assertEqual(goal_bounds(0)[1]["abstract_dpc_value"], 112)
        self.assertEqual(goal_bounds(0)[0], 288)
        self.assertEqual(goal_bounds(0)[1]["target_first_event_is_breakpoint"], 128)
        top = "trigger_core_formal"
        label = "native_epc_metadata"
        plan = {"top": top, "assumptions": [top + ".no_later_cold_reset"], "goals": [label], "covers": [],
                "expected": "proven", "proofMode": "bounded_commercial", "targetBounds": {label: 160}}
        scope = {"clock": "", "reset": EXPECTED_RESET,
                 "global": top + ".initial_common_cold_reset " + top + ".no_later_cold_reset",
                 "reset_initial": "assume:0", "initial_common_cold_reset": "1",
                 "assumptions": top + ".no_later_cold_reset", "reset_assumptions": ""}
        records = {("run", "state"): "complete", ("setup", "clock_mode"): "free_running"}
        records.update({("setup", key): "0" for key in ("bbox_inst", "bbox_mod", "bbox_out", "stopat")})
        records.update({(tag, key): value for tag in ("before", "after") for key, value in scope.items()})
        identity = {"name": top + "." + label, "type": "assert", "command": "assert", "disabled": "0",
                    "expression": label, "precondition": "0", "clock": "clock", "edge": "posedge"}
        for tag, verdict, run_status in (("before", "unknown", "unprocessed"),
                                         ("final", "undetermined", "processed")):
            records.update({(tag + "." + label, key): value for key, value in identity.items()})
            records[tag + "." + label, "validity_status"] = verdict
            records[tag + "." + label, "run_status"] = run_status
        records.update({("bounded." + label, key): value for key, value in identity.items()})
        records["bounded." + label, "validity_status"] = "bounded_proven_user"
        records["bounded." + label, "run_status"] = "processed"
        records["bounded." + label, "engine"] = "B"
        records["bounded." + label, "min_length"] = "160"
        records["bounded." + label, "target_bound"] = "160"
        records["lemma.dpc_resume_phase", "validity_status"] = "proven"
        records["lemma.dpc_resume_phase", "engine"] = "Hps"
        records["lemma.dpc_resume_phase", "min_length"] = "infinite"
        records["lemma.dpc_resume_phase", "target_bound"] = "0"
        result = check_native_records(records, plan)
        self.assertEqual(result["boundedGoals"], 1)
        self.assertEqual(result["unboundedGoals"], 0)
        self.assertEqual(result["propertyEvidence"][label]["targetBound"], 160)
        records["bounded." + label, "min_length"] = "159"
        with self.assertRaisesRegex(ValueError, "bounded proof is incomplete"):
            check_native_records(records, plan)
        records["bounded." + label, "min_length"] = "160"
        plan.update(proofStrategy=dict(SAFETY_STRATEGY), traceBound=160, timeLimitSeconds=600)
        plan["targetBounds"]["abstract_dpc_value"] = 112
        with self.assertRaisesRegex(ValueError, "grouped proof strategy"):
            check_native_records(records, plan)
        groups = (
            (1, {"bound": "112", "engines": "C I N", "per_engine_max_jobs": "2",
                 "time_limit": "2400", "per_property_time_limit": "2400"}),
            (2, {"bound": "0", "engines": "C I N", "per_engine_max_jobs": "1",
                 "time_limit": "600s", "per_property_time_limit": "600s"}),
            (3, {"bound": "160", "engines": "C I N B", "per_engine_max_jobs": "4",
                 "time_limit": "7200", "per_property_time_limit": "2400"}),
        )
        for group, values in groups:
            records.update({(f"group.{group}", key): value for key, value in values.items()})
        self.assertEqual(check_native_records(records, plan)["boundedGoals"], 1)
        plan["scenario"] = 1
        records.update({("group.4", key): value for key, value in groups[2][1].items()})
        records.update({("group.3", key): value for key, value in
                        {"bound": "160", "engines": "K", "per_engine_max_jobs": "1",
                         "time_limit": "2400", "per_property_time_limit": "2400"}.items()})
        self.assertEqual(check_native_records(records, plan)["boundedGoals"], 1)

    def test_proof_seed_is_frozen_and_scoped(self):
        from formal.debug_transport.run import sha
        from formal.trigger.run import (
            CORE_TOP,
            UNIT_TOP,
            case_definition,
        )

        wrappers = {UNIT_TOP: b"unit", CORE_TOP: b"core"}
        collectors = {role: b"" for role in ("legacy", "safety", "multiply_retry", "safety_retry", "trace")}
        plan, contents = case_definition("core-store-safety", {"unit.sv": b"u"}, {"core.sv": b"c"}, wrappers,
                                         collectors, 120, 600, b"seed")
        self.assertEqual(contents["proof_seed.jdb"], b"seed")
        self.assertEqual(plan["proofSeed"]["sha256"], sha(b"seed"))
        self.assertIn(b"set proof_seed proof_seed.jdb", contents["plan.tcl"])
        other, other_contents = case_definition("core-multiply-safety", {"unit.sv": b"u"}, {"core.sv": b"c"}, wrappers,
                                                collectors, 120, 600, b"seed")
        self.assertNotIn("proof_seed.jdb", other_contents)
        self.assertNotIn("proofSeed", other)
        for scenario, name in ((2, "core-illegal-safety"), (3, "core-older-safety")):
            seeded, seeded_contents = case_definition(
                name, {"unit.sv": b"u"}, {"core.sv": b"c"}, wrappers, collectors, 120, 600, b"seed",
                {scenario: b"scenario-seed"})
            filename = f"proof_seed_scenario{scenario}.jdb"
            self.assertEqual(seeded_contents[filename], b"scenario-seed")
            self.assertEqual(seeded["proofSeed"]["sha256"], sha(b"scenario-seed"))
            self.assertIn(f"set proof_seed {filename}".encode(), seeded_contents["plan.tcl"])

    def test_older_negative_mutation_keeps_target_valid(self):
        from formal.trigger.run import CORE_RTL, mutate

        source = "_GEN_466 = redirect_0 | returning | waiting | waking | synchronized;\n"
        changed = mutate({CORE_RTL: source.encode()}, "negative-older-priority")
        self.assertIn(b"_GEN_466 = 1'h0;", changed[CORE_RTL])
        with self.assertRaisesRegex(ValueError, "Mutation anchor differs"):
            mutate({CORE_RTL: b"mValid <= 1'h0;\n"}, "negative-older-priority")


if __name__ == "__main__":
    unittest.main()
