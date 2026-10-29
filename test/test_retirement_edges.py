# SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
# SPDX-License-Identifier: MIT
"""Reject ineffective edge stimuli and corrupted fault/reset observations."""

import copy
import json
from pathlib import Path
import tempfile
import unittest

from retirement_edges import (EdgeFailure, FixtureError, INTERRUPT_KEYS, RETIREMENT_KEYS,
                              SCHEMA, check_observation, digest, parse_observation, validate_inputs)


def retirement(word, index, rd=0, value=0):
    row = dict.fromkeys(RETIREMENT_KEYS, 0)
    row.update(pc=index * 4, raw=word, insn=word, order=index, length=4,
               rd=rd, writes=int(rd != 0), value=value, status_before=0x1800, status_after=0x1800)
    return row


def fault_observation():
    rows = [retirement(0x10000093, 0, 1, 0x100), retirement(0x05500113, 1, 2, 0x55),
            retirement(0x0020A1AF, 2)]
    rows[-1].update(insn=0, trap=1, cause=1, tval=8, fault=1)
    return {"schema": SCHEMA, "case": "fetch-fault-atomic", "retired": rows,
            "data_offers": 0, "fault_responses": 1}


def reset_observation():
    def scenario(reset):
        rows = [retirement(0x08000093, 0, 1, 0x80), retirement(0x30409073, 1),
                retirement(0x00800093, 2, 1, 8), retirement(0x30009073, 3),
                retirement(0x10500073, 4)]
        eligible = dict.fromkeys(INTERRUPT_KEYS, 0)
        eligible.update(valid=1, sleeping=1, pc=20, cause=0x80000007,
                        status_before=0x1808, status_after=0x1880, epc_after=20,
                        cause_after=0x80000007)
        observed = dict(eligible, valid=0) if reset else eligible.copy()
        stored = dict.fromkeys(INTERRUPT_KEYS, 0)
        stored.update(status_before=0x1800 if reset else 0x1880,
                      epc_before=0 if reset else 20, cause_before=0 if reset else 0x80000007)
        return {"retired": rows, "eligible": eligible, "observed": observed,
                "stored": stored, "data_offers": 0}
    return {"schema": SCHEMA, "case": "reset-irq", "positive": scenario(False), "reset": scenario(True)}


class ObservationTests(unittest.TestCase):
    def test_both_reached_edges_pass(self):
        self.assertEqual(check_observation(fault_observation())["faultPackets"], 1)
        self.assertEqual(check_observation(reset_observation())["positiveIrqEntries"], 1)

    def test_old_fetch_fault_operand_is_a_behavior_failure(self):
        row = fault_observation()
        row["retired"][-1]["operand"] = 0x55
        with self.assertRaisesRegex(EdgeFailure, "inactive observations: operand"):
            check_observation(row)

    def test_each_inactive_operand_mask_and_response_is_checked(self):
        for field in ("insn", "rd", "writes", "value", "rs1", "rs1_data", "rs2", "rs2_data",
                      "memory_address", "read_mask", "write_mask", "read_data", "write_data",
                      "operation", "operand", "response", "fault_read_mask", "fault_write_mask",
                      "csr_valid", "csr_read_mask", "csr_write_mask"):
            row = fault_observation()
            row["retired"][-1][field] = 1
            with self.subTest(field=field), self.assertRaises(EdgeFailure):
                check_observation(row)

    def test_data_request_is_a_behavior_failure(self):
        row = fault_observation()
        row["data_offers"] = 1
        with self.assertRaisesRegex(EdgeFailure, "data_offers"):
            check_observation(row)

    def test_uninitialized_rs2_is_an_invalid_fixture(self):
        row = fault_observation()
        row["retired"][1]["value"] = 0
        with self.assertRaisesRegex(FixtureError, "Setup GPR"):
            check_observation(row)

    def test_missing_fault_and_wrong_raw_are_invalid_fixtures(self):
        for key, value in (("fault_responses", 0), ("raw", 0x13), ("cause", 2)):
            row = fault_observation()
            if key == "fault_responses":
                row[key] = value
            else:
                row["retired"][-1][key] = value
            with self.subTest(key=key), self.assertRaises(FixtureError):
                check_observation(row)

    def test_old_reset_irq_valid_is_a_behavior_failure(self):
        row = reset_observation()
        row["reset"]["observed"]["valid"] = 1
        with self.assertRaisesRegex(EdgeFailure, "reset-active"):
            check_observation(row)

    def test_reset_retirement_valid_is_also_rejected(self):
        row = reset_observation()
        row["reset"]["observed"]["retire_valid"] = 1
        with self.assertRaises(EdgeFailure):
            check_observation(row)

    def test_disabled_irq_and_nonempty_m_do_not_count_as_counterexamples(self):
        for field, value in (("valid", 0), ("retire_valid", 1), ("sleeping", 0),
                             ("status_before", 0x1800), ("cause", 0x8000000B)):
            row = reset_observation()
            row["reset"]["eligible"][field] = value
            with self.subTest(field=field), self.assertRaises(FixtureError):
                check_observation(row)

    def test_actual_positive_and_reset_storage_are_required(self):
        for phase, field, value in (("positive", "cause_before", 0), ("reset", "epc_before", 20)):
            row = reset_observation()
            row[phase]["stored"][field] = value
            with self.subTest(phase=phase), self.assertRaises(FixtureError):
                check_observation(row)

    def test_schema_duplicates_missing_extra_and_invalid_numbers(self):
        for changes in ({"schema": "unknown"}, {"extra": 0}):
            row = fault_observation() | changes
            with self.assertRaises(FixtureError):
                check_observation(row)
        row = fault_observation()
        del row["retired"][-1]["operand"]
        with self.assertRaises(FixtureError):
            check_observation(row)
        for value in (True, -1, 1 << 32, 1.0):
            row = fault_observation()
            row["retired"][0]["value"] = value
            with self.subTest(value=value), self.assertRaises(FixtureError):
                check_observation(row)
        with self.assertRaisesRegex(FixtureError, "Duplicate"):
            parse_observation('{"schema":"a","schema":"b"}')
        with self.assertRaises(FixtureError):
            parse_observation('{')


class BindingTests(unittest.TestCase):
    def test_frozen_source_root_and_rtl_must_match_manifest(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            rtl, source = base / "rtl", base / "source"
            rtl.mkdir()
            source.mkdir()
            (rtl / "DitDahE2.sv").write_text("module DitDahE2; endmodule\n")
            (source / "core.scala").write_text("source\n")
            manifest = {"parameters": {"resetVector": 0, "enableC": False, "enableA": True,
                                        "protectedMode": False, "enableDebug": False},
                        "top": "DitDahE2", "exitStatus": 0,
                        "rtlHashes": {"DitDahE2.sv": digest(rtl / "DitDahE2.sv")},
                        "sourceHashes": {"core.scala": digest(source / "core.scala")}}
            (rtl / "manifest.json").write_text(json.dumps(manifest))
            self.assertEqual(validate_inputs(rtl, source, ["fetch-fault-atomic"]), manifest)
            (source / "core.scala").write_text("changed\n")
            with self.assertRaisesRegex(FixtureError, "Source input changed"):
                validate_inputs(rtl, source, ["reset-irq"])
            (source / "core.scala").write_text("source\n")
            (rtl / "DitDahE2.sv").write_text("changed\n")
            with self.assertRaisesRegex(FixtureError, "RTL input changed"):
                validate_inputs(rtl, source, ["reset-irq"])


if __name__ == "__main__":
    unittest.main()
