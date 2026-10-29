# SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
# SPDX-License-Identifier: MIT
"""Check retirement observations and reject semantic and structural mutations."""

import copy
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from retirement import (AtomicWitness, Boundary, Interrupt, TraceError, bind_native_trace, check_trace,
                        interrupts_from_stdout, parse_interrupt_jsonl, parse_jsonl, read_trace)


ROOT = Path(__file__).resolve().parent


def state(before=0, after=None, mask=0):
    return {"before": before, "after": before if after is None else after, "wmask": mask}


def packet(word=0x13, *, order=0, cycle=None, pc=None, **changes):
    pc = order * 4 if pc is None else pc
    result = {"schema": "ditdah-e2.rvfi.v1", "cycle": order if cycle is None else cycle,
              "order": order, "insn": word, "trap": False, "halt": False, "intr": False,
              "mode": 3, "ixl": 1, "rs1_addr": 0, "rs2_addr": 0,
              "rs1_rdata": 0, "rs2_rdata": 0, "rd_addr": 0, "rd_wdata": 0,
              "pc_rdata": pc, "pc_wdata": pc + 4, "mem_addr": 0, "mem_rmask": 0,
              "mem_wmask": 0, "mem_rdata": 0, "mem_wdata": 0, "mem_fault": False,
              "mem_fault_rmask": 0, "mem_fault_wmask": 0, "length": 4,
              "cause": 5, "tval": word, "misa": 0x40000100,
              "memory_operation": 0, "memory_operand": 0, "memory_response": 0,
              "csr": {"valid": False, "address": 0, "rmask": 0, "wmask": 0,
                      "rdata": 0, "wdata": 0},
              "csr_states": {name: state(0x1800 if name == "mstatus" else 0)
                             for name in ("mstatus", "mepc", "mcause", "mtval", "mcycle", "minstret")},
              "time": 0}
    result.update(changes)
    return result


def arithmetic():
    return [packet(0x00700093, rd_addr=1, rd_wdata=7),
            packet(0x00108133, order=1, rs1_addr=1, rs2_addr=1,
                   rs1_rdata=7, rs2_rdata=7, rd_addr=2, rd_wdata=14)]


def trapping(word=0, cause=2, value=0, **changes):
    first = packet(word, trap=True, cause=cause, tval=value, pc_wdata=0x100, **changes)
    first["csr_states"].update(mstatus=state(0x1800, 0x1800, 0x88),
                               mepc=state(0, 0, 0xFFFFFFFC),
                               mcause=state(0, cause, 0xFFFFFFFF),
                               mtval=state(0, value, 0xFFFFFFFF))
    second = packet(order=1, cycle=3, pc=0x100, intr=True)
    for name, previous in first["csr_states"].items():
        second["csr_states"][name] = state(previous["after"])
    return first, second


def irq_records():
    first = packet()
    first["csr_states"]["mstatus"] = state(0x1808)
    irq = {"schema": "ditdah-e2.irq.v1", "cycle": 1, "pc": 4, "target": 0x100,
           "cause": 0x8000000B, "mode": 3,
           "csr_states": {"mstatus": state(0x1808, 0x1880, 0x88),
                          "mepc": state(0, 4, 0xFFFFFFFC),
                          "mcause": state(0, 0x8000000B, 0xFFFFFFFF),
                          "mtval": state(0, 0, 0xFFFFFFFF)}}
    handler = packet(order=1, cycle=4, pc=0x100, intr=True)
    for name, value in irq["csr_states"].items():
        handler["csr_states"][name] = state(value["after"])
    return first, irq, handler


def atomic_records(operation=4, response=7, rd=3):
    function = {1: 2, 2: 3, 3: 1, 4: 0, 5: 4, 6: 12, 7: 8, 8: 16, 9: 20, 10: 24, 11: 28}[operation]
    right = 0 if operation == 1 else 2
    word = function << 27 | right << 20 | 1 << 15 | 2 << 12 | rd << 7 | 0x2F
    result = [packet(0x10000093, rd_addr=1, rd_wdata=0x100, misa=0x40000101),
              packet(0x00500113, order=1, rd_addr=2, rd_wdata=5, misa=0x40000101),
              packet(word, order=2, cycle=8, rs1_addr=1, rs1_rdata=0x100,
                     rs2_addr=right, rs2_rdata=5 if right else 0,
                     rd_addr=rd, rd_wdata=response if rd else 0, misa=0x40000101,
                     mem_addr=0x100, mem_rmask=0 if operation == 2 else 15,
                     mem_wmask=15 if operation == 2 and response == 0 else 0,
                     mem_rdata=0 if operation == 2 else response,
                     mem_wdata=5 if right else 0, memory_operation=operation,
                     memory_operand=5 if right else 0, memory_response=response)]
    write_mask = 15 if operation >= 3 or operation == 2 and response == 0 else 0
    post = 12 if operation == 4 else 5 if write_mask else 0
    witness = AtomicWitness(2, 0x100, operation, 5 if right else 0,
                            response if operation != 2 else 7, write_mask, post, 4, 5, 8)
    return result, witness


class ParsingTests(unittest.TestCase):
    def reject(self, row, message):
        with self.assertRaisesRegex(TraceError, message):
            parse_jsonl(json.dumps(row))

    def test_exact_packet_and_64_bit_values(self):
        row = packet(time=(1 << 64) - 1)
        row["csr_states"]["mcycle"] = state((1 << 64) - 1)
        self.assertEqual(parse_jsonl(json.dumps(row) + "\n"), [row])

    def test_missing_unknown_duplicate_and_wrong_schema(self):
        row = packet()
        del row["memory_response"]
        self.reject(row, "missing fields")
        row = packet(extra=0)
        self.reject(row, "unknown fields")
        self.reject(packet(schema="ditdah-e2.unknown.v1"), "unsupported schema")
        with self.assertRaisesRegex(TraceError, "duplicate JSON member order"):
            parse_jsonl(json.dumps(packet())[:-1] + ',"order":0}')
        text = json.dumps(packet()).replace('"valid": false', '"valid":false,"valid":false')
        with self.assertRaisesRegex(TraceError, "duplicate JSON member valid"):
            parse_jsonl(text)

    def test_numeric_types_widths_and_flags(self):
        for key, value in (("order", True), ("cycle", -1), ("rd_addr", 32),
                           ("insn", 1 << 32), ("time", 1 << 64), ("rs1_rdata", 1.0)):
            with self.subTest(key=key):
                self.reject(packet(**{key: value}), "unsigned")
        self.reject(packet(trap=0), "expected Boolean")
        self.reject(packet(halt=True), "permanent halt")

    def test_empty_truncated_array_and_nonfinite_records(self):
        for text in ("", "\n", "[]", json.dumps(packet())[:-1], "NaN"):
            with self.subTest(text=text[:10]), self.assertRaises(TraceError):
                parse_jsonl(text)
        self.assertRaises(TraceError, parse_jsonl, json.dumps(packet()) + "\n\n")

    def test_inactive_diagnostics_are_not_fabricated_effects(self):
        row = packet(cause=5, tval=0x12345678)
        row["csr"].update(address=0x300, rdata=0x1800, wdata=0xFFFFFFFF)
        self.assertEqual(check_trace(parse_jsonl(json.dumps(row)))["packets"], 1)
        row["csr"]["wmask"] = 1
        self.reject(row, "inactive CSR has an access mask")

    def test_state_width_and_write_mask(self):
        row = packet()
        row["csr_states"]["mcycle"]["after"] = 1 << 64
        self.reject(row, "unsigned 64-bit")
        row = packet()
        row["csr_states"]["mstatus"]["after"] = 0
        self.reject(row, "changed outside its write mask")
        row = packet()
        row["csr_states"]["unknown"] = state()
        self.reject(row, "unknown fields")

    def test_x0_and_raw_compressed_encoding(self):
        self.reject(packet(rs1_rdata=1), "rs1 x0")
        self.reject(packet(rd_wdata=1), "rd x0")
        self.reject(packet(0x10001, length=2, misa=0x40000104), "raw compressed")
        self.reject(packet(1, length=2), "raw compressed")

    def test_read_file_uses_the_same_strict_parser(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "trace.jsonl"
            path.write_text(json.dumps(packet()) + "\n")
            self.assertEqual(read_trace(path), [packet()])


class SequenceTests(unittest.TestCase):
    def reject(self, records, message, **options):
        with self.assertRaisesRegex(TraceError, message):
            check_trace(records, **options)

    def test_forwarded_sources_and_independent_integer_result(self):
        result = check_trace(arithmetic(), reset_vector=0, expected_count=2)
        self.assertEqual(result["counts"]["integer_results"], 2)
        self.assertFalse(result["isa_model_equivalence"])
        for key, value, message in (("rs1_rdata", 0, "prior GPR"),
                                    ("rs1_addr", 2, "prior GPR|source indexes"),
                                    ("rd_wdata", 15, "integer result")):
            rows = arithmetic()
            rows[1][key] = value
            self.reject(rows, message)

    def test_instruction_count_and_order_are_not_completion_guesses(self):
        rows = arithmetic()
        self.reject(rows[:1], "packet count", expected_count=2)
        self.reject(rows + [packet(order=2)], "packet count", expected_count=2)
        rows[1]["order"] = 2
        self.reject(rows, "nonconsecutive")
        rows[1]["order"] = 0
        self.reject(rows, "nonconsecutive")
        rows = arithmetic()
        rows[1]["cycle"] = 0
        self.reject(rows, "cycle does not increase")

    def test_pc_discontinuity_requires_a_real_transition(self):
        rows = arithmetic()
        rows[1]["pc_rdata"], rows[1]["pc_wdata"] = 0x100, 0x104
        self.reject(rows, "PC discontinuity")
        rows = [packet(0x0080006F, pc_wdata=8), packet(order=1, pc=8)]
        self.assertEqual(check_trace(rows)["packets"], 2)
        rows[0]["pc_wdata"] = 12
        self.reject(rows, "next PC")

    def test_nonwriting_raw_rd_bits_do_not_become_a_destination(self):
        row = packet(0x00000223, mem_addr=4, mem_wmask=1)
        self.assertEqual(check_trace([row])["packets"], 1)
        row["rd_addr"] = 4
        self.reject([row], "destination index")

    def test_load_lane_sign_extension_and_ordinary_store(self):
        load = packet(0x00300083, rd_addr=1, rd_wdata=0xFFFFFF80,
                      mem_rmask=8, mem_rdata=0x80000000, memory_response=0x80000000)
        self.assertEqual(check_trace([load])["packets"], 1)
        load["rd_wdata"] = 0x80
        self.reject([load], "load result")
        rows = [packet(0x00700093, rd_addr=1, rd_wdata=7),
                packet(0x00101123, order=1, rs2_addr=1, rs2_rdata=7,
                       mem_wmask=12, mem_wdata=7 << 16)]
        self.assertEqual(check_trace(rows)["packets"], 2)
        rows[1]["mem_wdata"] = 7
        self.reject(rows, "write operand")

    def test_access_fault_and_alignment_have_different_masks(self):
        rows = trapping(0x00002023, 7, 0, mem_fault=True, mem_fault_wmask=15)
        self.assertEqual(check_trace(rows)["counts"]["traps"], 1)
        changed = copy.deepcopy(rows)
        changed[0]["mem_wmask"] = 15
        self.reject(changed, "successful memory masks")
        rows = trapping(0x00101083, 4, 1)
        self.assertEqual(check_trace(rows)["counts"]["traps"], 1)
        changed = copy.deepcopy(rows)
        changed[0]["mem_fault"] = True
        self.reject(changed, "matching access trap")

    def test_fetch_fault_never_fabricates_an_instruction(self):
        rows = trapping(0, 1, 0, mem_fault=True)
        self.assertEqual(check_trace(rows)["packets"], 2)
        changed = copy.deepcopy(rows)
        changed[0]["insn"] = 0x13
        self.reject(changed, "fetch fault contains")

    def test_trap_handler_marker_is_consumed_by_the_first_visible_packet(self):
        rows = trapping()
        self.assertEqual(check_trace(rows)["counts"]["handler_markers"], 1)
        self.reject(rows[:1], "ends before")
        self.assertEqual(check_trace(rows[:1], allow_pending_handler=True)["packets"], 1)
        rows[1]["intr"] = False
        self.reject(rows, "trap-handler marker")
        self.reject([packet(intr=True)], "trap-handler marker")

    def test_compressed_packet_retains_raw_halfword(self):
        row = packet(1, length=2, pc_wdata=2, misa=0x40000104)
        self.assertEqual(check_trace([row])["packets"], 1)
        row["insn"] = 0x13
        self.reject([row], "raw compressed")

    def test_csr_read_and_write_suppression(self):
        row = packet(0x34001073)
        row["csr"].update(valid=True, address=0x340, wmask=0xFFFFFFFF, rdata=123)
        self.assertEqual(check_trace([row])["packets"], 1)
        row["csr"]["rmask"] = 0xFFFFFFFF
        self.reject([row], "CSR read suppression")
        row = packet(0x340020F3, rd_addr=1)
        row["csr"].update(valid=True, address=0x340, rmask=0xFFFFFFFF)
        self.assertEqual(check_trace([row])["packets"], 1)
        row["csr"]["wmask"] = 0xFFFFFFFF
        self.reject([row], "zero source")

    def test_csr_nonzero_register_containing_zero_still_permits_a_write(self):
        rows = [packet(0x00000113, rd_addr=2), packet(0x340120F3, order=1, rs1_addr=2, rd_addr=1)]
        rows[1]["csr"].update(valid=True, address=0x340, rmask=0xFFFFFFFF, wmask=0xFFFFFFFF)
        self.assertEqual(check_trace(rows)["packets"], 2)

    def test_counter_csr_keeps_full_width_and_no_background_write(self):
        row = packet(0xB80020F3, rd_addr=1, rd_wdata=1)
        row["csr"].update(valid=True, address=0xB80, rmask=0xFFFFFFFF, rdata=1)
        row["csr_states"]["mcycle"] = state((1 << 32) | 7)
        self.assertEqual(check_trace([row])["packets"], 1)
        row["csr"]["rdata"] = 7
        self.reject([row], "CSR result|observed state")

    def test_mret_changes_state_without_becoming_an_interrupt(self):
        first = packet(0x30200073, pc_wdata=0x100)
        first["csr_states"]["mepc"] = state(0x100)
        first["csr_states"]["mstatus"] = state(0x1800, 0x1880, 0x88)
        second = packet(order=1, pc=0x100)
        for name, value in first["csr_states"].items():
            second["csr_states"][name] = state(value["after"])
        self.assertEqual(check_trace([first, second])["packets"], 2)
        first["csr_states"]["mstatus"] = state(0x1800)
        self.reject([first, second], "MRET MSTATUS|unauthorized state write mask")

    def test_non_csr_cannot_authorize_a_state_write(self):
        for name in ("mstatus", "mepc", "mcause", "mtval", "mcycle", "minstret"):
            row = packet()
            before = row["csr_states"][name]["before"]
            row["csr_states"][name] = state(before, before ^ 8, 8)
            with self.subTest(name=name):
                self.reject([row], "unauthorized state write mask")

    def test_csr_write_value_and_state_effect_are_independent_checks(self):
        row = packet(0x3400D073)
        row["csr"].update(valid=True, address=0x340, wmask=0xFFFFFFFF, wdata=1)
        self.assertEqual(check_trace([row])["packets"], 1)
        row["csr"]["wdata"] = 2
        self.reject([row], "CSR write data")
        row = packet(0x3430D073)
        row["csr"].update(valid=True, address=0x343, wmask=0xFFFFFFFF, wdata=1)
        row["csr_states"]["mtval"] = state(0, 2, 0xFFFFFFFF)
        self.reject([row], "explicit CSR write")

    def test_fetch_fault_rejects_all_unavailable_data_fields(self):
        for key in ("mem_rdata", "mem_wdata", "memory_operand", "memory_response"):
            rows = trapping(0, 1, 0, mem_fault=True)
            rows[0][key] = 85
            with self.subTest(key=key):
                self.reject(rows, "unavailable or illegal instruction")

    def test_fetch_fault_rejects_shadow_consistent_source_registers(self):
        first = packet(0x05500093, rd_addr=1, rd_wdata=85)
        fault, handler = trapping(0, 1, 4, mem_fault=True, order=1, cycle=3, pc=4)
        handler.update(order=2, cycle=5)
        fault.update(rs1_addr=1, rs1_rdata=85)
        self.reject([first, fault, handler], "unavailable instruction has source-register")

    def test_fixed_csr_cannot_claim_writable_fields(self):
        for address, value in ((0x301, 0x40000100), (0x310, 0), (0xB03, 0)):
            row = packet(address << 20 | 0x1073)
            row["csr"].update(valid=True, address=address, rdata=value, wdata=value)
            self.assertEqual(check_trace([row])["packets"], 1)
            row["csr"]["wmask"] = 0xFFFFFFFF
            with self.subTest(address=address):
                self.reject([row], "fixed CSR has a write effect")

    def test_pmp_lock_and_tor_predecessor_masks_follow_prior_writes(self):
        misa = 0x40100100
        def write(address, value, order, read, mask, after):
            high = (value + 0x800) & 0xFFFFF000
            setup = packet(0x000000B7 | high, order=order, rd_addr=1,
                           rd_wdata=high, misa=misa)
            rows = [setup]
            if value & 0xFFF:
                rows.append(packet((value & 0xFFF) << 20 | 0x8093, order=order + 1,
                                   rs1_addr=1, rs1_rdata=high, rd_addr=1,
                                   rd_wdata=value, misa=misa))
            row = packet(address << 20 | 0x9073, order=order + len(rows),
                         rs1_addr=1, rs1_rdata=value, misa=misa)
            row["csr"].update(valid=True, address=address, rdata=read, wdata=after, wmask=mask)
            return rows + [row]
        rows = write(0x3B0, 0x100, 0, 0, 0x3FFFFFFF, 0x100)
        rows += write(0x3A0, 0x8800, len(rows), 0, 0x9F9F9F9F, 0x8800)
        rows += write(0x3B0, 0x200, len(rows), 0x100, 0, 0x100)
        self.assertEqual(check_trace(rows)["packets"], len(rows))
        rows[-1]["csr"].update(wmask=0x3FFFFFFF, wdata=0x200)
        self.reject(rows, "PMP write mask differs")

    def test_explicit_reset_and_resume_boundaries(self):
        rows = [packet(), packet(order=1, cycle=5, pc=0x100)]
        self.assertEqual(check_trace(rows, boundaries=[Boundary(3, "resume", 0x100)])["epochs"], 1)
        rows[1] = packet(order=0, cycle=5)
        self.assertEqual(check_trace(rows, boundaries=[Boundary(3, "reset", 0)])["epochs"], 2)
        self.reject(rows, "nonconsecutive")
        self.reject([packet()], "extra side event", boundaries=[Boundary(3, "reset", 0)])
        self.reject([packet()], "unknown lifecycle", boundaries=[Boundary(3, "unknown", 0)])

    def test_unobserved_csr_state_change_is_rejected(self):
        rows = [packet(), packet(order=1)]
        rows[1]["csr_states"]["mepc"] = state(4)
        self.reject(rows, "state changed without an event")


class InterruptTests(unittest.TestCase):
    def test_irq_requires_real_write_masks_even_when_value_does_not_change(self):
        for name, mask in (("mstatus", 0xFFFFFFFF), ("mepc", 0), ("mcause", 0), ("mtval", 0)):
            first, event, handler = irq_records()
            event["csr_states"][name]["wmask"] = mask
            with self.subTest(name=name), self.assertRaisesRegex(TraceError, "write mask"):
                check_trace([first, handler], interrupts=parse_interrupt_jsonl(json.dumps(event)))

    def test_irq_sidecar_connects_both_csr_boundaries(self):
        first, event, handler = irq_records()
        interrupts = parse_interrupt_jsonl(json.dumps(event))
        result = check_trace([first, handler], interrupts=interrupts)
        self.assertEqual(result["counts"]["irq_csr_effects"], 1)
        self.assertEqual(result["counts"]["handler_markers"], 1)
        self.assertEqual(parse_interrupt_jsonl(""), [])

    def test_wrong_irq_source_target_and_state_are_rejected(self):
        for field, value, message in (("pc", 8, "interrupt PC"), ("target", 0x200, "PC discontinuity"),
                                      ("mode", 0, "pre-entry privilege")):
            first, event, handler = irq_records()
            event[field] = value
            with self.subTest(field=field), self.assertRaisesRegex(TraceError, message):
                check_trace([first, handler], interrupts=parse_interrupt_jsonl(json.dumps(event)))
        first, event, handler = irq_records()
        event["csr_states"]["mepc"]["after"] = 8
        with self.assertRaisesRegex(TraceError, "trap CSR"):
            check_trace([first, handler], interrupts=parse_interrupt_jsonl(json.dumps(event)))
        first, event, handler = irq_records()
        handler["csr_states"]["mcause"] = state(0)
        with self.assertRaisesRegex(TraceError, "state changed without"):
            check_trace([first, handler], interrupts=parse_interrupt_jsonl(json.dumps(event)))

    def test_irq_parser_rejects_unknown_missing_and_wrong_kind(self):
        _, event, _ = irq_records()
        for change in ({"extra": 1}, {"schema": "ditdah-e2.rvfi.v1"}, {"mode": True}):
            row = copy.deepcopy(event)
            row.update(change)
            with self.assertRaises(TraceError):
                parse_interrupt_jsonl(json.dumps(row))
        del event["csr_states"]["mtval"]
        with self.assertRaisesRegex(TraceError, "missing fields"):
            parse_interrupt_jsonl(json.dumps(event))

    def test_legacy_interrupts_do_not_claim_csr_evidence(self):
        first, event, handler = irq_records()
        interrupts = interrupts_from_stdout("R 0 ignored\nN 1 4 256 2147483659\n")
        result = check_trace([first, handler], interrupts=interrupts)
        self.assertEqual(result["counts"]["legacy_interrupts_without_csr_evidence"], 1)
        self.assertNotIn("irq_csr_effects", result["counts"])
        with self.assertRaisesRegex(TraceError, "malformed interrupt"):
            interrupts_from_stdout("N 1 4 256\n")
        with self.assertRaisesRegex(TraceError, "not ordered"):
            check_trace([first, handler], interrupts=[Interrupt(2, 4, 256, 0x8000000B), interrupts[0]])


class AtomicTests(unittest.TestCase):
    def test_amo_operand_is_not_the_observed_post_value(self):
        rows, witness = atomic_records()
        self.assertEqual(rows[-1]["mem_wdata"], 5)
        self.assertEqual(witness.write_data, 12)
        result = check_trace(rows, atomic_witnesses=[witness])
        self.assertEqual(result["counts"]["atomic_witnesses"], 1)
        self.assertFalse(result["reservation_protocol_verified"])
        with self.assertRaisesRegex(TraceError, "lacks actual endpoint"):
            check_trace(rows)
        wrong = AtomicWitness(2, 0x100, 4, 5, 7, 15, 5, 4, 5, 8)
        with self.assertRaisesRegex(TraceError, "actual endpoint write"):
            check_trace(rows, atomic_witnesses=[wrong])

    def test_sc_rd0_uses_raw_status_and_requires_no_failed_write(self):
        rows, witness = atomic_records(2, 1, 0)
        self.assertEqual(rows[-1]["rd_wdata"], 0)
        self.assertEqual(check_trace(rows, atomic_witnesses=[witness])["packets"], 3)
        wrong = AtomicWitness(2, 0x100, 2, 5, 7, 15, 5, 4, 5, 8)
        with self.assertRaisesRegex(TraceError, "actual endpoint write"):
            check_trace(rows, atomic_witnesses=[wrong])
        rows[-1]["memory_response"] = 2
        with self.assertRaisesRegex(TraceError, "invalid SC status"):
            check_trace(rows, atomic_witnesses=[witness])

    def test_sc_success_lr_and_amo_rd0(self):
        for operation, response, rd in ((2, 0, 3), (1, 7, 3), (4, 7, 0)):
            rows, witness = atomic_records(operation, response, rd)
            with self.subTest(operation=operation, rd=rd):
                self.assertEqual(check_trace(rows, atomic_witnesses=[witness])["packets"], 3)

    def test_wrong_owner_timing_and_unclaimed_witness(self):
        rows, _ = atomic_records()
        wrong = [AtomicWitness(2, 0x100, 4, 5, 7, 15, 12, 4, 5, 8, owner="debug"),
                 AtomicWitness(2, 0x100, 4, 5, 7, 15, 12, 5, 4, 8)]
        for witness in wrong:
            with self.assertRaises(TraceError):
                check_trace(rows, atomic_witnesses=[witness])
        with self.assertRaisesRegex(TraceError, "extra endpoint"):
            check_trace([packet()], atomic_witnesses=[AtomicWitness(1, 0, 1, 0, 0, 0, 0, 0, 1, 2)])


class NativeBindingTests(unittest.TestCase):
    @staticmethod
    def native(row):
        values = (row["cycle"], row["pc_rdata"], row["insn"], row["pc_wdata"],
                  row["rd_addr"], int(row["rd_addr"] != 0), row["rd_wdata"], int(row["trap"]),
                  row["cause"], row["tval"], int(row["mode"] == 0))
        return "R " + " ".join(map(str, values)) + "\n"

    def test_existing_native_retirement_is_bound_without_an_extra_model(self):
        rows = arithmetic()
        text = "T 0 0 1\n" + "".join(self.native(row) for row in rows)
        self.assertEqual(bind_native_trace(rows, text), {"retirement_records": 2, "interrupt_records": 0})
        with self.assertRaisesRegex(TraceError, "count differs"):
            bind_native_trace(rows[:1], text)
        rows[1]["rd_wdata"] = 15
        with self.assertRaisesRegex(TraceError, "observation differs"):
            bind_native_trace(rows, text)

    def test_diagnostics_and_nonwriting_rd_are_not_artificial_effects(self):
        row = packet()
        fields = self.native(row).split()
        fields[5], fields[7], fields[9], fields[10] = "31", "123", "7", "42"
        self.assertEqual(bind_native_trace([row], " ".join(fields))["retirement_records"], 1)
        fields[6] = "2"
        with self.assertRaisesRegex(TraceError, "invalid retirement flags"):
            bind_native_trace([row], " ".join(fields))

    def test_fetch_fault_normalizes_unavailable_raw_word(self):
        rows = trapping(0, 1, 0, mem_fault=True)
        text = self.native(rows[0]).split()
        text[3] = str(0xDEADBEEF)
        self.assertEqual(bind_native_trace(rows[:1], " ".join(text))["retirement_records"], 1)

    def test_irq_sidecar_must_match_native_irq_count_and_payload(self):
        first, event, handler = irq_records()
        rows = [first, handler]
        interrupts = parse_interrupt_jsonl(json.dumps(event))
        text = self.native(first) + "N 1 4 256 2147483659\n" + self.native(handler)
        self.assertEqual(bind_native_trace(rows, text, interrupts)["interrupt_records"], 1)
        with self.assertRaisesRegex(TraceError, "interrupt count"):
            bind_native_trace(rows, text)
        with self.assertRaisesRegex(TraceError, "interrupt observation"):
            bind_native_trace(rows, text.replace("N 1 4 256", "N 1 4 512"), interrupts)


class HeaderTests(unittest.TestCase):
    def test_cpp_serializer_preserves_types_widths_and_separate_irq_records(self):
        compiler = shutil.which("c++")
        self.assertIsNotNone(compiler, "A C++17 compiler is required to test the trace serializer")
        row = packet(time=(1 << 64) - 1)
        row["csr_states"]["mcycle"] = state((1 << 63) | 7)
        _, irq, _ = irq_records()
        fields = {"retire_valid": 0, "retire_userMode": 0}
        mapping = {"order": "order", "insn": "insn", "trap": "trap", "intr": "intr",
                   "rs1": "rs1_addr", "rs2": "rs2_addr", "rs1Data": "rs1_rdata", "rs2Data": "rs2_rdata",
                   "rd": "rd_addr", "value": "rd_wdata", "pc": "pc_rdata", "nextPc": "pc_wdata",
                   "memoryAddress": "mem_addr", "memoryReadMask": "mem_rmask", "memoryWriteMask": "mem_wmask",
                   "memoryReadData": "mem_rdata", "memoryWriteData": "mem_wdata", "memoryFault": "mem_fault",
                   "faultReadMask": "mem_fault_rmask", "faultWriteMask": "mem_fault_wmask", "length": "length",
                   "cause": "cause", "tval": "tval", "misa": "misa", "memoryOperation": "memory_operation",
                   "memoryOperand": "memory_operand", "memoryResponse": "memory_response", "csrTime": "time"}
        fields.update({"retire_" + member: int(row[key]) for member, key in mapping.items()})
        for member, key in (("valid", "valid"), ("address", "address"), ("readMask", "rmask"),
                            ("writeMask", "wmask"), ("readData", "rdata"), ("writeData", "wdata")):
            fields["retire_csr_" + member] = int(row["csr"][key])
        for member, name in (("csrMstatus", "mstatus"), ("csrMepc", "mepc"), ("csrMcause", "mcause"),
                             ("csrMtval", "mtval"), ("csrCycle", "mcycle"), ("csrInstret", "minstret")):
            for suffix, key in (("before", "before"), ("after", "after"), ("writeMask", "wmask")):
                fields[f"retire_{member}_{suffix}"] = row["csr_states"][name][key]
        fields.update(interrupt_valid=0, interrupt_userMode=0, interrupt_pc=irq["pc"],
                      interrupt_target=irq["target"], interrupt_cause=irq["cause"])
        for member, name in (("csrMstatus", "mstatus"), ("csrMepc", "mepc"),
                             ("csrMcause", "mcause"), ("csrMtval", "mtval")):
            for suffix, key in (("before", "before"), ("after", "after"), ("writeMask", "wmask")):
                fields[f"interrupt_{member}_{suffix}"] = irq["csr_states"][name][key]
        declarations = "\n".join(f"uint64_t {key} = {value}ULL;" for key, value in fields.items())
        source = '#include "rvfi_trace.hpp"\n#include <iostream>\n#include <sstream>\n' + \
            'struct Dut {\n' + declarations + '\n};\nint main() { Dut dut; std::ostringstream out;\n' + \
            'writeRvfi(out, dut, 0); writeRvfiInterrupt(out, dut, 1);\n' + \
            'if (!out.str().empty()) { return 2; }\ndut.retire_valid=1; out << std::hex << std::showbase;\n' + \
            'writeRvfi(out, dut, 0); std::cout << out.str(); dut.interrupt_valid=1;\n' + \
            'if ((out.flags() & std::ios_base::basefield) != std::ios_base::hex) { return 3; }\n' + \
            'std::ostringstream irq; writeRvfiInterrupt(irq, dut, 1); std::cout << irq.str();\n' + \
            'std::ostringstream failed; failed.setstate(std::ios_base::badbit);\n' + \
            'try { writeRvfi(failed, dut, 0); return 4; } catch (const std::ios_base::failure&) {}\n' + \
            'try { writeRvfiInterrupt(failed, dut, 1); return 5; } catch (const std::ios_base::failure&) {}\n}\n'
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            (path / "test.cpp").write_text(source)
            result = subprocess.run([compiler, "-std=c++17", "-Wall", "-Wextra", "-Werror", "-I", str(ROOT),
                                     str(path / "test.cpp"), "-o", str(path / "test")], capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            result = subprocess.run([str(path / "test")], capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            lines = result.stdout.splitlines()
            self.assertEqual(len(lines), 2)
            self.assertEqual(parse_jsonl(lines[0]), [row])
            parsed = parse_interrupt_jsonl(lines[1])
            self.assertEqual(parsed[0].csr_states, irq["csr_states"])
            self.assertEqual(parsed[0].mode, 3)


if __name__ == "__main__":
    unittest.main()
