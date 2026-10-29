# SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
# SPDX-License-Identifier: MIT
"""Check endpoint joins without deriving observed SRAM writes from operands."""

import copy
import unittest

from atomic_retirement import join_atomic_witnesses
from retirement import TraceError, check_trace


def packet(word, order, cycle, rd=0, value=0, **changes):
    row = {"schema": "ditdah-e2.rvfi.v1", "cycle": cycle, "order": order, "insn": word,
           "trap": False, "halt": False, "intr": False, "mode": 3, "ixl": 1,
           "rs1_addr": 0, "rs2_addr": 0, "rs1_rdata": 0, "rs2_rdata": 0,
           "rd_addr": rd, "rd_wdata": value, "pc_rdata": order * 4, "pc_wdata": order * 4 + 4,
           "mem_addr": 0, "mem_rmask": 0, "mem_wmask": 0, "mem_rdata": 0, "mem_wdata": 0,
           "mem_fault": False, "mem_fault_rmask": 0, "mem_fault_wmask": 0,
           "length": 4, "cause": 5, "tval": 0, "misa": 0x40000101,
           "memory_operation": 0, "memory_operand": 0, "memory_response": 0,
           "csr": {"valid": False, "address": 0, "rmask": 0, "wmask": 0, "rdata": 0, "wdata": 0},
           "csr_states": {name: {"before": 0x1800 if name == "mstatus" else 0,
                                  "after": 0x1800 if name == "mstatus" else 0, "wmask": 0}
                          for name in ("mstatus", "mepc", "mcause", "mtval", "mcycle", "minstret")}, "time": 0}
    row.update(changes)
    return row


def fixture(operation=4, sc_failure=False, rd=3):
    functions = {1: 2, 2: 3, 3: 1, 4: 0, 5: 4, 6: 12, 7: 8, 8: 16, 9: 20, 10: 24, 11: 28}
    operand = 0 if operation == 1 else 5
    response = int(sc_failure) if operation == 2 else 7
    mask = 15 if operation >= 3 or operation == 2 and not sc_failure else 0
    writes = {3: 5, 4: 12, 5: 2, 6: 5, 7: 7, 8: 5, 9: 7, 10: 5, 11: 7}
    data = writes[operation] if operation >= 3 else 5 if mask else 0
    word = functions[operation] << 27 | (2 if operation != 1 else 0) << 20 | 1 << 15 | 2 << 12 | rd << 7 | 0x2F
    records = [packet(0x10000093, 0, 0, 1, 0x100), packet(0x00500113, 1, 1, 2, 5),
               packet(word, 2, 5, rd, response if rd else 0, rs1_addr=1, rs1_rdata=0x100,
                      rs2_addr=0 if operation == 1 else 2, rs2_rdata=operand,
                      mem_addr=0x100, mem_rmask=0 if operation == 2 else 15,
                      mem_wmask=15 if operation == 2 and not sc_failure else 0,
                      mem_rdata=0 if operation == 2 else response, mem_wdata=operand,
                      memory_operation=operation, memory_operand=operand, memory_response=response)]
    request = (0x100, 1, int(operation != 1), operand, 0 if operation == 1 else 15, 2, operation)
    history = [{"acceptedCycle": 3, "memoryCycle": 4, "port": "data", "request": request,
                "oldValue": None if operation == 2 else 7, "writeValue": data if mask else None,
                "response": (response, 0), "reservationBefore": 0x100 if operation == 2 and not sc_failure else None,
                "reservationAfter": 0x100 if operation == 1 else None}]
    samples = [[0] * 57 for _ in range(7)]
    samples[3][14:24] = [1, *request, 0, 1]
    samples[3][-4:] = [1, 0, 0, 0]
    samples[4][-4:] = [0, 0, mask, data]
    samples[5][22:27] = [1, 0, 1, response, 0]
    return records, history, samples


def render(records, history, samples, extra=None):
    lines = []
    for cycle, sample in enumerate(samples):
        lines.append(f"T {cycle} 0 0 0 0 0 0 0")
        lines.append(f"B {cycle} " + " ".join(map(str, sample)))
        if cycle == 3:
            address, machine, write, data, mask, size, operation = history[0]["request"]
            lines.append(f"Q {cycle} D {address} {write} {data} {mask} {size} {machine} {operation}")
        if cycle == 5:
            lines.append(f"S {cycle} D " + " ".join(map(str, history[0]["response"])))
        for record in records:
            if record["cycle"] == cycle:
                lines.append("R " + " ".join(map(str, (cycle, record["pc_rdata"], record["insn"],
                    record["pc_wdata"], record["rd_addr"], int(record["rd_addr"] != 0),
                    record["rd_wdata"], int(record["trap"]), record["cause"], record["tval"],
                    int(record["mode"] == 0)))))
        if extra and cycle == extra[0]:
            lines.append(extra[1])
    return "\n".join(lines + [f"F {len(samples)}"]) + "\n"


def joined(records, history, samples, **options):
    return join_atomic_witnesses(records, render(records, history, samples), history,
                                 sram_base=0x100, sram_size=64, **options)


class AtomicJoinTests(unittest.TestCase):
    def test_all_operations_join_actual_endpoint_samples(self):
        for operation in range(1, 12):
            records, history, samples = fixture(operation)
            with self.subTest(operation=operation):
                witnesses = joined(records, history, samples)
                self.assertEqual(len(witnesses), 1)
                witness = witnesses[0]
                self.assertEqual((witness.request_cycle, witness.commit_cycle, witness.response_cycle), (3, 4, 5))
                self.assertEqual((witness.write_mask, witness.write_data), tuple(samples[4][-2:]))
                self.assertEqual(check_trace(records, atomic_witnesses=witnesses)["counts"]["atomic_witnesses"], 1)

    def test_failed_sc_rd_zero_preserves_actual_status_and_no_write(self):
        records, history, samples = fixture(2, sc_failure=True, rd=0)
        witnesses = joined(records, history, samples)
        self.assertEqual((witnesses[0].write_mask, witnesses[0].write_data), (0, 0))
        self.assertEqual(records[-1]["memory_response"], 1)
        check_trace(records, atomic_witnesses=witnesses)

    def test_actual_write_is_not_recomputed_from_operand(self):
        records, history, samples = fixture()
        history[0]["writeValue"] = samples[4][-1] = 99
        witness = joined(records, history, samples)[0]
        self.assertEqual(witness.write_data, 99)
        with self.assertRaisesRegex(TraceError, "endpoint write differs"):
            check_trace(records, atomic_witnesses=[witness])

    def test_wrong_actual_write_mask_data_or_address_is_rejected(self):
        for index, value in ((-1, 99), (-2, 7), (-3, 1)):
            records, history, samples = fixture()
            samples[4][index] = value
            with self.subTest(index=index), self.assertRaises(TraceError):
                joined(records, history, samples)

    def test_history_cannot_claim_a_competing_write_for_core(self):
        records, history, samples = fixture()
        history[0]["port"] = "competitor"
        with self.assertRaises(TraceError):
            joined(records, history, samples)

    def test_missing_extra_or_duplicate_history_is_rejected(self):
        records, history, samples = fixture()
        trace = render(records, history, samples)
        for rows in ([], history + copy.deepcopy(history)):
            with self.subTest(count=len(rows)), self.assertRaises(TraceError):
                join_atomic_witnesses(records, trace, rows, sram_base=0x100, sram_size=64)

    def test_changed_request_response_and_retirement_owner_are_rejected(self):
        for change in ("request", "response", "retirement"):
            records, history, samples = fixture()
            if change == "request":
                samples[3][18] = 6
            elif change == "response":
                samples[5][25] = 8
            else:
                records[-1]["memory_operand"] = 6
            with self.subTest(change=change), self.assertRaises(TraceError):
                joined(records, history, samples)

    def test_extra_physical_write_has_no_owner(self):
        records, history, samples = fixture()
        samples[6][-2:] = [15, 1]
        with self.assertRaisesRegex(TraceError, "write lacks"):
            joined(records, history, samples)

    def test_data_endpoint_transaction_requires_reverse_native_owner(self):
        records, history, samples = fixture()
        trace = "\n".join(line for line in render(records, history, samples).splitlines()
                          if not line.startswith(("Q ", "S ")))
        with self.assertRaisesRegex(TraceError, "Data history lacks"):
            join_atomic_witnesses(records, trace, history, sram_base=0x100, sram_size=64)

    def test_missing_sample_and_incomplete_native_response_are_rejected(self):
        records, history, samples = fixture()
        trace = render(records, history, samples)
        for changed in ("\n".join(line for line in trace.splitlines() if not line.startswith("B 2 ")),
                        "\n".join(line for line in trace.splitlines() if not line.startswith("S 5 "))):
            with self.assertRaises(TraceError):
                join_atomic_witnesses(records, changed, history, sram_base=0x100, sram_size=64)

    def test_explicit_rejection_of_unsupported_boundaries(self):
        records, history, samples = fixture()
        trace = render(records, history, samples)
        for changed in (trace.replace("T 2 0 0 0 0 0 0 0", "T 2 0 1 0 0 0 0 0"),
                        trace.replace("T 2 0 0 0 0 0 0 0", "T 2 0 0 0 1 0 0 0"),
                        trace.replace("T 2 0 0 0 0 0 0 0", "T 2 0 0 0 0 0 0 1"),
                        render(records, history, samples, (2, "N 2 8 0 2147483659")),
                        render(records, history, samples, (2, "J 2 0 0 16 2 1"))):
            with self.assertRaisesRegex(TraceError, "does not support"):
                join_atomic_witnesses(records, changed, history, sram_base=0x100, sram_size=64)

    def test_region_and_payload_widths_are_bound(self):
        records, history, samples = fixture()
        trace = render(records, history, samples)
        with self.assertRaises(TraceError):
            join_atomic_witnesses(records, trace, history, sram_base=0x104, sram_size=64)
        history[0]["request"] = (*history[0]["request"][:3], 1 << 32, *history[0]["request"][4:])
        with self.assertRaises(TraceError):
            joined(records, history, samples)


if __name__ == "__main__":
    unittest.main()
