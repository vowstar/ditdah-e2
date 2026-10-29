# SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
# SPDX-License-Identifier: MIT
"""Reject unowned sampled effects without calculating expected atomic results."""

import copy
import json
from pathlib import Path
import subprocess
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from sail_atomic_samples import SampleError, sample_atomic_witnesses


RAM = 0x20000000


def packet(word, order, cycle, rd=0, value=0, **changes):
    row = {"schema": "ditdah-e2.rvfi.v1", "cycle": cycle, "order": order, "insn": word,
           "trap": False, "halt": False, "intr": False, "mode": 3, "ixl": 1,
           "rs1_addr": 0, "rs2_addr": 0, "rs1_rdata": 0, "rs2_rdata": 0,
           "rd_addr": rd, "rd_wdata": value, "pc_rdata": 0x80000000 + order * 4,
           "pc_wdata": 0x80000004 + order * 4,
           "mem_addr": 0, "mem_rmask": 0, "mem_wmask": 0, "mem_rdata": 0, "mem_wdata": 0,
           "mem_fault": False, "mem_fault_rmask": 0, "mem_fault_wmask": 0, "length": 4,
           "cause": 5, "tval": 0, "misa": 0x40101105, "memory_operation": 0,
           "memory_operand": 0, "memory_response": 0,
           "csr": {"valid": False, "address": 0, "rmask": 0, "wmask": 0, "rdata": 0, "wdata": 0},
           "csr_states": {name: {"before": 0x1800 if name == "mstatus" else 0,
                                  "after": 0x1800 if name == "mstatus" else 0, "wmask": 0}
                          for name in ("mstatus", "mepc", "mcause", "mtval", "mcycle", "minstret")}, "time": 0}
    row.update(changes)
    return row


def fixture(operation=4, response=7, writer_mask=15, writer_data=12, fault=False):
    function = {1: 2, 2: 3, 3: 1, 4: 0, 5: 4, 6: 12, 7: 8, 8: 16, 9: 20, 10: 24, 11: 28}[operation]
    operand = 0 if operation == 1 else 5
    raw = function << 27 | (0 if operation == 1 else 2) << 20 | 1 << 15 | 2 << 12 | 3 << 7 | 0x2F
    records = [packet(0x200000B7, 0, 0, 1, RAM), packet(0x00500113, 1, 1, 2, 5),
               packet(raw, 2, 5, 0 if fault else 3, 0 if fault else response,
                      rs1_addr=1, rs1_rdata=RAM, rs2_addr=0 if operation == 1 else 2,
                      rs2_rdata=operand, mem_addr=RAM, mem_rmask=0 if fault or operation == 2 else 15,
                      mem_wmask=15 if operation == 2 and response == 0 and not fault else 0,
                      mem_rdata=0 if fault or operation == 2 else response, mem_wdata=0 if fault else operand,
                      memory_operation=operation, memory_operand=operand, memory_response=response,
                      trap=fault, cause=7 if fault else 5, tval=RAM if fault else 0, mem_fault=fault,
                      mem_fault_wmask=15 if fault else 0, mem_fault_rmask=15 if fault and operation >= 3 else 0)]
    samples = [[0] * 57 for _ in range(9)]
    request = [RAM, 1, int(operation != 1), operand, 0 if operation == 1 else 15, 2, operation]
    samples[3][14:24] = [1, *request, 0, 1]
    samples[3][-4:] = [int(not fault), 0, 0, 0]
    samples[4][-4:] = [0, 0, writer_mask, writer_data]
    samples[5][22:27] = [1, 0, 1, response, int(fault)]
    samples[6][40:50] = [1, RAM, 1, 0, 0, 0, 2, 0, 0, 1]
    samples[6][-4:] = [1, 0, 0, 0]
    samples[8][48:53] = [1, 0, 1, 99, 0]
    return records, samples


def render(records, samples, *, signature=True):
    lines = []
    for cycle, sample in enumerate(samples):
        lines.extend((f"T {cycle} 0 0 0 0 0 0 0", f"B {cycle} " + " ".join(map(str, sample))))
        if cycle == 3:
            request = samples[3][15:22]
            address, machine, write, data, mask, size, operation = request
            lines.append(f"Q 3 D {address} {write} {data} {mask} {size} {machine} {operation}")
        if cycle == 5:
            lines.append(f"S 5 D {sample[25]} {sample[26]}")
        for row in records:
            if row["cycle"] == cycle:
                lines.append("R " + " ".join(map(str, (cycle, row["pc_rdata"], row["insn"], row["pc_wdata"],
                    row["rd_addr"], int(row["rd_addr"] != 0), row["rd_wdata"], int(row["trap"]),
                    row["cause"], row["tval"], int(row["mode"] == 0)))))
        if cycle == 8 and signature:
            lines.append(f"V 8 {RAM} {sample[51]} {sample[52]}")
    return "\n".join(lines + [f"F {len(samples)}"]) + "\n"


def extract(records, samples, **options):
    return sample_atomic_witnesses(records, render(records, samples), sram_base=RAM, sram_size=64, **options)


class ActualSampleTests(unittest.TestCase):
    def test_actual_writer_and_signature_bind_to_independent_owners(self):
        records, samples = fixture()
        result = extract(records, samples)
        witness, = result["witnesses"]
        self.assertEqual(witness["writer"], {"cycle": 4, "address": RAM, "mask": 15, "data": 12})
        self.assertEqual((witness["request_cycle"], witness["execution_cycle"], witness["response_cycle"]), (3, 4, 5))
        self.assertEqual((witness["response_data"], witness["request"]["data"]), (7, 5))
        self.assertEqual(result["competitorReads"], [{"cycle": 8, "address": RAM, "data": 99,
                                                     "fault": 0, "request_cycle": 6}])
        json.dumps(result)

    def test_every_amo_preserves_actual_writer_data_without_arithmetic(self):
        for operation in range(3, 12):
            records, samples = fixture(operation, writer_data=99)
            with self.subTest(operation=operation):
                self.assertEqual(extract(records, samples)["witnesses"][0]["writer"]["data"], 99)

    def test_lr_and_failed_sc_do_not_invent_write_commits(self):
        for operation, response in ((1, 7), (2, 1)):
            records, samples = fixture(operation, response, 0, 0)
            with self.subTest(operation=operation):
                witness, = extract(records, samples)["witnesses"]
                self.assertEqual(witness["writer"], {"cycle": None, "address": None, "mask": 0, "data": 0})
                self.assertEqual(witness["response_data"], response)

    def test_accepted_fault_is_not_relabelled_as_unissued(self):
        records, samples = fixture(response=0, writer_mask=0, writer_data=0, fault=True)
        result = extract(records, samples)
        self.assertEqual(result["unissuedFaults"], [])
        self.assertEqual(result["witnesses"][0]["response_fault"], 1)

    def test_unissued_fault_has_no_fabricated_endpoint(self):
        records, samples = fixture(response=0, writer_mask=0, writer_data=0, fault=True)
        samples[3] = [0] * 57
        samples[5] = [0] * 57
        trace = "\n".join(line for line in render(records, samples).splitlines() if not line.startswith(("Q ", "S ")))
        result = sample_atomic_witnesses(records, trace, sram_base=RAM, sram_size=64)
        self.assertEqual(result["witnesses"], [])
        self.assertEqual(result["unissuedFaults"], [{"order": 2, "cycle": 5, "operation": 4, "cause": 7}])

    def test_unowned_wrong_address_or_readonly_physical_write_is_rejected(self):
        for cycle, index, value in ((2, 55, 15), (4, 54, 1), (3, 54, 1)):
            records, samples = fixture()
            samples[cycle][index] = value
            with self.subTest(cycle=cycle, index=index), self.assertRaises(SampleError):
                extract(records, samples)
        records, samples = fixture(1, writer_mask=1, writer_data=99)
        with self.assertRaisesRegex(SampleError, "not owned"):
            extract(records, samples)

    def test_faulting_writer_is_rejected(self):
        records, samples = fixture(response=0, fault=True)
        with self.assertRaisesRegex(SampleError, "Faulting endpoint.*physical write"):
            extract(records, samples)

    def test_response_requires_its_actual_port_owner(self):
        records, samples = fixture()
        samples[5][22:27] = [0, 0, 0, 0, 0]
        samples[5][9:14] = [1, 0, 1, 7, 0]
        with self.assertRaises(SampleError):
            extract(records, samples)

    def test_multiple_acceptance_or_acceptance_during_execution_is_rejected(self):
        for cycle in (3, 4):
            records, samples = fixture()
            samples[cycle][40:50] = [1, RAM, 1, 0, 0, 0, 2, 0, 0, 1]
            with self.subTest(cycle=cycle), self.assertRaises(SampleError):
                extract(records, samples)

    def test_signature_forgery_and_duplicate_are_rejected(self):
        records, samples = fixture()
        trace = render(records, samples)
        for changed in (trace.replace(f"V 8 {RAM} 99 0", f"V 8 {RAM} 100 0"),
                        trace.replace("F 9", f"V 8 {RAM} 99 0\nF 9")):
            with self.assertRaises(SampleError):
                sample_atomic_witnesses(records, changed, sram_base=RAM, sram_size=64)

    def test_missing_extra_unfinished_and_lifecycle_records_are_rejected(self):
        records, samples = fixture()
        trace = render(records, samples)
        variants = ["\n".join(line for line in trace.splitlines() if not line.startswith("B 2 ")),
                    trace.replace("F 9", "F 9\nV 9 0 0 0"),
                    trace.replace("T 2 0 0 0 0 0 0 0", "T 2 0 1 0 0 0 0 0"),
                    trace.replace("T 2 0 0 0 0 0 0 0", "T 2 0 0 0 1 0 0 0"),
                    trace.replace("T 2 0 0 0 0 0 0 0", "T 2 0 0 0 0 0 0 1"),
                    trace.replace("B 2 ", "N 2 0 0 2147483659\nB 2 ")]
        for changed in variants:
            with self.subTest(change=variants.index(changed)), self.assertRaises(SampleError):
                sample_atomic_witnesses(records, changed, sram_base=RAM, sram_size=64)

    def test_extra_native_or_endpoint_owner_is_rejected(self):
        records, samples = fixture()
        trace = "\n".join(line for line in render(records, samples).splitlines() if not line.startswith(("Q ", "S ")))
        with self.assertRaisesRegex(SampleError, "lacks its core request"):
            sample_atomic_witnesses(records, trace, sram_base=RAM, sram_size=64)
        records[-1]["memory_operation"] = 0
        with self.assertRaises(SampleError):
            extract(records, samples)

    def test_order_and_region_are_explicit(self):
        records, samples = fixture()
        records[-1]["order"] = 1
        with self.assertRaisesRegex(SampleError, "Nonconsecutive"):
            extract(records, samples)
        records, samples = fixture()
        with self.assertRaises(SampleError):
            sample_atomic_witnesses(records, render(records, samples), sram_base=RAM + 4, sram_size=64)

    def test_clean_process_uses_no_local_execution_model(self):
        directory = Path(__file__).resolve().parent
        code = ("import sys; from test_sail_atomic_samples import fixture, extract; "
                "extract(*fixture()); print(any(n in sys.modules for n in "
                "('model','compressed_model','bit_model','atomic_memory','pmp')))")
        run = subprocess.run([sys.executable, "-c", code], cwd=directory, text=True, capture_output=True)
        self.assertEqual((run.returncode, run.stdout.strip()), (0, "False"), run.stderr)


if __name__ == "__main__":
    unittest.main()
