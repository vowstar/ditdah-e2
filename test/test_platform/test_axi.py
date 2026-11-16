# SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
# SPDX-License-Identifier: MIT
"""Reject semantic faults in adapter traces and formal mutations."""

import unittest

from test.test_platform.axi import CHANNELS, READY, FIELDS, check, check_axi_structure, expected_ports, parse_trace, vectors
from formal.axi.axi_formal import mutate_owner


def sample(cycle, **values):
    row = {"cycle": cycle, "reset": 0}
    for channel, payload in CHANNELS.items():
        row[channel + "v"] = 0
        row[READY[channel]] = 0
        row.update(dict.fromkeys(payload, 0))
    return {**row, **values}


def transaction():
    request = dict(zip(FIELDS, (1, 1, 0x20000003, 0x11223344, 8, 0, 1, 0, 0, 0, 0, 0, 0, 2), strict=True))
    samples = [sample(0, reset=1), sample(1, dv=1, dr=1, da=request["address"], dw=1,
                                        dd=request["data"], dm=8, dp=1),
               sample(2, av=1, ay=1, aa=0x20000000, ap=1, wv=1, wy=1, wd=request["data"], wm=8),
               sample(3, bv=1, by=1, br=2), sample(4, pv=1, pr=1, pf=1), sample(5)]
    return [request], [0] * 256, samples


def replacement():
    first = dict.fromkeys(FIELDS, 0)
    first.update(owner=0, address=0x20000000, size=2, machine=1, response=2)
    second = dict.fromkeys(FIELDS, 0)
    second.update(owner=1, address=0x20000004, write=1, data=0x12345678, mask=15, size=2, machine=1)
    rows = [sample(0, reset=1), sample(1, iv=1, ir=1, ia=first["address"], iz=2, ip=1),
            sample(2, rv=1, ry=1, ra=first["address"], rp=5),
            sample(3, qv=1, qy=1, qr=2, ov=1, **{"or": 1}, of=1,
                   dv=1, dr=1, da=second["address"], dw=1, dd=second["data"], dm=15, dz=2, dp=1),
            sample(4, av=1, ay=1, aa=second["address"], ap=1, wv=1, wy=1, wd=second["data"], wm=15),
            sample(5, bv=1, by=1, pv=1, pr=1), sample(6)]
    return [first, second], [0] * 256, rows


class AxiTests(unittest.TestCase):
    def test_bypass_and_replacement(self):
        counts = check(*replacement())
        self.assertEqual(counts["responses"], 2)
        self.assertEqual(counts["bypassResponses"], 2)
        self.assertEqual(counts["faultBypassResponses"], 1)
        self.assertEqual(counts["otherOwnerReplacements"], 1)

    def test_stalled_bypass_then_replacement(self):
        requests, memory, rows = replacement()
        stalled = dict(rows[3], dr=0, **{"or": 0})
        held = dict(rows[3], qv=0, qy=0, qr=0)
        rows[3:4] = [stalled, held]
        for index, row in enumerate(rows):
            row["cycle"] = index
        counts = check(requests, memory, rows)
        self.assertEqual(counts["nativeResponseStalls"], 1)
        rows[4]["of"] = 0
        with self.assertRaisesRegex(AssertionError, "Unstable o"):
            check(requests, memory, rows)

    def test_replacement_uses_old_response_owner(self):
        requests, memory, rows = replacement()
        rows[3].update(ov=0, pv=1, pr=1, pf=1)
        with self.assertRaisesRegex(AssertionError, "wrong owner"):
            check(requests, memory, rows)

    def test_same_owner_not_replaced_before_completion(self):
        first = dict.fromkeys(FIELDS, 0)
        first.update(owner=0, address=0x20000000, size=2, machine=1)
        second = dict(first, address=0x20000004)
        rows = [sample(0, reset=1), sample(1, iv=1, ir=1, ia=first["address"], iz=2, ip=1),
                sample(2, iv=1, ir=1, ia=second["address"], iz=2, ip=1)]
        with self.assertRaisesRegex(AssertionError, "before native completion"):
            check([first, second], [0] * 256, rows, complete=False)

    def test_simultaneous_accept_and_read_write_completion(self):
        first = dict.fromkeys(FIELDS, 0)
        first.update(owner=0, address=0x20000000, size=2, machine=1)
        second = dict(first, owner=1, address=0x20000004, write=1, data=0x12345678, mask=15)
        rows = [sample(0, reset=1),
                sample(1, iv=1, ir=1, ia=first["address"], iz=2, ip=1,
                       dv=1, dr=1, da=second["address"], dw=1, dd=second["data"], dm=15, dz=2, dp=1),
                sample(2, rv=1, ry=1, ra=first["address"], rp=5,
                       av=1, ay=1, aa=second["address"], ap=1, wv=1, wy=1, wd=second["data"], wm=15),
                sample(3, qv=1, qy=1, bv=1, by=1, ov=1, pv=1, pr=1, **{"or": 1}), sample(4)]
        counts = check([first, second], [0] * 256, rows)
        self.assertEqual(counts["responses"], 2)
        self.assertEqual(counts["parallelAcceptCycles"], 1)
        self.assertEqual(counts["readWriteOverlapCycles"], 1)
        self.assertEqual(counts["bypassResponses"], 2)
        rows[3]["pd"] = 1
        with self.assertRaisesRegex(AssertionError, "Wrong native response"):
            check([first, second], [0] * 256, rows)

    def test_two_ordered_reads_with_independent_native_backpressure(self):
        first = dict.fromkeys(FIELDS, 0)
        first.update(owner=0, address=0x20000000, size=2, machine=1)
        second = dict(first, owner=1, address=0x20000004, machine=0, response=2)
        memory = [0x11223344, 0x55667788] + [0] * 254
        rows = [sample(0, reset=1),
                sample(1, iv=1, ir=1, ia=first["address"], iz=2, ip=1,
                       dv=1, dr=1, da=second["address"], dz=2),
                sample(2, rv=1, ry=1, ra=first["address"], rp=5),
                sample(3, rv=1, ry=1, ra=second["address"], rp=0),
                sample(4, qv=1, qy=1, qd=memory[0], ov=1, od=memory[0]),
                sample(5, qv=1, qy=1, qd=memory[1], qr=2, ov=1, od=memory[0],
                       pv=1, pd=memory[1], pf=1, **{"or": 1}),
                sample(6, pv=1, pr=1, pd=memory[1], pf=1), sample(7)]
        counts = check([first, second], memory, rows)
        self.assertEqual(counts["responses"], 2)
        self.assertGreater(counts["twoReadOutstandingCycles"], 0)
        with self.assertRaisesRegex(AssertionError, "Serial native acceptance overlapped"):
            check([first, second], memory, rows, concurrent=False)
        rows[4]["qd"] = memory[1]
        with self.assertRaisesRegex(AssertionError, "Read data differs"):
            check([first, second], memory, rows)

    def test_instruction_write_remains_supported(self):
        first = dict.fromkeys(FIELDS, 0)
        first.update(owner=0, write=1, address=0x20000000, data=0x12345678, mask=15, size=2, machine=1)
        second = dict(first, owner=1, write=0, data=0, mask=0)
        rows = [sample(0, reset=1),
                sample(1, iv=1, ir=1, ia=first["address"], iw=1, id=first["data"], im=15, iz=2, ip=1,
                       dv=1, dr=1, da=second["address"], dz=2, dp=1),
                sample(2, av=1, ay=1, aa=first["address"], ap=5, wv=1, wy=1, wd=first["data"], wm=15,
                       rv=1, ry=1, ra=second["address"], rp=1),
                sample(3, bv=1, by=1, qv=1, qy=1, qd=first["data"], ov=1,
                       pv=1, pr=1, pd=first["data"], **{"or": 1}), sample(4)]
        self.assertEqual(check([first, second], [0] * 256, rows)["responses"], 2)


    def test_axi_structure_rejects_combination_and_abi_changes(self):
        ports = {}
        bit = 2
        for name, (direction, width) in expected_ports().items():
            ports[name] = {"direction": direction, "bits": list(range(bit, bit + width))}
            bit += width
        module = {"ports": ports, "cells": {}}
        design = {"modules": {"DitDahE2AxiLite": module}}
        self.assertEqual(check_axi_structure(design)["axiInputToOutputCombinationalPaths"], 0)
        cell = {"type": "$dff", "port_directions": {"D": "input", "Q": "output"},
                "connections": {"D": ports["axi_r_valid"]["bits"], "Q": ports["axi_ar_valid"]["bits"]}}
        module["cells"]["path"] = cell
        check_axi_structure(design)
        cell["type"] = "$not"
        with self.assertRaisesRegex(AssertionError, "combinational input-to-output"):
            check_axi_structure(design)
        module["cells"].clear()
        ports["axi_w_bits_strobe"]["bits"].append(bit)
        with self.assertRaisesRegex(AssertionError, "ABI changed"):
            check_axi_structure(design)

    def test_atomic_request_fails_without_bus_access(self):
        for owner in (0, 1):
            for operation in range(1, 16):
                request = dict.fromkeys(FIELDS, 0)
                request.update(owner=owner, address=0x20000000, size=2, operation=operation)
                prefix, response = ("d", "p") if owner else ("i", "o")
                rows = [sample(0, reset=1), sample(1, **{
                    prefix + "v": 1, prefix + "r": 1, prefix + "a": request["address"],
                    prefix + "z": 2, prefix + "x": operation}),
                    sample(2, **{response + "v": 1, response + "r": 1, response + "f": 1}), sample(3)]
                counts = check([request], [0] * 256, rows)
                self.assertEqual(counts[f"owner{owner}Rejected{operation}"], 1)
                rows[2]["rv"] = 1
                with self.assertRaisesRegex(AssertionError, "Atomic request reached AXI"):
                    check([request], [0] * 256, rows)

    def test_write_error(self):
        counts = check(*transaction())
        self.assertEqual(counts["responses"], 1)
        self.assertEqual(counts["owner1Code2"], 1)

    def test_wrong_owner_and_duplicate(self):
        requests, memory, samples = transaction()
        samples[4]["pv"] = 0
        samples[4]["ov"] = 1
        with self.assertRaisesRegex(AssertionError, "wrong owner"):
            check(requests, memory, samples)
        requests, memory, samples = transaction()
        samples[5]["pv"] = 1
        with self.assertRaisesRegex(AssertionError, "Unowned output"):
            check(requests, memory, samples)

    def test_blocked_address(self):
        requests, memory, samples = transaction()
        stalled = dict(samples[2], ay=0, wy=0)
        samples.insert(2, stalled)
        for cycle, row in enumerate(samples):
            row["cycle"] = cycle
        samples[3]["aa"] += 4
        with self.assertRaisesRegex(AssertionError, "Unstable a"):
            check(requests, memory, samples)

    def test_mask_and_protection(self):
        for field in ("wm", "ap"):
            requests, memory, samples = transaction()
            samples[2][field] ^= 1
            with self.assertRaises(AssertionError):
                check(requests, memory, samples)

    def test_exokay(self):
        requests, memory, samples = transaction()
        samples[3]["br"] = 1
        with self.assertRaisesRegex(AssertionError, "EXOKAY"):
            check(requests, memory, samples)

    def test_trace_shape(self):
        with self.assertRaisesRegex(AssertionError, "Incomplete trace"):
            parse_trace("cycle reset\n0\n")
        with self.assertRaisesRegex(AssertionError, "Missing trace cycle"):
            parse_trace("cycle reset\n1 0\n")

    def test_vectors_are_reproducible(self):
        self.assertEqual(vectors(19, 32), vectors(19, 32))
        rows, _ = vectors(19, 32)
        self.assertEqual({row["mask"] for row in rows if row["write"]}, set(range(16)))

    def test_owner_mutation(self):
        source = "assign data_response_valid = data_response_valid_0;"
        self.assertEqual(mutate_owner(source), "assign data_response_valid = instruction_response_valid;")
        with self.assertRaisesRegex(AssertionError, "no longer matches"):
            mutate_owner("assign other = 0;")


if __name__ == "__main__":
    unittest.main()
