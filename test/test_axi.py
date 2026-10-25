# SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
# SPDX-License-Identifier: MIT
"""Reject semantic faults in adapter traces and formal mutations."""

import unittest

from axi import CHANNELS, READY, FIELDS, check, parse_trace, vectors
from axi_formal import mutate_owner


def sample(cycle, **values):
    row = {"cycle": cycle, "reset": 0}
    for channel, payload in CHANNELS.items():
        row[channel + "v"] = 0
        row[READY[channel]] = 0
        row.update(dict.fromkeys(payload, 0))
    return {**row, **values}


def transaction():
    request = dict(zip(FIELDS, (1, 1, 0x20000003, 0x11223344, 8, 0, 1, 0, 0, 0, 0, 0, 2), strict=True))
    samples = [sample(0, reset=1), sample(1, dv=1, dr=1, da=request["address"], dw=1,
                                        dd=request["data"], dm=8, dp=1),
               sample(2, av=1, ay=1, aa=0x20000000, ap=1, wv=1, wy=1, wd=request["data"], wm=8),
               sample(3, bv=1, by=1, br=2), sample(4, pv=1, pr=1, pf=1), sample(5)]
    return [request], [0] * 256, samples


class AxiTests(unittest.TestCase):
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
        source = "assign data_response_valid = active & done & dataOwner;"
        self.assertEqual(mutate_owner(source), "assign data_response_valid = instruction_response_valid;")
        with self.assertRaisesRegex(AssertionError, "no longer matches"):
            mutate_owner("assign other = 0;")


if __name__ == "__main__":
    unittest.main()
