# SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
# SPDX-License-Identifier: MIT
"""Check local-memory history validation and invalid-access boundaries."""

import unittest
from test.units.local_memory import CASES, FIELDS, REQUEST, check, legal, request, vectors


def sample(cycle, **fields):
    return {**dict.fromkeys(FIELDS, 0), "cycle": cycle, **fields}


def trace():
    p = {"baseAddress": 256, "sizeBytes": 4, "readLatency": 1}
    write = request(256, phase=0, write=1, data=0x12345678, mask=15)
    read = request(256, phase=2, owner=0)
    a = sample(1, phase=0, data_request_valid=1, data_request_ready=1)
    b = sample(4, phase=2, instruction_request_valid=1, instruction_request_ready=1)
    for field in REQUEST:
        a["data_request_" + field] = write[field]
        b["instruction_request_" + field] = read[field]
    return p, [write, read], [sample(0, reset=1), a, sample(2, data_response_valid=1, data_response_ready=1),
                             sample(3, reset=1), b, sample(5, instruction_response_valid=1,
                             instruction_response_ready=1, instruction_response_data=0x12345678)]


class LocalMemoryTests(unittest.TestCase):
    def test_boundaries_and_shapes(self):
        p = {"baseAddress": 0xFFFFFFFC, "sizeBytes": 4, "readLatency": 2}
        for lane in range(4):
            for size in range(4):
                for mask in range(16):
                    r = request(p["baseAddress"] + lane, write=1, size=size, mask=mask)
                    expected = size < 3 and lane % (1 << size) == 0 and mask == ((1 << (1 << size)) - 1) << lane
                    self.assertEqual(legal(p, 1, r), expected)
        self.assertFalse(legal(p, 1, request(0, write=1, mask=15)))
        self.assertFalse(legal(p, 0, request(p["baseAddress"], write=1, mask=15)))
        self.assertFalse(legal(p, 1, request(p["baseAddress"], operation=1)))

    def test_memory_survives_quiescent_reset(self):
        self.assertEqual(check(*trace())["responses"], 2)
        p, rows, samples = trace()
        samples[-1]["instruction_response_data"] = 0
        with self.assertRaisesRegex(AssertionError, "Wrong local-memory response"):
            check(p, rows, samples)

    def test_latency_and_owner_faults_are_rejected(self):
        p, rows, samples = trace()
        p["readLatency"] = 2
        with self.assertRaisesRegex(AssertionError, "owner or latency"):
            check(p, rows, samples)
        p, rows, samples = trace()
        samples[-1].update(instruction_response_valid=0, data_response_valid=1)
        with self.assertRaisesRegex(AssertionError, "owner or latency"):
            check(p, rows, samples)

    def test_real_capacity_and_nonpower_cases(self):
        self.assertEqual({p["sizeBytes"] for p in CASES}, {4, 12, 16384, 32768})
        self.assertEqual({p["readLatency"] for p in CASES}, {1, 2})
        p = CASES[1]
        self.assertEqual(vectors(p, 7, 3), vectors(p, 7, 3))
        self.assertEqual(sum(r["phase"] == 0 for r in vectors(p, 7, 0)), 3)


if __name__ == "__main__":
    unittest.main()
