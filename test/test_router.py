# SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
# SPDX-License-Identifier: MIT
"""Check router classification, ownership checks, and mutation matching."""

import os
import tempfile
from pathlib import Path
import unittest

from router import FIELDS, REQUEST, check, digest, mutate, parse_trace, route, vectors, verify_hashes


REGIONS = {"rom": {"base": 0, "size": 64}, "sram": {"base": 256, "size": 64},
           "console": {"base": 512, "size": 8}, "timer": {"base": 1024, "size": 20}}


def sample(cycle, **fields):
    return {**dict.fromkeys(FIELDS, 0), "cycle": cycle, **fields}


def request(address=256, write=0, mask=0, size=2, owner=1):
    return dict(owner=owner, address=address, write=write, data=0x12345678, mask=mask, size=size)


def transaction():
    row = request()
    offered = sample(1, data_request_valid=1, data_request_ready=1,
                     memoryData_request_valid=1, memoryData_request_ready=1)
    for port in ("data", "memoryData"):
        offered.update({f"{port}_request_{key}": row[key] for key in REQUEST})
    response = sample(2, data_response_valid=1, data_response_data=0x20000001,
                      memoryData_response_valid=1, memoryData_response_data=0x20000001)
    accepted = dict(response, cycle=3, data_response_ready=1, memoryData_response_ready=1)
    return [row], [sample(0, reset=1), offered, response, accepted, sample(4)]


class RouterTests(unittest.TestCase):
    def test_region_boundaries_and_relative_address(self):
        for name, endpoint in (("rom", "memoryData"), ("sram", "memoryData"),
                               ("console", "console"), ("timer", "timer")):
            region = REGIONS[name]
            for offset in (0, region["size"] - 4):
                address = region["base"] + offset
                expected = offset if name in ("console", "timer") else address
                self.assertEqual(route(REGIONS, 1, request(address)), (endpoint, expected))
            self.assertIsNone(route(REGIONS, 1, request(region["base"] + region["size"])))
        high = {**REGIONS, "sram": {"base": 0xFFFFFFFC, "size": 4}}
        self.assertEqual(route(high, 1, request(0xFFFFFFFF, 1, 8, 0)), ("memoryData", 0xFFFFFFFF))

    def test_instruction_and_rom_direction(self):
        for address in (0, 256):
            self.assertEqual(route(REGIONS, 0, request(address)), ("memoryInstruction", address))
            self.assertIsNone(route(REGIONS, 0, request(address, 1, 15)))
        self.assertIsNone(route(REGIONS, 1, request(0, 1, 15)))
        self.assertIsNone(route(REGIONS, 0, request(512)))
        self.assertIsNone(route(REGIONS, 0, request(256, size=1)))

    def test_masks_alignment_and_mmio_width(self):
        for lane in range(4):
            for size in range(4):
                for mask in range(16):
                    valid = size < 3 and lane % (1 << size) == 0 and mask == (((1 << (1 << size)) - 1) << lane)
                    self.assertEqual(route(REGIONS, 1, request(256 + lane, 1, mask, size)) is not None, valid)
        for address in (512, 1024):
            for size in (0, 1):
                self.assertIsNone(route(REGIONS, 1, request(address, size=size)))
        self.assertIsNone(route(REGIONS, 1, request(mask=1)))

    def test_valid_response_and_backpressure(self):
        rows, samples = transaction()
        result = check(REGIONS, rows, samples)
        self.assertEqual(result["responses"], 1)
        self.assertEqual(result["responseStalls"], 1)
        self.assertEqual(result["endpointResponses"], 1)

    def test_rejected_write_has_no_endpoint(self):
        row = request(0, 1, 15)
        first = sample(1, data_request_valid=1, data_request_ready=1)
        first.update({"data_request_" + key: row[key] for key in REQUEST})
        samples = [sample(0, reset=1), first, sample(2, data_response_valid=1, data_response_ready=1, data_response_fault=1)]
        self.assertEqual(check(REGIONS, [row], samples)["rejected"], 1)
        samples[1]["memoryData_request_valid"] = 1
        with self.assertRaisesRegex(AssertionError, "Wrong endpoint offer"):
            check(REGIONS, [row], samples)

    def test_wrong_endpoint_and_duplicate(self):
        rows, samples = transaction()
        samples[1]["timer_request_valid"] = 1
        with self.assertRaisesRegex(AssertionError, "Wrong endpoint offer"):
            check(REGIONS, rows, samples)
        rows, samples = transaction()
        samples[4]["data_response_valid"] = 1
        with self.assertRaisesRegex(AssertionError, "Unowned data response"):
            check(REGIONS, rows, samples)

    def test_wrong_response_and_unstable_request(self):
        rows, samples = transaction()
        samples[2]["data_response_data"] ^= 1
        with self.assertRaisesRegex(AssertionError, "Wrong data response payload"):
            check(REGIONS, rows, samples)
        rows, samples = transaction()
        samples.insert(1, dict(samples[1], data_request_ready=0, memoryData_request_ready=0))
        for cycle, row in enumerate(samples):
            row["cycle"] = cycle
        samples[2]["memoryData_request_address"] += 4
        with self.assertRaisesRegex(AssertionError, "Unstable memoryData request"):
            check(REGIONS, rows, samples)

    def test_changed_blocked_response(self):
        rows, samples = transaction()
        samples[3]["data_response_data"] ^= 1
        with self.assertRaisesRegex(AssertionError, "Unstable data response"):
            check(REGIONS, rows, samples)

    def test_mutations_match_once(self):
        forms = {"direction": "wire allowed = region & ~instruction_request_bits_write;",
                 "duplicate": "assign memoryData_request_valid = ~dataActive & data_request_valid & memory;",
                 "endpoint": "assign timer_request_valid = ~dataActive & data_request_valid & timer_0;"}
        for name, text in forms.items():
            self.assertNotEqual(mutate(text, name), text)
            with self.assertRaisesRegex(AssertionError, "no longer matches"):
                mutate(text + text, name)
            with self.assertRaisesRegex(AssertionError, "no longer matches"):
                mutate("", name)

    def test_vectors_and_trace_shape(self):
        self.assertEqual(vectors(REGIONS, 7, 10), vectors(REGIONS, 7, 10))
        for owner in (0, 1):
            rows = [row for row in vectors(REGIONS, 7, 0) if row["owner"] == owner]
            self.assertEqual({row["mask"] for row in rows}, set(range(16)))
            self.assertEqual({row["size"] for row in rows}, set(range(4)))
        with self.assertRaisesRegex(AssertionError, "Unexpected trace fields"):
            list(parse_trace(["cycle reset\n"]))
        with self.assertRaisesRegex(AssertionError, "Incomplete trace"):
            list(parse_trace([" ".join(FIELDS), "0 1"]))

    def test_changed_frozen_input(self):
        with tempfile.TemporaryDirectory(prefix="ditdah-e2-router-test-", dir="/data/tmp" if os.access("/data/tmp", os.W_OK) else None) as directory:
            base = Path(directory)
            path = base / "input.txt"
            path.write_text("original")
            hashes = {path.name: digest(path)}
            verify_hashes(base, hashes)
            path.write_text("changed")
            with self.assertRaisesRegex(AssertionError, "Changed frozen input"):
                verify_hashes(base, hashes)


if __name__ == "__main__":
    unittest.main()
