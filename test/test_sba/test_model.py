# SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
# SPDX-License-Identifier: MIT
"""Check observable SBA register and byte-transaction contracts independently."""

import unittest

from test.test_sba.reference import (
    MASK32,
    READ,
    SBADDRESS,
    SBCS,
    SBDATA,
    WRITE,
    ByteMemory,
    SbaModel,
)


def controls(size=2, read_address=False, read_data=False, increment=False, clear=0):
    return (size << 17 | int(read_address) << 20 | int(read_data) << 15 |
            int(increment) << 16 | clear)


class SbaModelTests(unittest.TestCase):
    def setUp(self):
        self.model = SbaModel()
        self.model.activate(True)

    def complete(self, memory=None, fault=False):
        transfer = self.model.pending.transfer
        self.model.accept_bus_request(transfer.bus_payload)
        self.model.complete_bus((memory or ByteMemory()).response(transfer, fault), fault)

    def test_capabilities_reset_and_readonly_fields(self):
        self.assertEqual(self.model.read_register(SBCS), (0x20040407, MASK32))
        self.model.access(SBCS, WRITE, MASK32)
        value, _ = self.model.read_register(SBCS)
        self.assertEqual(value >> 29, 1)
        self.assertEqual(value >> 5 & 127, 32)
        self.assertEqual(value & 31, 7)
        self.assertEqual(value >> 21 & 3, 0)
        self.assertEqual(value >> 12 & 7, 0)

    def test_all_supported_lanes_use_byte_memory(self):
        memory = ByteMemory()
        for width in (1, 2, 4):
            for lane in range(0, 4, width):
                size = {1: 0, 2: 1, 4: 2}[width]
                self.model.access(SBCS, WRITE, controls(size))
                self.model.access(SBADDRESS, WRITE, 0x100 + lane)
                self.model.access(SBDATA, WRITE, 0xC37A91E5)
                payload = self.model.pending.transfer.bus_payload
                self.assertEqual(payload[4], sum(1 << index for index in range(lane, lane + width)))
                self.complete(memory)
                self.model.access(SBCS, WRITE, controls(size, read_address=True))
                self.model.access(SBADDRESS, WRITE, 0x100 + lane)
                self.complete(memory)
                value, mask = self.model.access(SBDATA, READ)
                self.assertEqual(value & mask, 0xC37A91E5 & ((1 << (8 * width)) - 1))

    def test_read_on_data_returns_previous_word_before_starting_next(self):
        memory = ByteMemory()
        self.model.access(SBCS, WRITE, controls(read_address=True, read_data=True, increment=True))
        self.model.access(SBADDRESS, WRITE, 0x100)
        first = memory.response(self.model.pending.transfer)
        self.complete(memory)
        self.assertEqual(self.model.address, 0x104)
        self.assertEqual(self.model.access(SBDATA, READ)[0], first)
        self.assertEqual(self.model.pending.transfer.address, 0x104)
        self.complete(memory)
        self.assertEqual(self.model.address, 0x108)

    def test_bad_size_and_alignment_never_offer_bus(self):
        for size in range(3, 8):
            self.model.access(SBCS, WRITE, controls(size, clear=7 << 12))
            self.model.access(SBDATA, WRITE, 0)
            self.assertEqual(self.model.error, 4)
            self.assertIsNone(self.model.pending)
        for size, address in ((1, 1), (2, 1), (2, 2), (2, 3)):
            self.model.access(SBCS, WRITE, controls(size, clear=7 << 12))
            self.model.access(SBADDRESS, WRITE, address)
            self.model.access(SBDATA, WRITE, 0)
            self.assertEqual(self.model.error, 3)
            self.assertIsNone(self.model.pending)

    def test_error_w1c_is_bitwise_and_start_is_inhibited(self):
        self.model.access(SBCS, WRITE, controls(2))
        self.model.access(SBADDRESS, WRITE, 1)
        self.model.access(SBDATA, WRITE, 1)
        self.assertEqual(self.model.error, 3)
        self.model.access(SBCS, WRITE, controls(clear=1 << 12))
        self.assertEqual(self.model.error, 2)
        self.model.access(SBDATA, WRITE, 5)
        self.assertIsNone(self.model.pending)
        self.model.access(SBCS, WRITE, controls(clear=2 << 12))
        self.assertEqual(self.model.error, 0)

    def test_busy_accesses_do_not_change_the_pending_descriptor(self):
        self.model.access(SBADDRESS, WRITE, 0x100)
        self.model.access(SBDATA, WRITE, 0x12345678)
        original = self.model.pending.transfer
        self.model.access(SBADDRESS, WRITE, 0x200)
        self.assertTrue(self.model.busy_error)
        self.assertEqual(self.model.pending.transfer, original)
        self.assertEqual(self.model.address, 0x100)
        self.model.access(SBCS, WRITE, MASK32)
        self.assertEqual(self.model.access_size, 2)
        self.complete()
        self.model.access(SBDATA, WRITE, 1)
        self.assertIsNone(self.model.pending)
        self.model.access(SBCS, WRITE, controls(clear=1 << 22))
        self.model.access(SBDATA, WRITE, 1)
        self.assertTrue(self.model.offered)

    def test_success_only_increment_and_address_wrap(self):
        self.model.access(SBCS, WRITE, controls(increment=True))
        self.model.access(SBADDRESS, WRITE, 0xFFFFFFFC)
        self.model.access(SBDATA, WRITE, 1)
        self.complete(fault=True)
        self.assertEqual(self.model.address, 0xFFFFFFFC)
        self.assertEqual(self.model.error, 2)
        self.model.access(SBCS, WRITE, controls(increment=True, clear=7 << 12))
        self.model.access(SBDATA, WRITE, 1)
        self.complete()
        self.assertEqual(self.model.address, 0)

    def test_deactivation_drains_both_offered_and_accepted_transactions(self):
        for accepted in (False, True):
            model = SbaModel()
            model.activate(True)
            model.access(SBCS, WRITE, controls(read_address=True, increment=True))
            model.access(SBADDRESS, WRITE, 0x100)
            payload = model.pending.transfer.bus_payload
            if accepted:
                model.accept_bus_request(payload)
            model.activate(False)
            self.assertEqual(model.read_register(SBCS), (0, MASK32))
            model.activate(True)
            self.assertTrue(model.busy)
            self.assertEqual(model.read_register(SBCS)[0], 0x20240407)
            if not accepted:
                self.assertEqual(model.pending.transfer.bus_payload, payload)
                model.accept_bus_request(payload)
            model.complete_bus(0xDEADBEEF, fault=True)
            self.assertEqual((model.address, model.data, model.error), (0, 0, 0))
            self.assertTrue(model.idle)

    def test_exact_once_owner_and_wrong_lane_negative_controls(self):
        self.model.access(SBCS, WRITE, controls(0))
        self.model.access(SBADDRESS, WRITE, 0x103)
        self.model.access(SBDATA, WRITE, 0xA5)
        payload = self.model.pending.transfer.bus_payload
        wrong = (*payload[:3], 0xA5, *payload[4:])
        with self.assertRaisesRegex(AssertionError, "logical byte transaction"):
            self.model.accept_bus_request(wrong)
        self.model.accept_bus_request(payload)
        with self.assertRaisesRegex(AssertionError, "no unaccepted transaction owner"):
            self.model.accept_bus_request(payload)
        self.model.complete_bus(0)
        self.model.complete_bus(0xFFFFFFFF, True)
        self.assertEqual((self.model.data, self.model.error), (0xA5, 0))


if __name__ == "__main__":
    unittest.main()
