# SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
# SPDX-License-Identifier: MIT
"""Exercise ownership and trace-checker failure paths without building RTL."""

import unittest

from test.test_sba import arbiter, verify_dm, verify_sba
from test.test_sba.reference import SBADDRESS, SBCS, SBDATA, WRITE, SbaModel


def render(samples, hex_fields):
    return "\n".join(" ".join(f"{value:x}" if index in hex_fields else str(value)
                              for index, value in enumerate(sample)) for sample in samples)


class SbaProtocolTests(unittest.TestCase):
    def test_short_reset_pulse_is_delivered_after_bus_drain_before_hart_ack(self):
        driver = verify_dm.Driver()
        driver.dmi(0x10, WRITE, 1)
        driver.bus_delay = 40
        driver.dmi(SBCS, WRITE, verify_sba.control(read_address=True))
        driver.dmi(SBADDRESS, WRITE, 0x100)
        driver.dmi(0x10, WRITE, 3)
        driver.dmi(0x10, WRITE, 1)
        self.assertFalse(driver.reference.ndmreset)
        self.assertTrue(driver.reference.reset_waiting)
        while not driver.reference.sba.idle:
            self.assertFalse(driver.reset_ack)
            sample, _ = driver.tick()
            self.assertEqual(sample[6], 0)
        self.assertFalse(driver.reset_ack)
        sample, _ = driver.tick()
        self.assertEqual(sample[6], 1)
        self.assertFalse(driver.reference.reset_waiting)
        driver.tick()
        self.assertEqual(driver.rows[-1][9], 1)
        while driver.reset_ack:
            driver.tick()
        self.assertTrue(driver.reference.have_reset)
        self.assertEqual(driver.reference.counts["resetEvents"], 1)

    def test_same_edge_deactivation_discards_a_faulting_response(self):
        model = SbaModel()
        model.activate(True)
        model.access(SBCS, WRITE, verify_sba.control(read_address=True, increment=True))
        model.access(SBADDRESS, WRITE, 0x100)
        model.accept_bus_request(model.pending.transfer.bus_payload)
        verify_sba.step(model, verify_sba.row(active=0, response_valid=1,
                                             response_data=0xDEADBEEF, response_fault=1), 0)
        model.activate(True)
        self.assertTrue(model.idle)
        self.assertEqual((model.address, model.data, model.error), (0, 0, 0))

    def test_busy_conflict_uses_pre_completion_owner(self):
        model = SbaModel()
        model.activate(True)
        model.access(SBADDRESS, WRITE, 0x100)
        model.access(SBDATA, WRITE, 0x1234)
        model.accept_bus_request(model.pending.transfer.bus_payload)
        verify_sba.step(model, verify_sba.row(accepted=1, address=SBDATA, operation=WRITE,
                                             value=0xFFFF, response_valid=1), 0)
        self.assertTrue(model.idle)
        self.assertTrue(model.busy_error)
        self.assertEqual(model.counts["writes"], 1)

    def test_vector_widths_and_trace_dimensions_fail_closed(self):
        for values in ({"active": True}, {"address": 128}, {"operation": 4}, {"response_data": -1}):
            with self.assertRaises(ValueError):
                verify_sba.row(**values)
        with self.assertRaisesRegex(AssertionError, "field count"):
            verify_sba.check([verify_sba.row()], "0 0 0")
        with self.assertRaisesRegex(AssertionError, "sample count"):
            verify_sba.check([verify_sba.row()], "")

    def test_read_request_unused_data_still_has_backpressure_stability(self):
        rows = verify_sba.vectors(1)
        model = SbaModel()
        samples = [verify_sba.step(model, row, index)[0] for index, row in enumerate(rows)]
        index = next(index for index in range(1, len(rows))
                     if samples[index - 1][3] and not rows[index - 1][6] and samples[index][3] and not samples[index][6])
        changed = list(samples[index])
        changed[7] ^= 1
        samples[index] = tuple(changed)
        with self.assertRaisesRegex(AssertionError, "changed under backpressure"):
            verify_sba.check(rows, render(samples, verify_sba.HEX_OUTPUT))

    def test_dmi_stalled_read_snapshot_cannot_change(self):
        rows = verify_dm.vectors()
        model = verify_dm.Reference()
        samples = [model.step(row, index)[0] for index, row in enumerate(rows)]
        self.assertGreater(model.counts["requestBackpressure"], 0)
        index = next(index for index, sample in enumerate(samples) if sample[2] and not rows[index][2])
        changed = list(samples[index])
        changed[3] ^= 1
        samples[index] = tuple(changed)
        with self.assertRaisesRegex(AssertionError, "DM SBA mismatch"):
            verify_dm.check(rows, render(samples, verify_dm.HEX_OUTPUT))

    def test_arbiter_checker_rejects_response_to_both_sources(self):
        rows = arbiter.vectors(1)
        model = arbiter.Reference()
        samples = [model.step(row, index) for index, row in enumerate(rows)]
        index = next(index for index, sample in enumerate(samples) if sample[9])
        changed = list(samples[index])
        changed[6] = 1
        samples[index] = tuple(changed)
        with self.assertRaisesRegex(AssertionError, "Arbiter transaction mismatch"):
            arbiter.check(rows, render(samples, arbiter.HEX_OUTPUT))


if __name__ == "__main__":
    unittest.main()
