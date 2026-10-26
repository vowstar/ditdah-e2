# SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
# SPDX-License-Identifier: MIT
"""Check fixed debug hart effects, drain ownership and invalid trace rejection."""

import unittest

from debug_hart import Driver, OUTPUTS, Reference, check, configuration, expected, row, stop_mutant, unpack, vectors


def render(samples):
    return "\n".join(str(sample[0]) + " " + " ".join(f"{value:x}" for value in sample[1:]) for sample in samples) + "\n"


class DebugHartTests(unittest.TestCase):
    def test_configuration_and_alignment(self):
        self.assertEqual(configuration({})["resetVector"], 0)
        self.assertEqual(configuration({"resetVector": 0x80000002, "enableC": True})["resetVector"], 0x80000002)
        for value in ({"resetVector": -1}, {"resetVector": True}, {"resetVector": 1},
                      {"enableC": 1}, {"protectedMode": "true"}, {"unknown": 0}, []):
            with self.assertRaises(ValueError):
                configuration(value)

    def test_command_on_halt_edge_uses_prior_state(self):
        reference = Reference()
        output = unpack(reference.step(row(halt=1, pc=0x1000, valid=1, register=0x7B0), 0))
        self.assertFalse(output["halted"])
        self.assertTrue(reference.halted)
        self.assertEqual(reference.response, (0, 4))

    def test_cold_reset_clears_debug_state_when_idle(self):
        driver = Driver()
        driver.halt()
        driver.command(register=0x7B0, write=1, data=0xFFFFFFFF)
        driver.command(register=0x7B1, write=1, data=0x2000)
        driver.tick(reset=1, active=0)
        self.assertEqual((driver.reference.status(), driver.reference.pc, driver.reference.halted), (0x40000413, 0, False))

    def test_dcsr_warl_and_halfword_pc(self):
        for compressed in (False, True):
            for protected in (False, True):
                driver = Driver({"enableC": compressed, "protectedMode": protected})
                driver.halt(user=protected)
                driver.command(register=0x7B0, expected_result=(0x400004D0 if protected else 0x400004D3, 0))
                driver.command(register=0x7B0, write=1, data=0xFFFFFFFF)
                driver.command(register=0x7B0, expected_result=(0x400094D7 if protected else 0x400084D7, 0))
                driver.command(register=0x7B1, write=1, data=0x80000003)
                driver.command(register=0x7B1, expected_result=(0x80000002 if compressed else 0x80000000, 0))

    def test_readonly_backend_write_has_intent_without_commit(self):
        driver = Driver()
        driver.halt()
        result = driver.tick(valid=1, write=1, register=0xF11, data=0xFFFFFFFF)
        self.assertEqual(result["write_requested"], 1)
        self.assertEqual(result["write_pulse"], 0)
        self.assertEqual(driver.reference.response, (0, 3))
        self.assertEqual(driver.registers[0xF11], 0)
        driver.tick()

    def test_halt_waits_for_older_trap_and_fetch(self):
        driver = Driver()
        driver.tick(halt=1, empty=0, fetch_idle=0, pc=0x1000)
        driver.tick(completed=1, empty=0, fetch_idle=0, pc=0x1000)
        self.assertFalse(driver.reference.halted)
        driver.tick(empty=1, fetch_idle=0, pc=0x2000)
        self.assertFalse(driver.reference.halted)
        driver.tick(pc=0x2000)
        self.assertTrue(driver.reference.halted)
        self.assertEqual(driver.reference.pc, 0x2000)
        self.assertEqual(driver.reference.cause, 3)

    def test_step_stops_on_completion_before_drain(self):
        driver = Driver()
        driver.halt()
        driver.command(register=0x7B0, write=1, data=7)
        driver.resume()
        result = driver.tick(completed=1, empty=0, fetch_idle=0)
        self.assertEqual((result["step"], result["stop"]), (1, 1))
        driver.tick(pc=0x3000, fetch_idle=0)
        self.assertFalse(driver.reference.halted)
        driver.tick(pc=0x3000)
        self.assertEqual((driver.reference.pc, driver.reference.cause), (0x3000, 4))

    def test_deactivation_preserves_halt_and_debug_csrs(self):
        driver = Driver({"enableC": True, "protectedMode": True})
        driver.halt()
        driver.command(register=0x7B0, write=1, data=0x9004)
        driver.command(register=0x7B1, write=1, data=0x1002)
        driver.tick(valid=1, register=0x1001, ready=0)
        driver.tick(active=0, ready=0)
        self.assertIsNone(driver.reference.response)
        self.assertTrue(driver.reference.halted)
        self.assertEqual((driver.reference.status(), driver.reference.pc), (0x400094D4, 0x1002))
        driver.command(register=0x7B1, expected_result=(0x1002, 0))

    def test_offered_store_survives_deactivation(self):
        driver = Driver({"protectedMode": True})
        driver.halt()
        driver.inputs["bus_ready"] = 0
        driver.tick(valid=1, memory=1, write=1, address=0x421, size=0, data=0xAB, machine=0)
        first = driver.tick()
        second = driver.tick(active=0, allowed=0, machine=1)
        third = driver.tick(valid=1, register=0x1001, allowed=0, machine=1)
        for result in (first, second, third):
            self.assertEqual(tuple(result[name] for name in ("bus_valid", "bus_address", "bus_machine", "bus_data", "bus_mask", "bus_operation")),
                             (1, 0x421, 0, 0xAB00, 2, 0))
        self.assertEqual(third["ready"], 0)
        driver.inputs["bus_ready"] = 1
        for _ in range(driver.delay + 2):
            driver.tick(valid=1, register=0x1001)
        while driver.reference.held is not None:
            driver.tick(valid=1, register=0x1001)
        driver.tick()
        self.assertEqual(driver.memory[0x421], 0xAB)
        self.assertEqual(driver.reference.counts["memoryRequests"], 1)
        self.assertEqual(driver.reference.counts["discardedMemoryResults"], 1)

    def test_reset_level_and_response_hold(self):
        driver = Driver({"resetVector": 0x80000002, "enableC": True})
        driver.halt()
        driver.tick(valid=1, register=0x1001, ready=0)
        saved = driver.reference.response
        driver.tick(warm_reset=1, halt_on_reset=1, ready=0)
        for _ in range(4):
            result = driver.tick(warm_reset=1, halt_on_reset=1, ready=0)
            self.assertEqual((result["core_reset"], result["reset_pending"], result["reset_event"]), (1, 1, 0))
            self.assertEqual((result["data"], result["error"]), saved)
        driver.tick(halt_on_reset=1, ready=0)
        result = driver.tick(ready=0)
        self.assertEqual((result["core_reset"], result["halted"], result["reset_event"]), (0, 1, 1))
        self.assertEqual((driver.reference.status(), driver.reference.pc), (0x40000553, 0x80000002))
        driver.tick()

    def test_bad_owner_and_changed_held_request(self):
        reference = Reference()
        with self.assertRaisesRegex(AssertionError, "lacks an accepted"):
            reference.step(row(bus_valid=1), 0)
        reference = Reference()
        reference.step(row(valid=1, register=0x1001), 0)
        reference.step(row(valid=1, register=0x1002, ready=0), 1)
        with self.assertRaisesRegex(AssertionError, "request changed"):
            reference.step(row(valid=1, register=0x1003, ready=0), 2)

    def test_corrupt_stop_and_response_are_rejected(self):
        driver = Driver()
        driver.halt()
        driver.command(register=0x7B1, expected_result=(0x1000, 0), stall=2)
        samples, _ = expected(driver.rows)
        for name in ("stop", "data"):
            changed = list(samples)
            field = 1 + next(index for index, item in enumerate(OUTPUTS) if item[0] == name)
            cycle = next(index for index, value in enumerate(samples) if value[field])
            changed[cycle] = (*changed[cycle][:field], changed[cycle][field] ^ 1, *changed[cycle][field + 1:])
            with self.assertRaisesRegex(AssertionError, "mismatch"):
                check(driver.rows, render(changed))

    def test_atomic_operation_on_debug_memory_is_rejected(self):
        driver = Driver()
        driver.halt()
        driver.command(memory=1, address=0x400)
        driver.command(memory=1, write=1, address=0x400, data=0x12345678)
        samples, _ = expected(driver.rows)
        fields = {name: index for index, (name, _, _) in enumerate(OUTPUTS, 1)}
        cycle = next(index for index, sample in enumerate(samples) if sample[fields["bus_valid"]])
        field = fields["bus_operation"]
        self.assertTrue(all(sample[field] == 0 for sample in samples))
        check(driver.rows, render(samples))
        for operation in (1, 2, 11):
            changed = list(samples)
            changed[cycle] = (*changed[cycle][:field], operation, *changed[cycle][field + 1:])
            with self.assertRaisesRegex(AssertionError, "bus_operation"):
                check(driver.rows, render(changed))

    def test_fixed_and_random_vectors(self):
        for compressed, protected in ((False, False), (True, True)):
            parameters = configuration({"enableC": compressed, "protectedMode": protected})
            rows = vectors(parameters)
            samples, counts = expected(rows, parameters)
            self.assertGreater(counts["requests"], 300)
            self.assertEqual(counts["pending"], 0)
            self.assertEqual(counts["memoryRequests"], counts["memoryResponses"])
            self.assertEqual(counts["cancelled"], 4)
            check(rows, render(samples), parameters)

    def test_mutant_requires_one_stop_assignment(self):
        self.assertEqual(stop_mutant("assign core_stop = halted;"), "assign core_stop = (halted) & ~core_completed;")
        for source in ("", "assign core_stop = a; assign core_stop = b;"):
            with self.assertRaises(ValueError):
                stop_mutant(source)


if __name__ == "__main__":
    unittest.main()
