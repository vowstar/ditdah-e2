# SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
# SPDX-License-Identifier: MIT

import copy
import unittest

import verify_platform as platform


def device_groups():
    events = {}

    def add(cycle, text):
        events.setdefault(cycle, []).append(text.split())

    for cycle, byte in ((0, 69), (3, 50), (6, 51), (9, 10)):
        add(cycle, f"Q {cycle} C 0 1 {byte} 15 2")
        add(cycle + 1, f"X {cycle + 1} {byte}")
        add(cycle + 2, f"S {cycle + 2} C 0 0")
    add(86, "Q 86 T 12 1 0 15 2")
    add(87, "S 87 T 0 0")
    add(90, "Q 90 T 8 1 0 15 2")
    add(91, "S 91 T 0 0")
    add(92, "Q 92 T 0 0 0 0 2")
    add(101, "S 101 T 0 0")
    add(102, "Q 102 T 8 1 5 15 2")
    add(104, "S 104 T 0 0")
    return [[f"T {cycle} {int(cycle == 99)} 1 {int(cycle >= 100)} {int(91 <= cycle <= 102)} 0 0".split(),
             *events.get(cycle, [])] for cycle in range(106)]


class PlatformTests(unittest.TestCase):
    def test_fixed_device_timing_and_snapshot(self):
        states, responses, timer, console = platform.device_expectations(device_groups())
        self.assertEqual(states[90][5:], (0, 0, 0))
        self.assertEqual(states[91][5:], (0, 1, 0))
        self.assertEqual(states[99][5:], (0, 1, 0))
        self.assertEqual(states[100][5:], (1, 1, 0))
        self.assertEqual(states[103][5:], (1, 0, 0))
        self.assertEqual(responses[101, "T"], (0, 0))
        self.assertEqual(timer["requests"], 4)
        self.assertEqual(timer["timerTransitions"], 2)
        self.assertEqual(console["writes"], 4)

    def test_device_fault_has_no_byte_effect(self):
        groups = device_groups()
        groups[15].append("Q 15 C 0 0 0 0 0".split())
        groups[16].append("S 16 C 0 1".split())
        _, responses, _, console = platform.device_expectations(groups)
        self.assertEqual(responses[16, "C"], (0, 1))
        self.assertEqual(console["faults"], 1)
        groups[16].append("X 16 69".split())
        with self.assertRaisesRegex(AssertionError, "Console transfer"):
            platform.device_expectations(groups)

    def test_timer_read_uses_acceptance_snapshot(self):
        groups = device_groups()
        groups[101][1][3] = "1"
        with self.assertRaisesRegex(AssertionError, "Device response"):
            platform.device_expectations(groups)

    def test_timer_tick_and_interrupt_edges(self):
        for cycle, field, value, message in ((99, 2, "0", "tick"), (99, 4, "1", "Timer state"),
                                             (90, 5, "1", "Timer state"), (103, 5, "1", "Timer state"),
                                             (93, 6, "1", "Timer state")):
            groups = device_groups()
            groups[cycle][0][field] = value
            with self.subTest(cycle=cycle, field=field), self.assertRaisesRegex(AssertionError, message):
                platform.device_expectations(groups)

    def test_device_response_owner_and_completion(self):
        groups = device_groups()
        groups[92].append("S 92 T 0 0".split())
        with self.assertRaisesRegex(AssertionError, "Device response"):
            platform.device_expectations(groups)
        groups = device_groups()
        groups[104] = groups[104][:1]
        with self.assertRaisesRegex(AssertionError, "did not drain"):
            platform.device_expectations(groups)
        groups = device_groups()
        groups[91].append(copy.copy(groups[91][1]))
        with self.assertRaisesRegex(AssertionError, "Duplicate device"):
            platform.device_expectations(groups)

    def test_console_bytes_require_an_accepted_write(self):
        for cycle, records in ((1, []), (1, ["X 1 70"]), (2, ["X 2 69"])):
            groups = device_groups()
            groups[cycle] = [groups[cycle][0], *[record.split() for record in records]]
            with self.subTest(cycle=cycle, records=records), self.assertRaisesRegex(AssertionError, "Console transfer"):
                platform.device_expectations(groups)

    def test_trace_clock_and_final_words(self):
        groups, words = platform.cycles("T 0 0 1 0 0 0 0\nF 1\nW 0 111\n")
        self.assertEqual(len(groups), 1)
        self.assertEqual(words, {0: 111})
        for trace in ("T 1 0 1 0 0 0 0\nF 1\nW 0 111\n",
                      "T 0 0 1 0 0 0 0\nR 1 0\nF 1\nW 0 111\n",
                      "T 0 0 1 0 0 0 0\nF 2\nW 0 111\n",
                      "T 0 0 1 0 0 0 0\nF 1 999\nW 0 111\n",
                      "T 0 0 1 0 0 0 0\nF 1\nW 0 111\nW 0 111\n",
                      "T 0 0 1 0 0 0 0\nF 1\n",
                      "T 0 0 1 0 0 0 0\nW 0 111\n"):
            with self.subTest(trace=trace), self.assertRaises(AssertionError):
                platform.cycles(trace)

    def test_negative_control_target_and_rejection(self):
        original = "assign timerInterrupt = time_0 >= compare;"
        self.assertEqual(platform.timer_comparator_mutant(original),
                         "assign timerInterrupt = time_0 > compare;")
        for source in ("assign timerInterrupt = compare < time_0;", original + original):
            with self.subTest(source=source), self.assertRaisesRegex(AssertionError, "mutation"):
                platform.timer_comparator_mutant(source)
        with self.assertRaisesRegex(AssertionError, "accepted an injected error"):
            platform.rejected(lambda: None)
        groups = device_groups()
        groups[101][1][3] = "1"
        self.assertEqual(platform.rejected(lambda: platform.device_expectations(groups)),
                         "Device response differs")

    def test_one_architectural_event_per_cycle(self):
        retirement = "R 0 0 111 0 0 0 0 0 0 0\n"
        interrupt = "N 0 0 4 2147483655\n"
        for events in (retirement + retirement, retirement + interrupt,
                       interrupt + retirement, interrupt + interrupt):
            with self.subTest(events=events), self.assertRaises(AssertionError):
                platform.cycles("T 0 0 1 0 0 0 0\n" + events + "F 1\nW 0 111\n")


if __name__ == "__main__":
    unittest.main()
