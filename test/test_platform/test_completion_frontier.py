# SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
# SPDX-License-Identifier: MIT
"""Exercise terminal instruction ownership with an already held frontier offer."""

from types import SimpleNamespace
import unittest

from test.test_platform.verify_platform import check, cycles, instruction_tail


def example():
    base = 0x10000
    words = {base: 0x100F, base + 4: 0x100F, base + 8: 0x6F, base + 12: 0x13}
    image = SimpleNamespace(entry=base, symbols={"software_done": base + 8}, words=lambda: words.copy())
    regions = {"itcm": {"base": base, "size": 4096, "backend": "sram"}}
    events = {}

    def add(cycle, value):
        events.setdefault(cycle, []).append(value)

    for start, finish, address in ((0, 1, base), (2, 3, base + 4), (4, 5, base + 8),
                                    (8, 12, base + 12), (12, 13, base + 8), (13, 14, base + 12),
                                    (14, 15, base + 8), (15, 16, base + 12), (16, None, base + 8)):
        offer = 5 if start == 8 else start
        add(offer, f"P {offer} I {address} 0 0 0 2 1")
        add(start, f"Q {start} I {address} 0 0 0 2 1")
        if finish is not None:
            add(finish, f"S {finish} I {words[address]} 0")
    for cycle, pc in ((2, base), (4, base + 4), (6, base + 8), (14, base + 8), (16, base + 8)):
        add(cycle, f"R {cycle} {pc} {words[pc]} {pc if pc == base + 8 else pc + 4} 0 0 0 0 0 0 0")
    text = "".join(f"T {cycle} 0 1 0 0 0 0\n" + "\n".join(events.get(cycle, [])) + "\n" for cycle in range(17))
    text = "\n".join(line for line in text.splitlines() if line) + "\nF 17\n"
    witness = [base + 8, 6, 4, 9, 9, 8, 9, 16, base + 8, 0, 0, 0, 2, 1, 0, *([0] * 12)]
    assert len(witness) == 27
    text += "J " + " ".join(map(str, witness)) + "\n"
    text += "".join(f"W {address} {value}\n" for address, value in words.items())
    return image, regions, text


class CompletionFrontierTests(unittest.TestCase):
    def check(self, trace):
        image, regions, _ = example()
        return check(image, {"enableM": True, "enableC": True}, regions, trace,
                     "local", expected_output=b"", allow_instruction_tail=True)

    def test_held_terminal_offer_drains_before_the_cut(self):
        _, _, trace = example()
        result = self.check(trace)
        self.assertEqual(result["completion"]["instructionOfferFrontier"], 4)
        self.assertEqual(result["completion"]["pendingInstructionId"], 9)
        with self.assertRaises(AssertionError):
            cycles(trace)

    def test_old_response_and_held_payload_cannot_be_discarded(self):
        _, _, trace = example()
        dropped = trace.replace("S 12 I 19 0\n", "")
        with self.assertRaisesRegex(AssertionError, "overwrote its owner"):
            self.check(dropped)
        changed = trace.replace("Q 8 I 65548", "Q 8 I 65552")
        with self.assertRaisesRegex(AssertionError, "differs from its first offer"):
            self.check(changed)

    def test_witness_is_bound_to_observed_terminal_retirement(self):
        _, _, trace = example()
        with self.assertRaisesRegex(AssertionError, "frontier differs"):
            self.check(trace.replace("J 65544 6 4 ", "J 65544 6 3 "))
        with self.assertRaisesRegex(AssertionError, "Missing instruction"):
            instruction_tail(trace + next(line for line in trace.splitlines(True) if line.startswith("J ")))


if __name__ == "__main__":
    unittest.main()
