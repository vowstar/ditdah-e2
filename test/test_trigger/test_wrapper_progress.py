# SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
# SPDX-License-Identifier: MIT
"""Reject incomplete progress and simulator assertion failures."""

import unittest

from formal.trigger.run import CORE_ASSERTIONS, HERE, labels
from test.test_trigger.wrapper_progress import mutate, result, simulation_wrapper


class WrapperProgressTests(unittest.TestCase):
    def test_adapter_keeps_all_assertions_and_both_fault_mutations(self):
        wrapper = (HERE / "trigger_core_formal.sv").read_text()
        simulated = simulation_wrapper(wrapper)
        self.assertEqual(simulated.count("assert("), len(CORE_ASSERTIONS))
        self.assertEqual(labels(wrapper, "assert"), set(CORE_ASSERTIONS))
        for name in ("phase-gate", "clear-setup-debt"):
            changed = mutate(wrapper, name)
            self.assertNotEqual(changed, wrapper)
            with self.assertRaisesRegex(ValueError, "anchor changed"):
                mutate("", name)

    def test_exit_zero_cannot_hide_failed_assertions_or_missing_progress(self):
        valid = "WRAPPER_RESULT scenario=0 finished=1 setup_requests=2 setup_responses=2 halted_ready=1 resumes=1\n"
        self.assertEqual(result(valid, 0, 0)["resumes"], 1)
        for log, status in ((valid, 1), ("ERROR: assertion failed\n" + valid, 0), ("FATAL: error\n" + valid, 0),
                            (valid.replace("setup_responses=2", "setup_responses=0"), 0), (valid + valid, 0), ("", 0)):
            with self.subTest(log=log, status=status), self.assertRaises(ValueError):
                result(log, status, 0)


if __name__ == "__main__":
    unittest.main()
