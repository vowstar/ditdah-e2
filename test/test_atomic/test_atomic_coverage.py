# SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
# SPDX-License-Identifier: MIT
"""Keep ordinary native coverage separate from shared atomic execution."""

from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "scripts"))
from test.test_ditdah_e2.verify import retirement_coverage


class AtomicCoverageTests(unittest.TestCase):
    def test_atomic_configuration_keeps_ordinary_instructions(self):
        atomic = {"lr.w", "sc.w", "amoswap.w", "amoadd.w", "amoxor.w", "amoand.w", "amoor.w",
                  "amomin.w", "amomax.w", "amominu.w", "amomaxu.w"}
        required, excluded = retirement_coverage(atomic | {"lw", "sw", "fence", "ecall"}, True)
        self.assertEqual(required, {"lw", "sw", "fence", "ecall"})
        self.assertEqual(excluded, sorted(atomic))

    def test_disabled_atomic_configuration_excludes_nothing(self):
        required, excluded = retirement_coverage({"lw", "sw", "lr.w"}, False)
        self.assertEqual(required, {"lw", "sw", "lr.w"})
        self.assertEqual(excluded, [])


if __name__ == "__main__":
    unittest.main()
