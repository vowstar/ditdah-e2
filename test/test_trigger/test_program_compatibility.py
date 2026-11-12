# SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
# SPDX-License-Identifier: MIT
"""Check trigger proof preparation after Program Buffer integration."""

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from formal.trigger import run


class ProgramCompatibilityTests(unittest.TestCase):
    def test_multiply_mutation_preserves_both_debug_gates(self):
        for gate in (" & ~_debug_core_stop", " & (~_debug_core_stop | xInjected)"):
            with self.subTest(gate=gate):
                source = ("& ~eligibleInterrupt & ~sleeping_0 & ~x_fault" + gate +
                          "\n    & ~_csr_trigger_matched;")
                changed = run.mutate({run.CORE_RTL: source.encode()}, "negative-multiply-start")
                self.assertEqual(changed[run.CORE_RTL],
                                 ("& ~eligibleInterrupt & ~sleeping_0 & ~x_fault" + gate + ";").encode())

    def test_multiply_mutation_rejects_missing_and_ambiguous_gates(self):
        source = ("& ~eligibleInterrupt & ~sleeping_0 & ~x_fault & (~_debug_core_stop | xInjected)\n"
                  "    & ~_csr_trigger_matched;")
        for text in (source.replace("~_csr_trigger_matched", "other_condition"), source + source):
            with self.subTest(text=text), self.assertRaisesRegex(ValueError, "Mutation anchor differs"):
                run.mutate({run.CORE_RTL: text.encode()}, "negative-multiply-start")

    def test_older_mutation_preserves_the_renumbered_flush_wire(self):
        for number in (466, 479):
            with self.subTest(number=number):
                name = f"_GEN_{number}"
                source = f"wire {name} = redirect_0 | returning | waiting | waking | synchronized;\n"
                changed = run.mutate({run.CORE_RTL: source.encode()}, "negative-older-priority")
                self.assertEqual(changed[run.CORE_RTL], f"wire {name} = 1'h0;\n".encode())

    def test_older_mutation_rejects_missing_and_ambiguous_flush_wires(self):
        source = "wire _GEN_479 = redirect_0 | returning | waiting | waking | synchronized;\n"
        for text in (source.replace("redirect_0", "other_redirect"),
                     source + source.replace("_GEN_479", "_GEN_480")):
            with self.subTest(text=text), self.assertRaisesRegex(ValueError, "Mutation anchor differs"):
                run.mutate({run.CORE_RTL: text.encode()}, "negative-older-priority")

    @staticmethod
    def candidate(root, ports):
        source = ("module DitDahE2(input clock, output " + ", ".join(ports) + "); endmodule\n").encode()
        (root / run.CORE_RTL).write_bytes(source)
        manifest = {"top": "DitDahE2", "exitStatus": 0,
                    "parameters": {"triggerCount": 2, "enableDebug": True, "enableM": True,
                                   "enableC": False, "protectedMode": False},
                    "rtlHashes": {run.CORE_RTL: run.sha(source)}, "sourceHashes": {}}
        (root / "manifest.json").write_text(json.dumps(manifest))

    def test_core_preparation_requires_all_observation_ports(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.candidate(root, run.CORE_DEBUG_OUTPUTS)
            run.load_rtl(root, "DitDahE2", True, root)
            for missing in run.CORE_DEBUG_OUTPUTS:
                with self.subTest(missing=missing):
                    self.candidate(root, [name for name in run.CORE_DEBUG_OUTPUTS if name != missing])
                    with self.assertRaisesRegex(ValueError, "requires Program Buffer observation ports"):
                        run.load_rtl(root, "DitDahE2", True, root)

    def test_wrapper_preparation_rejects_implicit_observation_ports(self):
        unit = (run.HERE / run.UNIT_WRAPPER).read_bytes()
        core = (run.HERE / run.CORE_WRAPPER).read_bytes()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / run.UNIT_WRAPPER).write_bytes(unit)
            (root / run.CORE_WRAPPER).write_bytes(core)
            with patch.object(run, "HERE", root):
                run.check_wrappers()
                for name in run.CORE_DEBUG_OUTPUTS:
                    with self.subTest(name=name):
                        changed = core.replace(("." + name + "()").encode(), b"")
                        (root / run.CORE_WRAPPER).write_bytes(changed)
                        with self.assertRaisesRegex(ValueError, "observation ports differ"):
                            run.check_wrappers()


if __name__ == "__main__":
    unittest.main()
