# SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
# SPDX-License-Identifier: MIT
"""Check measurement definitions and independent performance trace rejection."""

import json
import os
from pathlib import Path
import tempfile
import unittest

from fetch_performance import DONE, check, design, digest, negative_controls, ports, stable, workload, wrapper
from model import Model


def temporary():
    return tempfile.TemporaryDirectory(prefix="ditdah-e2-fetch-performance-test-",
                                       dir="/data/tmp" if os.access("/data/tmp", os.W_OK) else None)


def trace(name="straight", transport="native"):
    words = workload(name)
    model = Model(words)
    lines, cycle = [], 0
    while True:
        event = model.step()
        address = event.pc & ~3
        data = words.get(address, 0)
        phases = 3 if transport == "native" else 5
        for phase in range(phases):
            lines.append(f"T {cycle} {int(phase == phases - 1)} 1 0 0 {event.pc}")
            valid, response = int(phase == 0), int(phase == (1 if transport == "native" else 3))
            lines.append(f"I {cycle} {valid} 1 {address} 0 0 0 2 1 0 {response} 1 {data} 0")
            ar, rv = int(transport == "axi" and phase == 1), int(transport == "axi" and phase == 2)
            lines.append(f"A {cycle} {ar} 1 {address} 5 {rv} 1 {data} 0")
            if phase == phases - 1:
                lines.append(f"R {cycle} {event.pc} {event.word} {event.next_pc} {event.rd} "
                             f"{int(bool(event.rd))} {event.value if event.rd else 0} 0 0 0 0")
            cycle += 1
        if event.pc == DONE:
            break
    lines.append(f"F {cycle}")
    return words, "\n".join(lines) + "\n"


class PerformanceTest(unittest.TestCase):
    def test_native_window_counts_only_observed_fetch_starvation(self):
        words, text = trace()
        result = check(words, text, "native")
        self.assertEqual(result["windowCycles"], 766)
        self.assertEqual(result["windowRetirements"], 256)
        self.assertEqual(result["fetchStarvationCycles"], 510)
        self.assertEqual(result["retirementRecoveryCycles"], {})
        # A retirement gap remains, but pause excludes these fetch observations.
        changed = "\n".join(" ".join(parts[:4] + ["1"] + parts[5:]) if
                            (parts := line.split())[0] == "T" else line for line in text.splitlines())
        observed = check(words, changed, "native")
        self.assertEqual(observed["windowCycles"], 766)
        self.assertEqual(observed["fetchStarvationCycles"], 0)

    def test_branch_recovery_is_retirement_to_retirement(self):
        words, text = trace("branch")
        result = check(words, text, "native")
        self.assertEqual(result["takenBranchesInWindow"], 128)
        self.assertEqual(result["retirementRecoveryCycles"], {"3": 128})

    def test_axi_checks_both_protocol_boundaries(self):
        words, text = trace("branch", "axi")
        result = check(words, text, "axi")
        self.assertEqual(result["retirementRecoveryCycles"], {"5": 128})
        self.assertEqual(result["retirementsThroughCompletion"], 642)

    def test_wrong_register_value_fails(self):
        words, text = trace()
        text = text.replace("R 2 0 1311763 4 8 1 1", "R 2 0 1311763 4 8 1 2")
        with self.assertRaisesRegex(AssertionError, "Retirement differs"):
            check(words, text, "native")

    def test_response_without_owner_fails(self):
        words, text = trace()
        text = text.replace("I 0 1 1 0 0 0 0 2 1 0 0 1", "I 0 1 1 0 0 0 0 2 1 0 1 1")
        with self.assertRaisesRegex(AssertionError, "earlier owner"):
            check(words, text, "native")

    def test_wrong_memory_data_fails(self):
        words, text = trace()
        lines = text.splitlines()
        for index, line in enumerate(lines):
            fields = line.split()
            if fields[:2] == ["I", "1"]:
                fields[-2] = str(int(fields[-2]) ^ 1)
                lines[index] = " ".join(fields)
        with self.assertRaisesRegex(AssertionError, "differs from memory"):
            check(words, "\n".join(lines), "native")

    def test_wrong_axi_attributes_fail(self):
        words, text = trace(transport="axi")
        text = text.replace("A 1 1 1 0 5", "A 1 1 1 0 1")
        with self.assertRaisesRegex(AssertionError, "attributes"):
            check(words, text, "axi")

    def test_missing_cycle_fails(self):
        words, text = trace()
        text = "\n".join(line for line in text.splitlines() if not line.startswith("T 1 "))
        with self.assertRaisesRegex(AssertionError, "unclocked"):
            check(words, text, "native")

    def test_payload_hold(self):
        held = stable(None, 1, 0, (4, 5), "changed")
        self.assertEqual(stable(held, 1, 1, (4, 5), "changed"), None)
        with self.assertRaisesRegex(AssertionError, "changed"):
            stable(held, 1, 0, (8, 5), "changed")

    def test_shared_port_declarations(self):
        result = ports("module Demo(input clock, reset, input [31:0] a, b, output valid);", "Demo")
        self.assertEqual(result["b"], ("input", "[31:0]"))
        self.assertEqual(result["valid"], ("output", ""))

    def test_frozen_input_change_is_rejected(self):
        with temporary() as directory:
            root = Path(directory)
            (root / "core.sv").write_text("module core; endmodule\n")
            manifest = {"parameters": {}, "exitStatus": 0, "sourceHashes": {},
                        "rtlHashes": {"core.sv": digest((root / "core.sv").read_bytes())}}
            (root / "manifest.json").write_text(json.dumps(manifest))
            design(root / "manifest.json", root, root)
            (root / "core.sv").write_text("module changed; endmodule\n")
            with self.assertRaisesRegex(AssertionError, "input changed"):
                design(root / "manifest.json", root, root)

    def test_incompatible_configuration_is_rejected(self):
        with temporary() as directory:
            root = Path(directory)
            (root / "manifest.json").write_text(json.dumps({"parameters": {"protectedMode": True}}))
            with self.assertRaisesRegex(AssertionError, "configuration"):
                design(root / "manifest.json", root, root)

    def test_machine_m_and_c_are_supported(self):
        with temporary() as directory:
            root = Path(directory)
            manifest = {"parameters": {"enableM": True, "enableC": True}, "exitStatus": 0,
                        "sourceHashes": {}, "rtlHashes": {}}
            (root / "manifest.json").write_text(json.dumps(manifest))
            _, parameters, _ = design(root / "manifest.json", root, root)
            words, text = trace()
            self.assertEqual(check(words, text, "native", parameters)["windowCycles"], 766)

    def test_platform_description_is_bound(self):
        with temporary() as directory:
            root = Path(directory)
            (root / "platform.json").write_text("{}\n")
            manifest = {"parameters": {"core": {}}, "exitStatus": 0, "sourceHashes": {}, "rtlHashes": {},
                        "platformHash": digest(b"different description\n")}
            (root / "manifest.json").write_text(json.dumps(manifest))
            with self.assertRaisesRegex(AssertionError, "Platform description changed"):
                design(root / "manifest.json", root, root)

    def test_runtime_negative_controls(self):
        for transport, expected in (("native", 2), ("axi", 3)):
            words, text = trace(transport=transport)
            self.assertEqual(len(negative_controls(words, text, transport)), expected)

    def test_wrapper_observes_the_fetch_interface(self):
        with temporary() as directory:
            root = Path(directory)
            (root / "DitDahE2.sv").write_text("module DitDahE2(input clock, reset, output retire_valid);\nDitDahE2Fetch fetch ();\nendmodule\n")
            text = wrapper(root, "native")
            self.assertIn("assign f_ready = dut.fetch.output_ready;", text)
            self.assertIn("assign f_valid = dut.fetch.output_valid;", text)
            self.assertIn("assign i_operation = '0;", text)


if __name__ == "__main__":
    unittest.main()
