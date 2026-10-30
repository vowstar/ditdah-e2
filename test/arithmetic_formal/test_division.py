# SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
# SPDX-License-Identifier: MIT
"""Check division source contracts, metadata rejection, and standard arithmetic rules."""

import copy
import json
from pathlib import Path
import tempfile
import unittest

from arithmetic_formal import division_contracts, division_rules, facts, source


def metadata_fixture(operation):
    ports = []
    for name, (direction, width) in division_contracts.RTL_PORTS.items():
        shape = "[%d:0] " % (width - 1) if width > 1 else ""
        ports.append(direction + " " + shape + name)
    # This fixture checks the interface reader. It supplies no hardware proof.
    interface = "module DitDahE2MultiplyDivide(" + ",".join(ports) + "); endmodule\n"
    contract = division_contracts.bind_division(source.bench(operation), interface, operation)
    metadata = {
        "operation": operation,
        "provenLabels": list(division_contracts.required_native_labels(operation)),
        "assumptions": list(facts.ASSUMPTIONS),
        "fullWidth": True,
        "originalGuard": True,
        "collectedSourceSha256": contract["sourceSha256"],
        "collectedDutSha256": contract["dutSha256"],
        "booleanInductionRule": {"accepted": True},
        "covers": {
            label: {
                "replayed": True,
                "samples": 1,
                "hits": [0],
                "sha256": source.digest(label.encode()),
            }
            for label in facts.covers(operation)
        },
    }
    return interface, contract, metadata


class DivisionContractTests(unittest.TestCase):
    def test_four_source_contracts(self):
        for operation in range(4, 8):
            _, contract, metadata = metadata_fixture(operation)
            self.assertEqual(len(contract["requiredNativeLabels"]), 70)
            self.assertEqual(len(contract["definitions"]["drivers"]), 69)
            self.assertEqual(division_rules._check_evidence(contract, metadata), operation)

    def test_invalid_metadata_and_contracts_are_rejected(self):
        for operation in range(4, 8):
            _, original, baseline = metadata_fixture(operation)
            cover = facts.covers(operation)[0]
            changes = [
                ("metadata", ["provenLabels"], baseline["provenLabels"][:-1]),
                ("metadata", ["provenLabels"], baseline["provenLabels"] + ["extra"]),
                (
                    "metadata",
                    ["provenLabels"],
                    baseline["provenLabels"] + baseline["provenLabels"][:1],
                ),
                ("metadata", ["operation"], (operation + 1) % 8),
                ("metadata", ["fullWidth"], False),
                ("metadata", ["originalGuard"], False),
                ("metadata", ["assumptions"], list(facts.ASSUMPTIONS[:-1])),
                ("metadata", ["assumptions"], list(facts.ASSUMPTIONS) + ["extra"]),
                ("metadata", ["assumptions"], [facts.ASSUMPTIONS[0]] * 5),
                ("metadata", ["collectedSourceSha256"], "0" * 64),
                ("metadata", ["collectedDutSha256"], "1" * 64),
                ("metadata", ["covers"], {}),
                ("metadata", ["covers", "extra"], baseline["covers"][cover]),
                ("metadata", ["covers", cover, "replayed"], False),
                ("metadata", ["covers", cover, "samples"], 0),
                ("metadata", ["covers", cover, "hits"], []),
                ("metadata", ["covers", cover, "hits"], [1]),
                ("metadata", ["covers", cover, "sha256"], "wrong"),
                ("metadata", ["booleanInductionRule", "accepted"], False),
                ("metadata", ["booleanInductionRule"], {}),
                ("contract", ["guard"], ""),
                ("contract", ["guard"], original["guard"] + " && pending"),
                ("contract", ["operandBitsEach"], 16),
                ("contract", ["actualOperationBits"], 2),
                ("contract", ["referenceFunctionSha256"], "0" * 64),
                ("contract", ["requiredNativeLabels"], original["requiredNativeLabels"][:-1]),
                ("contract", ["sourceSha256"], "0" * 64),
                ("contract", ["dutSha256"], "wrong"),
                ("contract", ["contracts", "owner_sign", "body"], ["1"]),
                ("contract", ["contracts", "owner_sign", "kind"], "assume"),
                ("contract", ["definitions", "declarations"], []),
                ("contract", ["definitions", "instances"], []),
                ("contract", ["definitions", "drivers"], []),
                ("contract", ["assumptions"], []),
                ("contract", ["ports", "request_bits_left"], ["input", 16]),
                ("contract", ["transitionSha256"], "0" * 64),
                ("contract", ["contracts", "owner_sign", "guards"], []),
                ("metadata", ["covers", cover, "samples"], True),
                ("metadata", ["covers", cover, "hits"], [False]),
                ("metadata", ["booleanInductionRule", "accepted"], 1),
            ]
            self.assertEqual(len(changes), 40)
            for kind, keys, value in changes:
                with self.subTest(operation=operation, kind=kind, field=keys):
                    contract, metadata = copy.deepcopy(original), copy.deepcopy(baseline)
                    target = metadata if kind == "metadata" else contract
                    for key in keys[:-1]:
                        target = target[key]
                    target[keys[-1]] = value
                    with self.assertRaises(ValueError):
                        division_rules._check_evidence(contract, metadata)

    def test_real_port_driver_and_function_changes_are_rejected(self):
        interface, _, _ = metadata_fixture(4)
        text = source.bench(4)
        for changed in (
            text.replace(
                "input logic [31:0] request_bits_left", "input logic [15:0] request_bits_left"
            ),
            text.replace(
                "    wire request_ready, response_valid;",
                "    assign request_bits_operation[2] = 1'b0;\n    wire request_ready, response_valid;",
            ),
            text.replace(
                "    wire request_ready, response_valid;",
                "// function ignored\nassign request_bits_left[0] = 1'b0;\n// endfunction\n    wire request_ready, response_valid;",
            ),
            text.replace("unsigned_product[31:0]", "unsigned_product[63:32]"),
        ):
            self.assertNotEqual(changed, text)
            with self.assertRaises(ValueError):
                division_contracts.bind_division(changed, interface, 4)

    def test_standard_signed_operators_and_normalization(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            division_rules._prove_builtin_definitions(root / "operators")
            division_rules._prove_normalization(root / "normalization")
            division_rules._prove_projection(root / "projection")
            rows = [
                row for path in root.rglob("queries.json") for row in json.loads(path.read_text())
            ]
            self.assertTrue(rows)
            self.assertTrue(all(row["actual"] == row["expected"] for row in rows))
            self.assertTrue(
                any(row["actual"] == "sat" and row["name"].startswith("negative_") for row in rows)
            )


if __name__ == "__main__":
    unittest.main()
