# SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
# SPDX-License-Identifier: MIT
"""Exercise native child CPU allocation and its receipt without a formal tool."""

import copy
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from formal.debug_transport import run


@unittest.skipUnless(
    hasattr(os, "sched_getaffinity") and hasattr(os, "sched_setaffinity"),
    "CPU affinity APIs are required",
)
class CpuAllocationTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix="ditdah-e2-cpu-")
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.case = self.root / "cases/safety"
        self.case.mkdir(parents=True)
        self.private = self.root / "private"
        self.private.mkdir()
        self.available = sorted(os.sched_getaffinity(0))
        self.launcher = self.root / "affinity-child"
        self.plan = {
            "inputs": ["collect.tcl"],
            "top": "resource_test",
            "goals": [],
            "covers": [],
            "assumptions": [],
            "expected": "proven",
            "mutation": None,
            "negativeTarget": None,
        }
        run.write_json(self.case / "plan.json", self.plan)
        run.write_json(self.root / "manifest.json", {"rtlSha256": "0" * 64})
        (self.case / "collect.tcl").write_text("# Resource allocation fixture.\n")
        records = [("run", "state", "complete")]
        records += [("setup", key, "0") for key in ("bbox_inst", "bbox_mod", "bbox_out", "stopat")]
        records += [("setup", "clock_mode", "free_running")]
        records += [
            (tag, key, run.EXPECTED_RESET if key == "reset" else "")
            for tag in ("before", "after")
            for key in ("clock", "reset", "assumptions", "global", "reset_assumptions")
        ]
        self.launcher.write_text(
            "#!" + sys.executable + "\n"
            "import json, os, sys\n"
            "from pathlib import Path\n"
            "Path('child-resources.json').write_text(json.dumps({"
            "'cpus': sorted(os.sched_getaffinity(0)), "
            "'threads': os.environ.get('OMP_NUM_THREADS')}))\n"
            "Path('executable.private').write_text(sys.executable)\n"
            "records = " + repr(records) + "\n"
            "Path('native.tsv').write_text(''.join('\\t'.join(v.encode().hex() "
            "for v in row) + '\\n' for row in records))\n"
        )
        self.launcher.chmod(0o700)

    def collect(self, **kwargs):
        return run.collect_case(self.case, str(self.launcher), self.private, 10, **kwargs)

    def validate(self):
        with patch.object(run, "validate_frozen"), patch.object(run, "CASES", ("safety",)):
            return run.validate_commercial(self.root)

    def check_child(self, count, expected):
        self.assertEqual(self.collect(cpu_count=count), {"goals": 0, "covers": 0, "verdict": "proven"})
        observed = json.loads((self.case / "child-resources.json").read_text())
        receipt = json.loads((self.case / "receipt.json").read_text())
        self.assertEqual(observed, {"cpus": expected, "threads": str(count)})
        self.assertEqual(receipt["cpuAffinity"], observed["cpus"])
        self.assertEqual(receipt["cpuCount"], count)
        self.assertEqual(receipt["cpu"], expected[0])
        self.assertEqual(receipt["inputHashes"], {"collect.tcl": run.digest(self.case / "collect.tcl")})
        self.assertEqual(receipt["launcherSha256"], run.digest(self.launcher))
        self.assertEqual(self.validate()["commercialGate"], "passed")

    def test_default_remains_one_cpu_in_real_child(self):
        self.collect()
        observed = json.loads((self.case / "child-resources.json").read_text())
        receipt = json.loads((self.case / "receipt.json").read_text())
        self.assertEqual(observed, {"cpus": self.available[:1], "threads": "1"})
        self.assertEqual(receipt["cpu"], self.available[0])
        self.assertEqual(receipt["cpuCount"], 1)
        self.assertEqual(receipt["cpuAffinity"], self.available[:1])
        self.assertEqual(sorted(os.sched_getaffinity(0)), self.available)
        self.validate()

    def test_requested_sixteen_or_available_reaches_real_child(self):
        count = min(16, len(self.available))
        self.check_child(count, self.available[:count])
        self.assertEqual(sorted(os.sched_getaffinity(0)), self.available)

    def test_selection_uses_inherited_affinity(self):
        inherited = self.available[1::2] or self.available
        try:
            os.sched_setaffinity(0, inherited)
            count = min(2, len(inherited))
            self.check_child(count, inherited[:count])
            self.assertEqual(sorted(os.sched_getaffinity(0)), inherited)
        finally:
            os.sched_setaffinity(0, self.available)

    def test_invalid_counts_fail_before_launch(self):
        for count in (0, -1, True, False, 1.5, "16", None):
            with self.subTest(count=count), self.assertRaisesRegex(ValueError, "positive integer"):
                self.collect(cpu_count=count)
        self.assertFalse((self.case / "receipt.json").exists())
        self.assertFalse((self.case / "child-resources.json").exists())
        self.assertEqual(list(self.private.iterdir()), [])

    def test_insufficient_inherited_allocation_fails_before_launch(self):
        try:
            os.sched_setaffinity(0, self.available[:1])
            with self.assertRaisesRegex(ValueError, "requires 2 CPUs; inherited affinity provides 1"):
                self.collect(cpu_count=2)
        finally:
            os.sched_setaffinity(0, self.available)
        self.assertFalse((self.case / "receipt.json").exists())
        self.assertFalse((self.case / "child-resources.json").exists())
        self.assertEqual(list(self.private.iterdir()), [])

    def test_unavailable_affinity_and_child_setup_failure_are_clear(self):
        with patch.object(run.os, "sched_getaffinity"):
            del run.os.sched_getaffinity
            with self.assertRaisesRegex(ValueError, "unavailable on this platform"):
                self.collect()
        with (
            patch.object(run.os, "sched_getaffinity", side_effect=OSError("unavailable")),
            self.assertRaisesRegex(ValueError, "Inherited CPU affinity"),
        ):
            self.collect()
        with (
            patch.object(run.os, "sched_setaffinity", side_effect=OSError("denied")),
            self.assertRaisesRegex(ValueError, "native process failed to start"),
        ):
            self.collect()
        if len(self.available) > 1:
            with (
                patch.object(run.os, "sched_setaffinity", return_value=None),
                self.assertRaisesRegex(ValueError, "native process failed to start"),
            ):
                self.collect()
        self.assertFalse((self.case / "receipt.json").exists())
        self.assertFalse((self.case / "child-resources.json").exists())

    def test_complete_receipt_rejects_resource_and_existing_integrity_mutations(self):
        self.check_child(min(16, len(self.available)), self.available[:16])
        receipt_path = self.case / "receipt.json"
        receipt = json.loads(receipt_path.read_text())
        mutations = [
            {"cpuCount": 0}, {"cpuCount": True}, {"cpuCount": "1"},
            {"cpuAffinity": []}, {"cpuAffinity": [-1]}, {"cpuAffinity": [True]},
            {"cpuAffinity": [self.available[0], self.available[0]]},
            {"cpu": receipt["cpu"] + 1}, {"cpu": True}, {"cpu": False},
            {"cpu": str(receipt["cpu"])}, {"inputHashes": {}},
            {"launcherSha256": "invalid"},
        ]
        if len(receipt["cpuAffinity"]) > 1:
            mutations.append({"cpuAffinity": list(reversed(receipt["cpuAffinity"]))})
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                run.write_json(receipt_path, {**receipt, **mutation})
                with self.assertRaises(ValueError):
                    self.validate()
        for key in ("cpuCount", "cpuAffinity"):
            altered = copy.deepcopy(receipt)
            del altered[key]
            run.write_json(receipt_path, altered)
            with self.subTest(missing=key), self.assertRaises(ValueError):
                self.validate()
        run.write_json(receipt_path, receipt)
        completion_path = self.case / "completion.json"
        completion = json.loads(completion_path.read_text())
        run.write_json(completion_path, {**completion, "outputHashes": {}})
        with self.assertRaisesRegex(ValueError, "results changed"):
            self.validate()
        run.write_json(completion_path, completion)
        self.validate()

    def test_legacy_single_cpu_receipts_remain_valid(self):
        self.collect()
        path = self.case / "receipt.json"
        receipt = json.loads(path.read_text())
        del receipt["cpuCount"]
        del receipt["cpuAffinity"]
        run.write_json(path, receipt)
        self.assertEqual(self.validate()["commercialGate"], "passed")


if __name__ == "__main__":
    unittest.main()
