# SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
# SPDX-License-Identifier: MIT
"""Check that console observations require completed, valid bus stores."""

import hashlib
import os
from pathlib import Path
import tempfile
import unittest

from verify_software import check_console, check_extensions, console_stores, preserve_inputs
from build_software import instruction_inventory


def trace(data=b"E2\n", fault=0, address=0x10000000, size=2, mask=15):
    return "\n".join(f"Q {index * 2} D {address} 1 {value} {mask} {size}\nS {index * 2 + 1} D 0 {fault}"
                     for index, value in enumerate(data))


class SoftwareChecks(unittest.TestCase):
    def test_completed_stores(self):
        self.assertEqual(console_stores(trace()), b"E2\n")
        check_console(trace(), b"E2\n")

    def test_missing_response(self):
        with self.assertRaisesRegex(AssertionError, "Unfinished"):
            console_stores(trace().rsplit("\n", 1)[0])

    def test_failed_store(self):
        with self.assertRaisesRegex(AssertionError, "Failed"):
            console_stores(trace(fault=1))

    def test_invalid_device_access(self):
        for arguments in ({"address": 0x10000004}, {"size": 0, "mask": 1}):
            with self.subTest(arguments=arguments), self.assertRaisesRegex(AssertionError, "Invalid"):
                console_stores(trace(**arguments))

    def test_changed_output(self):
        for output in (b"E\n", b"E3\n", b"E2\n\n"):
            with self.subTest(output=output), self.assertRaisesRegex(AssertionError, "differs"):
                check_console(trace(), output)

    def test_unexpected_target_output(self):
        with self.assertRaisesRegex(AssertionError, "Unexpected"):
            check_console(trace(b"E3\n"), b"E3\n")

    def test_extension_execution_is_required(self):
        check_extensions({"mul": 1, "c.addi": 2}, True, True)
        check_extensions({"addi": 3}, False, False)
        with self.assertRaisesRegex(AssertionError, "retire MUL"):
            check_extensions({"mul": 0, "c.addi": 2}, True, True)
        with self.assertRaisesRegex(AssertionError, "retire a compressed"):
            check_extensions({"mul": 1, "c.addi": 0}, True, True)

    def test_instruction_inventory_rejects_unavailable_encodings(self):
        ordinary = " 0: 00108093 addi ra,ra,1\n"
        compressed = " 4: 0085 c.addi ra,1\n"
        multiply = " 6: 02b50533 mul a0,a0,a1\n"
        self.assertEqual([item["length"] for item in instruction_inventory(ordinary + compressed + multiply, True, True)],
                         [4, 2, 4])
        for listing, enabled_m, enabled_c in ((compressed, False, False), (multiply, False, True),
                                               (ordinary, True, False), (ordinary, False, True),
                                               ("0: 003f .2byte 0x003f", False, True),
                                               (ordinary + ordinary, False, False)):
            with self.subTest(listing=listing), self.assertRaises(ValueError):
                instruction_inventory(listing, enabled_m, enabled_c)

    def test_changed_source_is_not_preserved_as_verified(self):
        scratch = "/data/tmp" if os.access("/data/tmp", os.W_OK) else None
        with tempfile.TemporaryDirectory(prefix="ditdah-e2-software-inputs-", dir=scratch) as directory:
            root = Path(directory)
            (root / "source").mkdir()
            source = root / "source/input.txt"
            source.write_bytes(b"original\n")
            hashes = {"input.txt": hashlib.sha256(source.read_bytes()).hexdigest()}
            preserve_inputs(root / "copy", root / "source", hashes)
            self.assertEqual((root / "copy/input.txt").read_bytes(), b"original\n")
            source.write_bytes(b"changed\n")
            with self.assertRaisesRegex(AssertionError, "Input changed"):
                preserve_inputs(root / "changed-copy", root / "source", hashes)
            self.assertFalse((root / "changed-copy/input.txt").exists())


if __name__ == "__main__":
    unittest.main()
