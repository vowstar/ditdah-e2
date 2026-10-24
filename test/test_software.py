# SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
# SPDX-License-Identifier: MIT
"""Check that console observations require completed, valid bus stores."""

import unittest

from verify_software import check_console, console_stores


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


if __name__ == "__main__":
    unittest.main()
