# SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
# SPDX-License-Identifier: MIT
"""Keep the raw-identity semantic control uniquely bound to generated RTL."""

import unittest

from test.test_ditdah_e2.verify import without_raw_identity


class RawIdentityTests(unittest.TestCase):
    def test_only_compressed_identity_changes(self):
        original = "wire [31:0] rawInstruction = x_length == 3'h2 ? {16'h0, x_word[15:0]} : xDecoded;"
        self.assertEqual(without_raw_identity(original),
                         "wire [31:0] rawInstruction = x_length == 3'h2 ? xDecoded : xDecoded;")
        for text in ("", original + original):
            with self.assertRaisesRegex(AssertionError, "Cannot identify"):
                without_raw_identity(text)


if __name__ == "__main__":
    unittest.main()
