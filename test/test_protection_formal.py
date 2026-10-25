# SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
# SPDX-License-Identifier: MIT

import unittest

from protection_formal import mutate


class ProtectionFormalTests(unittest.TestCase):
    def test_mutation_targets_are_unique(self):
        targets = {
            "permission": "wire permitted = held ? heldPermission : allowed;",
            "denial-fault": "assign input_response_bits_fault = denied | output_response_bits_fault;",
            "denial-leak": "assign output_request_valid = available & input_request_valid & permitted;"}
        for name, source in targets.items():
            with self.subTest(name=name):
                self.assertNotEqual(mutate(source, name), source)
                for invalid in (source + source, "assign unused = 0;"):
                    with self.assertRaises(AssertionError):
                        mutate(invalid, name)


if __name__ == "__main__":
    unittest.main()
