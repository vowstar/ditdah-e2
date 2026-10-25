# SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
# SPDX-License-Identifier: MIT

import unittest

from protection_port import Reference, check, permission_mutant, response, vectors


A = (0x1000, 0, 0, 0, 2, 1)
B = (0x100C, 1, 0x12345678, 15, 2, 0)


def row(allowed=0, valid=0, ready=0, downstream_ready=0, peer=None, request=A, reset=0):
    data, fault = response(peer) if peer is not None else (0, 0)
    return (reset, allowed, valid, ready, downstream_ready, int(peer is not None), data, fault, *request)


def trace(rows):
    model = Reference()
    return "".join(" ".join(f"{value:x}" if index in (3, 6, 8, 9) else str(value)
                            for index, value in enumerate(model.step(item, cycle))) + "\n"
                   for cycle, item in enumerate(rows))


class ProtectionPortTests(unittest.TestCase):
    def test_blocked_permission_is_retained(self):
        model = Reference()
        first = model.step(row(allowed=1, valid=1), 0)
        self.assertEqual((first[1], first[5], first[6:12]), (0, 1, A))
        second = model.step(row(allowed=0, valid=1), 1)
        self.assertEqual(second[1:], first[1:])
        accepted = model.step(row(allowed=0, valid=1, downstream_ready=1), 2)
        self.assertEqual((accepted[1], accepted[5]), (1, 1))
        blocked = model.step(row(peer=A), 3)
        self.assertEqual(blocked[2:5], (1, 0x5A71DB03, 0))
        self.assertEqual(blocked[12], 0)
        finished = model.step(row(peer=A, ready=1), 4)
        self.assertEqual(finished[2:5], blocked[2:5])
        self.assertEqual(finished[12], 1)
        model.finish()

    def test_denied_offer_while_busy_keeps_its_first_decision(self):
        model = Reference()
        model.step(row(allowed=1, valid=1, downstream_ready=1), 0)
        held = model.step(row(allowed=0, valid=1, downstream_ready=1, request=B), 1)
        self.assertEqual((held[1], held[5]), (0, 0))
        model.step(row(allowed=1, valid=1, downstream_ready=1, peer=A, request=B), 2)
        replacement = model.step(row(allowed=1, valid=1, ready=1, downstream_ready=1, peer=A, request=B), 3)
        self.assertEqual((replacement[1], replacement[2], replacement[5]), (1, 1, 0))
        blocked = model.step(row(), 4)
        self.assertEqual(blocked[2:5], (1, 0, 1))
        self.assertEqual(blocked[12], 0)
        model.step(row(ready=1), 5)
        model.finish()
        self.assertEqual(model.counts["externalRequests"], 1)
        self.assertEqual(model.counts["deniedRequests"], 1)
        self.assertEqual(model.counts["replacements"], 1)

    def test_allowed_offer_while_busy_and_fault_response(self):
        model = Reference()
        model.step(row(allowed=0, valid=1), 0)
        model.step(row(allowed=1, valid=1, request=B), 1)
        accepted = model.step(row(allowed=0, valid=1, ready=1, downstream_ready=1, request=B), 2)
        self.assertEqual((accepted[1], accepted[2:5], accepted[5], accepted[6:12]), (1, (1, 0, 1), 1, B))
        returned = model.step(row(peer=B, ready=1), 3)
        self.assertEqual(returned[2:5], (1, *response(B)))
        self.assertEqual(returned[4], 1)
        model.finish()

    def test_local_denial_does_not_wait_for_downstream_ready(self):
        model = Reference()
        accepted = model.step(row(allowed=0, valid=1), 0)
        self.assertEqual((accepted[1], accepted[5]), (1, 0))
        response_value = model.step(row(allowed=1, ready=1), 1)
        self.assertEqual(response_value[2:5], (1, 0, 1))
        model.finish()
        self.assertEqual(model.counts["externalRequests"], 0)

    def test_invalid_input_and_incomplete_owner_are_rejected(self):
        for changed in (row(allowed=1, valid=0), row(allowed=1, valid=1, request=B)):
            model = Reference()
            model.step(row(allowed=1, valid=1), 0)
            with self.assertRaisesRegex(AssertionError, "offer changed"):
                model.step(changed, 1)
        with self.assertRaisesRegex(AssertionError, "no accepted request"):
            Reference().step(row(peer=A), 0)
        model = Reference()
        model.step(row(allowed=0, valid=1), 0)
        with self.assertRaisesRegex(AssertionError, "did not drain"):
            model.finish()
        with self.assertRaisesRegex(AssertionError, "Reset with"):
            model.step(row(reset=1), 1)

    def test_checker_rejects_withdrawal_and_wrong_response(self):
        rows = [row(allowed=1, valid=1), row(allowed=0, valid=1),
                row(allowed=0, valid=1, downstream_ready=1), row(peer=A, ready=1)]
        original = trace(rows)
        self.assertEqual(check(rows, original)["requests"], 1)
        lines = original.splitlines()
        fields = lines[1].split()
        fields[5] = "0"
        lines[1] = " ".join(fields)
        with self.assertRaisesRegex(AssertionError, "Downstream offer changed"):
            check(rows, "\n".join(lines))
        lines = original.splitlines()
        fields = lines[3].split()
        fields[4] = "1"
        lines[3] = " ".join(fields)
        with self.assertRaisesRegex(AssertionError, "ownership or permission"):
            check(rows, "\n".join(lines))

    def test_random_transactions_cover_retained_decisions(self):
        rows = vectors(19, count=32)
        counts = check(rows, trace(rows))
        self.assertEqual(counts["requests"], 32)
        self.assertEqual(counts["responses"], 32)
        for name in ("grantRetained", "denialRetained", "capturedWhileActive", "replacements", "busFaults"):
            self.assertGreater(counts[name], 0)

    def test_permission_mutation_has_one_target(self):
        source = "wire permitted = held ? heldPermission : allowed;"
        self.assertEqual(permission_mutant(source), "wire permitted = allowed;")
        for changed in (source + source, "wire permitted = allowed;", "wire other = heldPermission;"):
            with self.assertRaisesRegex(AssertionError, "mutation"):
                permission_mutant(changed)


if __name__ == "__main__":
    unittest.main()
