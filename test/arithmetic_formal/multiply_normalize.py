# SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
# SPDX-License-Identifier: MIT
"""Check owner and selected-parameter sign expressions with pure functions."""

import json
import time
import z3


def prove(output):
    output.mkdir(parents=True, exist_ok=False)
    left, right = z3.BitVecs("owner_left owner_right", 32)
    owner = z3.BitVec("owner_op", 3)
    U = z3.Function("magnitude_product", z3.BitVecSort(32), z3.BitVecSort(32), z3.BitVecSort(64))

    def terms(op):
        negative_left = z3.And(
            z3.Or(*[op == n for n in (1, 2, 4, 6)]), z3.Extract(31, 31, left) == 1
        )
        negative_right = z3.And(
            z3.Or(*[op == n for n in (1, 4, 6)]), z3.Extract(31, 31, right) == 1
        )
        magnitude_left = z3.If(negative_left, -left, left)
        magnitude_right = z3.If(negative_right, -right, right)
        product = U(magnitude_left, magnitude_right)
        corrected = z3.If(z3.Xor(negative_left, negative_right), -product, product)
        return {
            "left_sign": negative_left,
            "right_sign": negative_right,
            "left_magnitude": magnitude_left,
            "right_magnitude": magnitude_right,
            "corrected_product": corrected,
            "high_projection": z3.Extract(63, 32, corrected),
        }

    actual = terms(owner)
    rows = []

    def query(name, constraints, expected, role):
        solver = z3.SolverFor("QF_UFBV")
        solver.set(timeout=10000)
        solver.add(*constraints)
        (output / (name + ".smt2")).write_text(solver.to_smt2())
        start = time.monotonic()
        status = solver.check()
        row = {
            "name": name,
            "expected": expected,
            "actual": str(status),
            "role": role,
            "seconds": round(time.monotonic() - start, 6),
        }
        if status == z3.sat:
            model = solver.model()
            (output / (name + ".model.txt")).write_text(str(model) + "\n")
        rows.append(row)
        (output / "queries.json").write_text(json.dumps(rows, indent=2) + "\n")
        if not str(status) == expected:
            raise ValueError(row)

    for operation in (1, 2, 3):
        selected = terms(z3.BitVecVal(operation, 3))
        for field in selected:
            query(
                "op" + str(operation) + "_" + field,
                [owner == operation, actual[field] != selected[field]],
                "unsat",
                "The selected owner uses the exact magnitude and sign expression of the parameter theorem",
            )
        query(
            "op" + str(operation) + "_high_bits_nonvacuity",
            [owner == operation, z3.Extract(31, 31, left) == 1, z3.Extract(31, 31, right) == 1],
            "sat",
            "Both raw operand high bits remain feasible",
        )
        query(
            "negative_op" + str(operation) + "_missing_owner_selection",
            [owner != operation, actual["high_projection"] != selected["high_projection"]],
            "sat",
            "The parameter and owner expression cannot be exchanged without selecting the same operation",
        )
    summary = {
        "positiveUnsat": 18,
        "highBitNonvacuitySat": 3,
        "effectiveSelectionCountermodels": 3,
        "operandBitsEach": 32,
        "ownerOperationBits": 3,
        "functionSignature": "U(BV32,BV32) returns BV64",
        "multiplicationAxiomsAdded": 0,
        "nativePremisesBound": False,
        "originalArithmeticCompositionalProven": False,
    }
    (output / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    return summary
