# SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
# SPDX-License-Identifier: MIT
"""Check all sign cases with full-width modular integer arithmetic."""

import json
import time
import z3

WORD = 2**32
DOUBLE = 2**64


def prove(output):
    output.mkdir(parents=True, exist_ok=False)
    A, B = z3.Ints("A B")
    rows = []

    def query(name, facts, conclusion, expected="unsat", predecessors=()):
        solver = z3.Solver()
        solver.set(timeout=5000)
        solver.add(*facts, z3.Not(conclusion))
        (output / (name + ".smt2")).write_text(solver.to_smt2())
        start = time.monotonic()
        result = solver.check()
        row = {
            "name": name,
            "expected": expected,
            "actual": str(result),
            "seconds": round(time.monotonic() - start, 6),
            "provedPredecessors": list(predecessors),
        }
        if result == z3.sat:
            model = solver.model()
            row["model"] = {str(v): model.eval(v, model_completion=True).as_long() for v in (A, B)}
            (output / (name + ".model.json")).write_text(json.dumps(row["model"], indent=2) + "\n")
        else:
            row["reasonUnknown"] = solver.reason_unknown()
        rows.append(row)
        (output / "queries.json").write_text(json.dumps(rows, indent=2) + "\n")
        if not str(result) == expected:
            raise ValueError(row)

    domains = [A >= 0, A < WORD, B >= 0, B < WORD]
    for op in range(4):
        for high_left in range(2):
            for high_right in range(2):
                tag = f"op{op}_msb{high_left}{high_right}"
                facts = domains + [
                    A >= WORD // 2 if high_left else A < WORD // 2,
                    B >= WORD // 2 if high_right else B < WORD // 2,
                ]
                negative_left = op in (1, 2) and bool(high_left)
                negative_right = op == 1 and bool(high_right)
                magnitude_left = WORD - A if negative_left else A
                magnitude_right = WORD - B if negative_right else B
                standard_left = A + DOUBLE - WORD if negative_left else A
                standard_right = B + DOUBLE - WORD if negative_right else B
                magnitude_product = magnitude_left * magnitude_right
                corrected = (
                    -magnitude_product if negative_left != negative_right else magnitude_product
                ) % DOUBLE
                standard = standard_left * standard_right % DOUBLE
                query(
                    tag + "_magnitudes",
                    facts,
                    z3.And(
                        magnitude_left >= 0,
                        magnitude_left < WORD,
                        magnitude_right >= 0,
                        magnitude_right < WORD,
                    ),
                )
                query(
                    tag + "_restoration",
                    facts,
                    z3.And(
                        (-magnitude_left if negative_left else magnitude_left) % DOUBLE
                        == standard_left,
                        (-magnitude_right if negative_right else magnitude_right) % DOUBLE
                        == standard_right,
                    ),
                )
                query(tag + "_full_product", facts, corrected == standard)
                corrected_projection = corrected % WORD if op == 0 else corrected / WORD
                standard_projection = standard % WORD if op == 0 else standard / WORD
                query(
                    tag + "_projection",
                    facts + [corrected == standard],
                    corrected_projection == standard_projection,
                    predecessors=(tag + "_full_product",),
                )
                query(tag + "_nonvacuity", facts, z3.BoolVal(False), expected="sat")
    mag_left = WORD - A
    mag_right = WORD - B
    good_both_negative = mag_left * mag_right % DOUBLE
    bad_or_sign = -mag_left * mag_right % DOUBLE
    query(
        "negative_or_sign",
        domains + [A == WORD - 1, B == WORD // 2],
        bad_or_sign / WORD == good_both_negative / WORD,
        expected="sat",
    )
    correct_mixed = -(WORD - A) * B % DOUBLE
    bad_mixed_right = (WORD - A) * (WORD - B) % DOUBLE
    query(
        "negative_mixed_right_sign",
        domains + [A == WORD - 1, B == WORD // 2],
        bad_mixed_right / WORD == correct_mixed / WORD,
        expected="sat",
    )
    unsigned = A * B % DOUBLE
    query(
        "negative_high_low_projection",
        domains + [A == WORD - 1, B == WORD - 1],
        unsigned % WORD == unsigned / WORD,
        expected="sat",
    )
    X = z3.Int("full_product")
    query("modular_negation_after_truncation", [], (-(X % DOUBLE)) % DOUBLE == (-X) % DOUBLE)
    query(
        "mixed_product_low64_after_65bit_truncation",
        [],
        (X % (2**65)) % DOUBLE == X % DOUBLE,
    )
    summary = {
        "solver": "Z3",
        "solverVersion": z3.get_version_string(),
        "positiveUnsat": 66,
        "nonvacuitySat": 16,
        "negativeCountermodels": 3,
        "sourceBound": True,
        "full32BitOperands": True,
        "allFourOperationParameters": True,
        "allHighBitCombinations": True,
        "nativeCommercialProof": False,
        "actualUnitPremisesDischarged": False,
        "actualMOperationsAccepted": 0,
        "fullMArithmeticAccepted": False,
    }
    (output / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    return summary
