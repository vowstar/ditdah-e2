# SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
# SPDX-License-Identifier: MIT
"""Prove the complete multiplication response predicate by sampled induction."""

import json
import time
import z3


class State:

    def __init__(self, name):
        for field in ("reset", "cancel", "pending", "active", "response_valid", "negative"):
            setattr(self, field, z3.Bool(name + "." + field))
        for field, width in [
            ("left", 32),
            ("right", 32),
            ("operation", 3),
            ("iteration", 6),
            ("product", 64),
            ("response", 32),
            ("expected", 32),
        ]:
            setattr(self, field, z3.BitVec(name + "." + field, width))


class Certificate:

    def __init__(
        self,
        operation,
        *,
        base=True,
        epoch=True,
        terminal=True,
        wrong_finish=False,
        wrong_hold=False
    ):
        if not operation in range(4):
            raise ValueError("Arithmetic proof obligation failed")
        self.operation = operation
        c, p = self.current, self.past = (State("current"), State("past"))
        self.first, self.history, self.previous_reset = z3.Bools(
            "first_proof_frame history_valid previous_reset"
        )
        self.finish, self.hold, self.previous_owner = z3.Bools(
            "chain_previous_mul_finish chain_previous_mul_hold chain_previous_owner"
        )
        self.snapshot_product = z3.BitVec("chain_previous_product", 64)
        self.snapshot_negative = z3.Bool("chain_previous_negative")
        self.snapshot_left, self.snapshot_right = z3.BitVecs(
            "chain_previous_owner_left chain_previous_owner_right", 32
        )
        self.U = z3.Function(
            "unsigned_product_reference", z3.BitVecSort(32), z3.BitVecSort(32), z3.BitVecSort(64)
        )

        def signs(state, op):
            left_signed = z3.Or(*[op == n for n in (1, 2, 4, 6)])
            right_signed = z3.Or(*[op == n for n in (1, 4, 6)])
            return (
                z3.And(left_signed, z3.Extract(31, 31, state.left) == 1),
                z3.And(right_signed, z3.Extract(31, 31, state.right) == 1),
            )

        def magnitudes(state, op):
            left_negative, right_negative = signs(state, op)
            return (
                z3.If(left_negative, -state.left, state.left),
                z3.If(right_negative, -state.right, state.right),
            )

        self.signs, self.magnitudes = (signs, magnitudes)

        def reference(state):
            op = z3.BitVecVal(operation, 3)
            magnitude_left, magnitude_right = magnitudes(state, op)
            product = self.U(magnitude_left, magnitude_right)
            left_negative, right_negative = signs(state, op)
            corrected = z3.If(z3.Xor(left_negative, right_negative), -product, product)
            return z3.Extract(31, 0, product) if operation == 0 else z3.Extract(63, 32, corrected)

        self.ref = reference
        self.guard = lambda state: z3.And(
            z3.Not(state.reset),
            z3.Not(state.cancel),
            state.response_valid,
            state.operation == operation,
        )
        self.G, self.pG = (self.guard(c), self.guard(p))
        self.I = z3.Implies(self.G, c.response == c.expected)
        self.pI = z3.Implies(self.pG, p.response == p.expected)
        self.p_terminal = z3.And(
            z3.Not(p.reset),
            z3.Not(p.cancel),
            p.pending,
            p.active,
            p.operation == operation,
            p.iteration == 32,
        )
        self.common = z3.And(
            self.history, z3.Not(c.reset), z3.Not(c.cancel), c.pending, c.operation == operation
        )
        self.facts = {}
        if base:
            self.facts["native_initial_idle"] = z3.Implies(
                z3.And(z3.Not(c.reset), self.first), z3.Not(c.pending)
            )
        if epoch:
            self.facts["native_response_epoch"] = z3.Implies(
                self.G, z3.And(self.history, c.pending, z3.Or(self.finish, self.hold))
            )
        self.facts["source_previous_reset_capture"] = z3.Implies(
            z3.And(self.history, z3.Not(self.first)), self.previous_reset == p.reset
        )
        self.facts["native_finish_actual_past_terminal_guard"] = z3.Implies(
            z3.And(self.G, self.finish), z3.And(self.previous_owner, self.p_terminal)
        )
        snapshot_guard = z3.And(self.history, z3.Not(c.reset), z3.Not(self.previous_reset))
        self.facts["native_snapshot_product"] = z3.Implies(
            snapshot_guard, self.snapshot_product == p.product
        )
        self.facts["native_snapshot_left"] = z3.Implies(
            snapshot_guard, self.snapshot_left == p.left
        )
        self.facts["native_snapshot_right"] = z3.Implies(
            snapshot_guard, self.snapshot_right == p.right
        )
        self.facts["native_snapshot_negative"] = z3.Implies(
            snapshot_guard, self.snapshot_negative == p.negative
        )
        self.facts["native_actual_past_owner_sign"] = z3.Implies(
            z3.And(z3.Not(p.reset), z3.Not(p.cancel), p.pending),
            p.negative == z3.Xor(*signs(p, p.operation)),
        )
        owner_guard = z3.And(self.common, self.previous_owner)
        self.facts["native_owner_left_stable"] = z3.Implies(
            owner_guard, c.left == self.snapshot_left
        )
        self.facts["native_owner_right_stable"] = z3.Implies(
            owner_guard, c.right == self.snapshot_right
        )
        if terminal:
            self.facts["native_actual_past_terminal"] = z3.Implies(
                self.p_terminal, p.product == self.U(*magnitudes(p, p.operation))
            )
        projected = (
            z3.Extract(31, 0, self.snapshot_product)
            if operation == 0
            else z3.Extract(
                63, 32, z3.If(self.snapshot_negative, -self.snapshot_product, self.snapshot_product)
            )
        )
        self.facts["native_finish_projection"] = z3.Implies(
            z3.And(self.common, self.finish),
            c.response == projected ^ z3.BitVecVal(int(wrong_finish), 32),
        )
        self.facts["proved_checker_capture"] = z3.Implies(
            z3.And(z3.Not(c.reset), c.pending), c.expected == self.ref(c)
        )
        hold_guard = z3.And(self.G, self.hold)
        self.facts["native_hold_actual_past_goal_guard"] = z3.Implies(hold_guard, self.pG)
        self.facts["native_hold_response_word"] = z3.Implies(hold_guard, c.response == p.response)
        self.facts["native_hold_expected_word"] = z3.Implies(
            hold_guard, c.expected == p.expected ^ z3.BitVecVal(int(wrong_hold), 32)
        )


def prove(output, operation):
    output.mkdir(parents=True, exist_ok=False)
    rows = []

    def query(name, certificate, extras, expected, role):
        solver = z3.SolverFor("QF_UFBV")
        solver.set(timeout=15000)
        solver.add(*certificate.facts.values(), *extras)
        (output / (name + ".smt2")).write_text(solver.to_smt2())
        start = time.monotonic()
        verdict = solver.check()
        row = {
            "name": name,
            "expected": expected,
            "actual": str(verdict),
            "role": role,
            "seconds": round(time.monotonic() - start, 6),
            "premises": list(certificate.facts),
        }
        if verdict == z3.sat:
            model = solver.model()
            (output / (name + ".model.txt")).write_text(str(model) + "\n")
            words = [
                *vars(certificate.current).values(),
                *vars(certificate.past).values(),
                certificate.first,
                certificate.history,
                certificate.finish,
                certificate.hold,
                certificate.previous_owner,
                certificate.previous_reset,
            ]
            values = {str(word): str(model.eval(word, model_completion=True)) for word in words}
            values.update(
                {
                    "currentPredicate": str(model.eval(certificate.I, model_completion=True)),
                    "pastPredicate": str(model.eval(certificate.pI, model_completion=True)),
                }
            )
            (output / (name + ".values.json")).write_text(json.dumps(values, indent=2) + "\n")
        rows.append(row)
        (output / "queries.json").write_text(json.dumps(rows, indent=2) + "\n")
        if not str(verdict) == expected:
            raise ValueError(row)

    c = Certificate(operation)
    step = z3.Not(c.first)
    query(
        "base_first_frame",
        c,
        [c.first, z3.Not(c.I)],
        "unsat",
        "Native initial idle and response predecessor exclude a response in the first frame",
    )
    query(
        "reset_guard",
        c,
        [c.current.reset, z3.Not(c.I)],
        "unsat",
        "Original result predicate is inactive during reset",
    )
    query(
        "finish_has_actual_past_terminal",
        c,
        [step, c.G, c.finish, z3.Not(c.p_terminal)],
        "unsat",
        "A fresh response has the actual preceding terminal owner",
    )
    query(
        "finish_owner_words_are_actual_past",
        c,
        [
            step,
            c.G,
            c.finish,
            z3.Or(c.current.left != c.past.left, c.current.right != c.past.right),
        ],
        "unsat",
        "Native raw-word snapshots and owner stability discharge pure-function congruence",
    )
    query(
        "finish_response_matches_current_reference",
        c,
        [step, c.G, c.finish, c.current.response != c.ref(c.current)],
        "unsat",
        "Past terminal product, actual sign and native response projection use the same raw arguments",
    )
    query(
        "finish_result_without_induction_hypothesis",
        c,
        [step, c.G, c.finish, z3.Not(c.I)],
        "unsat",
        "Fresh completion uses no previous result hypothesis",
    )
    query(
        "hold_result_with_local_hypothesis",
        c,
        [step, c.G, c.hold, c.pI, z3.Not(c.I)],
        "unsat",
        "The actual preceding response and expected words are unchanged",
    )
    query(
        "all_step_cases",
        c,
        [step, c.pI, z3.Not(c.I)],
        "unsat",
        "Original guard and finish or hold cases are exhaustive",
    )
    previous_I = z3.Bool("boolean_observer.previous_I")
    monitor = z3.Implies(z3.And(c.history, step), previous_I == z3.Or(c.past.reset, c.pI))
    query(
        "boolean_monitor_step_substitution",
        c,
        [step, previous_I, monitor, z3.Not(c.I)],
        "unsat",
        "Pure previous-I observer discharges the sampled induction step",
    )
    query(
        "base_nonvacuity",
        c,
        [c.first, z3.Not(c.current.reset)],
        "sat",
        "Initial idle is satisfiable",
    )
    high = [z3.Extract(31, 31, c.current.left) == 1, z3.Extract(31, 31, c.current.right) == 1]
    query(
        "finish_nonvacuity",
        c,
        [step, c.G, c.finish, *high],
        "sat",
        "Fresh completion permits both high operand bits",
    )
    query(
        "hold_nonvacuity",
        c,
        [step, c.G, c.hold, c.pI, *high],
        "sat",
        "Held completion permits both high operand bits",
    )
    for name, certificate, extras in [
        ("negative_missing_base", Certificate(operation, base=False), "base"),
        ("negative_missing_response_epoch", Certificate(operation, epoch=False), "step"),
        ("negative_missing_past_terminal", Certificate(operation, terminal=False), "finish"),
        ("negative_wrong_finish_bit", Certificate(operation, wrong_finish=True), "finish"),
        ("negative_wrong_hold_expected", Certificate(operation, wrong_hold=True), "hold"),
    ]:
        additions = [z3.Not(certificate.I)]
        if extras == "base":
            additions += [certificate.first, z3.Not(certificate.current.reset)]
        else:
            additions += [z3.Not(certificate.first), certificate.pI]
            if extras == "finish":
                additions += [certificate.G, certificate.finish]
            if extras == "hold":
                additions += [certificate.G, certificate.hold]
        query(
            name,
            certificate,
            additions,
            "sat",
            "Countermodel to the proof with one missing or corrupted premise",
        )
    summary = {
        "schema": "ditdah-e2.mul-result-local-induction.v1",
        "copyright": "2026 Huang Rui <vowstar@gmail.com>",
        "license": "MIT",
        "solver": {"name": "Z3", "version": z3.get_version_string(), "logic": "QF_UFBV"},
        "operationParameter": operation,
        "sourceOperandBitsEach": 32,
        "functionSignature": "U(BV32,BV32) returns BV64",
        "functionInterpretation": "Unsigned 32 by 32 magnitude multiplication, reduced modulo 2^64",
        "referenceNormalizationRequiresCheckedSignTheorem": operation != 0,
        "multiplicationAxiomsAdded": 0,
        "unsat": 9,
        "nonvacuitySat": 3,
        "effectiveNegativeCountermodels": 5,
        "goalGuard": "!reset && !cancel && response_valid && owner_op == OPERATION",
        "goalConclusion": "response_bits == expected",
        "inductionHypothesis": "The complete result predicate at the actual preceding sample inside a local step only",
        "globalGoalAssumptionAdded": False,
        "nativePremisesDischarged": False,
        "originalArithmeticCompositionalProven": False,
        "nativeDirectArithmeticProven": False,
        "actualMOperationsAccepted": 0,
    }
    (output / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    return summary
