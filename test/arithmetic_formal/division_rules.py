# SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
# SPDX-License-Identifier: MIT
"""Compose full-width division from native sampled facts and checked arithmetic rules."""

import json
import re
import tempfile
import time
from pathlib import Path

import z3

from . import capture_rules, division_contracts, source
from . import facts as formal_facts


def bv(number, width=32):
    return z3.BitVecVal(number, width)


def _prove_sums(output):
    output.mkdir(parents=True, exist_ok=False)
    R = z3.BitVec("previous_R", 33)
    D = z3.BitVec("previous_D", 32)
    Q = z3.BitVec("previous_partial", 32)
    bit = z3.BitVec("incoming_bit", 1)
    Rc = z3.BitVec("current_R", 33)
    Dc = z3.BitVec("current_D", 32)
    Qc = z3.BitVec("current_partial", 32)
    F = z3.Function(
        "pure_sum",
        z3.BitVecSort(33),
        z3.BitVecSort(32),
        z3.BitVecSort(32),
        z3.BitVecSort(65),
    )
    Rn = z3.ZeroExt(1, z3.Extract(31, 0, R))
    Qn = z3.ZeroExt(1, z3.Extract(30, 0, Q))
    Rfits = z3.Extract(32, 32, R) == bv(0, 1)
    Qfits = z3.Extract(31, 31, Q) == bv(0, 1)
    shifted = z3.Concat(z3.Extract(31, 0, R), bit)
    decision = z3.UGE(shifted, z3.ZeroExt(1, D))
    rnext = z3.If(decision, shifted - z3.ZeroExt(1, D), shifted)
    qnext = z3.Concat(z3.Extract(30, 0, Q), z3.If(decision, bv(1, 1), bv(0, 1)))
    old = F(R, D, Q)
    childold = F(Rn, D, Qn)
    childr0 = shifted
    childr1 = shifted - z3.ZeroExt(1, D)
    childq0 = z3.Concat(z3.Extract(30, 0, Q), bv(0, 1))
    childq1 = z3.Concat(z3.Extract(30, 0, Q), bv(1, 1))
    childdouble = (childold << 1) + z3.ZeroExt(64, bit)
    doubled = (old << 1) + z3.ZeroExt(64, bit)
    pred = F(rnext, D, qnext)
    branch0 = F(childr0, D, childq0) == childdouble
    branch1 = z3.Implies(decision, F(childr1, D, childq1) == childdouble)
    So, Co, Sp, Cn, Sd, Sc = z3.BitVecs(
        "scalar_old scalar_child_old scalar_predicted scalar_child_next scalar_doubled scalar_current",
        65,
    )
    rows = []

    def query(name, facts, goal, expected="unsat", predecessors=(), substitution=None):
        solver = z3.Solver()
        solver.set(timeout=10000)
        solver.add(*facts, z3.Not(goal))
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
        if substitution is not None:
            row["captureFreeSubstitution"] = substitution
        if result == z3.sat:
            model = solver.model()
            values = {
                str(v): model.eval(v, model_completion=True).as_long()
                for v in (R, D, Q, bit, Rc, Dc, Qc)
            }
            row["model"] = values
            (output / (name + ".model.json")).write_text(
                json.dumps(values, indent=2) + "\n"
            )
        rows.append(row)
        (output / "queries.json").write_text(json.dumps(rows, indent=2) + "\n")
        if not str(result) == expected:
            raise ValueError("Division proof obligation failed")

    query("old_remainder_normalization", [Rfits], R == Rn)
    query("old_partial_normalization", [Qfits], Q == Qn)
    query(
        "old_sum_congruence",
        [R == Rn, Q == Qn],
        old == childold,
        predecessors=("old_remainder_normalization", "old_partial_normalization"),
    )
    query(
        "no_subtract_word_binding",
        [z3.Not(decision)],
        z3.And(rnext == childr0, qnext == childq0),
    )
    query(
        "subtract_word_binding", [decision], z3.And(rnext == childr1, qnext == childq1)
    )
    query(
        "no_subtract_sum_congruence",
        [rnext == childr0, qnext == childq0],
        pred == F(childr0, D, childq0),
        predecessors=("no_subtract_word_binding",),
    )
    query(
        "subtract_sum_congruence",
        [rnext == childr1, qnext == childq1],
        pred == F(childr1, D, childq1),
        predecessors=("subtract_word_binding",),
    )
    query(
        "polynomial_scalar_transport",
        [So == Co, Sp == Cn, Cn == (Co << 1) + z3.ZeroExt(64, bit)],
        Sp == (So << 1) + z3.ZeroExt(64, bit),
        predecessors=(
            "old_sum_congruence",
            "no_subtract_sum_congruence",
            "subtract_sum_congruence",
        ),
        substitution={
            "scalar_old": "division_previous_sum",
            "scalar_child_old": "selected division_no_subtract.old_sum or division_subtract.old_sum",
            "scalar_predicted": "division_predicted_sum",
            "scalar_child_next": "selected branch next_sum",
            "incoming_bit": "division_previous_quotient[31]",
            "localNumericPremise": "native branch exact_polynomial_transition, guarded in subtract case",
        },
    )
    query(
        "polynomial_all_cases",
        [z3.Implies(z3.Not(decision), Sp == Sd), z3.Implies(decision, Sp == Sd)],
        Sp == Sd,
        predecessors=("polynomial_scalar_transport",),
        substitution={
            "scalar_predicted": "division_predicted_sum",
            "scalar_doubled": "division_doubled_previous_sum",
            "decision": "division_previous_decision, source exact unsigned comparison",
        },
    )
    query(
        "actual_sum_congruence",
        [Rc == rnext, Dc == D, Qc == qnext],
        F(Rc, Dc, Qc) == pred,
    )
    query(
        "actual_sum_recurrence",
        [Sc == Sp, Sp == Sd],
        Sc == Sd,
        predecessors=("actual_sum_congruence", "polynomial_all_cases"),
        substitution={
            "scalar_current": "division_sum",
            "scalar_predicted": "division_predicted_sum",
            "scalar_doubled": "division_doubled_previous_sum",
        },
    )
    scalar_formula = z3.Implies(
        z3.And(So == Co, Sp == Cn, Cn == (Co << 1) + z3.ZeroExt(64, bit)),
        Sp == (So << 1) + z3.ZeroExt(64, bit),
    )
    substitutions = []
    for name, childnew in [
        ("no_subtract", F(childr0, D, childq0)),
        ("subtract", F(childr1, D, childq1)),
    ]:
        pairs = [(So, old), (Co, childold), (Sp, pred), (Cn, childnew)]
        actual = z3.substitute(scalar_formula, *pairs)
        expected = z3.Implies(
            z3.And(
                old == childold,
                pred == childnew,
                childnew == (childold << 1) + z3.ZeroExt(64, bit),
            ),
            pred == doubled,
        )
        if not (
            z3.eq(actual, expected) and all((a.sort() == b.sort() for a, b in pairs))
        ):
            raise ValueError("Division proof obligation failed")
        substitutions.append(
            {
                "name": name,
                "typedCaptureFreeSubstitutionChecked": True,
                "formalToActual": [{str(a): b.sexpr()} for a, b in pairs],
                "actualFormula": actual.sexpr(),
                "nativeBranchGuard": (
                    "always" if name == "no_subtract" else "division_previous_decision"
                ),
            }
        )
    boolean_formula = z3.Implies(
        z3.And(z3.Implies(z3.Not(decision), Sp == Sd), z3.Implies(decision, Sp == Sd)),
        Sp == Sd,
    )
    actual = z3.substitute(boolean_formula, (Sp, pred), (Sd, doubled))
    expected = z3.Implies(
        z3.And(
            z3.Implies(z3.Not(decision), pred == doubled),
            z3.Implies(decision, pred == doubled),
        ),
        pred == doubled,
    )
    if not z3.eq(actual, expected):
        raise ValueError("Division proof obligation failed")
    substitutions.append(
        {
            "name": "case_completeness",
            "typedCaptureFreeSubstitutionChecked": True,
            "actualFormula": actual.sexpr(),
        }
    )
    transitivity = z3.Implies(z3.And(Sc == Sp, Sp == Sd), Sc == Sd)
    actual = z3.substitute(transitivity, (Sc, F(Rc, Dc, Qc)), (Sp, pred), (Sd, doubled))
    expected = z3.Implies(
        z3.And(F(Rc, Dc, Qc) == pred, pred == doubled), F(Rc, Dc, Qc) == doubled
    )
    if not z3.eq(actual, expected):
        raise ValueError("Division proof obligation failed")
    substitutions.append(
        {
            "name": "actual_sum_recurrence",
            "typedCaptureFreeSubstitutionChecked": True,
            "actualFormula": actual.sexpr(),
        }
    )
    (output / "substitutions.json").write_text(
        json.dumps(substitutions, indent=2) + "\n"
    )
    for name, facts in [
        ("nonvacuity_nosubtract", [z3.Not(decision), D == bv(2147483648, 32)]),
        (
            "nonvacuity_subtract",
            [
                decision,
                D == bv(2147483648, 32),
                R == bv(2147483647, 33),
                bit == bv(1, 1),
            ],
        ),
        ("nonvacuity_zero_divisor", [D == bv(0, 32)]),
    ]:
        query(name, [Rfits, Qfits, branch0, branch1] + facts, z3.BoolVal(False), "sat")
    query(
        "negative_missing_remainder_width",
        [
            Qfits,
            R == bv(1 << 32, 33),
            Q == bv(0, 32),
            D == bv(0, 32),
            F(R, D, Q) == bv(1 << 32, 65),
            F(Rn, D, Qn) == bv(0, 65),
        ],
        old == childold,
        "sat",
    )
    query(
        "negative_missing_partial_width",
        [
            Rfits,
            R == bv(0, 33),
            Q == bv(1 << 31, 32),
            D == bv(1, 32),
            F(R, D, Q) == bv(1 << 31, 65),
            F(Rn, D, Qn) == bv(0, 65),
        ],
        old == childold,
        "sat",
    )
    query(
        "negative_missing_actual_partial",
        [
            Rc == rnext,
            Dc == D,
            R == bv(0, 33),
            D == bv(1, 32),
            Q == bv(0, 32),
            bit == bv(0, 1),
            Qc == bv(1, 32),
            F(R, D, Q) == bv(0, 65),
            F(Rc, Dc, Qc) == bv(1, 65),
            pred == doubled,
        ],
        F(Rc, Dc, Qc) == doubled,
        "sat",
    )
    query(
        "negative_missing_subtract_guard",
        [
            Rfits,
            Qfits,
            branch1,
            R == bv(0, 33),
            D == bv(1, 32),
            Q == bv(0, 32),
            bit == bv(0, 1),
            F(R, D, Q) == bv(0, 65),
            F(childr1, D, childq1) == bv(1 << 33, 65),
        ],
        F(childr1, D, childq1) == doubled,
        "sat",
    )
    summary = {
        "positiveUnsat": sum(row["actual"] == "unsat" for row in rows),
        "nonvacuitySat": sum(
            row["actual"] == "sat" and "negative_" not in row["name"] for row in rows
        ),
        "negativeCountermodels": sum(
            row["actual"] == "sat" and "negative_" in row["name"] for row in rows
        ),
    }
    (output / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    return summary


class ConservationState:

    def __init__(self, name):
        for field in ("reset", "cancel", "pending", "active"):
            setattr(self, field, z3.Bool(name + "." + field))
        for field, width in (
            ("R", 33),
            ("D", 32),
            ("Q", 32),
            ("L", 32),
            ("right", 32),
            ("op", 3),
            ("i", 6),
            ("zero", 1),
        ):
            setattr(self, field, z3.BitVec(name + "." + field, width))


class ConservationCertificate:

    def __init__(
        self,
        operation,
        *,
        epoch=True,
        base=True,
        wrong_snapshot=False,
        wrong_bit=False,
        actual_sum=True,
        op_snapshot=True,
    ):
        if not operation in (4, 5, 6, 7):
            raise ValueError("Division proof obligation failed")
        self.current, self.past = (
            ConservationState("current"),
            ConservationState("past"),
        )
        c, p = (self.current, self.past)
        self.history, self.first, self.previous_reset = z3.Bools(
            "history_valid division_first_proof_frame previous_reset"
        )
        self.previous_owner, self.previous_step = z3.Bools(
            "division_previous_owner division_previous_step"
        )
        self.snap = {
            field: z3.BitVec("snapshot." + field, width)
            for field, width in (
                ("R", 33),
                ("D", 32),
                ("Q", 32),
                ("L", 32),
                ("right", 32),
                ("op", 3),
                ("i", 6),
                ("zero", 1),
            )
        }
        self.S = z3.Function(
            "sum65",
            z3.BitVecSort(33),
            z3.BitVecSort(32),
            z3.BitVecSort(32),
            z3.BitVecSort(6),
            z3.BitVecSort(65),
        )
        self.P = z3.Function(
            "prefix65",
            z3.BitVecSort(32),
            z3.BitVecSort(3),
            z3.BitVecSort(6),
            z3.BitVecSort(65),
        )
        self.selected = lambda state: z3.And(
            state.pending, state.op == bv(operation, 3)
        )
        self.guard = lambda state: z3.And(
            z3.Not(state.reset),
            z3.Not(state.cancel),
            self.selected(state),
            state.active,
        )
        self.G, self.pG = (self.guard(c), self.guard(p))
        self.current_sum = self.S(c.R, c.D, c.Q, c.i)
        self.past_sum = self.S(p.R, p.D, p.Q, p.i)
        self.current_prefix = self.P(c.L, c.op, c.i)
        self.past_prefix = self.P(p.L, p.op, p.i)
        self.snapshot_sum = self.S(
            self.snap["R"], self.snap["D"], self.snap["Q"], self.snap["i"]
        )
        self.snapshot_prefix = self.P(self.snap["L"], self.snap["op"], self.snap["i"])
        self.bit = z3.ZeroExt(64, z3.Extract(31, 31, self.snap["Q"]))
        prefix_bit = self.bit ^ bv(1 if wrong_bit else 0, 65)
        self.I = z3.Implies(self.G, self.current_sum == self.current_prefix)
        self.pI = z3.Implies(self.pG, self.past_sum == self.past_prefix)
        self.common = z3.And(
            self.history, z3.Not(c.reset), z3.Not(c.cancel), self.selected(c)
        )
        self.facts = {
            "source_previous_reset_capture": z3.Implies(
                z3.And(self.history, z3.Not(self.first)), self.previous_reset == p.reset
            )
        }
        if epoch:
            self.facts["reverse_active_epoch"] = z3.Implies(
                self.G,
                z3.And(
                    self.history,
                    z3.Or(
                        c.i == bv(0, 6), z3.And(self.previous_step, self.previous_owner)
                    ),
                ),
            )
        snapshot_guard = z3.And(
            self.history,
            z3.Not(c.reset),
            z3.Not(self.previous_reset),
            self.previous_owner,
        )
        for field in self.snap:
            if field == "op" and (not op_snapshot):
                continue
            expected = getattr(p, field)
            if wrong_snapshot and field == "Q":
                expected = expected ^ bv(1, 32)
            self.facts["snapshot_" + field] = z3.Implies(
                snapshot_guard, self.snap[field] == expected
            )
        flag_guard = z3.And(self.history, z3.Not(c.reset))
        self.facts["step_flag"] = z3.Implies(
            flag_guard,
            self.previous_step
            == z3.And(
                z3.Not(self.previous_reset),
                z3.Not(p.cancel),
                self.selected(p),
                p.active,
                z3.ULT(p.i, bv(32, 6)),
            ),
        )
        self.facts["owner_flag"] = z3.Implies(
            flag_guard,
            self.previous_owner
            == z3.And(z3.Not(self.previous_reset), z3.Not(p.cancel), self.selected(p)),
        )
        self.facts["initial_sum"] = z3.Implies(
            z3.And(self.common, c.active, c.i == bv(0, 6)),
            self.current_sum == self.current_prefix,
        )
        step_guard = z3.And(self.common, self.previous_step)
        if actual_sum:
            self.facts["actual_sum_step"] = z3.Implies(
                step_guard, self.current_sum == (self.snapshot_sum << 1) + self.bit
            )
        self.facts["prefix_step"] = z3.Implies(
            step_guard, self.current_prefix == (self.snapshot_prefix << 1) + prefix_bit
        )
        if base:
            self.facts["first_frame_idle"] = z3.Implies(
                z3.And(z3.Not(c.reset), self.first),
                z3.And(z3.Not(c.pending), z3.Not(c.active)),
            )


def _prove_conservation(output, operation):
    output.mkdir(parents=True, exist_ok=False)
    rows = []

    def query(name, certificate, extras, expected, role):
        solver = z3.SolverFor("QF_UFBV")
        solver.set(timeout=15000)
        for label, fact in certificate.facts.items():
            flag = z3.Bool("fact." + label)
            solver.add(z3.Implies(flag, fact), flag)
        solver.add(*extras)
        (output / (name + ".smt2")).write_text(solver.to_smt2())
        start = time.monotonic()
        result = solver.check()
        row = {
            "name": name,
            "expected": expected,
            "actual": str(result),
            "seconds": round(time.monotonic() - start, 6),
            "role": role,
            "premises": list(certificate.facts),
        }
        if result == z3.sat:
            model = solver.model()
            (output / (name + ".model.txt")).write_text(str(model) + "\n")
            words = {
                field: str(
                    model.eval(
                        getattr(certificate.current, field), model_completion=True
                    )
                )
                for field in ("R", "D", "Q", "L", "right", "op", "i", "zero")
            }
            words.update(
                currentPredicate=str(model.eval(certificate.I, model_completion=True)),
                pastPredicate=str(model.eval(certificate.pI, model_completion=True)),
            )
            (output / (name + ".values.json")).write_text(
                json.dumps(words, indent=2) + "\n"
            )
        rows.append(row)
        (output / "queries.json").write_text(json.dumps(rows, indent=2) + "\n")
        if not str(result) == expected:
            raise ValueError("Division proof obligation failed")

    c = ConservationCertificate(operation)
    step = z3.And(c.G, c.current.i != bv(0, 6), z3.Not(c.first))
    query(
        "base_first_frame",
        c,
        [c.first, z3.Not(c.I)],
        "unsat",
        "The native first-frame idle theorem discharges the original guard",
    )
    query(
        "reset_guard",
        c,
        [c.current.reset, z3.Not(c.I)],
        "unsat",
        "The original guard is inactive during reset",
    )
    query(
        "reverse_epoch_actual_past_guard",
        c,
        [step, z3.Not(c.pG)],
        "unsat",
        "The native reverse epoch and exact flag/reset sampling supply the actual preceding guard",
    )
    query(
        "snapshot_sum_actual_past",
        c,
        [step, c.snapshot_sum != c.past_sum],
        "unsat",
        "Four native primitive snapshots bind the same pure 65-bit sum function",
    )
    query(
        "snapshot_prefix_actual_past",
        c,
        [step, c.snapshot_prefix != c.past_prefix],
        "unsat",
        "Owner and iteration snapshots bind the same pure prefix function",
    )
    query(
        "iteration_zero_base",
        c,
        [c.G, c.current.i == bv(0, 6), z3.Not(c.I)],
        "unsat",
        "Native initial conservation applies after reverse epoch provides history",
    )
    query(
        "single_step_nonzero",
        c,
        [step, c.pI, z3.Not(c.I)],
        "unsat",
        "Equal preceding sum/prefix and the same doubled-sum incoming bit establish the current invariant",
    )
    query(
        "single_step_all_cases",
        c,
        [z3.Not(c.first), c.pI, z3.Not(c.I)],
        "unsat",
        "Iteration zero and nonzero cases exhaust the original active guard",
    )
    previous_I = z3.Bool("boolean_observer.previous_I")
    observer = z3.Implies(
        z3.And(c.history, z3.Not(c.first)), previous_I == z3.Or(c.past.reset, c.pI)
    )
    query(
        "boolean_monitor_step_substitution",
        c,
        [z3.Not(c.first), previous_I, observer, z3.Not(c.I)],
        "unsat",
        "A pure previous-I observer discharges the second native Boolean induction premise",
    )
    query(
        "base_nonvacuity",
        c,
        [c.first, z3.Not(c.current.reset)],
        "sat",
        "The first non-reset frame is feasible",
    )
    for divisor in (0, 1):
        query(
            "step_nonvacuity_divisor_" + str(divisor),
            c,
            [
                step,
                c.pI,
                c.current.D == bv(divisor, 32),
                z3.Extract(31, 31, c.current.L) == bv(1, 1),
                z3.Extract(31, 31, c.current.Q) == bv(1, 1),
            ],
            "sat",
            "The local rule retains zero and nonzero divisors and both high operand-state bits",
        )
    for name, options, role in (
        (
            "negative_missing_epoch",
            {"epoch": False},
            "Without reverse epoch the current active frame can have unrelated history",
        ),
        (
            "negative_wrong_snapshot",
            {"wrong_snapshot": True},
            "A changed captured quotient bit breaks actual-past sum binding",
        ),
        (
            "negative_wrong_incoming_bit",
            {"wrong_bit": True},
            "Different incoming bits break sum and prefix recurrence agreement",
        ),
        (
            "negative_missing_actual_sum_bridge",
            {"actual_sum": False},
            "Primitive capture alone does not establish the sum recurrence",
        ),
        (
            "negative_missing_owner_operation_snapshot",
            {"op_snapshot": False},
            "The signed prefix depends on the actual captured owner operation",
        ),
    ):
        bad = ConservationCertificate(operation, **options)
        query(name, bad, [z3.Not(bad.first), bad.pI, z3.Not(bad.I)], "sat", role)
    no_base = ConservationCertificate(operation, base=False)
    query(
        "negative_missing_base",
        no_base,
        [no_base.first, z3.Not(no_base.current.reset), z3.Not(no_base.I)],
        "sat",
        "A local step does not establish the first frame",
    )
    summary = {
        "positiveUnsat": sum(row["actual"] == "unsat" for row in rows),
        "nonvacuitySat": sum(
            row["actual"] == "sat" and "negative_" not in row["name"] for row in rows
        ),
        "negativeCountermodels": sum(
            row["actual"] == "sat" and "negative_" in row["name"] for row in rows
        ),
    }
    (output / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    return summary


def _prove_unique(output):
    output.mkdir(parents=True, exist_ok=False)
    A, D, Q, R = z3.Ints("A D Q R")
    domains = [
        A >= 0,
        A < 2**32,
        D >= 0,
        D < 2**32,
        Q >= 0,
        Q < 2**32,
        R >= 0,
        R < 2**33,
    ]
    eligible = [D > 0, R < D, A == D * Q + R]
    rows = []

    def query(name, premises, conclusion, expected="unsat", predecessors=()):
        solver = z3.Solver()
        solver.set(timeout=5000)
        solver.add(*premises, z3.Not(conclusion))
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
            values = {
                str(x): model.eval(x, model_completion=True).as_long()
                for x in (A, D, Q, R)
            }
            row["countermodel"] = values
            (output / (name + ".model.json")).write_text(
                json.dumps(values, indent=2) + "\n"
            )
        else:
            row["reasonUnknown"] = solver.reason_unknown()
        rows.append(row)
        (output / "queries.json").write_text(json.dumps(rows, indent=2) + "\n")
        if not str(result) == expected:
            raise ValueError("Division proof obligation failed")

    query(
        "product_and_sum_fit_65",
        domains,
        z3.And(D * Q >= 0, D * Q < 2**65, D * Q + R >= 0, D * Q + R < 2**65),
    )
    query(
        "remove_65_bit_modulo",
        domains + [D * Q + R < 2**65],
        z3.And(D * Q % 2**65 == D * Q, (D * Q + R) % 2**65 == D * Q + R),
        predecessors=("product_and_sum_fit_65",),
    )
    query("unique_integer_quotient", domains + eligible, Q == A / D)
    query("integer_divmod_identity", [D > 0], A == D * (A / D) + A % D)
    query(
        "unique_integer_remainder",
        domains + eligible + [Q == A / D],
        R == A % D,
        predecessors=("unique_integer_quotient",),
    )
    query(
        "quotient_projection_fits_32",
        domains + eligible + [Q == A / D],
        z3.And(A / D >= 0, A / D < 2**32),
        predecessors=("unique_integer_quotient",),
    )
    query(
        "remainder_projection_fits_32",
        domains + eligible + [R == A % D],
        z3.And(A % D >= 0, A % D < 2**32),
        predecessors=("unique_integer_remainder",),
    )
    query(
        "restore_32_bit_results",
        domains + eligible + [Q == A / D, R == A % D],
        z3.And(A / D % 2**32 == Q, A % D % 2**32 == R),
        predecessors=("unique_integer_quotient", "unique_integer_remainder"),
    )
    query(
        "negative_missing_remainder_bound",
        domains + [D > 0, A == D * Q + R],
        Q == A / D,
        expected="sat",
    )
    query(
        "negative_32_bit_product",
        domains
        + [
            D > 0,
            R < D,
            A == (D * Q + R) % 2**32,
            D == 65536,
            Q == 65536,
            A == 0,
            R == 0,
        ],
        Q == A / D,
        expected="sat",
    )
    query("negative_wrong_quotient", domains + eligible, Q == A / D + 1, expected="sat")
    query(
        "negative_wrong_remainder", domains + eligible, R == A % D + 1, expected="sat"
    )
    for name, values in [
        ("nonvacuity_high_operands", (2**32 - 1, 2**31, 1, 2**31 - 1)),
        ("nonvacuity_small_divisor", (2**32 - 1, 1, 2**32 - 1, 0)),
        ("nonvacuity_zero_dividend", (0, 2**32 - 1, 0, 0)),
    ]:
        query(
            name,
            domains + eligible + [x == v for x, v in zip((A, D, Q, R), values)],
            z3.BoolVal(False),
            expected="sat",
        )
    summary = {
        "positiveUnsat": sum(row["actual"] == "unsat" for row in rows),
        "nonvacuitySat": sum(
            row["actual"] == "sat" and "negative_" not in row["name"] for row in rows
        ),
        "negativeCountermodels": sum(
            row["actual"] == "sat" and "negative_" in row["name"] for row in rows
        ),
    }
    (output / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    return summary


class TerminalCertificate:

    def __init__(
        self,
        operation,
        *,
        terminal_fields=True,
        owner_divisor=True,
        remainder_bound=True,
        zero_flag=True,
    ):
        self.reset, self.cancel, self.pending, self.active, self.history = z3.Bools(
            "reset cancel pending active history_valid"
        )
        if not operation in (4, 5, 6, 7):
            raise ValueError("Division proof obligation failed")
        self.L, self.right = z3.BitVecs("owner_left owner_right", 32)
        self.R = z3.BitVec("actual_remainder", 33)
        self.D, self.Q, self.partial, self.prefix = z3.BitVecs(
            "actual_divisor actual_quotient quotient_partial dividend_prefix", 32
        )
        self.op, self.i = (z3.BitVec("owner_operation", 3), z3.BitVec("iteration", 6))
        left_signed = z3.Or(*[self.op == bv(n, 3) for n in (1, 2, 4, 6)])
        right_signed = z3.Or(*[self.op == bv(n, 3) for n in (1, 4, 6)])
        self.left_magnitude = z3.If(
            z3.And(left_signed, z3.Extract(31, 31, self.L) == 1), -self.L, self.L
        )
        self.right_magnitude = z3.If(
            z3.And(right_signed, z3.Extract(31, 31, self.right) == 1),
            -self.right,
            self.right,
        )
        self.zero = z3.Bool("actual_zero_divisor")
        self.F = z3.Function(
            "actual_sum65",
            z3.BitVecSort(33),
            z3.BitVecSort(32),
            z3.BitVecSort(32),
            z3.BitVecSort(65),
        )
        self.UQ = z3.Function(
            "unsigned_division32",
            z3.BitVecSort(32),
            z3.BitVecSort(32),
            z3.BitVecSort(32),
        )
        self.UR = z3.Function(
            "unsigned_remainder32",
            z3.BitVecSort(32),
            z3.BitVecSort(32),
            z3.BitVecSort(32),
        )
        selected = z3.And(self.pending, self.op == bv(operation, 3))
        owner = z3.And(z3.Not(self.reset), z3.Not(self.cancel), selected)
        self.G = z3.And(owner, self.active)
        self.K = z3.And(self.G, self.i == bv(32, 6))
        self.nonzero = z3.And(self.K, self.right_magnitude != bv(0, 32))
        self.zero_case = z3.And(self.K, self.right_magnitude == bv(0, 32))
        common = z3.And(self.history, owner)
        actual_sum = self.F(self.R, self.D, self.Q)
        self.terminal = z3.Implies(
            self.K, actual_sum == z3.ZeroExt(33, self.left_magnitude)
        )
        self.quotient = z3.Implies(
            self.nonzero, self.Q == self.UQ(self.left_magnitude, self.right_magnitude)
        )
        self.remainder = z3.Implies(
            self.nonzero,
            z3.Extract(31, 0, self.R)
            == self.UR(self.left_magnitude, self.right_magnitude),
        )
        self.zero_terminal = z3.Implies(
            self.zero_case,
            z3.And(self.zero, z3.Extract(31, 0, self.R) == self.left_magnitude),
        )
        self.facts = {
            "native_history_for_owner": z3.Implies(owner, self.history),
            "proved_original_conservation": z3.Implies(
                self.G,
                self.F(self.R, self.D, self.partial) == z3.ZeroExt(33, self.prefix),
            ),
        }
        if terminal_fields:
            self.facts["native_terminal_fields"] = z3.Implies(
                z3.And(common, self.active, self.i == bv(32, 6)),
                z3.And(self.partial == self.Q, self.prefix == self.left_magnitude),
            )
        if owner_divisor:
            self.facts["native_owner_divisor"] = z3.Implies(
                z3.And(z3.Not(self.reset), z3.Not(self.cancel), self.pending),
                self.D == self.right_magnitude,
            )
        if remainder_bound:
            self.facts["native_remainder_bound"] = z3.Implies(
                z3.And(self.G, self.right_magnitude != bv(0, 32)),
                z3.ULT(self.R, z3.ZeroExt(1, self.D)),
            )
        eligible = z3.And(
            self.D != bv(0, 32),
            z3.ULT(self.R, z3.ZeroExt(1, self.D)),
            actual_sum == z3.ZeroExt(33, self.left_magnitude),
        )
        self.facts["proved_integer_uniqueness"] = z3.Implies(
            eligible,
            z3.And(
                self.Q == self.UQ(self.left_magnitude, self.D),
                self.R == z3.ZeroExt(1, self.UR(self.left_magnitude, self.D)),
            ),
        )
        self.facts["proved_zero_product_identity"] = z3.Implies(
            self.D == bv(0, 32), actual_sum == z3.ZeroExt(32, self.R)
        )
        if zero_flag:
            self.facts["native_zero_divisor_flag"] = z3.Implies(
                z3.And(z3.Not(self.reset), z3.Not(self.cancel), self.pending),
                self.zero == (self.right == bv(0, 32)),
            )


def _prove_terminal(output, operation):
    output.mkdir(parents=True, exist_ok=False)
    rows = []

    def query(name, certificate, extras, expected, role):
        solver = z3.SolverFor("QF_UFBV")
        solver.set(timeout=15000)
        solver.add(*certificate.facts.values(), *extras)
        (output / (name + ".smt2")).write_text(solver.to_smt2())
        start = time.monotonic()
        result = solver.check()
        row = {
            "name": name,
            "actual": str(result),
            "expected": expected,
            "role": role,
            "seconds": round(time.monotonic() - start, 6),
            "premises": list(certificate.facts),
        }
        if result == z3.sat:
            model = solver.model()
            (output / (name + ".model.txt")).write_text(str(model) + "\n")
            values = {
                str(value): str(model.eval(value, model_completion=True))
                for value in (
                    certificate.L,
                    certificate.right,
                    certificate.R,
                    certificate.D,
                    certificate.Q,
                    certificate.partial,
                    certificate.prefix,
                    certificate.i,
                    certificate.zero,
                )
            }
            values.update(
                terminal=str(model.eval(certificate.terminal, model_completion=True)),
                quotient=str(model.eval(certificate.quotient, model_completion=True)),
                remainder=str(model.eval(certificate.remainder, model_completion=True)),
                zeroTerminal=str(
                    model.eval(certificate.zero_terminal, model_completion=True)
                ),
            )
            (output / (name + ".values.json")).write_text(
                json.dumps(values, indent=2) + "\n"
            )
        rows.append(row)
        (output / "queries.json").write_text(json.dumps(rows, indent=2) + "\n")
        if not str(result) == expected:
            raise ValueError("Division proof obligation failed")

    c = TerminalCertificate(operation)
    query(
        "terminal_field_congruence",
        c,
        [c.K, c.F(c.R, c.D, c.partial) != c.F(c.R, c.D, c.Q)],
        "unsat",
        "Native terminal quotient-mask equality discharges the three-word pure-function congruence premises",
    )
    query(
        "original_full_terminal",
        c,
        [z3.Not(c.terminal)],
        "unsat",
        "The original terminal guard has no added history condition",
    )
    query(
        "nonzero_eligible_for_uniqueness",
        c,
        [
            c.nonzero,
            z3.Not(
                z3.And(
                    c.D != bv(0, 32),
                    z3.ULT(c.R, z3.ZeroExt(1, c.D)),
                    c.F(c.R, c.D, c.Q) == z3.ZeroExt(33, c.left_magnitude),
                )
            ),
        ],
        "unsat",
        "Native divisor ownership and remainder range discharge every Euclidean theorem premise",
    )
    query(
        "nonzero_quotient_reference",
        c,
        [z3.Not(c.quotient)],
        "unsat",
        "The proved quotient lemma uses the actual owner divisor",
    )
    query(
        "nonzero_remainder_reference",
        c,
        [z3.Not(c.remainder)],
        "unsat",
        "The proved 33-bit remainder equality implies the source low-word projection",
    )
    query(
        "zero_terminal_reference",
        c,
        [z3.Not(c.zero_terminal)],
        "unsat",
        "Zero divisors use the zero-product identity and the native zero-divisor flag",
    )
    query(
        "nonvacuity_zero_divisor",
        c,
        [
            c.zero_case,
            c.L == bv(2147483648, 32),
            c.Q == bv(4294967295, 32),
            c.R == z3.ZeroExt(1, c.left_magnitude),
        ],
        "sat",
        "Zero divisor with the raw dividend high bit set",
    )
    query(
        "nonvacuity_high_divisor",
        c,
        [
            c.nonzero,
            c.L == bv(2147483648, 32),
            c.right == bv(2147483648, 32),
            c.Q == bv(1, 32),
            c.R == bv(0, 33),
        ],
        "sat",
        "Both raw operand high bits and the exact magnitude quotient",
    )
    query(
        "nonvacuity_small_divisor",
        c,
        [
            c.nonzero,
            c.L == bv(4294967295, 32),
            c.right == bv(1, 32),
            c.Q == c.left_magnitude,
            c.R == bv(0, 33),
        ],
        "sat",
        "Divisor one with a complete 32-bit raw dividend",
    )
    for name, arguments, attribute in (
        ("negative_missing_terminal_fields", {"terminal_fields": False}, "terminal"),
        ("negative_missing_divisor_ownership", {"owner_divisor": False}, "quotient"),
        ("negative_missing_remainder_bound", {"remainder_bound": False}, "quotient"),
        ("negative_missing_zero_flag", {"zero_flag": False}, "zero_terminal"),
    ):
        bad = TerminalCertificate(operation, **arguments)
        query(
            name,
            bad,
            [z3.Not(getattr(bad, attribute))],
            "sat",
            "A missing required source premise gives a countermodel",
        )
    R, D, Q = (z3.BitVec("R", 33), z3.BitVec("D", 32), z3.BitVec("Q", 32))
    concrete = z3.ZeroExt(32, R) + z3.ZeroExt(33, D) * z3.ZeroExt(33, Q)
    solver = z3.SolverFor("QF_BV")
    solver.add(D == bv(0, 32), concrete != z3.ZeroExt(32, R))
    (output / "zero_product_numeric_identity.smt2").write_text(solver.to_smt2())
    if not solver.check() == z3.unsat:
        raise ValueError("Division proof obligation failed")
    rows.append(
        {
            "name": "zero_product_numeric_identity",
            "actual": "unsat",
            "expected": "unsat",
            "role": "The concrete 65-bit source function has a zero product for D=0",
            "premises": [],
        }
    )
    (output / "queries.json").write_text(json.dumps(rows, indent=2) + "\n")
    summary = {
        "positiveUnsat": sum(row["actual"] == "unsat" for row in rows),
        "nonvacuitySat": sum(
            row["actual"] == "sat" and "negative_" not in row["name"] for row in rows
        ),
        "negativeCountermodels": sum(
            row["actual"] == "sat" and "negative_" in row["name"] for row in rows
        ),
    }
    (output / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    return summary


def _signed_operator(left, right, quotient, remainder, is_remainder):
    left_negative = z3.Extract(31, 31, left) == bv(1, 1)
    right_negative = z3.Extract(31, 31, right) == bv(1, 1)
    function = remainder if is_remainder else quotient
    positive = function(left, right)
    left_only = -function(-left, right)
    right_only = function(left, -right) if is_remainder else -function(left, -right)
    both = -function(-left, -right) if is_remainder else function(-left, -right)
    return z3.If(
        left_negative,
        z3.If(right_negative, both, left_only),
        z3.If(right_negative, right_only, positive),
    )


def _prove_builtin_definitions(output):
    output.mkdir(parents=True, exist_ok=False)
    rows = []
    for is_remainder in (False, True):
        for left_bit in (0, 1):
            for right_bit in (0, 1):
                low_left, low_right = z3.BitVecs("remaining_left remaining_right", 31)
                left = z3.Concat(bv(left_bit, 1), low_left)
                right = z3.Concat(bv(right_bit, 1), low_right)
                actual = z3.SRem(left, right) if is_remainder else left / right
                defined = _signed_operator(left, right, z3.UDiv, z3.URem, is_remainder)
                name = "signed_remainder" if is_remainder else "signed_division"
                name += "_msb" + str(left_bit) + str(right_bit)
                solver = z3.SolverFor("QF_BV")
                solver.set(timeout=5000)
                solver.add(actual != defined)
                (output / (name + ".smt2")).write_text(solver.to_smt2())
                result = solver.check()
                if result != z3.unsat:
                    raise ValueError("Signed operator definition differs: " + name)
                rows.append({"name": name, "actual": str(result), "expected": "unsat"})
    left, right = z3.BitVecs("whole_left whole_right", 32)
    cases = [
        z3.And(
            z3.Extract(31, 31, left) == bv(a, 1), z3.Extract(31, 31, right) == bv(b, 1)
        )
        for a in (0, 1)
        for b in (0, 1)
    ]
    goals = {
        "sign_partition_exhaustive": z3.Or(*cases),
        "whole_words_reconstructed": z3.And(
            z3.Concat(z3.Extract(31, 31, left), z3.Extract(30, 0, left)) == left,
            z3.Concat(z3.Extract(31, 31, right), z3.Extract(30, 0, right)) == right,
        ),
    }
    for name, goal in goals.items():
        solver = z3.SolverFor("QF_BV")
        solver.add(z3.Not(goal))
        (output / (name + ".smt2")).write_text(solver.to_smt2())
        result = solver.check()
        if result != z3.unsat:
            raise ValueError("Signed operand partition is incomplete")
        rows.append({"name": name, "actual": str(result), "expected": "unsat"})
    (output / "queries.json").write_text(json.dumps(rows, indent=2) + "\n")
    return {"positiveUnsat": len(rows), "signedRemainderOperator": "bvsrem"}


W = 2**32


def _prove_normalization(output):
    output.mkdir(parents=True, exist_ok=False)
    A, C = z3.BitVecs("left right", 32)
    UQ = z3.Function(
        "unsigned_quotient", z3.BitVecSort(32), z3.BitVecSort(32), z3.BitVecSort(32)
    )
    UR = z3.Function(
        "unsigned_remainder", z3.BitVecSort(32), z3.BitVecSort(32), z3.BitVecSort(32)
    )
    rows = []
    parsed = {
        "bvsdiv": _signed_operator(A, C, UQ, UR, False),
        "bvsrem": _signed_operator(A, C, UQ, UR, True),
    }

    def query(name, facts, goal, expected="unsat", predecessors=(), role=""):
        solver = z3.Solver()
        solver.set(timeout=10000)
        solver.add(*facts, z3.Not(goal))
        (output / (name + ".smt2")).write_text(solver.to_smt2())
        start = time.monotonic()
        result = solver.check()
        row = {
            "name": name,
            "expected": expected,
            "actual": str(result),
            "seconds": round(time.monotonic() - start, 6),
            "provedPredecessors": list(predecessors),
            "role": role,
        }
        if result == z3.sat:
            model = solver.model()
            row["model"] = {
                str(v): model.eval(v, model_completion=True).as_long() for v in (A, C)
            }
            (output / (name + ".model.json")).write_text(
                json.dumps(row["model"], indent=2) + "\n"
            )
        rows.append(row)
        (output / "queries.json").write_text(json.dumps(rows, indent=2) + "\n")
        if not str(result) == expected:
            raise ValueError("Division proof obligation failed")

    query(
        "unsigned_divide_by_one",
        [],
        z3.UDiv(A, bv(1)) == A,
        role="actual bvudiv semantics, full32 arbitrary input",
    )
    query(
        "unsigned_remainder_by_one",
        [],
        z3.URem(A, bv(1)) == bv(0),
        role="actual bvurem semantics, full32 arbitrary input",
    )
    unit = [
        UQ(bv(2147483648), bv(1)) == bv(2147483648),
        UR(bv(2147483648), bv(1)) == bv(0),
    ]

    def expressions(op):
        signed = op in (4, 6)
        na = z3.And(z3.BoolVal(signed), z3.Extract(31, 31, A) == bv(1, 1))
        nb = z3.And(z3.BoolVal(signed), z3.Extract(31, 31, C) == bv(1, 1))
        ma = z3.If(na, -A, A)
        mb = z3.If(nb, -C, C)
        q = z3.If(mb == bv(0), bv(0), UQ(ma, mb))
        r = z3.If(mb == bv(0), bv(0), UR(ma, mb))
        cq = z3.If(z3.Xor(na, nb), -q, q)
        cr = z3.If(na, -r, r)
        d0 = A if op in (6, 7) else bv(4294967295)
        actual = z3.If(C == bv(0), d0, cr if op in (6, 7) else cq)
        reference = (
            parsed["bvsrem" if op == 6 else "bvsdiv"]
            if signed
            else UR(A, C) if op == 7 else UQ(A, C)
        )
        if signed:
            reference = z3.If(
                z3.And(A == bv(2147483648), C == bv(4294967295)),
                bv(0 if op == 6 else 2147483648),
                reference,
            )
        reference = z3.If(C == bv(0), d0, reference)
        return {
            "na": na,
            "nb": nb,
            "ma": ma,
            "mb": mb,
            "q": q,
            "r": r,
            "actual": actual,
            "reference": reference,
            "d0": d0,
        }

    for op in (4, 5, 6, 7):
        e = expressions(op)
        ra = z3.If(e["na"], -z3.ZeroExt(32, e["ma"]), z3.ZeroExt(32, e["ma"]))
        rb = z3.If(e["nb"], -z3.ZeroExt(32, e["mb"]), z3.ZeroExt(32, e["mb"]))
        ia = z3.SignExt(32, A) if op in (4, 6) else z3.ZeroExt(32, A)
        ib = z3.SignExt(32, C) if op in (4, 6) else z3.ZeroExt(32, C)
        query(
            f"op{op}_zero_divisor_result",
            [],
            z3.Implies(C == bv(0), e["actual"] == e["d0"]),
        )
        for ha in (0, 1):
            for hb in (0, 1):
                tag = f"op{op}_msb{ha}{hb}"
                facts = unit + [
                    z3.Extract(31, 31, A) == bv(ha, 1),
                    z3.Extract(31, 31, C) == bv(hb, 1),
                ]
                query(tag + "_left_restore", facts, ra == ia)
                query(tag + "_right_restore", facts, rb == ib)
                query(
                    tag + "_nonzero_magnitude", facts + [C != bv(0)], e["mb"] != bv(0)
                )
                query(
                    tag + "_projection",
                    facts,
                    e["actual"] == e["reference"],
                    predecessors=(
                        "unsigned_divide_by_one",
                        "unsigned_remainder_by_one",
                        tag + "_nonzero_magnitude",
                    ),
                    role="Signed operators use the separately checked full-width definitions and unsigned unit-divisor theorems",
                )
                query(tag + "_nonvacuity", facts, z3.BoolVal(False), "sat")
        query(
            f"op{op}_zero_nonvacuity",
            unit + [A == bv(2147483648), C == bv(0)],
            z3.BoolVal(False),
            "sat",
        )
        if op in (4, 6):
            query(
                f"op{op}_overflow_nonvacuity",
                unit + [A == bv(2147483648), C == bv(4294967295)],
                z3.BoolVal(False),
                "sat",
            )
    NA, ND = z3.Ints("natural_dividend natural_divisor")
    bounds = [NA >= 0, NA < W, ND > 0, ND < W]
    nq = NA / ND
    nr = NA % ND
    query(
        "unsigned_ideal_bounds",
        bounds,
        z3.And(nq >= 0, nq < W, nr >= 0, nr < ND, nr < W),
        role="source unsigned32 quotient and remainder need no output truncation",
    )
    query(
        "unsigned_ideal_relation",
        bounds,
        ND * nq + nr == NA,
        role="standard natural unsigned quotient/remainder identity",
    )
    query(
        "unsigned_ideal_65bit_projection",
        bounds + [ND * nq + nr == NA],
        (ND * nq + nr) % 2**65 == NA,
        predecessors=("unsigned_ideal_relation", "unsigned_ideal_bounds"),
        role="exact source65 sum has no wraparound",
    )
    e = expressions(4)
    badq = z3.If(e["na"], -e["q"], e["q"])
    facts = unit + [A == bv(5), C == bv(4294967294), UQ(bv(5), bv(2)) == bv(2)]
    query("negative_quotient_sign", facts, badq == e["reference"], "sat")
    e = expressions(6)
    badr = z3.If(z3.Xor(e["na"], e["nb"]), -e["r"], e["r"])
    facts = unit + [A == bv(4294967291), C == bv(4294967294), UR(bv(5), bv(2)) == bv(1)]
    query("negative_remainder_sign", facts, badr == e["reference"], "sat")
    e = expressions(7)
    query(
        "negative_removed_zero_bypass",
        unit + [A == bv(2147483648), C == bv(0)],
        e["r"] == e["reference"],
        "sat",
    )
    query(
        "negative_bare_signed_divide_zero",
        [A == bv(4294967291), C == bv(0)],
        A / C == bv(4294967295),
        "sat",
        role="SMT signed divide by zero is not the RISC V explicit result for a negative dividend",
    )
    positive = sum(r["actual"] == "unsat" for r in rows)
    nonvac = sum(
        r["actual"] == "sat" and (not r["name"].startswith("negative_")) for r in rows
    )
    negative = sum(
        r["actual"] == "sat" and r["name"].startswith("negative_") for r in rows
    )
    if not (positive, nonvac, negative) == (73, 22, 4):
        raise ValueError("Division proof obligation failed")
    summary = {
        "positiveUnsat": sum(row["actual"] == "unsat" for row in rows),
        "nonvacuitySat": sum(
            row["actual"] == "sat" and "negative_" not in row["name"] for row in rows
        ),
        "negativeCountermodels": sum(
            row["actual"] == "sat" and "negative_" in row["name"] for row in rows
        ),
    }
    (output / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    return summary


class ResultState:

    def __init__(self, name):
        for field in (
            "reset",
            "cancel",
            "pending",
            "active",
            "history",
            "valid",
            "ready",
            "accepted",
            "zero",
        ):
            setattr(self, field, z3.Bool(name + "." + field))
        for field, width in [
            ("L", 32),
            ("right", 32),
            ("op", 3),
            ("i", 6),
            ("Q", 32),
            ("R", 33),
            ("response", 32),
            ("expected", 32),
        ]:
            setattr(self, field, z3.BitVec(name + "." + field, width))


class ResultCertificate:

    def __init__(
        self,
        operation,
        *,
        base=True,
        epoch=True,
        terminal=True,
        wrong_finish=False,
        wrong_hold=False,
    ):
        if not operation in (4, 5, 6, 7):
            raise ValueError("Division proof obligation failed")
        self.operation = operation
        c, p = self.current, self.past = (ResultState("current"), ResultState("past"))
        self.first, self.previous_reset, self.previous_owner, self.finish, self.hold = (
            z3.Bools(
                "division_first_proof_frame previous_reset division_previous_owner division_previous_finish division_previous_response_hold"
            )
        )
        self.snapshot_L, self.snapshot_right, self.snapshot_Q = z3.BitVecs(
            "division_previous_owner_left division_previous_owner_right division_previous_quotient",
            32,
        )
        self.snapshot_op = z3.BitVec("division_previous_owner_operation", 3)
        self.snapshot_R = z3.BitVec("division_previous_remainder", 33)
        self.snapshot_zero = z3.Bool("division_previous_zero_divisor")
        self.previous_response = z3.BitVec("previous_response", 32)
        self.previous_valid, self.previous_ready, self.previous_cancel = z3.Bools(
            "previous_response_valid previous_response_ready previous_cancel"
        )
        self.UQ = z3.Function(
            "unsigned_division32",
            z3.BitVecSort(32),
            z3.BitVecSort(32),
            z3.BitVecSort(32),
        )
        self.UR = z3.Function(
            "unsigned_remainder32",
            z3.BitVecSort(32),
            z3.BitVecSort(32),
            z3.BitVecSort(32),
        )

        def signs(left, right, op):
            left_signed = z3.Or(*[op == bv(k, 3) for k in (1, 2, 4, 6)])
            right_signed = z3.Or(*[op == bv(k, 3) for k in (1, 4, 6)])
            return (
                z3.And(left_signed, z3.Extract(31, 31, left) == bv(1, 1)),
                z3.And(right_signed, z3.Extract(31, 31, right) == bv(1, 1)),
            )

        def magnitudes(left, right, op):
            na, nb = signs(left, right, op)
            return (z3.If(na, -left, left), z3.If(nb, -right, right))

        self.signs, self.magnitudes = (signs, magnitudes)

        def reference(state):
            na, nb = signs(state.L, state.right, bv(operation, 3))
            ma, mb = magnitudes(state.L, state.right, bv(operation, 3))
            if operation & 2:
                value = self.UR(ma, mb)
                return z3.If(
                    state.right == bv(0, 32), state.L, z3.If(na, -value, value)
                )
            value = self.UQ(ma, mb)
            return z3.If(
                state.right == bv(0, 32),
                bv(4294967295, 32),
                z3.If(z3.Xor(na, nb), -value, value),
            )

        self.ref = reference
        self.selected = lambda state: z3.And(
            state.pending, state.op == bv(operation, 3)
        )
        self.guard = lambda state: z3.And(
            z3.Not(state.reset),
            z3.Not(state.cancel),
            state.valid,
            state.op == bv(operation, 3),
        )
        self.G, self.pG = (self.guard(c), self.guard(p))
        self.I = z3.Implies(self.G, c.response == c.expected)
        self.pI = z3.Implies(self.pG, p.response == p.expected)
        self.common = z3.And(
            c.history, z3.Not(c.reset), z3.Not(c.cancel), self.selected(c)
        )
        self.p_terminal = z3.And(
            z3.Not(p.reset),
            z3.Not(p.cancel),
            self.selected(p),
            p.active,
            p.i == bv(32, 6),
        )
        self.facts = {}
        if base:
            self.facts["native_first_frame_idle"] = z3.Implies(
                z3.And(z3.Not(c.reset), self.first), z3.Not(c.pending)
            )
        if epoch:
            self.facts["native_response_epoch"] = z3.Implies(
                self.G, z3.And(c.history, c.pending, z3.Or(self.finish, self.hold))
            )
        self.facts["source_previous_reset_capture"] = z3.Implies(
            z3.And(c.history, z3.Not(self.first)), self.previous_reset == p.reset
        )
        flags = z3.And(c.history, z3.Not(c.reset))
        self.facts["native_finish_flag_actual_past"] = z3.Implies(
            flags,
            self.finish
            == z3.And(
                z3.Not(self.previous_reset),
                z3.Not(p.cancel),
                self.selected(p),
                p.active,
                p.i == bv(32, 6),
            ),
        )
        self.facts["native_owner_flag_actual_past"] = z3.Implies(
            flags,
            self.previous_owner
            == z3.And(z3.Not(self.previous_reset), z3.Not(p.cancel), self.selected(p)),
        )
        self.facts["native_hold_flag_actual_past"] = z3.Implies(
            flags,
            self.hold
            == z3.And(
                z3.Not(self.previous_reset),
                z3.Not(p.cancel),
                self.selected(p),
                p.valid,
                z3.Not(p.ready),
            ),
        )
        snapshot = z3.And(
            c.history, z3.Not(c.reset), z3.Not(self.previous_reset), self.previous_owner
        )
        self.facts["native_snapshot_left"] = z3.Implies(
            snapshot, self.snapshot_L == p.L
        )
        self.facts["native_snapshot_right"] = z3.Implies(
            snapshot, self.snapshot_right == p.right
        )
        self.facts["native_snapshot_operation"] = z3.Implies(
            snapshot, self.snapshot_op == p.op
        )
        self.facts["native_snapshot_remainder"] = z3.Implies(
            snapshot, self.snapshot_R == p.R
        )
        self.facts["native_snapshot_quotient"] = z3.Implies(
            snapshot, self.snapshot_Q == p.Q
        )
        self.facts["native_snapshot_zero_divisor"] = z3.Implies(
            snapshot, self.snapshot_zero == p.zero
        )
        self.facts["native_owner_words_stable"] = z3.Implies(
            z3.And(self.common, self.previous_owner),
            z3.And(
                c.L == self.snapshot_L,
                c.right == self.snapshot_right,
                c.op == self.snapshot_op,
            ),
        )
        self.facts["native_past_owner_history"] = z3.Implies(
            z3.And(z3.Not(p.reset), z3.Not(p.cancel), self.selected(p)), p.history
        )
        pma, pmb = magnitudes(p.L, p.right, p.op)
        if terminal:
            self.facts["proved_past_terminal_quotient"] = z3.Implies(
                z3.And(p.history, self.p_terminal, pmb != bv(0, 32)),
                p.Q == self.UQ(pma, pmb),
            )
            self.facts["proved_past_terminal_remainder"] = z3.Implies(
                z3.And(p.history, self.p_terminal, pmb != bv(0, 32)),
                z3.Extract(31, 0, p.R) == self.UR(pma, pmb),
            )
        self.facts["native_past_zero_divisor"] = z3.Implies(
            z3.And(z3.Not(p.reset), z3.Not(p.cancel), p.pending),
            p.zero == (p.right == bv(0, 32)),
        )
        sna, snb = signs(self.snapshot_L, self.snapshot_right, self.snapshot_op)
        if operation & 2:
            sr = z3.Extract(31, 0, self.snapshot_R)
            finish_value = z3.If(
                self.snapshot_zero, self.snapshot_L, z3.If(sna, -sr, sr)
            )
        else:
            finish_value = z3.If(
                self.snapshot_zero,
                bv(4294967295, 32),
                z3.If(z3.Xor(sna, snb), -self.snapshot_Q, self.snapshot_Q),
            )
        self.facts["native_finish_value"] = z3.Implies(
            z3.And(self.common, self.finish),
            c.response == finish_value ^ bv(int(wrong_finish), 32),
        )
        self.facts["proved_checker_capture"] = z3.Implies(
            z3.And(z3.Not(c.reset), c.pending), c.expected == self.ref(c)
        )
        history = z3.And(c.history, z3.Not(c.reset), z3.Not(self.previous_reset))
        self.facts["native_response_word_actual_past"] = z3.Implies(
            history, self.previous_response == p.response
        )
        self.facts["native_valid_actual_past"] = z3.Implies(
            history, self.previous_valid == p.valid
        )
        self.facts["native_ready_actual_past"] = z3.Implies(
            history, self.previous_ready == p.ready
        )
        self.facts["native_cancel_actual_past"] = z3.Implies(
            history, self.previous_cancel == p.cancel
        )
        blocked = z3.And(
            z3.Not(c.reset),
            z3.Not(c.cancel),
            c.history,
            z3.Not(self.previous_reset),
            z3.Not(self.previous_cancel),
            self.previous_valid,
            z3.Not(self.previous_ready),
        )
        self.facts["native_blocked_response_keeps_value"] = z3.Implies(
            blocked, c.response == self.previous_response
        )
        self.facts["native_hold_precludes_past_accept"] = z3.Implies(
            z3.And(self.common, self.hold), z3.Not(p.accepted)
        )
        self.facts["native_expected_without_accept_holds"] = z3.Implies(
            z3.And(history, z3.Not(p.accepted)),
            c.expected == p.expected ^ bv(int(wrong_hold), 32),
        )


def _prove_result(output, operation):
    output.mkdir(parents=True, exist_ok=False)
    rows = []

    def query(name, certificate, extras, expected, role):
        solver = z3.SolverFor("QF_UFBV")
        solver.set(timeout=15000)
        solver.add(*certificate.facts.values(), *extras)
        (output / (name + ".smt2")).write_text(solver.to_smt2())
        start = time.monotonic()
        status = solver.check()
        row = {
            "name": name,
            "expected": expected,
            "actual": str(status),
            "role": role,
            "seconds": round(time.monotonic() - start, 6),
            "premises": list(certificate.facts),
        }
        if status == z3.sat:
            model = solver.model()
            (output / (name + ".model.txt")).write_text(str(model) + "\n")
            fields = [
                *vars(certificate.current).values(),
                *vars(certificate.past).values(),
                certificate.first,
                certificate.previous_reset,
                certificate.previous_owner,
                certificate.finish,
                certificate.hold,
                certificate.snapshot_zero,
            ]
            values = {
                str(field): str(model.eval(field, model_completion=True))
                for field in fields
            }
            values.update(
                currentPredicate=str(model.eval(certificate.I, model_completion=True)),
                pastPredicate=str(model.eval(certificate.pI, model_completion=True)),
            )
            (output / (name + ".values.json")).write_text(
                json.dumps(values, indent=2) + "\n"
            )
        rows.append(row)
        (output / "queries.json").write_text(json.dumps(rows, indent=2) + "\n")
        if not str(status) == expected:
            raise ValueError("Division proof obligation failed")

    c = ResultCertificate(operation)
    step = z3.Not(c.first)
    query(
        "base_first_frame",
        c,
        [c.first, z3.Not(c.I)],
        "unsat",
        "Idle first frame and native response epoch exclude the original response guard",
    )
    query(
        "reset_guard",
        c,
        [c.current.reset, z3.Not(c.I)],
        "unsat",
        "The original result predicate is inactive during reset",
    )
    query(
        "finish_actual_past_terminal",
        c,
        [step, c.G, c.finish, z3.Not(c.p_terminal)],
        "unsat",
        "The actual finish flag and reset capture supply the full preceding terminal guard",
    )
    query(
        "finish_current_owner_equals_actual_past",
        c,
        [
            step,
            c.G,
            c.finish,
            z3.Or(
                c.current.L != c.past.L,
                c.current.right != c.past.right,
                c.current.op != c.past.op,
            ),
        ],
        "unsat",
        "Native guarded snapshots and owner stability preserve both full 32-bit source arguments",
    )
    query(
        "finish_nonzero_reference",
        c,
        [
            step,
            c.G,
            c.finish,
            c.current.right != bv(0, 32),
            c.current.response != c.ref(c.current),
        ],
        "unsat",
        "A nonzero finish uses the proved Euclidean quotient with the same owner words",
    )
    query(
        "finish_zero_reference",
        c,
        [
            step,
            c.G,
            c.finish,
            c.current.right == bv(0, 32),
            c.current.response != c.ref(c.current),
        ],
        "unsat",
        "A zero divisor selects the actual standard zero-divisor response",
    )
    query(
        "finish_result_without_hypothesis",
        c,
        [step, c.G, c.finish, z3.Not(c.I)],
        "unsat",
        "Fresh completion uses the independent checker capture theorem without a previous result hypothesis",
    )
    query(
        "hold_actual_past_guard",
        c,
        [step, c.G, c.hold, z3.Not(c.pG)],
        "unsat",
        "The actual hold flag supplies the complete preceding result guard",
    )
    query(
        "hold_actual_past_words",
        c,
        [
            step,
            c.G,
            c.hold,
            z3.Or(
                c.current.response != c.past.response,
                c.current.expected != c.past.expected,
            ),
        ],
        "unsat",
        "Actual response metadata and no-acceptance capture preserve both compared words",
    )
    query(
        "hold_result_with_local_hypothesis",
        c,
        [step, c.G, c.hold, c.pI, z3.Not(c.I)],
        "unsat",
        "Held completion uses the complete original predicate only at the actual preceding frame",
    )
    query(
        "all_step_cases",
        c,
        [step, c.pI, z3.Not(c.I)],
        "unsat",
        "The actual response epoch makes finish and hold exhaustive",
    )
    previous_I = z3.Bool("boolean_observer.previous_I")
    monitor = z3.Implies(
        z3.And(c.current.history, step), previous_I == z3.Or(c.past.reset, c.pI)
    )
    query(
        "boolean_monitor_step_substitution",
        c,
        [step, previous_I, monitor, z3.Not(c.I)],
        "unsat",
        "A pure previous-I observer discharges the second native Boolean induction rule premise",
    )
    query(
        "base_nonvacuity",
        c,
        [c.first, z3.Not(c.current.reset)],
        "sat",
        "The first non-reset frame remains feasible",
    )
    query(
        "finish_nonzero_nonvacuity",
        c,
        [
            step,
            c.G,
            c.finish,
            c.current.L == bv(2147483648, 32),
            c.current.right == bv(2147483648, 32),
            c.current.response == bv(0 if operation & 2 else 1, 32),
        ],
        "sat",
        "Both high operand bits remain feasible with the correct nonzero magnitude result",
    )
    query(
        "finish_zero_nonvacuity",
        c,
        [
            step,
            c.G,
            c.finish,
            c.current.L == bv(4294967295, 32),
            c.current.right == bv(0, 32),
        ],
        "sat",
        "The final proof retains zero divisors",
    )
    query(
        "hold_nonvacuity",
        c,
        [
            step,
            c.G,
            c.hold,
            c.pI,
            c.current.L == bv(2147483648, 32),
            c.current.right == bv(2147483648, 32),
        ],
        "sat",
        "Held completion retains both high operand bits",
    )
    for name, options, branch in [
        ("negative_missing_base", {"base": False}, "base"),
        ("negative_missing_response_epoch", {"epoch": False}, "step"),
        ("negative_missing_terminal_reference", {"terminal": False}, "finish"),
        ("negative_wrong_finish_bit", {"wrong_finish": True}, "finish"),
        ("negative_wrong_held_expected", {"wrong_hold": True}, "hold"),
    ]:
        bad = ResultCertificate(operation, **options)
        extra = [z3.Not(bad.I)]
        if branch == "base":
            extra += [bad.first, z3.Not(bad.current.reset)]
        else:
            extra += [z3.Not(bad.first), bad.pI]
            if branch in ("finish", "hold"):
                extra += [bad.G, bad.finish if branch == "finish" else bad.hold]
        query(
            name,
            bad,
            extra,
            "sat",
            "A missing or corrupted required premise gives a countermodel",
        )
    summary = {
        "positiveUnsat": sum(row["actual"] == "unsat" for row in rows),
        "nonvacuitySat": sum(
            row["actual"] == "sat" and "negative_" not in row["name"] for row in rows
        ),
        "negativeCountermodels": sum(
            row["actual"] == "sat" and "negative_" in row["name"] for row in rows
        ),
    }
    (output / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    return summary


def _prove_projection(output):
    output.mkdir(parents=True, exist_ok=False)
    rows = []
    for operation in (4, 5, 6, 7):
        c = ResultCertificate(operation)
        state = c.current
        signed = operation in (4, 6)
        na = z3.And(z3.BoolVal(signed), z3.Extract(31, 31, state.L) == bv(1, 1))
        nb = z3.And(z3.BoolVal(signed), z3.Extract(31, 31, state.right) == bv(1, 1))
        ma, mb = (z3.If(na, -state.L, state.L), z3.If(nb, -state.right, state.right))
        q = z3.If(mb == bv(0, 32), bv(0, 32), c.UQ(ma, mb))
        r = z3.If(mb == bv(0, 32), bv(0, 32), c.UR(ma, mb))
        corrected = z3.If(na, -r, r) if operation & 2 else z3.If(z3.Xor(na, nb), -q, q)
        zero_result = state.L if operation & 2 else bv(4294967295, 32)
        projected = z3.If(state.right == bv(0, 32), zero_result, corrected)
        actual_ma, actual_mb = c.magnitudes(state.L, state.right, state.op)
        comparisons = [
            (
                "raw_zero_iff_magnitude_zero",
                [],
                (state.right == bv(0, 32)) == (mb == bv(0, 32)),
                "unsat",
            ),
            (
                "same_normalized_reference",
                [(state.right == bv(0, 32)) == (mb == bv(0, 32))],
                c.ref(state) == projected,
                "unsat",
            ),
            (
                "selected_actual_operation_magnitudes",
                [state.op == bv(operation, 3)],
                z3.And(actual_ma == ma, actual_mb == mb),
                "unsat",
            ),
            (
                "projection_nonempty_high_bits",
                [state.L == bv(2147483648, 32), state.right == bv(2147483648, 32)],
                z3.BoolVal(False),
                "sat",
            ),
            (
                "negative_missing_actual_operation_selection",
                [],
                z3.And(actual_ma == ma, actual_mb == mb),
                "sat",
            ),
        ]
        for name, facts, goal, expected in comparisons:
            name = "op" + str(operation) + "_" + name
            solver = z3.SolverFor("QF_UFBV")
            solver.set(timeout=15000)
            solver.add(
                *[z3.simplify(fact) for fact in facts], z3.simplify(z3.Not(goal))
            )
            (output / (name + ".smt2")).write_text(solver.to_smt2())
            result = solver.check()
            if not str(result) == expected:
                raise ValueError("Division proof obligation failed")
            row = {
                "name": name,
                "expected": expected,
                "actual": str(result),
                "operation": operation,
                "provedPredecessors": (
                    ["op" + str(operation) + "_raw_zero_iff_magnitude_zero"]
                    if name.endswith("same_normalized_reference")
                    else []
                ),
            }
            if result == z3.sat:
                model = solver.model()
                values = {
                    str(v): model.eval(v, model_completion=True).as_long()
                    for v in (state.L, state.right, state.op)
                }
                (output / (name + ".values.json")).write_text(
                    json.dumps(values, indent=2) + "\n"
                )
            rows.append(row)
    (output / "queries.json").write_text(json.dumps(rows, indent=2) + "\n")
    summary = {
        "positiveUnsat": sum(row["actual"] == "unsat" for row in rows),
        "nonvacuitySat": sum(
            row["actual"] == "sat" and "negative_" not in row["name"] for row in rows
        ),
        "negativeCountermodels": sum(
            row["actual"] == "sat" and "negative_" in row["name"] for row in rows
        ),
    }
    (output / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    return summary


NATIVE_ROLES = {
    "sums": (
        "division_previous_remainder_fits",
        "division_previous_partial_fits",
        "division_no_subtract.exact_polynomial_transition",
        "division_subtract.exact_polynomial_transition",
        "division_actual_remainder_step",
        "division_actual_divisor_stable",
        "division_mask_step",
    ),
    "conservation": (
        "division_epoch_active_has_predecessor",
        "division_initial_frame_is_idle",
        "division_initial_conservation",
        "division_prefix_step",
        "division_snapshot_step_flag",
        "division_snapshot_owner_flag",
        "division_snapshot_remainder",
        "division_snapshot_divisor",
        "division_snapshot_quotient",
        "division_snapshot_iteration",
        "division_snapshot_owner_left",
        "division_snapshot_owner_right",
        "division_snapshot_owner_operation",
        "division_snapshot_zero_divisor",
    ),
    "terminal": (
        "division_history_for_owner",
        "division_terminal_fields",
        "owner_divisor",
        "remainder_below_divisor",
        "owner_zero_divisor",
    ),
    "capture": (
        "division_initial_frame_is_idle",
        "pending_capture_or_hold_predecessor",
        "captured_expected_from_request",
        "captured_owner_left_from_request",
        "captured_owner_right_from_request",
        "expected_without_accept_holds",
        "owner_left_without_accept_holds",
        "owner_right_without_accept_holds",
    ),
    "result": (
        "division_initial_frame_is_idle",
        "division_response_epoch_has_predecessor",
        "division_snapshot_finish_flag",
        "division_snapshot_owner_flag",
        "division_snapshot_response_hold",
        "division_snapshot_owner_left",
        "division_snapshot_owner_right",
        "division_snapshot_owner_operation",
        "division_snapshot_remainder",
        "division_snapshot_quotient",
        "division_snapshot_zero_divisor",
        "division_owner_words_stable",
        "division_history_for_owner",
        "owner_zero_divisor",
        "division_actual_finish_value",
        "division_snapshot_previous_response",
        "division_snapshot_previous_response_valid",
        "division_snapshot_previous_response_ready",
        "division_snapshot_previous_cancel",
        "blocked_result_keeps_value",
        "division_response_hold_precludes_accept",
        "expected_without_accept_holds",
    ),
}


def _json_value(value):
    return json.loads(json.dumps(value, sort_keys=True))


def _typed_substitutions(operation):
    c = ConservationCertificate(operation)

    def sum_word(r, d, q, i):
        remaining = bv(32, 6) - i
        partial = q & z3.LShR(bv(0xFFFFFFFF), z3.ZeroExt(26, remaining))
        return z3.ZeroExt(32, r) + z3.ZeroExt(33, d) * z3.ZeroExt(33, partial)

    def prefix_word(left, op, i):
        signed = z3.Or(*[op == bv(n, 3) for n in (1, 2, 4, 6)])
        negative = z3.And(signed, z3.Extract(31, 31, left) == bv(1, 1))
        magnitude = z3.If(negative, -left, left)
        return z3.ZeroExt(33, z3.LShR(magnitude, z3.ZeroExt(26, bv(32, 6) - i)))

    sum_body = sum_word(
        *[
            z3.Var(i, sort)
            for i, sort in enumerate(
                (
                    z3.BitVecSort(33),
                    z3.BitVecSort(32),
                    z3.BitVecSort(32),
                    z3.BitVecSort(6),
                )
            )
        ]
    )
    prefix_body = prefix_word(
        *[
            z3.Var(i, sort)
            for i, sort in enumerate(
                (z3.BitVecSort(32), z3.BitVecSort(3), z3.BitVecSort(6))
            )
        ]
    )
    actual = z3.substitute_funs(c.I, (c.S, sum_body), (c.P, prefix_body))
    state = c.current
    expected = z3.Implies(
        c.G,
        sum_word(state.R, state.D, state.Q, state.i)
        == prefix_word(state.L, state.op, state.i),
    )
    if not z3.eq(actual, expected):
        raise ValueError("Division conservation substitution is not capture free")
    terminal = TerminalCertificate(operation)
    r, d, q = (
        z3.Var(i, sort)
        for i, sort in enumerate(
            (z3.BitVecSort(33), z3.BitVecSort(32), z3.BitVecSort(32))
        )
    )
    terminal_body = z3.ZeroExt(32, r) + z3.ZeroExt(33, d) * z3.ZeroExt(33, q)
    terminal_actual = z3.substitute_funs(
        terminal.F(terminal.R, terminal.D, terminal.Q), (terminal.F, terminal_body)
    )
    terminal_expected = z3.ZeroExt(32, terminal.R) + z3.ZeroExt(
        33, terminal.D
    ) * z3.ZeroExt(33, terminal.Q)
    if not z3.eq(terminal_actual, terminal_expected):
        raise ValueError("Division terminal substitution is not capture free")
    result = ResultCertificate(operation)
    left, right = z3.Var(0, z3.BitVecSort(32)), z3.Var(1, z3.BitVecSort(32))
    result_actual = z3.substitute_funs(
        result.ref(result.current),
        (result.UQ, z3.UDiv(left, right)),
        (result.UR, z3.URem(left, right)),
    )
    na, nb = result.signs(result.current.L, result.current.right, bv(operation, 3))
    ma, mb = result.magnitudes(result.current.L, result.current.right, bv(operation, 3))
    corrected = (
        z3.If(na, -z3.URem(ma, mb), z3.URem(ma, mb))
        if operation & 2
        else z3.If(z3.Xor(na, nb), -z3.UDiv(ma, mb), z3.UDiv(ma, mb))
    )
    zero_result = result.current.L if operation & 2 else bv(0xFFFFFFFF)
    result_expected = z3.If(result.current.right == bv(0), zero_result, corrected)
    if not z3.eq(result_actual, result_expected):
        raise ValueError(
            "Division result substitution changes unsigned operator arguments"
        )
    return {
        "conservation": actual.sexpr(),
        "terminalSum": terminal_actual.sexpr(),
        "normalizedReference": result_actual.sexpr(),
        "functionArguments": {
            "sum65": [33, 32, 32, 6],
            "prefix65": [32, 3, 6],
            "terminalSum65": [33, 32, 32],
            "quotient32": [32, 32],
            "remainder32": [32, 32],
        },
        "captureFree": True,
    }


def _check_evidence(contract, native_facts):
    operation = contract.get("operation")
    required = division_contracts.required_native_labels(operation)
    if len(required) != 70 or len(set(required)) != 70:
        raise ValueError("Division native theorem inventory changed")
    text = source.bench(operation)
    expected_contracts = {
        name: {
            "kind": kind,
            "clock": division_contracts.syntax.tokens("posedge clock"),
            "body": division_contracts.syntax.tokens(body),
            "guards": [
                {"tokens": division_contracts.syntax.tokens(g), "positive": p}
                for g, p in guards
            ],
        }
        for name, (kind, guards, body) in division_contracts.CONTRACTS.items()
    }
    expected_scaffold = {
        "declarations": division_contracts.DECLARATIONS,
        "instances": division_contracts.INSTANCES,
        "drivers": division_contracts.DRIVERS,
    }
    if (
        _json_value(contract.get("contracts")) != _json_value(expected_contracts)
        or _json_value(contract.get("definitions")) != _json_value(expected_scaffold)
        or _json_value(contract.get("ports"))
        != _json_value(division_contracts.RTL_PORTS)
        or contract.get("assumptions") != list(formal_facts.ASSUMPTIONS)
        or contract.get("sourceSha256") != source.digest(text.encode())
        or contract.get("referenceFunctionSha256") != source.REFERENCE_HASH
        or contract.get("operandBitsEach") != 32
        or contract.get("actualOperationBits") != 3
        or contract.get("guard")
        != "!reset && !cancel && response_valid && owner_op == OPERATION"
        or contract.get("requiredNativeLabels") != list(required)
    ):
        raise ValueError("Division source binding is incomplete")
    if contract.get("transitionSha256") != source.digest(
        Path(division_contracts.__file__).with_name("divide_step.sv").read_bytes()
    ):
        raise ValueError("Division transition source changed after binding")
    labels = native_facts.get("provenLabels", ())
    if (
        len(labels) != len(set(labels))
        or set(labels) != set(required)
        or native_facts.get("operation") != operation
        or native_facts.get("fullWidth") is not True
        or native_facts.get("originalGuard") is not True
        or set(native_facts.get("assumptions", ())) != set(formal_facts.ASSUMPTIONS)
        or len(native_facts.get("assumptions", ())) != 5
        or native_facts.get("collectedSourceSha256") != contract["sourceSha256"]
        or native_facts.get("collectedDutSha256") != contract.get("dutSha256")
        or re.fullmatch(r"[0-9a-f]{64}", contract.get("dutSha256", "")) is None
    ):
        raise ValueError(
            "Division native facts do not match the bound source and configuration"
        )
    covers = native_facts.get("covers", {})
    if set(covers) != set(formal_facts.covers(operation)):
        raise ValueError("Division native coverage is incomplete")
    for record in covers.values():
        if (
            record.get("replayed") is not True
            or type(record.get("samples")) is not int
            or record["samples"] < 1
            or not record.get("hits")
            or any(
                type(hit) is not int or not 0 <= hit < record["samples"]
                for hit in record["hits"]
            )
            or re.fullmatch(r"[0-9a-f]{64}", record.get("sha256", "")) is None
        ):
            raise ValueError("Division cover has no checked native witness")
    if native_facts.get("booleanInductionRule", {}).get("accepted") is not True:
        raise ValueError("Division induction needs the checked native Boolean rule")
    return operation


def _check_scalar_models(output):
    for row in json.loads((output / "integer" / "queries.json").read_text()):
        if row["actual"] != "sat":
            continue
        values = row["countermodel"]
        a, d, q, r = (values[name] for name in ("A", "D", "Q", "R"))
        if not (
            0 <= a < 2**32 and 0 <= d < 2**32 and 0 <= q < 2**32 and 0 <= r < 2**33
        ):
            raise ValueError("Integer division witness exceeds the source widths")
        name = row["name"]
        if name == "negative_32_bit_product":
            valid = d > 0 and r < d and a == (d * q + r) % 2**32 and q != a // d
        elif name == "negative_missing_remainder_bound":
            valid = d > 0 and a == d * q + r and q != a // d
        else:
            valid = d > 0 and r < d and a == d * q + r
            if name == "negative_wrong_quotient":
                valid = valid and q != a // d + 1
            if name == "negative_wrong_remainder":
                valid = valid and r != a % d + 1
        if not valid:
            raise ValueError("Integer division witness failed independent replay")


def prove_division(contract, native_facts, *, output_dir=None):
    operation = _check_evidence(contract, native_facts)
    output = (
        Path(output_dir)
        if output_dir is not None
        else Path(tempfile.mkdtemp(prefix="division-rules-"))
    )
    if output.exists():
        if any(output.iterdir()):
            raise ValueError("Division rule output must be empty")
    else:
        output.mkdir(parents=True)
    substitutions = _typed_substitutions(operation)
    (output / "typed-substitutions.json").write_text(
        json.dumps(substitutions, indent=2, sort_keys=True) + "\n"
    )
    stages = {}
    plan = (
        ("sums", (), lambda path: _prove_sums(path)),
        ("conservation", ("sums",), lambda path: _prove_conservation(path, operation)),
        ("integer", (), lambda path: _prove_unique(path)),
        (
            "terminal",
            ("conservation", "integer"),
            lambda path: _prove_terminal(path, operation),
        ),
        ("operators", (), lambda path: _prove_builtin_definitions(path)),
        ("normalization", ("operators",), lambda path: _prove_normalization(path)),
        ("projection", ("normalization",), lambda path: _prove_projection(path)),
        ("capture", (), lambda path: capture_rules.prove(path)),
        (
            "result",
            ("terminal", "projection", "capture"),
            lambda path: _prove_result(path, operation),
        ),
    )
    rows = []
    for name, dependencies, execute in plan:
        if set(dependencies) - set(stages):
            raise ValueError("Division composition has an unproved predecessor")
        result = execute(output / name)
        queries = json.loads((output / name / "queries.json").read_text())
        if any(row["actual"] != row["expected"] for row in queries):
            raise ValueError("Division rule has no matching solver verdict")
        stages[name] = {
            "dependencies": list(dependencies),
            "nativePremises": list(NATIVE_ROLES.get(name, ())),
            "queries": len(queries),
            "accepted": True,
        }
        if result is not None:
            stages[name]["details"] = result
        for row in queries:
            rows.append({"stage": name, **row})
    _check_scalar_models(output)
    report = {
        "operation": operation,
        "sourceSha256": contract["sourceSha256"],
        "dutSha256": contract["dutSha256"],
        "solver": z3.get_version_string(),
        "stages": stages,
        "queries": len(rows),
        "positiveUnsat": sum(row["actual"] == "unsat" for row in rows),
        "satisfiableChecks": sum(row["actual"] == "sat" for row in rows),
        "nativePremises": len(native_facts["provenLabels"]),
        "originalGuard": contract["guard"],
        "operandBitsEach": 32,
        "actualRequestOperationBits": 3,
        "resetScope": "initial_reset_only",
        "zeroDivisorExcluded": False,
        "newInputAssumptions": 0,
        "booleanInductionRuleAccepted": True,
        "originalArithmeticCompositionalProven": True,
        "nativeDirectArithmeticStatus": "not_run",
        "fullCoreMProven": False,
    }
    (output / "composition.json").write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n"
    )
    return report
