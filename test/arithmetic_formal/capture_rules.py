# SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
# SPDX-License-Identifier: MIT
"""Prove reference capture by induction for an arbitrary pure result function."""

import json
import time
import z3


class Certificate:

    def __init__(self, *, epoch=True, base=True, wrong_capture=False, wrong_hold=False):
        self.reset, self.pending = z3.Bools("reset pending")
        self.past_reset, self.past_pending, self.past_accepted = z3.Bools(
            "past.reset past.pending past.accepted"
        )
        self.first, self.history, self.previous_reset = z3.Bools(
            "first_proof_frame history_valid previous_reset"
        )
        self.E, self.L, self.R = z3.BitVecs("expected owner_left owner_right", 32)
        self.pE, self.pL, self.pR = z3.BitVecs("past.expected past.owner_left past.owner_right", 32)
        self.reqL, self.reqR = z3.BitVecs("past.request_left past.request_right", 32)
        self.F = z3.Function("reference", z3.BitVecSort(32), z3.BitVecSort(32), z3.BitVecSort(32))
        self.G = z3.And(z3.Not(self.reset), self.pending)
        self.pG = z3.And(z3.Not(self.past_reset), self.past_pending)
        self.I = z3.Implies(self.G, self.E == self.F(self.L, self.R))
        self.pI = z3.Implies(self.pG, self.pE == self.F(self.pL, self.pR))
        self.guard = z3.And(self.history, z3.Not(self.reset), z3.Not(self.previous_reset))
        self.facts = {}
        self.facts["source_previous_reset_capture"] = z3.Implies(
            z3.And(self.history, z3.Not(self.first)), self.previous_reset == self.past_reset
        )
        if epoch:
            self.facts["pending_predecessor"] = z3.Implies(
                self.G,
                z3.And(
                    self.history,
                    z3.Not(self.previous_reset),
                    z3.Or(self.past_accepted, self.past_pending),
                ),
            )
        capture = z3.And(self.guard, self.past_accepted)
        hold = z3.And(self.guard, z3.Not(self.past_accepted))
        self.facts["capture_expected"] = z3.Implies(capture, self.E == self.F(self.reqL, self.reqR))
        self.facts["capture_left"] = z3.Implies(
            capture, self.L == self.reqL ^ z3.BitVecVal(1 if wrong_capture else 0, 32)
        )
        self.facts["capture_right"] = z3.Implies(capture, self.R == self.reqR)
        self.facts["hold_expected"] = z3.Implies(
            hold, self.E == self.pE ^ z3.BitVecVal(1 if wrong_hold else 0, 32)
        )
        self.facts["hold_left"] = z3.Implies(hold, self.L == self.pL)
        self.facts["hold_right"] = z3.Implies(hold, self.R == self.pR)
        if base:
            self.facts["initial_idle"] = z3.Implies(
                z3.And(z3.Not(self.reset), self.first), z3.Not(self.pending)
            )


def prove(output):
    output.mkdir(parents=True, exist_ok=False)
    rows = []

    def query(name, cert, extras, expected, role):
        solver = z3.SolverFor("QF_UFBV")
        solver.set(timeout=15000)
        for label, fact in cert.facts.items():
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
            "role": role,
            "elapsedSeconds": round(time.monotonic() - start, 6),
            "premises": list(cert.facts),
        }
        if result == z3.sat:
            model = solver.model()
            (output / (name + ".model.txt")).write_text(str(model) + "\n")
            values = {
                str(value): str(model.eval(value, model_completion=True))
                for value in (
                    cert.reset,
                    cert.pending,
                    cert.past_reset,
                    cert.past_pending,
                    cert.past_accepted,
                    cert.first,
                    cert.history,
                    cert.previous_reset,
                    cert.E,
                    cert.L,
                    cert.R,
                    cert.pE,
                    cert.pL,
                    cert.pR,
                    cert.reqL,
                    cert.reqR,
                )
            }
            values["currentPredicate"] = str(model.eval(cert.I, model_completion=True))
            values["pastPredicate"] = str(model.eval(cert.pI, model_completion=True))
            values["currentReference"] = str(
                model.eval(cert.F(cert.L, cert.R), model_completion=True)
            )
            (output / (name + ".values.json")).write_text(json.dumps(values, indent=2) + "\n")
        rows.append(row)
        (output / "queries.json").write_text(json.dumps(rows, indent=2) + "\n")
        if not str(result) == expected:
            raise ValueError(name)

    c = Certificate()
    query(
        "base_first_frame",
        c,
        [c.first, z3.Not(c.I)],
        "unsat",
        "Native first-frame pending is false",
    )
    query(
        "reset_guard",
        c,
        [c.reset, z3.Not(c.I)],
        "unsat",
        "The original guard is inactive during reset",
    )
    query(
        "capture_step",
        c,
        [z3.Not(c.first), c.G, c.past_accepted, z3.Not(c.I)],
        "unsat",
        "Captured function result and both owner words have the same actual request arguments",
    )
    query(
        "hold_epoch_has_past_guard",
        c,
        [z3.Not(c.first), c.G, z3.Not(c.past_accepted), z3.Not(c.pG)],
        "unsat",
        "A live pending owner without a preceding acceptance has a live preceding owner",
    )
    query(
        "hold_step",
        c,
        [z3.Not(c.first), c.G, z3.Not(c.past_accepted), c.pI, z3.Not(c.I)],
        "unsat",
        "All three held words and the local previous-frame hypothesis preserve the function result",
    )
    query(
        "all_step_cases",
        c,
        [z3.Not(c.first), c.pI, z3.Not(c.I)],
        "unsat",
        "Acceptance and hold cases are exhaustive",
    )
    previous_I = z3.Bool("boolean_observer.previous_I")
    monitor = z3.Implies(
        z3.And(c.history, z3.Not(c.first)), previous_I == z3.Or(c.past_reset, c.pI)
    )
    query(
        "boolean_monitor_step_substitution",
        c,
        [z3.Not(c.first), previous_I, monitor, z3.Not(c.I)],
        "unsat",
        "A pure previous-I observer discharges the sampled induction step",
    )
    query(
        "base_nonvacuity", c, [c.first, z3.Not(c.reset)], "sat", "The first non-reset frame exists"
    )
    query(
        "capture_nonvacuity",
        c,
        [
            z3.Not(c.first),
            c.G,
            c.past_accepted,
            z3.Extract(31, 31, c.L) == 1,
            z3.Extract(31, 31, c.R) == 1,
        ],
        "sat",
        "Both captured operand high bits may be set",
    )
    query(
        "hold_nonvacuity",
        c,
        [
            z3.Not(c.first),
            c.G,
            z3.Not(c.past_accepted),
            c.pI,
            z3.Extract(31, 31, c.L) == 1,
            z3.Extract(31, 31, c.R) == 1,
        ],
        "sat",
        "A held owner may have both operand high bits set",
    )
    no_epoch = Certificate(epoch=False)
    query(
        "negative_missing_pending_epoch",
        no_epoch,
        [z3.Not(no_epoch.first), no_epoch.pI, z3.Not(no_epoch.I)],
        "sat",
        "Without a predecessor a live owner can have an unrelated expected value",
    )
    no_base = Certificate(base=False)
    query(
        "negative_missing_base",
        no_base,
        [no_base.first, z3.Not(no_base.reset), z3.Not(no_base.I)],
        "sat",
        "A First frame is not implied by the step",
    )
    bad_capture = Certificate(wrong_capture=True)
    query(
        "negative_wrong_captured_owner",
        bad_capture,
        [
            z3.Not(bad_capture.first),
            bad_capture.G,
            bad_capture.past_accepted,
            z3.Not(bad_capture.I),
        ],
        "sat",
        "A one-bit owner capture error breaks pure-function substitution",
    )
    bad_hold = Certificate(wrong_hold=True)
    query(
        "negative_wrong_held_expected",
        bad_hold,
        [
            z3.Not(bad_hold.first),
            bad_hold.G,
            z3.Not(bad_hold.past_accepted),
            bad_hold.pI,
            z3.Not(bad_hold.I),
        ],
        "sat",
        "A one-bit held-result error breaks the invariant",
    )
    summary = {
        "schema": "ditdah-e2.reference-capture-uf-rules.v1",
        "copyright": "2026 Huang Rui <vowstar@gmail.com>",
        "license": "MIT",
        "solver": {"name": "Z3", "version": z3.get_version_string(), "logic": "QF_UFBV"},
        "functionSignature": "F(BV32,BV32) returns BV32",
        "arithmeticAxiomsAdded": 0,
        "positiveUnsat": 7,
        "nonvacuitySat": 3,
        "negativeCountermodelsSat": 4,
        "hypothesisScope": "The preceding frame inside one local step obligation",
        "sourceAssumptionsAdded": 0,
        "nativeFactsDischargedByThisScript": False,
        "checkerCaptureAccepted": False,
        "originalArithmeticTargetProven": False,
        "fullUnitMProven": False,
        "queries": rows,
    }
    (output / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    return {key: value for key, value in summary.items() if key != "queries"}
