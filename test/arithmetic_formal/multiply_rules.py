# SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
# SPDX-License-Identifier: MIT
"""Check typed congruence, conservation induction, and terminal multiplication."""

import json
import time
import z3
from . import multiply_invariant as generic

BV = z3.BitVecVal


def prove(output, operation):
    output.mkdir(parents=True, exist_ok=False)
    rows = []

    def query(op, name, facts, extras, expected, claim=None, role=""):
        solver = z3.SolverFor("QF_UFBV")
        solver.set(timeout=15000)
        solver.add(*facts.values(), *extras)
        target = output / ("op" + str(op))
        target.mkdir(exist_ok=True)
        (target / (name + ".smt2")).write_text(solver.to_smt2())
        started = time.monotonic()
        actual = solver.check()
        row = {
            "operation": op,
            "name": name,
            "expected": expected,
            "actual": str(actual),
            "premises": list(facts),
            "role": role,
            "seconds": round(time.monotonic() - started, 6),
        }
        if actual == z3.sat:
            model = solver.model()
            (target / (name + ".model.txt")).write_text(str(model) + "\n")
            if claim is not None:
                row["claimValue"] = str(model.eval(claim, model_completion=True))
        rows.append(row)
        (output / "queries.json").write_text(json.dumps(rows, indent=2) + "\n")
        if not str(actual) == expected:
            raise ValueError((name, actual))
        if name.startswith("negative_") and claim is not None:
            if not row["claimValue"] == "False":
                raise ValueError("Arithmetic proof obligation failed")

    for op in [operation]:
        c = generic.Certificate()
        s = c.snap
        P, M, Q = (c.current.P, c.current.M, c.current.Q)
        U = c.U
        F = c.total
        predP = s["P"] + z3.If(z3.Extract(0, 0, s["Q"]) == BV(1, 1), s["M"], BV(0, 64))
        predM = z3.Concat(z3.Extract(62, 0, s["M"]), BV(0, 1))
        predQ = z3.Concat(BV(0, 1), z3.Extract(31, 1, s["Q"]))
        predT = F(predP, predM, predQ)
        hold_flag = z3.Bool("chain_previous_mul_hold")
        step = z3.And(c.common, c.previous_step)
        owner = z3.And(c.common, c.previous_owner)
        initial = z3.And(c.common, c.current.active, c.current.iteration == BV(0, 6))
        hold = z3.And(c.common, hold_flag)
        op_scope = c.OP == BV(op, 3)
        current_magL = generic.Certificate.mag(c.current.left, c.current.op, True)
        current_magR = generic.Certificate.mag(c.current.right, c.current.op, False)
        snap_magL = generic.Certificate.mag(s["left"], s["op"], True)
        snap_magR = generic.Certificate.mag(s["right"], s["op"], False)
        phi = [
            (
                "actual_total_update",
                step,
                {
                    "native_step_product": z3.Implies(step, P == predP),
                    "native_step_multiplicand": z3.Implies(step, M == predM),
                    "native_step_multiplier": z3.Implies(step, Q == predQ),
                },
                c.T == predT,
                "native_step_multiplicand",
            ),
            (
                "reference_stable",
                owner,
                {
                    "native_owner_magnitudes": z3.Implies(
                        owner, z3.And(current_magL == snap_magL, current_magR == snap_magR)
                    )
                },
                c.R == c.Rsnapshot,
                "native_owner_magnitudes",
            ),
            (
                "initial_total",
                initial,
                {
                    "native_initial_state": z3.Implies(
                        initial,
                        z3.And(
                            P == BV(0, 64), M == z3.ZeroExt(32, current_magL), Q == current_magR
                        ),
                    )
                },
                c.T == c.R,
                "native_initial_state",
            ),
            (
                "blocked_total_stable",
                hold,
                {
                    "native_hold_product": z3.Implies(hold, P == s["P"]),
                    "native_hold_multiplicand": z3.Implies(hold, M == s["M"]),
                    "native_hold_multiplier": z3.Implies(hold, Q == s["Q"]),
                },
                c.T == c.Tsnapshot,
                "native_hold_multiplier",
            ),
        ]
        for name, guard, facts, claim, remove in phi:
            query(
                op,
                "phi_" + name,
                facts,
                [op_scope, guard, z3.Not(claim)],
                "unsat",
                role="Conditional function equality from exact native typed tuple premises",
            )
            query(
                op,
                "phi_" + name + "_nonvacuity",
                facts,
                [op_scope, guard],
                "sat",
                role="The full source guard is satisfiable",
            )
            query(
                op,
                "negative_phi_" + name,
                {k: v for k, v in facts.items() if k != remove},
                [op_scope, guard, z3.Not(claim)],
                "sat",
                claim,
                role="One required tuple premise is removed",
            )
        facts = {
            "composed_actual_total_update": z3.Implies(step, c.T == predT),
            "native_sampled_identity": z3.Implies(step, predT == c.Tsnapshot),
        }
        claim = c.T == c.Tsnapshot
        query(
            op,
            "total_preserved",
            facts,
            [op_scope, step, z3.Not(claim)],
            "unsat",
            role="Exact-guard equality transitivity",
        )
        query(op, "total_preserved_nonvacuity", facts, [op_scope, step], "sat")
        for missing in list(facts):
            query(
                op,
                "negative_total_without_" + missing,
                {k: v for k, v in facts.items() if k != missing},
                [op_scope, step, z3.Not(claim)],
                "sat",
                claim,
            )
        nz = z3.And(c.G, c.current.iteration != BV(0, 6), z3.Not(c.first))
        cases = [
            ("base_first_frame", [c.first, z3.Not(c.I)]),
            ("base_reset_guard", [c.current.reset, z3.Not(c.I)]),
            ("epoch_implies_actual_past_guard", [nz, z3.Not(c.Gpast)]),
            ("snapshot_total_is_actual_past_total", [nz, c.Tsnapshot != c.Tpast]),
            ("snapshot_reference_is_actual_past_reference", [nz, c.Rsnapshot != c.Rpast]),
            ("iteration_zero_base", [c.G, c.current.iteration == BV(0, 6), z3.Not(c.I)]),
            ("single_step_nonzero", [nz, c.Ipast, z3.Not(c.I)]),
            ("single_step_all_cases", [z3.Not(c.first), c.Ipast, z3.Not(c.I)]),
        ]
        for name, extras in cases:
            query(
                op,
                "conservation_" + name,
                c.facts,
                [op_scope, *extras],
                "unsat",
                role="Conservation induction for the selected operation",
            )
        previous_I = z3.Bool("boolean_monitor.previous_I")
        monitor = z3.Implies(
            z3.And(c.H, z3.Not(c.first)), previous_I == z3.Or(c.past.reset, c.Ipast)
        )
        query(
            op,
            "conservation_boolean_monitor_step_substitution",
            c.facts,
            [op_scope, z3.Not(c.first), previous_I, monitor, z3.Not(c.I)],
            "unsat",
            role="The local previous-frame hypothesis discharges the sampled induction step",
        )
        query(
            op,
            "conservation_base_nonvacuity",
            c.facts,
            [op_scope, c.first, z3.Not(c.current.reset)],
            "sat",
        )
        query(
            op,
            "conservation_step_nonvacuity",
            c.facts,
            [
                op_scope,
                nz,
                c.Ipast,
                z3.Extract(31, 31, c.current.left) == 1,
                z3.Extract(31, 31, c.current.right) == 1,
            ],
            "sat",
        )
        for name, d, extras in [
            ("missing_epoch", generic.Certificate(epoch=False), "step"),
            ("wrong_snapshot_word", generic.Certificate(wrong_snapshot=True), "nonzero"),
            ("missing_base", generic.Certificate(base=False), "base"),
        ]:
            additional = [d.OP == BV(op, 3), z3.Not(d.I)]
            if extras == "base":
                additional += [d.first, z3.Not(d.current.reset)]
            else:
                additional += [z3.Not(d.first), d.Ipast]
                if extras == "nonzero":
                    additional += [d.current.iteration != BV(0, 6)]
            query(op, "negative_conservation_" + name, d.facts, additional, "sat", d.I)
        terminal_guard = z3.And(c.G, c.current.iteration == BV(32, 6))
        native_guard = z3.And(c.common, c.current.active, c.current.iteration == BV(32, 6))
        terminal_claim = c.current.P == c.R
        tfacts = {
            "proved_complete_conservation": c.I,
            "native_active_epoch": c.facts["active_epoch"],
            "native_terminal_total_is_product": z3.Implies(native_guard, c.T == c.current.P),
        }
        query(
            op,
            "terminal",
            tfacts,
            [op_scope, terminal_guard, z3.Not(terminal_claim)],
            "unsat",
            role="Proved complete conservation and the native terminal equality, enabled by active epoch history",
        )
        query(op, "terminal_nonvacuity", tfacts, [op_scope, terminal_guard], "sat")
        for missing in list(tfacts):
            query(
                op,
                "negative_terminal_without_" + missing,
                {k: v for k, v in tfacts.items() if k != missing},
                [op_scope, terminal_guard, z3.Not(terminal_claim)],
                "sat",
                terminal_claim,
            )
    result = {
        "schema": "ditdah-e2.mul-middle-local-rules.v1",
        "copyright": "2026 Huang Rui <vowstar@gmail.com>",
        "license": "MIT",
        "solver": {"name": "Z3", "version": z3.get_version_string(), "logic": "QF_UFBV"},
        "operations": [operation],
        "positiveUnsat": sum((r["actual"] == "unsat" for r in rows)),
        "nonvacuitySat": sum(
            (r["actual"] == "sat" and (not r["name"].startswith("negative_")) for r in rows)
        ),
        "negativeCountermodelsSat": sum(
            (r["actual"] == "sat" and r["name"].startswith("negative_") for r in rows)
        ),
        "functionSignature": "U(BV64,BV32) returns BV64",
        "concreteInterpretation": "M64 * zero_extend_32(Q32) modulo 2^64",
        "newArithmeticAxioms": 0,
        "fourPhiRulesProvedForEachOperation": True,
        "totalPreservedByCheckedTransitivity": True,
        "conservationInductionHypothesisOnlyLocalPast": True,
        "terminalUsesPreviouslyProvedConservation": True,
        "originalArithmeticTargetEverAssumed": False,
        "nativeGroundFactsDischargedByThisScript": False,
        "completeArithmeticForNewOperationsAccepted": False,
    }
    (output / "summary.json").write_text(json.dumps(result, indent=2) + "\n")
    return result
