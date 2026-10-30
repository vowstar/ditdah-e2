# SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
# SPDX-License-Identifier: MIT
"""Typed conservation predicate and exact sampled premises for multiplication."""

import z3


def bv(value, width):
    return z3.BitVecVal(value, width)


class State:

    def __init__(self, name):
        for k in ("reset", "cancel", "pending", "active"):
            setattr(self, k, z3.Bool(name + "." + k))
        for k, w in (
            ("P", 64),
            ("M", 64),
            ("Q", 32),
            ("left", 32),
            ("right", 32),
            ("op", 3),
            ("iteration", 6),
        ):
            setattr(self, k, z3.BitVec(name + "." + k, w))


class Certificate:

    def __init__(self, *, epoch=True, base=True, wrong_snapshot=False):
        self.current = State("current")
        self.past = State("past")
        c, p = (self.current, self.past)
        self.OP = z3.BitVec("OPERATION", 3)
        self.H = z3.Bool("history_valid")
        self.previous_reset = z3.Bool("previous_reset")
        self.previous_step = z3.Bool("chain_previous_mul_step")
        self.previous_owner = z3.Bool("chain_previous_owner")
        self.first = z3.Bool("first_proof_frame")
        self.snap = {
            k: z3.BitVec("snapshot." + k, w)
            for k, w in (("P", 64), ("M", 64), ("Q", 32), ("left", 32), ("right", 32), ("op", 3))
        }
        self.U = z3.Function("U", z3.BitVecSort(64), z3.BitVecSort(32), z3.BitVecSort(64))
        self.total = lambda P, M, Q: P + self.U(M, Q)
        self.ref = lambda left, right, op: self.U(
            z3.ZeroExt(32, self.mag(left, op, True)), self.mag(right, op, False)
        )
        self.selected = lambda s: z3.And(
            s.pending, s.op == self.OP, z3.Extract(2, 2, self.OP) == bv(0, 1)
        )
        self.guard = lambda s: z3.And(z3.Not(s.reset), z3.Not(s.cancel), self.selected(s), s.active)
        self.G = self.guard(c)
        self.Gpast = self.guard(p)
        self.T = self.total(c.P, c.M, c.Q)
        self.Tpast = self.total(p.P, p.M, p.Q)
        self.R = self.ref(c.left, c.right, c.op)
        self.Rpast = self.ref(p.left, p.right, p.op)
        self.Tsnapshot = self.total(self.snap["P"], self.snap["M"], self.snap["Q"])
        self.Rsnapshot = self.ref(self.snap["left"], self.snap["right"], self.snap["op"])
        self.I = z3.Implies(self.G, self.T == self.R)
        self.Ipast = z3.Implies(self.Gpast, self.Tpast == self.Rpast)
        self.common = z3.And(self.H, z3.Not(c.reset), z3.Not(c.cancel), self.selected(c))
        self.facts = {}
        self.facts["source_previous_reset_capture"] = z3.Implies(
            z3.And(self.H, z3.Not(self.first)), self.previous_reset == p.reset
        )
        if epoch:
            self.facts["active_epoch"] = z3.Implies(
                self.G,
                z3.And(
                    self.H,
                    z3.Or(c.iteration == bv(0, 6), z3.And(self.previous_step, self.previous_owner)),
                ),
            )
        snapshot_guard = z3.And(self.H, z3.Not(c.reset), z3.Not(self.previous_reset))
        for k in self.snap:
            rhs = getattr(p, k)
            if k == "Q" and wrong_snapshot:
                rhs = rhs ^ bv(1, 32)
            self.facts["snapshot_" + k] = z3.Implies(snapshot_guard, self.snap[k] == rhs)
        flag_guard = z3.And(self.H, z3.Not(c.reset))
        past_owner = z3.And(z3.Not(p.cancel), self.selected(p))
        past_step = z3.And(past_owner, p.active, z3.ULT(p.iteration, bv(32, 6)))
        self.facts["sampled_step_flag"] = z3.Implies(
            flag_guard, self.previous_step == z3.And(z3.Not(self.previous_reset), past_step)
        )
        self.facts["sampled_owner_flag"] = z3.Implies(
            flag_guard, self.previous_owner == z3.And(z3.Not(self.previous_reset), past_owner)
        )
        self.facts["initial_phi"] = z3.Implies(
            z3.And(self.common, c.active, c.iteration == bv(0, 6)), self.T == self.R
        )
        self.facts["total_preserved"] = z3.Implies(
            z3.And(self.common, self.previous_step), self.T == self.Tsnapshot
        )
        self.facts["reference_stable"] = z3.Implies(
            z3.And(self.common, self.previous_owner), self.R == self.Rsnapshot
        )
        if base:
            self.facts["first_frame_base"] = z3.Implies(
                z3.And(z3.Not(c.reset), self.first), z3.And(z3.Not(c.pending), z3.Not(c.active))
            )

    @staticmethod
    def mag(word, op, left):
        signed = z3.Or(*[op == bv(n, 3) for n in ((1, 2, 4, 6) if left else (1, 4, 6))])
        negative = z3.And(signed, z3.Extract(31, 31, word) == bv(1, 1))
        return z3.If(negative, bv(0, 32) - word, word)
