# SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
# SPDX-License-Identifier: MIT
"""Executable words and architectural expectations for the implemented subset."""

from dataclasses import dataclass, field
import random


def immediate(rd, rs1, value, opcode=0x13, funct3=0):
    return ((value & 4095) << 20) | (rs1 << 15) | (funct3 << 12) | (rd << 7) | opcode


def add(rd, a, b):
    return (b << 20) | (a << 15) | (rd << 7) | 0x33


def store(rs2, rs1, offset=0, funct3=2):
    return (((offset & 4095) >> 5) << 25) | (rs2 << 20) | (rs1 << 15) | (funct3 << 12) | ((offset & 31) << 7) | 0x23


def branch(a, b, offset, unequal=False, funct3=None):
    f3 = int(unequal) if funct3 is None else funct3
    return (((offset >> 12) & 1) << 31) | (((offset >> 5) & 63) << 25) | (b << 20) | (a << 15) | (f3 << 12) | (((offset >> 1) & 15) << 8) | (((offset >> 11) & 1) << 7) | 0x63


def jump(rd, offset):
    return (((offset >> 20) & 1) << 31) | (((offset >> 1) & 1023) << 21) | (((offset >> 11) & 1) << 20) | (((offset >> 12) & 255) << 12) | (rd << 7) | 0x6F


BREAK = 0x00100073


@dataclass
class Case:
    name: str
    code: list[int]
    data: dict[int, int] = field(default_factory=dict)
    signature: dict[int, int] = field(default_factory=dict)
    instruction_fault: int | None = None
    data_fault: int | None = None
    cause: int = 3
    reset: int = 0

    def words(self):
        return self.data | {(self.reset + index * 4) & 0xFFFFFFFF: word
                            for index, word in enumerate(self.code)}


def cases():
    a = immediate
    load = lambda rd, base, offset=0: a(rd, base, offset, 0x03, 2)
    result = [
        Case("sum_loop", [a(1, 0, 10), a(2, 0, 0), add(2, 2, 1), a(1, 1, -1),
             branch(1, 0, -8, True), a(3, 0, 256), store(2, 3), load(4, 3),
             add(5, 4, 2), store(5, 3, 4), BREAK], signature={256: 55, 260: 110}),
        Case("forwarding", [a(1, 0, 256), load(2, 1), add(3, 2, 2), add(4, 3, 2),
             store(4, 1, 4), BREAK], data={256: 17}, signature={260: 51}),
        Case("load_store_address", [a(1, 0, 256), load(2, 1), load(3, 2), store(3, 2, 4),
             BREAK], data={256: 512, 512: 0xFEDCBA98}, signature={516: 0xFEDCBA98}),
        Case("zero_and_wrap", [0xFFFFF0B7, a(1, 1, -1), a(0, 1, 7), a(2, 0, 1),
             add(3, 1, 2), a(4, 0, 256), store(0, 4), store(3, 4, 4), BREAK],
             signature={256: 0, 260: 0xFFFFF000}),
        Case("jumps", [jump(1, 12), store(1, 0, 256), 0, a(2, 1, 21),
             a(3, 2, 0, 0x67), store(1, 0, 256), store(3, 0, 260), BREAK],
             signature={256: 0, 260: 20}),
        Case("wrong_path_fault", [jump(1, 12), 0, store(1, 0, 256), BREAK], instruction_fault=4),
        Case("load_fault_younger_store", [load(1, 0, 256), store(1, 0, 260), BREAK],
             data_fault=256, signature={260: 0}, cause=5),
        Case("load_fault_younger_branch", [load(1, 0, 256), jump(0, 8), store(1, 0, 260), BREAK],
             data_fault=256, signature={260: 0}, cause=5),
        Case("store_fault", [a(1, 0, 9), store(1, 0, 256), store(1, 0, 260), BREAK],
             data_fault=256, signature={256: 0, 260: 0}, cause=7),
        Case("fetch_fault", [a(1, 0, 9), store(1, 0, 256), BREAK],
             instruction_fault=4, signature={256: 0}, cause=1),
        Case("load_misaligned", [load(0, 0, 257), BREAK], cause=4),
        Case("store_misaligned", [store(0, 0, 258), BREAK], cause=6),
        Case("jump_misaligned", [jump(1, 2), BREAK], cause=0),
        Case("jalr_misaligned", [a(1, 0, 3), a(2, 1, 0, 0x67), BREAK], cause=0),
        Case("branch_not_taken_misaligned", [a(1, 0, 1), branch(0, 1, 2), BREAK]),
        Case("branch_taken_misaligned", [branch(0, 0, 2), BREAK], cause=0),
        Case("load_zero_fault", [load(0, 0, 256), BREAK], data_fault=256, cause=5),
    ]
    for index, word in enumerate([0, 0xFFFFFFFF, 0x02000033, 0x40001033, 0x02001013,
                                  0x00001067, 0x00003003, 0x00003023, 0x00002063,
                                  0x30001073, 0x02005013, 0x40001013, 0x0000100F]):
        result.append(Case(f"illegal_{index}", [word, store(0, 0, 256)], cause=2))
    result += [
        Case("ecall", [0x00000073, store(0, 0, 256)], cause=11),
        Case("fence_order", [a(1, 0, 87), store(1, 0, 256), 0x0FF0000F,
             load(2, 0, 256), 0x8330000F, store(2, 0, 260), BREAK], signature={260: 87}),
        Case("narrow_lanes", [a(1, 0, -128), store(1, 0, 257, 0), a(1, 0, -1),
             store(1, 0, 258, 1), a(2, 0, 257, 3, 0), a(3, 0, 257, 3, 4),
             a(4, 0, 258, 3, 1), a(5, 0, 258, 3, 5), store(2, 0, 272),
             store(3, 0, 276), store(4, 0, 280), store(5, 0, 284), BREAK],
             data={256: 0x12345678}, signature={256: 0xFFFF8078, 272: 0xFFFFFF80,
                                              276: 128, 280: 0xFFFFFFFF, 284: 65535}),
        Case("half_load_misaligned", [a(1, 0, 257, 3, 1), BREAK], cause=4),
        Case("half_store_misaligned", [store(0, 0, 259, 1), BREAK], cause=6),
        Case("byte_fault", [a(1, 0, 257, 3, 4), BREAK], data_fault=257, cause=5),
        Case("byte_store_fault", [a(1, 0, -1), store(1, 0, 259, 0), BREAK],
             data_fault=259, data={256: 0x12345678}, signature={256: 0x12345678}, cause=7),
        Case("reset_entry", [a(1, 0, 42), store(1, 0, 256), BREAK], signature={256: 42}),
        Case("auipc", [0x80000097, a(1, 1, -1), store(1, 0, 256), BREAK], signature={256: 0x7FFFFFFF}),
    ]
    for f3 in range(8):
        variants = (0, 32) if f3 in (0, 5) else (0,)
        for f7 in variants:
            code = [0x800000B7, a(2, 0, 31),
                    (f7 << 25) | (2 << 20) | (1 << 15) | (f3 << 12) | (3 << 7) | 0x33,
                    store(3, 0, 256), BREAK]
            result.append(Case(f"register_{f3}_{f7}", code))
        for shift in ((0, 31) if f3 in (1, 5) else (-2048, -1, 2047)):
            for f7 in ((0, 32) if f3 == 5 else (0,)):
                value = shift | (f7 << 5)
                result.append(Case(f"immediate_{f3}_{shift}_{f7}",
                    [0x800000B7, a(3, 1, value, funct3=f3), store(3, 0, 256), BREAK]))
    for f3 in (0, 1, 4, 5, 6, 7):
        for x, y in ((-1, 1), (1, -1), (1, 1)):
            result.append(Case(f"branch_{f3}_{x}_{y}", [a(1, 0, x), a(2, 0, y),
                branch(1, 2, 8, funct3=f3), a(3, 0, 7), store(3, 0, 256), BREAK]))
    for f3 in (0, 1, 2, 4, 5):
        for lane in range(0, 4, 1 << (f3 & 3)):
            result.append(Case(f"load_lane_{f3}_{lane}", [a(1, 0, 256 + lane, 3, f3),
                store(1, 0, 272), BREAK], data={256: 0x80FF7F01}))
    for seed in range(4):
        rng = random.Random(seed)
        code = [a(31, 0, 1024)]
        for _ in range(120):
            rd, rs1, rs2 = (rng.randrange(31) for _ in range(3))
            choice = rng.randrange(4)
            code.append(a(rd, rs1, rng.randrange(-2048, 2048)) if choice == 0 else
                        add(rd, rs1, rs2) if choice == 1 else
                        store(rs2, 31, rng.randrange(16) * 4) if choice == 2 else
                        load(rd, 31, rng.randrange(16) * 4))
        result.append(Case(f"random_{seed}", code + [BREAK]))
    return result
