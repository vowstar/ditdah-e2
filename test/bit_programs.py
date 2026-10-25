# SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
# SPDX-License-Identifier: MIT
"""Exercise bit instructions across core dependencies and precise traps."""

from bit_operations import ENCODINGS, arithmetic, encode
from programs import (Case, COMPLETION_PC, HANDLER_PC, PROGRAM_PC, TRAP_RECORD, add, branch,
                      constant, finish, immediate, jump, store, trap_handler)


FIXED = dict(zip(ENCODINGS, (
    33, 35, 39, 0x80000000, 0xFFFFFFE1, 0x7FFFFFE1, 0, 0, 2,
    31, 0x80000001, 0x80000001, 31, 1, 1, 1, 0xC0000000, 3,
    0x03000000, 0xFF0000FF, 0x01000080, 1, 0x80000001, 1, 0,
    1, 0x80000081, 0x80000001, 0x80000081)))


def cases(zba=False, zbb=False, zbs=False):
    subset = int(zba) | (int(zbb) << 1) | (int(zbs) << 2)
    result = []
    for name, (_, extension, form) in ENCODINGS.items():
        word = encode(name, shift=7)
        if not subset & extension:
            result.append(Case(f"bit_disabled_{name}", [word, store(3, 0, 256)],
                               expected_causes=(2,), signature={256: 0, TRAP_RECORD: PROGRAM_PC,
                               TRAP_RECORD + 4: 2, TRAP_RECORD + 8: word}))
            continue
        code = constant(1, 0x80000001) + [immediate(2, 0, 31), word, add(4, 3, 3),
            store(4, 0, 260), store(3, 0, 256), encode(name, rd=0, shift=7), store(0, 0, 264)]
        code += constant(5, FIXED[name]) + [branch(3, 5, 8), store(5, 0, 268)]
        result.append(Case(f"bit_{name}_fixed", finish(code), expected_causes=(),
            signature={256: FIXED[name], 260: FIXED[name] * 2 & 0xFFFFFFFF, 264: 0, 268: 0}))
        code = [immediate(1, 0, 512, 3, 2)]
        if form == "R":
            code.append(immediate(2, 0, 516, 3, 2))
        code += [word, store(3, 0, 256)]
        result.append(Case(f"bit_{name}_load", finish(code), expected_causes=(),
            data={512: 0x80000001, 516: 31}, signature={256: FIXED[name]}))
        result.append(Case(f"bit_{name}_zero_operands",
            finish([encode(name, rs1=0, rs2=0, shift=7), store(3, 0, 256)]),
            expected_causes=(), signature={256: arithmetic(name, 0, 0, 7)}))
        code, signature = [], {}
        for shift in range(32):
            code += constant(1, 0xA5008101) + [immediate(2, 0, shift + 32),
                encode(name, shift=shift), store(3, 0, 256 + shift * 4)]
            signature[256 + shift * 4] = arithmetic(name, 0xA5008101, shift + 32, shift)
        result.append(Case(f"bit_{name}_shifts", finish(code), expected_causes=(), signature=signature))
        if form != "R":
            encoded_rs2 = (word >> 20) & 31
            code = constant(1, 0x80000001) + [immediate(encoded_rs2, 0, 512, 3, 2),
                word, store(3, 0, 256)]
            # No load destination in this program is a real bit operand.
            if encoded_rs2 not in (1, 3):
                result.append(Case(f"bit_{name}_no_false_load", finish(code), expected_causes=(),
                                   data={512: 31}, signature={256: FIXED[name]}))
        for write in (False, True):
            memory = store(2, 0, 512) if write else immediate(6, 0, 512, 3, 2)
            code = constant(1, 0x80000001) + [immediate(2, 0, 31), immediate(3, 0, 77), memory, word]
            handler = [store(3, 0, 256)]
            handler += trap_handler()
            handler[-1] = jump(0, COMPLETION_PC - HANDLER_PC - (len(handler) - 1) * 4)
            result.append(Case(f"bit_{name}_older_{'store' if write else 'load'}_fault", code,
                handler=handler, data_fault=512, expected_causes=(7 if write else 5,),
                signature={256: 77, TRAP_RECORD: PROGRAM_PC + 16, TRAP_RECORD + 8: 512}))
    for index, word in enumerate((0x22002033, 0x2000203B, 0x6000101B, 0x62005013,
                                  0x4800101B, 0x4A001013, 0x6B805013, 0x08104033,
                                  0x60301013, 0x28805013, 0x28005033)):
        result.append(Case(f"bit_reserved_{index}", [word, store(3, 0, 256)], expected_causes=(2,),
            signature={256: 0, TRAP_RECORD: PROGRAM_PC, TRAP_RECORD + 4: 2, TRAP_RECORD + 8: word}))
    for case in result:
        case.enable_zba, case.enable_zbb, case.enable_zbs = zba, zbb, zbs
    return result
