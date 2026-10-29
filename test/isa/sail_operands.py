# SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
# SPDX-License-Identifier: MIT
"""Recover RV32 source slots from standard encodings, without executing them."""


FEATURES = ("enableC", "enableM", "enableA", "enableZba", "enableZbb", "enableZbs")


def _validate(instruction, length, parameters):
    if type(length) is not int or length not in (2, 4):
        raise ValueError("Expected a two-byte or four-byte instruction")
    if type(instruction) is not int or not 0 <= instruction < 1 << (length * 8):
        raise ValueError("Instruction bits exceed their original length")
    if type(parameters) is not dict or any(type(parameters.get(key)) is not bool for key in FEATURES):
        raise ValueError("Operand recovery requires explicit Boolean ISA features")


def _compressed(word):
    quadrant, family = word & 3, word >> 13
    register, second = word >> 7 & 31, word >> 2 & 31
    compact_first, compact_second = 8 + (word >> 7 & 7), 8 + (word >> 2 & 7)
    high, low = word >> 12 & 1, word >> 2 & 31
    immediate_nonzero = high != 0 or low != 0
    none = (0, 0), False
    hint = (0, 0), True
    if quadrant == 0:
        if family == 0 and word & 0x1FE0:
            return (2, 0), False
        if family == 2:
            return (compact_first, 0), False
        if family == 6:
            return (compact_first, compact_second), False
        return none
    if quadrant == 1:
        if family == 0:
            return (register, 0), register == 0 or not immediate_nonzero
        if family == 2:
            return hint if register == 0 else none
        if family == 3:
            if not immediate_nonzero:
                return none
            if register == 2:
                return (2, 0), False
            return hint if register == 0 else none
        if family == 4:
            form = word >> 10 & 3
            if form in (0, 1):
                if high:
                    return none
                return (compact_first, 0), low == 0
            if form == 2:
                return (compact_first, 0), False
            return none if high else ((compact_first, compact_second), False)
        if family in (6, 7):
            return (compact_first, 0), False
        return none
    if quadrant == 2:
        if family == 0:
            if high:
                return none
            return (register, 0), register == 0 or low == 0
        if family == 2:
            return ((2, 0), False) if register != 0 else none
        if family == 4:
            if second == 0:
                return ((register, 0), False) if register != 0 else none
            if register == 0:
                return (0, second), True
            return ((register if high else 0, second), False)
        if family == 6:
            return (2, second), False
    return none


def is_hint(instruction, length, parameters):
    """Recognize enabled RV32C HINT/no-op encodings, not reserved forms.

    Classification does not erase source reads or identity writes. Any omitted
    Sail identity write needs a separate check against its own register shadow.
    """
    _validate(instruction, length, parameters)
    return length == 2 and parameters["enableC"] and _compressed(instruction)[1]


def sources(instruction, length, parameters):
    """Return used GPR addresses; disabled/reserved encodings have no slots.

    CSR privilege/address rejection does not change encoded operand usage.
    Compressed HINTs retain the sources of their ordinary base expansion.
    Fetch faults without original instruction bits are handled by the caller.
    """
    _validate(instruction, length, parameters)
    if length == 2:
        return _compressed(instruction)[0] if parameters["enableC"] else (0, 0)
    opcode, function, upper = instruction & 127, instruction >> 12 & 7, instruction >> 25
    left, right = instruction >> 15 & 31, instruction >> 20 & 31
    immediate = instruction >> 20
    if opcode == 0x03:
        return (left, 0) if function in (0, 1, 2, 4, 5) else (0, 0)
    if opcode == 0x23:
        return (left, right) if function in (0, 1, 2) else (0, 0)
    if opcode == 0x63:
        return (left, right) if function in (0, 1, 4, 5, 6, 7) else (0, 0)
    if opcode == 0x67:
        return (left, 0) if function == 0 else (0, 0)
    if opcode == 0x73:
        return (left, 0) if function in (1, 2, 3) else (0, 0)
    if opcode == 0x13:
        if function in (0, 2, 3, 4, 6, 7):
            return left, 0
        if function == 1:
            legal = upper == 0 or parameters["enableZbb"] and immediate in (0x600, 0x601, 0x602, 0x604, 0x605) or \
                parameters["enableZbs"] and upper in (0x14, 0x24, 0x34)
        else:
            legal = upper in (0, 0x20) or parameters["enableZbb"] and \
                (upper == 0x30 or immediate in (0x287, 0x698)) or parameters["enableZbs"] and upper == 0x24
        return (left, 0) if legal else (0, 0)
    if opcode == 0x33:
        base = upper == 0 or upper == 0x20 and function in (0, 5)
        multiply = parameters["enableM"] and upper == 1
        address = parameters["enableZba"] and upper == 0x10 and function in (2, 4, 6)
        basic = parameters["enableZbb"] and (upper == 0x20 and function in (4, 6, 7) or
                  upper == 5 and function in (4, 5, 6, 7) or upper == 0x30 and function in (1, 5))
        single = parameters["enableZbs"] and (upper in (0x14, 0x24, 0x34) and function == 1 or
                                             upper == 0x24 and function == 5)
        if parameters["enableZbb"] and upper == 4 and function == 4 and right == 0:
            return left, 0
        return (left, right) if base or multiply or address or basic or single else (0, 0)
    if opcode == 0x2F and parameters["enableA"] and function == 2:
        operation = instruction >> 27
        if operation in (0, 1, 2, 3, 4, 8, 12, 16, 20, 24, 28) and (operation != 2 or right == 0):
            return left, right if operation != 2 else 0
    return 0, 0
