# SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
# SPDX-License-Identifier: MIT
"""Architectural RV32 bit semantics without hardware or test-driver imports."""


def execute(word, a, b, zba=False, zbb=False, zbs=False):
    opcode, function, upper = word & 127, (word >> 12) & 7, word >> 25
    immediate, selector = word >> 20, (word >> 20) & 31
    name, value = None, None
    if zba and opcode == 0x33 and upper == 0x10 and function in (2, 4, 6):
        amount = function // 2
        name, value = f"sh{amount}add", a * (2 ** amount) + b
    if zbb and opcode == 0x33:
        if upper == 0x20 and function in (4, 6, 7):
            name, value = {4: ("xnor", ~(a ^ b)), 6: ("orn", a | ~b), 7: ("andn", a & ~b)}[function]
        elif upper == 5 and function in (4, 5, 6, 7):
            unsigned = function % 2
            left = a if unsigned else (a & 0x7FFFFFFF) - (a & 0x80000000)
            right = b if unsigned else (b & 0x7FFFFFFF) - (b & 0x80000000)
            name = ("max" if function >= 6 else "min") + ("u" if unsigned else "")
            value = max(left, right) if function >= 6 else min(left, right)
        elif upper == 4 and function == 4 and selector == 0:
            name, value = "zext.h", a & 65535
        elif upper == 0x30 and function in (1, 5):
            name = "rol" if function == 1 else "ror"
            amount = b % 32
            digits = format(a, "032b")
            amount = amount if function == 1 else -amount
            value = int(digits[amount:] + digits[:amount], 2) if amount else a
    if zbb and opcode == 0x13:
        if function == 1 and immediate in (0x600, 0x601, 0x602):
            name = ("clz", "ctz", "cpop")[immediate - 0x600]
            digits = format(a, "032b")
            value = sum(bit == "1" for bit in digits) if name == "cpop" else \
                len((digits if name == "clz" else digits[::-1]).split("1", 1)[0])
        elif function == 1 and immediate in (0x604, 0x605):
            width = 8 if immediate == 0x604 else 16
            name = "sext.b" if width == 8 else "sext.h"
            low = a & ((1 << width) - 1)
            value = low - (1 << width) if low & (1 << (width - 1)) else low
        elif function == 5 and upper == 0x30:
            name = "rori"
            digits = format(a, "032b")
            value = int(digits[-selector:] + digits[:-selector], 2) if selector else a
        elif function == 5 and immediate == 0x287:
            name = "orc.b"
            value = sum((255 if a & (255 << offset) else 0) << offset for offset in (0, 8, 16, 24))
        elif function == 5 and immediate == 0x698:
            name = "rev8"
            digits = format(a, "08x")
            value = int("".join(digits[index:index + 2] for index in (6, 4, 2, 0)), 16)
    if zbs and opcode in (0x13, 0x33):
        operation = {(0x24, 1): "bclr", (0x24, 5): "bext", (0x34, 1): "binv", (0x14, 1): "bset"}.get((upper, function))
        if operation is not None:
            index = selector if opcode == 0x13 else b % 32
            name = operation + ("i" if opcode == 0x13 else "")
            if operation == "bext":
                value = int(bool(a & (2 ** index)))
            else:
                bits = list(format(a, "032b"))
                position = 31 - index
                bits[position] = "0" if operation == "bclr" else "1" if operation == "bset" else str(1 - int(bits[position]))
                value = int("".join(bits), 2)
    return None if name is None else (name, value % (1 << 32))
