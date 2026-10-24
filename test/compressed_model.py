# SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
# SPDX-License-Identifier: MIT
"""Share one compressed instruction oracle between unit and architectural checks."""

from dataclasses import dataclass

from compressed_unit import decode as decode_halfword


@dataclass(frozen=True, slots=True)
class Decoded:
    raw: int
    expanded: int
    length: int
    legal: bool
    hint: bool
    name: str


def decode(raw, *, enable_c=True):
    """Check width and expand RV32C. The caller checks 32-bit instruction legality."""
    if type(raw) is not int or not 0 <= raw <= 0xFFFFFFFF:
        raise ValueError("Instruction window must be an unsigned 32-bit integer")
    if type(enable_c) is not bool:
        raise ValueError("enable_c must be a Boolean")
    if enable_c and raw & 3 != 3:
        halfword = raw & 0xFFFF
        legal, hint, expanded, name = decode_halfword(halfword)
        return Decoded(halfword, expanded, 2, bool(legal), bool(hint), name)
    if raw & 3 != 3:
        return Decoded(raw, 0, 4, False, False, "illegal.compressed_disabled")
    if raw & 31 == 31:
        return Decoded(raw, 0, 4, False, False, "illegal.long")
    return Decoded(raw, raw, 4, True, False, "uncompressed")
