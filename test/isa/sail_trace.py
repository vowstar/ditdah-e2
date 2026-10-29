# SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
# SPDX-License-Identifier: MIT
"""Parse the reviewed Sail 0.12 ordinary execution trace without ISA evaluation."""

from dataclasses import asdict, dataclass
import re


class SailTraceError(ValueError):
    """The trace is incomplete or outside the supported native grammar."""


HEADER = re.compile(r"\[(\d+)\] \[([MU])\]: 0x([0-9a-fA-F]{8}) "
                    r"\(0x([0-9a-fA-F]{4}|[0-9a-fA-F]{8})\) (.+)")
GPR = re.compile(r"x([0-9]+) <- 0x([0-9a-fA-F]{8})")
CSR = re.compile(r"CSR ([A-Za-z0-9_.]+) \(0x([0-9a-fA-F]{3})\) (<-|->) 0x([0-9a-fA-F]{8})")
MEMORY = re.compile(r"mem\[(RW|X|R|W),0x([0-9a-fA-F]+)\] (<-|->) 0x([0-9a-fA-F]+)")
TRAP = re.compile(r"trapping from ([MU]) to ([MU]) to handle ([a-z0-9/-]+)")
EXCEPTION = re.compile(r"handling exc#([a-z0-9/-]+) at priv ([MU]) with tval 0x([0-9a-fA-F]+)")
RETURN = re.compile(r"ret-ing from ([MU]) to ([MU])")


@dataclass(frozen=True)
class MemoryAccess:
    kind: str
    write: bool
    address: int
    width: int
    value: int


@dataclass(frozen=True)
class CsrAccess:
    address: int
    write: bool
    value: int


@dataclass(frozen=True)
class SailStep:
    index: int
    pc: int
    instruction: int | None
    length: int | None
    mode: int
    register_writes: tuple[tuple[int, int], ...]
    memory: tuple[MemoryAccess, ...]
    csrs: tuple[CsrAccess, ...]
    trap: bool
    cause: int | None
    tval: int | None
    return_mode: int | None
    mnemonic: str | None

    def record(self):
        return asdict(self)


def _mode(text):
    return 3 if text == "M" else 0


def _step(lines, position):
    header = None
    registers, memory, csrs = [], [], []
    trap = exception = returned = None
    saw_instruction = False
    mnemonic = None
    for line in lines:
        match = HEADER.fullmatch(line)
        if match:
            if header is not None:
                raise SailTraceError("Multiple instructions in one native step")
            index, mode, pc, instruction, assembly = match.groups()
            mnemonic = assembly.split()[0]
            header = int(index), int(pc, 16), int(instruction, 16), len(instruction) // 2, _mode(mode)
            saw_instruction = True
            continue
        match = MEMORY.fullmatch(line)
        if match:
            kind, address, arrow, value = match.groups()
            width = len(value) // 2
            address = int(address, 16)
            if len(value) % 2 or width not in (1, 2, 4) or address > 0xffffffff:
                raise SailTraceError("Memory record is outside the RV32 scalar profile")
            if kind != "RW" and (kind == "W") != (arrow == "<-"):
                raise SailTraceError("Unexpected memory direction")
            if (kind == "X") == saw_instruction:
                raise SailTraceError("Unexpected memory direction or fetch ordering")
            memory.append(MemoryAccess(kind, arrow == "<-", address, width, int(value, 16)))
            continue
        match = GPR.fullmatch(line)
        if match:
            register, value = int(match[1]), int(match[2], 16)
            if not saw_instruction or not 0 <= register < 32 or register == 0 and value:
                raise SailTraceError("Invalid GPR write record")
            registers.append((register, value))
            continue
        match = CSR.fullmatch(line)
        if match:
            csrs.append(CsrAccess(int(match[2], 16), match[3] == "<-", int(match[4], 16)))
            continue
        match = TRAP.fullmatch(line)
        if match:
            if trap is not None:
                raise SailTraceError("Repeated trap")
            trap = match.groups()
            continue
        match = EXCEPTION.fullmatch(line)
        if match:
            if exception is not None:
                raise SailTraceError("Repeated native exception")
            exception = match[1], match[2], int(match[3], 16)
            continue
        match = RETURN.fullmatch(line)
        if match:
            if returned is not None or not saw_instruction:
                raise SailTraceError("Repeated return or missing instruction")
            returned = match.groups()
            continue
        raise SailTraceError("Unknown semantic trace record")
    if header is None:
        if trap is None or exception is None or trap[2] != "fetch-access-fault" or registers or memory:
            raise SailTraceError("Native step has no decoded instruction or complete fetch fault")
        epc = [item.value for item in csrs if item.write and item.address == 0x341]
        if len(epc) != 1:
            raise SailTraceError("Instructionless fetch fault lacks a unique native PC")
        header = position, epc[0], None, None, _mode(trap[0])
    index, pc, instruction, length, mode = header
    if pc % 2 or length == 2 and instruction & 3 == 3:
        raise SailTraceError("Invalid native instruction width or alignment")
    if len([item for item in registers if item[0]]) > 1:
        raise SailTraceError("Multiple GPR destinations in one scalar step")
    cause = tval = None
    if (trap is None) != (exception is None):
        raise SailTraceError("Incomplete native exception evidence")
    if trap is not None:
        if _mode(trap[0]) != mode or trap[2] != exception[0] or trap[1] != exception[1] or trap[1] != "M":
            raise SailTraceError("Inconsistent native exception identity")
        effects = {item.address: item.value for item in csrs if item.write}
        if any(address not in effects for address in (0x341, 0x342, 0x343)):
            raise SailTraceError("Missing numeric trap CSR evidence")
        cause, tval = effects[0x342], effects[0x343]
        if instruction is None and cause != 1:
            raise SailTraceError("Instructionless native trap is not a fetch access fault")
        if effects[0x341] != pc or tval != exception[2] or cause & 0x80000000:
            raise SailTraceError("Trap CSR evidence differs or contains an unsupported interrupt")
        if any(register for register, _ in registers):
            raise SailTraceError("Faulting instruction wrote a GPR")
    if returned is not None and (_mode(returned[0]) != mode or trap is not None):
        raise SailTraceError("Inconsistent native return")
    return SailStep(index, pc, instruction, length, mode, tuple(registers), tuple(memory), tuple(csrs),
                    trap is not None, cause, tval, _mode(returned[1]) if returned else None, mnemonic)


def parse_trace(text):
    """Read complete native steps, preserving unavailable fetch-fault instruction fields."""
    if not text or not text.endswith("\n\n"):
        raise SailTraceError("Empty trace or incomplete final step")
    groups, current = [], []
    for line in text.splitlines():
        if line:
            current.append(line)
        elif current:
            groups.append(_step(current, len(groups)))
            current = []
    if current or not groups:
        raise SailTraceError("Unterminated or empty native trace")
    if any(step.index != index for index, step in enumerate(groups)):
        raise SailTraceError("Missing, duplicate or unordered native step")
    return groups


def parse_signature(text, words):
    """Read the pinned four-byte signature format with an exact declared extent."""
    lines = text.splitlines()
    if len(lines) != words or not lines or any(re.fullmatch(r"[0-9a-fA-F]{8}", line) is None for line in lines):
        raise SailTraceError("Signature extent or word format differs")
    return [int(line, 16) for line in lines]
