# SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
# SPDX-License-Identifier: MIT
"""Sequential RV32 semantics, independent of the hardware decoder and pipeline."""

from dataclasses import dataclass

from compressed_model import decode as decode_instruction
from bit_model import execute as execute_bit

MASK = (1 << 32) - 1
MASK64 = (1 << 64) - 1
TIME_BASE = 0xFFFFFFF0
M_INSTRUCTIONS = ("mul", "mulh", "mulhsu", "mulhu", "div", "divu", "rem", "remu")
ATOMIC_FUNCTIONS = {2: ("lr.w", 1), 3: ("sc.w", 2), 1: ("amoswap.w", 3),
                    0: ("amoadd.w", 4), 4: ("amoxor.w", 5), 12: ("amoand.w", 6),
                    8: ("amoor.w", 7), 16: ("amomin.w", 8), 20: ("amomax.w", 9),
                    24: ("amominu.w", 10), 28: ("amomaxu.w", 11)}


def signed(value, width):
    value &= (1 << width) - 1
    return value - (1 << width) if value >> (width - 1) else value


def multiply_divide(operation, left, right):
    if operation < 4:
        a = signed(left, 32) if operation in (1, 2) else left
        b = signed(right, 32) if operation == 1 else right
        product = a * b
        return (product if operation == 0 else product >> 32) & MASK
    if right == 0:
        return MASK if operation in (4, 5) else left
    a, b = (signed(left, 32), signed(right, 32)) if operation in (4, 6) else (left, right)
    quotient = abs(a) // abs(b)
    if (a < 0) != (b < 0):
        quotient = -quotient
    return (quotient if operation in (4, 5) else a - quotient * b) & MASK


def atomic_value(function, old, operand):
    values = {1: operand, 0: old + operand, 4: old ^ operand, 12: old & operand,
              8: old | operand, 16: min(signed(old, 32), signed(operand, 32)),
              20: max(signed(old, 32), signed(operand, 32)), 24: min(old, operand), 28: max(old, operand)}
    if function not in values:
        raise ValueError("Unknown atomic arithmetic function")
    return values[function] & MASK


@dataclass
class Event:
    pc: int
    word: int
    next_pc: int
    rd: int = 0
    value: int = 0
    trap: bool = False
    cause: int = 0
    tval: int = 0
    memory: tuple | None = None
    instruction: str = "illegal"
    length: int = 4
    user_mode: bool = False
    memory_machine: bool = True
    memory_operation: int = 0
    acquire: bool = False
    release: bool = False


class Model:
    def __init__(self, words, reset=0, instruction_fault=None, data_fault=None, *, enable_m=False, enable_c=False,
                 protected_mode=False, enable_a=False, memory_access=None, enable_zba=False, enable_zbb=False, enable_zbs=False):
        self.memory = {address + lane: (word >> (8 * lane)) & 255
                       for address, word in words.items() for lane in range(4)}
        self.pc = reset
        self.registers = [0] * 32
        self.instruction_fault = instruction_fault
        self.data_fault = data_fault
        self.enable_m = enable_m
        self.enable_c = enable_c
        self.protected_mode = protected_mode
        self.enable_a = enable_a
        self.memory_access = memory_access
        self.reservation = None
        self.bit_extensions = enable_zba, enable_zbb, enable_zbs
        self.user_mode = False
        self.pmp = None
        if protected_mode:
            from pmp import Reference
            self.pmp = Reference()
        self.csrs = {0x300: 0x1800, 0x301: 0x40000100 | (int(enable_m) << 12) | (int(enable_c) << 2) |
                     (int(protected_mode) << 20) | int(enable_a) | (2 if all(self.bit_extensions) else 0), 0x304: 0,
                     0x305: reset & ~3, 0x310: 0, 0x320: 0, 0x340: 0, 0x341: 0,
                     0x342: 0, 0x343: 0, 0x344: 0,
                     **dict.fromkeys(range(0xF11, 0xF16), 0)}
        self.csrs.update(dict.fromkeys((*range(0xB03, 0xB20), *range(0xB83, 0xBA0),
                                       *range(0x323, 0x340), 0xB00, 0xB80, 0xB02, 0xB82,
                                       0xC00, 0xC80, 0xC01, 0xC81, 0xC02, 0xC82), 0))
        if protected_mode:
            self.csrs[0x306] = 0
            self.csrs[0x30A] = 0
            self.csrs[0x31A] = 0
        self.counters = {0xB00: 0, 0xB02: 0}
        self.cycle = -1
        self.time = TIME_BASE
        self.sleeping = False
        self.external_clock = False
        self.edge_inhibit = 0
        self.retired = False
        self.counter_writes = {}

    def _begin_cycle(self, cycle, mask):
        if cycle != self.cycle + 1:
            raise AssertionError("Missing model clock edge")
        if self.cycle >= 0:
            for address, bit in ((0xB00, 0), (0xB02, 2)):
                value = self.counters[address]
                if address in self.counter_writes:
                    high, data = self.counter_writes[address]
                    upper, lower = divmod(value, 1 << 32)
                    value = data * (1 << 32) + lower if high else upper * (1 << 32) + data
                elif not (self.edge_inhibit >> bit) & 1 and (address == 0xB00 or self.retired):
                    value = (value + 1) & MASK64
                self.counters[address] = value
        self.cycle, self.time = cycle, (TIME_BASE + cycle) & MASK64
        self.csrs[0x344] = sum(((mask >> lane) & 1) << bit for lane, bit in enumerate((3, 7, 11)))
        self.edge_inhibit = self.csrs[0x320]
        self.retired = False
        self.counter_writes = {}
        if self.csrs[0x344] & self.csrs[0x304]:
            self.sleeping = False

    def clock(self, cycle, mask=0):
        self.external_clock = True
        self._begin_cycle(cycle, mask)

    def read_csr(self, address):
        if self.pmp is not None:
            implemented, value = self.pmp.read(address)
            if implemented:
                return value
        if address in (0xB00, 0xB80, 0xC00, 0xC80):
            value = self.counters[0xB00]
        elif address in (0xB02, 0xB82, 0xC02, 0xC82):
            value = self.counters[0xB02]
        elif address in (0xC01, 0xC81):
            value = self.time
        else:
            return self.csrs[address]
        return (value >> (32 if address & 0x80 else 0)) & MASK

    def interrupt_cause(self):
        if self.user_mode or self.csrs[0x300] & 8:
            pending = self.csrs[0x344] & self.csrs[0x304]
            for bit in (11, 3, 7):
                if pending & (1 << bit):
                    return (1 << 31) | bit
        return None

    def enter_trap(self, pc, cause, value):
        self.reservation = None
        vector = self.csrs[0x305]
        target = vector & ~3
        if cause & (1 << 31) and vector & 3 == 1:
            target = (target + 4 * (cause & 0x7FFFFFFF)) & MASK
        self.csrs[0x341], self.csrs[0x342], self.csrs[0x343] = pc, cause, value & MASK
        status = self.csrs[0x300]
        if self.protected_mode:
            self.csrs[0x300] = (status & ~0x1888) | (0 if self.user_mode else 0x1800) | ((status & 8) << 4)
            self.user_mode = False
        else:
            self.csrs[0x300] = 0x1800 | ((status & 8) << 4)
        self.sleeping = False
        return target

    def interrupt(self):
        cause = self.interrupt_cause()
        if cause is None:
            raise AssertionError("Interrupt without an enabled pending source")
        pc = self.pc
        self.pc = self.enter_trap(pc, cause, 0)
        return pc, self.pc, cause

    def write_csr(self, address, value):
        if address == 0x300 or 0x3A0 <= address <= 0x3A3 or 0x3B0 <= address <= 0x3BF:
            self.reservation = None
        if self.pmp is not None and self.pmp.read(address)[0]:
            self.pmp.write(address, value & MASK)
            return
        if self.protected_mode and address == 0x300:
            self.csrs[address] = (value & 0x220088) | (0 if value & 0x1800 == 0 else 0x1800)
            return
        if self.protected_mode and address == 0x306:
            self.csrs[address] = value & 7
            return
        if address in (0xB00, 0xB80, 0xB02, 0xB82):
            self.counter_writes[address & ~0x80] = (bool(address & 0x80), value & MASK)
            return
        if address == 0x305:
            self.csrs[address] = (value & 0xFFFFFFFC) | int(value & 3 == 1)
            return
        masks = {0x300: 0x88, 0x301: 0, 0x304: 0x888,
                 0x310: 0, 0x320: 5, 0x340: MASK, 0x341: 0xFFFFFFFE if self.enable_c else 0xFFFFFFFC,
                 0x342: MASK, 0x343: MASK, 0x344: 0}
        mask = masks.get(address, 0)
        self.csrs[address] = (self.csrs[address] & ~mask) | (value & mask)

    def word(self, address):
        return sum(self.memory.get((address + lane) & MASK, 0) << (lane * 8)
                   for lane in range(4))

    def complete_memory(self, event):
        if self.memory_access is not None:
            value, fault = self.memory_access(event)
            assert type(value) is int and 0 <= value <= MASK and fault in (False, True), "Invalid reference memory completion"
            return value, bool(fault)
        address = event.memory[0]
        value = int(self.reservation != address) if event.memory_operation == 2 else self.word(address & ~3)
        return value, address == self.data_fault

    def step(self):
        if not self.external_clock:
            self._begin_cycle(self.cycle + 1, 0)
        if self.sleeping:
            raise AssertionError("Retirement while WFI waits")
        pc = self.pc
        raw, length, decoded, fetch_fault = self.word(pc), 4, None, None
        fetch_denied = self.pmp is not None and not self.pmp.allowed((pc & ~3, 2, int(not self.user_mode), 2))
        if fetch_denied:
            raw, length, fetch_fault = 0, 2 if self.enable_c else 4, pc
        elif self.enable_c:
            if pc & ~3 == self.instruction_fault:
                raw, length, fetch_fault = 0, 2, pc
            else:
                decoded = decode_instruction(raw)
                raw, length = decoded.raw, decoded.length
                second = (pc + 2) & MASK
                if length == 4 and pc & 2:
                    denied = self.pmp is not None and not self.pmp.allowed((second & ~3, 2, int(not self.user_mode), 2))
                    if denied or second & ~3 == self.instruction_fault:
                        raw, fetch_fault = 0, second
        elif pc == self.instruction_fault:
            fetch_fault = pc
        insn = decoded.expanded if decoded is not None else raw
        result = Event(pc, raw, (pc + length) & MASK, length=length, user_mode=self.user_mode)

        def fault(cause, value):
            result.trap, result.cause, result.tval = True, cause, value & MASK
            result.next_pc, result.rd, result.value = self.enter_trap(pc, cause, value), 0, 0

        op, rd, f3 = insn & 127, (insn >> 7) & 31, (insn >> 12) & 7
        a, b = self.registers[(insn >> 15) & 31], self.registers[(insn >> 20) & 31]
        imm = signed(insn >> 20, 12)
        bit = execute_bit(insn, a, b, *self.bit_extensions)
        if fetch_fault is not None:
            fault(1, fetch_fault)
        elif decoded is not None and not decoded.legal:
            fault(2, raw)
        elif op in (0x37, 0x17):
            result.instruction = "lui" if op == 0x37 else "auipc"
            result.rd, result.value = rd, ((insn & 0xFFFFF000) + (pc if op == 0x17 else 0)) & MASK
        elif self.enable_m and op == 0x33 and insn >> 25 == 1:
            result.instruction = M_INSTRUCTIONS[f3]
            result.rd, result.value = rd, multiply_divide(f3, a, b)
        elif bit is not None:
            result.instruction, result.value = bit
            result.rd = rd
        elif (op == 0x13 and (f3 not in (1, 5) or insn >> 25 == 0 or
                             (f3 == 5 and insn >> 25 == 32))) or (
                op == 0x33 and (insn >> 25 == 0 or (insn >> 25 == 32 and f3 in (0, 5)))):
            rhs = b if op == 0x33 else imm & MASK
            subtract = op == 0x33 and insn >> 25 == 32 and f3 == 0
            arithmetic = f3 == 5 and insn >> 25 == 32
            operations = [a - rhs if subtract else a + rhs, a << (rhs & 31),
                          int(signed(a, 32) < signed(rhs, 32)), int(a < rhs), a ^ rhs,
                          (signed(a, 32) if arithmetic else a) >> (rhs & 31), a | rhs, a & rhs]
            names = ["sub" if subtract else "add", "sll", "slt", "sltu", "xor",
                     "sra" if arithmetic else "srl", "or", "and"]
            result.instruction = names[f3]
            if op == 0x13:
                result.instruction = {"sltu": "sltiu"}.get(result.instruction, result.instruction + "i")
            result.rd, result.value = rd, operations[f3] & MASK
        elif (op == 0x03 and f3 in (0, 1, 2, 4, 5)) or (op == 0x23 and f3 in (0, 1, 2)):
            write = op == 0x23
            count = 1 << (f3 & 3)
            result.instruction = {0: "lb", 1: "lh", 2: "lw", 4: "lbu", 5: "lhu"}[f3] if not write else ["sb", "sh", "sw"][f3]
            offset = signed(((insn >> 25) << 5) | rd, 12) if write else imm
            address = (a + offset) & MASK
            result.memory_machine = not self.user_mode and (not self.protected_mode or
                not self.csrs[0x300] & (1 << 17) or self.csrs[0x300] & 0x1800 == 0x1800)
            if address % count:
                fault(6 if write else 4, address)
            elif self.pmp is not None and not self.pmp.allowed((address, f3 & 3, int(result.memory_machine), int(write))):
                fault(7 if write else 5, address)
            else:
                lane = address % 4
                result.memory = (address, int(write), (b << (8 * lane)) & MASK if write else 0,
                                 ((1 << count) - 1) << lane if write else 0, f3 & 3)
                completed_value, completed_fault = self.complete_memory(result)
                if completed_fault:
                    fault(7 if write else 5, address)
                elif write:
                    for index in range(count):
                        self.memory[(address + index) & MASK] = (b >> (8 * index)) & 255
                    if self.reservation == address & ~3:
                        self.reservation = None
                else:
                    value = completed_value >> (8 * lane) & ((1 << (8 * count)) - 1)
                    result.rd = rd
                    result.value = (value if f3 >= 4 else signed(value, count * 8)) & MASK
        elif self.enable_a and op == 0x2F and f3 == 2 and insn >> 27 in ATOMIC_FUNCTIONS and (
                insn >> 27 != 2 or insn >> 20 & 31 == 0):
            function = insn >> 27
            result.instruction, result.memory_operation = ATOMIC_FUNCTIONS[function]
            result.acquire, result.release = bool(insn & (1 << 26)), bool(insn & (1 << 25))
            load_reserved, conditional = function == 2, function == 3
            result.memory_machine = not self.user_mode and (not self.protected_mode or
                not self.csrs[0x300] & (1 << 17) or self.csrs[0x300] & 0x1800 == 0x1800)
            denied = self.pmp is not None and any(not self.pmp.allowed((a, 2, int(result.memory_machine), kind))
                                                 for kind in ((0,) if load_reserved else (1,) if conditional else (0, 1)))
            if a % 4:
                fault(4 if load_reserved else 6, a)
            elif denied:
                fault(5 if load_reserved else 7, a)
            else:
                result.memory = (a, int(not load_reserved), 0 if load_reserved else b, 0 if load_reserved else 15, 2)
                old, failed = self.complete_memory(result)
                if failed:
                    fault(5 if load_reserved else 7, a)
                else:
                    result.rd, result.value = rd, old
                    if load_reserved:
                        self.reservation = a
                    else:
                        if conditional:
                            assert old in (0, 1), "Invalid reference SC status"
                            self.reservation = None
                        if not conditional or old == 0:
                            updated = b if conditional else atomic_value(function, old, b)
                            for lane in range(4):
                                self.memory[a + lane] = updated >> (8 * lane) & 255
                            if self.reservation == a:
                                self.reservation = None
        elif op == 0x63 and f3 in (0, 1, 4, 5, 6, 7):
            result.instruction = {0: "beq", 1: "bne", 4: "blt", 5: "bge", 6: "bltu", 7: "bgeu"}[f3]
            offset = signed(((insn >> 31) << 12) | (((insn >> 7) & 1) << 11)
                            | (((insn >> 25) & 63) << 5) | (((insn >> 8) & 15) << 1), 13)
            taken = {0: a == b, 1: a != b, 4: signed(a, 32) < signed(b, 32),
                     5: signed(a, 32) >= signed(b, 32), 6: a < b, 7: a >= b}[f3]
            if taken:
                result.next_pc = (pc + offset) & MASK
                if result.next_pc % (2 if self.enable_c else 4):
                    fault(0, result.next_pc)
        elif op in (0x6F, 0x67) and (op == 0x6F or f3 == 0):
            result.instruction = "jal" if op == 0x6F else "jalr"
            offset = signed(((insn >> 31) << 20) | (((insn >> 12) & 255) << 12)
                            | (((insn >> 20) & 1) << 11) | (((insn >> 21) & 1023) << 1), 21)
            target = ((a + imm) & ~1) if op == 0x67 else pc + offset
            result.next_pc = target & MASK
            if result.next_pc % (2 if self.enable_c else 4):
                fault(0, result.next_pc)
            else:
                result.rd, result.value = rd, (pc + length) & MASK
        elif op == 0x73 and f3 in (1, 2, 3, 5, 6, 7):
            address, source = insn >> 20, (insn >> 15) & 31
            result.instruction = {1: "csrrw", 2: "csrrs", 3: "csrrc",
                                  5: "csrrwi", 6: "csrrsi", 7: "csrrci"}[f3]
            write = f3 in (1, 5) or source != 0
            implemented = address in self.csrs or self.pmp is not None and self.pmp.read(address)[0]
            user_denied = self.user_mode and (address >> 8 & 3) != 0
            if self.user_mode and address in (0xC00, 0xC80, 0xC01, 0xC81, 0xC02, 0xC82):
                user_denied = not bool(self.csrs[0x306] & (1 << (address & 3)))
            if not implemented or user_denied or (write and address >> 10 == 3):
                fault(2, insn)
            else:
                old = self.read_csr(address)
                operand = source if f3 >= 5 else a
                updated = operand if f3 & 3 == 1 else old | operand if f3 & 3 == 2 else old & ~operand
                if write:
                    self.write_csr(address, updated)
                result.rd, result.value = rd, old
        elif insn == 0x30200073:
            result.instruction = "mret"
            self.reservation = None
            if self.user_mode:
                fault(2, insn)
            else:
                result.next_pc = self.csrs[0x341]
                status = self.csrs[0x300]
                if self.protected_mode:
                    self.user_mode = status & 0x1800 == 0
                    self.csrs[0x300] = (status & ~0x1888) | 0x80 | ((status >> 4) & 8)
                    if self.user_mode:
                        self.csrs[0x300] &= ~(1 << 17)
                else:
                    self.csrs[0x300] = 0x1880 | ((status >> 4) & 8)
        elif insn == 0x10500073:
            result.instruction = "wfi"
            if self.user_mode and self.csrs[0x300] & (1 << 21):
                fault(2, insn)
            else:
                self.sleeping = not bool(self.csrs[0x344] & self.csrs[0x304])
        elif insn == 0x00100073:
            result.instruction = "ebreak"
            fault(3, pc)
        elif insn == 0x00000073:
            result.instruction = "ecall"
            fault(8 if self.user_mode else 11, 0)
        elif op == 0x0F and f3 in (0, 1):
            result.instruction = "fence.i" if f3 else "fence"
        else:
            fault(2, raw)
        if decoded is not None and decoded.legal and length == 2 and fetch_fault is None:
            result.instruction = "c." + decoded.name
        if result.rd:
            self.registers[result.rd] = result.value
        else:
            result.value = 0
        self.pc = result.next_pc
        self.retired = not result.trap
        return result
