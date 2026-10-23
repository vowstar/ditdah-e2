# SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
# SPDX-License-Identifier: MIT
"""Sequential RV32 semantics, independent of the hardware decoder and pipeline."""

from dataclasses import dataclass

MASK = (1 << 32) - 1


def signed(value, width):
    value &= (1 << width) - 1
    return value - (1 << width) if value >> (width - 1) else value


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


class Model:
    def __init__(self, words, reset=0, instruction_fault=None, data_fault=None):
        self.memory = {address + lane: (word >> (8 * lane)) & 255
                       for address, word in words.items() for lane in range(4)}
        self.pc = reset
        self.registers = [0] * 32
        self.instruction_fault = instruction_fault
        self.data_fault = data_fault
        self.csrs = {0x300: 0x1800, 0x301: 0x40000100, 0x304: 0,
                     0x305: reset & ~3, 0x310: 0, 0x340: 0, 0x341: 0,
                     0x342: 0, 0x343: 0, 0x344: 0,
                     **dict.fromkeys(range(0xF11, 0xF16), 0)}

    def write_csr(self, address, value):
        masks = {0x300: 0x88, 0x301: 0, 0x304: 0, 0x305: 0xFFFFFFFC,
                 0x310: 0, 0x340: MASK, 0x341: 0xFFFFFFFC,
                 0x342: MASK, 0x343: MASK, 0x344: 0}
        mask = masks[address]
        self.csrs[address] = (self.csrs[address] & ~mask) | (value & mask)

    def word(self, address):
        return sum(self.memory.get((address + lane) & MASK, 0) << (lane * 8)
                   for lane in range(4))

    def step(self):
        pc = self.pc
        insn = self.word(pc)
        result = Event(pc, insn, (pc + 4) & MASK)

        def fault(cause, value):
            result.trap, result.cause, result.tval = True, cause, value & MASK
            result.next_pc, result.rd, result.value = self.csrs[0x305], 0, 0
            self.csrs[0x341], self.csrs[0x342], self.csrs[0x343] = pc, cause, value & MASK
            self.csrs[0x300] = 0x1800 | ((self.csrs[0x300] & 8) << 4)

        op, rd, f3 = insn & 127, (insn >> 7) & 31, (insn >> 12) & 7
        a, b = self.registers[(insn >> 15) & 31], self.registers[(insn >> 20) & 31]
        imm = signed(insn >> 20, 12)
        if pc == self.instruction_fault:
            fault(1, pc)
        elif op in (0x37, 0x17):
            result.instruction = "lui" if op == 0x37 else "auipc"
            result.rd, result.value = rd, ((insn & 0xFFFFF000) + (pc if op == 0x17 else 0)) & MASK
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
            if address % count:
                fault(6 if write else 4, address)
            else:
                lane = address % 4
                result.memory = (address, int(write), (b << (8 * lane)) & MASK if write else 0,
                                 ((1 << count) - 1) << lane if write else 0, f3 & 3)
                if address == self.data_fault:
                    fault(7 if write else 5, address)
                elif write:
                    for index in range(count):
                        self.memory[(address + index) & MASK] = (b >> (8 * index)) & 255
                else:
                    value = sum(self.memory.get((address + index) & MASK, 0) << (index * 8) for index in range(count))
                    result.rd = rd
                    result.value = (value if f3 >= 4 else signed(value, count * 8)) & MASK
        elif op == 0x63 and f3 in (0, 1, 4, 5, 6, 7):
            result.instruction = {0: "beq", 1: "bne", 4: "blt", 5: "bge", 6: "bltu", 7: "bgeu"}[f3]
            offset = signed(((insn >> 31) << 12) | (((insn >> 7) & 1) << 11)
                            | (((insn >> 25) & 63) << 5) | (((insn >> 8) & 15) << 1), 13)
            taken = {0: a == b, 1: a != b, 4: signed(a, 32) < signed(b, 32),
                     5: signed(a, 32) >= signed(b, 32), 6: a < b, 7: a >= b}[f3]
            if taken:
                result.next_pc = (pc + offset) & MASK
                if result.next_pc % 4:
                    fault(0, result.next_pc)
        elif op in (0x6F, 0x67) and (op == 0x6F or f3 == 0):
            result.instruction = "jal" if op == 0x6F else "jalr"
            offset = signed(((insn >> 31) << 20) | (((insn >> 12) & 255) << 12)
                            | (((insn >> 20) & 1) << 11) | (((insn >> 21) & 1023) << 1), 21)
            target = ((a + imm) & ~1) if op == 0x67 else pc + offset
            result.next_pc = target & MASK
            if result.next_pc % 4:
                fault(0, result.next_pc)
            else:
                result.rd, result.value = rd, (pc + 4) & MASK
        elif op == 0x73 and f3 in (1, 2, 3, 5, 6, 7):
            address, source = insn >> 20, (insn >> 15) & 31
            result.instruction = {1: "csrrw", 2: "csrrs", 3: "csrrc",
                                  5: "csrrwi", 6: "csrrsi", 7: "csrrci"}[f3]
            write = f3 in (1, 5) or source != 0
            if address not in self.csrs or (write and address >> 10 == 3):
                fault(2, insn)
            else:
                old = self.csrs[address]
                operand = source if f3 >= 5 else a
                updated = operand if f3 & 3 == 1 else old | operand if f3 & 3 == 2 else old & ~operand
                if write:
                    self.write_csr(address, updated)
                result.rd, result.value = rd, old
        elif insn == 0x30200073:
            result.instruction = "mret"
            result.next_pc = self.csrs[0x341]
            self.csrs[0x300] = 0x1880 | ((self.csrs[0x300] >> 4) & 8)
        elif insn == 0x00100073:
            result.instruction = "ebreak"
            fault(3, pc)
        elif insn == 0x00000073:
            result.instruction = "ecall"
            fault(11, 0)
        elif op == 0x0F and f3 == 0:
            result.instruction = "fence"
        else:
            fault(2, insn)
        if result.rd:
            self.registers[result.rd] = result.value
        else:
            result.value = 0
        self.pc = result.next_pc
        return result
