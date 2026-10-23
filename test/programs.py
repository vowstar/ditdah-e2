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
MRET = 0x30200073
PROGRAM_PC = 0x1000
HANDLER_PC = 0x2000
COMPLETION_PC = 0x3000
TRAP_RECORD = 0x800
MASK = 0xFFFFFFFF


def csr(rd, address, source=0, operation=2):
    return (address << 20) | (source << 15) | (operation << 12) | (rd << 7) | 0x73


def constant(rd, value):
    upper = ((value + 0x800) >> 12) & 0xFFFFF
    return [(upper << 12) | (rd << 7) | 0x37, immediate(rd, rd, value)]


def trap_handler(handler_pc=HANDLER_PC, completion_pc=COMPLETION_PC, record=TRAP_RECORD):
    code = constant(25, record)
    for index, address in enumerate((0x341, 0x342, 0x343, 0x300, 0x340)):
        code += [csr(26, address), store(26, 25, index * 4)]
    code.append(jump(0, completion_pc - handler_pc - len(code) * 4))
    return code


def csr_cases():
    def complete(name, code, signature=None):
        return Case(name, code + [jump(0, COMPLETION_PC - PROGRAM_PC - len(code) * 4)],
                    signature=signature or {}, expected_causes=())

    code = [immediate(1, 0, 0x55), csr(2, 0x340, 1, 1), csr(3, 0x340, 1, 2),
            immediate(1, 0, 15), csr(4, 0x340, 1, 3), csr(5, 0x340, 3, 5),
            csr(6, 0x340, 8, 6), csr(7, 0x340, 1, 7), csr(8, 0x340)]
    code += [store(register, 0, 256 + 4 * (register - 2)) for register in range(2, 9)]
    result = [complete("csr_operations", code,
                       dict(zip(range(256, 284, 4), (0, 0x55, 0x55, 0x50, 3, 11, 10))))]
    result.append(complete("csr_zero_operands", [csr(0, 0x340, 31, 5), csr(1, 0x340, 0, 2),
        csr(2, 0x340, 0, 3), csr(3, 0x340, 0, 6), csr(4, 0x340, 0, 7),
        csr(0, 0x340, 0, 1), csr(5, 0x340), csr(0, 0x340, 7, 5), csr(6, 0x340, 0, 5),
        csr(7, 0x340)] + [store(i, 0, 256 + (i - 1) * 4) for i in range(1, 8)],
        dict(zip(range(256, 284, 4), (31, 31, 31, 31, 0, 7, 0)))))
    addresses = (0x300, 0x301, 0x304, 0x305, 0x310, 0x340, 0x341, 0x342, 0x343, 0x344)
    expected = ((0x1800, 0x40000100, 0, 0, 0, 0, 0, 0, 0, 0),
                (0x1888, 0x40000100, 0, 0xFFFFFFFC, 0, 0xFFFFFFFF,
                 0xFFFFFFFC, 0xFFFFFFFF, 0xFFFFFFFF, 0),
                (0x1880, 0x40000100, 0, 0x5A4, 0, 0x5A5, 0x5A4, 0x5A5, 0x5A5, 0))
    for value, values in zip((0, -1, 0x5A5), expected):
        code = [immediate(1, 0, value)]
        for index, address in enumerate(addresses):
            code += [csr(0, address, 1, 1), csr(2, address), store(2, 0, 256 + index * 4)]
        result.append(complete(f"csr_warl_{value}", code, dict(zip(range(256, 296, 4), values))))
    code = []
    for address in range(0xF11, 0xF16):
        for operation in (2, 3, 6, 7):
            code += [csr(1, address, 0, operation), store(1, 0, 256 + (address - 0xF11) * 4)]
    result.append(complete("csr_identification", code, dict.fromkeys(range(256, 276, 4), 0)))
    for operation in (1, 2, 3, 5, 6, 7):
        source = 1 if operation in (2, 3, 6, 7) else 0
        word = csr(2, 0xF11, source, operation)
        result.append(Case(f"csr_readonly_write_{operation}", [word, store(2, 0, 256)],
                           signature={256: 0, TRAP_RECORD: PROGRAM_PC,
                                      TRAP_RECORD + 4: 2, TRAP_RECORD + 8: word}, expected_causes=(2,)))
    for address in (0x302, 0x306, 0xB00, 0xC00, 0x7B0):
        word = csr(1, address)
        result.append(Case(f"csr_unimplemented_{address:x}", [word],
                           signature={TRAP_RECORD + 8: word}, expected_causes=(2,)))
    for memory_write in (False, True):
        memory = store(1, 0, 256) if memory_write else immediate(2, 0, 256, 3, 2)
        for younger in (csr(0, 0x340, 31, 5), MRET):
            label = "mret" if younger == MRET else "csr"
            code = [immediate(1, 0, 55), csr(0, 0x340, 1, 1), memory, younger, BREAK]
            result.append(Case(f"fault_{'store' if memory_write else 'load'}_younger_{label}", code,
                               data_fault=256, signature={256: 0, TRAP_RECORD + 16: 55},
                               expected_causes=(7 if memory_write else 5,)))
    for enabled in (0, 1):
        code = [0x000010B7, immediate(1, 1, 28), csr(0, 0x341, 1, 1),
                immediate(2, 0, enabled * 128), csr(0, 0x300, 2, 1), MRET,
                store(1, 0, 260), csr(3, 0x300), store(3, 0, 256)]
        result.append(complete(f"mret_status_{enabled}", code,
                               {256: 0x1888 if enabled else 0x1880, 260: 0}))
        handler = trap_handler()[:-1]
        handler += [csr(24, 0x340), immediate(24, 24, 1), csr(0, 0x340, 24, 1),
                    immediate(27, 0, 2), branch(24, 27, 20), csr(26, 0x341),
                    immediate(26, 26, 4), csr(0, 0x341, 26, 1), MRET]
        handler += [jump(0, COMPLETION_PC - HANDLER_PC - len(handler) * 4)]
        code = [immediate(1, 0, enabled * 8), csr(0, 0x300, 1, 1), 0x73,
                csr(3, 0x300), store(3, 0, 256), BREAK]
        result.append(Case(f"trap_mret_{enabled}", code, handler=handler,
                           signature={256: 0x1888 if enabled else 0x1880,
                                      TRAP_RECORD: PROGRAM_PC + 20, TRAP_RECORD + 4: 3,
                                      TRAP_RECORD + 8: PROGRAM_PC + 20,
                                      TRAP_RECORD + 12: 0x1880 if enabled else 0x1800,
                                      TRAP_RECORD + 16: 1}, expected_causes=(11, 3)))
    return result


def nested_case():
    handler = [csr(26, 0x342), immediate(27, 0, 3), 0,
               csr(20, 0x341), csr(21, 0x300), csr(19, 0x342), csr(18, 0x343)]
    handler += constant(25, TRAP_RECORD)
    handler += [store(20, 25), store(19, 25, 4), store(18, 25, 8), store(21, 25, 12)]
    inner_pc = HANDLER_PC + len(handler) * 4
    handler += [BREAK, csr(23, 0x300), store(23, 25, 48), csr(0, 0x342, 19, 1),
                csr(0, 0x343, 18, 1), csr(0, 0x300, 21, 1), immediate(20, 20, 4),
                csr(0, 0x341, 20, 1), MRET]
    handler[2] = branch(26, 27, (len(handler) - 2) * 4)
    handler += [csr(22, 0x341), store(22, 25, 32), csr(23, 0x342), store(23, 25, 36),
                csr(23, 0x343), store(23, 25, 40), csr(23, 0x300), store(23, 25, 44),
                immediate(22, 22, 4), csr(0, 0x341, 22, 1), MRET]
    code = [immediate(1, 0, 8), csr(0, 0x300, 1, 1), 0x73, immediate(2, 0, 77),
            store(2, 0, 256), csr(3, 0x300), store(3, 0, 260),
            csr(4, 0x342), store(4, 0, 264), csr(5, 0x343), store(5, 0, 268)]
    code += [jump(0, COMPLETION_PC - PROGRAM_PC - len(code) * 4)]
    signature = {256: 77, 260: 0x1888, 264: 11, 268: 0,
                 TRAP_RECORD: PROGRAM_PC + 8, TRAP_RECORD + 4: 11,
                 TRAP_RECORD + 8: 0, TRAP_RECORD + 12: 0x1880,
                 TRAP_RECORD + 32: inner_pc, TRAP_RECORD + 36: 3,
                 TRAP_RECORD + 40: inner_pc, TRAP_RECORD + 44: 0x1800,
                 TRAP_RECORD + 48: 0x1880}
    return Case("nested_trap_return", code, signature=signature, handler=handler, expected_causes=(11, 3))


@dataclass
class Case:
    name: str
    code: list[int]
    data: dict[int, int] = field(default_factory=dict)
    signature: dict[int, int] = field(default_factory=dict)
    instruction_fault: int | None = None
    data_fault: int | None = None
    expected_causes: tuple[int, ...] = (3,)
    reset: int = 0
    completion_pc: int = COMPLETION_PC
    handler: list[int] | None = None
    program_pc: int = PROGRAM_PC
    handler_pc: int = HANDLER_PC

    def words(self):
        for address in (self.reset, self.program_pc, self.handler_pc, self.completion_pc):
            if address % 4 or not 0 <= address <= MASK:
                raise ValueError("Region base must be a word-aligned 32-bit address")
        if len(self.code) > 1024:
            raise ValueError("Program exceeds its region")
        handler = trap_handler(self.handler_pc, self.completion_pc) if self.handler is None else self.handler
        if len(handler) > 1024:
            raise ValueError("Handler exceeds its region")
        bootstrap = constant(30, self.handler_pc)
        distance = (self.program_pc - self.reset - 16 + (1 << 31)) % (1 << 32) - (1 << 31)
        if not -(1 << 20) <= distance < 1 << 20:
            raise ValueError("Program exceeds the bootstrap jump range")
        bootstrap += [csr(0, 0x305, 30, 1), immediate(30, 0, 0),
                      jump(0, distance)]
        reserved = ((self.reset, len(bootstrap) * 4), (self.program_pc, 4096),
                    (self.handler_pc, 4096), (self.completion_pc, 4))
        for index, (address, size) in enumerate(reserved):
            for other, other_size in reserved[index + 1:]:
                if ((address - other) & MASK) < other_size or ((other - address) & MASK) < size:
                    raise ValueError("Executable regions overlap")
        image = {}
        for name, region in (("bootstrap", {(self.reset + 4 * i) & MASK: word for i, word in enumerate(bootstrap)}),
                             ("program", {(self.program_pc + 4 * i) & MASK: word for i, word in enumerate(self.code)}),
                             ("handler", {(self.handler_pc + 4 * i) & MASK: word for i, word in enumerate(handler)}),
                             ("completion", {self.completion_pc: jump(0, 0)}), ("data", self.data)):
            for address, word in region.items():
                if address % 4 or not 0 <= address <= MASK or not 0 <= word <= MASK:
                    raise ValueError(f"Invalid {name} word")
                if name == "data" and any(((address - base) & MASK) < size for base, size in reserved):
                    raise ValueError("Data exceeds its region")
                if address in image:
                    raise ValueError(f"Overlapping {name} word")
                image[address] = word
        if any(address % 4 or not 0 <= address <= MASK or
               any(((address - base) & MASK) < size for base, size in reserved) for address in self.signature):
            raise ValueError("Signature exceeds its data region")
        return image


def reset_cases(reset):
    program, handler, completion = ((reset + offset) & MASK for offset in (0x1000, 0x2000, 0x3000))
    reserved = ((reset, 20), (program, 4096), (handler, 4096), (completion, 4))
    data = next(address for address in range(0x4000, 0x18000, 0x4000)
                if all(((address + lane - base) & MASK) >= size
                       for lane in range(0, 0x200, 4) for base, size in reserved))
    record = data + 0x100
    layout = {"reset": reset, "program_pc": program, "handler_pc": handler, "completion_pc": completion}
    code = constant(3, data) + [immediate(1, 0, 42), store(1, 3), 0x00000117, store(2, 3, 4), BREAK]
    pc = (program + 24) & MASK
    signature = {data: 42, data + 4: (program + 16) & MASK,
                 record: pc, record + 4: 3, record + 8: pc, record + 12: 0x1800}
    result = [Case("reset_entry", code, signature=signature,
                   handler=trap_handler(handler, completion, record), **layout)]
    if reset > MASK - 16:
        code = constant(3, data) + [immediate(1, 0, 63), store(1, 3), BREAK]
        pc = (program + 16) & MASK
        result.append(Case("reset_pc_wrap", code, signature={data: 63, record: pc, record + 8: pc},
                           handler=trap_handler(handler, completion, record), **layout))
    code = constant(3, data) + [immediate(1, 0, 8), csr(0, 0x300, 1, 1), csr(0, 0x340, 17, 5), 0x73,
                               csr(4, 0x300), store(4, 3), csr(5, 0x341), store(5, 3, 4),
                               csr(6, 0x340), store(6, 3, 8)]
    code.append(jump(0, completion - program - len(code) * 4))
    handler_code = trap_handler(handler, completion, record)[:-1]
    handler_code += [csr(26, 0x341), immediate(26, 26, 4), csr(0, 0x341, 26, 1), MRET]
    signature = {data: 0x1888, data + 4: (program + 24) & MASK, data + 8: 17,
                 record: (program + 20) & MASK, record + 4: 11, record + 8: 0,
                 record + 12: 0x1880, record + 16: 17}
    result.append(Case("reset_csr_trap", code, signature=signature, handler=handler_code,
                       expected_causes=(11,), **layout))
    return result


def cases(reset=0):
    if reset:
        return reset_cases(reset)
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
             signature={256: 0, 260: PROGRAM_PC + 20}),
        Case("wrong_path_fault", [jump(1, 12), 0, store(1, 0, 256), BREAK], instruction_fault=PROGRAM_PC + 4),
        Case("load_fault_younger_store", [load(1, 0, 256), store(1, 0, 260), BREAK],
             data_fault=256, signature={260: 0}, expected_causes=(5,)),
        Case("load_fault_younger_branch", [load(1, 0, 256), jump(0, 8), store(1, 0, 260), BREAK],
             data_fault=256, signature={260: 0}, expected_causes=(5,)),
        Case("store_fault", [a(1, 0, 9), store(1, 0, 256), store(1, 0, 260), BREAK],
             data_fault=256, signature={256: 0, 260: 0}, expected_causes=(7,)),
        Case("fetch_fault", [a(1, 0, 9), store(1, 0, 256), BREAK],
             instruction_fault=PROGRAM_PC + 4, signature={256: 0}, expected_causes=(1,)),
        Case("load_misaligned", [load(0, 0, 257), BREAK], expected_causes=(4,)),
        Case("store_misaligned", [store(0, 0, 258), BREAK], expected_causes=(6,)),
        Case("jump_misaligned", [jump(1, 2), BREAK], expected_causes=(0,)),
        Case("jalr_misaligned", [a(1, 0, 3), a(2, 1, 0, 0x67), BREAK], expected_causes=(0,)),
        Case("branch_not_taken_misaligned", [a(1, 0, 1), branch(0, 1, 2), BREAK]),
        Case("branch_taken_misaligned", [branch(0, 0, 2), BREAK], expected_causes=(0,)),
        Case("load_zero_fault", [load(0, 0, 256), BREAK], data_fault=256, expected_causes=(5,)),
    ]
    for index, word in enumerate([0, 0xFFFFFFFF, 0x02000033, 0x40001033, 0x02001013,
                                  0x00001067, 0x00003003, 0x00003023, 0x00002063,
                                  0x30001073, 0x02005013, 0x40001013, 0x0000100F]):
        if word == 0x30001073:
            result.append(Case("csr_mstatus_zero_encoding", [word, store(0, 0, 256),
                jump(0, COMPLETION_PC - PROGRAM_PC - 8)], expected_causes=()))
        else:
            result.append(Case(f"illegal_{index}", [word, store(0, 0, 256)], expected_causes=(2,)))
    result += [
        Case("ecall", [0x00000073, store(0, 0, 256)], expected_causes=(11,)),
        Case("fence_order", [a(1, 0, 87), store(1, 0, 256), 0x0FF0000F,
             load(2, 0, 256), 0x8330000F, store(2, 0, 260), BREAK], signature={260: 87}),
        Case("narrow_lanes", [a(1, 0, -128), store(1, 0, 257, 0), a(1, 0, -1),
             store(1, 0, 258, 1), a(2, 0, 257, 3, 0), a(3, 0, 257, 3, 4),
             a(4, 0, 258, 3, 1), a(5, 0, 258, 3, 5), store(2, 0, 272),
             store(3, 0, 276), store(4, 0, 280), store(5, 0, 284), BREAK],
             data={256: 0x12345678}, signature={256: 0xFFFF8078, 272: 0xFFFFFF80,
                                              276: 128, 280: 0xFFFFFFFF, 284: 65535}),
        Case("half_load_misaligned", [a(1, 0, 257, 3, 1), BREAK], expected_causes=(4,)),
        Case("half_store_misaligned", [store(0, 0, 259, 1), BREAK], expected_causes=(6,)),
        Case("byte_fault", [a(1, 0, 257, 3, 4), BREAK], data_fault=257, expected_causes=(5,)),
        Case("byte_store_fault", [a(1, 0, -1), store(1, 0, 259, 0), BREAK],
             data_fault=259, data={256: 0x12345678}, signature={256: 0x12345678}, expected_causes=(7,)),
        Case("reset_entry", [a(1, 0, 42), store(1, 0, 256), BREAK], signature={256: 42}),
        Case("auipc", [0x80000097, a(1, 1, -1), store(1, 0, 256), BREAK], signature={256: 0x80000FFF}),
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
    result += csr_cases() + [nested_case()]
    for case in result:
        case.reset = reset
    return result
