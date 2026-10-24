# SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
# SPDX-License-Identifier: MIT
"""Build mixed instruction and fetch boundary cases from byte images."""

from dataclasses import dataclass, field

from programs import MASK, MRET, constant, csr, immediate, jump, store, trap_handler


@dataclass
class CompressedCase:
    name: str
    image: dict[int, int]
    reset: int
    program_pc: int
    handler_pc: int
    completion_pc: int
    signature: dict[int, int] = field(default_factory=dict)
    instruction_fault: int | None = None
    data_fault: int | None = None
    expected_causes: tuple[int, ...] = ()
    interrupt_schedule: tuple = ()
    expected_interrupts: tuple[int, ...] = ()
    enable_m: bool = False
    enable_c: bool = True

    def words(self):
        return dict(self.image)


def _image(regions):
    memory = {}
    for address, instructions in regions:
        for word, length in instructions:
            if length not in (2, 4) or not 0 <= word < 1 << (8 * length):
                raise ValueError("Invalid encoded instruction")
            for byte in word.to_bytes(length, "little"):
                if address in memory:
                    raise ValueError("Overlapping instruction bytes")
                memory[address] = byte
                address = (address + 1) & MASK
    words = {}
    for address, byte in memory.items():
        aligned = address & ~3
        words[aligned] = words.get(aligned, 0) | byte << (8 * (address & 3))
    return words


def _ci(family, rd, value, quadrant=1):
    value &= 63
    return family << 13 | (value >> 5) << 12 | rd << 7 | (value & 31) << 2 | quadrant


def _cj(offset, link=False):
    value = offset & 4095
    return (1 if link else 5) << 13 | ((value >> 11) & 1) << 12 | ((value >> 4) & 1) << 11 | \
        ((value >> 8) & 3) << 9 | ((value >> 10) & 1) << 8 | ((value >> 6) & 1) << 7 | \
        ((value >> 7) & 1) << 6 | ((value >> 1) & 7) << 3 | ((value >> 5) & 1) << 2 | 1


def _cb(register, offset, unequal=False):
    value = offset & 511
    return (7 if unequal else 6) << 13 | ((value >> 8) & 1) << 12 | \
        ((value >> 3) & 3) << 10 | (register - 8) << 7 | ((value >> 6) & 3) << 5 | \
        ((value >> 1) & 3) << 3 | ((value >> 5) & 1) << 2 | 1


class _Program:
    def __init__(self, address):
        self.address = address
        self.code = []
        self.labels = {}
        self.fixups = []

    @property
    def pc(self):
        return (self.address + sum(length for _, length in self.code)) & MASK

    def emit(self, raw, length=2):
        self.code.append((raw, length))

    def mark(self, name):
        if name in self.labels:
            raise ValueError("Duplicate program label")
        self.labels[name] = self.pc

    def relative(self, name, encoder):
        self.fixups.append((len(self.code), self.pc, name, encoder))
        self.emit(0)

    def address_of(self, register, name, offset=0):
        self.fixups.append((len(self.code), None, name, (register, offset)))
        self.code.extend(((0, 4), (0, 4)))

    def finish(self, completion):
        self.emit(jump(0, (completion - self.pc) & MASK), 4)
        for index, pc, name, encoder in self.fixups:
            if pc is None:
                register, offset = encoder
                self.code[index:index + 2] = [(word, 4) for word in constant(register, (self.labels[name] + offset) & MASK)]
            else:
                self.code[index] = (encoder((self.labels[name] - pc) & MASK), 2)
        return self.code


def cases(reset=0, enable_m=False):
    if type(reset) is not int or not 0 <= reset <= MASK or reset & 1:
        raise ValueError("Reset must be a halfword-aligned RV32 address")
    program, handler, completion = (((reset + offset) & MASK) & ~3 for offset in (0x1000, 0x2000, 0x3000))
    reserved = ((reset, 40), (program, 4096), (handler, 4096), (completion, 4))
    base = next(address for address in (0x100, 0x4000, 0x8000, 0xC000, 0x10000)
                if all(((address + lane - start) & MASK) >= size
                       for lane in range(0, 0x600, 4) for start, size in reserved))
    record = base + 0x100

    def build(name, instructions, signature, fault=None, start=program, handler_code=None, causes=None):
        boot = constant(30, handler) + [csr(0, 0x305, 30, 1), immediate(30, 0, 0)] + constant(9, base)
        boot += [jump(0, (start - reset - len(boot) * 4) & MASK)]
        if handler_code is None:
            handler_code = trap_handler(handler, completion, record)
        image = _image(((reset, [(word, 4) for word in boot]), (start, instructions),
                        (handler, [(word, 4) for word in handler_code]), (completion, [(jump(0, 0), 4)])))
        return CompressedCase(name, image, reset, start, handler, completion, signature,
                              instruction_fault=fault,
                              expected_causes=((1,) if fault is not None else ()) if causes is None else causes,
                              enable_m=enable_m)

    mixed = [(0x440D, 2), (immediate(11, 0, 23), 4), (0xC080, 2), (0x4088, 2),
             (0x147D, 2), (0xFC6D, 2), (0xC0C8, 2), (store(11, 9, 8), 4),
             (jump(0, (completion - program - 20) & MASK), 4)]
    result = [build("c_mixed_loop", mixed, {base: 1, base + 4: 1, base + 8: 23})]
    target = (program + 2) & MASK
    for name, instructions, fault, tval in (
            ("crossing_second_fault", [(immediate(8, 0, 99), 4), (store(8, 9), 4)],
             (program + 4) & MASK, (program + 4) & MASK),
            ("first_fault_upper", [(0x441D, 2), (store(8, 9), 4)], program, target)):
        handler_code = trap_handler(handler, completion, record)[:-1] + [store(8, 9, 4)]
        handler_code += [jump(0, (completion - handler - len(handler_code) * 4) & MASK)]
        result.append(build(name, instructions, {base: 0, base + 4: 0, record: target,
                                                record + 4: 1, record + 8: tval}, fault, target, handler_code))
    halfword = [(jump(1, 6), 4), (0x447D, 2), (0x441D, 2), (store(8, 9), 4),
                (store(1, 9, 4), 4), (0x2011, 2), (0x447D, 2), (store(1, 9, 8), 4),
                (store(8, 9, 12), 4), (jump(0, (completion - program - 28) & MASK), 4)]
    result.append(build("halfword_jump", halfword, {base: 7, base + 4: (program + 4) & MASK,
                                                   base + 8: (program + 18) & MASK, base + 12: 7}))

    arithmetic = _Program(program)
    arithmetic.emit(immediate(2, 9, 64), 4)
    immediate_steps = (
        (0x0040, 8, base + 68), (0x1FE0, 8, base + 1084),
        (_ci(2, 8, -32), 8, 0xFFFFFFE0), (_ci(0, 8, 31), 8, MASK),
        (_ci(0, 8, -32), 8, 0xFFFFFFDF), (_ci(2, 10, 31), None, None),
        (_ci(0, 10, 31, 2), 10, 0x80000000), (0x817D, 10, 1),
        (_ci(2, 10, -32), None, None), (0x8515, 10, MASK), (0x9901, 10, 0xFFFFFFE0),
        (_ci(3, 11, 31), 11, 0x1F000), (_ci(3, 11, -32), 11, 0xFFFE0000),
        (0x617D, 2, base + 560), (0x7101, 2, base + 48), (0x0001, None, None))
    signature = {}
    for word, register, value in immediate_steps:
        arithmetic.emit(word)
        if register is not None:
            offset = len(signature) * 4
            arithmetic.emit(store(register, 9, offset), 4)
            signature[base + offset] = value & MASK
    result.append(build("c_immediate_arithmetic", arithmetic.finish(completion), signature))

    registers = _Program(program)
    registers.emit(_ci(2, 10, 13))
    registers.emit(_ci(2, 11, 6))
    for index, word in enumerate((0x842A, 0x942E, 0x8C0D, 0x8C2D, 0x8C4D, 0x8C6D)):
        registers.emit(word)
        registers.emit(store(8, 9, index * 4), 4)
    result.append(build("c_register_arithmetic", registers.finish(completion),
                        dict(zip(range(base, base + 24, 4), (13, 19, 13, 11, 15, 6)))))

    memory = _Program(program)
    memory.emit(immediate(2, 9, 0x200), 4)
    memory.emit(immediate(12, 2, 0), 4)
    for word, length in ((_ci(2, 10, -1), 2), (0xDE68, 2), (0x5E6C, 2), (store(11, 9), 4),
                         (_ci(2, 10, 31), 2), (0xDFAA, 2), (0x50FE, 2), (store(1, 9, 4), 4),
                         (_ci(2, 10, -32), 2), (0xC02A, 2), (0x4F82, 2), (store(31, 9, 8), 4)):
        memory.emit(word, length)
    result.append(build("c_stack_memory", memory.finish(completion),
                        {base: MASK, base + 4: 31, base + 8: 0xFFFFFFE0,
                         base + 0x27C: MASK, base + 0x2FC: 31, base + 0x200: 0xFFFFFFE0}))

    control = _Program(program)
    control.emit(_ci(2, 8, 0))
    control.relative("equal", lambda offset: _cb(8, offset))
    control.emit(store(9, 9, 80), 4)
    control.mark("equal")
    control.relative("bad", lambda offset: _cb(8, offset, True))
    control.emit(_ci(2, 8, 1))
    control.relative("bad", lambda offset: _cb(8, offset))
    control.relative("unequal", lambda offset: _cb(8, offset, True))
    control.emit(store(9, 9, 80), 4)
    control.mark("unequal")
    control.relative("calls", _cj)
    control.emit(store(9, 9, 80), 4)
    control.mark("calls")
    control.address_of(12, "indirect", 1)
    control.emit(0x9602)
    control.mark("indirect_return")
    control.emit(store(1, 9), 4)
    control.relative("direct", lambda offset: _cj(offset, True))
    control.mark("direct_return")
    control.emit(store(1, 9, 4), 4)
    control.relative("done", _cj)
    control.mark("indirect")
    control.emit(_ci(2, 10, 7))
    control.emit(store(10, 9, 8), 4)
    control.emit(0x8082)
    control.mark("direct")
    control.emit(_ci(2, 10, 11))
    control.emit(store(10, 9, 12), 4)
    control.emit(0x8082)
    control.mark("bad")
    control.emit(store(9, 9, 80), 4)
    control.mark("done")
    result.append(build("c_control_flow", control.finish(completion),
                        {base: control.labels["indirect_return"], base + 4: control.labels["direct_return"],
                         base + 8: 7, base + 12: 11, base + 80: 0}))

    result.append(build("c_ebreak", [(0x0001, 2), (0x9002, 2), (store(9, 9), 4)],
                        {base: 0, record: (program + 2) & MASK, record + 4: 3,
                         record + 8: (program + 2) & MASK}, causes=(3,)))

    hints = _Program(program)
    for register in range(1, 32):
        if register != 9:
            hints.emit(immediate(register, 0, register * 7), 4)
    for word in (0x0005, 0x0081, 0x4001, 0x6005, 0x8001, 0x8401,
                 0x0002, 0x0006, 0x0082, 0x8006, 0x9006):
        hints.emit(word)
    for register in range(32):
        hints.emit(store(register, 9, register * 4), 4)
    result.append(build("c_hints", hints.finish(completion),
                        {base + register * 4: base if register == 9 else register * 7 for register in range(32)}))

    illegal = (("addi4spn_zero", 0x0000, 2), ("reserved_quadrant_zero", 0x8000, 2),
               ("floating_memory", 0x2000, 2), ("lui_zero", 0x6001, 2),
               ("addi16sp_zero", 0x6101, 2), ("custom_srli", 0x9001, 2),
               ("custom_srai", 0x9401, 2), ("rv64_arithmetic", 0x9C01, 2),
               ("reserved_arithmetic", 0x9C41, 2), ("custom_slli", 0x1002, 2),
               ("lwsp_zero", 0x4002, 2), ("jr_zero", 0x8002, 2),
               ("floating_stack", 0x2002, 2), ("long_48", 0x89AB001F, 4),
               ("long_64", 0x89AB003F, 4), ("long_80", 0x89AB007F, 4),
               ("long_reserved", 0x89AB707F, 4))
    for name, raw, length in illegal:
        for offset in (0, 2):
            pc = (program + offset) & MASK
            result.append(build(f"c_illegal_{name}_{offset}", [(raw, length), (store(9, 9), 4)],
                                {base: 0, record: pc, record + 4: 2, record + 8: raw},
                                start=pc, causes=(2,)))
    result.append(build("c_long_no_third_word", [(0x89AB003F, 4), (0xFFFF, 2)],
                        {record: (program + 2) & MASK, record + 4: 2, record + 8: 0x89AB003F},
                        fault=(program + 8) & MASK, start=(program + 2) & MASK, causes=(2,)))

    for name, prefix, trapped, length, cause in (
            ("c_mret_halfword", [], 0x9002, 2, 3),
            ("c_mret_crossing", [(0x0001, 2)], 0x00000073, 4, 11)):
        resume = _Program(program)
        for word, size in prefix:
            resume.emit(word, size)
        trap_pc = resume.pc
        resume.emit(trapped, length)
        return_pc = resume.pc
        resume.emit(_ci(2, 8, 9))
        resume.emit(store(8, 9), 4)
        resume.emit(csr(10, 0x341), 4)
        resume.emit(store(10, 9, 4), 4)
        handler_code = trap_handler(handler, completion, record)[:-1]
        handler_code += [csr(26, 0x341), immediate(26, 26, length), csr(0, 0x341, 26, 1), MRET]
        result.append(build(name, resume.finish(completion),
                            {base: 9, base + 4: return_pc, record: trap_pc,
                             record + 4: cause, record + 8: trap_pc if cause == 3 else 0},
                            handler_code=handler_code, causes=(cause,)))

    for wide in (False, True):
        modify = _Program(program)
        replacement = immediate(10, 0, 17) if wide else _ci(2, 10, 17)
        modify.address_of(12, "replacement")
        for word in constant(13, replacement):
            modify.emit(word, 4)
        if wide:
            modify.emit(store(13, 12, 0, 1), 4)
            modify.emit(immediate(13, 13, 16, funct3=5), 4)
            modify.emit(store(13, 12, 2, 1), 4)
            modify.emit(0x0001)
        else:
            modify.emit(0x0001)
            modify.emit(store(13, 12, 0, 1), 4)
        fence_pc = modify.pc
        modify.emit(0x0000100F, 4)
        modify.mark("replacement")
        modify.emit(immediate(10, 0, 3) if wide else _ci(2, 10, 3), 4 if wide else 2)
        modify.emit(store(10, 9), 4)
        assert fence_pc & 3 == 2 and modify.labels["replacement"] & 3 == 2
        result.append(build("c_fence_crossing_code" if wide else "c_fence_crossing_halfword",
                            modify.finish(completion),
                            {base: 17, (fence_pc + 2) & MASK: (replacement & 0xFFFF) << 16}))

    redirect = _Program(program)
    redirect.relative("target", _cj)
    redirect.emit(immediate(8, 0, 31), 4)
    redirect.emit(store(8, 9), 4)
    redirect.emit(0x0001)
    redirect.mark("target")
    redirect.emit(_ci(2, 8, 9))
    redirect.emit(store(8, 9, 4), 4)
    result.append(build("c_redirect_crossing_fault", redirect.finish(completion),
                        {base: 0, base + 4: 9}, fault=(program + 4) & MASK, causes=()))

    boot = [0x00000417, csr(10, 0x305)] + constant(9, base)
    boot += [store(8, 9), store(10, 9, 4)] + constant(30, handler) + [csr(0, 0x305, 30, 1)]
    boot += [jump(0, (program - reset - len(boot) * 4) & MASK)]
    reset_image = _image(((reset, [(word, 4) for word in boot]),
                          (program, [(0x0001, 2), (jump(0, (completion - program - 2) & MASK), 4)]),
                          (handler, [(word, 4) for word in trap_handler(handler, completion, record)]),
                          (completion, [(jump(0, 0), 4)])))
    result.append(CompressedCase("c_reset_vector", reset_image, reset, program, handler, completion,
                                 {base: reset, base + 4: reset & ~3}, enable_m=enable_m))

    for wide in (False, True):
        interrupted = _Program(program)
        for word in constant(1, 1 << 11) + [csr(0, 0x304, 1, 1), csr(0, 0x300, 8, 6)]:
            interrupted.emit(word, 4)
        interrupted.emit(_ci(2, 8, 0))
        interrupted.emit(_ci(2, 11, 0))
        trigger = interrupted.pc
        interrupted.relative("resume", _cj)
        interrupted.emit(store(9, 9, 20), 4)
        interrupted.mark("resume")
        target = interrupted.pc
        assert target & 3 == 2
        interrupted.emit(immediate(8, 0, 17) if wide else _ci(2, 8, 17), 4 if wide else 2)
        interrupted.emit(_ci(0, 11, 1))
        for word in (store(8, 9), store(11, 9, 4), csr(10, 0x300), store(10, 9, 8)):
            interrupted.emit(word, 4)
        handler_code = trap_handler(handler, completion, record)[:-1] + [store(8, 9, 12), MRET]
        case = build("c_irq_crossing" if wide else "c_irq_halfword", interrupted.finish(completion),
                     {base: 17, base + 4: 1, base + 8: 0x1888, base + 12: 0, base + 20: 0,
                      record: target, record + 4: 0x8000000B, record + 8: 0, record + 12: 0x1880},
                     handler_code=handler_code, causes=())
        case.interrupt_schedule = (("R", trigger, 4), ("N", 1, 0))
        case.expected_interrupts = (0x8000000B,)
        result.append(case)
    return result
