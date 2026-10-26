# SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
# SPDX-License-Identifier: MIT
"""Build protected instruction programs with fixed signatures and trap records."""

from dataclasses import dataclass, field

from programs import MASK, MRET, WFI, add, branch, constant, csr, immediate, jump, multiply, store


PROGRAM = 0x1000
HANDLER = 0x2000
COMPLETION = 0x3000
SIGNATURE = 0x500
TRAPS = 0x800


@dataclass
class ProtectedCase:
    name: str
    image: dict[int, int]
    signature: dict[int, int]
    expected_causes: tuple[int, ...]
    reset: int = 0
    enable_m: bool = False
    enable_c: bool = False
    enable_a: bool = False
    enable_zba: bool = False
    enable_zbb: bool = False
    enable_zbs: bool = False
    protected_mode: bool = True
    program_pc: int = PROGRAM
    handler_pc: int = HANDLER
    completion_pc: int = COMPLETION
    instruction_fault: int | None = None
    data_fault: int | None = None
    interrupt_schedule: tuple = ()
    expected_interrupts: tuple[int, ...] = ()
    expected_memory_machine: dict[int, bool] = field(default_factory=dict)

    def words(self):
        return dict(self.image)


class Program:
    def __init__(self, start=PROGRAM):
        self.start = start
        self.code = []
        self.traps = []

    @property
    def pc(self):
        return (self.start + sum(length for _, length in self.code)) & MASK

    def emit(self, *words, length=4):
        address = self.pc
        self.code.extend((word, length) for word in words)
        return address

    def load(self, register, value):
        return self.emit(*constant(register, value))

    def write_csr(self, address, value):
        self.load(1, value)
        return self.emit(csr(0, address, 1, 1))

    def save(self, register, offset=0):
        return self.emit(store(register, 20, offset))

    def trap(self, word, cause, value=0, status=0):
        address = self.emit(word)
        self.traps.append((cause, address, value, status))
        return address


def _image(regions, data):
    memory = {}
    for base, code in regions:
        address = base
        for word, length in code:
            if length not in (2, 4) or not 0 <= word < 1 << (length * 8):
                raise ValueError("Invalid protected instruction encoding")
            for value in word.to_bytes(length, "little"):
                if address in memory:
                    raise ValueError("Protected program regions overlap")
                memory[address] = value
                address = (address + 1) & MASK
    for address, value in data.items():
        if address & 3 or not 0 <= value <= MASK:
            raise ValueError("Invalid protected data word")
        for lane in range(4):
            if address + lane in memory:
                raise ValueError("Protected data overlaps instructions")
            memory[address + lane] = value >> (8 * lane) & 255
    result = {}
    for address, value in memory.items():
        result[address & ~3] = result.get(address & ~3, 0) | value << (8 * (address & 3))
    return result


def _handler(count, recovery=(), resume_step=4):
    code = Program(HANDLER)
    code.load(25, TRAPS)
    code.emit(immediate(24, 31, 4, funct3=1), add(25, 25, 24))
    for index, address in enumerate((0x341, 0x342, 0x343, 0x300)):
        code.emit(csr(26, address), store(26, 25, index * 4))
    code.emit(csr(26, 0x342), immediate(31, 31, 1), immediate(28, 0, count), branch(31, 28, 24 + len(recovery) * 4))
    code.emit(*recovery)
    code.emit(csr(27, 0x341), branch(26, 0, 8, funct3=4), immediate(27, 27, resume_step), csr(0, 0x341, 27, 1), MRET)
    code.load(27, COMPLETION)
    code.emit(immediate(0, 27, 0, opcode=0x67))
    return code.code


def _case(name, program, signature, *, reset=0, enable_m=False, enable_c=False, enable_a=False, enter_user=True,
          status=0, setup=(), data=None, schedule=(), memory_machine=None, grant_all=True, recovery=(),
          resume_step=4, initial_registers=(), enable_zba=False, enable_zbb=False, enable_zbs=False):
    boot = Program(reset)
    boot.write_csr(0x305, HANDLER)
    boot.load(20, SIGNATURE)
    for register, value in initial_registers:
        boot.load(register, value)
    if grant_all:
        boot.write_csr(0x3BF, 0x1FFFFFFF)
        boot.write_csr(0x3A3, 0x1F000000)
    for address, value in setup:
        boot.write_csr(address, value)
    if enter_user:
        boot.write_csr(0x341, program.start)
        boot.write_csr(0x300, status)
        boot.emit(MRET)
    else:
        boot.load(1, program.start)
        boot.emit(immediate(0, 1, 0, opcode=0x67))
    expected = {SIGNATURE + address: value for address, value in signature.items()}
    for index, (cause, pc, value, saved_status) in enumerate(program.traps):
        for offset, result in enumerate((pc, cause, value, saved_status)):
            expected[TRAPS + index * 16 + offset * 4] = result
    image = _image(((reset, boot.code), (program.start, program.code),
                    (HANDLER, _handler(len(program.traps), recovery, resume_step)), (COMPLETION, [(0x6F, 4)])), data or {})
    return ProtectedCase(name, image, expected, tuple(item[0] for item in program.traps if item[0] < 1 << 31),
                         reset=reset, enable_m=enable_m, enable_c=enable_c, enable_a=enable_a,
                         enable_zba=enable_zba, enable_zbb=enable_zbb, enable_zbs=enable_zbs,
                         program_pc=program.start,
                         interrupt_schedule=tuple(schedule), expected_interrupts=tuple(item[0] for item in program.traps if item[0] >> 31),
                         expected_memory_machine=memory_machine or {})


def _pmp_setup(entries):
    setup = [(0x3B0 + index, address) for index, (address, _) in sorted(entries.items())]
    for group in range(4):
        value = sum(entries.get(group * 4 + lane, (0, 0))[1] << (lane * 8) for lane in range(4))
        setup.append((0x3A0 + group, value))
    return tuple(setup)


def _pmp_entry_cases(common):
    result = []
    for index in range(16):
        for mode in range(4):
            excluded = {index, index - 1} if mode == 1 else {index}
            code, signature = [entry for entry in range(16) if entry not in excluded][:2]
            entries = {code: (0x5FF, 0x1D), signature: (0x15F, 0x1B),
                       index: (0x101 if mode == 1 else 0x100, 3 | (mode << 3))}
            if mode == 1 and index:
                entries[index - 1] = (0x100, 0)
            program = Program()
            program.load(2, 0x400)
            program.emit(immediate(10, 0, 42), immediate(11, 0, 77))
            write = store(10, 2, 0)
            read = immediate(11, 2, 0, opcode=3, funct3=2)
            if mode:
                program.emit(write, read)
            else:
                program.trap(write, 7, 0x400)
                program.trap(read, 5, 0x400)
            program.save(11)
            program.emit(immediate(2, 2, 16))
            program.trap(read, 5, 0x410)
            program.save(11, 4)
            program.trap(0x73, 8)
            value = 42 if mode else 77
            case = _case(f"protected_pmp_entry_{index}_{mode}", program, {0: value, 4: value},
                         setup=_pmp_setup(entries), data={0x400: 7}, grant_all=False, **common)
            case.signature[0x400] = 42 if mode else 7
            result.append(case)
    return result


def _pmp_lock_cases(common):
    result = []
    for index in range(16):
        for mode in range(4):
            address = 0x110 if mode == 1 else 0x100
            config = 0x87 | (mode << 3)
            entries = {index: (address, config)}
            if index:
                entries[index - 1] = (0x100, 0)
            group, lane = divmod(index, 4)
            program = Program()
            program.write_csr(0x3A0 + group, 0)
            program.emit(csr(10, 0x3A0 + group))
            program.save(10)
            program.write_csr(0x3B0 + index, 0xFFFFFFFF)
            program.emit(csr(10, 0x3B0 + index))
            program.save(10, 4)
            expected = {0: config << (lane * 8), 4: address}
            if index:
                program.write_csr(0x3AF + index, 0x200)
                program.emit(csr(10, 0x3AF + index))
                program.save(10, 8)
                expected[8] = 0x100 if mode == 1 else 0x200
                previous_group, previous_lane = divmod(index - 1, 4)
                program.write_csr(0x3A0 + previous_group, 7 << (previous_lane * 8))
                program.emit(csr(10, 0x3A0 + previous_group))
                program.save(10, 12)
                expected[12] = (7 << (previous_lane * 8)) | ((config << (lane * 8)) if previous_group == group else 0)
            program.write_csr(0x3A0 + group, 0xFFFFFFFF)
            program.emit(csr(10, 0x3A0 + group))
            program.save(10, 16)
            expected[16] = (0x9F9F9F9F & ~(255 << (lane * 8))) | (config << (lane * 8))
            program.trap(0x73, 11, status=0x1800)
            result.append(_case(f"protected_pmp_lock_{index}_{mode}", program, expected,
                                enter_user=False, setup=_pmp_setup(entries), grant_all=False, **common))
    return result


def _pmp_permission_cases(common):
    result = []
    for machine in (False, True):
        for locked in (False, True):
            for permission in range(8):
                config = 0x10 | (int(locked) << 7) | permission
                effective = permission if permission & 1 else permission & ~2
                readable = machine and not locked or bool(effective & 1)
                writable = machine and not locked or bool(effective & 2)
                status = 0x1800 if machine else 0
                program = Program()
                program.load(2, 0x400)
                program.emit(immediate(10, 0, 55), immediate(11, 0, 42))
                read = immediate(10, 2, 0, opcode=3, funct3=2)
                write = store(11, 2)
                if readable:
                    program.emit(read)
                else:
                    program.trap(read, 5, 0x400, status)
                program.save(10)
                if writable:
                    program.emit(write)
                else:
                    program.trap(write, 7, 0x400, status)
                if readable:
                    program.emit(read)
                else:
                    program.trap(read, 5, 0x400, status)
                program.save(10, 4)
                program.trap(0x73, 11 if machine else 8, status=status)
                final = 42 if writable else 73
                case = _case(f"protected_pmp_data_{int(machine)}_{int(locked)}_{permission}", program,
                             {0: 73 if readable else 55, 4: final if readable else 55}, enter_user=not machine,
                             setup=_pmp_setup({0: (0x100, config), 1: (0x5FF, 0x1D), 2: (0x15F, 0x1B)}),
                             data={0x400: 73}, grant_all=False, **common)
                case.signature[0x400] = final
                result.append(case)
                program = Program()
                executable = machine and not locked or bool(effective & 4)
                program.emit(immediate(10, 0, 42))
                program.save(10)
                if executable:
                    program.trap(0x73, 11 if machine else 8, status=status)
                else:
                    program.traps.append((1, program.start, program.start, status))
                result.append(_case(f"protected_pmp_execute_{int(machine)}_{int(locked)}_{permission}", program,
                                    {0: 42 if executable else 0}, enter_user=not machine,
                                    setup=_pmp_setup({0: (0x400, config), 1: (0x5FF, 0x1D), 2: (0x15F, 0x1B)}),
                                    grant_all=False, **common))
    return result


def _pmp_boundary_cases(common):
    result = []
    program = Program()
    expected = {}
    for index in range(16):
        program.write_csr(0x3B0 + index, MASK)
        program.emit(csr(10, 0x3B0 + index))
        program.save(10, index * 4)
        expected[index * 4] = 0x3FFFFFFF
    for group in range(4):
        program.write_csr(0x3A0 + group, MASK)
        program.emit(csr(10, 0x3A0 + group))
        program.save(10, 64 + group * 4)
        expected[64 + group * 4] = 0x9F9F9F9F
    program.trap(0x73, 11, status=0x1800)
    result.append(_case("protected_pmp_warl", program, expected, enter_user=False, grant_all=False, **common))
    for machine in (False, True):
        program = Program()
        program.emit(immediate(10, 0, 42))
        program.save(10)
        if machine:
            program.trap(0x73, 11, status=0x1800)
        else:
            program.traps.append((1, program.start, program.start, 0))
        result.append(_case(f"protected_pmp_no_match_{int(machine)}", program, {0: 42 if machine else 0},
                            enter_user=not machine, grant_all=False, **common))
    program = Program()
    program.load(2, 0x400)
    program.emit(immediate(11, 0, 42), immediate(10, 2, 0, opcode=3, funct3=2))
    program.save(10)
    program.trap(store(11, 2), 7, 0x400)
    program.emit(immediate(10, 2, 4, opcode=3, funct3=2))
    program.save(10, 4)
    program.emit(store(11, 2, 4), immediate(10, 2, 4, opcode=3, funct3=2))
    program.save(10, 8)
    program.trap(0x73, 8)
    case = _case("protected_pmp_lowest_overlap", program, {0: 73, 4: 19, 8: 42},
                 setup=_pmp_setup({0: (0x100, 0x11), 1: (0x103, 0x1B), 2: (0x5FF, 0x1D), 3: (0x15F, 0x1B)}),
                 data={0x400: 73, 0x404: 19}, grant_all=False, **common)
    case.signature.update({0x400: 73, 0x404: 42})
    result.append(case)
    for reversed_range in (False, True):
        program = Program()
        program.load(2, 0x400)
        program.emit(immediate(10, 2, 0, opcode=3, funct3=2))
        program.save(10)
        program.trap(0x73, 8)
        entries = {0: (0x101 if reversed_range else 0x100, 0), 1: (0x100, 0x08),
                   2: (0x100, 0x11), 3: (0x5FF, 0x1D), 4: (0x15F, 0x1B)}
        result.append(_case(f"protected_pmp_empty_tor_{int(reversed_range)}", program, {0: 73},
                            setup=_pmp_setup(entries), data={0x400: 73}, grant_all=False, **common))
    program = Program()
    program.load(2, 0xFFFFFFFC)
    program.load(11, 0x12345678)
    program.emit(store(11, 2), immediate(10, 2, 0, opcode=3, funct3=2))
    program.save(10)
    program.trap(0x73, 8)
    case = _case("protected_pmp_full_address_space", program, {0: 0x12345678}, **common)
    case.signature[0xFFFFFFFC] = 0x12345678
    result.append(case)
    program = Program()
    program.trap(0x73, 8)
    program.emit(immediate(10, 0, 7))
    program.save(10)
    program.trap(0x73, 8)
    recovery = (*constant(24, 0x401), csr(0, 0x3B0, 24, 1),
                *constant(24, 0x1B1C), csr(0, 0x3A0, 24, 1))
    result.append(_case("protected_pmp_grant_refetch", program, {0: 7},
                        setup=_pmp_setup({0: (0x400, 0x14), 1: (0x15F, 0x1B)}),
                        grant_all=False, recovery=recovery, **common))
    program = Program()
    program.load(2, 0x400)
    program.emit(immediate(10, 2, 0, opcode=3, funct3=2))
    program.save(10)
    target = program.pc + 24
    program.write_csr(0x3B0, target >> 2)
    program.write_csr(0x3A0, 0x90)
    assert program.pc == target
    program.emit(store(10, 20, 4))
    program.traps.append((1, target, target, 0x1800))
    result.append(_case("protected_pmp_revoke_refetch", program, {0: 73, 4: 0}, enter_user=False,
                        data={0x400: 73}, grant_all=False, **common))
    return result


def _pmp_compressed_cases(common):
    if not common["enable_c"]:
        return []
    result = []
    for crossing in (False, True):
        program = Program(PROGRAM + 2)
        program.emit(immediate(10, 0, 42) if crossing else 0x451D, length=4 if crossing else 2)
        program.save(10)
        program.traps.append((1, PROGRAM + 2, PROGRAM + 4 if crossing else PROGRAM + 2, 0))
        entries = {0: (0x400, 0x14 if crossing else 0x10), 1: (0x15F, 0x1B)}
        result.append(_case("protected_c_second_word_denied" if crossing else "protected_c_first_word_denied", program,
                            {0: 0}, setup=_pmp_setup(entries), grant_all=False, **common))
    program = Program(PROGRAM + 2)
    program.emit(0x451D, length=2)
    program.save(10)
    program.trap(0x73, 8)
    result.append(_case("protected_c_halfword_mret", program, {0: 7}, **common))
    program = Program(PROGRAM + 2)
    program.emit(immediate(10, 0, 42))
    program.save(10)
    program.trap(0x73, 8)
    entries = {0: (0x400, 0x14), 1: (0x401, 0x14), 2: (0x5FF, 0x1D), 3: (0x15F, 0x1B)}
    result.append(_case("protected_c_two_word_entries", program, {0: 42},
                        setup=_pmp_setup(entries), grant_all=False, **common))
    program = Program()
    program.emit(0x451D, 0xC02A, length=2)
    denied_pc = program.emit(store(10, 20, 4))
    program.traps.append((1, denied_pc, denied_pc, 0))
    result.append(_case("protected_c_region_end", program, {0: 7, 4: 0},
                        setup=_pmp_setup({0: (0x400, 0x14), 1: (0x15F, 0x1B)}),
                        initial_registers=((2, SIGNATURE),), grant_all=False, **common))
    program = Program(PROGRAM + 2)
    program.traps.append((1, program.pc, program.pc + 2, 0))
    program.emit(immediate(10, 0, 42))
    program.save(10)
    program.trap(0x73, 8)
    recovery = (*constant(24, 0x1B1D14), csr(0, 0x3A0, 24, 1))
    result.append(_case("protected_c_grant_retry", program, {0: 42},
                        setup=_pmp_setup({0: (0x400, 0x14), 1: (0x5FF, 0), 2: (0x15F, 0x1B)}),
                        recovery=recovery, resume_step=0, grant_all=False, **common))
    for crossing in (False, True):
        program = Program()
        trigger = program.emit(jump(0, 6))
        program.emit(0x557D, length=2)
        target = program.pc
        program.traps.append((0x8000000B, target, 0, 0))
        program.emit(immediate(10, 10, 7) if crossing else 0x051D, length=4 if crossing else 2)
        program.save(10)
        program.trap(0x73, 8)
        result.append(_case("protected_c_irq_crossing" if crossing else "protected_c_irq_halfword", program,
                            {0: 7}, setup=((0x304, 2048),),
                            schedule=(("R", trigger, 4), ("N", 1, 0)), **common))
    return result


def _user_compute(common):
    program = Program()
    expected = {}

    def save(value, register=10):
        offset = len(expected) * 4
        program.save(register, offset)
        expected[offset] = value

    program.load(1, 0xFFFFFFF3)
    program.load(2, 5)
    for funct3, funct7, value in ((0, 0, 0xFFFFFFF8), (0, 32, 0xFFFFFFEE), (1, 0, 0xFFFFFE60),
                                 (2, 0, 1), (3, 0, 0), (4, 0, 0xFFFFFFF6), (5, 0, 0x07FFFFFF),
                                 (5, 32, 0xFFFFFFFF), (6, 0, 0xFFFFFFF7), (7, 0, 1)):
        program.emit((funct7 << 25) | (2 << 20) | (1 << 15) | (funct3 << 12) | (10 << 7) | 0x33)
        save(value)
    for funct3, operand, value in ((0, 7, 0xFFFFFFFA), (2, 7, 1), (3, 7, 0), (4, 7, 0xFFFFFFF4),
                                   (6, 7, 0xFFFFFFF7), (7, 7, 3), (1, 3, 0xFFFFFF98),
                                   (5, 3, 0x1FFFFFFE), (5, 0x403, 0xFFFFFFFE)):
        program.emit(immediate(10, 1, operand, funct3=funct3))
        save(value)
    address = program.emit(0x00000517)
    save(address)
    for funct3, first, second, value in ((0, 1, 1, 2), (0, 1, 2, 3), (1, 1, 2, 2), (1, 1, 1, 3),
                                         (4, 1, 2, 2), (4, 2, 1, 3), (5, 2, 1, 2), (5, 1, 2, 3),
                                         (6, 2, 1, 2), (6, 1, 2, 3), (7, 1, 2, 2), (7, 2, 1, 3)):
        program.emit(immediate(10, 0, 0), branch(first, second, 8, funct3=funct3),
                     immediate(10, 10, 1), immediate(10, 10, 2))
        save(value)
    program.load(2, 0x400)
    for funct3, offset, value in ((0, 3, 0xFFFFFF80), (4, 3, 128), (1, 2, 0xFFFF80FF),
                                 (5, 2, 0x80FF), (2, 0, 0x80FF7F01)):
        program.emit(immediate(10, 2, offset, opcode=3, funct3=funct3))
        save(value)
    program.emit(immediate(11, 0, -128), store(11, 2, 1, funct3=0),
                 immediate(11, 0, -1), store(11, 2, 2, funct3=1),
                 immediate(10, 2, 0, opcode=3, funct3=2))
    save(0xFFFF8001)
    program.load(11, 0x12345678)
    program.emit(store(11, 2, 4), immediate(10, 2, 4, opcode=3, funct3=2))
    save(0x12345678)
    schedule = ()
    if common["enable_m"]:
        for operation, left, right, value in ((4, 0xFFFFFFF3, 5, 0xFFFFFFFE), (0, 12345, 37, 456765),
                                              (1, 0xFFFFFFF3, 5, 0xFFFFFFFF), (2, 0xFFFFFFFE, MASK, 0xFFFFFFFE),
                                              (3, MASK, MASK, 0xFFFFFFFE), (5, MASK, 3, 0x55555555),
                                              (6, 0xFFFFFFF3, 5, 0xFFFFFFFD), (7, MASK, 7, 3)):
            program.load(1, left)
            program.load(2, right)
            if operation == 4:
                program.traps.append((0x8000000B, program.pc, 0, 0))
            program.emit(multiply(10, 1, 2, operation))
            save(value)
        schedule = (("M", 1, 4, 1), ("N", 1, 0))
    if common["enable_c"]:
        program.load(2, 0x480)
        program.emit(0x440D, 0x147D, 0xFC7D, length=2)
        save(0, 8)
        program.emit(0x44B5, 0xC026, 0x4502, 0x9526, length=2)
        save(26)
    program.trap(0x73, 8)
    case = _case("protected_user_compute", program, expected, setup=((0x304, 2048),),
                 data={0x400: 0x80FF7F01, 0x404: 0}, schedule=schedule, **common)
    case.signature.update({0x400: 0xFFFF8001, 0x404: 0x12345678})
    if common["enable_c"]:
        case.signature[0x480] = 13
    return case


def _mret_machine_mprv(common):
    program = Program()
    program.load(2, 0x400)
    program.write_csr(0x300, 0x21800)
    target = program.pc + 16
    program.write_csr(0x341, target)
    program.emit(MRET)
    assert program.pc == target
    program.emit(csr(10, 0x300))
    save_status = program.save(10)
    read = program.emit(immediate(11, 2, 0, opcode=3, funct3=2), immediate(12, 0, 99))
    denied = program.trap(store(12, 2), 7, 0x400, 0x21800)
    save_value = program.save(11, 4)
    program.write_csr(0x300, 0)
    program.trap(0x73, 11, status=0x1800)
    case = _case("protected_mret_machine_mprv", program, {0: 0x20080, 4: 73}, enter_user=False,
                 setup=((0x3B0, 0x100), (0x3A0, 0x11)), data={0x400: 73},
                 memory_machine={save_status: False, read: False, denied: False, save_value: False}, **common)
    case.signature[0x400] = 73
    return case


def cases(reset=0, enable_m=False, enable_c=False, *, enable_a=False, enable_zba=False, enable_zbb=False, enable_zbs=False):
    if type(reset) is not int or not 0 <= reset <= MASK or reset % (2 if enable_c else 4):
        raise ValueError("Protected reset must satisfy instruction alignment")
    common = dict(reset=reset, enable_m=enable_m, enable_c=enable_c, enable_a=enable_a,
                  enable_zba=enable_zba, enable_zbb=enable_zbb, enable_zbs=enable_zbs)
    result = []
    program = Program()
    program.load(1, MASK)
    for index, operation in enumerate((1, 2, 3, 5, 6, 7)):
        program.emit(csr(10, 0x30A, 31 if operation & 4 else 1, operation))
        program.save(10, index * 8)
        program.emit(csr(10, 0x30A))
        program.save(10, index * 8 + 4)
    for index, operation in enumerate((2, 3, 6, 7)):
        program.emit(csr(10, 0x30A, 0, operation))
        program.save(10, 48 + index * 4)
    program.emit(csr(0, 0x30A, 1, 1), csr(0, 0x30A, 31, 5), csr(10, 0x30A))
    program.save(10, 64)
    program.trap(0x73, 11, status=0x1800)
    result.append(_case("protected_menvcfg_zero", program, dict.fromkeys(range(0, 68, 4), 0),
                        enter_user=False, **common))
    for operation in (1, 2, 3, 5, 6, 7):
        program = Program()
        program.load(1, MASK)
        program.emit(immediate(10, 0, 55))
        for source in (1, 0):
            word = csr(10, 0x30A, source, operation)
            program.trap(word, 2, word)
        program.save(10)
        program.trap(0x73, 8)
        result.append(_case(f"protected_user_menvcfg_{operation}", program, {0: 55}, **common))
    program = Program()
    word = csr(10, 0x31A)
    program.trap(word, 2, word, 0x1800)
    program.trap(0x73, 11, status=0x1800)
    result.append(_case("protected_menvcfgh_absent", program, {}, enter_user=False, **common))
    program = Program()
    for index, value in enumerate((0, 0x800, 0x1000, 0x1800, 0xFFFFFFFF)):
        program.write_csr(0x300, value)
        program.emit(csr(10, 0x300))
        program.save(10, index * 4)
    program.emit(csr(10, 0x301))
    program.save(10, 20)
    program.write_csr(0x306, 0xFFFFFFFF)
    program.emit(csr(10, 0x306))
    program.save(10, 24)
    program.write_csr(0x300, 0)
    program.trap(0x73, 11, status=0x1800)
    result.append(_case("protected_status_warl", program,
                        {0: 0, 4: 0x1800, 8: 0x1800, 12: 0x1800, 16: 0x221888,
                         20: 0x40100100 | (int(enable_m) << 12) | (int(enable_c) << 2) | int(enable_a) |
                         (2 if enable_zba and enable_zbb and enable_zbs else 0), 24: 7},
                        enter_user=False, **common))
    for name, status in (("protected_user_ecall", 0), ("protected_mret_clears_mprv", 1 << 17)):
        program = Program()
        program.emit(immediate(10, 0, 42))
        address = program.save(10)
        program.trap(0x73, 8)
        result.append(_case(name, program, {0: 42}, status=status, memory_machine={address: False}, **common))
    for denied in (False, True):
        program = Program()
        program.emit(immediate(10, 0, 55))
        program.load(2, 0x400)
        program.write_csr(0x300, 1 << 17)
        load = immediate(10, 2, 0, opcode=3, funct3=2)
        load_pc = program.trap(load, 5, 0x400, 0x21800) if denied else program.emit(load)
        if denied:
            program.write_csr(0x300, 0)
        save_pc = program.save(10)
        if not denied:
            program.write_csr(0x300, 0)
        program.trap(0x73, 11, status=0x1800)
        result.append(_case("protected_mprv_denied" if denied else "protected_mprv_data", program, {0: 55 if denied else 73},
                            enter_user=False, setup=((0x3B0, 0x100), (0x3A0, 0x14 if denied else 0x11)),
                            data={0x400: 73}, memory_machine={load_pc: False, save_pc: denied}, **common))
    for address in (0x300, 0x301, 0x304, 0x306, 0x340, 0x3A0, 0x3BF, 0xB00, 0xF11, 0x7B0):
        program = Program()
        program.emit(immediate(10, 0, 55))
        instruction = csr(10, address)
        program.trap(instruction, 2, instruction)
        program.save(10)
        program.trap(0x73, 8)
        result.append(_case(f"protected_user_csr_{address:x}", program, {0: 55}, **common))
    for name, instruction, status in (("protected_user_mret", MRET, 0), ("protected_user_wfi_tw", WFI, 1 << 21)):
        program = Program()
        program.trap(instruction, 2, instruction, status)
        program.emit(immediate(10, 0, 77))
        program.save(10)
        program.trap(0x73, 8, status=status)
        result.append(_case(name, program, {0: 77}, status=status, **common))
    counter_setup = ((0x320, 5), (0xB00, 0x89ABCDEF), (0xB80, 0x12345678), (0xB02, 0x76543210), (0xB82, 0x0FEDCBA9))
    for address, expected in ((0xC00, 0x89ABCDEF), (0xC80, 0x12345678), (0xC01, 0),
                              (0xC81, 1), (0xC02, 0x76543210), (0xC82, 0x0FEDCBA9)):
        for enabled in (False, True):
            program = Program()
            program.emit(immediate(10, 0, 55))
            instruction = csr(10, address)
            if enabled:
                program.emit(instruction)
                if address == 0xC01:
                    program.emit(csr(11, address), (10 << 20) | (11 << 15) | (3 << 12) | (10 << 7) | 0x33)
            else:
                program.trap(instruction, 2, instruction)
            program.save(10)
            program.trap(0x73, 8)
            setup = (*counter_setup, (0x306, (1 << (address & 3)) if enabled else (7 ^ (1 << (address & 3)))))
            result.append(_case(f"protected_user_counter_{address:x}_{int(enabled)}", program,
                                {0: expected if enabled else 55}, setup=setup, **common))
    for waiting in (False, True):
        program = Program()
        if waiting:
            trigger = program.emit(WFI)
        else:
            program.emit(immediate(10, 0, 7))
            trigger = program.emit(jump(0, 8))
            program.emit(immediate(10, 0, 99))
        cause = 0x80000007 if waiting else 0x8000000B
        program.traps.append((cause, program.pc, 0, 0))
        program.emit(immediate(10, 10, 1))
        program.save(10)
        program.trap(0x73, 8)
        result.append(_case("protected_user_wfi_irq" if waiting else "protected_user_irq_mie_zero", program,
                            {0: 1 if waiting else 8}, setup=((0x304, 128 if waiting else 2048),),
                            schedule=(("R", trigger, 2 if waiting else 4), ("N", 1, 0)), **common))
    result.extend(_pmp_entry_cases(common))
    result.extend(_pmp_lock_cases(common))
    result.extend(_pmp_permission_cases(common))
    result.extend(_pmp_boundary_cases(common))
    result.extend(_pmp_compressed_cases(common))
    result.append(_user_compute(common))
    result.append(_mret_machine_mprv(common))
    from bit_operations import ENCODINGS, encode
    from bit_programs import FIXED
    subset = int(enable_zba) | (int(enable_zbb) << 1) | (int(enable_zbs) << 2)
    for name, (_, extension, _) in ENCODINGS.items():
        program = Program()
        program.load(1, 0x80000001)
        program.emit(immediate(2, 0, 31))
        word = encode(name, shift=7)
        if subset & extension:
            program.emit(word)
        else:
            program.trap(word, 2, word)
        saved = program.save(3)
        program.trap(0x73, 8)
        result.append(_case(f"protected_bit_{name}", program,
                           {0: FIXED[name] if subset & extension else 0},
                           memory_machine={saved: False}, **common))
    return result
