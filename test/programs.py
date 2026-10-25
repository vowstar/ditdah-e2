# SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
# SPDX-License-Identifier: MIT
"""Executable words and architectural expectations for the implemented subset."""

from dataclasses import dataclass, field
import random


def immediate(rd, rs1, value, opcode=0x13, funct3=0):
    return ((value & 4095) << 20) | (rs1 << 15) | (funct3 << 12) | (rd << 7) | opcode


def add(rd, a, b):
    return (b << 20) | (a << 15) | (rd << 7) | 0x33


def multiply(rd, a, b, operation=0):
    return (1 << 25) | (b << 20) | (a << 15) | (operation << 12) | (rd << 7) | 0x33


def store(rs2, rs1, offset=0, funct3=2):
    return (((offset & 4095) >> 5) << 25) | (rs2 << 20) | (rs1 << 15) | (funct3 << 12) | ((offset & 31) << 7) | 0x23


def branch(a, b, offset, unequal=False, funct3=None):
    f3 = int(unequal) if funct3 is None else funct3
    return (((offset >> 12) & 1) << 31) | (((offset >> 5) & 63) << 25) | (b << 20) | (a << 15) | (f3 << 12) | (((offset >> 1) & 15) << 8) | (((offset >> 11) & 1) << 7) | 0x63


def jump(rd, offset):
    return (((offset >> 20) & 1) << 31) | (((offset >> 1) & 1023) << 21) | (((offset >> 11) & 1) << 20) | (((offset >> 12) & 255) << 12) | (rd << 7) | 0x6F


BREAK = 0x00100073
MRET = 0x30200073
WFI = 0x10500073
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


def csr_cases(enable_m=False, enable_c=False, *, enable_a=False, enable_zba=False, enable_zbb=False, enable_zbs=False):
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
    misa = 0x40000100 | (int(enable_m) << 12) | (int(enable_c) << 2) | int(enable_a) | (2 if enable_zba and enable_zbb and enable_zbs else 0)
    expected = ((0x1800, misa, 0, 0, 0, 0, 0, 0, 0, 0),
                (0x1888, misa, 0x888, 0xFFFFFFFC, 0, 0xFFFFFFFF,
                 0xFFFFFFFE if enable_c else 0xFFFFFFFC, 0xFFFFFFFF, 0xFFFFFFFF, 0),
                (0x1880, misa, 0x80, 0x5A5, 0, 0x5A5, 0x5A4, 0x5A5, 0x5A5, 0))
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
    for address in (0x302, 0x306, 0xB01, 0xC03, 0x7B0):
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


def finish(code):
    return code + [jump(0, COMPLETION_PC - PROGRAM_PC - len(code) * 4)]


def interrupt_cases():
    code = constant(1, 1 << 11) + [csr(0, 0x304, 1, 1), csr(0, 0x300, 8, 6),
                                  immediate(2, 0, 99), store(2, 0, 256)]
    result = [Case("irq_external", finish(code), expected_causes=(),
                   interrupt_schedule=(("C", 0, 4), ("N", 1, 0)), expected_interrupts=(0x8000000B,),
                   signature={256: 0, TRAP_RECORD: PROGRAM_PC + 16,
                              TRAP_RECORD + 4: 0x8000000B, TRAP_RECORD + 8: 0, TRAP_RECORD + 12: 0x1880})]
    code = [immediate(1, 0, 128), csr(0, 0x304, 1, 1), csr(0, 0x300, 8, 6), WFI]
    result.append(Case("wfi_timer", finish(code), expected_causes=(),
                       interrupt_schedule=(("R", PROGRAM_PC + 12, 2), ("N", 1, 0)),
                       expected_interrupts=(0x80000007,),
                       signature={TRAP_RECORD: PROGRAM_PC + 16, TRAP_RECORD + 4: 0x80000007}))
    code = [immediate(1, 0, 128), csr(0, 0x304, 1, 1), WFI,
            csr(2, 0x344), store(2, 0, 256), csr(3, 0x300), store(3, 0, 260)]
    result.append(Case("wfi_local_wake", finish(code), expected_causes=(),
                       interrupt_schedule=(("R", PROGRAM_PC + 8, 2),), signature={256: 128, 260: 0x1800}))
    for clear_global in (True, False):
        clear = csr(0, 0x300, 8, 7) if clear_global else csr(0, 0x304, 0, 1)
        code = constant(1, 1 << 11) + [csr(0, 0x304, 1, 1), csr(0, 0x300, 8, 6), clear,
            WFI if clear_global else immediate(0, 0, 0), immediate(2, 0, 77), store(2, 0, 256),
            csr(3, 0x300), store(3, 0, 260), csr(4, 0x304), store(4, 0, 264)]
        result.append(Case(f"irq_disable_{'global' if clear_global else 'source'}", finish(code),
            expected_causes=(), interrupt_schedule=(("R", PROGRAM_PC + 16, 4),),
            signature={256: 77, 260: 0x1800 if clear_global else 0x1808, 264: 0x800 if clear_global else 0}))
    for pending in range(8):
        for enabled in range(8):
            for global_enable in range(2):
                pending_bits = sum(((pending >> lane) & 1) << bit for lane, bit in enumerate((3, 7, 11)))
                enable_bits = sum(((enabled >> lane) & 1) << bit for lane, bit in enumerate((3, 7, 11)))
                code = constant(1, enable_bits) + [csr(0, 0x304, 1, 1), csr(2, 0x344), store(2, 0, 256),
                    csr(3, 0x304), store(3, 0, 260), csr(0, 0x300, global_enable * 8, 5),
                    immediate(4, 0, 77), store(4, 0, 264)]
                active = pending & enabled if global_enable else 0
                cause = 0x8000000B if active & 4 else 0x80000003 if active & 1 else 0x80000007
                signature = {256: pending_bits, 260: enable_bits, 264: 0 if active else 77}
                if active:
                    signature.update({TRAP_RECORD: PROGRAM_PC + 32, TRAP_RECORD + 4: cause})
                result.append(Case(f"irq_matrix_p{pending}_e{enabled}_g{global_enable}", finish(code),
                    expected_causes=(), signature=signature, interrupt_schedule=(("C", 0, pending), ("N", 1, 0)),
                    expected_interrupts=(cause,) if active else ()))
    for global_enable in (0, 1):
        code = [immediate(1, 0, 128), csr(0, 0x304, 1, 1), csr(0, 0x300, global_enable * 8, 5), WFI,
                csr(2, 0x344), store(2, 0, 256)]
        signature = {TRAP_RECORD: PROGRAM_PC + 16} if global_enable else {256: 0x88}
        result.append(Case(f"wfi_masked_until_timer_{global_enable}", finish(code), expected_causes=(),
            interrupt_schedule=(("C", 0, 1), ("C", 500, 3), ("N", 1, 0)), signature=signature,
            expected_interrupts=(0x80000007,) if global_enable else ()))
    code = [immediate(1, 0, 128), csr(0, 0x304, 1, 1), WFI, csr(2, 0x344), store(2, 0, 256)]
    result.append(Case("wfi_pending_local", finish(code), expected_causes=(),
                       interrupt_schedule=(("C", 0, 2),), signature={256: 128}))
    handler = constant(25, TRAP_RECORD) + [csr(24, 0x340), immediate(27, 24, 2, funct3=1), add(25, 25, 27),
        csr(26, 0x342), store(26, 25), csr(26, 0x341), store(26, 25, 32),
        immediate(24, 24, 1), csr(0, 0x340, 24, 1), MRET]
    code = constant(1, 0x888) + [csr(0, 0x304, 1, 1), csr(0, 0x300, 8, 6),
        immediate(4, 0, 77), store(4, 0, 256), csr(5, 0x340), store(5, 0, 260)]
    result.append(Case("irq_priority_mret", finish(code), handler=handler, expected_causes=(),
        interrupt_schedule=(("C", 0, 7), ("N", 1, 3), ("N", 2, 2), ("N", 3, 0)),
        expected_interrupts=(0x8000000B, 0x80000003, 0x80000007),
        signature={256: 77, 260: 3, TRAP_RECORD: 0x8000000B, TRAP_RECORD + 4: 0x80000003,
                   TRAP_RECORD + 8: 0x80000007, TRAP_RECORD + 32: PROGRAM_PC + 16,
                   TRAP_RECORD + 36: PROGRAM_PC + 16, TRAP_RECORD + 40: PROGRAM_PC + 16}))
    for source, cause in ((1, 3), (2, 7), (4, 11), (0, 11)):
        routine = HANDLER_PC + 128
        handler = [0] * 32
        for slot in (0, 3, 7, 11):
            handler[slot] = jump(0, routine - HANDLER_PC - slot * 4)
        handler += trap_handler(routine, COMPLETION_PC)
        code = constant(1, HANDLER_PC | 1) + [csr(0, 0x305, 1, 1)]
        if source:
            code += constant(2, 1 << cause) + [csr(0, 0x304, 2, 1), csr(0, 0x300, 8, 6)]
        else:
            code += [0x73]
        signature = {TRAP_RECORD: PROGRAM_PC + (28 if source else 12),
                     TRAP_RECORD + 4: (1 << 31) | cause if source else cause}
        result.append(Case(f"irq_vector_{source}", finish(code), handler=handler, signature=signature,
            expected_causes=() if source else (11,), interrupt_schedule=(("C", 0, source), ("N", 1, 0)),
            expected_interrupts=((1 << 31) | cause,) if source else ()))
    for write in (False, True):
        for failed in (False, True):
            code = constant(1, 1 << 11) + [csr(0, 0x304, 1, 1), csr(0, 0x300, 8, 6), immediate(2, 0, 23)]
            memory_pc = PROGRAM_PC + len(code) * 4
            code += [store(2, 0, 256) if write else immediate(2, 0, 256, 3, 2), store(2, 0, 260)]
            cause = 7 if write else 5
            signature = {256: 17 if failed or not write else 23, 260: 0,
                TRAP_RECORD: memory_pc if failed else memory_pc + 4,
                TRAP_RECORD + 4: cause if failed else 0x8000000B,
                TRAP_RECORD + 8: 256 if failed else 0}
            result.append(Case(f"irq_{'store' if write else 'load'}_{'fault' if failed else 'wait'}", finish(code),
                data={256: 17}, data_fault=256 if failed else None, signature=signature,
                expected_causes=(cause,) if failed else (), expected_interrupts=() if failed else (0x8000000B,),
                interrupt_schedule=(("D", 256, 4), ("N", 1, 0))))
    for seed in range(4):
        rng = random.Random(seed)
        code = constant(1, 0x888) + [csr(0, 0x304, 1, 1), csr(0, 0x300, 8, 6)]
        schedule, causes, signature = [], [], {}
        for index in range(8):
            value, mask = rng.randrange(2048), rng.randrange(1, 8)
            pc = PROGRAM_PC + len(code) * 4
            code += [immediate(2, 0, value), store(2, 0, 256 + index * 4), csr(3, 0xC00)]
            schedule += [("R", pc, mask) if index % 2 else ("D", 256 + index * 4, mask), ("N", index + 1, 0)]
            causes.append(0x8000000B if mask & 4 else 0x80000003 if mask & 1 else 0x80000007)
            signature[256 + index * 4] = value
        result.append(Case(f"irq_random_{seed}", finish(code), handler=[csr(26, 0x342), csr(27, 0x341), MRET],
            signature=signature, expected_causes=(), expected_interrupts=tuple(causes), interrupt_schedule=tuple(schedule)))
    return result


def counter_cases():
    code = [csr(0, 0x320, 5, 5), immediate(1, 0, -1), csr(0, 0xB00, 1, 1),
            csr(0, 0xB80, 7, 5), csr(0, 0xB02, 11, 5), csr(0, 0xB82, 3, 5)]
    addresses = (0xB00, 0xB80, 0xC00, 0xC80, 0xB02, 0xB82, 0xC02, 0xC82, 0xC01, 0xC81)
    for index, address in enumerate(addresses):
        code += [csr(2, address), store(2, 0, 256 + index * 4)]
    values = (MASK, 7, MASK, 7, 11, 3, 11, 3)
    result = [Case("counter_aliases", finish(code), expected_causes=(),
                   signature=dict(zip(range(256, 288, 4), values)))]
    code = [csr(0, 0x320, 1, 5), csr(0, 0xB02, 0, 1), csr(2, 0xC02),
            csr(3, 0xB02), csr(4, 0xB02, 0, 1), csr(5, 0xC02)]
    code += [store(index, 0, 256 + (index - 2) * 4) for index in range(2, 6)]
    result.append(Case("counter_self_retirement", finish(code), expected_causes=(),
                       signature={256: 0, 260: 1, 264: 2, 268: 0}))
    code = [csr(0, 0x320, 5, 5), csr(0, 0xB02, 10, 5), csr(0, 0x320, 1, 5),
            csr(2, 0xC02), csr(0, 0x320, 5, 5), csr(3, 0xC02), store(2, 0, 256), store(3, 0, 260)]
    result.append(Case("counter_inhibit_boundary", finish(code), expected_causes=(), signature={256: 10, 260: 12}))
    code = [immediate(1, 0, -1), csr(0, 0x320, 1, 1), csr(2, 0x320), store(2, 0, 256),
            csr(0, 0x320, 2, 5), csr(3, 0x320), store(3, 0, 260)]
    result.append(Case("counter_inhibit_warl", finish(code), expected_causes=(), signature={256: 5, 260: 0}))
    code = [csr(0, 0x320, 1, 5), immediate(1, 0, -2), immediate(2, 0, -1),
            csr(0, 0xB82, 2, 1), csr(0, 0xB02, 1, 1), csr(3, 0xC02), csr(4, 0xC82), csr(5, 0xC02),
            store(3, 0, 256), store(4, 0, 260), store(5, 0, 264)]
    result.append(Case("counter_instret_wrap", finish(code), expected_causes=(),
                       signature={256: 0xFFFFFFFE, 260: MASK, 264: 0}))
    code = [csr(0, 0x320, 5, 5), immediate(1, 0, -1), csr(0, 0xB80, 1, 1), csr(0, 0xB00, 1, 1),
            csr(0, 0x320, 4, 5), immediate(0, 0, 0), csr(2, 0xC80), csr(3, 0xC00),
            store(2, 0, 256), store(3, 0, 260)]
    result.append(Case("counter_cycle_wrap", finish(code), expected_causes=(), signature={256: 0}))
    handler = [csr(26, 0xC02), store(26, 0, 256), csr(27, 0x341), immediate(27, 27, 4),
               csr(0, 0x341, 27, 1), MRET]
    code = [csr(0, 0x320, 1, 5), csr(0, 0xB02, 0, 1), 0x73, csr(2, 0xC02), store(2, 0, 260)]
    result.append(Case("counter_exception", finish(code), handler=handler, expected_causes=(11,), signature={256: 0, 260: 6}))
    code = constant(1, 1 << 11) + [csr(0, 0x304, 1, 1), csr(0, 0x300, 8, 6), csr(0, 0x320, 1, 5),
        csr(0, 0xB02, 0, 1), csr(2, 0xC02), store(2, 0, 260)]
    result.append(Case("counter_interrupt", finish(code), handler=[csr(26, 0xC02), store(26, 0, 256), MRET],
        expected_causes=(), expected_interrupts=(0x8000000B,), signature={256: 0, 260: 3},
        interrupt_schedule=(("R", PROGRAM_PC + 20, 4), ("N", 1, 0))))
    code = [immediate(1, 0, 128), csr(0, 0x304, 1, 1), csr(0, 0x320, 1, 5),
        csr(0, 0xB02, 0, 1), WFI, csr(2, 0xC02), store(2, 0, 256)]
    result.append(Case("counter_wfi", finish(code), expected_causes=(), signature={256: 1},
                       interrupt_schedule=(("R", PROGRAM_PC + 16, 2),)))
    code = [csr(2, 0xC81), csr(3, 0xC01), csr(4, 0xC81), branch(2, 4, -12, True),
            store(3, 0, 256), store(4, 0, 260)]
    result.append(Case("counter_time", finish(code), expected_causes=()))
    code = [immediate(1, 0, -1)]
    addresses = (*range(0xB03, 0xB20), *range(0xB83, 0xBA0), *range(0x323, 0x340))
    for index, address in enumerate(addresses):
        code += [csr(0, address, 1, 1), csr(2, address), store(2, 0, 256 + index * 4)]
    result.append(Case("counter_hpm_zero", finish(code), expected_causes=(),
                       signature=dict.fromkeys(range(256, 256 + len(addresses) * 4, 4), 0)))
    for address in (0xC00, 0xC80, 0xC01, 0xC81, 0xC02, 0xC82):
        word = csr(0, address, 0, 1)
        result.append(Case(f"counter_readonly_{address:x}", [word], expected_causes=(2,),
                           signature={TRAP_RECORD + 4: 2, TRAP_RECORD + 8: word}))
    return result


M_RESULTS = (
    (0, 0, (0, 0, 0, 0, MASK, MASK, 0, 0)),
    (1, 0, (0, 0, 0, 0, MASK, MASK, 1, 1)),
    (MASK, 0, (0, 0, 0, 0, MASK, MASK, MASK, MASK)),
    (0x80000000, MASK, (0x80000000, 0, 0x80000000, 0x7FFFFFFF, 0x80000000, 0, 0, 0x80000000)),
    (MASK, 2, (0xFFFFFFFE, MASK, MASK, 1, 0, 0x7FFFFFFF, MASK, 1)),
    (0x80000000, 2, (0, MASK, MASK, 1, 0xC0000000, 0x40000000, 0, 0)),
    (0x7FFFFFFF, MASK, (0x80000001, MASK, 0x7FFFFFFE, 0x7FFFFFFE, 0x80000001, 0, 0, 0x7FFFFFFF)),
    (0xFFFFFFF9, 3, (0xFFFFFFEB, MASK, MASK, 2, 0xFFFFFFFE, 0x55555553, MASK, 0)),
    (7, 0xFFFFFFFD, (0xFFFFFFEB, MASK, 6, 6, 0xFFFFFFFE, 0, 1, 7)),
    (0x80000000, 0x80000000, (0, 0x40000000, 0xC0000000, 0x40000000, 1, 1, 0, 0)),
    (MASK, MASK, (1, 0, MASK, 0xFFFFFFFE, 1, 1, 0, 0)),
)


def multiply_cases():
    result = []
    for operation, name in enumerate(("mul", "mulh", "mulhsu", "mulhu", "div", "divu", "rem", "remu")):
        code, signature = [], {}
        for index, (left, right, expected) in enumerate(M_RESULTS):
            code += constant(1, left) + constant(2, right)
            code += [multiply(3, 1, 2, operation), store(3, 0, 256 + index * 4)]
            signature[256 + index * 4] = expected[operation]
        result.append(Case(f"m_{name}_boundaries", finish(code), signature=signature, expected_causes=(), enable_m=True))
    code = [immediate(1, 0, -7), immediate(2, 0, 3), multiply(3, 1, 2),
            multiply(4, 3, 2, 4), multiply(5, 2, 4), immediate(6, 5, 22), multiply(7, 6, 2)]
    code += [store(register, 0, 256 + 4 * (register - 3)) for register in range(3, 8)]
    result.append(Case("m_forward_dependencies", finish(code), expected_causes=(), enable_m=True,
                       signature=dict(zip(range(256, 276, 4), (0xFFFFFFEB, 0xFFFFFFF9, 0xFFFFFFEB, 1, 3)))))
    code = [immediate(1, 0, 768, 3, 2), immediate(2, 0, 772, 3, 2), multiply(3, 1, 2, 4),
            immediate(4, 0, 776, 3, 2), multiply(5, 3, 4), immediate(6, 0, 780, 3, 2),
            multiply(7, 4, 6, 6), store(3, 0, 256), store(5, 0, 260), store(7, 0, 264)]
    result.append(Case("m_load_dependencies", finish(code), expected_causes=(), enable_m=True,
                       data={768: 0xFFFFFFF9, 772: 3, 776: 7, 780: 0xFFFFFFFD},
                       signature={256: 0xFFFFFFFE, 260: 0xFFFFFFF2, 264: 1}))
    code = [immediate(1, 0, -7), csr(0, 0x340, 1, 1), csr(2, 0x340),
            immediate(3, 0, 3), multiply(4, 2, 3), store(4, 0, 256)]
    result.append(Case("m_csr_dependency", finish(code), expected_causes=(), enable_m=True,
                       signature={256: 0xFFFFFFEB}))
    code = [immediate(1, 0, -7), immediate(2, 0, 3), multiply(0, 1, 2), multiply(3, 0, 2),
            multiply(0, 1, 0, 4), multiply(4, 1, 0, 6), store(0, 0, 256), store(3, 0, 260), store(4, 0, 264)]
    result.append(Case("m_zero_register", finish(code), expected_causes=(), enable_m=True,
                       signature={256: 0, 260: 0, 264: 0xFFFFFFF9}))
    code = [immediate(1, 0, 7), immediate(2, 0, 3), immediate(3, 0, 55),
            multiply(3, 1, 2), store(3, 0, 256)]
    handler = trap_handler()[:-1] + [store(3, 0, 260)]
    handler += [jump(0, COMPLETION_PC - HANDLER_PC - len(handler) * 4)]
    fault_pc = PROGRAM_PC + 12
    result.append(Case("m_fetch_fault", code, instruction_fault=fault_pc, handler=handler,
                       expected_causes=(1,), enable_m=True,
                       signature={256: 0, 260: 55, TRAP_RECORD: fault_pc,
                                  TRAP_RECORD + 4: 1, TRAP_RECORD + 8: fault_pc}))
    for write in (False, True):
        memory = store(1, 0, 768) if write else immediate(8, 0, 768, 3, 2)
        code = [immediate(1, 0, 7), immediate(2, 0, 3), memory, multiply(3, 1, 2),
                store(3, 0, 256), multiply(4, 3, 2, 4), store(4, 0, 260)]
        result.append(Case(f"m_older_{'store' if write else 'load'}_wait", finish(code), expected_causes=(), enable_m=True,
                           data={768: 11}, signature={256: 21, 260: 7, 768: 7 if write else 11}))
        code = [immediate(1, 0, 7), immediate(2, 0, 3), immediate(3, 0, 55), immediate(4, 0, 66),
                memory, multiply(3, 1, 2), store(3, 0, 264), multiply(4, 1, 2, 4)]
        handler = trap_handler()[:-1] + [store(3, 0, 256), store(4, 0, 260)]
        handler += [jump(0, COMPLETION_PC - HANDLER_PC - len(handler) * 4)]
        result.append(Case(f"m_older_{'store' if write else 'load'}_fault", code, data_fault=768, handler=handler,
                           expected_causes=(7 if write else 5,), enable_m=True, data={768: 11},
                           signature={256: 55, 260: 66, 264: 0, 768: 11, TRAP_RECORD: PROGRAM_PC + 16}))
    for operation, name, delay, left, expected in ((0, "mul", 1, 7, 33), (4, "div", 17, 7, 3),
                                                  (1, "mulh", 33, MASK - 6, 0), (0, "result", 34, 7, 33)):
        code = constant(5, 1 << 11) + [csr(0, 0x304, 5, 1), csr(0, 0x300, 8, 6)]
        code += constant(1, left) + constant(2, 3) + [immediate(20, 0, 0)]
        pc = PROGRAM_PC + len(code) * 4
        code += [multiply(3, 1, 2, operation), store(3, 0, 256), store(20, 0, 260)]
        handler = constant(25, TRAP_RECORD)
        handler += [csr(26, 0x341), store(26, 25), csr(26, 0x342), store(26, 25, 4),
                    immediate(20, 20, 1), immediate(1, 0, 11), MRET]
        result.append(Case(f"m_interrupt_restart_{name}", finish(code), handler=handler,
                           expected_causes=(), expected_interrupts=(0x8000000B,), enable_m=True,
                           interrupt_schedule=(("M", 1, 4, delay), ("N", 1, 0)),
                           signature={256: expected, 260: 1, TRAP_RECORD: pc, TRAP_RECORD + 4: 0x8000000B}))
    return result


def multiply_reset_case(layout):
    base = next(iter(layout.signature))
    left, right, values = M_RESULTS[7]
    code = constant(31, base) + constant(1, left) + constant(2, right)
    for operation in range(8):
        code += [multiply(3, 1, 2, operation), store(3, 31, operation * 4)]
    code += [jump(0, layout.completion_pc - layout.program_pc - len(code) * 4)]
    return Case("m_reset_arithmetic", code, signature={base + 4 * index: value for index, value in enumerate(values)},
                reset=layout.reset, program_pc=layout.program_pc, handler_pc=layout.handler_pc,
                completion_pc=layout.completion_pc, expected_causes=(), enable_m=True)


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
    interrupt_schedule: tuple[tuple[str, int, int] | tuple[str, int, int, int], ...] = ()
    expected_interrupts: tuple[int, ...] = ()
    enable_m: bool = False
    enable_c: bool = False
    enable_a: bool = False
    enable_zba: bool = False
    enable_zbb: bool = False
    enable_zbs: bool = False

    def words(self):
        for entry in self.interrupt_schedule:
            kind, key, mask, *delay = entry
            if kind not in ("C", "D", "R", "N", "M") or key < 0 or not 0 <= mask <= 7:
                raise ValueError("Invalid interrupt schedule")
            if (kind in ("D", "R") and key > MASK) or (kind in ("N", "M") and not key):
                raise ValueError("Invalid interrupt trigger")
            if (kind == "M" and (len(delay) != 1 or delay[0] < 1)) or (kind != "M" and delay):
                raise ValueError("Invalid arithmetic interrupt delay")
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


def cases(reset=0, enable_m=False, enable_c=False, *, enable_a=False, enable_zba=False, enable_zbb=False, enable_zbs=False):
    compressed = []
    if enable_c:
        from compressed_programs import cases as compressed_cases
        compressed = compressed_cases(reset, enable_m)
        for case in compressed:
            case.enable_a = enable_a
            case.enable_zba, case.enable_zbb, case.enable_zbs = enable_zba, enable_zbb, enable_zbs
        if reset % 4:
            return compressed
    if reset:
        result = reset_cases(reset)
        if enable_m:
            result.append(multiply_reset_case(result[0]))
        for case in result:
            case.enable_m = enable_m
            case.enable_c = enable_c
            case.enable_a = enable_a
            case.enable_zba, case.enable_zbb, case.enable_zbs = enable_zba, enable_zbb, enable_zbs
        return result + compressed
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
                                  0x30001073, 0x02005013, 0x40001013, 0x0000200F]):
        if word == 0x02000033 and enable_m:
            result.append(Case("m_zero_encoding", finish([word, store(0, 0, 256)]),
                               signature={256: 0}, expected_causes=()))
        elif word == 0x30001073:
            result.append(Case("csr_mstatus_zero_encoding", [word, store(0, 0, 256),
                jump(0, COMPLETION_PC - PROGRAM_PC - 8)], expected_causes=()))
        else:
            result.append(Case(f"illegal_{index}", [word, store(0, 0, 256)], expected_causes=(2,)))
    result += [
        Case("fence_i_fields", finish([a(1, 0, 67), 0xFFFF9F8F, store(1, 0, 256),
             0x0000100F, 0x0000100F]), signature={256: 67}, expected_causes=()),
        Case("fence_i_older_fault", [load(1, 0, 256), 0x0000100F, store(1, 0, 260)],
             data_fault=256, signature={260: 0, TRAP_RECORD: PROGRAM_PC}, expected_causes=(5,)),
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
    target_pc = PROGRAM_PC + 24
    replacement = a(3, 0, 77)
    code = constant(1, target_pc) + constant(2, replacement)
    code += [store(2, 1), 0x0000100F, a(3, 0, 99), store(3, 0, 256)]
    result.append(Case("fence_i_self_modify", finish(code),
                       signature={256: 77}, expected_causes=()))
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
    from bit_programs import cases as bit_cases
    result += bit_cases(enable_zba, enable_zbb, enable_zbs)
    result += csr_cases(enable_m, enable_c, enable_a=enable_a, enable_zba=enable_zba, enable_zbb=enable_zbb, enable_zbs=enable_zbs) + [nested_case()] + interrupt_cases() + counter_cases()
    if enable_m:
        result += multiply_cases()
    if enable_c:
        result = [case for case in result if case.name not in
                  ("jump_misaligned", "jalr_misaligned", "branch_taken_misaligned")]
    for case in result:
        case.reset = reset
        case.enable_m = enable_m
        case.enable_c = enable_c
        case.enable_a = enable_a
        case.enable_zba = enable_zba
        case.enable_zbb = enable_zbb
        case.enable_zbs = enable_zbs
    return result + compressed
