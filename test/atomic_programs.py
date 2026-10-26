# SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
# SPDX-License-Identifier: MIT
"""Fixed programs for atomic instructions and competing SRAM accesses."""

from dataclasses import dataclass, field

from programs import add, branch, constant, csr, immediate, jump, store
from debug_programs import WAIT_RETIRE, WRITE, POLL, IDLE, register, memory
from bit_operations import encode as bit_instruction


RAM = 0x20000000
SIGNATURE = RAM + 0x100
DONE = 0xF00
HANDLER = 0x800
HALT_ATOMIC = 11
FUNCTIONS = {"lr.w": 2, "sc.w": 3, "amoswap.w": 1, "amoadd.w": 0, "amoxor.w": 4,
             "amoand.w": 12, "amoor.w": 8, "amomin.w": 16, "amomax.w": 20,
             "amominu.w": 24, "amomaxu.w": 28}


def atomic(name, rd, address, operand=0, aq=False, rl=False):
    assert name in FUNCTIONS and all(0 <= value < 32 for value in (rd, address, operand))
    return ((FUNCTIONS[name] << 27) | (int(aq) << 26) | (int(rl) << 25) | (operand << 20) |
            (address << 15) | (2 << 12) | (rd << 7) | 0x2F)


@dataclass
class AtomicCase:
    name: str
    image: dict
    signature: dict
    completion_pc: int = DONE
    expected_causes: tuple = ()
    competitors: list = field(default_factory=list)
    interrupts: list = field(default_factory=list)
    expected_interrupts: tuple = ()
    requires_response_overlap: bool = False
    expected_halts: int = 0
    expected_resumes: int = 0
    expected_resets: int = 0
    requires_warm_write: bool = False
    pma_fault: int | None = None
    requires_sram_fetch: bool = False
    requires_atomic_forward: bool = False
    expected_sc_failures: int | None = None
    expected_fences: int = 0
    console: tuple = ()
    requires_lock_contention: bool = False
    debug: list = field(default_factory=list)
    boundary: tuple | None = None
    enable_m: bool = False
    enable_c: bool = False
    protected_mode: bool = False


class Program:
    def __init__(self):
        self.words = []

    def emit(self, *words):
        pc = len(self.words) * 4
        self.words.extend(words)
        assert len(self.words) * 4 < HANDLER
        return pc

    def setup(self, value=0x80000003, operand=0x7FFFFFFE):
        self.emit(*constant(1, RAM), *constant(2, operand), *constant(3, SIGNATURE),
                  *constant(4, value), store(4, 1), store(0, 1, 4))

    def signature(self, registers):
        self.emit(*(store(register, 3, index * 4) for index, register in enumerate(registers)))

    def finish(self, name, values, **options):
        self.emit(jump(0, DONE - len(self.words) * 4))
        image = dict(enumerate(self.words))
        image = {index * 4: word for index, word in image.items()}
        image[DONE] = 0x6F
        return AtomicCase(name, image, {SIGNATURE + index * 4: value for index, value in enumerate(values)}, **options)


def cases(zba=False, zbb=False, zbs=False, *, enable_m=True):
    result = []
    for size, offsets, value, signed_value in ((0, range(4), 0x80, 0xFFFFFF80), (1, (0, 2), 0x8001, 0xFFFF8001)):
        for offset in offsets:
            program = Program()
            program.setup(0x11223344, value)
            program.emit(*constant(8, HANDLER), csr(0, 0x305, 8, 1),
                         store(2, 1, offset, size), immediate(5, 1, offset, 3, size),
                         immediate(6, 1, offset, 3, size + 4), immediate(7, 1, 0, 3, 2))
            program.signature((5, 6, 7))
            mask = ((1 << (8 << size)) - 1) << (offset * 8)
            updated = (0x11223344 & ~mask) | (value << (offset * 8))
            case = program.finish(f"sram_{'byte' if size == 0 else 'halfword'}_{offset}", (signed_value, value, updated))
            case.image[HANDLER] = jump(0, DONE - HANDLER)
            result.append(case)
    updates = {"amoswap.w": 0x7FFFFFFE, "amoadd.w": 1, "amoxor.w": 0xFFFFFFFD,
               "amoand.w": 2, "amoor.w": 0xFFFFFFFF, "amomin.w": 0x80000003,
               "amomax.w": 0x7FFFFFFE, "amominu.w": 0x7FFFFFFE, "amomaxu.w": 0x80000003}
    for name, updated in updates.items():
        for ordering in range(4):
            for discard in (False, True):
                program = Program()
                program.setup()
                program.emit(atomic(name, 0 if discard else 5, 1, 2, bool(ordering & 2), bool(ordering & 1)),
                             immediate(6, 5, 1), immediate(7, 1, 0, 3, 2), add(8, 7, 2))
                program.signature((5, 6, 7, 8))
                old = 0 if discard else 0x80000003
                result.append(program.finish(name.replace(".", "_") + f"_{ordering}_x{int(discard)}",
                                             (old, old + 1, updated, (updated + 0x7FFFFFFE) & 0xFFFFFFFF)))
    for lr_order in range(4):
        for sc_order in range(4):
            program = Program()
            program.setup(0x10203040, 0x55667788)
            program.emit(atomic("lr.w", 5, 1, aq=bool(lr_order & 2), rl=bool(lr_order & 1)),
                         immediate(6, 5, 1),
                         atomic("sc.w", 7, 1, 2, bool(sc_order & 2), bool(sc_order & 1)),
                         atomic("sc.w", 8, 1, 2), immediate(9, 1, 0, 3, 2))
            program.signature((5, 6, 7, 8, 9))
            result.append(program.finish(f"lr_sc_{lr_order}_{sc_order}",
                                         (0x10203040, 0x10203041, 0, 1, 0x55667788)))
    for same_word, size in ((True, 0), (True, 1), (True, 2), (False, 2)):
        program = Program()
        program.setup(0x10203040, 0x55667788)
        pc = program.emit(atomic("lr.w", 5, 1))
        program.emit(*(immediate(0, 0, 0) for _ in range(24)))
        program.emit(atomic("sc.w", 6, 1, 2), immediate(7, 1, 0, 3, 2))
        program.signature((5, 6, 7))
        replacement = {0: 0x102030A5, 1: 0x1020A5A5, 2: 0xA5A5A5A5}[size]
        competitor = {"triggerPc": pc, "trigger": "lr_completion", "address": RAM if same_word else RAM + 4,
                      "size": size, "write": True, "data": 0xA5A5A5A5, "holdResponse": 12}
        result.append(program.finish(f"competing_store_{int(same_word)}_{size}",
                                     (0x10203040, int(same_word), replacement if same_word else 0x55667788),
                                     competitors=[competitor]))
    for operation in ("lr.w", "sc.w", "amoadd.w"):
        for offset in (1, 2, 3):
            program = Program()
            program.setup()
            program.emit(*constant(4, HANDLER), csr(0, 0x305, 4, 1), immediate(1, 1, offset))
            pc = program.emit(atomic(operation, 5, 1, 0 if operation == "lr.w" else 2))
            case = program.finish(operation.replace(".", "_") + f"_misaligned_{offset}",
                                  (4 if operation == "lr.w" else 6, RAM + offset, pc),
                                  expected_causes=(4 if operation == "lr.w" else 6,))
            handler = [csr(5, 0x342), csr(6, 0x343), csr(7, 0x341), store(5, 3), store(6, 3, 4), store(7, 3, 8)]
            handler.append(jump(0, DONE - HANDLER - len(handler) * 4))
            case.image.update({HANDLER + index * 4: word for index, word in enumerate(handler)})
            result.append(case)
    program = Program()
    program.setup(0x10203040, 0x55667788)
    program.emit(atomic("lr.w", 0, 1), atomic("sc.w", 0, 1, 2), immediate(5, 1, 0, 3, 2))
    program.signature((0, 5))
    result.append(program.finish("lr_sc_x0", (0, 0x55667788)))
    program = Program()
    program.setup(0x10203040, 0x20)
    program.emit(*(immediate(0, 0, 0) for _ in range(4)))
    program.emit(atomic("amoadd.w", 5, 1, 2), immediate(6, 1, 0, 3, 2))
    program.signature((5, 6))
    result.append(program.finish("held_competitor_read", (0x10203040, 0x10203060),
        competitors=[{"triggerPc": 32, "trigger": "retirement", "address": RAM,
                      "size": 2, "write": False, "data": 0, "holdResponse": 256}], requires_response_overlap=True))
    program = Program()
    program.setup(0x10203040, 0)
    retry = program.emit(atomic("lr.w", 5, 1, aq=True), immediate(7, 5, 1), atomic("sc.w", 6, 1, 7, rl=True))
    program.emit(branch(6, 0, retry - len(program.words) * 4, unequal=True), immediate(8, 1, 0, 3, 2))
    program.signature((5, 6, 8))
    result.append(program.finish("constrained_retry", (0xA5A5A5A5, 0, 0xA5A5A5A6),
        competitors=[{"triggerPc": retry, "trigger": "lr_completion", "address": RAM,
                      "size": 2, "write": True, "data": 0xA5A5A5A5, "holdResponse": 0}]))
    program = Program()
    program.setup(0x10203040, 0)
    retry = program.emit(atomic("lr.w", 5, 1, aq=True), immediate(7, 5, 1),
                         atomic("sc.w", 6, 1, 7, rl=True))
    program.emit(branch(6, 0, retry - len(program.words) * 4, unequal=True),
                 immediate(8, 1, 0, 3, 2))
    program.signature((5, 6, 8))
    result.append(program.finish("repeated_interference", (0xA5A50004, 0, 0xA5A50005),
        competitors=[{"triggerPc": retry, "trigger": "lr_completion", "address": RAM,
                      "size": 2, "write": True, "data": 0xA5A50000 + index, "holdResponse": 0}
                     for index in range(1, 5)], expected_sc_failures=4))
    program = Program()
    program.setup(0, 0x12345678)
    start = program.emit(store(0, 1, 8))
    program.emit(store(2, 1), 0x0310000F, immediate(9, 1, 4), immediate(10, 0, 1),
                 atomic("amoswap.w", 5, 9, 10, rl=True))
    wait = program.emit(immediate(6, 1, 8, 3, 2))
    program.emit(branch(6, 0, wait - len(program.words) * 4),
                 immediate(7, 1, 0, 3, 2), immediate(8, 1, 4, 3, 2))
    program.signature((5, 6, 7, 8))
    result.append(program.finish("message_passing", (0, 1, 0x12345678, 1), expected_fences=1,
        competitors=[{"triggerPc": start, "address": RAM + 4, "size": 2, "write": False,
                      "data": 0, "holdResponse": 0, "pollUntil": 1},
                     {"triggerPc": 0, "address": RAM, "size": 2, "write": False,
                      "data": 0, "holdResponse": 0, "afterPrevious": True, "expectedRead": 0x12345678},
                     {"triggerPc": 0, "address": RAM + 8, "size": 2, "write": True,
                      "data": 1, "holdResponse": 0, "afterPrevious": True}]))
    program = Program()
    program.setup(1, 1)
    start = program.emit(store(0, 1, 8))
    lock = program.emit(atomic("lr.w", 5, 1, aq=True))
    program.emit(branch(5, 0, lock - len(program.words) * 4, unequal=True),
                 atomic("sc.w", 6, 1, 2),
                 branch(6, 0, lock - (len(program.words) * 4 + 8), unequal=True))
    program.emit(immediate(7, 1, 4, 3, 2), immediate(7, 7, 1), store(7, 1, 4),
                 0x0310000F, store(0, 1))
    wait = program.emit(immediate(8, 1, 8, 3, 2))
    program.emit(branch(8, 0, wait - len(program.words) * 4), immediate(9, 1, 0, 3, 2))
    program.signature((5, 6, 7, 8, 9))
    result.append(program.finish("contended_lock", (0, 0, 42, 1, 0), expected_fences=1,
        requires_lock_contention=True,
        competitors=[{"triggerPc": start, "address": RAM + 4, "size": 2, "write": True,
                      "data": 41, "holdResponse": 24},
                     {"triggerPc": 0, "address": RAM, "size": 2, "write": True,
                      "data": 0, "holdResponse": 0, "afterPrevious": True},
                     {"triggerPc": 0, "address": RAM, "size": 2, "write": False,
                      "data": 0, "holdResponse": 0, "afterPrevious": True, "pollUntil": 1},
                     {"triggerPc": 0, "address": RAM, "size": 2, "write": False,
                      "data": 0, "holdResponse": 0, "afterPrevious": True, "pollUntil": 0},
                     {"triggerPc": 0, "address": RAM + 4, "size": 2, "write": False,
                      "data": 0, "holdResponse": 0, "afterPrevious": True, "expectedRead": 42},
                     {"triggerPc": 0, "address": RAM + 8, "size": 2, "write": True,
                      "data": 1, "holdResponse": 0, "afterPrevious": True}]))
    program = Program()
    program.setup(0x10, 0x20)
    program.emit(*constant(9, 0x10000000), immediate(10, 0, 70),
                 atomic("amoadd.w", 5, 1, 2), 0x0FF0000F, store(10, 9), 0x0FF0000F,
                 atomic("lr.w", 6, 1), immediate(7, 0, 0x40), atomic("sc.w", 8, 1, 7),
                 0x0FF0000F)
    ready = program.emit(immediate(11, 9, 4, 3, 2))
    program.emit(branch(11, 0, ready - len(program.words) * 4), immediate(12, 1, 0, 3, 2))
    program.signature((5, 6, 8, 11, 12))
    result.append(program.finish("sram_mmio_fence", (0x10, 0x30, 0, 1, 0x40),
                                 expected_fences=3, console=(70,)))
    program = Program()
    program.setup(0x10, 3)
    pc = program.emit(atomic("amoadd.w", 5, 1, 2))
    program.emit(immediate(6, 1, 0, 3, 2))
    program.signature((5, 6))
    result.append(program.finish("amo_competing_boundary", (0x10, 0x80),
        competitors=[{"triggerPc": pc, "trigger": "amo_accept", "address": RAM, "size": 2,
                      "write": True, "data": 0x80, "holdResponse": 0}]))
    for offset in (0, 4):
        program = Program()
        program.setup(0x10203040, 0x55667788)
        program.emit(atomic("lr.w", 5, 1), store(2, 1, offset), atomic("sc.w", 6, 1, 4),
                     immediate(7, 1, 0, 3, 2))
        program.signature((6, 7))
        result.append(program.finish(f"local_store_{offset}", (int(offset == 0), 0x55667788 if offset == 0 else 0x10203040)))
    for csr_address in (0x300, 0x340):
        program = Program()
        program.setup(0x10203040, 0x55667788)
        program.emit(csr(8, csr_address), atomic("lr.w", 5, 1), csr(0, csr_address, 8, 1),
                     atomic("sc.w", 6, 1, 2), immediate(7, 1, 0, 3, 2))
        program.signature((6, 7))
        result.append(program.finish(f"reservation_csr_{csr_address:x}",
                                     (int(csr_address == 0x300), 0x10203040 if csr_address == 0x300 else 0x55667788)))
    for name, permission, expected_cause in (("lr.w", 4, 5), ("sc.w", 1, 7), ("amoadd.w", 1, 7)):
        program = Program()
        program.setup()
        program.emit(*constant(8, HANDLER), csr(0, 0x305, 8, 1),
                     *constant(8, RAM >> 2), csr(0, 0x3B0, 8, 1),
                     *constant(8, 0xFFFFFFFF), csr(0, 0x3B1, 8, 1),
                     *constant(8, 0x1F10 | permission), csr(0, 0x3A0, 8, 1),
                     *constant(8, 1 << 17), csr(0, 0x300, 8, 1))
        pc = program.emit(atomic(name, 5, 1, 0 if name == "lr.w" else 2))
        case = program.finish(name.replace(".", "_") + "_pmp_denied", (expected_cause, RAM, pc, 0x80000003),
                              expected_causes=(expected_cause,), protected_mode=True)
        handler = [csr(5, 0x342), csr(6, 0x343), csr(7, 0x341), immediate(8, 1, 0, 3, 2),
                   store(5, 3), store(6, 3, 4), store(7, 3, 8), store(8, 3, 12)]
        handler.append(jump(0, DONE - HANDLER - len(handler) * 4))
        case.image.update({HANDLER + index * 4: word for index, word in enumerate(handler)})
        result.append(case)
    program = Program()
    program.setup(0x10203040, 0x55667788)
    program.emit(*constant(8, HANDLER), csr(0, 0x305, 8, 1))
    pc = program.emit(immediate(5, 1, 2, 3, 2), atomic("amoswap.w", 6, 1, 2))
    case = program.finish("older_load_fault", (4, RAM + 2, pc, 0x10203040), expected_causes=(4,))
    handler = [csr(5, 0x342), csr(6, 0x343), csr(7, 0x341), immediate(8, 1, 0, 3, 2),
               store(5, 3), store(6, 3, 4), store(7, 3, 8), store(8, 3, 12)]
    handler.append(jump(0, DONE - HANDLER - len(handler) * 4))
    case.image.update({HANDLER + index * 4: word for index, word in enumerate(handler)})
    result.append(case)
    program = Program()
    program.setup(0x10203040, 0x55667788)
    program.emit(store(0, 3, 12), *constant(8, HANDLER), csr(0, 0x305, 8, 1),
                 *constant(8, 1 << 11), csr(0, 0x304, 8, 1),
                 *constant(8, 0x1808), csr(0, 0x300, 8, 1))
    pc = program.emit(atomic("lr.w", 5, 1))
    program.emit(*(immediate(0, 0, 0) for _ in range(8)))
    program.emit(atomic("sc.w", 6, 1, 2), immediate(7, 1, 0, 3, 2))
    program.signature((5, 6, 7))
    case = program.finish("interrupt_clears_reservation", (0x10203040, 1, 0x10203040),
                          interrupts=[pc], expected_interrupts=(0x8000000B,))
    case.signature[SIGNATURE + 12] = 0x8000000B
    case.image.update({HANDLER: csr(20, 0x342), HANDLER + 4: store(20, 3, 12), HANDLER + 8: 0x30200073})
    result.append(case)
    for use_memory in (False, True):
        program = Program()
        program.setup(0x10203040, 0x55667788)
        pc = program.emit(atomic("lr.w", 5, 1))
        program.emit(*(immediate(0, 0, 0) for _ in range(64)))
        program.emit(atomic("sc.w", 6, 1, 2), immediate(7, 1, 0, 3, 2))
        program.signature((5, 6, 7))
        actions = [(WAIT_RETIRE, pc, 0, 0), (WRITE, 0x10, 1, 0),
                   (WRITE, 0x10, 0x80000001, 0), (POLL, 0x11, 0x300, 0x300)]
        register(actions, 0x7B1)
        register(actions, 0x7B0)
        if use_memory:
            memory(actions, RAM)
            memory(actions, RAM + 4, 0x89ABCDEF)
            memory(actions, RAM + 4)
        actions.extend(((WRITE, 0x10, 0x40000001, 0), (POLL, 0x11, 0x30000, 0x30000)))
        result.append(program.finish("debug_memory_reservation" if use_memory else "debug_halt_reservation",
                                     (0x10203040, 1, 0x10203040), debug=actions, expected_halts=1, expected_resumes=1))
    for size, offsets, value in ((0, range(4), 0xA5), (1, (0, 2), 0xBEEF)):
        for offset in offsets:
            program = Program()
            program.setup(0x10203040, 0x55667788)
            pc = program.emit(atomic("lr.w", 5, 1))
            program.emit(*(immediate(0, 0, 0) for _ in range(64)))
            program.emit(atomic("sc.w", 6, 1, 2), immediate(7, 1, 0, 3, 2))
            program.signature((5, 6, 7))
            actions = [(WAIT_RETIRE, pc, 0, 0), (WRITE, 0x10, 1, 0),
                       (WRITE, 0x10, 0x80000001, 0), (POLL, 0x11, 0x300, 0x300)]
            memory(actions, RAM + offset, size=size)
            memory(actions, RAM + offset, value, size=size)
            memory(actions, RAM + offset, size=size)
            actions.extend(((WRITE, 0x10, 0x40000001, 0), (POLL, 0x11, 0x30000, 0x30000)))
            mask = ((1 << (8 << size)) - 1) << (offset * 8)
            updated = (0x10203040 & ~mask) | (value << (offset * 8))
            result.append(program.finish(f"debug_sram_{'byte' if size == 0 else 'halfword'}_{offset}",
                (0x10203040, 1, updated), debug=actions, expected_halts=1, expected_resumes=1))
    program = Program()
    program.setup(0x10203040, 0x55667788)
    pc = program.emit(atomic("lr.w", 5, 1))
    program.emit(*(immediate(0, 0, 0) for _ in range(64)))
    program.emit(atomic("sc.w", 6, 1, 2), immediate(7, 1, 0, 3, 2))
    program.signature((5, 6, 7))
    actions = [(WAIT_RETIRE, pc, 0, 0), (WRITE, 0x10, 1, 0), (WRITE, 0x10, 0x80000001, 0),
               (POLL, 0x11, 0x300, 0x300), (WRITE, 0x10, 3, 0), (IDLE, 0, 8, 0),
               (WRITE, 0x10, 1, 0), (POLL, 0x11, 0xC0000, 0xC0000)]
    case = program.finish("warm_reset_competitor", (0x10203040, 0, 0x55667788), debug=actions,
        expected_halts=1, expected_resets=1, requires_warm_write=True,
        competitors=[{"triggerPc": 0xFFFFFFFF, "trigger": "reset_request", "address": RAM + 0x40,
                      "size": 2, "write": True, "data": 0xA5A5A5A5, "holdResponse": 32}])
    case.signature[RAM + 0x40] = 0xA5A5A5A5
    result.append(case)
    for target, region in ((0, "rom"), (0x10000000, "console"), (0x30000000, "unmapped")):
        for name in ("lr.w", "sc.w", "amoadd.w"):
            program = Program()
            program.setup()
            program.emit(*constant(8, HANDLER), csr(0, 0x305, 8, 1), *constant(1, target))
            pc = program.emit(atomic(name, 5, 1, 0 if name == "lr.w" else 2))
            cause = 5 if name == "lr.w" else 7
            case = program.finish(name.replace(".", "_") + "_" + region, (cause, target, pc),
                                  expected_causes=(cause,), pma_fault=target)
            handler = [csr(5, 0x342), csr(6, 0x343), csr(7, 0x341), store(5, 3), store(6, 3, 4), store(7, 3, 8)]
            handler.append(jump(0, DONE - HANDLER - len(handler) * 4))
            case.image.update({HANDLER + index * 4: word for index, word in enumerate(handler)})
            result.append(case)
    program = Program()
    program.setup(42, 17)
    program.emit(*constant(8, RAM >> 2), csr(0, 0x3B0, 8, 1),
                 *constant(8, 0xFFFFFFFF), csr(0, 0x3B1, 8, 1),
                 *constant(8, 0x1F13), csr(0, 0x3A0, 8, 1),
                 *constant(8, 1 << 17), csr(0, 0x300, 8, 1),
                 atomic("amoadd.w", 5, 1, 2), immediate(6, 1, 0, 3, 2))
    program.signature((5, 6))
    result.append(program.finish("mprv_atomic_allowed", (42, 59), protected_mode=True))
    program = Program()
    program.setup(42, 17)
    program.emit(*constant(8, 0xFFFFFFFF), csr(0, 0x3B0, 8, 1),
                 *constant(8, 0x1F), csr(0, 0x3A0, 8, 1))
    user_pc = len(program.words) * 4 + 20
    program.emit(*constant(8, user_pc), csr(0, 0x341, 8, 1), csr(0, 0x300, 0, 1), 0x30200073,
                 atomic("amoadd.w", 5, 1, 2), atomic("lr.w", 6, 1), atomic("sc.w", 7, 1, 2),
                 immediate(8, 1, 0, 3, 2))
    program.signature((5, 6, 7, 8))
    result.append(program.finish("user_atomic_execution", (42, 59, 0, 17), protected_mode=True))
    program = Program()
    program.setup(42, 17)
    code = [atomic("amoadd.w", 5, 1, 2), immediate(6, 5, 1), immediate(0, 9, 0, 0x67)] + [0x13] * 5
    program.emit(*constant(8, RAM + 0x400))
    for index, word in enumerate(code):
        program.emit(*constant(10, word), store(10, 8, index * 4))
    program.emit(0x100F)
    return_pc = len(program.words) * 4 + 12
    program.emit(*constant(9, return_pc), immediate(0, 8, 0, 0x67), immediate(7, 1, 0, 3, 2))
    program.signature((5, 6, 7))
    result.append(program.finish("sram_instruction_execution", (42, 43, 59), requires_sram_fetch=True))
    if enable_m:
        program = Program()
        program.setup(42, 17)
        multiply = (1 << 25) | (2 << 20) | (2 << 15) | (2 << 7) | 0x33
        code = [multiply, immediate(2, 2, 1), atomic("amoadd.w", 5, 1, 2),
                immediate(6, 1, 0, 3, 2), immediate(0, 9, 0, 0x67)] + [0x13] * 5
        program.emit(*constant(8, RAM + 0x400))
        for index, word in enumerate(code):
            program.emit(*constant(10, word), store(10, 8, index * 4))
        program.emit(0x100F)
        return_pc = len(program.words) * 4 + 12
        program.emit(*constant(9, return_pc), immediate(0, 8, 0, 0x67))
        program.signature((2, 5, 6))
        result.append(program.finish("atomic_input_forward", (290, 42, 332),
                                     requires_sram_fetch=True, requires_atomic_forward=True, enable_m=True))
    if zba and zbb and zbs:
        program = Program()
        program.setup(0x12345678, 0x10)
        program.emit(atomic("amoadd.w", 5, 1, 2),
                     bit_instruction("rev8", rd=6, rs1=5),
                     bit_instruction("bclri", rd=7, rs1=6, shift=4),
                     bit_instruction("sh1add", rd=8, rs1=7, rs2=2),
                     atomic("amoxor.w", 9, 1, 8), atomic("lr.w", 10, 1),
                     bit_instruction("rori", rd=11, rs1=10, shift=8),
                     bit_instruction("bseti", rd=12, rs1=11, shift=0),
                     bit_instruction("sh2add", rd=13, rs1=12, rs2=2),
                     atomic("sc.w", 14, 1, 13), immediate(15, 1, 0, 3, 2))
        program.signature(range(5, 16))
        result.append(program.finish("atomic_bit_dependencies",
            (0x12345678, 0x78563412, 0x78563402, 0xF0AC6814, 0x12345688,
             0xE2983E9C, 0x9CE2983E, 0x9CE2983F, 0x738A610C, 0, 0x738A610C)))
    for control in ("interrupt", "halt"):
        for name, operation, returned, final_word in (("lr.w", 1, 42, 42),
                ("sc.w", 2, 0, 17), ("amoadd.w", 4, 42, 59)):
            program = Program()
            program.setup(42, 17)
            program.emit(*constant(8, HANDLER), csr(0, 0x305, 8, 1))
            if control == "interrupt":
                program.emit(*constant(8, 1 << 11), csr(0, 0x304, 8, 1),
                             *constant(8, 0x1808), csr(0, 0x300, 8, 1))
            if operation == 2:
                program.emit(atomic("lr.w", 9, 1))
            pc = program.emit(atomic(name, 5, 1, 0 if operation == 1 else 2))
            program.emit(store(2, 1, 4), atomic("sc.w", 6, 1, 2), immediate(7, 1, 0, 3, 2),
                         immediate(10, 1, 4, 3, 2))
            program.signature((5, 6, 7, 10))
            actions = []
            if control == "halt":
                actions = [(WRITE, 0x10, 1, 0), (HALT_ATOMIC, 0x10, 0x80000001, operation),
                           (POLL, 0x11, 0x300, 0x300)]
                for number in (0x7B1, 0x7B0, 0x1005, 0x341, 0x342, 0x343):
                    register(actions, number)
                memory(actions, RAM)
                memory(actions, RAM + 4)
                actions.extend(((WRITE, 0x10, 0x40000001, 0), (POLL, 0x11, 0x30000, 0x30000)))
            case = program.finish("pending_" + name.replace(".", "_") + "_" + control,
                (returned, 1, final_word, 17), boundary=(control, pc, operation), debug=actions,
                expected_halts=int(control == "halt"), expected_resumes=int(control == "halt"),
                expected_interrupts=(0x8000000B,) if control == "interrupt" else ())
            if control == "interrupt":
                case.image.update({HANDLER: csr(20, 0x341), HANDLER + 4: csr(21, 0x342),
                                   HANDLER + 8: 0x30200073})
            result.append(case)
    return result
