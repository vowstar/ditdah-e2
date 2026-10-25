# SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
# SPDX-License-Identifier: MIT
"""Fixed programs for atomic instructions and competing SRAM accesses."""

from dataclasses import dataclass, field

from programs import add, branch, constant, csr, immediate, jump, store
from debug_programs import WAIT_RETIRE, WRITE, POLL, IDLE, register, memory


RAM = 0x20000000
SIGNATURE = RAM + 0x100
DONE = 0xF00
HANDLER = 0x800
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
    debug: list = field(default_factory=list)
    enable_m: bool = True
    enable_c: bool = True
    protected_mode: bool = True


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


def cases():
    result = []
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
                              expected_causes=(expected_cause,))
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
    return result
