# SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
# SPDX-License-Identifier: MIT
"""Build programs and DMI operations for processor debug checks."""

from dataclasses import dataclass, replace

from programs import add, branch, constant, csr, immediate, jump, store, multiply


WAIT_RETIRE, READ, WRITE, POLL, IDLE, FINISH = range(6)
BUS_CONTROL, WAIT_ACCEPT, WAIT_OFFER, INTERRUPTS = 6, 7, 8, 9
WAIT_IRQ = 10
LOOP, RESTART, DONE, DATA = 0x100, 0x200, 0x300, 0x400
VALUE = 0x13579BDF


@dataclass
class DebugCase:
    name: str
    image: dict
    actions: list
    signature: dict
    steps: int = 0
    halts: int = 1
    resumes: int | None = None
    resets: int = 0
    cancellations: int = 0
    data_fault: int | None = None
    enable_m: bool = True
    enable_c: bool = True
    protected_mode: bool = True
    enable_a: bool = False
    enable_zba: bool = False
    enable_zbb: bool = False
    enable_zbs: bool = False
    interrupts: int = 0
    step_outcome: tuple | None = None
    bus_faults: int = 0
    reset_halts: int = 0
    orphan_step: bool = False


def register(actions, number, value=None):
    if value is not None:
        actions.append((WRITE, 4, value, 0))
    actions.extend(((WRITE, 0x17, (2 << 20) | (1 << 17) | (int(value is not None) << 16) | number, 0),
                    (POLL, 0x16, 0, 1 << 12)))
    if value is None:
        actions.append((READ, 4, 0, 0))


def memory(actions, address, value=None, size=2, denied=False, fault=False):
    actions.append((WRITE, 5, address, 0))
    if value is not None:
        actions.append((WRITE, 4, value, 0))
    actions.extend(((WRITE, 0x17, (2 << 24) | (size << 20) | (int(value is not None) << 16), 0),
                    (POLL, 0x16, 0, 1 << 12)))
    if fault:
        actions.extend(((READ, 4, 0, 0), (READ, 0x16, 0, 0),
                        (WRITE, 0x16, 0x700, 0), (READ, 0x16, 0, 0)))
    elif denied:
        actions.append((WRITE, 0x16, 0x700, 0))
    elif value is None:
        actions.append((READ, 4, 0, 0))


def cases(enable_m=True, enable_c=True, protected_mode=True, *, enable_a=False,
          enable_zba=False, enable_zbb=False, enable_zbs=False):
    image = {}

    def code(start, words):
        for index, word in enumerate(words):
            address = start + index * 4
            assert address not in image
            image[address] = word

    boot = constant(1, DATA) + [immediate(5, 0, 0), immediate(6, 0, 7)]
    boot.append(jump(0, LOOP - len(boot) * 4))
    code(0, boot)
    code(LOOP, [immediate(5, 5, 1), store(5, 1), immediate(6, 6, 3), store(6, 1, 4), jump(0, -16)])
    ending = [immediate(11, 10, 9), multiply(14, 10, 10) if enable_m else add(14, 10, 10), store(10, 1, 8), store(11, 1, 12),
              immediate(12, 1, 8, 3, 2), add(13, 11, 12), store(13, 1, 16)]
    ending.append(jump(0, DONE - RESTART - len(ending) * 4))
    code(RESTART, ending)
    code(DONE, [0x6F])
    image.update(dict.fromkeys(range(DATA, DATA + 20, 4), 0))
    result = []
    for stepping in (False, True):
        actions = [(WAIT_RETIRE, LOOP + 4, 0, 0), (WRITE, 0x10, 1, 0),
                   (WRITE, 0x10, 0x80000001, 0), (POLL, 0x11, 0x300, 0x300)]
        register(actions, 0x7B1)
        register(actions, 0x7B0)
        register(actions, 0xB00)
        actions.append((IDLE, 0, 32, 0))
        register(actions, 0xB00)
        for index in range(32):
            register(actions, 0x1000 + index)
        register(actions, 0x1000, 0xFFFFFFFF)
        register(actions, 0x1000)
        register(actions, 0x100A, VALUE)
        register(actions, 0x100A)
        register(actions, 0x7B1, RESTART | 3)
        register(actions, 0x7B1)
        register(actions, 0x7B1, RESTART)
        register(actions, 0x7B1)
        if stepping:
            register(actions, 0x7B0, 7)
        actions.extend(((WRITE, 0x10, 0x40000001, 0), (POLL, 0x11, 0x30000, 0x30000)))
        if stepping:
            actions.append((POLL, 0x11, 0x300, 0x300))
            register(actions, 0x7B1)
            register(actions, 0x7B0)
            register(actions, 0x100B)
            register(actions, 0x100E)
            register(actions, 0x7B0, 3)
            actions.extend(((WRITE, 0x10, 0x40000001, 0), (POLL, 0x11, 0x30000, 0x30000)))
        actions.extend(((WAIT_RETIRE, DONE, 0, 0), (FINISH, 0, 0, 0)))
        result.append(DebugCase("single_step" if stepping else "halt_resume", dict(image), actions,
                                {DATA + 8: VALUE, DATA + 12: VALUE + 9, DATA + 16: 2 * VALUE + 9}, int(stepping), 1 + int(stepping)))
    base = result[0]
    insertion = next(index for index, item in enumerate(base.actions) if item == (WRITE, 0x10, 0x40000001, 0))
    if protected_mode:
        for user in (False, True):
            actions = list(base.actions[:insertion])
            if user:
                for number, value in ((0x3B0, 0xFFFFFFFF), (0x3A0, 0x1F), (0x7B0, 0), (0x7B1, LOOP)):
                    register(actions, number, value)
                actions.extend(((WRITE, 0x10, 0x40000001, 0), (POLL, 0x11, 0x30000, 0x30000),
                                (WAIT_RETIRE, LOOP + 4, 0, 0), (WRITE, 0x10, 0x80000001, 0),
                                (POLL, 0x11, 0x300, 0x300)))
                register(actions, 0x7B1, RESTART)
            for number, value in ((0x341, 0x234), (0x342, 7), (0x343, 0xABCDEF)):
                register(actions, number, value)
            state = (0x7B1, 0x7B0, 0x300, 0x341, 0x342, 0x343)
            for number in state:
                register(actions, number)
            for number in (0x30A, 0x31A):
                register(actions, number)
                register(actions, number, 0xFFFFFFFF)
                register(actions, number)
            for number in state:
                register(actions, number)
            actions.extend(base.actions[insertion:])
            result.append(DebugCase("menvcfg_user" if user else "menvcfg_machine", dict(image), actions,
                                    base.signature, halts=1 + int(user)))
    for offered in (False, True):
        for write in (False, True):
            actions = list(base.actions[:insertion])
            for number, value in ((0x341, 0x234), (0x342, 7), (0x343, 0xABCDEF), (0x7B0, 7)):
                register(actions, number, value)
            actions.extend(((BUS_CONTROL, 8, 3 if offered else 2, 24),
                            (WRITE, 5, DATA + 64, 0), (WRITE, 4, VALUE, 0),
                            (WRITE, 0x17, 0x2210000, 0),
                            (WAIT_OFFER if offered else WAIT_ACCEPT, DATA + 64, 0, 0),
                            (WRITE, 0x10, 0, 0), (WRITE, 0x10, 1, 0),
                            (POLL, 0x16, 0, 1 << 12), (WRITE, 0x10, 0x40000001, 0),
                            (POLL, 0x11, 0x30000, 0x30000), (POLL, 0x11, 0x300, 0x300),
                            (BUS_CONTROL, 0, 0, 0)))
            for number in (0x7B0, 0x7B1, 0x100B, 0x341, 0x342, 0x343):
                register(actions, number)
            register(actions, 0x7B0, 3)
            actions.extend(((WRITE, 0x10, 0x40000001, 0), (POLL, 0x11, 0x30000, 0x30000),
                            (WAIT_RETIRE, DONE, 0, 0), (FINISH, 0, 0, 0)))
            stepped = dict(image) | {DATA + 64: 0, DATA + 68: 0,
                RESTART: store(10, 1, 68) if write else immediate(11, 1, 64, 3, 2),
                RESTART + 4: jump(0, DONE - RESTART - 4)}
            name = f"orphan_{'offered' if offered else 'accepted'}_step_{'store' if write else 'load'}"
            result.append(DebugCase(name, stepped, actions, {DATA + 64: VALUE, DATA + 68: VALUE if write else 0},
                                    steps=1, halts=2, cancellations=1, orphan_step=True,
                                    step_outcome=(RESTART, RESTART + 4, False, 0, False)))
    for write in (False, True):
        actions = list(base.actions[:insertion])
        for number, value in ((0x341, 0x234), (0x342, 7), (0x343, 0xABCDEF)):
            register(actions, number, value)
        actions.append((WRITE, 4, 0x2468ACE0, 0))
        memory(actions, DATA + 64, 0xDEADBEEF if write else None, fault=True)
        for number in (0x341, 0x342, 0x343):
            register(actions, number)
        memory(actions, DATA + 68, 0x2468ACE0)
        memory(actions, DATA + 68)
        actions.extend(base.actions[insertion:])
        fault_image = dict(image) | {DATA + 64: 0x11223344, DATA + 68: 0}
        result.append(DebugCase("abstract_write_fault" if write else "abstract_read_fault", fault_image, actions,
                                base.signature | {DATA + 64: 0x11223344, DATA + 68: 0x2468ACE0},
                                data_fault=DATA + 64, bus_faults=1))
    for offered in (False, True):
        actions = list(base.actions[:insertion])
        actions.extend(((WRITE, 0x10, 9, 0), (BUS_CONTROL, 0, 1 if offered else 2, 0),
                        (WRITE, 5, DATA + 64, 0), (WRITE, 4, VALUE, 0),
                        (WRITE, 0x17, 0x2210000, 0),
                        (WAIT_OFFER if offered else WAIT_ACCEPT, DATA + 64, 0, 0),
                        (WRITE, 0x10, 3, 0), (IDLE, 0, 8, 0), (BUS_CONTROL, 0, 0, 0),
                        (IDLE, 0, 32, 0), (WRITE, 0x10, 1, 0),
                        (POLL, 0x11, 0xC0300, 0xC0300), (POLL, 0x16, 0, 1 << 12),
                        (WRITE, 0x16, 0x700, 0)))
        register(actions, 0x7B1)
        register(actions, 0x7B0)
        actions.extend(((WRITE, 0x10, 0x10000005, 0), (WRITE, 0x10, 3, 0),
                        (IDLE, 0, 8, 0), (WRITE, 0x10, 1, 0),
                        (POLL, 0x11, 0xC0000, 0xC0000), (WAIT_RETIRE, LOOP + 4, 0, 0),
                        (WRITE, 0x10, 0x80000001, 0), (POLL, 0x11, 0x300, 0x300)))
        register(actions, 0x7B0)
        register(actions, 0x100A, VALUE)
        register(actions, 0x7B1, RESTART)
        actions.extend(base.actions[insertion:])
        result.append(DebugCase("reset_halt_offered_memory" if offered else "reset_halt_accepted_memory",
                                dict(image) | {DATA + 64: 0}, actions, base.signature | {DATA + 64: VALUE},
                                halts=3, resumes=1, resets=2, reset_halts=1))
    actions = list(base.actions[:insertion])
    register(actions, 0x7B0, 0x8003)
    actions.extend(((WRITE, 0x10, 0x40000001, 0), (POLL, 0x11, 0x30000, 0x30000),
                    (POLL, 0x11, 0x300, 0x300)))
    register(actions, 0x7B0)
    register(actions, 0x7B1)
    register(actions, 0x7B1, RESTART + 4)
    actions.extend(base.actions[insertion:])
    break_image = dict(image)
    for address in sorted((address for address in image if RESTART <= address < DONE), reverse=True):
        break_image[address + 4] = image[address]
    break_image[RESTART] = 0x100073
    last = RESTART + len(ending) * 4
    break_image[last] = jump(0, DONE - last)
    result.append(DebugCase("ebreak", break_image, actions, base.signature, halts=2))
    actions = list(base.actions[:insertion])
    register(actions, 0x340, 0x89ABCDEF)
    register(actions, 0x340)
    register(actions, 0x3B0, DATA >> 2)
    register(actions, 0x3B1, 0xFFFFFFFF)
    register(actions, 0x3A0, 0x1F11)
    register(actions, 0x300, 1 << 17)
    register(actions, 0x300)
    memory(actions, DATA)
    memory(actions, DATA, 0xDEADBEEF, denied=True)
    memory(actions, DATA + 8, 0xA1B2C3D4)
    memory(actions, DATA + 9, 0x56, size=0)
    memory(actions, DATA + 10, 0x789A, size=1)
    memory(actions, DATA + 8)
    memory(actions, DATA + 9, size=0)
    memory(actions, DATA + 10, size=1)
    memory(actions, DATA + 9, size=2, denied=True)
    register(actions, 0x7B0, 0)
    actions.extend(base.actions[insertion:-1])
    actions.extend(((WRITE, 0x10, 0x80000001, 0), (POLL, 0x11, 0x300, 0x300)))
    register(actions, 0x300)
    register(actions, 0x7B0)
    actions.extend(base.actions[insertion:])
    result.append(DebugCase("abstract_memory_user", dict(image), actions, base.signature, halts=2))
    actions = list(base.actions[:insertion])
    actions.append((WRITE, 0x10, 1, 0))
    actions.append((BUS_CONTROL, 0, 2, 0))
    actions.extend(((WRITE, 5, DATA + 8, 0), (WRITE, 4, VALUE, 0),
                    (WRITE, 0x17, 0x2210000, 0), (WAIT_ACCEPT, DATA + 8, 0, 0),
                    (WRITE, 0x10, 3, 0), (IDLE, 0, 8, 0), (BUS_CONTROL, 0, 0, 0),
                    (IDLE, 0, 8, 0), (WRITE, 0x10, 1, 0),
                    (POLL, 0x11, 0xC0000, 0xC0000), (WAIT_RETIRE, LOOP + 4, 0, 0),
                    (WRITE, 0x10, 0x80000001, 0), (POLL, 0x11, 0x300, 0x300),
                    (POLL, 0x16, 0, 1 << 12), (WRITE, 0x16, 0x700, 0)))
    register(actions, 0x7B1)
    register(actions, 0x100A, VALUE)
    register(actions, 0x7B1, RESTART)
    actions.extend(base.actions[insertion:])
    result.append(DebugCase("reset_accepted_memory", dict(image), actions, base.signature,
                            halts=2, resumes=1, resets=1))
    actions = list(base.actions[:insertion])
    actions.append((BUS_CONTROL, 0, 1, 0))
    actions.extend(((WRITE, 5, DATA + 8, 0), (WRITE, 4, VALUE, 0),
                    (WRITE, 0x17, 0x2210000, 0), (WAIT_OFFER, DATA + 8, 0, 0),
                    (WRITE, 0x10, 0, 0), (IDLE, 0, 8, 0), (BUS_CONTROL, 0, 0, 0),
                    (IDLE, 0, 64, 0), (WRITE, 0x10, 1, 0), (POLL, 0x11, 0x300, 0x300)))
    register(actions, 0x7B1)
    actions.extend(base.actions[insertion:])
    result.append(DebugCase("deactivate_offered_memory", dict(image), actions, base.signature, cancellations=1))
    fault_image = dict(image)
    fault_boot = constant(1, DATA) + constant(3, 0x180) + [csr(0, 0x305, 3, 1)]
    fault_boot.append(jump(0, LOOP - len(fault_boot) * 4))
    for index, value in enumerate(fault_boot):
        fault_image[index * 4] = value
    fault_image[LOOP] = immediate(5, 1, 0, 3, 2)
    fault_image[0x180] = 0x6F
    actions = [(BUS_CONTROL, 0, 2, 0), (WAIT_ACCEPT, DATA, 0, 0),
               (WRITE, 0x10, 1, 0), (WRITE, 0x10, 0x80000001, 0),
               (IDLE, 0, 8, 0), (BUS_CONTROL, 0, 0, 0), (POLL, 0x11, 0x300, 0x300)]
    actions.extend(base.actions[4:])
    result.append(DebugCase("halt_pending_load_fault", fault_image, actions, base.signature, data_fault=DATA))
    reset_case = next(case for case in result if case.name == "reset_accepted_memory")
    actions = [(BUS_CONTROL, address, 1, mask) if kind == BUS_CONTROL and value == 2 else
               (WAIT_OFFER, address, value, mask) if kind == WAIT_ACCEPT else (kind, address, value, mask)
               for kind, address, value, mask in reset_case.actions]
    result.append(replace(reset_case, name="reset_offered_memory", actions=actions))
    deactivate_case = next(case for case in result if case.name == "deactivate_offered_memory")
    actions = [(BUS_CONTROL, address, 2, mask) if kind == BUS_CONTROL and value == 1 else
               (WAIT_ACCEPT, address, value, mask) if kind == WAIT_OFFER else (kind, address, value, mask)
               for kind, address, value, mask in deactivate_case.actions]
    result.append(replace(deactivate_case, name="deactivate_accepted_memory", actions=actions))
    user_memory = next(case for case in result if case.name == "abstract_memory_user")
    actions = list(user_memory.actions)
    last_resume = max(index for index, action in enumerate(actions) if action == (WRITE, 0x10, 0x40000001, 0))
    extra = []
    register(extra, 0x3A0, 0)
    memory(extra, DATA + 64, 0x2468ACE0)
    memory(extra, DATA + 64)
    register(extra, 0x300, 1 << 17)
    memory(extra, DATA + 64, denied=True)
    register(extra, 0x300, 0)
    register(extra, 0x3A0, 0x1F11)
    actions[last_resume:last_resume] = extra
    result.append(replace(user_memory, name="halt_user_memory", actions=actions,
                          signature=user_memory.signature | {DATA + 64: 0x2468ACE0}))
    user_break = next(case for case in result if case.name == "ebreak")
    actions = [(kind, address, 0x1000, mask) if (kind, address, value) == (WRITE, 4, 0x8003) else
               (kind, address, value, mask) for kind, address, value, mask in user_break.actions]
    first_resume = next(index for index, action in enumerate(actions) if action == (WRITE, 0x10, 0x40000001, 0))
    extra = []
    register(extra, 0x3B0, 0xFFFFFFFF)
    register(extra, 0x3A0, 0x1F)
    actions[first_resume:first_resume] = extra
    result.append(replace(user_break, name="ebreak_user", actions=actions))
    for name, word, fault_address in (
            ("step_illegal", 0xFFFFFFFF, None),
            ("step_load_fault", immediate(17, 0, DATA + 32, 3, 2), DATA + 32),
            ("step_wfi", 0x10500073, None),
            ("step_pending_interrupt", None, None)):
        stepped = dict(image)
        if word is not None:
            for address in sorted((a for a in image if RESTART <= a < DONE), reverse=True):
                stepped[address + 4] = image[address]
            stepped[RESTART] = word
            last = RESTART + len(ending) * 4
            stepped[last] = jump(0, DONE - last)
        stepped[0x180] = immediate(20, 20, 1)
        stepped[0x184] = 0x6F
        stepped[DATA + 32] = 0x11223344
        actions = list(base.actions[:insertion])
        register(actions, 0x305, 0x180)
        register(actions, 0xB02)
        register(actions, 0x7B0, 7)
        if name == "step_pending_interrupt":
            register(actions, 0x304, 0x888)
            register(actions, 0x300, 0x1808)
            actions.append((INTERRUPTS, 0, 7, 0))
        actions.extend(((WRITE, 0x10, 0x40000001, 0), (POLL, 0x11, 0x30000, 0x30000),
                        (POLL, 0x11, 0x300, 0x300)))
        register(actions, 0x7B0)
        register(actions, 0x7B1)
        register(actions, 0xB02)
        register(actions, 0x1014)
        register(actions, 0x1011)
        for number in (0x341, 0x342, 0x343, 0x344):
            register(actions, number)
        if name == "step_pending_interrupt":
            actions.append((INTERRUPTS, 0, 0, 0))
        if name in ("step_illegal", "step_load_fault"):
            register(actions, 0x7B1, RESTART + 4)
        register(actions, 0x7B0, 3)
        actions.extend(base.actions[insertion:])
        result.append(DebugCase(name, stepped, actions, base.signature, steps=1, halts=2,
                                data_fault=fault_address))
    for name, prefix, user, target, cause in (
            ("step_load", [immediate(17, 0, DATA + 32, 3, 2)], False, RESTART + 4, 0),
            ("step_taken_branch", [branch(0, 0, 8), 0xFFFFFFFF], False, RESTART + 8, 0),
            ("step_mret", [0x30200073], False, RESTART + 4, 0),
            ("step_mret_user", [0x30200073], True, RESTART + 4, 0),
            ("step_ecall", [0x73], False, 0x180, 11),
            ("step_ecall_user", [0x73], True, 0x180, 8),
            ("step_pmp_fault", [immediate(17, 0, DATA + 32, 3, 2)], True, 0x180, 5)):
        if user and not protected_mode:
            continue
        stepped = dict(image)
        shifted = prefix + ending
        shifted[-1] = jump(0, DONE - RESTART - (len(shifted) - 1) * 4)
        stepped.update({RESTART + 4 * index: word for index, word in enumerate(shifted)})
        stepped[0x180], stepped[0x184], stepped[DATA + 32] = immediate(20, 20, 1), 0x6F, 0x11223344
        actions = list(base.actions[:insertion])
        register(actions, 0x305, 0x180)
        if user:
            register(actions, 0x3B0, (DATA + 32) >> 2)
            register(actions, 0x3B1, 0xFFFFFFFF)
            register(actions, 0x3A0, 0x1F10 if name == "step_pmp_fault" else 0x1F00)
        if name.startswith("step_mret"):
            register(actions, 0x341, RESTART + 4)
            register(actions, 0x300, 0 if user else 0x1800)
        starts_user = user and not name.startswith("step_mret")
        register(actions, 0x7B0, 4 if starts_user else 7)
        actions.extend(((WRITE, 0x10, 0x40000001, 0), (POLL, 0x11, 0x30000, 0x30000),
                        (POLL, 0x11, 0x300, 0x300)))
        for number in (0x7B0, 0x7B1, 0x1011, 0x1014, 0x341, 0x342, 0x343, 0x300):
            register(actions, number)
        if cause:
            register(actions, 0x7B1, RESTART + 4)
        register(actions, 0x7B0, 0 if user else 3)
        actions.extend(base.actions[insertion:])
        result.append(DebugCase(name, stepped, actions, base.signature, steps=1, halts=2,
                                step_outcome=(RESTART, target, bool(cause), cause, starts_user)))
    if protected_mode:
        interrupted = dict(image)
        user_code = [branch(22, 0, 0)] + ending
        user_code[-1] = jump(0, DONE - RESTART - (len(user_code) - 1) * 4)
        interrupted.update({RESTART + 4 * index: word for index, word in enumerate(user_code)})
        handler = [immediate(23, 23, -1), branch(23, 0, -4, unequal=True),
                   csr(24, 0x341, 0, 2), store(24, 1, 24), csr(24, 0x300, 0, 2), store(24, 1, 28),
                   csr(24, 0x342, 0, 2), store(24, 1, 32), immediate(22, 0, 1),
                   immediate(24, 0, 0x55), store(24, 1, 36), 0x30200073]
        interrupted.update({0x180 + 4 * index: word for index, word in enumerate(handler)})
        actions = list(base.actions[:insertion])
        for number, value in ((0x3B0, 0xFFFFFFFF), (0x3A0, 0x1F), (0x305, 0x180),
                              (0x304, 0x800), (0x300, 0), (0x1016, 0), (0x1017, 10000), (0x7B0, 0)):
            register(actions, number, value)
        actions.extend(((WRITE, 0x10, 0x40000001, 0), (POLL, 0x11, 0x30000, 0x30000),
                        (WAIT_RETIRE, RESTART, 0, 0), (INTERRUPTS, 0, 4, 0), (WAIT_IRQ, 0x8000000B, 1, 0),
                        (INTERRUPTS, 0, 0, 0), (WRITE, 0x10, 0x80000001, 0), (POLL, 0x11, 0x300, 0x300)))
        for number in (0x341, 0x342, 0x343, 0x300, 0x7B0, 0x7B1):
            register(actions, number)
        register(actions, 0x1017, 1)
        actions.extend(base.actions[insertion:])
        result.append(DebugCase("user_irq_handler_halt", interrupted, actions,
                                base.signature | {DATA + 24: RESTART, DATA + 28: 0,
                                                  DATA + 32: 0x8000000B, DATA + 36: 0x55},
                                halts=2, interrupts=1))
    return [replace(case, enable_m=enable_m, enable_c=enable_c, protected_mode=protected_mode,
                    enable_a=enable_a, enable_zba=enable_zba, enable_zbb=enable_zbb, enable_zbs=enable_zbs)
            for case in result if protected_mode or case.name not in ("abstract_memory_user", "halt_user_memory", "ebreak_user")]
