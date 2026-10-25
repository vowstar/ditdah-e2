# SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
# SPDX-License-Identifier: MIT
"""Build programs and DMI operations for processor debug checks."""

from dataclasses import dataclass

from programs import add, constant, immediate, jump, store


WAIT_RETIRE, READ, WRITE, POLL, IDLE, FINISH = range(6)
LOOP, RESTART, DONE, DATA = 0x100, 0x200, 0x300, 0x400
VALUE = 0x13579BDF


@dataclass
class DebugCase:
    name: str
    image: dict
    actions: list
    signature: dict
    steps: int = 0


def register(actions, number, value=None):
    if value is not None:
        actions.append((WRITE, 4, value, 0))
    actions.extend(((WRITE, 0x17, (2 << 20) | (1 << 17) | (int(value is not None) << 16) | number, 0),
                    (POLL, 0x16, 0, 1 << 12)))
    if value is None:
        actions.append((READ, 4, 0, 0))


def cases():
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
    ending = [immediate(11, 10, 9), store(10, 1, 8), store(11, 1, 12),
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
        for index in range(32):
            register(actions, 0x1000 + index)
        register(actions, 0x1000, 0xFFFFFFFF)
        register(actions, 0x1000)
        register(actions, 0x100A, VALUE)
        register(actions, 0x100A)
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
            register(actions, 0x7B0, 3)
            actions.extend(((WRITE, 0x10, 0x40000001, 0), (POLL, 0x11, 0x30000, 0x30000)))
        actions.extend(((WAIT_RETIRE, DONE, 0, 0), (FINISH, 0, 0, 0)))
        result.append(DebugCase("single_step" if stepping else "halt_resume", dict(image), actions,
                                {DATA + 8: VALUE, DATA + 12: VALUE + 9, DATA + 16: 2 * VALUE + 9}, int(stepping)))
    return result
