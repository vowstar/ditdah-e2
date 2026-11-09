# SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
# SPDX-License-Identifier: MIT
"""Bind the fixed machine exception tests to their source and cause sequence."""

import hashlib
from pathlib import Path


MACHINE_ENVIRONMENT = {
    'arch_test.h': 'cfb0d028baed0fd63e9bf6b8adbbd2a67d2e72b49e58a104659c5b87708f37bc',
    'test_macros.h': '8b8bd3808a303261f41662f4cf9ddca6108707daf9b6774f7288f1a0773390e0',
}


MACHINE_TESTS = {
    'ebreak.S': ((3,),
        '1f7218f5ad55cdd98c2aa90486b956a20d701c16f57e886415ff12e550052087'),
    'ecall.S': ((11,),
        '0398bf62830c8f25f57b9dba9d5b4f8f3713555f3eac41cd12d2ed960c891980'),
    'misalign-beq-01.S': ((0,),
        'a463f8f02c3eedc371c6c3dae295c9d47e15ab9af407350fa85f0187a05e7fd6'),
    'misalign-bge-01.S': ((0,),
        '4ccc3988735a5d5f3155bacabc3b75340b8c758fa1b795ae2ebaa278385b0e4a'),
    'misalign-bgeu-01.S': ((0,),
        '0b4e45b46560fc7baebcdcfea23ba76fb68a614718da5ee0329240705b698eb2'),
    'misalign-blt-01.S': ((0,),
        '3905e2bc92ff132e085c6961f054993cde4f0d8172388988af5a0f327085c75a'),
    'misalign-bltu-01.S': ((0,),
        'f6d5aff369b456d706883b2879d3f2502eb560c5c6f6196d7e9251504a0af7f3'),
    'misalign-bne-01.S': ((0,),
        '629bf2f72a11c76a8b870dfd4a9578bb72b3a5e5f76cc3195b57f1e64e6ba8a3'),
    'misalign-jal-01.S': ((0, 0, 2, 0),
        'd11ca9f1f89252fc545abb7f167b10c7897256dbef1e0a44f42b62c4978c7505'),
    'misalign-lh-01.S': ((4,),
        '4b5be6ec4041eab012f2c3f1b0acbbb618768329e410e8b3c49d14af4191f1df'),
    'misalign-lhu-01.S': ((4,),
        '8bd4984545d96d43708ce5f8329d219956786deb653e7527769ee0c1e6d2a15b'),
    'misalign-lw-01.S': ((4, 4, 4),
        'fe8df26385cceff9f17d723aad7f3c31e7f480f1c916e82e83939d5a42010fa2'),
    'misalign-sh-01.S': ((6,),
        '9806fec921d9ba6f44b73f5266269ac90c0db1339725e0a354f327a84c844830'),
    'misalign-sw-01.S': ((6, 6, 6),
        'cfb96ac2b158205fcc0ae884f7163ab348dd0490ae368faa3337747ea9fe38b8'),
    'misalign2-jalr-01.S': ((0,),
        'ca9996564ed881f89d5a50b454baaed6011a88d21a4e8b454da6d9123435af70'),
}


COMPRESSED_BREAKPOINT_HASH = 'a2b5f95de5f9faaea2161c81af270c57c53a16ddadcb11f7df87697ba41c48fc'


def machine_exception_causes(path, *, enable_c=False):
    path = Path(path)
    if path.parent.parent.name == 'C' and path.name == 'cebreak-01.S':
        if not enable_c:
            raise ValueError('Compressed breakpoint requires C enabled')
        if hashlib.sha256(path.read_bytes()).hexdigest() != COMPRESSED_BREAKPOINT_HASH:
            raise ValueError('Compressed breakpoint source changed')
        return (3, 11)
    if path.parent.parent.name != 'privilege':
        return ()
    if enable_c:
        raise ValueError('Machine exception tests require C disabled')
    if path.name not in MACHINE_TESTS:
        raise ValueError('Unselected machine exception test')
    causes, expected = MACHINE_TESTS[path.name]
    if hashlib.sha256(path.read_bytes()).hexdigest() != expected:
        raise ValueError('Machine exception test source changed')
    # The fixed RVTEST_CODE_END enters machine cleanup through ECALL.
    return causes + (11,)


def validate_machine_environment(directory):
    for name, expected in MACHINE_ENVIRONMENT.items():
        if hashlib.sha256((Path(directory) / name).read_bytes()).hexdigest() != expected:
            raise ValueError('Machine exception environment changed')


def cleanup_exception_pc(program):
    address = program.symbols['rvtest_code_end']
    words = program.words()
    if words.get(address) != 0x113 or words.get(address + 4) != 0x73:
        raise ValueError('Machine cleanup instructions changed')
    return address + 4


def changed_exception_cause(trace):
    lines = trace.splitlines()
    for index, line in enumerate(lines):
        fields = line.split()
        if fields and fields[0] == 'R' and len(fields) >= 11 and int(fields[8]):
            fields[9] = str(int(fields[9]) ^ 1)
            lines[index] = ' '.join(fields)
            return '\n'.join(lines) + '\n'
    raise ValueError('No exception cause to change')


def machine_data_faults(path, program):
    if Path(path).name != 'misalign-jal-01.S':
        return {}
    base = program.symbols['rvtest_code_begin']
    expected = {0xa0: 0x20a0056f, 0xb0: 0x22a0006f, 0x2a8: 0x45130000,
                0x2ac: 0x00010035, 0x2b4: 0x00000117, 0x2b8: 0x02610113,
                0x2d4: 0x00010067}
    words = program.words()
    if any(words.get(base + offset) != word for offset, word in expected.items()):
        raise ValueError('Machine JAL recovery layout changed')
    # The fixed recovery skips eight bytes and later reaches this data fill.
    return {base + 0x2a8: expected[0x2a8]}
