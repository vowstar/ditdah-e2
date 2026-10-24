# SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
# SPDX-License-Identifier: MIT
"""Validate architectural test ELF images and signatures."""

import hashlib
import importlib.util
from pathlib import Path
import re
import struct
import sys
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[2]
LOCAL = Path(__file__).resolve().parent
RESET = 0x80000000


def isa_specification(enable_m=False, enable_c=False):
    if type(enable_m) is not bool or type(enable_c) is not bool:
        raise ValueError("ISA configuration must be Boolean")
    text = (LOCAL / 'isa.yaml').read_text()
    isa = 'RV32I' + ('M' if enable_m else '') + ('C' if enable_c else '') + 'Zicsr'
    extensions = 0x100 | (0x1000 if enable_m else 0) | (4 if enable_c else 0)
    for old, new in (('RV32IZicsr', isa), ('0x40000100', hex(0x40000000 | extensions)),
                     ('[0x100]', f'[{hex(extensions)}]')):
        if text.count(old) != 1:
            raise ValueError("Architectural ISA template changed")
        text = text.replace(old, new)
    return text


def compressed_test_kind(name, text):
    declarations = re.findall(r'RVTEST_ISA\("([^"]+)"\)', text)
    if len(declarations) != 1:
        raise ValueError('Missing or duplicate architectural ISA declaration')
    isa = declarations[0]
    if isa == 'RV32IC' and 'def rvtest_mtrap_routine=True' not in text:
        return 'selected'
    if name == 'cebreak-01.S' and isa == 'RV32IC_Zicsr':
        return 'requires machine trap adapter'
    if isa in ('RV32I_Zca_Zcb', 'RV32IM_Zca_Zcb', 'RV32I_Zca_Zcb_Zbb'):
        return 'requires Zcb'
    raise ValueError('Unexpected compressed test declaration')


def architectural_configuration(isa):
    for enable_m, enable_c in ((False, False), (True, False), (False, True), (True, True)):
        name = 'RV32I' + ('M' if enable_m else '') + ('C' if enable_c else '')
        if isa == name + 'Zicsr':
            return enable_m, enable_c, name.lower() + '_zicsr'
    raise ValueError('Unsupported architectural test configuration')


def execution_case(words, reset, complete, *, enable_m=False, enable_c=False):
    return SimpleNamespace(name='isa', words=lambda: words, reset=reset, instruction_fault=None,
                           data_fault=None, completion_pc=complete, expected_causes=(),
                           expected_interrupts=(), interrupt_schedule=(), signature={},
                           enable_m=enable_m, enable_c=enable_c)


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def signature_words(text):
    lines = text.splitlines()
    if not lines or any(len(line) != 8 or any(c not in '0123456789abcdefABCDEF' for c in line) for line in lines):
        raise ValueError("Invalid signature format")
    return tuple(int(line, 16) for line in lines)


def compare_signatures(reference, actual):
    if signature_words(reference) != signature_words(actual):
        raise ValueError("Architectural signature mismatch")


def normalize_elf(data, *, enable_c=False):
    if len(data) < 52 or data[:7] != b'\x7fELF\x01\x01\x01':
        raise ValueError('Expected ELF32 before metadata normalization')
    flags, = struct.unpack_from('<I', data, 36)
    if enable_c:
        if flags & ~1:
            raise ValueError('Unsupported ELF flags')
        return data
    if flags == 0:
        return data
    if flags != 1:
        raise ValueError('Unsupported ELF flags')
    phoff, = struct.unpack_from('<I', data, 28)
    phsize, phnum = struct.unpack_from('<HH', data, 42)
    if phsize != 32 or not phnum or phoff + phsize * phnum > len(data):
        raise ValueError('Invalid ELF program headers')
    executable = 0
    for index in range(phnum):
        kind, offset, virtual, _, size, _, access, _ = struct.unpack_from('<8I', data, phoff + index * phsize)
        if kind != 1 or not access & 1:
            continue
        if virtual % 4 or size % 4 or offset + size > len(data):
            raise ValueError('Executable segment is not word aligned')
        for at in range(offset, offset + size, 4):
            word, = struct.unpack_from('<I', data, at)
            if word & 3 != 3 or word & 31 == 31:
                raise ValueError('Executable segment contains a non-32-bit encoding')
        executable += size
    if not executable:
        raise ValueError('Missing executable bytes')
    normalized = bytearray(data)
    struct.pack_into('<I', normalized, 36, 0)
    return bytes(normalized)


def load_program(path, *, enable_c=False):
    spec = importlib.util.spec_from_file_location('isa_elf', ROOT / 'test/elf.py')
    loader = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = loader
    spec.loader.exec_module(loader)
    image = loader.load_elf(path, reset_vector=RESET,
                            regions=(loader.Region('test_ram', RESET, 0x400000, 7),), enable_c=enable_c)
    begin, end, complete = (image.symbols[name] for name in
                            ('begin_signature', 'end_signature', 'test_complete'))
    if begin % 4 or end % 4 or begin >= end:
        raise ValueError("Invalid signature extent")
    if any(address not in image.memory for address in range(begin, end)):
        raise ValueError("Signature exceeds loaded memory")
    if complete % 4 or image.words().get(complete) != 0x6f:
        raise ValueError("Missing completion loop")
    return image, begin, end, complete
