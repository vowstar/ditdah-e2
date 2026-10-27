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
from elf_mapping import instruction_ranges

ROOT = Path(__file__).resolve().parents[2]
LOCAL = Path(__file__).resolve().parent
RESET = 0x80000000


BIT_EXTENSIONS = ('Zba', 'Zbb', 'Zbs')


def isa_specification(enable_m=False, enable_c=False, *, enable_zba=False,
                      enable_zbb=False, enable_zbs=False):
    flags = enable_m, enable_c, enable_zba, enable_zbb, enable_zbs
    if any(type(value) is not bool for value in flags):
        raise ValueError("ISA configuration must be Boolean")
    text = (LOCAL / 'isa.yaml').read_text()
    bits = [name for name, enabled in zip(BIT_EXTENSIONS, flags[2:]) if enabled]
    isa = ('RV32I' + ('M' if enable_m else '') + ('C' if enable_c else '') +
           ('B' if all(flags[2:]) else '') + 'Zicsr' + ''.join('_' + name for name in bits))
    extensions = 0x100 | (0x1000 if enable_m else 0) | (4 if enable_c else 0) | (2 if all(flags[2:]) else 0)
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
        return 'selected'
    if isa in ('RV32I_Zca_Zcb', 'RV32IM_Zca_Zcb', 'RV32I_Zca_Zcb_Zbb'):
        return 'requires Zcb'
    raise ValueError('Unexpected compressed test declaration')


def architectural_configuration(isa):
    match = re.fullmatch(r'RV32I(M?)(C?)(B?)(Zicsr(?:_Zba)?(?:_Zbb)?(?:_Zbs)?)', isa)
    if match is None:
        raise ValueError('Unsupported architectural test configuration')
    if bool(match[3]) != all(name in match[4].split('_') for name in BIT_EXTENSIONS):
        raise ValueError('Unsupported architectural test configuration')
    enable_m, enable_c = bool(match[1]), bool(match[2])
    base = 'rv32i' + ('m' if enable_m else '') + ('c' if enable_c else '')
    return enable_m, enable_c, base + '_' + match[4].lower()


def test_extensions(isa):
    match = re.fullmatch(r'rv32i(m?)(c?)((?:_?z[a-z0-9]+)*)', isa.lower())
    if match is None:
        raise ValueError('Unsupported architectural test declaration')
    multi = re.findall(r'z[a-z0-9]+', match[3])
    if len(multi) != len(set(multi)) or set(multi) - {'zicsr', 'zba', 'zbb', 'zbs'}:
        raise ValueError('Unsupported architectural test declaration')
    return {'i', *match[1], *match[2], *multi}


def validate_test_isa(isa, march):
    if not test_extensions(isa) <= test_extensions(march):
        raise ValueError('Test exceeds the configured ISA')


def bit_test_extension(text):
    declarations = re.findall(r'RVTEST_ISA\("([^"]+)"\)', text)
    if len(declarations) != 1 or 'def rvtest_mtrap_routine=True' in text:
        raise ValueError('Unexpected bit test declaration')
    alternatives = declarations[0].split(',')
    supported = {'RV32I' + name: name for name in BIT_EXTENSIONS}
    unsupported = {'RV32IZbc', 'RV32IZbkb', 'RV32IZbkc', 'RV32IZk', 'RV32IZkn', 'RV32IZks'}
    if len(alternatives) != len(set(alternatives)) or set(alternatives) - supported.keys() - unsupported:
        raise ValueError('Unexpected bit test declaration')
    selected = [supported[name] for name in alternatives if name in supported]
    if len(selected) > 1:
        raise ValueError('Unexpected bit test declaration')
    return selected[0] if selected else None


def bit_test_instruction(path):
    name = Path(path).stem.removesuffix('-01')
    return {'orcb_32': 'orc.b', 'rev8_32': 'rev8', 'zext.h_32': 'zext.h'}.get(name, name)


def changed_andn_result(trace):
    lines = trace.splitlines()
    for index, line in enumerate(lines):
        fields = line.split()
        if fields[0] == 'R' and int(fields[3]) & 0xfe00707f == 0x40007033 and int(fields[6]):
            value = int(fields[7])
            fields[7] = str(value ^ 1)
            lines[index] = ' '.join(fields)
            return '\n'.join(lines) + '\n'
    raise ValueError('No ANDN register result to change')


def execution_case(words, reset, complete, *, enable_m=False, enable_c=False,
                   enable_zba=False, enable_zbb=False, enable_zbs=False, expected_causes=()):
    return SimpleNamespace(name='isa', words=lambda: words, reset=reset, instruction_fault=None,
                           data_fault=None, completion_pc=complete, expected_causes=expected_causes,
                           expected_interrupts=(), interrupt_schedule=(), signature={},
                           enable_m=enable_m, enable_c=enable_c, enable_zba=enable_zba,
                           enable_zbb=enable_zbb, enable_zbs=enable_zbs)


def validate_rtl_configuration(parameters, enable_m, enable_c, *, enable_zba=False,
                               enable_zbb=False, enable_zbs=False):
    names = {"resetVector", "enableM", "enableC", "protectedMode", "enableDebug", "enableA", "enableZba", "enableZbb", "enableZbs"}
    if not isinstance(parameters, dict) or parameters.keys() - names:
        raise ValueError("Unsupported RTL configuration")
    if any(type(parameters.get(name, False)) is not bool for name in names - {"resetVector"}):
        raise ValueError("RTL ISA configuration must be Boolean")
    if type(parameters.get("resetVector")) is not int or parameters["resetVector"] != RESET:
        raise ValueError("RTL reset configuration mismatch")
    if parameters.get("enableA", False):
        raise ValueError("This ISA collection does not use the atomic platform")
    if parameters.get("enableDebug", False):
        raise ValueError("This ISA collection requires debug disabled")
    if parameters.get("protectedMode", False):
        raise ValueError("This ISA collection requires the machine profile")
    flags = enable_m, enable_c, enable_zba, enable_zbb, enable_zbs
    keys = 'enableM', 'enableC', 'enableZba', 'enableZbb', 'enableZbs'
    if any(type(value) is not bool for value in flags) or flags != tuple(parameters.get(key, False) for key in keys):
        raise ValueError("RTL ISA configuration mismatch")


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


def normalize_elf(data, *, enable_c=False, mapped_data=False):
    if len(data) < 52 or data[:7] != b'\x7fELF\x01\x01\x01':
        raise ValueError('Expected ELF32 before metadata normalization')
    flags, = struct.unpack_from('<I', data, 36)
    if mapped_data:
        if flags & ~1:
            raise ValueError('Unsupported ELF flags')
        instruction_ranges(data, enable_c=enable_c)
        if enable_c:
            return data
        normalized = bytearray(data)
        struct.pack_into('<I', normalized, 36, 0)
        return bytes(normalized)
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
