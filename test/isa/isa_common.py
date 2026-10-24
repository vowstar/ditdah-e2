# SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
# SPDX-License-Identifier: MIT
"""Run architectural tests through RISCOF adapters."""

import json
from pathlib import Path
import subprocess
import sys

from riscof.pluginTemplate import pluginTemplate
from isa_checks import LOCAL, RESET, digest, execution_case, load_program, normalize_elf, signature_words


def execute(command, *, cwd, timeout=180, output=None):
    result = subprocess.run(command, cwd=cwd, capture_output=True, text=True, timeout=timeout)
    if output is not None:
        output.write_text(result.stdout)
    if result.returncode:
        raise RuntimeError(f"{Path(command[0]).name} exited with {result.returncode}\n{result.stdout}{result.stderr}")
    return result.stdout


class Adapter(pluginTemplate):
    __version__ = '1'

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.config = kwargs['config']
        self.isa_spec = self.config['ispec']
        self.platform_spec = self.config['pspec']

    def initialise(self, suite, workdir, env):
        self.work = Path(workdir)
        self.environment = Path(env)

    def build(self, isa_yaml, platform_yaml):
        from riscof.utils import load_yaml
        spec = load_yaml(isa_yaml)['hart0']
        if spec['ISA'] != 'RV32IZicsr' or spec['supported_xlen'] != [32]:
            raise ValueError("Unsupported architectural test configuration")

    def compile(self, entry):
        directory = Path(entry['work_dir'])
        elf = directory / (self.__model__ + '.elf')
        if entry['isa'].lower() != 'rv32i':
            raise ValueError("Only RV32I tests are enabled")
        command = ['riscv32-none-elf-gcc', '-march=rv32i_zicsr', '-mabi=ilp32',
                   '-mcmodel=medany', '-mno-relax', '-nostdlib', '-nostartfiles',
                   '-static', '-Wl,--build-id=none,--discard-all', '-T', str(LOCAL / 'env/link.ld'),
                   '-I', str(LOCAL / 'env'), '-I', str(self.environment),
                   *['-D' + value for value in entry['macros']], entry['test_path'],
                   '-o', str(elf)]
        execute(command, cwd=directory)
        original = elf.read_bytes()
        elf.with_suffix('.raw.elf').write_bytes(original)
        elf.write_bytes(normalize_elf(original))
        return elf

    def signature_path(self, entry):
        return Path(entry['work_dir']) / (self.name[:-1] + '.signature')


class SpikeAdapter(Adapter):
    __model__ = 'spike_reference'

    def runTests(self, testlist):
        for entry in testlist.values():
            elf = self.compile(entry)
            shared = elf.parent.parent / 'dut/ditdah_e2.elf'
            if digest(elf) != digest(shared):
                raise ValueError('Reference and RTL compiled different executable images')
            elf = shared
            _, begin, end, _ = load_program(elf)
            signature = self.signature_path(entry)
            execute(['spike', '--isa=rv32i_zicsr', '--priv=m', '-m0x80000000:0x400000',
                     '+signature=' + str(signature), '+signature-granularity=4', str(elf)],
                    cwd=elf.parent)
            if len(signature_words(signature.read_text())) != (end - begin) // 4:
                raise ValueError("Incomplete Spike signature")


class RtlAdapter(Adapter):
    __model__ = 'ditdah_e2'

    def build(self, isa_yaml, platform_yaml):
        super().build(isa_yaml, platform_yaml)
        rtl = Path(self.config['rtl'])
        self.inputs = Path(self.config['inputs'])
        manifest = json.loads((rtl / 'manifest.json').read_text())
        if manifest['parameters'] != {'resetVector': RESET}:
            raise ValueError("RTL reset configuration mismatch")
        for name, expected in manifest['sourceHashes'].items():
            if digest(self.inputs / name) != expected:
                raise ValueError("Frozen RTL source mismatch")
        for name, expected in manifest['rtlHashes'].items():
            if digest(rtl / name) != expected:
                raise ValueError("Frozen RTL artifact mismatch")
        self.bound = {path: digest(path) for path in
                      [rtl / name for name in manifest['rtlHashes']] +
                      [rtl / 'manifest.json'] + [self.inputs / name for name in manifest['sourceHashes']] +
                      [self.inputs / 'test' / name for name in ('sim.cpp', 'model.py', 'programs.py', 'verify.py')]}
        self.binary = self.work / 'obj/VDitDahE2'
        execute(['verilator', '--cc', '--exe', '--build', '-j', '2', '--top-module', 'DitDahE2',
                 '--Mdir', str(self.binary.parent), '-CFLAGS', '-std=c++17',
                 *[str(rtl / name) for name in manifest['rtlHashes']],
                 str(self.inputs / 'test/sim.cpp')], cwd=self.work)

    def runTests(self, testlist):
        sys.path.insert(0, str(self.inputs / 'test'))
        from verify import check
        for entry in testlist.values():
            elf = self.compile(entry)
            program, begin, end, complete = load_program(elf)
            image = elf.with_suffix('.hex')
            words = program.words()
            image.write_text(''.join(f'{address:08x} {word:08x}\n' for address, word in sorted(words.items())))
            trace = execute([str(self.binary), str(image), '19', '40', str(1 << 32),
                             str(1 << 32), '1000000', str(complete)], cwd=elf.parent,
                            output=elf.with_suffix('.trace'))
            case = execution_case(words, RESET, complete)
            metrics = check(case, trace)
            memory = {int(fields[1]): int(fields[2]) for line in trace.splitlines()
                      if (fields := line.split())[0] == 'W'}
            self.signature_path(entry).write_text(''.join(f'{memory[address]:08x}\n' for address in range(begin, end, 4)))
            elf.with_suffix('.json').write_text(json.dumps(metrics, indent=2) + '\n')
        if any(digest(path) != expected for path, expected in self.bound.items()):
            raise ValueError("Verification inputs changed during execution")
