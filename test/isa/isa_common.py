# SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
# SPDX-License-Identifier: MIT
"""Run architectural tests through RISCOF adapters."""

import json
from pathlib import Path
import subprocess
import sys

from riscof.pluginTemplate import pluginTemplate
from isa_checks import LOCAL, RESET, architectural_configuration, digest, execution_case, load_program, normalize_elf, signature_words


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
        if spec['supported_xlen'] != [32]:
            raise ValueError("Unsupported architectural test configuration")
        self.enable_m, self.enable_c, self.march = architectural_configuration(spec['ISA'])

    def compile(self, entry):
        directory = Path(entry['work_dir'])
        elf = directory / (self.__model__ + '.elf')
        isa = entry['isa'].lower()
        if isa not in ('rv32i', 'rv32im', 'rv32ic', 'rv32imc') or (
                'm' in isa[5:] and not self.enable_m) or ('c' in isa[5:] and not self.enable_c):
            raise ValueError("Test exceeds the configured ISA")
        command = ['riscv32-none-elf-gcc', '-march=' + self.march, '-mabi=ilp32',
                   '-mcmodel=medany', '-mno-relax', '-nostdlib', '-nostartfiles',
                   '-static', '-Wl,--build-id=none,--discard-all', '-T', str(LOCAL / 'env/link.ld'),
                   '-I', str(LOCAL / 'env'), '-I', str(self.environment),
                   *['-D' + value for value in entry['macros']], entry['test_path'],
                   '-o', str(elf)]
        execute(command, cwd=directory)
        original = elf.read_bytes()
        elf.with_suffix('.raw.elf').write_bytes(original)
        elf.write_bytes(normalize_elf(original, enable_c=self.enable_c))
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
            _, begin, end, complete = load_program(elf, enable_c=self.enable_c)
            signature = self.signature_path(entry)
            execute(['spike', '--isa=' + self.march, '--priv=m', '-m0x80000000:0x400000',
                     '+signature=' + str(signature), '+signature-granularity=4', str(elf)],
                    cwd=elf.parent)
            if len(signature_words(signature.read_text())) != (end - begin) // 4:
                raise ValueError("Incomplete Spike signature")
            (Path(entry['work_dir']) / 'spike_reference.json').write_text(json.dumps({
                'exitStatus': 0, 'isa': self.march, 'elfHash': digest(elf),
                'completionPc': complete, 'signatureHash': digest(signature)}, indent=2) + '\n')


class RtlAdapter(Adapter):
    __model__ = 'ditdah_e2'

    def build(self, isa_yaml, platform_yaml):
        super().build(isa_yaml, platform_yaml)
        rtl = Path(self.config['rtl'])
        self.inputs = Path(self.config['inputs'])
        manifest = json.loads((rtl / 'manifest.json').read_text())
        parameters = manifest['parameters']
        if any(type(parameters.get(name, False)) is not bool for name in ('enableM', 'enableC')):
            raise ValueError("RTL ISA configuration must be Boolean")
        if (self.enable_m, self.enable_c) != (parameters.get('enableM', False), parameters.get('enableC', False)):
            raise ValueError("RTL ISA configuration mismatch")
        if (parameters.get('resetVector') != RESET or parameters.keys() - {'resetVector', 'enableM', 'enableC'} or
                type(self.enable_m) is not bool or type(self.enable_c) is not bool):
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
                      [self.inputs / 'test/sim.cpp'] + sorted((self.inputs / 'test').glob('*.py'))}
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
            program, begin, end, complete = load_program(elf, enable_c=self.enable_c)
            image = elf.with_suffix('.hex')
            words = program.words()
            image.write_text(''.join(f'{address:08x} {word:08x}\n' for address, word in sorted(words.items())))
            trace = execute([str(self.binary), str(image), '19', '40', str(1 << 32),
                             str(1 << 32), '1000000', str(complete)], cwd=elf.parent,
                            output=elf.with_suffix('.trace'))
            case = execution_case(words, RESET, complete, enable_m=self.enable_m, enable_c=self.enable_c)
            metrics = check(case, trace)
            memory = {int(fields[1]): int(fields[2]) for line in trace.splitlines()
                      if (fields := line.split())[0] == 'W'}
            if memory[program.symbols['tohost']] != 1:
                raise ValueError('Test did not report success through tohost')
            if self.enable_c and 'c' in entry['isa'].lower()[5:] and not any(
                    name.startswith('c.') and count for name, count in metrics['instructions'].items()):
                raise ValueError('Compressed test retired no compressed instructions')
            metrics.update({'exitStatus': 0, 'completionPc': complete, 'completionWord': 0x6F, 'tohost': 1})
            self.signature_path(entry).write_text(''.join(f'{memory[address]:08x}\n' for address in range(begin, end, 4)))
            elf.with_suffix('.json').write_text(json.dumps(metrics, indent=2) + '\n')
        if any(digest(path) != expected for path, expected in self.bound.items()):
            raise ValueError("Verification inputs changed during execution")
