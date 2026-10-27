# SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
# SPDX-License-Identifier: MIT
"""Run architectural tests through RISCOF adapters."""

import json
from pathlib import Path
import subprocess
import sys

from riscof.pluginTemplate import pluginTemplate
from machine_exceptions import changed_exception_cause, cleanup_exception_pc, machine_data_faults, machine_exception_causes, validate_machine_environment
from elf_mapping import instruction_pc, instruction_ranges
from isa_checks import BIT_EXTENSIONS, LOCAL, RESET, architectural_configuration, bit_test_instruction, changed_andn_result, digest, execution_case, load_program, normalize_elf, signature_words, test_extensions, validate_rtl_configuration, validate_test_isa


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
        self.bit_flags = {'enable_' + name.lower(): name.lower() in self.march.split('_')
                          for name in BIT_EXTENSIONS}

    def compile(self, entry):
        directory = Path(entry['work_dir'])
        elf = directory / (self.__model__ + '.elf')
        validate_test_isa(entry['isa'], self.march)
        causes = machine_exception_causes(entry['test_path'], enable_c=self.enable_c)
        if causes:
            validate_machine_environment(self.environment)
        command = ['riscv32-none-elf-gcc', '-march=' + self.march, '-mabi=ilp32',
                   '-mcmodel=medany', '-mno-relax', '-nostdlib', '-nostartfiles', '-static']
        includes = ['-I', str(LOCAL / 'env'), '-I', str(self.environment),
                    *['-D' + value for value in entry['macros']]]
        if Path(entry['test_path']).parent.parent.name == 'B':
            includes.append('-DDITDAH_E2_BIT_SIGNATURE')
        if causes:
            execute(command + includes + ['-c', entry['test_path'], '-o', 'test.o'], cwd=directory)
            execute(command + ['-Wl,--build-id=none', '-T', str(LOCAL / 'env/link.ld'),
                               'test.o', '-o', str(elf)], cwd=directory)
        else:
            execute(command + ['-Wl,--build-id=none,--discard-all', '-T', str(LOCAL / 'env/link.ld')] +
                    includes + [entry['test_path'], '-o', str(elf)], cwd=directory)
        original = elf.read_bytes()
        elf.with_suffix('.raw.elf').write_bytes(original)
        elf.write_bytes(normalize_elf(original, enable_c=self.enable_c, mapped_data=bool(causes)))
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
        validate_rtl_configuration(parameters, self.enable_m, self.enable_c, **self.bit_flags)
        for name, expected in manifest['sourceHashes'].items():
            if digest(self.inputs / name) != expected:
                raise ValueError("Frozen RTL source mismatch")
        for name, expected in manifest['rtlHashes'].items():
            if digest(rtl / name) != expected:
                raise ValueError("Frozen RTL artifact mismatch")
        self.bound = {path: digest(path) for path in
                      [rtl / name for name in manifest['rtlHashes']] +
                      [rtl / 'manifest.json'] + [self.inputs / name for name in manifest['sourceHashes']] +
                      [self.inputs / 'test/sim.cpp'] + sorted((self.inputs / 'test').glob('*.py')) +
                      sorted((self.inputs / 'test').glob('*.hpp'))}
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
            case = execution_case(words, RESET, complete, enable_m=self.enable_m, enable_c=self.enable_c,
                                  **self.bit_flags, expected_causes=machine_exception_causes(
                                      entry['test_path'], enable_c=self.enable_c))
            metrics = check(case, trace)
            metrics['expectedExceptionCauses'] = list(case.expected_causes)
            if case.expected_causes:
                ranges = instruction_ranges(elf.read_bytes(), enable_c=self.enable_c)
                data_faults = machine_data_faults(entry['test_path'], program)
                for line in trace.splitlines():
                    fields = line.split()
                    if fields[0] != 'R':
                        continue
                    pc = int(fields[2])
                    expected_fault = (int(fields[8]) == 1 and int(fields[9]) == 2 and
                                      data_faults.get(pc) == int(fields[3]) == int(fields[10]))
                    if not instruction_pc(ranges, pc, enable_c=self.enable_c) and not expected_fault:
                        raise ValueError('Retirement PC is outside mapped instructions')
                metrics['mappedDataFaults'] = data_faults
                metrics['mappedInstructionRanges'] = ranges
                changed = elf.with_suffix('.changed-exception.trace')
                changed.write_text(changed_exception_cause(trace))
                try:
                    check(case, changed.read_text())
                except AssertionError as error:
                    if str(error) != 'Fault metadata mismatch':
                        raise
                else:
                    raise AssertionError('Instruction checker accepted a changed exception cause')
                metrics['exceptionCauseControl'] = {
                    'traceHash': digest(changed), 'rejection': 'Fault metadata mismatch'}
                metrics['exceptionWitnesses'] = [
                    {'pc': int(fields[2]), 'cause': int(fields[9]), 'tval': int(fields[10])}
                    for line in trace.splitlines() if (fields := line.split())[0] == 'R' and int(fields[8])]
                if metrics['exceptionWitnesses'][-1] != {
                        'pc': cleanup_exception_pc(program), 'cause': 11, 'tval': 0}:
                    raise ValueError('Machine cleanup exception mismatch')
                metrics['testBodyExceptionCauses'] = list(case.expected_causes[:-1])

            memory = {int(fields[1]): int(fields[2]) for line in trace.splitlines()
                      if (fields := line.split())[0] == 'W'}
            if memory[program.symbols['tohost']] != 1:
                raise ValueError('Test did not report success through tohost')
            if 'c' in test_extensions(entry['isa']) and not any(
                    name.startswith('c.') and count for name, count in metrics['instructions'].items()):
                raise ValueError('Compressed test retired no compressed instructions')
            if Path(entry['test_path']).parent.parent.name == 'B':
                instruction = bit_test_instruction(entry['test_path'])
                if not metrics['instructions'].get(instruction, 0):
                    raise ValueError('Bit test did not retire its target instruction')
                metrics['targetInstruction'] = instruction
                stores = [fields for line in trace.splitlines() if (fields := line.split())[0] == 'Q' and
                          fields[2] == 'D' and int(fields[4]) and begin <= int(fields[3]) < end]
                if not stores:
                    raise ValueError('Bit test issued no signature store')
                metrics['signatureStores'] = len(stores)
                metrics['inlineDebugAssertion'] = False
                if instruction == 'andn':
                    altered = changed_andn_result(trace)
                    changed = elf.with_suffix('.changed.trace')
                    changed.write_text(altered)
                    try:
                        check(case, altered)
                    except AssertionError as error:
                        if str(error) != 'Register result mismatch':
                            raise
                    else:
                        raise AssertionError('Instruction checker accepted a wrong ANDN result')
                    metrics['resultNegativeControl'] = {
                        'traceHash': digest(changed), 'rejection': 'Register result mismatch'}
            metrics.update({'exitStatus': 0, 'completionPc': complete, 'completionWord': 0x6F, 'tohost': 1})
            self.signature_path(entry).write_text(''.join(f'{memory[address]:08x}\n' for address in range(begin, end, 4)))
            elf.with_suffix('.json').write_text(json.dumps(metrics, indent=2) + '\n')
        if any(digest(path) != expected for path, expected in self.bound.items()):
            raise ValueError("Verification inputs changed during execution")
