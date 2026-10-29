# SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
# SPDX-License-Identifier: MIT
"""Check one menvcfg ELF on the native core and the fixed Spike model."""

import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT / 'test'), str(ROOT / 'scripts'), str(ROOT / 'test/isa')]
from elf import Region, load_elf
from protected_reference import reference_sequence, rtl_sequence, WARNING
from verify import check, checker_inputs, sources
from verify_protected import without_menvcfg


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def input_hashes():
    paths = {str(Path(module.__file__).resolve().relative_to(ROOT))
             for module in tuple(sys.modules.values())
             if getattr(module, '__file__', None)
             and Path(module.__file__).suffix == '.py'
             and Path(module.__file__).resolve().is_relative_to(ROOT)}
    paths.update(('test/pmp.py', 'Makefile', 'test/isa/menvcfg.sh', 'test/isa/test_menvcfg_reference.py',
                  'software/menvcfg_reference.S', 'software/menvcfg_reference.ld'))
    return checker_inputs() | sources() | {name: digest(ROOT / name) for name in paths}


def execute(command, output):
    result = subprocess.run(command, capture_output=True, text=True, timeout=120)
    output.with_suffix('.stdout').write_text(result.stdout)
    output.with_suffix('.stderr').write_text(result.stderr)
    assert result.returncode == 0, 'Command failed'
    return result


class ImageCase:
    instruction_fault = data_fault = None
    expected_interrupts = interrupt_schedule = ()

    def __init__(self, image, parameters):
        self.name = 'menvcfg_reference'
        self.image = image
        self.reset = image.entry
        self.completion_pc = image.symbols['software_done']
        for field, key in [('protected_mode', 'protectedMode'), ('enable_m', 'enableM'),
                           ('enable_c', 'enableC'), ('enable_a', 'enableA'),
                           ('enable_zba', 'enableZba'), ('enable_zbb', 'enableZbb'), ('enable_zbs', 'enableZbs')]:
            setattr(self, field, parameters[key])
        start = image.symbols['signature']
        self.signature = dict.fromkeys(range(start, start + 256, 4), 0)
        labels = [f'user_op{i}' if self.protected_mode else f'csr_op{i}' for i in range(6)]
        self.expected_traps = [(image.symbols[label], 2, image.words()[image.symbols[label]], int(self.protected_mode))
                               for label in labels]
        if self.protected_mode:
            self.expected_traps.append((image.symbols['user_ecall'], 8, 0, 1))
            for index in range(6):
                self.signature[start + 32 + 4 * index] = 55
        else:
            for index in range(6):
                self.signature[start + 4 * index] = 55
        self.expected_causes = tuple(row[1] for row in self.expected_traps)
        for index, (pc, cause, value, user) in enumerate(self.expected_traps):
            self.signature[start + 128 + 16 * index] = cause
            self.signature[start + 132 + 16 * index] = pc
            self.signature[start + 136 + 16 * index] = value
            self.signature[start + 140 + 16 * index] = 0 if user else 3

    def words(self):
        return self.image.words()


def reference_state(raw, expected):
    lines = [line for line in raw.splitlines() if line]
    assert lines[:2] == [WARNING, ':'] and lines[3] == 'M', 'Unexpected reference state'
    values = [lines[2], *lines[4:]]
    assert len(values) == len(expected)
    assert all(re.fullmatch(r'0x[0-9a-f]{8}', line) for line in values)
    actual = [int(line, 16) for line in values]
    assert actual == expected, 'Reference signature mismatch'
    return actual


def external_events(sequence, state, case):
    events = []
    trap_index = 0
    for index, (user, pc, word, write) in enumerate(sequence):
        if pc == case.image.symbols['trap_vector']:
            at = 1 + 32 + 4 * trap_index
            cause, fault_pc, tval, mpp = state[at:at + 4]
            assert index and cause in (2, 8)
            assert mpp in (0, 3), 'Unsupported trap privilege'
            events.append((int(mpp == 0), fault_pc, case.words()[fault_pc], None, 1, cause, tval))
            trap_index += 1
        events.append((user, pc, word, write, 0, 0, 0))
    assert trap_index == len(case.expected_traps)
    return [(*event, events[index + 1][1] if index + 1 < len(events) else event[1])
            for index, event in enumerate(events)]


def compare_external(trace, expected, completion):
    actual = []
    for line in trace.splitlines():
        fields = line.split()
        if not fields or fields[0] != 'R':
            continue
        pc, word, next_pc, rd, writes, value, trap, cause, tval, user = map(int, fields[2:])
        actual.append((user, pc, word, (rd, value) if writes else None, trap,
                       cause if trap else 0, tval if trap else 0, next_pc))
        if pc == completion:
            break
    assert len(actual) == len(expected), 'External architectural event count differs'
    assert actual == expected, 'External architectural event mismatch'
    accesses = [row for row in actual if row[2] & 0x7f == 0x73
                and (row[2] >> 12) & 7 in (1, 2, 3, 5, 6, 7) and row[2] >> 20 in (0x30a, 0x31a)]
    return {'events': len(actual), 'csrAccessesCompared': len(accesses),
            'successfulCsrResultsCompared': sum(not row[4] and row[3] is not None for row in accesses),
            'trapsCompared': sum(row[4] for row in actual), 'nextPcsCompared': len(actual)}


def reuse_simulator(previous, destination, rtl_hashes, tools, control=False):
    top = previous.parent / 'summary.json'
    profile = previous / 'summary.json'
    prior = json.loads(top.read_text())
    accepted = json.loads(profile.read_text())
    assert prior['exitStatus'] == accepted['exitStatus'] == 0
    for role in ('verilator', 'cxx', 'make'):
        assert tools[role] == prior['tools'][role], 'Simulator build tool differs'
    for name in ('test/sim.cpp', 'test/inactive_debug.hpp'):
        assert digest(ROOT / name) == prior['sourceHashes'][name], 'Simulator source differs'
        assert digest(previous.parent / 'inputs' / name) == prior['sourceHashes'][name]
    original = previous / 'rejected-csr-control' if control else previous
    record = accepted['rtlControl'] if control else accepted
    assert not record.get('build', {}).get('reused', False), 'Use an original simulator build'
    if control:
        compile_status = record['build']['exitStatus'] if 'build' in record else record['compileExitStatus']
        assert compile_status == record['exitStatus'] == 0
        old_hashes = record['rtlHashes']
    else:
        old_manifest = original / 'rtl/manifest.json'
        assert digest(old_manifest) == record['rtlManifestHash']
        old_hashes = json.loads(old_manifest.read_text())['rtlHashes']
    assert old_hashes == rtl_hashes, 'Simulator RTL differs'
    assert all(digest(original / 'rtl' / name) == value for name, value in old_hashes.items())
    executable = original / 'obj/VDitDahE2'
    assert digest(executable) == record['simulatorHash'], 'Simulator executable differs'
    destination.mkdir()
    shutil.copy2(executable, destination / executable.name)
    evidence = destination.parent / 'inherited-build'
    evidence.mkdir()
    files = [top, profile, *sorted((original / 'obj').glob('*.mk'))]
    prefix = 'compile' if control else 'rtl-build'
    files += [original / (prefix + suffix) for suffix in ('.stdout', '.stderr')]
    bindings = []
    for index, path in enumerate(files):
        target = evidence / (str(index) + '-' + path.name)
        shutil.copyfile(path, target)
        bindings.append({'source': str(path), 'copy': str(target), 'sha256': digest(target)})
    return {'reused': True, 'originalDirectory': str(original), 'evidence': bindings,
            'simulatorHash': digest(destination / executable.name),
            'originalCompileExitStatus': 0}


def rtl_control(case, expected, manifest, build_command, program, output, tools, previous):
    directory = output / 'rejected-csr-control'
    rtl = directory / 'rtl'
    rtl.mkdir(parents=True)
    address = case.words()[case.image.symbols['csr_op0']] >> 20
    for name in manifest['rtlHashes']:
        text = (output / 'rtl' / name).read_text()
        (rtl / name).write_text(without_menvcfg(text, address) if name == 'DitDahE2Csr.sv' else text)
    command = [str(rtl / Path(item).name) if item.endswith('.sv') else item for item in build_command]
    command[command.index('--Mdir') + 1] = str(directory / 'obj')
    rtl_hashes = {name: digest(rtl / name) for name in manifest['rtlHashes']}
    if previous:
        build = reuse_simulator(previous, directory / 'obj', rtl_hashes, tools, control=True)
    else:
        execute(command, directory / 'compile')
        build = {'reused': False, 'exitStatus': 0, 'command': command}
    simulator_hash = digest(directory / 'obj/VDitDahE2')
    run_command = [str(directory / 'obj/VDitDahE2'), str(program), '1', '24',
                   str(1 << 32), str(1 << 32), '50000', str(case.completion_pc)]
    result = execute(run_command, directory / 'execution')
    rows = [list(map(int, line.split()[2:])) for line in result.stdout.splitlines() if line.startswith('R ')]
    assert any(row[0] == case.image.symbols['csr_op0'] and row[6:9] == [1, 2, row[1]] for row in rows)
    try:
        compare_external(result.stdout, expected, case.completion_pc)
    except AssertionError as error:
        reason = str(error)
        assert reason in ('External architectural event count differs', 'External architectural event mismatch')
    else:
        raise AssertionError('External checker accepted rejected menvcfg')
    assert digest(directory / 'obj/VDitDahE2') == simulator_hash
    assert all(digest(rtl / name) == value for name, value in rtl_hashes.items())
    report = {'build': build, 'address': address, 'exitStatus': result.returncode, 'externalRejection': reason,
              'localModelCalledBeforeExternalComparison': False,
              'command': run_command, 'rtlHashes': rtl_hashes,
              'traceHash': hashlib.sha256(result.stdout.encode()).hexdigest(),
              'simulatorHash': digest(directory / 'obj/VDitDahE2')}
    (directory / 'summary.json').write_text(json.dumps(report, indent=2) + '\n')
    return report


def run_profile(name, rtl, output, linker, tools, previous=None, csr_address=0x30a):
    output.mkdir()
    manifest_path = rtl / 'manifest.json'
    manifest = json.loads(manifest_path.read_text())
    assert manifest['sourceHashes'] == sources(), 'RTL source inputs differ'
    assert all(digest(rtl / name) == value for name, value in manifest['rtlHashes'].items())
    parameters = manifest['parameters']
    assert parameters['resetVector'] == 0x80000000
    frozen = output / 'rtl'
    frozen.mkdir()
    for item in [*manifest['rtlHashes'], 'manifest.json']:
        shutil.copyfile(rtl / item, frozen / item)
    elf = output / 'program.elf'
    compile_command = [tools['compiler']['path'], '-march=rv32i_zicsr', '-mabi=ilp32', '-mno-relax',
                       '-nostdlib', '-nostartfiles', '-static', '-Wl,--no-relax', '-T', str(linker),
                       '-DUSER_PROFILE=' + str(int(parameters['protectedMode'])),
                       '-DENV_CSR=' + hex(csr_address),
                       str(ROOT / 'software/menvcfg_reference.S'), '-o', str(elf)]
    execute(compile_command, output / 'software-build')
    image = load_elf(elf, reset_vector=parameters['resetVector'], enable_c=parameters['enableC'],
                     regions=(Region('rom', 0x80000000, 0x10000, 5), Region('sram', 0x20000000, 0x10000, 7)))
    assert max(segment.address + segment.memory_size for segment in image.segments if segment.flags & 1) < 0x80001000
    case = ImageCase(image, parameters)
    program = output / 'program.hex'
    program.write_text(''.join(f'{address:08x} {word:08x}\n' for address, word in sorted(case.words().items())))
    simulator = output / 'obj/VDitDahE2'
    build_command = [tools['verilator']['path'], '--cc', '--exe', '--build', '-j', '2',
                     '--top-module', 'DitDahE2', '--Mdir', str(output / 'obj'), '-CFLAGS', '-std=c++17',
                     *[str(frozen / item) for item in manifest['rtlHashes']], str(ROOT / 'test/sim.cpp')]
    if previous:
        build = reuse_simulator(previous, output / 'obj', manifest['rtlHashes'], tools)
    else:
        execute(build_command, output / 'rtl-build')
        build = {'reused': False, 'exitStatus': 0, 'command': build_command}
    simulator_hash = digest(simulator)
    program_hash = digest(program)
    sequences, runs = [], []
    for seed, delay in ((0, 0), (1, 24), (19, 40)):
        command = [str(simulator), str(program), str(seed), str(delay), str(1 << 32), str(1 << 32),
                   '50000', str(case.completion_pc)]
        result = execute(command, output / f'rtl-s{seed}-d{delay}')
        metrics = check(case, result.stdout)
        sequence, traps = rtl_sequence(result.stdout, case.completion_pc)
        assert traps == case.expected_traps, 'RTL trap sequence differs'
        sequences.append(sequence)
        runs.append({'seed': seed, 'delay': delay, 'exitStatus': result.returncode,
                     'command': command, 'localModelPassed': True, 'traceHash': hashlib.sha256(result.stdout.encode()).hexdigest(), **metrics})
    (output / 'local-model.json').write_text(json.dumps({'exitStatus': 0, 'elfHash': digest(elf), 'runs': runs}, indent=2) + '\n')
    command_file = output / 'spike.commands'
    command_file.write_text('\n'.join(['rs 1000', 'pc 0', 'priv 0',
        *['mem ' + format(address, 'x') for address in case.signature], 'quit']) + '\n')
    isa = 'rv32i' + ('m' if parameters['enableM'] else '') + ('a' if parameters['enableA'] else '')
    isa += 'c' if parameters['enableC'] else ''
    isa += '_zicsr_zifencei_zicntr'
    isa += ''.join('_' + extension for key, extension in [('enableZba', 'zba'), ('enableZbb', 'zbb'), ('enableZbs', 'zbs')] if parameters[key])
    spike_command = [tools['spike']['path'], '--isa=' + isa, '--priv=' + ('mu' if parameters['protectedMode'] else 'm'),
                     '--pmpregions=16', '--pmpgranularity=4', '-m0x80000000:0x10000,0x20000000:0x10000', '--pc=0x80000000',
                     '--log-commits', '-l', '--log=' + str(output / 'commits.log'), '-d',
                     '--debug-cmd=' + str(command_file), str(elf)]
    reference = execute(spike_command, output / 'spike')
    assert not reference.stdout
    expected = [case.completion_pc, *case.signature.values()]
    state = reference_state(reference.stderr, expected)
    sequence, causes = reference_sequence((output / 'commits.log').read_text(), image.entry, case.completion_pc)
    assert causes == list(case.expected_causes)
    assert all(actual == sequence for actual in sequences), 'Successful instruction sequence differs'
    events = external_events(sequence, state, case)
    if parameters['protectedMode']:
        first_user = next(index for index, event in enumerate(events) if event[0])
        assert events[first_user][1] == image.symbols['user_op0'] and events[first_user][4] == 1
        assert events[first_user - 1][2] == 0x30200073
    for run in runs:
        trace = output / f"rtl-s{run['seed']}-d{run['delay']}.stdout"
        run['externalComparison'] = compare_external(trace.read_text(), events, case.completion_pc)
    (output / 'external-reference.json').write_text(json.dumps({'exitStatus': 0, 'elfHash': digest(elf),
        'events': events, 'trapCauses': causes, 'runs': [item['externalComparison'] for item in runs]}, indent=2) + '\n')
    bad = reference.stderr.replace('0x00000037\n', '0x00000036\n', 1)
    assert bad != reference.stderr
    (output / 'changed-signature.log').write_text(bad)
    try:
        reference_state(bad, expected)
    except AssertionError as error:
        assert str(error) == 'Reference signature mismatch'
    else:
        raise AssertionError('Changed signature was accepted')
    control = rtl_control(case, events, manifest, build_command, program, output, tools, previous) if parameters['protectedMode'] else None
    report = {'name': name, 'csrAddress': csr_address, 'parameters': parameters, 'isa': isa, 'rtlManifestHash': digest(manifest_path),
              'elfHash': digest(elf), 'simulatorHash': digest(simulator), 'compileCommand': compile_command,
              'programHash': program_hash, 'linkerHash': digest(linker),
              'build': build, 'spikeCommand': spike_command, 'runs': runs,
              'successfulInstructions': len(sequence), 'trapCauses': causes, 'expectedTraps': case.expected_traps,
              'expectedSignature': case.signature, 'signatureControlRejected': True,
              'rtlControl': control, 'exitStatus': 0,
              'fixedZeroEnvironmentCsrInBothSelectedImplementations': parameters['protectedMode']}
    assert digest(manifest_path) == report['rtlManifestHash']
    assert all(digest(rtl / key) == value for key, value in manifest['rtlHashes'].items())
    assert all(digest(frozen / key) == value for key, value in manifest['rtlHashes'].items())
    assert digest(simulator) == simulator_hash and digest(program) == program_hash
    (output / 'summary.json').write_text(json.dumps(report, indent=2) + '\n')
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--profile', action='append', required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--linker', type=Path, default=ROOT / 'software/menvcfg_reference.ld')
    parser.add_argument('--reuse-build', action='append', default=[], metavar='PROFILE=DIRECTORY')
    parser.add_argument('--csr-address', type=lambda text: int(text, 0), choices=(0x30a, 0x31a), default=0x30a)
    args = parser.parse_args()
    assert not args.output.exists()
    output = args.output.resolve()
    output.mkdir()
    initial = input_hashes()
    for name in initial:
        target = output / 'inputs' / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / name, target)
    linker_hash = digest(args.linker)
    frozen_linker = output / 'link.ld'
    shutil.copyfile(args.linker, frozen_linker)
    assert digest(frozen_linker) == linker_hash
    tools = {}
    for role, name, option in [('compiler', 'riscv32-none-elf-gcc', '--version'), ('spike', 'spike', '--help'),
                              ('verilator', 'verilator', '--version'), ('cxx', 'g++', '--version'),
                              ('make', 'make', '--version'), ('python', 'python3', '--version')]:
        path = Path(shutil.which(name)).resolve()
        result = execute([str(path), option], output / ('tool-' + role))
        tools[role] = {'path': str(path), 'sha256': digest(path), 'version': (result.stdout + result.stderr).splitlines()[0]}
    results = []
    reusable = dict(specification.split('=', 1) for specification in args.reuse_build)
    assert len(reusable) == len(args.reuse_build), 'Duplicate build reuse profile'
    names = set()
    for specification in args.profile:
        name, rtl = specification.split('=', 1)
        assert re.fullmatch('[a-z][a-z0-9-]*', name)
        assert name not in names, 'Duplicate profile'
        names.add(name)
        previous = Path(reusable.pop(name)).resolve() if name in reusable else None
        results.append(run_profile(name, Path(rtl).resolve(), output / name, frozen_linker, tools,
                                   previous, args.csr_address))
    assert not reusable, 'Unknown build reuse profile'
    assert initial == input_hashes(), 'Frozen input changed'
    assert all(digest(output / 'inputs' / name) == value for name, value in initial.items()), 'Input copy changed'
    assert digest(args.linker) == digest(frozen_linker) == linker_hash, 'Linker changed'
    assert all(digest(record['path']) == record['sha256'] for record in tools.values()), 'Tool changed'
    summary = {'scope': 'Fixed menvcfg programs with full successful retirement comparison and exact signatures',
               'exitStatus': 0, 'csrAddress': args.csr_address, 'sourceHashes': initial, 'tools': tools, 'results': results,
               'command': sys.argv, 'linkerHash': linker_hash,
               'referenceRevision': 'de5094a1a901d77ff44f89b38e00fefa15d4018e',
               'fixedZeroScope': 'The selected CSR reads zero and ignores writes when U-mode is enabled.'}
    (output / 'summary.json').write_text(json.dumps(summary, indent=2) + '\n')
    print('PASS: menvcfg reference check')


if __name__ == '__main__':
    main()
