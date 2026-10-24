# SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
# SPDX-License-Identifier: MIT
"""Compare fixed RV32I architectural tests on Spike and bound RTL."""

import argparse
import configparser
import importlib.metadata
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

from isa_checks import ROOT, LOCAL, compare_signatures, digest, signature_words

ADD = 'rv32i_m/I/src/add-01.S'
REVISIONS = {
    'architecturalTests': 'fc32e41d49480fd99ba0a192dfff9c3319b44873',
    'riscof': '90ebd1bf48bc7928a5f6a7b0b4993f9fbc944f47',
    'spike': 'de5094a1a901d77ff44f89b38e00fefa15d4018e',
}


def inputs():
    paths = sorted(path for path in LOCAL.rglob('*')
                   if path.is_file() and path.suffix in ('.py', '.sh', '.yaml', '.md', '.h', '.ld'))
    paths += [ROOT / name for name in ('test/elf.py', 'nix/isa-tools.nix', 'flake.lock')]
    return {str(path.relative_to(ROOT)): digest(path) for path in paths}


def archive_inputs(output, bound):
    for name, expected in bound.items():
        if digest(ROOT / name) != expected:
            raise ValueError('Architectural test adapter inputs changed')
        target = output / 'inputs' / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / name, target)


def check_result(test, work, output):
    base = work / 'run' / test
    actual_file = base / 'dut/DUT-ditdah_e2.signature'
    reference_file = base / 'ref/Reference-spike_reference.signature'
    reference, actual = reference_file.read_text(), actual_file.read_text()
    compare_signatures(reference, actual)
    words = signature_words(actual)
    altered = '\n'.join(f'{word ^ (1 if index == 0 else 0):08x}' for index, word in enumerate(words)) + '\n'
    try:
        compare_signatures(reference, altered)
    except ValueError as error:
        if str(error) != 'Architectural signature mismatch':
            raise
    else:
        raise AssertionError('Signature checker accepted a changed result')
    if digest(base / 'dut/ditdah_e2.elf') != digest(base / 'ref/spike_reference.elf'):
        raise ValueError('Reference and RTL compiled different ELF images')
    output.mkdir(parents=True, exist_ok=True)
    for original, destination in ((reference_file, 'spike.signature'), (actual_file, 'rtl.signature'),
                                  (base / 'dut/ditdah_e2.elf', 'test.elf'),
                                  (base / 'dut/ditdah_e2.raw.elf', 'test.raw.elf'),
                                  (base / 'dut/ditdah_e2.trace', 'rtl.trace')):
        shutil.copyfile(original, output / destination)
    return {
        'test': test, 'exitStatus': 0, 'signatureWords': len(words),
        'elfHash': digest(output / 'test.elf'), 'rawElfHash': digest(output / 'test.raw.elf'),
        'signatureHash': digest(output / 'rtl.signature'), 'traceHash': digest(output / 'rtl.trace'),
        'negativeControls': 1, 'execution': json.loads((base / 'dut/ditdah_e2.json').read_text()),
    }


def run(args):
    source = Path(os.environ['ARCH_TEST_SOURCE'])
    suite_source = source / 'riscv-test-suite'
    tests = [ADD] if args.suite == 'add' else sorted(str(path.relative_to(suite_source))
                                                  for path in (suite_source / 'rv32i_m/I/src').glob('*.S'))
    if len(tests) != (1 if args.suite == 'add' else 39):
        raise ValueError('Unexpected fixed test collection')
    acceptance_hash = None
    if args.accepted:
        args.rtl = args.accepted / 'reset-80000000/rtl'
        args.source_root = args.accepted / 'inputs'
        acceptance = json.loads((args.accepted / 'acceptance.json').read_text())
        if acceptance['exitStatus'] != 0 or not any(item['configuration'] == 'reset-80000000' for item in acceptance['checks']):
            raise ValueError('The selected reset configuration lacks passing acceptance')
        for name, expected in acceptance['sourceHashes'].items():
            if digest(args.source_root / name) != expected:
                raise ValueError('Accepted source snapshot changed')
        acceptance_hash = digest(args.accepted / 'acceptance.json')
    bound = inputs()
    manifest = json.loads((args.rtl / 'manifest.json').read_text())
    candidate = {'rtl/manifest.json': args.rtl / 'manifest.json'}
    candidate.update({'rtl/' + name: args.rtl / name for name in manifest['rtlHashes']})
    candidate.update({'source/' + name: args.source_root / name for name in manifest['sourceHashes']})
    candidate.update({'source/test/' + name: args.source_root / 'test' / name
                      for name in ('sim.cpp', 'model.py', 'programs.py', 'verify.py')})
    candidate_hashes = {name: digest(path) for name, path in candidate.items()}
    dependencies = {name: importlib.metadata.version(name) for name in
                    ('riscof', 'riscv-config', 'riscv-isac', 'setuptools', 'GitPython', 'click', 'Jinja2', 'pytz')}
    args.output.mkdir(parents=True, exist_ok=True)
    scratch = '/data/tmp' if os.access('/data/tmp', os.W_OK) else None
    with tempfile.TemporaryDirectory(prefix='ditdah-e2-isa-', dir=scratch) as directory:
        work = Path(directory)
        suite = work / 'suite'
        for name in tests:
            target = suite / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.symlink_to(suite_source / name)
        config = configparser.ConfigParser()
        config['RISCOF'] = {
            'ReferencePlugin': 'spike_reference', 'ReferencePluginPath': str(LOCAL),
            'DUTPlugin': 'ditdah_e2', 'DUTPluginPath': str(LOCAL),
        }
        common = {'ispec': str(LOCAL / 'isa.yaml'), 'pspec': str(LOCAL / 'platform.yaml'),
                  'pluginpath': str(LOCAL)}
        config['spike_reference'] = common
        config['ditdah_e2'] = common | {'rtl': str(args.rtl), 'inputs': str(args.source_root)}
        with (work / 'config.ini').open('w') as stream:
            config.write(stream)
        help_run = subprocess.run(['riscof', 'run', '--help'], capture_output=True, text=True, check=True)
        if '--no-browser' not in help_run.stdout:
            raise ValueError('Unexpected RISCOF run interface')
        command = ['riscof', 'run', '--config', str(work / 'config.ini'), '--suite', str(suite),
                   '--env', str(suite_source / 'env'), '--work-dir', str(work / 'run'), '--no-browser']
        process = subprocess.run(command, capture_output=True, text=True, timeout=1800)
        log = (process.stdout + process.stderr).replace(str(work), '<work>').replace(str(ROOT), '<project>').replace(str(source), '<arch-tests>')
        (args.output / 'run.log').write_text(log)
        if process.returncode:
            for path in (work / 'run').rglob('*'):
                if path.is_file() and path.suffix in ('.elf', '.trace', '.signature', '.json'):
                    target = args.output / 'failure' / path.relative_to(work / 'run')
                    target.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copyfile(path, target)
            archive_inputs(args.output, bound)
            (args.output / 'failure.json').write_text(json.dumps({
                'exitStatus': process.returncode, 'selectedTests': tests, 'sourceHashes': bound,
                'revisions': REVISIONS, 'scope': 'execution failed before collection acceptance',
            }, indent=2) + '\n')
            raise RuntimeError(f'RISCOF failed with exit status {process.returncode}. See {args.output / "run.log"}')
        signatures = list((work / 'run').rglob('DUT-ditdah_e2.signature'))
        if len(signatures) != len(tests):
            raise ValueError('Not all selected tests produced signatures')
        results = [check_result(test, work, args.output if len(tests) == 1 else args.output / Path(test).stem)
                   for test in tests]
        if candidate_hashes != {name: digest(path) for name, path in candidate.items()}:
            raise ValueError('Candidate or checker inputs changed during execution')
        archive_inputs(args.output, bound)
        summary = {
            'scope': 'fixed RV32I architectural test signatures', 'suite': args.suite,
            'command': 'python3 test/isa/run.py', 'exitStatus': 0,
            'tests': results, 'testCount': len(tests), 'revisions': REVISIONS, 'pythonPackages': dependencies,
            'sourceHashes': bound, 'testHashes': {test: digest(suite_source / test) for test in tests},
            'candidateHashes': candidate_hashes,
            'environmentHashes': {str(path.relative_to(source)): digest(path)
                                  for path in sorted((suite_source / 'env').rglob('*')) if path.is_file()},
            'acceptanceHash': acceptance_hash, 'rtlManifestHash': digest(args.rtl / 'manifest.json'),
            'elfNormalization': 'clear RVC metadata after checking all executable bytes for 32-bit encodings',
            'compiler': subprocess.check_output(['riscv32-none-elf-gcc', '-dumpfullversion'], text=True).strip(),
            'verilator': subprocess.check_output(['verilator', '--version'], text=True).strip(),
            'negativeControls': len(tests),
            'memory': {'base': 0x80000000, 'size': 0x400000, 'resetVector': 0x80000000},
            'fullIsaCompliance': 'not run', 'coverageCommand': 'not run',
        }
        (args.output / 'summary.json').write_text(json.dumps(summary, indent=2) + '\n')
    print(f'PASS: {len(tests)} official tests, {sum(result["signatureWords"] for result in results)} signature words, {len(tests)} semantic negative controls')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    candidate = parser.add_mutually_exclusive_group(required=True)
    candidate.add_argument('--accepted', type=Path)
    candidate.add_argument('--rtl', type=Path)
    parser.add_argument('--source-root', type=Path)
    parser.add_argument('--suite', choices=('add', 'rv32i'), default='add')
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    if args.accepted and args.source_root:
        parser.error('--source-root cannot accompany --accepted')
    args.accepted = args.accepted.resolve() if args.accepted else None
    args.rtl = args.rtl.resolve() if args.rtl else None
    args.source_root = (args.source_root or Path('.')).resolve()
    args.output = (args.output or Path('result/isa-' + args.suite)).resolve()
    run(args)
