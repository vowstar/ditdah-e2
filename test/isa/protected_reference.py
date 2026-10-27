# SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
# SPDX-License-Identifier: MIT
"""Compare one checked U/PMP platform workload with the fixed Spike model."""

import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT / 'test'), str(ROOT / 'scripts')]
from elf import Region, load_elf
from verify_platform import check, verify_platform_inputs

PARAMETERS = {
    'resetVector': 0x80000000, 'enableM': True, 'enableC': True,
    'protectedMode': True, 'enableDebug': False, 'enableA': False,
    'enableZba': False, 'enableZbb': False, 'enableZbs': False,
}
REGIONS = {
    'rom': {'base': 0x80000000, 'size': 0x10000},
    'sram': {'base': 0x20000000, 'size': 0x10000},
    'console': {'base': 0x30000000, 'size': 0x1000},
    'timer': {'base': 0x10001000, 'size': 0x1000},
}
WARNING = "warning: tohost and fromhost symbols not in ELF; can't communicate with target"


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def reference_state(raw, expected):
    lines = [line for line in raw.splitlines() if line]
    assert lines[:2] == [WARNING, ':'], 'Unexpected reference diagnostic'
    assert len(lines) == 12 and lines[3] == 'M', 'Reference final privilege differs'
    numeric = [lines[2], *lines[4:]]
    assert all(re.fullmatch(r'0x[0-9a-f]{8}', line) for line in numeric), 'Invalid reference value'
    values = [int(line, 16) for line in numeric]
    assert values == expected, 'Reference signature mismatch'
    return values


def rtl_sequence(trace, completion):
    sequence, traps = [], []
    for line in trace.splitlines():
        fields = line.split()
        if not fields or fields[0] != 'R':
            continue
        pc, word, next_pc, rd, writes, value, trap, cause, tval, user = map(int, fields[2:])
        if trap:
            traps.append((pc, cause, tval, user))
        else:
            sequence.append((user, pc, word, (rd, value) if writes else None))
        if pc == completion:
            assert not trap, 'Completion instruction trapped'
            return sequence, traps
    raise AssertionError('RTL completion is missing')


def reference_sequence(raw, entry, completion):
    sequence, causes = [], []
    started = False
    for line in raw.splitlines():
        match = re.fullmatch(r'core\s+0: ([03]) (0x[0-9a-f]{8}) \((0x[0-9a-f]+)\)(.*)', line)
        assert match, 'Unexpected reference commit record'
        privilege, pc, word = int(match[1]), int(match[2], 16), int(match[3], 16)
        started = started or pc == entry
        if not started:
            continue
        register = re.search(r'\bx(\d+)\s+0x([0-9a-f]{8})', match[4])
        write = (int(register[1]), int(register[2], 16)) if register else None
        sequence.append((int(privilege == 0), pc, word, write))
        if word & 0x7f == 0x73 and word >> 20 == 0x342:
            assert write is not None, 'Trap cause read is missing'
            causes.append(write[1])
        if pc == completion:
            return sequence, causes
    raise AssertionError('Reference completion is missing')


def run(verification, output):
    assert not output.exists(), 'Reference output already exists'
    verification_hash = digest(verification / 'summary.json')
    summary = json.loads((verification / 'summary.json').read_text())
    assert summary['workload'] == 'protected' and summary['exitStatus'] == 0
    assert summary['parameters'] == PARAMETERS and summary['regions'] == REGIONS, 'Reference profile differs'
    manifest = json.loads((verification / 'platform/manifest.json').read_text())
    assert manifest['parameters']['core'] == PARAMETERS and manifest['regions'] == REGIONS
    assert digest(verification / 'platform/manifest.json') == summary['platformManifestHash']
    bound = verify_platform_inputs(verification / 'platform', manifest)
    for name, expected in summary['inputHashes'].items():
        assert digest(verification / 'inputs' / name) == digest(ROOT / name) == expected, 'Checker input differs'
    elf = verification / 'software/program.elf'
    assert digest(elf) == summary['software']['artifactHashes']['program.elf'], 'ELF input differs'
    memory = tuple(Region(name, REGIONS[name]['base'], REGIONS[name]['size'], access)
                   for name, access in [('rom', 5), ('sram', 7)])
    image = load_elf(elf, reset_vector=PARAMETERS['resetVector'], enable_c=True, regions=memory)
    expected = [1, 7, image.symbols['denied_store'], image.symbols['protected_word'],
                0x13579bdf, 8, 0x2468ace0]
    sequences, trace_hashes = [], {}
    assert [(run['seed'], run['delay']) for run in summary['runs']] == [(0, 0), (1, 9), (19, 24)]
    for result in summary['runs']:
        name = f"protected-s{result['seed']}-d{result['delay']}.trace"
        trace = verification / name
        assert digest(trace) == result['traceHash'] and result['exitStatus'] == 0
        metrics = check(image, PARAMETERS, REGIONS, trace.read_text(), 'protected')
        for key, value in metrics.items():
            assert json.loads(json.dumps(value)) == result[key], 'RTL report differs'
        sequence, traps = rtl_sequence(trace.read_text(), image.symbols['software_done'])
        assert traps == [(image.symbols['denied_store'], 7, image.symbols['protected_word'], 1),
                         (image.symbols['user_ecall'], 8, 0, 1)], 'RTL trap sequence differs'
        assert metrics['observations'] == expected
        sequences.append(sequence)
        trace_hashes[name] = digest(trace)
    dependencies = set(summary['inputHashes']) | {
        'test/isa/protected_reference.py', 'test/isa/protected.sh',
        'nix/isa-tools.nix', 'nix/toolchain.nix', 'nix/stable-toolchain.nix', 'flake.nix', 'flake.lock',
    }
    sources = {name: digest(ROOT / name) for name in sorted(dependencies)}
    output.mkdir(parents=True)
    for name in sources:
        target = output / 'inputs' / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / name, target)
    commands = ['rs 2000', 'pc 0', 'priv 0']
    commands += ['mem ' + format(image.symbols['protected_signature'] + 4 * index, 'x') for index in range(7)]
    commands += ['mem ' + format(image.symbols['protected_word'], 'x'), 'quit']
    (output / 'commands.txt').write_text('\n'.join(commands) + '\n')
    spike = Path(shutil.which('spike')).resolve()
    tool_hash = digest(spike)
    help_run = subprocess.run([str(spike), '--help'], capture_output=True, text=True, check=True)
    help_text = help_run.stdout + help_run.stderr
    (output / 'spike-help.txt').write_text(help_text)
    version = help_text.splitlines()[0]
    assert version.startswith('Spike RISC-V ISA Simulator '), 'Unexpected reference tool'
    command = [str(spike), '--isa=rv32imc_zicsr_zifencei_zicntr', '--priv=mu',
               '--pmpregions=16', '--pmpgranularity=4',
               '-m0x80000000:0x10000,0x30000000:0x1000,0x20000000:0x10000',
               '--log-commits', '-l', '--log=' + str(output / 'commits.log'),
               '-d', '--debug-cmd=' + str(output / 'commands.txt'), str(elf)]
    process = subprocess.run(command, capture_output=True, text=True, timeout=15)
    (output / 'stdout.log').write_text(process.stdout)
    (output / 'stderr.log').write_text(process.stderr)
    assert process.returncode == 0 and not process.stdout, 'Reference execution failed'
    state = [image.symbols['software_done'], *expected, 0x13579bdf]
    reference_state(process.stderr, state)
    sequence, causes = reference_sequence((output / 'commits.log').read_text(), image.entry,
                                          image.symbols['software_done'])
    assert causes == [7, 8] and all(actual == sequence for actual in sequences), 'Architectural sequence differs'
    bad = process.stderr.replace('0x00000001\n', '0x00000000\n', 1)
    assert bad != process.stderr
    (output / 'changed-signature.log').write_text(bad)
    try:
        reference_state(bad, state)
    except AssertionError as error:
        assert str(error) == 'Reference signature mismatch'
    else:
        raise AssertionError('Reference checker accepted a changed signature')
    assert digest(spike) == tool_hash and digest(elf) == summary['software']['artifactHashes']['program.elf']
    assert all(digest(path) == value for path, value in bound.items()), 'Platform inputs changed'
    assert sources == {name: digest(ROOT / name) for name in sources}, 'Checker inputs changed'
    assert digest(verification / 'summary.json') == verification_hash, 'Verification input changed'
    assert all(digest(verification / name) == value for name, value in trace_hashes.items()), 'RTL trace changed'
    normalized = [item.replace(str(output), '<output>').replace(str(verification), '<verification>') for item in command]
    normalized[0] = 'spike'
    report = {
        'scope': 'One compiled U/PMP workload with the same ELF on RTL and Spike',
        'exitStatus': 0, 'parameters': PARAMETERS, 'regions': REGIONS, 'command': normalized,
        'spikeHash': tool_hash, 'spikeVersion': version,
        'referenceRevision': 'de5094a1a901d77ff44f89b38e00fefa15d4018e',
        'verificationHash': verification_hash, 'elfHash': digest(elf),
        'sourceHashes': sources, 'traceHashes': trace_hashes,
        'rtlRuns': len(sequences), 'successfulInstructions': len(sequence),
        'successfulUserInstructions': sum(item[0] for item in sequence), 'userTraps': 2,
        'trapCauses': causes, 'signature': expected, 'negativeControls': 1,
        'artifactHashes': {name: digest(output / name) for name in
                           ('commands.txt', 'commits.log', 'stdout.log', 'stderr.log', 'changed-signature.log', 'spike-help.txt')},
        'officialPrivilegeSuite': False, 'physicalAcceptance': False,
    }
    (output / 'summary.json').write_text(json.dumps(report, indent=2) + '\n')
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--verification', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    report = run(args.verification.resolve(), args.output.resolve())
    print(f"PASS: {report['rtlRuns']} RTL traces and {report['successfulInstructions']} successful instructions match Spike")


if __name__ == '__main__':
    main()
