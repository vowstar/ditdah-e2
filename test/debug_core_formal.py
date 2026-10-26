# SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
# SPDX-License-Identifier: MIT
"""Bound precise halt and single step through the complete processor DMI path."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess

from core_formal import check_inputs, freeze_design, freeze_tools, tool_versions, write_snapshot

OBSERVATIONS = {'observed_halted': ('_debug_debug_status_halted', 1),
                'observed_resume': ('_debug_core_resume', 1),
                'observed_step': ('_debug_core_singleStep', 1),
                'observed_dpc': ('_debug_core_resumePc', 32)}
CASES = ('safety', 'normal', 'load-fault', 'illegal', 'older-fault', 'early-halt', 'extra-step')


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def observe(source):
    match = re.search(r'module DitDahE2\((.*?)\n\);', source, re.S)
    if not match:
        raise ValueError('Core module port list changed')
    declarations = []
    assignments = []
    for name, (original, width) in OBSERVATIONS.items():
        if not re.search(r'\bwire\s+(?:\[[^]]+\]\s+)?' + original + r'\s*;', source):
            raise ValueError('Missing debug observation: ' + original)
        declarations.append('  output ' + ('[31:0] ' if width == 32 else '') + name)
        assignments.append(f'  assign {name} = {original};')
    changed = source[:match.end(1)] + ',\n' + ',\n'.join(declarations) + source[match.end(1):]
    if changed.count('endmodule') != 1:
        raise ValueError('Unexpected core module count')
    return changed.replace('endmodule', '\n'.join(assignments) + '\nendmodule')


def mutate(source, name):
    if name == 'early-halt':
        pattern = r'(wire\s+\w+\s*=\s*)core_empty\s*&\s*core_fetchIdle;'
        changed, count = re.subn(pattern, r"\g<1>1'b1;", source)
    elif name == 'extra-step':
        pattern = r'(assign\s+core_stop\s*=\s*)([^;]+);'
        changed, count = re.subn(pattern, r'\g<1>(\2) & ~core_completed;', source)
    else:
        raise ValueError('Unknown debug mutation')
    if count != 1:
        raise ValueError('Changed debug mutation target')
    return changed


def drain_schedule(wrapper):
    declaration = b'  (* anyconst *) reg [1:0] initial_delay, stepped_delay;'
    if wrapper.count(declaration) != 1:
        raise ValueError('Changed initial response schedule')
    return wrapper.replace(declaration, b'  wire [1:0] initial_delay = 2;\n  (* anyconst *) reg [1:0] stepped_delay;')


def trace_witness(path, condition):
    identifiers, values, time = {}, {}, 0
    for line in path.read_text().splitlines():
        words = line.split()
        if words and words[0] == '$var':
            identifiers[words[3]] = words[4]
        elif line.startswith('#'):
            if condition(values):
                return {'time': time, **values}
            time = int(line[1:])
        elif line.startswith('b'):
            value, identifier = line[1:].split()
            if identifier in identifiers and set(value) <= {'0', '1'}:
                values[identifiers[identifier]] = int(value, 2)
        elif len(line) > 1 and line[0] in '01' and line[1:] in identifiers:
            values[identifiers[line[1:]]] = int(line[0])
    if condition(values):
        return {'time': time, **values}
    raise ValueError('Trace lacks the required semantic witness')


def run_case(output, rtl, wrapper, name, depth, timeout):
    work = output / name
    work.mkdir()
    for filename, content in rtl.items():
        text = content.decode()
        if filename == 'DitDahE2.sv':
            text = observe(text)
        if filename == 'DitDahE2DebugHart.sv' and name in ('early-halt', 'extra-step'):
            text = mutate(text, name)
        (work / filename).write_text(text)
    if name == 'early-halt':
        wrapper = drain_schedule(wrapper)
    (work / 'debug_core_formal.sv').write_bytes(wrapper)
    targets = {'normal': 0, 'load-fault': 1, 'illegal': 2, 'older-fault': 3}
    defines = '-DREACHABILITY ' if name in targets else ''
    parameter = f'chparam -set TARGET {targets[name]} debug_core_formal\n' if name in targets else ''
    files = [*rtl, 'debug_core_formal.sv']
    config = (f'[options]\nmode bmc\ndepth {depth}\ntimeout {timeout}\nvcd_sim on\n'
              '[engines]\nabc bmc3\n[script]\n'
              f'read -formal -sv {defines}' + ' '.join(files) + '\n' + parameter +
              'prep -top debug_core_formal\n[files]\n' + '\n'.join(files) + '\n')
    (work / 'run.sby').write_text(config)
    inputs = {str(p.name): digest(p) for p in work.iterdir() if p.is_file()}
    print('Running', name, flush=True)
    process = subprocess.Popen(['sby', '-f', 'run.sby'], cwd=work, text=True,
                               stdout=subprocess.PIPE, stderr=subprocess.STDOUT, start_new_session=True)
    timed_out = False
    try:
        log, _ = process.communicate(timeout=timeout + 20)
    except subprocess.TimeoutExpired:
        timed_out = True
        os.killpg(process.pid, signal.SIGTERM)
        try:
            log, _ = process.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            log, _ = process.communicate()
    (work / 'console.log').write_text(log.replace(str(output.resolve()), '<evidence>'))
    status_file = work / 'run/status'
    status = 'TIMEOUT' if timed_out else status_file.read_text().split()[0] if status_file.exists() else 'ERROR'
    result = {'name': name, 'engine': 'abc bmc3', 'mode': 'bmc', 'depth': depth,
              'timeoutSeconds': timeout, 'status': status, 'exitStatus': process.returncode,
              'command': ['sby', '-f', 'run.sby'], 'inputHashes': inputs}
    wanted = 'PASS' if name == 'safety' else 'FAIL'
    result['accepted'] = status == wanted and process.returncode == (0 if name == 'safety' else 2)
    if result['accepted'] and name != 'safety':
        traces = list((work / 'run/engine_0').glob('trace*.vcd'))
        if not traces:
            result['accepted'] = False
            result['error'] = 'Missing VCD witness'
        else:
            if name in targets:
                condition = lambda v: v.get('finished') == 1 and v.get('phase') == 11 and v.get('scenario') == targets[name] and (name != 'normal' or v.get('saw_delayed_halt') == 1)
            else:
                field = 'early_halt' if name == 'early-halt' else 'extra_step'
                condition = lambda v: v.get(field) == 1 and (name != 'early-halt' or v.get('data_busy') == 1)
            try:
                witness = trace_witness(traces[0], condition)
                result['witness'] = {key: value for key, value in witness.items() if key in
                                     {'time', 'scenario', 'phase', 'finished', 'early_halt', 'extra_step',
                                      'step_count', 'observed_dpc', 'saw_delayed_halt', 'saw_step_fault', 'saw_initial_fault',
                                      'data_busy', 'instruction_busy', 'observed_halted', 'retire_valid', 'cycle'}}
                result['traceHash'] = digest(traces[0])
            except ValueError as error:
                result['accepted'] = False
                result['error'] = str(error)
    (work / 'outcome.json').write_text(json.dumps(result, indent=2) + '\n')
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--rtl', type=Path, required=True)
    parser.add_argument('--source-root', type=Path, default=Path('.'))
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--depth', type=int, default=64)
    parser.add_argument('--timeout', type=int, default=180)
    parser.add_argument('--case', action='append', choices=CASES)
    args = parser.parse_args()
    if args.depth < 64 or args.timeout < 10:
        parser.error('Use at least 64 cycles and a ten second tool limit')
    if args.output.exists():
        parser.error('Output must be a new directory')
    manifest, contents, bindings = freeze_design(args.rtl, args.source_root, Path(__file__).with_suffix('.sv'), Path(__file__))
    parameters = manifest['parameters']
    assert parameters['enableDebug'] and not any(parameters.get(k, False) for k in
           ('enableM', 'enableC', 'protectedMode', 'enableA', 'enableZba', 'enableZbb', 'enableZbs')), 'Unsupported debug proof configuration'
    contents['test/core_formal.py'] = Path(__file__).with_name('core_formal.py').read_bytes()
    contents['test/test_debug_core_formal.py'] = Path(__file__).with_name('test_debug_core_formal.py').read_bytes()
    tools, bindings['toolHashes'] = freeze_tools()
    args.output.mkdir(parents=True)
    frozen = write_snapshot(args.output, contents)
    rtl = {name: contents['rtl/' + name] for name in manifest['rtlHashes']}
    report = {'exitStatus': None, 'scope': 'Bounded precise halt and one-step execution through real DMI',
              **bindings, 'tools': tool_versions(), 'outcomes': [],
              'assumptions': ['initial synchronous reset', 'fixed ROM with four instruction scenarios',
                              'native requests accepted when the peer is idle',
                              'instruction responses available one cycle after acceptance',
                              'each data response has a constant selected delay of one to three cycles',
                              'DMI requests held through acceptance and responses always consumed',
                              'interrupt inputs and time input tied to zero'],
              'observations': OBSERVATIONS,
              'latency': {'completionBoundCycles': 60, 'clockConditionHz': 1000,
                          'millisecondsUpperBound': 60,
                          'scope': 'The fixed ROM and declared response schedule',
                          'physicalFrequencyClaim': False},
              'limits': ['fixed programs and M-mode debug configuration', 'bounded core behavior',
                         'no reset, interrupt, compressed, atomic or PMP proof']}
    for name in args.case or CASES:
        result = run_case(args.output, rtl, contents['test/debug_core_formal.sv'], name, args.depth, args.timeout)
        report['outcomes'].append(result)
        (args.output / 'summary.json').write_text(json.dumps(report, indent=2) + '\n')
        if not result['accepted']:
            raise RuntimeError(name + ': ' + result['status'])
    check_inputs(frozen)
    check_inputs(tools)
    report['exitStatus'] = 0
    (args.output / 'summary.json').write_text(json.dumps(report, indent=2) + '\n')
    artifacts = {str(p.relative_to(args.output)): digest(p) for p in sorted(args.output.rglob('*')) if p.is_file()}
    (args.output / 'artifacts.json').write_text(json.dumps(artifacts, indent=2) + '\n')
    print('PASS:', len(report['outcomes']), 'bounded debug checks')


if __name__ == '__main__':
    main()
