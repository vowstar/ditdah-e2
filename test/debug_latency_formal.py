# SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
# SPDX-License-Identifier: MIT
"""Bound run control with arbitrary instructions and finite external service."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import sys

from core_formal import check_inputs, freeze_design, freeze_tools, tool_versions, write_snapshot
from debug_core_formal import trace_witness

OBSERVATIONS = {
    'observed_halted': '_debug_debug_status_halted',
    'observed_resume': '_debug_core_resume',
    'observed_ack': '_debug_debug_status_resumeAck',
    'observed_stop': '_debug_core_stop',
    'observed_m_valid': 'mValid',
    'observed_step': '_debug_core_singleStep',
}
TARGETS = {'complete': 0, 'instruction-accepted': 1, 'data-accepted': 2,
           'instruction-offered': 3, 'data-offered': 4, 'step-retire': 5,
           'step-trap': 6, 'step-memory': 7, 'step-multiply': 8, 'step-crossing': 9}
CASES = ('safety', 'step-safety', 'payload', 'step-payload', *TARGETS, 'halt-blocked', 'resume-blocked', 'extra-step')


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def bounds(accept=8, response=24, dmi=8):
    if any(type(x) is not int or not 1 <= x <= 32 for x in (accept, response, dmi)):
        raise ValueError('Service bounds must be integers from one through 32')
    return {'halt': 2 * (accept + response) + 8, 'resume': accept + response + 6,
            'poll': 2 * (dmi + 2)}


def step_bound(accept, response, enable_m, enable_c):
    bounds(accept, response, 1)
    return (4 if enable_c else 3) * (accept + response) + (34 if enable_m else 0) + 16


def general_step_bound(accept, response, enable_m, enable_c):
    return bounds(accept, response, 1)['resume'] + step_bound(accept, response, enable_m, enable_c)


def derivation():
    return {
        'scope': 'Conservative source and protocol derivation, separate from the finite prefix check',
        'start': 'Acceptance of a recognized dmcontrol write with dmactive already set and abstractcs.busy clear',
        'conditions': ['resume addresses a halted hart', 'no reset, deactivation or replacement control request',
                       'the core clock continues to run', 'native acceptance and response deadlines include old offered traffic',
                       'atomic arbitration and device access, when enabled, must meet the same native deadline'],
        'halt': 'A_I + R_I + A_D + R_D + 8',
        'resume': 'A_D + R_D + 6',
        'normalStep': '(2 + C) * (A_I + R_I) + A_D + R_D + 34 * M + 16',
        'generalStep': '(A_D + R_D + 6) + (2 + C) * (A_I + R_I) + A_D + R_D + 34 * M + 16',
        'poll': '2 * (D + 2)',
        'haltReason': 'Stop blocks X and new F requests. X multiply/divide is canceled. At most one old F transaction and one M transaction remain. A serial M instruction can wait for F, then complete.',
        'resumeReason': 'A recognized resume waits for any old abstract transfer and its response, then clears halted and acknowledges. A busy DM ignores the write and has no promised resume deadline.',
        'normalStepReason': 'This wrapper has no orphan abstract transfer. C can require two fetched words. The final stop can drain one more fetch. Add one data access, the multiplier bound and pipeline control edges. WFI does not wait for an interrupt during step.',
        'generalStepReason': 'DM deactivation clears busy but retains an old offered or accepted native transfer. Reactivated resume waits for this transfer before starting the stepped instruction. Add the resume bound to the normal step bound, including a separate data access by that instruction.',
        'pollReason': 'A stale reply can take D cycles to consume. The next read needs an ownership turnover edge and a registered reply, then at most D cycles to consume. Two additional edges cover sampling alignment.',
        'fetchOwnership': 'Fetch.scala creates held only on a blocked offer. An offer with outstanding requires its response on the same edge. The existing fetch proof asserts held implies no outstanding.',
        'sourceLocations': {'DitDahE2.scala': [112, 257, 271, 348, 388, 401],
                            'Fetch.scala': [87, 97, 98, 118], 'DebugHart.scala': [57, 72, 82, 158],
                            'DebugModule.scala': [43, 87, 95], 'MemoryProtection.scala': [29, 34, 45]},
        'configurationScope': 'The source derivation applies with Debug enabled. PMP denial completes locally. A and bit instructions add no core owner. Only the reported generated configurations are checked by this runner.',
    }


def observe(source):
    match = re.search(r'module DitDahE2\((.*?)\n\);', source, re.S)
    if not match or source.count('endmodule') != 1:
        raise ValueError('Core module changed')
    for signal in OBSERVATIONS.values():
        if not re.search(r'\b(?:wire|reg)\s+' + signal + r'\s*[;=]', source):
            raise ValueError('Missing control observation: ' + signal)
    ports = ',\n' + ',\n'.join('  output ' + name for name in OBSERVATIONS)
    changed = source[:match.end(1)] + ports + source[match.end(1):]
    assignments = '\n'.join(f'  assign {name} = {signal};' for name, signal in OBSERVATIONS.items())
    return changed.replace('endmodule', assignments + '\nendmodule')


def mutate(source, name):
    if name == 'halt-blocked':
        pattern = r'(wire\s+\w+\s*=\s*)core_empty\s*&\s*core_fetchIdle;'
        result, count = re.subn(pattern, r'\1core_empty & core_fetchIdle & core_completed;', source)
    elif name == 'resume-blocked':
        pattern = r'(wire\s+resume\s*=\s*)([^;]+);'
        result, count = re.subn(pattern, r"\g<1>1'b0 & (\2);", source)
    elif name == 'extra-step':
        pattern = r'(assign\s+core_stop\s*=\s*)([^;]+);'
        result, count = re.subn(pattern, r'\g<1>(\2) & ~(core_completed & core_singleStep);', source)
    else:
        raise ValueError('Unknown control mutation')
    if count != 1:
        raise ValueError('Changed control mutation target')
    return result


def witness_condition(name):
    if name in TARGETS:
        flag = {'instruction-accepted': 'halt_with_i_accepted', 'data-accepted': 'halt_with_d_accepted',
                'instruction-offered': 'halt_with_i_offered', 'data-offered': 'halt_with_d_offered',
                'step-retire': 'step_retired', 'step-trap': 'step_trapped', 'step-memory': 'step_memory',
                'step-multiply': 'step_multiply', 'step-crossing': 'step_crossing'}.get(name)
        return lambda values: values.get('finished') == 1 and (flag is None or values.get(flag) == 1) and (
            name != 'step-multiply' or values.get('step_retired') == 1 and values.get('retire_word', 0) & 0xFE00007F == 0x02000033)
    flag = {'halt-blocked': 'halt_expired', 'resume-blocked': 'resume_expired', 'extra-step': 'extra_step'}[name]
    return lambda values: values.get(flag) == 1


def run_case(output, rtl, wrapper, name, depth, timeout, parameters):
    work = output / name
    work.mkdir()
    for filename, content in rtl.items():
        text = content.decode()
        if filename == 'DitDahE2.sv':
            text = observe(text)
        if filename == 'DitDahE2DebugHart.sv' and name in ('halt-blocked', 'resume-blocked', 'extra-step'):
            text = mutate(text, name)
        (work / filename).write_text(text)
    (work / 'debug_latency_formal.sv').write_bytes(wrapper)
    options = '-DREACHABILITY ' if name in TARGETS else ''
    settings = {**parameters, 'TARGET': TARGETS.get(name, 0), 'STEP': int(name.startswith('step-') or name == 'extra-step'),
                'PROPERTY': int(name in ('payload', 'step-payload'))}
    engine, mode = ('abc pdr', 'prove') if settings['PROPERTY'] else ('abc bmc3', 'bmc')
    config = (f'[options]\nmode {mode}\ndepth {depth}\ntimeout {timeout}\nvcd_sim on\n'
              f'[engines]\n{engine}\n[script]\n'
              f'read -formal -sv {options}' + ' '.join([*rtl, 'debug_latency_formal.sv']) + '\n' +
              ''.join(f'chparam -set {key} {value} debug_latency_formal\n' for key, value in settings.items()) +
              'prep -top debug_latency_formal\n[files]\n' + '\n'.join([*rtl, 'debug_latency_formal.sv']) + '\n')
    (work / 'run.sby').write_text(config)
    frozen = {path: path.read_bytes() for path in work.iterdir() if path.is_file()}
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
    check_inputs(frozen)
    status_file = work / 'run/status'
    status = 'TIMEOUT' if timed_out else status_file.read_text().split()[0] if status_file.exists() else 'ERROR'
    wanted = 'PASS' if name in ('safety', 'step-safety', 'payload', 'step-payload') else 'FAIL'
    result = {'name': name, 'engine': engine, 'mode': mode, 'depth': depth,
              'timeoutSeconds': timeout, 'parameters': settings, 'status': status,
              'propertyGroup': 'request stability' if settings['PROPERTY'] else 'control deadlines and completion',
              'finiteServiceAssumptions': not bool(settings['PROPERTY']),
              'exitStatus': process.returncode, 'command': ['sby', '-f', 'run.sby'],
              'inputHashes': {p.name: hashlib.sha256(data).hexdigest() for p, data in frozen.items()},
              'accepted': status == wanted and process.returncode == (0 if wanted == 'PASS' else 2)}
    if result['accepted'] and wanted == 'FAIL':
        traces = sorted((work / 'run/engine_0').glob('trace*.vcd'))
        try:
            if not traces:
                raise ValueError('Missing semantic witness')
            values = trace_witness(traces[0], witness_condition(name))
            fields = {'time', 'cycle', 'phase', 'finished', 'halt_expired', 'resume_expired',
                      'halt_requested', 'resume_requested', 'observed_halted', 'observed_ack',
                      'halt_start', 'resume_start', 'request_cycle', 'i_busy', 'd_busy',
                      'halt_with_i_accepted', 'halt_with_d_accepted', 'halt_with_i_offered', 'halt_with_d_offered',
                      'step_count', 'step_retired', 'step_trapped', 'step_memory', 'step_multiply', 'step_crossing',
                      'step_started', 'step_halted', 'extra_step', 'retire_word', 'retire_pc'}
            result['witness'] = {key: value for key, value in values.items() if key in fields}
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
    parser.add_argument('--depth', type=int, default=384)
    parser.add_argument('--prefix', type=int, default=16)
    parser.add_argument('--accept-bound', type=int, default=8)
    parser.add_argument('--response-bound', type=int, default=24)
    parser.add_argument('--dmi-bound', type=int, default=8)
    parser.add_argument('--timeout', type=int, default=1800)
    parser.add_argument('--case', action='append', choices=CASES)
    args = parser.parse_args()
    limits = bounds(args.accept_bound, args.response_bound, args.dmi_bound)
    if args.output.exists():
        parser.error('Output must be a new directory')
    manifest, contents, bindings = freeze_design(args.rtl, args.source_root, Path(__file__).with_suffix('.sv'), Path(__file__))
    parameters = manifest['parameters']
    if not parameters['enableDebug'] or any(parameters.get(k, False) for k in
            ('protectedMode', 'enableA', 'enableZba', 'enableZbb', 'enableZbs')):
        parser.error('This control check supports machine mode with optional M and C')
    limits['normalStep'] = step_bound(args.accept_bound, args.response_bound, parameters['enableM'], parameters['enableC'])
    limits['generalStep'] = general_step_bound(args.accept_bound, args.response_bound, parameters['enableM'], parameters['enableC'])
    selected = args.case or [name for name in CASES if (name != 'step-multiply' or parameters['enableM'])
                            and (name != 'step-crossing' or parameters['enableC'])]
    if ('step-multiply' in selected and not parameters['enableM']) or ('step-crossing' in selected and not parameters['enableC']):
        parser.error('The selected cover requires its implemented extension')
    stepping = any(name.startswith('step-') or name == 'extra-step' for name in selected)
    minimum_depth = args.prefix + limits['halt'] + 2 * limits['poll'] + 16
    minimum_depth += limits['normalStep'] + 3 * (args.dmi_bound + 2) if stepping else limits['resume']
    if not 2 <= args.prefix <= 64 or args.depth < minimum_depth + 2 or args.depth > 1023 or args.timeout < 10:
        parser.error(f'Use a prefix of two through 64 and depth from {minimum_depth + 2} through 1023')
    for name in ('core_formal.py', 'debug_core_formal.py', 'test_debug_latency_formal.py'):
        contents['test/' + name] = Path(__file__).with_name(name).read_bytes()
    tools, bindings['toolHashes'] = freeze_tools()
    interpreter = Path(sys.executable).resolve()
    tools[interpreter] = interpreter.read_bytes()
    bindings['toolHashes']['python'] = digest(interpreter)
    bindings['checkerHashes'] = {name: hashlib.sha256(data).hexdigest() for name, data in contents.items() if name.startswith('test/')}
    args.output.mkdir(parents=True)
    frozen = write_snapshot(args.output, contents)
    rtl = {name: contents['rtl/' + name] for name in manifest['rtlHashes']}
    report = {**bindings, 'exitStatus': None, 'scope': 'Control deadlines and request stability with arbitrary instructions',
              'tools': tool_versions(), 'outcomes': [], 'boundsCycles': limits,
              'python': sys.version.splitlines()[0], 'derivation': derivation(), 'selectedCases': selected,
              'requestCycleRange': [2, args.prefix], 'finishBoundCycles': minimum_depth,
              'command': ['python3', 'test/debug_latency_formal.py', '--rtl', 'rtl', '--source-root', 'source',
                          '--output', 'verification', '--depth', str(args.depth), '--prefix', str(args.prefix),
                          '--accept-bound', str(args.accept_bound), '--response-bound', str(args.response_bound),
                          '--dmi-bound', str(args.dmi_bound), '--timeout', str(args.timeout),
                          *[part for name in selected for part in ('--case', name)]],
              'clockCondition': {'minimumHz': 1000, 'haltObservationMilliseconds': limits['halt'] + limits['poll'],
                                 'resumeObservationMilliseconds': limits['resume'] + limits['poll'],
                                 'normalStepObservationMilliseconds': limits['normalStep'] + limits['poll'],
                                 'generalStepObservationMilliseconds': limits['generalStep'] + limits['poll'],
                                 'physicalFrequencyClaim': False},
              'controlAssumptions': ['initial synchronous reset', 'arbitrary instruction and data values and faults',
                              'arbitrary interrupt and time inputs', 'one owned response per accepted native request',
                              'native request acceptance and response availability meet the recorded bounds',
                              'DMI responses are consumed within the recorded bound',
                              'DM activation completes before halt, only the step setup uses abstract commands',
                              'resume is requested only after DMI reports the hart halted',
                              'status is polled without host idle cycles'],
              'stabilityAssumptions': ['initial synchronous reset', 'arbitrary instruction and data values and faults',
                                       'one response owner per native port', 'an offered peer response remains stable until accepted',
                                       'native and DMI backpressure have no finite bound',
                                       'the same DMI command sequence is used without service deadlines'],
              'stepConfiguration': {'dcsrWrite': 7, 'step': 1, 'stepie': 0, 'ebreakm': 0, 'ebreaku': 0,
                                    'privilege': 'M', 'completion': 'one successful retirement or one trap event'},
              'limits': ['control deadlines use BMC over the recorded finite execution prefix',
                         'request stability uses a separate unbounded proof under its recorded protocol assumptions',
                         'no physical clock frequency claim',
                         'no arbitrary DMI command sequences or orphan abstract transfers',
                         'PMP, atomic and bit extension configurations are not checked here']}
    settings = {'PREFIX': args.prefix, 'ACCEPT_BOUND': args.accept_bound,
                'RESPONSE_BOUND': args.response_bound, 'DMI_BOUND': args.dmi_bound,
                'ENABLE_M': int(parameters['enableM']), 'ENABLE_C': int(parameters['enableC'])}
    try:
        for name in selected:
            outcome = run_case(args.output, rtl, contents['test/debug_latency_formal.sv'], name,
                               args.depth, args.timeout, settings)
            report['outcomes'].append(outcome)
            (args.output / 'summary.json').write_text(json.dumps(report, indent=2) + '\n')
            if not outcome['accepted']:
                raise RuntimeError(name + ': ' + outcome['status'])
        check_inputs(frozen)
        check_inputs(tools)
        report['exitStatus'] = 0
    finally:
        check_inputs(frozen)
        check_inputs(tools)
        (args.output / 'summary.json').write_text(json.dumps(report, indent=2) + '\n')
        artifacts = {str(p.relative_to(args.output)): digest(p) for p in sorted(args.output.rglob('*')) if p.is_file()}
        (args.output / 'artifacts.json').write_text(json.dumps(artifacts, indent=2) + '\n')
    print('PASS:', len(report['outcomes']), 'control checks')


if __name__ == '__main__':
    main()
