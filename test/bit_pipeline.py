# SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
# SPDX-License-Identifier: MIT
"""Reject actual RTL mutations of bit operand forwarding and load interlocks."""

import hashlib
from pathlib import Path
import re
import subprocess


def mutate(text, kind):
    if kind == "forwarding":
        source = re.findall(r'wire\s+\[31:0\]\s+b\s*=\s*match2\s*&\s*~m_load\s*\?\s*m_value\s*:\s*(\w+\[bits\[24:20\]\]);', text)
        assert len(source) == 1, "Changed bit operand register selection"
        pattern = r'(\.b\s*\()b(\),\s*\.valid\s*\(_bit_valid\))'
        changed, count = re.subn(pattern, lambda match: match[1] + source[0] + match[2], text)
    elif kind == "load_interlock":
        pattern = r'(wire\s+match2\s*=.*?)(?=;)'
        matches = list(re.finditer(pattern, text, re.S))
        assert len(matches) == 1 and matches[0].group().count('_bit_usesRs2') == 1, "Changed bit dependency structure"
        matched = matches[0]
        changed = text[:matched.start()] + matched.group().replace('_bit_usesRs2', "1'b0") + text[matched.end():]
        count = 1
    else:
        raise ValueError("Unknown bit pipeline mutation")
    assert count == 1 and changed != text, "Changed bit forwarding structure"
    return changed


def negative_controls(selected, rtl, manifest, command, work, output, check):
    first = next((name for name in ('sh1add', 'andn', 'bclr')
                  if any(case.name == f'bit_{name}_fixed' for case in selected)), None)
    if first is None:
        return []
    controls = []
    for kind, suffix in (("forwarding", "fixed"), ("load_interlock", "load")):
        case = next((case for case in selected if case.name == f'bit_{first}_{suffix}'), None)
        if case is None:
            continue
        mutant = output / ('bit-' + kind)
        mutant.mkdir()
        for name in manifest['rtlHashes']:
            text = (rtl / name).read_text()
            if name == 'DitDahE2.sv':
                text = mutate(text, kind)
            (mutant / name).write_text(text)
        build = [str((mutant / Path(arg).name).resolve()) if arg.endswith('.sv') else arg for arg in command]
        object_dir = work / ('bit-' + kind + '-obj')
        build[build.index('--Mdir') + 1] = str(object_dir)
        compiled = subprocess.run(build, capture_output=True, text=True)
        normalize = lambda text: text.replace(str(work), '$WORK').replace(str(Path.cwd()), '$SOURCE')
        (mutant / 'compile.log').write_text(normalize(compiled.stdout + compiled.stderr))
        assert compiled.returncode == 0, "Bit mutant did not compile"
        image = mutant / 'image.hex'
        image.write_text(''.join(f'{a:08x} {w:08x}\n' for a, w in sorted(case.words().items())))
        run = subprocess.run([str(object_dir / 'VDitDahE2'), str(image.resolve()), '0', '0',
                              str(1 << 32), str(1 << 32), '20000', str(case.completion_pc)],
                             capture_output=True, text=True)
        (mutant / 'execution.trace').write_text(run.stdout)
        assert run.returncode == 0, "Bit mutant did not complete"
        try:
            check(case, run.stdout)
        except AssertionError as error:
            assert 'Register result mismatch' in str(error), "Bit mutant failed for another reason"
        else:
            raise AssertionError("Checker accepted a bit pipeline mutation")
        controls.append({'mutation': kind, 'case': case.name, 'exitStatus': 0,
                         'failure': 'Register result mismatch',
                         'artifactHashes': {str(path.relative_to(output)): hashlib.sha256(path.read_bytes()).hexdigest()
                                            for path in sorted(mutant.iterdir()) if path.is_file()}})
    return controls
