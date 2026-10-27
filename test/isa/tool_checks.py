# SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
# SPDX-License-Identifier: MIT
"""Check the fixed ISA validator against real configuration files."""

import importlib.metadata
import json
from pathlib import Path

from isa_checks import digest, isa_specification


def check_tool_configuration(output):
    import riscv_config.constants as constants
    from riscv_config.checker import check_isa_specs
    from riscv_config.errors import ValidationError

    output.mkdir(parents=True, exist_ok=True)
    all_bits = dict(enable_zba=True, enable_zbb=True, enable_zbs=True)
    full = isa_specification(**all_bits)
    cases = {
        'i': (isa_specification(), None),
        'm': (isa_specification(True), None),
        'c': (isa_specification(False, True), None),
        'bits': (full, None),
        'misa-mismatch': (full.replace('reset-val: 0x40000102', 'reset-val: 0x40000100'),
                          'reset value does not match with extensions enabled'),
        'order-mismatch': (isa_specification(True, True).replace('RV32IMCZicsr', 'RV32ICMZicsr'),
                           "Alphabet 'C' should occur after 'M"),
    }
    records = {}
    for name, (text, expected) in cases.items():
        path = output / (name + '.yaml')
        path.write_text(text)
        try:
            check_isa_specs(str(path), str(output), dump_yaml=False)
        except ValidationError as error:
            message = str(error)
            if expected is None or expected not in message:
                raise
            records[name] = {'accepted': False, 'rejection': expected, 'inputHash': digest(path)}
        else:
            if expected is not None:
                raise AssertionError('ISA validator accepted an invalid configuration')
            records[name] = {'accepted': True, 'inputHash': digest(path)}
    source = Path(constants.__file__).parent
    report = {
        'version': importlib.metadata.version('riscv-config'), 'exitStatus': 0,
        'cases': records,
        'sourceHashes': {name: digest(source / name) for name in
                         ('constants.py', 'isa_validator.py', 'schemaValidator.py')},
    }
    (output / 'summary.json').write_text(json.dumps(report, indent=2) + '\n')
    return report
