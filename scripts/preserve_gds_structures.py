#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
# SPDX-License-Identifier: MIT

import argparse
from collections import namedtuple
from fractions import Fraction
import hashlib
import json
import os
from pathlib import Path
import struct


class MergeError(Exception):
    pass


Cell = namedtuple("Cell", "start end references")
Stream = namedtuple("Stream", "data unit cells record_end")


def real8(data):
    if len(data) != 8:
        raise MergeError("invalid_real")
    value = Fraction(int.from_bytes(data[1:], "big"), 1 << 56)
    exponent = (data[0] & 127) - 64
    value *= Fraction(16) ** exponent
    return -value if data[0] & 128 else value


def name_value(data):
    value = data[:-1] if data.endswith(b"\0") else data
    if not value or any(byte < 32 or byte > 126 for byte in value):
        raise MergeError("invalid_name")
    return value.decode("ascii")


def check_references(cells):
    if any(reference not in cells for cell in cells.values() for reference in cell.references):
        raise MergeError("unresolved_reference")
    active = set()
    done = set()

    def visit(name):
        if name in active:
            raise MergeError("cyclic_reference")
        if name in done:
            return
        active.add(name)
        for reference in cells[name].references:
            visit(reference)
        active.remove(name)
        done.add(name)

    for name in cells:
        visit(name)


def parse_stream(data):
    offset = 0
    start = None
    name = None
    references = set()
    element = None
    cells = {}
    unit = None
    header_count = 0
    library_count = 0
    library_names = 0
    ended = False
    record_end = None
    while offset < len(data):
        if len(data) - offset < 4:
            raise MergeError("truncated_record")
        length, kind, dtype = struct.unpack_from(">HBB", data, offset)
        if length < 4 or length % 2 or offset + length > len(data):
            raise MergeError("invalid_record_length")
        payload = data[offset + 4:offset + length]
        if kind == 0:
            if offset != 0 or dtype != 2 or length != 6:
                raise MergeError("invalid_header")
            header_count += 1
        elif kind == 1:
            if start is not None or dtype != 2 or length != 28:
                raise MergeError("invalid_library")
            library_count += 1
        elif kind == 2:
            if start is not None or dtype != 6:
                raise MergeError("invalid_library_name")
            name_value(payload)
            library_names += 1
        elif kind == 3:
            if start is not None or cells or unit is not None or dtype != 5 or length != 20:
                raise MergeError("invalid_units")
            if real8(payload[:8]) <= 0 or real8(payload[8:]) <= 0:
                raise MergeError("invalid_units")
            unit = real8(payload[8:])
        elif kind == 5:
            if start is not None or unit is None or dtype != 2 or length != 28:
                raise MergeError("invalid_structure")
            start, name, references, element = offset, None, set(), None
        elif kind == 6:
            if start is None or name is not None or element is not None or dtype != 6:
                raise MergeError("invalid_structure_name")
            name = name_value(payload)
        elif kind in {8, 9, 10, 11, 12, 21, 45}:
            if start is None or name is None or element is not None or dtype != 0 or length != 4:
                raise MergeError("invalid_element")
            element = kind
        elif kind == 18:
            if element not in {10, 11} or dtype != 6:
                raise MergeError("invalid_reference")
            references.add(name_value(payload))
        elif kind == 17:
            if element is None or dtype != 0 or length != 4:
                raise MergeError("invalid_element_end")
            element = None
        elif kind == 7:
            if start is None or name is None or element is not None or dtype != 0 or length != 4:
                raise MergeError("invalid_structure_end")
            if name in cells:
                raise MergeError("duplicate_structure")
            cells[name] = Cell(start, offset + length, frozenset(references))
            start = None
        elif kind == 4:
            if start is not None or dtype != 0 or length != 4:
                raise MergeError("invalid_library_end")
            record_end = offset + length
            padding = data[record_end:]
            if padding and (any(padding) or len(padding) % 2 or len(padding) >= 2048 or len(data) % 2048):
                raise MergeError("invalid_padding")
            ended = True
            break
        offset += length
    if not ended or not cells or unit is None or (header_count, library_count, library_names) != (1, 1, 1):
        raise MergeError("incomplete_stream")
    check_references(cells)
    return Stream(data, unit, cells, record_end)


def cell_bytes(stream, name):
    cell = stream.cells[name]
    return stream.data[cell.start:cell.end]


def preserve(layout_data, library_data, names):
    if not isinstance(names, list) or not names or any(not isinstance(name, str) for name in names):
        raise MergeError("invalid_selection")
    if len(set(names)) != len(names):
        raise MergeError("duplicate_selection")
    layout, library = parse_stream(layout_data), parse_stream(library_data)
    if layout.unit != library.unit:
        raise MergeError("database_units_mismatch")
    if any(name not in layout.cells or name not in library.cells for name in names):
        raise MergeError("selected_structure_missing")
    selected = set(names)
    closure = set()
    pending = list(names)
    while pending:
        name = pending.pop()
        if name not in closure:
            closure.add(name)
            pending.extend(library.cells[name].references)
    for name in closure - selected:
        if name not in layout.cells or cell_bytes(layout, name) != cell_bytes(library, name):
            raise MergeError("dependency_not_preserved")
    pieces = []
    cursor = 0
    for name in sorted(names, key=lambda item: layout.cells[item].start):
        cell = layout.cells[name]
        pieces.extend((layout_data[cursor:cell.start], cell_bytes(library, name)))
        cursor = cell.end
    pieces.append(layout_data[cursor:layout.record_end])
    output = b"".join(pieces)
    if layout.record_end != len(layout_data) or len(layout_data) % 2048 == 0:
        output += b"\0" * (-len(output) % 2048)
    result = parse_stream(output)
    if result.cells.keys() != layout.cells.keys():
        raise MergeError("structure_set_changed")
    for name in result.cells:
        expected = library if name in selected else layout
        if cell_bytes(result, name) != cell_bytes(expected, name):
            raise MergeError("structure_bytes_changed")
    return output, {
        "replacedStructures": len(selected),
        "unchangedStructures": len(layout.cells) - len(selected),
        "libraryClosureStructures": len(closure),
        "unresolvedReferences": 0,
        "databaseUnitNumerator": result.unit.numerator,
        "databaseUnitDenominator": result.unit.denominator,
        "inputPaddingBytes": len(layout_data) - layout.record_end,
        "outputPaddingBytes": len(output) - result.record_end,
    }


def digest(data):
    return hashlib.sha256(data).hexdigest()


def create_file(path, data):
    with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb") as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())


class Parser(argparse.ArgumentParser):
    def error(self, message):
        raise MergeError("arguments")


def main():
    try:
        parser = Parser(description="Preserve selected library structures in a derived GDS file.")
        for option in ("layout", "library", "cells", "output", "report"):
            parser.add_argument("--" + option, required=True, type=Path)
        args = parser.parse_args()
        if args.output.resolve() == args.report.resolve() or args.output.exists() or args.report.exists():
            raise MergeError("output_exists")
        inputs = {key: getattr(args, key).read_bytes() for key in ("layout", "library", "cells")}
        names = json.loads(inputs["cells"])
        output, summary = preserve(inputs["layout"], inputs["library"], names)
        if any(getattr(args, key).read_bytes() != value for key, value in inputs.items()):
            raise MergeError("input_changed")
        summary.update({"inputHashes": {key: digest(value) for key, value in inputs.items()}, "outputSha256": digest(output)})
        create_file(args.output, output)
        create_file(args.report, (json.dumps(summary, indent=2) + "\n").encode())
        print(json.dumps({"error": "none", **summary}))
        return 0
    except MergeError as error:
        print(json.dumps({"error": str(error)}))
    except (OSError, ValueError, RecursionError):
        print(json.dumps({"error": "input_or_output_failure"}))
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
