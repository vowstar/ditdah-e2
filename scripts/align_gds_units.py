#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
# SPDX-License-Identifier: MIT

from fractions import Fraction
import json
from pathlib import Path
import struct

from preserve_gds_structures import (
    MergeError, Parser, cell_bytes, create_file, digest, name_value, parse_stream, real8,
)


MINIMUM = -(1 << 31)
MAXIMUM = (1 << 31) - 1
MATRICES = {
    "R0": ((1, 0), (0, 1)),
    "R180": ((-1, 0), (0, -1)),
    "MX": ((1, 0), (0, -1)),
    "MY": ((-1, 0), (0, 1)),
}


def fraction_record(value):
    return {"numerator": value.numerator, "denominator": value.denominator}


def units_record(data):
    offset = 0
    while offset < len(data):
        length, kind, dtype = struct.unpack_from(">HBB", data, offset)
        if kind == 3:
            if length != 20 or dtype != 5:
                raise MergeError("invalid_units")
            return offset, data[offset:offset + length]
        offset += length
    raise MergeError("units_missing")


def grid_proof(old, new):
    ratio = old / new
    bound = (1 << 31) * abs(ratio - 1)
    if bound >= Fraction(1, 2):
        raise MergeError("unit_grid_mismatch")
    return {"old": fraction_record(old), "new": fraction_record(new),
            "oldOverNew": fraction_record(ratio),
            "maximumGridDisplacement": fraction_record(bound)}


def reference_orientation(angle, reflected):
    rotation = angle % 360
    if rotation == 0:
        return "MX" if reflected else "R0"
    if rotation == 180:
        return "MY" if reflected else "R180"
    raise MergeError("reference_rotation_outside_scope")


def transform_point(matrix, point, origin):
    x, y = point
    tx, ty = origin
    return (matrix[0][0] * x + matrix[0][1] * y + tx,
            matrix[1][0] * x + matrix[1][1] * y + ty)


def geometry_contract(stream):
    geometry = {}
    orientations = {}
    for name, cell in stream.cells.items():
        bounds = None
        references = []
        reference = None
        offset = cell.start
        while offset < cell.end:
            length, kind, dtype = struct.unpack_from(">HBB", stream.data, offset)
            payload = stream.data[offset + 4:offset + length]
            if kind == 11:
                raise MergeError("array_reference_outside_scope")
            if kind == 10:
                reference = {"name": None, "origin": None, "seen": set(),
                             "angle": Fraction(0), "reflected": False}
            elif kind == 18 and reference is not None:
                if reference["name"] is not None:
                    raise MergeError("duplicate_reference_name")
                reference["name"] = name_value(payload)
            elif kind == 16:
                if dtype != 3 or len(payload) % 8 or not payload:
                    raise MergeError("invalid_coordinates")
                for x, y in struct.iter_unpack(">ii", payload):
                    if bounds is None:
                        bounds = [x, y, x, y]
                    else:
                        bounds = [min(bounds[0], x), min(bounds[1], y),
                                  max(bounds[2], x), max(bounds[3], y)]
                if reference is not None:
                    if len(payload) != 8 or reference["origin"] is not None:
                        raise MergeError("invalid_reference_origin")
                    reference["origin"] = struct.unpack(">ii", payload)
            elif kind in {26, 27, 28} and reference is not None:
                if kind in reference["seen"]:
                    raise MergeError("duplicate_reference_transform")
                reference["seen"].add(kind)
                if kind == 26:
                    if dtype != 1 or len(payload) != 2:
                        raise MergeError("invalid_reference_transform")
                    flags = struct.unpack(">H", payload)[0]
                    if flags not in {0, 0x8000}:
                        raise MergeError("reference_flags_outside_scope")
                    reference["reflected"] = flags == 0x8000
                elif dtype != 5 or len(payload) != 8:
                    raise MergeError("invalid_reference_transform")
                elif kind == 27 and real8(payload) != 1:
                    raise MergeError("non_unit_spatial_magnification")
                elif kind == 28:
                    reference["angle"] = real8(payload)
            elif kind == 17 and reference is not None:
                if reference["name"] is None or reference["origin"] is None:
                    raise MergeError("incomplete_reference")
                orientation = reference_orientation(reference["angle"], reference["reflected"])
                reference["matrix"] = MATRICES[orientation]
                orientations[orientation] = orientations.get(orientation, 0) + 1
                references.append(reference)
                reference = None
            offset += length
        geometry[name] = (bounds, references)
    children = {item["name"] for _, references in geometry.values() for item in references}
    maximum_depth = 0

    def visit(name, matrix, origin, depth):
        nonlocal maximum_depth
        if depth > 1:
            raise MergeError("hierarchy_depth_outside_scope")
        maximum_depth = max(maximum_depth, depth)
        bounds, references = geometry[name]
        if bounds is not None:
            corners = ((bounds[0], bounds[1]), (bounds[0], bounds[3]),
                       (bounds[2], bounds[1]), (bounds[2], bounds[3]))
            transformed = [transform_point(matrix, point, origin) for point in corners]
            if any(value < MINIMUM or value > MAXIMUM for point in transformed for value in point):
                raise MergeError("transformed_coordinate_outside_scope")
        for item in references:
            if depth != 0:
                raise MergeError("hierarchy_depth_outside_scope")
            next_origin = transform_point(matrix, item["origin"], origin)
            visit(item["name"], item["matrix"], next_origin, depth + 1)

    for name in geometry.keys() - children:
        visit(name, MATRICES["R0"], (0, 0), 0)
    return {"spatialReferences": sum(len(items) for _, items in geometry.values()),
            "maximumHierarchyDepth": maximum_depth,
            "coordinatesInSigned32Range": True,
            "translationsOnly": set(orientations) <= {"R0"},
            "unitSpatialMagnification": True,
            "orthogonalReferenceTransforms": True,
            "referenceTransformCounts": orientations}


def align(layout_data, library_data):
    layout, library = parse_stream(layout_data), parse_stream(library_data)
    layout_geometry = geometry_contract(layout)
    library_geometry = geometry_contract(library)
    offset, old_record = units_record(layout_data)
    _, new_record = units_record(library_data)
    old_user, old_meter = real8(old_record[4:12]), real8(old_record[12:20])
    new_user, new_meter = real8(new_record[4:12]), real8(new_record[12:20])
    proof = {
        "databaseInUserUnits": grid_proof(old_user, new_user),
        "databaseInMeters": grid_proof(old_meter, new_meter),
        "userUnitInMeters": grid_proof(old_meter / old_user, new_meter / new_user),
    }
    output = layout_data[:offset] + new_record + layout_data[offset + 20:]
    result = parse_stream(output)
    if result.unit != library.unit or result.cells.keys() != layout.cells.keys():
        raise MergeError("unit_alignment_failed")
    if any(cell_bytes(result, name) != cell_bytes(layout, name) for name in layout.cells):
        raise MergeError("structure_bytes_changed")
    report = {
        "coordinateMinimum": MINIMUM, "coordinateMaximum": MAXIMUM,
        "maximumCoordinateMagnitude": 1 << 31,
        "rounding": "nearest_integer", "proof": proof,
        "maximumPhysicalDifferenceMeters": fraction_record((1 << 31) * abs(old_meter - new_meter)),
        "physicalMeterCoordinatesIdentical": old_meter == new_meter,
        "integerCoordinatesChanged": False, "structureBytesChanged": False,
        "unitHeaderChanged": old_record != new_record,
        "unitsRecordOffset": offset, "unitsRecordBytes": 20,
        "changedHeaderByteCount": sum(a != b for a, b in zip(old_record, new_record)),
        "oldUnitsRecordSha256": digest(old_record), "newUnitsRecordSha256": digest(new_record),
        "sourceLibraryCount": 1, "layoutGeometry": layout_geometry,
        "libraryGeometry": library_geometry,
    }
    return output, report


def main():
    try:
        parser = Parser(description="Align GDS unit metadata with an exact integer grid proof.")
        for option in ("layout", "library", "output", "report"):
            parser.add_argument("--" + option, required=True, type=Path)
        args = parser.parse_args()
        if args.output.resolve() == args.report.resolve() or args.output.exists() or args.report.exists():
            raise MergeError("output_exists")
        inputs = {key: getattr(args, key).read_bytes() for key in ("layout", "library")}
        output, report = align(inputs["layout"], inputs["library"])
        if any(getattr(args, key).read_bytes() != value for key, value in inputs.items()):
            raise MergeError("input_changed")
        report.update({"inputHashes": {key: digest(value) for key, value in inputs.items()},
                       "outputSha256": digest(output)})
        create_file(args.output, output)
        create_file(args.report, (json.dumps(report, indent=2) + "\n").encode())
        print(json.dumps({"error": "none", "outputSha256": report["outputSha256"],
                          "integerCoordinatesChanged": False, "structureBytesChanged": False}))
        return 0
    except MergeError as error:
        print(json.dumps({"error": str(error)}))
    except (OSError, ValueError, RecursionError):
        print(json.dumps({"error": "input_or_output_failure"}))
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
