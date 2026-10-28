# SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
# SPDX-License-Identifier: MIT

import json
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest

SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS))

from preserve_gds_structures import MergeError, parse_stream, preserve


ONE = bytes.fromhex("4110000000000000")
TWO = bytes.fromhex("4120000000000000")


def record(kind, dtype=0, payload=b""):
    if len(payload) % 2:
        payload += b"\0"
    return struct.pack(">HBB", len(payload) + 4, kind, dtype) + payload


def text(magnification):
    return b"".join((
        record(12), record(13, 2, struct.pack(">h", 1)),
        record(22, 2, struct.pack(">h", 0)), record(26, 1, b"\0\0"),
        record(27, 5, magnification), record(16, 3, struct.pack(">ii", 5, 7)),
        record(25, 6, b"Port"), record(17),
    ))


def reference(name, array=False):
    elements = [record(11 if array else 10), record(18, 6, name.encode()),
                record(26, 1, b"\x80\0"), record(27, 5, TWO),
                record(28, 5, bytes.fromhex("425a000000000000"))]
    if array:
        elements.append(record(19, 2, struct.pack(">hh", 2, 2)))
    points = (100, 200, 300, 200, 100, 400) if array else (100, 200)
    elements.extend((record(16, 3, struct.pack(">" + "i" * len(points), *points)), record(17)))
    return b"".join(elements)


def cell(name, elements=b"", timestamp=0):
    return (record(5, 2, struct.pack(">12h", *([timestamp] * 12)))
            + record(6, 6, name.encode()) + elements + record(7))


def stream(cells, unit=ONE, user_unit=ONE):
    return (record(0, 2, struct.pack(">h", 600)) + record(1, 2, b"\0" * 24)
            + record(2, 6, b"Fixture") + record(3, 5, user_unit + unit)
            + b"".join(cells) + record(4))


class PreserveTests(unittest.TestCase):
    def setUp(self):
        self.original_leaf = cell("Leaf", text(b"\0" * 8), timestamp=1)
        self.changed_leaf = cell("Leaf", text(ONE), timestamp=2)
        self.top = cell("Top", reference("Leaf"))
        self.library = stream([self.original_leaf])
        self.layout = stream([self.top, self.changed_leaf])

    def test_preserves_complete_source_and_instance_transform(self):
        output, report = preserve(self.layout, self.library, ["Leaf"])
        self.assertEqual(output, stream([self.top, self.original_leaf]))
        self.assertEqual(report["replacedStructures"], 1)
        self.assertEqual(report["unchangedStructures"], 1)
        self.assertEqual(report["unresolvedReferences"], 0)

    def test_preserves_array_transform_and_record_order(self):
        top = cell("Top", reference("Leaf", array=True))
        output, _ = preserve(stream([self.changed_leaf, top]), self.library, ["Leaf"])
        self.assertEqual(output, stream([self.original_leaf, top]))

    def test_preserves_two_cells_and_unselected_bytes(self):
        source = cell("Other", text(b"\0" * 8), timestamp=3)
        changed = cell("Other", text(ONE))
        top = cell("Top", reference("Leaf") + reference("Other"))
        output, _ = preserve(stream([changed, top, self.changed_leaf]),
                             stream([self.original_leaf, source]), ["Leaf", "Other"])
        self.assertEqual(output, stream([source, top, self.original_leaf]))

    def test_database_units_define_coordinate_scale(self):
        output, _ = preserve(self.layout, stream([self.original_leaf], user_unit=TWO), ["Leaf"])
        self.assertEqual(output, stream([self.top, self.original_leaf]))

    def test_rejects_database_unit_change(self):
        with self.assertRaisesRegex(MergeError, "database_units_mismatch"):
            preserve(self.layout, stream([self.original_leaf], unit=TWO), ["Leaf"])

    def test_rejects_missing_structure(self):
        with self.assertRaisesRegex(MergeError, "selected_structure_missing"):
            preserve(self.layout, self.library, ["Missing"])

    def test_rejects_duplicate_selection(self):
        with self.assertRaisesRegex(MergeError, "duplicate_selection"):
            preserve(self.layout, self.library, ["Leaf", "Leaf"])

    def test_rejects_empty_selection(self):
        with self.assertRaisesRegex(MergeError, "invalid_selection"):
            preserve(self.layout, self.library, [])

    def test_rejects_duplicate_structure_names(self):
        with self.assertRaisesRegex(MergeError, "duplicate_structure"):
            parse_stream(stream([self.original_leaf, self.original_leaf]))

    def test_rejects_unresolved_reference(self):
        with self.assertRaisesRegex(MergeError, "unresolved_reference"):
            parse_stream(stream([self.top]))

    def test_rejects_reference_cycle(self):
        with self.assertRaisesRegex(MergeError, "cyclic_reference"):
            parse_stream(stream([cell("Leaf", reference("Leaf"))]))

    def test_requires_preserved_dependency(self):
        outer = cell("Outer", reference("Leaf"))
        library = stream([outer, self.original_leaf])
        layout = stream([outer, self.changed_leaf])
        with self.assertRaisesRegex(MergeError, "dependency_not_preserved"):
            preserve(layout, library, ["Outer"])

    def test_accepts_explicit_dependency_selection(self):
        outer = cell("Outer", reference("Leaf"))
        library = stream([outer, self.original_leaf])
        output, report = preserve(stream([outer, self.changed_leaf]), library, ["Outer", "Leaf"])
        self.assertEqual(output, library)
        self.assertEqual(report["libraryClosureStructures"], 2)

    def test_accepts_already_identical_dependency(self):
        outer = cell("Outer", reference("Leaf"))
        library = stream([outer, self.original_leaf])
        output, _ = preserve(library, library, ["Outer"])
        self.assertEqual(output, library)

    def test_rejects_truncation(self):
        with self.assertRaises(MergeError):
            parse_stream(self.layout[:-1])

    def test_rejects_odd_record_length(self):
        with self.assertRaisesRegex(MergeError, "invalid_record_length"):
            parse_stream(b"\0\x05" + self.layout[2:])

    def test_rejects_zero_database_units(self):
        with self.assertRaisesRegex(MergeError, "invalid_units"):
            parse_stream(stream([self.original_leaf], unit=b"\0" * 8))

    def test_rejects_unterminated_element(self):
        with self.assertRaisesRegex(MergeError, "invalid_structure_end"):
            parse_stream(stream([cell("Leaf", record(12))]))

    def test_preserves_records_and_rebuilds_null_word_padding(self):
        changed = cell("Leaf", text(ONE).replace(record(27, 5, ONE), b""))
        layout = stream([self.top, changed])
        layout += b"\0" * (-len(layout) % 2048)
        library = self.library + b"\0" * (-len(self.library) % 2048)
        output, report = preserve(layout, library, ["Leaf"])
        expected = stream([self.top, self.original_leaf])
        self.assertEqual(output, expected + b"\0" * (-len(expected) % 2048))
        self.assertEqual(len(output) % 2048, 0)
        self.assertNotEqual(report["inputPaddingBytes"], report["outputPaddingBytes"])

    def test_rejects_nonzero_trailing_data(self):
        padding = bytearray(-len(self.layout) % 2048)
        padding[-1] = 1
        with self.assertRaisesRegex(MergeError, "invalid_padding"):
            parse_stream(self.layout + padding)

    def test_rejects_unaligned_padding(self):
        with self.assertRaisesRegex(MergeError, "invalid_padding"):
            parse_stream(self.layout + b"\0\0")

    def run_cli(self, directory, extra=()):
        args = [sys.executable, str(SCRIPTS / "preserve_gds_structures.py")]
        for option, filename in [("layout", "layout.gds"), ("library", "library.gds"),
                                 ("cells", "cells.json"), ("output", "output.gds"), ("report", "report.json")]:
            args.extend(("--" + option, str(directory / filename)))
        return subprocess.run([*args, *extra], stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE, universal_newlines=True)

    def test_cli_binds_hashes_without_names_or_paths(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "layout.gds").write_bytes(self.layout)
            (root / "library.gds").write_bytes(self.library)
            (root / "cells.json").write_text('["Leaf"]')
            result = self.run_cli(root)
            self.assertEqual(result.returncode, 0)
            self.assertEqual(result.stderr, "")
            self.assertNotIn(str(root), result.stdout)
            self.assertNotIn("Leaf", result.stdout)
            self.assertEqual((root / "output.gds").read_bytes(), stream([self.top, self.original_leaf]))
            self.assertEqual(json.loads(result.stdout)["error"], "none")

    def test_cli_does_not_overwrite_existing_output(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "output.gds").write_bytes(b"preserved")
            result = self.run_cli(root)
            self.assertEqual(result.returncode, 1)
            self.assertEqual(json.loads(result.stdout), {"error": "output_exists"})
            self.assertEqual((root / "output.gds").read_bytes(), b"preserved")

    def test_cli_failure_hides_paths(self):
        with tempfile.TemporaryDirectory() as temporary:
            result = self.run_cli(Path(temporary))
            self.assertEqual(result.returncode, 1)
            self.assertEqual(result.stderr, "")
            self.assertEqual(json.loads(result.stdout), {"error": "input_or_output_failure"})

    def test_cli_argument_failure_hides_values(self):
        with tempfile.TemporaryDirectory() as temporary:
            result = self.run_cli(Path(temporary), ("--unexpected", "input-marker"))
            self.assertEqual(result.returncode, 1)
            self.assertEqual(result.stderr, "")
            self.assertEqual(json.loads(result.stdout), {"error": "arguments"})


if __name__ == "__main__":
    unittest.main()
