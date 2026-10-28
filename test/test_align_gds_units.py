# SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
# SPDX-License-Identifier: MIT

from fractions import Fraction
import json
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest

SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS))

from align_gds_units import MATRICES, align, grid_proof, reference_orientation, transform_point
from preserve_gds_structures import MergeError
from test_preserve_gds_structures import ONE, TWO, cell, record, stream, text


def unit_with_delta(bits):
    return b"\x41" + ((1 << 52) + (1 << bits)).to_bytes(7, "big")


def placement(name, origin=(100, 200), extra=b""):
    return (record(10) + record(18, 6, name.encode()) + extra
            + record(16, 3, struct.pack(">ii", *origin)) + record(17))


def point_cell(x, y):
    return cell("Leaf", record(12) + record(13, 2, struct.pack(">h", 1))
                + record(22, 2, b"\0\0") + record(16, 3, struct.pack(">ii", x, y))
                + record(25, 6, b"Port") + record(17))


HALF_TURN = bytes.fromhex("42b4000000000000")
TRANSFORMS = {
    "R0": b"",
    "R180": record(26, 1, b"\0\0") + record(28, 5, HALF_TURN),
    "MX": record(26, 1, b"\x80\0"),
    "MY": record(26, 1, b"\x80\0") + record(28, 5, HALF_TURN),
}


class UnitTests(unittest.TestCase):
    def setUp(self):
        self.leaf = cell("Leaf", text(b"\0" * 8))
        self.top = cell("Top", placement("Leaf"))
        self.library = stream([self.leaf])
        self.layout = stream([self.top, self.leaf], unit=unit_with_delta(0))

    def test_changes_only_units_record(self):
        output, report = align(self.layout, self.library)
        self.assertEqual(output, stream([self.top, self.leaf]))
        self.assertTrue(report["unitHeaderChanged"])
        self.assertFalse(report["integerCoordinatesChanged"])
        self.assertFalse(report["structureBytesChanged"])
        self.assertFalse(report["physicalMeterCoordinatesIdentical"])
        self.assertEqual(report["coordinateMinimum"], -(1 << 31))
        self.assertEqual(report["coordinateMaximum"], (1 << 31) - 1)
        self.assertEqual(report["layoutGeometry"]["maximumHierarchyDepth"], 1)

    def test_preserves_text_zero_magnification(self):
        output, _ = align(self.layout, self.library)
        self.assertIn(self.leaf, output)
        self.assertIn(record(27, 5, b"\0" * 8), output)

    def test_rejects_unit_mismatch(self):
        with self.assertRaisesRegex(MergeError, "unit_grid_mismatch"):
            align(stream([self.top, self.leaf], unit=TWO), self.library)

    def test_checks_first_units_component(self):
        with self.assertRaisesRegex(MergeError, "unit_grid_mismatch"):
            align(stream([self.top, self.leaf], user_unit=TWO), self.library)

    def test_rejects_exact_half_grid_boundary(self):
        with self.assertRaisesRegex(MergeError, "unit_grid_mismatch"):
            grid_proof(Fraction(1) + Fraction(1, 1 << 32), Fraction(1))

    def test_proof_includes_negative_endpoint(self):
        result = grid_proof(Fraction(1) + Fraction(1, 1 << 33), Fraction(1))
        self.assertEqual(result["maximumGridDisplacement"], {"numerator": 1, "denominator": 4})

    def test_accepts_minimum_signed_coordinate(self):
        leaf = cell("Leaf", record(12) + record(16, 3, struct.pack(">ii", -(1 << 31), 0)) + record(17))
        top = cell("Top", placement("Leaf", (0, 0)))
        output, _ = align(stream([top, leaf], unit=unit_with_delta(0)), stream([leaf]))
        self.assertEqual(output, stream([top, leaf]))

    def test_rejects_nonunit_spatial_magnification(self):
        top = cell("Top", placement("Leaf", extra=record(27, 5, TWO)))
        with self.assertRaisesRegex(MergeError, "non_unit_spatial_magnification"):
            align(stream([top, self.leaf]), self.library)

    def test_rejects_spatial_rotation(self):
        top = cell("Top", placement("Leaf", extra=record(28, 5, ONE)))
        with self.assertRaisesRegex(MergeError, "reference_rotation_outside_scope"):
            align(stream([top, self.leaf]), self.library)

    def test_rejects_reserved_reference_flags(self):
        top = cell("Top", placement("Leaf", extra=record(26, 1, b"\x80\x01")))
        with self.assertRaisesRegex(MergeError, "reference_flags_outside_scope"):
            align(stream([top, self.leaf]), self.library)

    def test_four_exact_integer_transforms(self):
        expected = {"R0": (10, 6), "R180": (4, 16), "MX": (10, 16), "MY": (4, 6)}
        for orientation, point in expected.items():
            with self.subTest(orientation=orientation):
                self.assertEqual(transform_point(MATRICES[orientation], (3, -5), (7, 11)), point)
                top = cell("Top", placement("Leaf", extra=TRANSFORMS[orientation]))
                layout = stream([top, self.leaf], unit=unit_with_delta(0))
                output, report = align(layout, self.library)
                self.assertEqual(output, stream([top, self.leaf]))
                geometry = report["layoutGeometry"]
                self.assertEqual(geometry["referenceTransformCounts"], {orientation: 1})
                self.assertEqual(geometry["translationsOnly"], orientation == "R0")

    def test_equivalent_signed_half_turns(self):
        for angle in (-540, -180, 180, 540):
            self.assertEqual(reference_orientation(Fraction(angle), False), "R180")
            self.assertEqual(reference_orientation(Fraction(angle), True), "MY")
        for angle in (-360, 0, 360):
            self.assertEqual(reference_orientation(Fraction(angle), False), "R0")
            self.assertEqual(reference_orientation(Fraction(angle), True), "MX")

    def test_rejects_quarter_turns_and_fractional_angles(self):
        angles = (bytes.fromhex("425a000000000000"), bytes.fromhex("4310e00000000000"),
                  bytes.fromhex("422d000000000000"), bytes.fromhex("4080000000000000"))
        for angle in angles:
            for reflected in (b"\0\0", b"\x80\0"):
                extra = record(26, 1, reflected) + record(28, 5, angle)
                top = cell("Top", placement("Leaf", extra=extra))
                with self.assertRaisesRegex(MergeError, "reference_rotation_outside_scope"):
                    align(stream([top, self.leaf]), self.library)

    def test_rejects_absolute_reference_flags(self):
        for flags in (2, 4, 0x8002, 0x8004):
            top = cell("Top", placement("Leaf", extra=record(26, 1, struct.pack(">H", flags))))
            with self.assertRaisesRegex(MergeError, "reference_flags_outside_scope"):
                align(stream([top, self.leaf]), self.library)

    def test_reflected_minimum_requires_boundary_translation(self):
        cases = (("MX", (0, -(1 << 31)), (0, -1)),
                 ("MY", (-(1 << 31), 0), (-1, 0)),
                 ("R180", (-(1 << 31), -(1 << 31)), (-1, -1)))
        for orientation, point, origin in cases:
            leaf = point_cell(*point)
            for translation, accepted in ((origin, True), ((0, 0), False)):
                top = cell("Top", placement("Leaf", translation, TRANSFORMS[orientation]))
                layout = stream([top, leaf], unit=unit_with_delta(0))
                if accepted:
                    output, _ = align(layout, stream([leaf]))
                    self.assertEqual(output, stream([top, leaf]))
                else:
                    with self.assertRaisesRegex(MergeError, "transformed_coordinate_outside_scope"):
                        align(layout, stream([leaf]))

    def test_reflected_maximum_negative_boundary(self):
        leaf = point_cell((1 << 31) - 1, (1 << 31) - 1)
        for offset, accepted in ((-1, True), (-2, False)):
            top = cell("Top", placement("Leaf", (offset, offset), TRANSFORMS["R180"]))
            if accepted:
                output, _ = align(stream([top, leaf]), stream([leaf]))
                self.assertEqual(output, stream([top, leaf]))
            else:
                with self.assertRaisesRegex(MergeError, "transformed_coordinate_outside_scope"):
                    align(stream([top, leaf]), stream([leaf]))

    def test_signed_boundaries_for_each_transform(self):
        limits = (-(1 << 31), -1, 0, 1, (1 << 31) - 1)
        signs = {"R0": (1, 1), "R180": (-1, -1), "MX": (1, -1), "MY": (-1, 1)}
        for orientation, (sx, sy) in signs.items():
            for x in limits:
                for y in limits:
                    leaf = point_cell(x, y)
                    for tx in (-1, 0, 1):
                        for ty in (-1, 0, 1):
                            top = cell("Top", placement("Leaf", (tx, ty), TRANSFORMS[orientation]))
                            accepted = all(-(1 << 31) <= value < 1 << 31
                                           for value in (sx * x + tx, sy * y + ty))
                            with self.subTest(orientation=orientation, point=(x, y), origin=(tx, ty)):
                                if accepted:
                                    align(stream([top, leaf]), stream([leaf]))
                                else:
                                    with self.assertRaisesRegex(MergeError, "transformed_coordinate_outside_scope"):
                                        align(stream([top, leaf]), stream([leaf]))

    def test_reflection_does_not_allow_nonunit_magnification(self):
        for magnification in (b"\0" * 8, TWO, bytes.fromhex("c110000000000000"),
                              bytes.fromhex("4118000000000000")):
            extra = TRANSFORMS["MX"] + record(27, 5, magnification)
            top = cell("Top", placement("Leaf", extra=extra))
            with self.assertRaisesRegex(MergeError, "non_unit_spatial_magnification"):
                align(stream([top, self.leaf]), self.library)

    def test_reflection_preserves_text_magnification_and_unit_reference(self):
        extra = TRANSFORMS["MX"] + record(27, 5, ONE)
        top = cell("Top", placement("Leaf", extra=extra))
        output, report = align(stream([top, self.leaf]), self.library)
        self.assertEqual(output, stream([top, self.leaf]))
        self.assertTrue(report["layoutGeometry"]["unitSpatialMagnification"])

    def run_cli(self, root):
        args = [sys.executable, str(SCRIPTS / "align_gds_units.py")]
        for option, filename in (("layout", "layout.gds"), ("library", "library.gds"),
                                 ("output", "output.gds"), ("report", "report.json")):
            args.extend(("--" + option, str(root / filename)))
        return subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                              universal_newlines=True)

    def test_cli_aligns_four_transform_layout(self):
        top = cell("Top", b"".join(placement("Leaf", extra=value) for value in TRANSFORMS.values()))
        layout = stream([top, self.leaf], unit=unit_with_delta(0))
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "layout.gds").write_bytes(layout)
            (root / "library.gds").write_bytes(self.library)
            result = self.run_cli(root)
            self.assertEqual(result.returncode, 0)
            self.assertEqual(result.stderr, "")
            self.assertNotIn(directory, result.stdout)
            self.assertNotIn("Leaf", result.stdout)
            self.assertEqual(json.loads(result.stdout)["error"], "none")
            self.assertEqual((root / "output.gds").read_bytes(), stream([top, self.leaf]))
            report = json.loads((root / "report.json").read_text())
            self.assertEqual(report["layoutGeometry"]["referenceTransformCounts"],
                             {"R0": 1, "R180": 1, "MX": 1, "MY": 1})
            self.assertEqual((root / "layout.gds").read_bytes(), layout)
            self.assertEqual((root / "library.gds").read_bytes(), self.library)

    def test_cli_rejects_unsupported_angle(self):
        top = cell("Top", placement("Leaf", extra=record(28, 5, bytes.fromhex("425a000000000000"))))
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "layout.gds").write_bytes(stream([top, self.leaf]))
            (root / "library.gds").write_bytes(self.library)
            result = self.run_cli(root)
            self.assertEqual(result.returncode, 1)
            self.assertEqual(result.stderr, "")
            self.assertEqual(json.loads(result.stdout), {"error": "reference_rotation_outside_scope"})
            self.assertFalse((root / "output.gds").exists())

    def test_rejects_array_reference(self):
        top = cell("Top", record(11) + record(18, 6, b"Leaf")
                   + record(19, 2, struct.pack(">hh", 1, 1))
                   + record(16, 3, struct.pack(">6i", 0, 0, 1, 0, 0, 1)) + record(17))
        with self.assertRaisesRegex(MergeError, "array_reference_outside_scope"):
            align(stream([top, self.leaf]), self.library)

    def test_rejects_deeper_hierarchy(self):
        middle = cell("Middle", placement("Leaf"))
        top = cell("Top", placement("Middle"))
        with self.assertRaisesRegex(MergeError, "hierarchy_depth_outside_scope"):
            align(stream([top, middle, self.leaf]), self.library)

    def test_rejects_transformed_coordinate_overflow(self):
        top = cell("Top", placement("Leaf", ((1 << 31) - 1, 0)))
        with self.assertRaisesRegex(MergeError, "transformed_coordinate_outside_scope"):
            align(stream([top, self.leaf]), self.library)


if __name__ == "__main__":
    unittest.main()
