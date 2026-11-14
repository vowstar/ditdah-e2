# SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
# SPDX-License-Identifier: MIT

import copy
import json
from pathlib import Path
import shutil
import struct
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT))
import build_local_software as local
import platform_map
from test.common.elf import Region, load_elf
from test.common.model import Model


def executable(entry, segments, flags=0):
    contents = bytearray(256)
    ident = b"\x7fELF\x01\x01\x01" + bytes(9)
    contents[:52] = ident + struct.pack("<HHIIIIIHHHHHH", 2, 243, 1, entry, 52, 0,
                                      flags, 52, 32, len(segments), 0, 0, 0)
    for index, (address, data, size, access, virtual) in enumerate(segments):
        offset = len(contents)
        struct.pack_into("<8I", contents, 52 + index * 32, 1, offset, virtual,
                         address, len(data), size, access, 1)
        contents.extend(data)
    return bytes(contents)


class LocalSoftwareFixture:
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="ditdah-e2-local-software-test-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.regions = json.loads((ROOT / "platform.json").read_text())
        self.regions.update(itcm={"base": 0x10000, "size": 16384},
                            dtcm={"base": 0x20010000, "size": 32768})
        self.platform = self.root / "platform.json"
        self.platform.write_text(json.dumps(self.regions))
        self.payload = self.root / "payload.elf"
        self.itcm, self.dtcm = self.regions["itcm"]["base"], self.regions["dtcm"]["base"]
        self.entry = self.itcm + 4
        self.segments = [(self.itcm, struct.pack("<II", 0x00000013, 0x0000006F), 12, 5, self.itcm),
                         (self.dtcm + 4, b"\xa1\xb2\xc3", 8, 6, self.dtcm + 4)]
        self.write_payload()

    def write_payload(self, *, entry=None, segments=None, flags=0):
        self.payload.write_bytes(executable(self.entry if entry is None else entry,
                                            self.segments if segments is None else segments, flags))


class LocalSoftwareInputs(LocalSoftwareFixture, unittest.TestCase):
    def test_segment_zero_fill_gaps_and_entry(self):
        image, banks = local.bank_images(self.payload, platform_map.validate(self.regions))
        self.assertEqual(image.entry, self.entry)
        self.assertEqual(banks["itcm"], self.segments[0][1] + bytes(4))
        self.assertEqual(banks["dtcm"], bytes(4) + b"\xa1\xb2\xc3" + bytes(5))

    def test_rejects_segments_outside_banks_and_changed_physical_address(self):
        for address, size, virtual in ((0, 8, 0), (self.itcm + 16380, 8, self.itcm + 16380),
                                       (self.itcm, 8, self.itcm + 4)):
            with self.subTest(address=address, size=size, virtual=virtual):
                self.write_payload(segments=[(address, bytes(4), size, 5, virtual)])
                with self.assertRaises(ValueError):
                    local.bank_images(self.payload, platform_map.validate(self.regions))

    def test_rejects_invalid_entry_segments_and_flags(self):
        invalid = [(self.dtcm + 4, self.segments, 0),
                   (self.itcm + 12, self.segments, 0),
                   (self.entry, [self.segments[0], self.segments[0]], 0),
                   (self.entry, self.segments, 2)]
        for entry, segments, flags in invalid:
            with self.subTest(entry=entry, flags=flags), self.assertRaises(ValueError):
                self.write_payload(entry=entry, segments=segments, flags=flags)
                local.bank_images(self.payload, platform_map.validate(self.regions))

    def test_rejects_truncated_payload_and_rom_image_overflow(self):
        for data in (b"", self.payload.read_bytes()[:80]):
            with self.subTest(size=len(data)), self.assertRaises(ValueError):
                self.payload.write_bytes(data)
                local.bank_images(self.payload, platform_map.validate(self.regions))
        self.write_payload()
        regions = copy.deepcopy(self.regions)
        regions["rom"]["size"] = 16
        with self.assertRaisesRegex(ValueError, "ROM capacity"):
            local.bank_images(self.payload, platform_map.validate(regions))

    def test_requires_local_regions_and_preserves_existing_outputs(self):
        del self.regions["dtcm"]
        self.platform.write_text(json.dumps(self.regions))
        with self.assertRaisesRegex(ValueError, "both itcm and dtcm"):
            local.build(self.payload, self.platform, self.root / "new")
        output = self.root / "existing"
        output.mkdir()
        sentinel = output / "evidence.txt"
        sentinel.write_text("original")
        with self.assertRaisesRegex(ValueError, "must not exist"):
            local.build(self.payload, self.platform, output)
        self.assertEqual(sentinel.read_text(), "original")


@unittest.skipUnless(shutil.which("riscv32-none-elf-gcc") and shutil.which("riscv32-none-elf-objdump"),
                     "RV32 compiler and objdump required")
class LocalSoftwareBuild(LocalSoftwareFixture, unittest.TestCase):
    def test_actual_rom_program_copies_poisoned_banks_before_fence_and_jump(self):
        output = self.root / "boot"
        report = local.build(self.payload, self.platform, output)
        rom = self.regions["rom"]
        image = load_elf(output / "program.elf", regions=(Region("rom", rom["base"], rom["size"], 5),))
        self.assertEqual(len(image.segments), 1)
        self.assertFalse(any(self.itcm <= address < self.itcm + 16384 or
                             self.dtcm <= address < self.dtcm + 32768 for address in image.memory))
        model = Model(image.words())
        banks = {key: (output / f"{key}.bin").read_bytes() for key in ("itcm", "dtcm")}
        for key, contents in banks.items():
            for offset in range(len(contents)):
                model.memory[self.regions[key]["base"] + offset] = 0x5A
        writes, fenced = [], False
        for _ in range(1000):
            if model.pc == self.entry:
                break
            event = model.step()
            self.assertFalse(event.trap)
            if event.memory and event.memory[1]:
                self.assertFalse(fenced)
                writes.append(event.memory[0])
            fenced |= event.instruction == "fence.i"
        self.assertEqual(model.pc, self.entry)
        self.assertTrue(fenced)
        expected_writes = []
        for key, contents in banks.items():
            base = self.regions[key]["base"]
            self.assertEqual(bytes(model.memory[base + i] for i in range(len(contents))), contents)
            expected_writes.extend(range(base, base + len(contents), 4))
        self.assertEqual(writes, expected_writes)
        self.assertEqual(report["payloadEntry"], self.entry)
        for name, digest in report["artifactHashes"].items():
            self.assertEqual(local.digest(output / name), digest)
        for name, digest in report["sourceHashes"].items():
            self.assertEqual(local.digest(output / "inputs" / name), digest)

    def test_backend_and_latency_changes_keep_the_same_boot_elf(self):
        first = self.root / "first"
        local.build(self.payload, self.platform, first)
        for key in ("itcm", "dtcm"):
            self.regions[key].update(backend="axi", readLatency=2)
        self.platform.write_text(json.dumps(self.regions))
        second = self.root / "second"
        local.build(self.payload, self.platform, second)
        self.assertEqual((first / "program.elf").read_bytes(), (second / "program.elf").read_bytes())

    def test_empty_unused_bank_and_compressed_payload_entry(self):
        self.write_payload(entry=self.itcm + 2, flags=1,
                           segments=[(self.itcm, b"\x01\x00\x01\x00", 4, 5, self.itcm)])
        output = self.root / "compressed"
        report = local.build(self.payload, self.platform, output)
        self.assertEqual(report["payloadEntry"], self.itcm + 2)
        self.assertEqual(report["payloadElfFlags"], 1)
        self.assertEqual((output / "dtcm.bin").read_bytes(), b"")

    def test_rejects_rom_overflow_from_boot_instructions(self):
        self.regions["rom"]["size"] = 64
        self.platform.write_text(json.dumps(self.regions))
        with self.assertRaisesRegex(ValueError, "assembly or link"):
            local.build(self.payload, self.platform, self.root / "small")


if __name__ == "__main__":
    unittest.main()
