# SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
# SPDX-License-Identifier: MIT
"""Check executable pairing and the local payload's stack alignment."""

import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
import platform_map
from test.common.elf import ElfImage, Region, load_elf
from test.test_local_memory.platform import verify_boot_payload


class BootInputTests(unittest.TestCase):
    def setUp(self):
        self.banks = {"itcm": bytes(range(4)), "dtcm": bytes(range(4, 8))}
        self.payload = ElfImage(0x10000, (), {}, {})
        self.boot = ElfImage(0, (), {"__payload_entry": 0x10000,
                             "__itcm_image_start": 128, "__itcm_image_end": 132,
                             "__dtcm_image_start": 132, "__dtcm_image_end": 136},
                             {128 + index: index for index in range(8)})

    def test_matching_images(self):
        verify_boot_payload(self.boot, self.payload, self.banks)

    def test_same_layout_different_payload_is_rejected(self):
        changed = {**self.banks, "dtcm": b"\x04\x05\x06\x08"}
        with self.assertRaisesRegex(ValueError, "image bytes"):
            verify_boot_payload(self.boot, self.payload, changed)

    def test_entry_and_extent_mismatch_are_rejected(self):
        self.payload.entry += 4
        with self.assertRaisesRegex(ValueError, "entry"):
            verify_boot_payload(self.boot, self.payload, self.banks)
        self.payload.entry -= 4
        self.boot.symbols["__itcm_image_end"] += 4
        with self.assertRaisesRegex(ValueError, "extent"):
            verify_boot_payload(self.boot, self.payload, self.banks)

    def test_missing_embedded_byte_is_rejected(self):
        del self.boot.memory[128]
        with self.assertRaisesRegex(ValueError, "image bytes"):
            verify_boot_payload(self.boot, self.payload, self.banks)

    @unittest.skipUnless(shutil.which("riscv32-none-elf-gcc"), "Requires the pinned RISC-V compiler")
    def test_four_byte_aligned_bank_has_abi_aligned_stack(self):
        regions = json.loads((ROOT / "platform-local.json").read_text())
        regions["dtcm"]["base"] += 4
        scratch = "/data/tmp" if Path("/data/tmp").is_dir() else None
        with tempfile.TemporaryDirectory(prefix="ditdah-e2-stack-", dir=scratch) as directory:
            work = Path(directory)
            (work / "memory.ld").write_text(platform_map.artifacts(regions)["memory.ld"])
            shutil.copyfile(ROOT / "software/local-memory.ld", work / "payload.ld")
            (work / "payload.S").write_text(".option norvc\n.section .text.start\n.globl _start\n_start: j _start\n.section .bss\n.space 4\n")
            subprocess.run(["riscv32-none-elf-gcc", "-march=rv32imc_zicsr_zifencei", "-mabi=ilp32",
                            "-nostdlib", "-nostartfiles", "-Wl,--build-id=none", "-T", "payload.ld",
                            "payload.S", "-o", "payload.elf"], cwd=work, check=True, capture_output=True)
            memory = tuple(Region(name, regions[name]["base"], regions[name]["size"], 7)
                           for name in ("itcm", "dtcm"))
            image = load_elf(work / "payload.elf", reset_vector=regions["itcm"]["base"],
                             regions=memory, enable_c=True)
            top = image.symbols["__stack_top"]
            self.assertEqual(top % 16, 0)
            self.assertLessEqual(top, regions["dtcm"]["base"] + regions["dtcm"]["size"])
            self.assertGreaterEqual(top - image.symbols["__bss_end"], 256)


if __name__ == "__main__":
    unittest.main()
