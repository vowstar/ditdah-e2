# SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
# SPDX-License-Identifier: MIT
"""Exercise the storage leaf without a bus or an atomic controller."""

from pathlib import Path
import random
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]


def stimulus(depth, width, granularity):
    mask = (1 << (width // granularity)) - 1
    value_mask = (1 << width) - 1
    rows = [(index, 0, mask, (0x13579BDF ^ index * 0xA53C19) & value_mask) for index in range(depth)]
    rows += [(0, 1, 0, 0), (0, 0, 0, 0), (0, 0, 0, 0)]
    for lane in range(width // granularity):
        rows += [(0, 1, 1 << lane, (0xFEDCBA9876543210 >> lane) & value_mask),
                 (0, 0, 0, 0), (0, 1, 0, 0)]
    rng = random.Random(73)
    for _ in range(60):
        rows.append((rng.randrange(depth), rng.randrange(2), rng.randrange(mask + 1), rng.getrandbits(width)))
    if depth != 1 << max(1, (depth - 1).bit_length()):
        rows += [(depth, 1, mask, value_mask), (depth, 0, mask, 0)]
    rows += [(index, 1, 0, 0) for index in range(depth)]
    return rows + [(0, 0, 0, 0)] * 3


def bench(depth=3, width=32, granularity=8, latency=1, legacy=True):
    address_width = max(1, (depth - 1).bit_length())
    lanes = width // granularity
    memory, due, output = {}, {}, None
    steps = []
    for cycle, (address, read, mask, data) in enumerate(stimulus(depth, width, granularity)):
        if read and address < depth:
            due[cycle + latency - 1] = memory[address]
        if address < depth:
            for lane in range(lanes):
                if mask >> lane & 1:
                    bits = ((1 << granularity) - 1) << (lane * granularity)
                    memory[address] = (memory.get(address, 0) & ~bits) | (data & bits)
        if cycle in due:
            output = due.pop(cycle)
        steps.append(f"    address={address}; readEnable={read}; writeMask={lanes}'h{mask:x}; writeData={width}'h{data:x}; #1 clock=1; #1;")
        if output is not None:
            steps.append(f"    if (readData !== {width}'h{output:x}) $fatal(1, \"SRAM data differs at cycle {cycle}\");")
            if legacy and width == 32 and granularity == 8:
                steps.append('    if (legacyData !== readData) $fatal(1, "Legacy SRAM differs");')
        steps.append("    clock=0;")
    compatibility = ""
    if legacy and width == 32 and granularity == 8:
        compatibility = ("wire [31:0] legacyData; DitDahE2AtomicSram #(.WORDS(" + str(depth) + "), .ADDRESS_WIDTH(" +
                         str(address_width) + "), .READ_LATENCY(" + str(latency) + ")) old(clock,address,readEnable,writeMask,writeData,legacyData);")
    return f"""module SramBench;
  reg clock=0, readEnable=0;
  reg [{address_width-1}:0] address=0;
  reg [{lanes-1}:0] writeMask=0;
  reg [{width-1}:0] writeData=0;
  wire [{width-1}:0] readData;
  DitDahE2Sram #(.DEPTH({depth}),.WIDTH({width}),.MASK_GRANULARITY({granularity}),.READ_LATENCY({latency})) dut(.*);
  {compatibility}
  initial begin
{chr(10).join(steps)}
    $display("PASS storage behavior"); $finish;
  end
endmodule
"""


class SramTests(unittest.TestCase):
    def run_storage(self, source, testbench):
        with tempfile.TemporaryDirectory(prefix="ditdah-e2-sram-unit-", dir="/data/tmp") as temporary:
            folder = Path(temporary)
            (folder / "Sram.sv").write_text(source)
            (folder / "AtomicSram.sv").write_bytes((ROOT / "ditdah_e2/src/AtomicSram.sv").read_bytes())
            (folder / "bench.sv").write_text(testbench)
            run = subprocess.run(["iverilog", "-g2012", "-s", "SramBench", "-o", "sim", "Sram.sv", "AtomicSram.sv", "bench.sv"],
                                 cwd=folder, capture_output=True, text=True)
            self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
            return subprocess.run(["vvp", "sim"], cwd=folder, capture_output=True, text=True)

    def test_geometry_latency_masks_collisions_and_holding(self):
        source = (ROOT / "ditdah_e2/src/Sram.sv").read_text()
        for depth in (1, 3, 8):
            for width, granularity in ((8, 8), (32, 8), (64, 16)):
                for latency in (1, 2):
                    with self.subTest(depth=depth, width=width, granularity=granularity, latency=latency):
                        run = self.run_storage(source, bench(depth, width, granularity, latency))
                        self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
                        self.assertIn("PASS storage behavior", run.stdout)

    def test_invalid_geometry_is_rejected(self):
        source = (ROOT / "ditdah_e2/src/Sram.sv").read_text()
        for settings in (".DEPTH(0)", ".READ_LATENCY(3)", ".WIDTH(30)", ".MASK_GRANULARITY(7)", ".DEPTH(3),.ADDRESS_WIDTH(1)"):
            with self.subTest(settings=settings):
                run = self.run_storage(source, "module SramBench; DitDahE2Sram #(" + settings + ") dut(); initial #1 $finish; endmodule")
                self.assertNotEqual(run.returncode, 0)
                self.assertIn("Unsupported SRAM geometry", run.stdout)

    def test_checker_rejects_wrong_mask_and_read_collision(self):
        source = (ROOT / "ditdah_e2/src/Sram.sv").read_text()
        for before, after in (("validAddress && writeMask[lane]", "validAddress && (|writeMask)"),
                              ("readData <= memory[address]", "readData <= writeMask == 0 ? memory[address] : writeData")):
            with self.subTest(mutation=before):
                self.assertEqual(source.count(before), 1)
                run = self.run_storage(source.replace(before, after), bench(legacy=False))
                self.assertNotEqual(run.returncode, 0)
                self.assertIn("SRAM data differs", run.stdout)


if __name__ == "__main__":
    unittest.main()
