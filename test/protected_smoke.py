# SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
# SPDX-License-Identifier: MIT
"""Check a protected program that handles a denied store and returns to U."""

import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile

from programs import constant, immediate, store, csr, jump, branch, add, MRET
from verify import check


class ProtectedCase:
    name = "protected_store_return"
    reset = 0
    enable_m = enable_c = protected_mode = True
    instruction_fault = data_fault = None
    interrupt_schedule = expected_interrupts = ()
    expected_causes = (7, 8)
    completion_pc = 0x3000
    signature = {0x400: 7, 0x500: 42, 0x504: 42, 0x600: 7, 0x604: 8}

    def words(self):
        boot = constant(1, 0x2000) + [csr(0, 0x305, 1, 1)]
        boot += constant(1, 0x100) + [csr(0, 0x3B0, 1, 1)]
        boot += constant(1, 0x1000) + [csr(0, 0x3B1, 1, 1)]
        boot += constant(1, 0x0F11) + [csr(0, 0x3A0, 1, 1)]
        boot += constant(1, 0x1000) + [csr(0, 0x341, 1, 1), csr(0, 0x300, 0, 1), MRET]
        user = constant(1, 0x500) + [immediate(2, 0, 42), store(2, 1)]
        user += constant(3, 0x400) + [store(2, 3), immediate(4, 1, 0, opcode=3, funct3=2), store(4, 1, 4), 0x73]
        handler = constant(25, 0x600) + [immediate(24, 31, 2, funct3=1), add(25, 25, 24),
            csr(26, 0x342), store(26, 25), immediate(31, 31, 1), immediate(28, 0, 8),
            branch(26, 28, 20), csr(27, 0x341), immediate(27, 27, 4), csr(0, 0x341, 27, 1), MRET]
        handler += [jump(0, self.completion_pc - 0x2000 - 4 * len(handler))]
        result = {0x400: 7, self.completion_pc: 0x6F}
        for base, code in ((0, boot), (0x1000, user), (0x2000, handler)):
            result.update({base + 4 * index: word for index, word in enumerate(code)})
        return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--rtl", type=Path, default=Path("result/protected-rtl"))
    parser.add_argument("--output", type=Path, default=Path("result/protected-smoke"))
    args = parser.parse_args()
    output = args.output
    output.mkdir()
    manifest = json.loads((args.rtl / "manifest.json").read_text())
    case = ProtectedCase()
    with tempfile.TemporaryDirectory(prefix="ditdah-e2-protected-smoke-", dir="/data/tmp") as directory:
        work = Path(directory)
        command = ["verilator", "--cc", "--exe", "--build", "-j", "2", "--top-module", "DitDahE2",
                   "--Mdir", str(work / "obj"), "-CFLAGS", "-std=c++17",
                   *[str((args.rtl / name).resolve()) for name in manifest["rtlHashes"]],
                   str(Path("test/sim.cpp").resolve())]
        build = subprocess.run(command, capture_output=True, text=True)
        (output / "compile.log").write_text(build.stdout + build.stderr)
        assert build.returncode == 0
        (work / "image.hex").write_text("".join(f"{address:08x} {word:08x}\n" for address, word in sorted(case.words().items())))
        runs = []
        for seed, delay in ((0, 0), (1, 24), (19, 40)):
            command = [str(work / "obj/VDitDahE2"), str(work / "image.hex"), str(seed), str(delay),
                       str(1 << 32), str(1 << 32), "50000", str(case.completion_pc)]
            run = subprocess.run(command, capture_output=True, text=True)
            name = f"protected-s{seed}-d{delay}"
            (output / f"{name}.trace").write_text(run.stdout)
            (output / f"{name}.log").write_text(run.stderr)
            assert run.returncode == 0, run.stderr
            metrics = check(case, run.stdout)
            runs.append({"seed": seed, "delay": delay, "exitStatus": 0, **metrics,
                         "traceHash": hashlib.sha256(run.stdout.encode()).hexdigest()})
    (output / "summary.json").write_text(json.dumps({"scope": "first protected store and return program", "runs": runs}, indent=2) + "\n")
    print("PASS: protected store, precise trap and user return under three memory delays")


if __name__ == "__main__":
    main()
