# SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
# SPDX-License-Identifier: MIT
"""Run bounded locked-owner arbiter reference checks and effective RTL mutation."""

import argparse
import json
from pathlib import Path

from formal.debug_sba.reference import digest, run
from test.test_sba.arbiter import mutate


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rtl", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--depth", type=int, default=16)
    parser.add_argument("--timeout", type=int, default=60)
    args = parser.parse_args()
    if args.output.exists() or args.depth < 8 or args.timeout < 1:
        parser.error("Use a new output directory, depth>=8 and a positive timeout")
    args.output.mkdir(parents=True)
    source = args.rtl / "DitDahE2MemoryArbiter.sv" if args.rtl.is_dir() else args.rtl
    original, frozen = source.read_text(), digest(source)
    wrapper = Path(__file__).with_name("arbiter_formal.sv").read_bytes()
    results = []
    for name, mode, rtl in (("safety", "bmc", original), ("covers", "cover", original),
                            ("negative-owner", "bmc", mutate(original, "wrong-response-owner"))):
        results.append(run(args.output / name, rtl, wrapper, mode, args.depth, args.timeout,
                           top="arbiter_formal", module="DitDahE2MemoryArbiter"))
    if [item["exitStatus"] for item in results] != [0, 0, 1]:
        raise AssertionError("Arbiter reference safety, covers or effective negative did not qualify")
    if digest(source) != frozen:
        raise AssertionError("Arbiter RTL input changed")
    (args.output / "summary.json").write_text(json.dumps({"exitStatus": 0, "results": results,
        "scope": "bounded two-owner request/response protocol and round-robin policy",
        "unboundedProven": False, "commercialGate": "not_run"}, indent=2) + "\n")
    print(f"PASS: arbiter bounded reference at depth {args.depth}, eight covers and an effective RTL negative")


if __name__ == "__main__":
    main()
