# SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
# SPDX-License-Identifier: MIT
"""Generate a processor platform with shared atomic SRAM."""

import argparse
import json
from pathlib import Path

from build_platform import ROOT, build


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--platform", type=Path, default=ROOT / "platform.json")
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--output", type=Path, default=Path("result/atomic-platform"))
    args = parser.parse_args()
    build(args.output, args.platform, json.loads(args.config.read_text()), atomic=True)
    print("Generated DitDahE2 atomic platform RTL")


if __name__ == "__main__":
    main()
