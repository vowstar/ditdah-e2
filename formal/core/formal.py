# SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
# SPDX-License-Identifier: MIT
"""Run the fetch proof for the generated instruction configuration."""

import argparse
from pathlib import Path
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[2]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rtl", type=Path, default=Path("result/rtl"))
    parser.add_argument("--source-root", type=Path, default=Path("."))
    parser.add_argument("--output", type=Path, default=Path("result/formal"))
    args = parser.parse_args()
    subprocess.run([sys.executable, str(ROOT / "formal/fetch/compressed_fetch_formal.py"),
                    "--rtl", str(args.rtl), "--source-root", str(args.source_root),
                    "--output", str(args.output)], check=True)
    subprocess.run([sys.executable, str(ROOT / "formal/fetch/fetch_latency.py"),
                    "--rtl", str(args.rtl), "--source-root", str(args.source_root),
                    "--output", str(args.output / "latency")], check=True)


if __name__ == "__main__":
    main()
