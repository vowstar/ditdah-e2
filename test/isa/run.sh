#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
# SPDX-License-Identifier: MIT
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../.."
exec nix develop --impure --expr '
  let
    project = builtins.getFlake (toString ./.);
    pkgs = import ./nix/toolchain.nix {
      zaozi = project.inputs.zaozi;
      system = builtins.currentSystem;
    };
  in (import ./nix/isa-tools.nix { inherit pkgs; }).shell
' --command python3 test/isa/run.py "$@"
