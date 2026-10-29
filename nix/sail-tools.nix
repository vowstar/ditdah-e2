# SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
# SPDX-License-Identifier: MIT
{ pkgs }:
let
  model = assert pkgs.sail-riscv.version == "0.12";
    assert pkgs.sail-riscv.src.rev == "refs/tags/0.12";
    assert pkgs.sail-riscv.src.outputHash ==
      "sha256-pi/XP6+NX/wNpBESmnEg2d5cppMpMwFripDPk9vTx9I=";
    pkgs.sail-riscv;
  compiler = pkgs.pkgsCross.riscv32-embedded.stdenv.cc;
in {
  inherit model compiler;
  shell = pkgs.mkShell {
    nativeBuildInputs = [ model compiler compiler.bintools pkgs.python3
      pkgs.verilator pkgs.gnumake pkgs.stdenv.cc ];
    env.PYTHONDONTWRITEBYTECODE = "1";
  };
}
