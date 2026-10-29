# SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
# SPDX-License-Identifier: MIT
{ pkgs }:
let
  python = pkgs.python3.withPackages (ps: [ ps.click ]);
  source = pkgs.fetchFromGitHub {
    owner = "YosysHQ";
    repo = "riscv-formal";
    rev = "2aa7b4934190baeb2ef62b2de414f104b489d3cc";
    hash = "sha256-LpkuVlVDknzO0xk8hXVYVmvHeAy8UMMfT3bSjQY5Lg8=";
  };
in {
  inherit source;
  shell = pkgs.mkShell {
    nativeBuildInputs = [ python pkgs.yosys pkgs.sby pkgs.z3 pkgs.gnumake ];
    env.RISCV_FORMAL_ROOT = source;
    env.PYTHONDONTWRITEBYTECODE = "1";
    env.PYTHONPATH = "${python}/${pkgs.python3.sitePackages}";
  };
}
