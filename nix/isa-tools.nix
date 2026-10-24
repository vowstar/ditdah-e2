# SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
# SPDX-License-Identifier: MIT
{ pkgs }:
let
  archTests = pkgs.fetchFromGitHub {
    owner = "riscv-non-isa";
    repo = "riscv-arch-test";
    rev = "fc32e41d49480fd99ba0a192dfff9c3319b44873";
    hash = "sha256-nhmKQJGyqbtAt51yDE1YdcD9GSQQv77VmLYpO85j120=";
  };
  riscof = pkgs.python3Packages.riscof.overridePythonAttrs (old: {
    src = pkgs.fetchFromGitHub {
      owner = "riscv-software-src";
      repo = "riscof";
      rev = "90ebd1bf48bc7928a5f6a7b0b4993f9fbc944f47";
      hash = "sha256-U0rsGLC3gJ82MtO7Rhh+TyAZrwqTbG1pjeY9rzkYJr4=";
    };
    propagatedBuildInputs = (old.propagatedBuildInputs or []) ++ (with pkgs.python3Packages; [
      gitpython click jinja2 pytz riscv-config riscv-isac setuptools
    ]);
    postPatch = (old.postPatch or "") + ''
      python - <<'PY'
      from pathlib import Path
      path = Path("riscof/framework/main.py")
      text = path.read_text()
      imports = ["from riscv_isac.isac import preprocessing",
                 "from riscv_isac.plugins.translator_cgf import Translate_cgf"]
      for statement in imports:
          assert text.count(statement) == 1
          text = text.replace(statement + "\n", "")
      declaration = "def run_coverage(base, dut_isa_spec, dut_platform_spec, work_dir, cgf_file=None, header_file=None):"
      assert text.count(declaration) == 1
      text = text.replace(declaration, declaration + "\n" +
                          "\n".join("    " + statement for statement in imports))
      path.write_text(text)
      PY
    '';
  });
  spike = assert pkgs.spike.src.rev == "de5094a1a901d77ff44f89b38e00fefa15d4018e"; pkgs.spike;
  compiler = pkgs.pkgsCross.riscv32-embedded.stdenv.cc;
  python = pkgs.python3.withPackages (_: [ riscof ]);
in {
  inherit archTests riscof spike compiler python;
  shell = pkgs.mkShell {
    nativeBuildInputs = [ compiler compiler.bintools python spike pkgs.verilator ];
    env.ARCH_TEST_SOURCE = toString archTests;
    env.PYTHONDONTWRITEBYTECODE = "1";
  };
}
