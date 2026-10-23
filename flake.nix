# SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
# SPDX-License-Identifier: MIT
{
  description = "DitDah-E2 three-stage embedded processor";
  inputs = {
    zaozi.url = "github:xinpian-tech/zaozi";
    nixpkgs.follows = "zaozi/nixpkgs";
    flake-utils.follows = "zaozi/flake-utils";
  };
  outputs = { self, zaozi, flake-utils, ... }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import ./nix/toolchain.nix { inherit zaozi system; };
        jar = "${pkgs.zaozi.zaozi-assembly}/share/java/elaborator.jar";
        arguments = pkgs.lib.escapeShellArgs [
          "--server=false" "--java-home" "${pkgs.jdk25}"
          "--extra-jars" jar "--scala-version" "3.8.4" "-O=-experimental"
          "--java-opt" "--enable-native-access=ALL-UNNAMED"
          "--java-opt" "--enable-preview"
          "--java-opt" "-Djava.library.path=${pkgs.circt-install}/lib:${pkgs.mlir-install}/lib"
        ];
        elaborate = pkgs.writeShellScriptBin "elaborate-ditdah-e2" ''
          set -euo pipefail
          scratch="''${TMPDIR:-/tmp}"
          if [ -w /data/tmp ]; then scratch=/data/tmp; fi
          work=$(mktemp -d "$scratch/ditdah-e2-scala-XXXXXX")
          trap 'rm -rf "$work"' EXIT
          ${pkgs.scala-cli}/bin/scala-cli run --power --offline ${arguments} \
            --workspace "$work" --main-class ditdah_e2.DitDahE2 \
            "$DITDAH_E2_SOURCE" -- "$@"
        '';
        maven = pkgs.mkMavenRepository { lockFile = "${zaozi}/mtf.lock.json"; };
        tools = [ elaborate pkgs.scala-cli pkgs.circt-install pkgs.mlir-install
          pkgs.verilator pkgs.iverilog pkgs.yosys pkgs.sby pkgs.z3 pkgs.reuse
          pkgs.python3 pkgs.gnumake maven ];
      in {
        packages.default = pkgs.runCommand "ditdah-e2-rtl" {
          nativeBuildInputs = tools;
        } ''
          cp -R ${./ditdah_e2} ditdah_e2
          cp -R ${./scripts} scripts
          cp ${./flake.nix} flake.nix
          cp ${./flake.lock} flake.lock
          cp -R ${./nix} nix
          chmod -R u+w .
          export COURSIER_CACHE="$NIX_BUILD_TOP/coursier-cache"
          python3 scripts/build_rtl.py --output "$out"
        '';
        devShells.default = pkgs.mkShell {
          nativeBuildInputs = tools;
          env.ZAOZI_JAR = jar;
          env.PYTHONDONTWRITEBYTECODE = "1";
        };
      });
}
