# SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
# SPDX-License-Identifier: MIT
{ zaozi, system }:
(import ./stable-toolchain.nix {
  inherit zaozi system;
  lock = builtins.fromJSON (builtins.readFile ../flake.lock);
}).extend (final: prev: {
          mkMavenRepository = args:
            let
              lock = builtins.fromJSON (builtins.readFile args.lockFile);
              metadata = final.lib.filterAttrs (_: artifact:
                builtins.hasAttr "maven-metadata.xml" artifact.files
              ) lock.artifacts;
              pinned = final.lib.mapAttrs (directory: _:
                let
                  prefix = "${directory}/";
                  coordinates = final.lib.filter (path:
                    final.lib.hasPrefix prefix path
                    && !(final.lib.hasInfix "/" (final.lib.removePrefix prefix path))
                  ) (builtins.attrNames lock.artifacts);
                  versions = builtins.sort final.lib.versionOlder
                    (map (final.lib.removePrefix prefix) coordinates);
                  parts = final.lib.splitString "/" directory;
                  artifactId = final.lib.last parts;
                  groupId = final.lib.concatStringsSep "." (final.lib.init parts);
                  latest = final.lib.last versions;
                  xml = final.writeText "pinned-maven-metadata.xml" ''
                    <?xml version="1.0" encoding="UTF-8"?>
                    <metadata>
                      <groupId>${groupId}</groupId><artifactId>${artifactId}</artifactId>
                      <versioning><latest>${latest}</latest><release>${latest}</release>
                        <versions>${final.lib.concatMapStrings (version: "<version>${version}</version>") versions}</versions>
                      </versioning>
                    </metadata>
                  '';
                in final.runCommand "pinned-maven-metadata-${artifactId}" { } ''
                  install -Dm444 ${xml} "$out/${directory}/maven-metadata.xml"
                  sha1sum "$out/${directory}/maven-metadata.xml" | cut -d' ' -f1 \
                    > "$out/${directory}/maven-metadata.xml.sha1"
                  chmod 444 "$out/${directory}/maven-metadata.xml.sha1"
                ''
              ) metadata;
            # Remote version indexes change even when every selected artifact is pinned.
            in prev.mkMavenRepository (pinned // args);
        })
