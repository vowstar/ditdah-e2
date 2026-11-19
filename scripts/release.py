# SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
# SPDX-License-Identifier: MIT

"""Build portable RTL archives and publish verified GitHub Release assets."""

import argparse
import gzip
import hashlib
import io
import json
from pathlib import Path
import re
import subprocess
import sys
import tarfile
import tempfile

from build_rtl import configuration
import platform_map


ROOT = Path(__file__).resolve().parents[1]


def digest(data):
    return hashlib.sha256(data).hexdigest()


def asset_names(version):
    return (
        f"ditdah-e2-{version}-rtl.tar.gz",
        f"ditdah-e2-{version}-local-sram-rtl.tar.gz",
        "SHA256SUMS",
    )


def checksums(directory, names):
    return "".join(f"{digest((directory / name).read_bytes())}  {name}\n" for name in names)


def asset_digests(directory, version):
    names = asset_names(version)
    entries = list(directory.iterdir())
    if {path.name for path in entries} != set(names) or any(
        path.is_symlink() or not path.is_file() for path in entries
    ):
        raise ValueError("Unexpected release files")
    if (directory / "SHA256SUMS").read_text() != checksums(directory, names[:-1]):
        raise ValueError("Release checksums do not match the archives")
    return {name: "sha256:" + digest((directory / name).read_bytes()) for name in names}


def archive(output, build, top, version, commit):
    block = top == "DitDahE2PlatformBlock"
    rtl = build / "rtl" if block else build
    report = json.loads((build / "manifest.json").read_bytes())
    if report["top"] != top or report["exitStatus"] != 0:
        raise ValueError(f"Invalid build manifest for {top}")

    parameters = report["parameters"]
    if block:
        platform = (ROOT / "platform-local.json").read_bytes()
        expected = platform_map.parameters(platform_map.validate(json.loads(platform)), {})
        if report["platformHash"] != digest(platform):
            raise ValueError("Platform map differs from the build input")
    else:
        expected = configuration({})
    if parameters != expected:
        raise ValueError(f"Release configuration differs from the default for {top}")

    for path, checksum in report["sourceHashes"].items():
        if digest((ROOT / path).read_bytes()) != checksum:
            raise ValueError(f"Source differs from the build input: {path}")
    names = (rtl / "filelist.f").read_text().splitlines()
    if names != sorted(report["rtlHashes"]) or f"{top}.sv" not in names:
        raise ValueError(f"Invalid Verilog file list for {top}")

    files = {}
    for name in names:
        if not re.fullmatch(r"[a-zA-Z0-9_]+[.]sv", name):
            raise ValueError(f"Invalid Verilog filename: {name}")
        files[name] = (rtl / name).read_bytes()
        if digest(files[name]) != report["rtlHashes"][name]:
            raise ValueError(f"Verilog hash differs from manifest: {name}")
    manifest = {key: report[key] for key in ("top", "parameters", "sourceHashes", "rtlHashes", "firtool")}
    manifest.update(version=version, sourceCommit=commit)
    if block:
        files["platform-local.json"] = platform
        manifest["platformHash"] = report["platformHash"]
    files["manifest.json"] = (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode()
    files["LICENSE"] = (ROOT / "LICENSE").read_bytes()
    files["filelist.f"] = (rtl / "filelist.f").read_bytes()

    with tempfile.TemporaryDirectory(prefix="ditdah-e2-lint-") as scratch:
        for name, data in files.items():
            (Path(scratch) / name).write_bytes(data)
        subprocess.run(
            ["verilator", "--lint-only", "--top-module", top, "-f", "filelist.f"],
            cwd=scratch, check=True,
        )
    with output.open("xb") as stream, gzip.GzipFile(
        fileobj=stream, filename="", mode="wb", mtime=0,
    ) as compressed, tarfile.open(fileobj=compressed, mode="w", format=tarfile.USTAR_FORMAT) as pack:
        for name, data in sorted(files.items()):
            entry = tarfile.TarInfo(name)
            entry.size = len(data)
            entry.mode = 0o644
            pack.addfile(entry, io.BytesIO(data))


def build_release(output, version):
    output.mkdir(parents=True, exist_ok=True)
    if any(output.iterdir()):
        raise ValueError("Release output directory must be empty")
    commit = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    if subprocess.check_output(["git", "status", "--porcelain", "--untracked-files=no"], cwd=ROOT):
        raise ValueError("Release build requires a clean checkout")
    core, platform, checksum = asset_names(version)
    with tempfile.TemporaryDirectory(prefix="ditdah-e2-release-") as scratch:
        scratch = Path(scratch)
        for script, args in (
            ("build_rtl.py", ["--output", scratch / "core"]),
            ("build_platform.py", ["--platform", "platform-local.json", "--output", scratch / "platform"]),
            ("build_platform_block.py", ["--platform-build", scratch / "platform", "--output", scratch / "block"]),
        ):
            subprocess.run([sys.executable, ROOT / "scripts" / script, *args], cwd=ROOT, check=True)
        archive(output / core, scratch / "core", "DitDahE2", version, commit)
        archive(output / platform, scratch / "block", "DitDahE2PlatformBlock", version, commit)
    (output / checksum).write_text(checksums(output, (core, platform)))
    asset_digests(output, version)


def gh_json(*args):
    return json.loads(subprocess.check_output(["gh", "api", *args]))


def require_tag(repo, version, tag_object):
    ref = gh_json(f"repos/{repo}/git/ref/tags/{version}")["object"]
    if ref["type"] != "tag" or ref["sha"] != tag_object:
        raise ValueError("Remote tag differs from the verified tag")


def find_release(repo, version):
    pages = gh_json(f"repos/{repo}/releases", "--paginate", "--slurp")
    return next((release for page in pages for release in page if release["tag_name"] == version), None)


def release_assets(repo, release_id):
    pages = gh_json(f"repos/{repo}/releases/{release_id}/assets", "--paginate", "--slurp")
    assets = {}
    for page in pages:
        for asset in page:
            name = asset["name"]
            if name in assets or asset["state"] != "uploaded":
                raise ValueError(f"Incomplete or duplicate release asset: {name}")
            assets[name] = asset["digest"]
    return assets


def publish(directory, version, repo, tag_object):
    expected = asset_digests(directory, version)
    core, platform, _ = asset_names(version)
    title = f"DitDah-E2 {version}"
    notes = (
        "SystemVerilog for the default RV32 core and local SRAM platform.\n\n"
        "| Download | Top module | Contents |\n"
        "| --- | --- | --- |\n"
        f"| `{core}` | `DitDahE2` | Default core RTL |\n"
        f"| `{platform}` | `DitDahE2PlatformBlock` | Platform RTL with behavioral SRAM models |\n\n"
        "Each archive includes a Verilog file list, build manifest and MIT license.\n"
        "Download `SHA256SUMS` beside both archives and run `sha256sum -c SHA256SUMS`.\n"
    )
    require_tag(repo, version, tag_object)
    release = find_release(repo, version)
    if release is None:
        subprocess.run(
            ["gh", "release", "create", version, "--repo", repo, "--verify-tag", "--draft",
             "--title", title, "--notes", notes], check=True,
        )
        release = find_release(repo, version)
    if release is None or release["name"] != title or release["body"].rstrip() != notes.rstrip():
        raise ValueError("GitHub Release title or notes differ from the prepared text")
    assets = release_assets(repo, release["id"])
    if any(expected.get(name) != value for name, value in assets.items()):
        raise ValueError("GitHub Release contains unexpected files or digests")
    missing = expected.keys() - assets.keys()
    if missing and release["draft"]:
        subprocess.run(
            ["gh", "release", "upload", version, "--repo", repo,
             *(directory / name for name in sorted(missing))], check=True,
        )
        assets = release_assets(repo, release["id"])
    if assets != expected:
        raise ValueError("GitHub Release asset verification failed")
    if release["draft"]:
        require_tag(repo, version, tag_object)
        subprocess.run(
            ["gh", "release", "edit", version, "--repo", repo, "--verify-tag", "--draft=false"],
            check=True,
        )
    print(f"Verified release assets for {repo} {version}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    for command in ("build", "publish"):
        arguments = commands.add_parser(command)
        arguments.add_argument("--version", required=True)
        arguments.add_argument("--directory", type=Path, required=True)
        if command == "publish":
            arguments.add_argument("--repo", required=True)
            arguments.add_argument("--tag-object", required=True)
    args = parser.parse_args()
    if not re.fullmatch(r"v(?:0|[1-9][0-9]*)[.](?:0|[1-9][0-9]*)[.](?:0|[1-9][0-9]*)", args.version):
        parser.error("version must have the form vMAJOR.MINOR.PATCH")
    if args.command == "build":
        build_release(args.directory, args.version)
    else:
        if not re.fullmatch(r"[0-9a-f]{40}", args.tag_object):
            parser.error("tag object must be a full object ID")
        publish(args.directory, args.version, args.repo, args.tag_object)


if __name__ == "__main__":
    main()
