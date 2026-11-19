# SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
# SPDX-License-Identifier: MIT

from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts"))
import release


class ReleaseTests(unittest.TestCase):
    def setUp(self):
        scratch = tempfile.TemporaryDirectory()
        self.addCleanup(scratch.cleanup)
        self.directory = Path(scratch.name)
        self.version = "v0.1.0"
        self.names = release.asset_names(self.version)
        for name in self.names[:-1]:
            (self.directory / name).write_text(f"Fixture for {name}\n")
        (self.directory / self.names[-1]).write_text(release.checksums(self.directory, self.names[:-1]))
        self.repo = "example/ditdah-e2"
        self.tag = "1" * 40

    def test_checksum_file_must_cover_both_expected_archives(self):
        (self.directory / "SHA256SUMS").write_text(release.checksums(self.directory, self.names[:1]))
        with self.assertRaisesRegex(ValueError, "checksums"):
            release.asset_digests(self.directory, self.version)

    def test_tag_object_must_match(self):
        with patch.object(release, "gh_json", return_value={"object": {"type": "tag", "sha": "2" * 40}}):
            with self.assertRaisesRegex(ValueError, "Remote tag differs"):
                release.require_tag(self.repo, self.version, self.tag)

    def test_resume_draft_keeps_matching_assets_and_checks_digests(self):
        expected = release.asset_digests(self.directory, self.version)
        draft = {"id": 1, "draft": True, "name": "DitDah-E2 v0.1.0", "body": ""}

        def command(args, *, check):
            if args[:3] == ["gh", "release", "create"]:
                draft["body"] = args[args.index("--notes") + 1]

        with (
            patch.object(release, "require_tag") as tag,
            patch.object(release, "find_release", side_effect=[None, None, draft, draft]),
            patch.object(release, "release_assets", side_effect=[
                {self.names[0]: expected[self.names[0]]}, expected,
                {self.names[0]: expected[self.names[0]]}, {**expected, self.names[1]: "sha256:" + "0" * 64},
            ]),
            patch.object(release.time, "sleep") as wait,
            patch.object(release, "gh_json", return_value={"draft": False, "tag_name": self.version}) as api,
            patch.object(release.subprocess, "run", side_effect=command) as run,
        ):
            release.publish(self.directory, self.version, self.repo, self.tag)
            self.assertEqual([call.args[0][2] for call in run.call_args_list], ["create", "upload"])
            upload_paths = run.call_args_list[1].args[0][6:]
            self.assertCountEqual(upload_paths, [self.directory / name for name in self.names[1:]])
            wait.assert_called_once_with(1)
            self.assertEqual(tag.call_count, 2)
            api.assert_called_once_with(
                f"repos/{self.repo}/releases/1", "--method", "PATCH",
                "-f", f"tag_name={self.version}", "-F", "draft=false",
            )
            run.reset_mock()
            api.reset_mock()
            with self.assertRaisesRegex(ValueError, "asset verification failed"):
                release.publish(self.directory, self.version, self.repo, self.tag)
            self.assertEqual([call.args[0][2] for call in run.call_args_list], ["upload"])
            api.assert_not_called()


if __name__ == "__main__":
    unittest.main()
