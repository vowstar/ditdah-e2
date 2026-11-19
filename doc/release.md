# Release RTL

The [release workflow](../.github/workflows/release.yml) packages the default core and the local SRAM platform.
The platform archive includes behavioral SRAM models.
Each archive includes a Verilog file list, source and RTL hashes, and the MIT license.

## Preflight

Run `nix develop . -c make verify-compliance` and review the verification records for the release commit.
Dispatch the release workflow on `main` with `gh workflow run release.yml --ref main`.
The manual run checks licensing and builds and lints both archives.
A successful run also stores the pinned toolchain in the Actions cache on `main`.
Use `gh run view RUN_ID --json headSha --jq .headSha` to identify the tested commit.
Use `gh run download RUN_ID -n rtl-release` to inspect the archives.

## Publish a version

Set `commit` to the tested commit and `version` to a tag in `vMAJOR.MINOR.PATCH` form.
Sign the tag with the maintainer's registered release key.

```sh
git tag -s "$version" "$commit" -m "DitDah-E2 $version"
git verify-tag "$version"
git push --no-follow-tags origin "refs/tags/$version"
```

The publish job creates a draft and uploads the two archives and `SHA256SUMS`.
It checks all three uploaded digests before it publishes the draft.
Use `gh run watch` to follow the release run.

For a transient publication failure, rerun the failed job with `gh run rerun RUN_ID --failed`.
If GitHub just created the draft, wait for it to appear before retrying.
The job keeps matching files and uploads missing files. Remove incomplete or mismatched files from the draft before retrying.
If the Actions artifact has expired after seven days, rerun all jobs with `gh run rerun RUN_ID`.
Reruns use the original commit. Test workflow fixes before tagging a new version.

Download both archives and `SHA256SUMS` into one directory.
Run `sha256sum -c SHA256SUMS` there to check the downloads.
