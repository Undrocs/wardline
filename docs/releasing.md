# Releasing

Wardline has not published a release yet. This page documents the process the
release workflow implements, so that the first release is not improvised and so
that reviewers can see what is enforced in code.

**Nothing here authorises publishing.** Cutting a tag and publishing a release
are owner decisions; the workflow only makes them safe to perform.

## Preconditions (repository settings)

These are configured once, in GitHub settings. The workflow refuses to publish
until they hold:

1. **Tag protection for `v*`.** A protected tag cannot be moved or deleted, which
   is what makes the commit a release points at meaningful after publication.
   Protection rules are readable only with repository admin permission, so the
   workflow needs a token in the `TAG_PROTECTION_TOKEN` secret (or the
   `REQUIRE_PROTECTED_TAGS` repository variable set to `false`, which only makes
   sense if equivalent protection is enforced elsewhere).
2. **A `release` environment with required reviewers.** The `publish` job targets
   that environment, so publication waits for a human approval.
3. **Required status checks on `main`** (build, test, vet, race, fuzz smoke), so
   the commit a tag points at has passed CI.

## Cutting a release

```sh
git switch main
git pull --ff-only
git tag -a v0.1.0 -m "Wardline 0.1.0"
git push origin v0.1.0
```

The tag push starts `.github/workflows/release.yml`.

## What the workflow does

1. **Validates the tag** (`prepare` job). The tag must match
   `vMAJOR.MINOR.PATCH` (with optional pre-release/build suffix), the requested
   tag is checked out explicitly (on a manual run), and the checked-out commit is
   compared with the commit the tag points at. A release binary that was built
   from a different commit than the tag is impossible to verify later, so this is
   a hard failure.
2. **Requires tag protection.** The tag must match a configured protection rule.
3. **Builds and verifies each platform** (Linux, macOS, Windows on amd64 and
   arm64) with `scripts/build-release-archive.sh` and
   `scripts/verify-release-archive.sh`. Archives for the runner's own platform
   are executed and must report the released version.
4. **Verifies every archive again** in the publish job, checks that all six
   platforms are present, assembles `SHA256SUMS` and checks it.
5. **Publishes** only if no release with that tag exists. Existing assets are
   never replaced: `gh release upload --clobber` was removed because replacing a
   binary under an existing tag invalidates every checksum users already have.
   Publishing a fix means cutting a new tag.

## Archive layout

```
wardline_<version>_<goos>_<goarch>/
  wardline            # wardline.exe on Windows
  LICENSE
  THIRD-PARTY-NOTICES.md
  README.md
  CHANGELOG.md
```

Archives are reproducible: `-trimpath`, no `CGO`, fixed archive mtime and
ownership, sorted entries. `version`, `commit` and build date are injected with
`-ldflags`; the build date is the only non-reproducible field.

## Verifying a download

```sh
sha256sum --check SHA256SUMS
tar -xzf wardline_<version>_linux_amd64.tar.gz
./wardline_<version>_linux_amd64/wardline version   # must print the released version
```

## Doing it locally

```sh
scripts/build-release-archive.sh v0.0.0-local linux amd64 /tmp/out
scripts/verify-release-archive.sh /tmp/out/wardline_0.0.0-local_linux_amd64.tar.gz linux amd64 --run
scripts/release-smoke.sh     # includes the failure cases
```

`--run` only executes an archive that matches the host platform; for any other
platform it prints a skip and verifies the contents only.

## Not done by the workflow

- No release is created by a pull request, a branch push or a schedule.
- No binary, archive or checksum is committed to the repository.
- No third-party release action is used, and every action is pinned to a full
  commit SHA.
