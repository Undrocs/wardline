#!/bin/sh
# Exercise the release packaging scripts end to end.
#
# Usage: scripts/release-smoke.sh
#
# Builds a Linux and a Windows archive from the current tree, verifies both, and
# checks that the verifier rejects the failures it exists to catch (a Windows
# archive without wardline.exe, a missing file, an archive whose name does not
# match its platform). No network access and nothing is published.
set -eu

cd "$(dirname "$0")/.."

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

tag=v0.0.0-smoke

echo "== build linux/amd64 (executable)"
linux=$(./scripts/build-release-archive.sh "$tag" linux amd64 "$tmp/dist")
./scripts/verify-release-archive.sh "$linux" linux amd64 --run

echo "== build windows/amd64 (packaging only)"
win=$(./scripts/build-release-archive.sh "$tag" windows amd64 "$tmp/dist")
./scripts/verify-release-archive.sh "$win" windows amd64

echo "== reject a Windows archive without wardline.exe"
mkdir -p "$tmp/broken/wardline_0.0.0-smoke_windows_amd64"
echo "not a binary" >"$tmp/broken/wardline_0.0.0-smoke_windows_amd64/wardline"
for f in LICENSE THIRD-PARTY-NOTICES.md README.md CHANGELOG.md; do
	cp "$f" "$tmp/broken/wardline_0.0.0-smoke_windows_amd64/"
done
(cd "$tmp/broken" && zip -qr9X wardline_0.0.0-smoke_windows_amd64.zip wardline_0.0.0-smoke_windows_amd64)
if ./scripts/verify-release-archive.sh "$tmp/broken/wardline_0.0.0-smoke_windows_amd64.zip" windows amd64 2>"$tmp/err"; then
	echo "FAIL: a Windows archive without wardline.exe was accepted" >&2
	exit 1
else
	echo "ok: rejected ($(head -n1 "$tmp/err"))"
fi

echo "== reject a Unix archive with a missing file"
mkdir -p "$tmp/missing/wardline_0.0.0-smoke_linux_amd64"
cp "$tmp/dist/wardline_0.0.0-smoke_linux_amd64/wardline" "$tmp/missing/wardline_0.0.0-smoke_linux_amd64/"
for f in LICENSE README.md CHANGELOG.md; do
	cp "$f" "$tmp/missing/wardline_0.0.0-smoke_linux_amd64/"
done
(cd "$tmp/missing" && tar -czf wardline_0.0.0-smoke_linux_amd64.tar.gz wardline_0.0.0-smoke_linux_amd64)
if ./scripts/verify-release-archive.sh "$tmp/missing/wardline_0.0.0-smoke_linux_amd64.tar.gz" linux amd64 2>"$tmp/err"; then
	echo "FAIL: an archive missing THIRD-PARTY-NOTICES.md was accepted" >&2
	exit 1
else
	echo "ok: rejected ($(head -n1 "$tmp/err"))"
fi

echo "== reject an archive whose name lies about the platform"
if ./scripts/verify-release-archive.sh "$linux" windows amd64 2>"$tmp/err"; then
	echo "FAIL: archive name was not checked against the platform" >&2
	exit 1
else
	echo "ok: rejected ($(head -n1 "$tmp/err"))"
fi

echo "== reject an unsafe tag"
if ./scripts/build-release-archive.sh 'v1.0.0/../../etc' linux amd64 "$tmp/dist" 2>"$tmp/err"; then
	echo "FAIL: an unsafe tag was accepted" >&2
	exit 1
else
	echo "ok: rejected ($(head -n1 "$tmp/err"))"
fi

echo "all release packaging checks passed"
