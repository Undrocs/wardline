#!/bin/sh
# Build one release archive for a single platform.
#
# Usage: scripts/build-release-archive.sh <tag> <goos> <goarch> <output-dir>
#
# The archive layout is fixed and verified by scripts/verify-release-archive.sh:
#
#   wardline_<version>_<goos>_<goarch>/
#     wardline            (or wardline.exe on Windows)
#     LICENSE
#     THIRD-PARTY-NOTICES.md
#     README.md
#     CHANGELOG.md
#
# Requirements for reproducibility: -trimpath, no build cache paths in the
# binary, a fixed archive mtime/owner and sorted entries.
#
# The tag is validated before it is used to build a path: an operator-supplied
# value must never be able to escape the output directory or produce a
# misleading asset name.
set -eu

tag=${1:-}
goos=${2:-}
goarch=${3:-}
outdir=${4:-dist}

case "$tag" in
v[0-9]*.[0-9]*.[0-9]*) ;;
*)
	echo "invalid tag: '$tag' (expected vMAJOR.MINOR.PATCH)" >&2
	exit 2
	;;
esac
# Only characters that are safe in a filename, and no path separators.
if printf '%s' "$tag" | grep -q '[^A-Za-z0-9._+-]'; then
	echo "invalid tag: '$tag' contains unsafe characters" >&2
	exit 2
fi
version=${tag#v}
case "$version" in
'' | */* | *..*)
	echo "invalid version derived from tag: '$version'" >&2
	exit 2
	;;
esac
case "$goos" in
linux | darwin | windows) ;;
*)
	echo "unsupported GOOS: '$goos'" >&2
	exit 2
	;;
esac
case "$goarch" in
amd64 | arm64) ;;
*)
	echo "unsupported GOARCH: '$goarch'" >&2
	exit 2
	;;
esac

cd "$(dirname "$0")/.."

commit=$(git rev-parse HEAD)
build_date=$(date -u +%Y-%m-%dT%H:%M:%SZ)
name="wardline_${version}_${goos}_${goarch}"

# Windows binaries must carry the .exe suffix: the file name is what makes the
# download executable on that platform.
binary=wardline
if [ "$goos" = windows ]; then
	binary=wardline.exe
fi

mkdir -p "$outdir/$name"
CGO_ENABLED=0 GOOS="$goos" GOARCH="$goarch" go build -trimpath \
	-ldflags "-s -w \
		-X github.com/Undrocs/wardline/internal/version.Version=${version} \
		-X github.com/Undrocs/wardline/internal/version.Commit=${commit} \
		-X github.com/Undrocs/wardline/internal/version.BuildDate=${build_date}" \
	-o "$outdir/$name/$binary" ./cmd/wardline

cp LICENSE THIRD-PARTY-NOTICES.md README.md CHANGELOG.md "$outdir/$name/"

# Reproducible archive: fixed mtime/owner and sorted entries.
if [ "$goos" = windows ]; then
	archive="$outdir/${name}.zip"
	rm -f "$archive"
	(cd "$outdir" && zip -qr9X "${name}.zip" "$name")
else
	archive="$outdir/${name}.tar.gz"
	rm -f "$archive"
	(cd "$outdir" && tar --sort=name --owner=0 --group=0 --numeric-owner \
		--mtime='UTC 2026-01-01' -czf "${name}.tar.gz" "$name")
fi

(cd "$outdir" && sha256sum "${name}.$( [ "$goos" = windows ] && echo zip || echo tar.gz )" > "${name}.sha256")

echo "$archive"
