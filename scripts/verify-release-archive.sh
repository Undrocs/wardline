#!/bin/sh
# Verify a release archive before it is published.
#
# Usage: scripts/verify-release-archive.sh <archive> <goos> <goarch> [--run]
#
# Checks, in order:
#   1. the archive filename matches wardline_<version>_<goos>_<goarch>.<ext>;
#   2. the archive contains exactly one top-level directory with that name;
#   3. the expected files are present (binary, LICENSE, notices, README,
#      CHANGELOG) and nothing unexpected was added;
#   4. the binary is named wardline on Unix and wardline.exe on Windows;
#   5. with --run, the binary executes and reports the expected version. This
#      is only valid when the archive matches the host platform.
set -eu

archive=${1:-}
goos=${2:-}
goarch=${3:-}
run=false
if [ "${4:-}" = "--run" ]; then
	run=true
fi

if [ -z "$archive" ] || [ ! -f "$archive" ]; then
	echo "usage: $0 <archive> <goos> <goarch> [--run]" >&2
	exit 2
fi

base=$(basename "$archive")
case "$base" in
*.tar.gz) ext=tar.gz ;;
*.zip) ext=zip ;;
*)
	echo "unsupported archive extension: $base" >&2
	exit 1
	;;
esac

stem=${base%."$ext"}
case "$stem" in
wardline_*_"$goos"_"$goarch") ;;
*)
	echo "archive name '$base' does not describe $goos/$goarch" >&2
	exit 1
	;;
esac
version=$(printf '%s' "$stem" | sed -e 's/^wardline_//' -e "s/_${goos}_${goarch}\$//")
if ! printf '%s' "$version" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+([-+][A-Za-z0-9.+-]+)?$'; then
	echo "archive name '$base' carries an unexpected version '$version'" >&2
	exit 1
fi

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

case "$ext" in
tar.gz) tar -xzf "$archive" -C "$tmp" ;;
zip) unzip -qq "$archive" -d "$tmp" ;;
esac

entries=$(ls -A "$tmp")
if [ "$(printf '%s\n' "$entries" | wc -l)" -ne 1 ]; then
	echo "archive must contain exactly one top-level directory, found: $entries" >&2
	exit 1
fi
if [ "$entries" != "$stem" ]; then
	echo "top-level directory '$entries' does not match archive name '$stem'" >&2
	exit 1
fi

root="$tmp/$entries"
binary=wardline
if [ "$goos" = windows ]; then
	binary=wardline.exe
fi

for want in "$binary" LICENSE THIRD-PARTY-NOTICES.md README.md CHANGELOG.md; do
	if [ ! -f "$root/$want" ]; then
		echo "archive is missing $want" >&2
		exit 1
	fi
done

unexpected=$(cd "$root" && find . -mindepth 1 -maxdepth 1 ! -name "$binary" ! -name LICENSE \
	! -name THIRD-PARTY-NOTICES.md ! -name README.md ! -name CHANGELOG.md -print)
if [ -n "$unexpected" ]; then
	echo "archive contains unexpected entries: $unexpected" >&2
	exit 1
fi

if [ -e "$root/wardline" ] && [ -e "$root/wardline.exe" ]; then
	echo "archive contains both wardline and wardline.exe" >&2
	exit 1
fi
if [ "$goos" = windows ] && [ -e "$root/wardline" ]; then
	echo "Windows archive must not contain an extension-less binary" >&2
	exit 1
fi
if [ "$goos" != windows ] && [ -e "$root/wardline.exe" ]; then
	echo "Unix archive must not contain wardline.exe" >&2
	exit 1
fi

if [ "$run" = true ]; then
	case "$(uname -s)" in
	Linux) host_os=linux ;;
	Darwin) host_os=darwin ;;
	*) host_os=unknown ;;
	esac
	case "$(uname -m)" in
	x86_64 | amd64) host_arch=amd64 ;;
	arm64 | aarch64) host_arch=arm64 ;;
	*) host_arch=unknown ;;
	esac
	if [ "$host_os" != "$goos" ] || [ "$host_arch" != "$goarch" ]; then
		echo "skip: cannot execute $goos/$goarch on $host_os/$host_arch" >&2
	else
		out=$("$root/$binary" version)
		case "$out" in
		*"$version"*) ;;
		*)
			echo "binary reports '$out', expected version $version" >&2
			exit 1
			;;
		esac
	fi
fi

echo "ok: $base (wardline $version, $goos/$goarch)"
