#!/bin/sh
# Verifies a downloaded release: the minisign signature of SHA256SUMS, then the checksum of
# every release file present in the directory.
#
#   scripts/release/verify.sh [directory] [minisign.pub]
#
# Run it in the folder with the downloads (default: the current one). The public key
# defaults to release-keys/minisign.pub of this repository; compare it with the key
# published in docs/INSTALL.en.md before trusting it.
set -eu

DIR=${1:-.}
PUB=${2:-$(dirname "$0")/../../release-keys/minisign.pub}

if grep -q PLACEHOLDER "$PUB"; then
	echo "$PUB is a placeholder, not a release key: releases are not signed yet" >&2
	exit 1
fi
command -v minisign >/dev/null 2>&1 || { echo "minisign is not installed (https://jedisct1.github.io/minisign/)" >&2; exit 1; }
PUB=$(cd "$(dirname "$PUB")" && pwd)/$(basename "$PUB") # absolute, before changing directory
cd "$DIR"
minisign -V -p "$PUB" -m SHA256SUMS -x SHA256SUMS.sig
if command -v sha256sum >/dev/null 2>&1; then
	sha256sum -c SHA256SUMS --ignore-missing
else
	shasum -a 256 -c SHA256SUMS --ignore-missing
fi
