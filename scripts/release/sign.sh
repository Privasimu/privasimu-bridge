#!/bin/sh
# Signs the release checksums: dist/SHA256SUMS -> dist/SHA256SUMS.sig (minisign, Ed25519).
# The secret key never lives in this repository; pass its path in MINISIGN_SECRET_KEY.
# minisign asks for the key's password on the terminal.
#
#   MINISIGN_SECRET_KEY=$HOME/.privasimu-release/minisign.key VERSION=0.3.0 scripts/release/sign.sh
#
# See docs/RELEASE-SIGNING.md.
set -eu

DIST=${DIST:-dist}
VERSION=${VERSION:?set VERSION, for example VERSION=0.3.0}
KEY=${MINISIGN_SECRET_KEY:?set MINISIGN_SECRET_KEY to the path of the minisign secret key (kept off the repository)}
PUB=${MINISIGN_PUBLIC_KEY:-release-keys/minisign.pub}

command -v minisign >/dev/null 2>&1 || { echo "minisign is not installed (https://jedisct1.github.io/minisign/)" >&2; exit 1; }
[ -f "$DIST/SHA256SUMS" ] || { echo "$DIST/SHA256SUMS is missing: run make dist first" >&2; exit 1; }
if grep -q PLACEHOLDER "$PUB"; then
	echo "$PUB is still the placeholder: generate the release keys first (docs/RELEASE-SIGNING.md)" >&2
	exit 1
fi
case "$KEY" in
*/release-keys/* | release-keys/*)
	echo "refusing a secret key inside the repository ($KEY)" >&2
	exit 1
	;;
esac

rm -f "$DIST/SHA256SUMS.sig"
minisign -S -s "$KEY" -m "$DIST/SHA256SUMS" -x "$DIST/SHA256SUMS.sig" \
	-t "privasimu-bridge $VERSION SHA256SUMS"
# Check the signature against the public key in the repository before publishing.
minisign -V -p "$PUB" -m "$DIST/SHA256SUMS" -x "$DIST/SHA256SUMS.sig"
echo "signed $DIST/SHA256SUMS -> $DIST/SHA256SUMS.sig"
