#!/bin/sh
# Signs pushed container images with cosign in key-pair mode (the default image and the
# -scan image). Sign by digest, never by tag. The secret key never lives in this
# repository: pass its path in COSIGN_KEY (cosign asks for its password, or reads
# COSIGN_PASSWORD).
#
#   COSIGN_KEY=$HOME/.privasimu-release/cosign.key scripts/release/sign-image.sh \
#     registry.example.com/privasimu-bridge@sha256:<digest> \
#     registry.example.com/privasimu-bridge@sha256:<digest of the -scan image>
#
# COSIGN_TLOG=false keeps the signature out of the public Rekor transparency log (then
# verify with --insecure-ignore-tlog=true). See docs/RELEASE-SIGNING.md.
set -eu

KEY=${COSIGN_KEY:?set COSIGN_KEY to the path of the cosign secret key (kept off the repository)}
PUB=${COSIGN_PUBLIC_KEY:-release-keys/cosign.pub}
[ "$#" -ge 1 ] || { echo "usage: $0 <image@sha256:digest>..." >&2; exit 2; }

command -v cosign >/dev/null 2>&1 || { echo "cosign is not installed (https://docs.sigstore.dev/cosign/system_config/installation/)" >&2; exit 1; }
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

TLOG=${COSIGN_TLOG:-true}
for ref in "$@"; do
	case "$ref" in
	*@sha256:*) ;;
	*)
		echo "sign by digest (name@sha256:...), not by tag: $ref" >&2
		exit 2
		;;
	esac
	cosign sign --yes --key "$KEY" --tlog-upload="$TLOG" "$ref"
	if [ "$TLOG" = false ]; then
		cosign verify --key "$PUB" --insecure-ignore-tlog=true "$ref" >/dev/null
	else
		cosign verify --key "$PUB" "$ref" >/dev/null
	fi
	echo "signed and verified $ref"
done
