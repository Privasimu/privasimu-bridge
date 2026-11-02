# Signed releases

Every Privasimu Bridge release is signed, so a client can check that a binary or image
comes from Privasimu and was not changed on the way (owner decision Q9, 2 November 2026):

| What | How | Signature | Public key in this repository |
|---|---|---|---|
| Binaries (`privasimu-bridge-<version>-<os>-<arch>[.exe]`) | `SHA256SUMS` lists their SHA-256; `SHA256SUMS` is signed with **minisign** (Ed25519) | `SHA256SUMS.sig` | [`release-keys/minisign.pub`](../release-keys/minisign.pub) |
| Container images (`privasimu-bridge:<version>` and `privasimu-bridge:<version>-scan`) | **cosign** in key-pair mode, by image digest | stored in the registry next to the image (and in the Rekor transparency log unless disabled) | [`release-keys/cosign.pub`](../release-keys/cosign.pub) |

**Status: the keys have not been generated yet.** Both files in `release-keys/` are
placeholders that say so; `scripts/release/*.sh` refuse to sign or verify with them, and
`internal/buildinfo/releasekeys_test.go` accepts in `release-keys/` only the placeholders or
real public keys. No secret key is, or may ever be, in this repository: the same test fails
when a minisign or cosign secret key appears anywhere in the working tree, and `.gitignore`
ignores `*.key`.

## 1. One-time setup by the owner

Do this on a trusted workstation (ideally offline), not on a build server or in CI.

### 1.1 minisign key (binaries)

Install minisign 0.11 or later (<https://jedisct1.github.io/minisign/>), then:

```sh
mkdir -p ~/.privasimu-release && chmod 700 ~/.privasimu-release
minisign -G -p release-keys/minisign.pub -s ~/.privasimu-release/minisign.key
```

- minisign asks for a password: use a long, unique one and keep it in the owner's password
  manager. Never use `-W` (a key without a password).
- `-p` overwrites the placeholder `release-keys/minisign.pub` with the real public key (two
  lines: `untrusted comment: minisign public key <KEY ID>` and the base64 key).
- `~/.privasimu-release/minisign.key` is the secret key: keep it out of every repository,
  back it up encrypted in two places (for example the password manager's file vault and an
  encrypted USB key in a safe).

### 1.2 cosign key pair (images)

Install cosign 2.x (<https://docs.sigstore.dev/cosign/system_config/installation/>), then:

```sh
cd ~/.privasimu-release
cosign generate-key-pair            # asks for a password; writes cosign.key and cosign.pub
cp cosign.pub /path/to/privasimu-bridge/release-keys/cosign.pub
```

`cosign.key` is encrypted with the password; store and back it up like the minisign key.
A cloud KMS key works too (`cosign generate-key-pair --kms <uri>`); then `COSIGN_KEY` is the
KMS URI and no key file exists.

### 1.3 Publish the public keys

1. Commit the two public keys (only `release-keys/minisign.pub` and
   `release-keys/cosign.pub`) on a branch and merge it through a pull request.
2. Replace the placeholder text in the "Verify the download" parts of `README.md`,
   `docs/INSTALL.en.md` and `docs/INSTALL.id.md` with the minisign public key line (the
   base64 line) and its key id, so users can compare what they downloaded with what the
   documentation says.
3. Publish both public keys a second way that does not depend on this repository (for
   example the Privasimu website or every release's notes), so a client can cross-check.

## 2. Each release

```sh
# Binaries and SHA256SUMS; with the key set, dist also writes SHA256SUMS.sig.
make dist VERSION=0.3.0 MINISIGN_SECRET_KEY=$HOME/.privasimu-release/minisign.key
make verify-release                 # what users run: signature, then checksums

# Images: build, push, then sign by digest (never by tag).
make image image-scan VERSION=0.3.0 IMAGE=registry.example.com/privasimu-bridge
docker push registry.example.com/privasimu-bridge:0.3.0
docker push registry.example.com/privasimu-bridge:0.3.0-scan
COSIGN_KEY=$HOME/.privasimu-release/cosign.key scripts/release/sign-image.sh \
  registry.example.com/privasimu-bridge@sha256:<digest> \
  registry.example.com/privasimu-bridge@sha256:<digest of -scan>
```

Upload the binaries, `SHA256SUMS` and `SHA256SUMS.sig` to the release. `sign.sh` and
`sign-image.sh` verify each signature with the public key in `release-keys/` right after
signing, so a mismatch between the secret key used and the published public key is caught
before anything is published. `COSIGN_TLOG=false` keeps an image signature out of the
public Rekor log (users then add `--insecure-ignore-tlog=true` when verifying).

The `-scan` image pins Syft and Grype by version and by the SHA-256 of their release
archives (`Dockerfile.scan`); updating a tool means updating its version and checksums
together from the tool's official `checksums.txt`.

## 3. Verification (users)

Binaries (Linux, macOS; Windows with `minisign.exe` and `Get-FileHash`):

```sh
minisign -Vm SHA256SUMS -x SHA256SUMS.sig -p minisign.pub
sha256sum -c SHA256SUMS --ignore-missing
```

or `scripts/release/verify.sh <download folder>`. Images:

```sh
cosign verify --key cosign.pub registry.example.com/privasimu-bridge:0.3.0-scan
```

A verification failure means: do not install, and tell Privasimu.

## 4. Rotation and compromise

- **Planned rotation** (for example every two years, or a new owner): generate new keys as
  in section 1, sign the next release with the new keys, and publish the new public keys
  with a note in the release; keep the old public key documented for older releases.
- **Lost password or key**: generate new keys; there is no recovery.
- **Suspected compromise**: stop releasing, generate new keys, publish a notice listing the
  affected versions, re-sign the current release with the new keys, and remove the old
  public keys from the documentation.
