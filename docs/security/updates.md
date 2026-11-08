# Signed updates and release keys (#67)

VX6 lets update metadata and binaries travel over untrusted DHT peers or
mirrors, while the **installed binary**, not the sender, decides whether an
update is authorized. This follows the TUF model. The implementation is in
[`internal/release`](../../internal/release); the offline signing tool is
[`cmd/vx6-release`](../../cmd/vx6-release); the client command is `vx6 update`.

## The key question: "unreversible even when fully open source"

A private signing key **cannot** be hidden inside a published binary. Anyone can
read open-source code or disassemble a binary and extract an embedded secret;
obfuscation only delays that and gives false confidence. So VX6 does not try.

What actually holds, and is the industry-standard answer (TUF, Go module
checksum DB, Linux package repos, Sigstore), is:

- **Only PUBLIC keys ship in the binary.** `internal/release/pinned.go` holds
  the release root **public** keys and a signing **threshold**. These are safe
  to publish — they verify signatures, they cannot create them.
- **PRIVATE signing keys never ship.** They are generated offline with
  `vx6-release keygen` and stored encrypted (argon2id → XChaCha20-Poly1305).
  The key reader accepts only the KDF parameters emitted by this schema, so a
  modified key file cannot request unbounded memory or CPU before decryption.
  They live on maintainers' offline machines, ideally split across people/HSMs.
- **Forging an update needs a threshold of those private keys.** Reverse-
  engineering the open-source client reveals nothing useful: the secrets are
  not in it. The security rests on the secrecy of the offline keys and the
  passphrases, never on hiding anything in the binary.

So the client is safe to open-source completely. "Non-reverse-engineerable"
is reframed correctly as: **there is nothing secret in the client to reverse.**

## What authorizes an update

A threshold-signed **manifest** binds: schema, human version, a monotonic
**sequence**, issue/expiry timestamps, and for each platform an artifact's
exact **size** and **SHA-256**. Verification (`Verifier.VerifyManifest`):

1. parse + shape-check untrusted bytes (bounded size, known schema, valid
   platform tokens, hex hashes);
2. require a **threshold** of valid, distinct, non-revoked **root** signatures
   over a canonical payload (duplicates and unknown keys do not count);
3. reject if **expired** (freeze / stale-metadata guard);
4. reject if the sequence is **not strictly greater** than the running build
   (rollback guard);
5. require an artifact entry for this platform.

`VerifyArtifact` then streams the downloaded bytes and checks them against the
signed size and hash (constant-time), rejecting truncated, oversized or
tampered files. A peer's version/NodeID claims are never consulted.

## Staging, activation, rollback

`Installer` (in the privileged node service, not the user CLI):

- writes verified bytes to a **non-executable** staging file (never runs a
  partial download);
- re-verifies, copies the current build aside, moves the staged file to
  `versions/<seq>` (0755), and repoints a `current` symlink **atomically**;
- keeps the previous build and **rolls back** on a failed post-activation
  health check;
- leaves privileged placement (replacing a root-owned path, restarting the
  unit) to the OS/service manager, as #67 requires.

Installer state is placed in a private directory (mode 0700). It rejects
symlinked state directories, creates stage/version files exclusively, and
allows rollback targets only from its own version store. This is a local state
directory requirement, not a substitute for the not-yet-implemented service
manager integration.

## Key rotation and revocation

Trust moves forward only. A `SignedTrustRoot` names a new key set, threshold
and revoked key IDs, with a strictly greater **epoch**, signed by a threshold
of the **outgoing** keys. `Verifier.AdvanceTrust` applies it; an epoch that does
not advance is refused (rollback guard). A compromised key is revoked by
rotating to a root that lists it in `revoked`; it then no longer counts toward
any threshold.

## Offline signing workflow

```sh
# one-time, on each offline signer machine (passphrase via prompt or
# VX6_RELEASE_PASSPHRASE; never a flag):
vx6-release keygen -out root1.key.json

# pin the public roots into the client at release time (generated, not hand-edited):
vx6-release pin-root -threshold 2 \
  -key root1.key.json -key root2.key.json -key root3.key.json \
  -out internal/release/pinned.go

# per release: build artifacts, write manifest.json (size+sha256 per platform),
# then collect a threshold of signatures, each on a different offline machine:
vx6-release sign-manifest -key root1.key.json -in manifest.json
vx6-release sign-manifest -key root2.key.json -in manifest.json

# anyone can dry-run verify without secrets:
vx6-release verify -root root.json -manifest manifest.json -seq <trusted-running-sequence> -os linux -arch amd64
```

The sequence argument is required: rollback checking is meaningful only when
compared to a trusted sequence for the currently installed build. The present
CLI is a verification tool; it does not yet read that sequence from an
installed binary or persist accepted update state.

## Current status

`internal/release/pinned.go` ships **empty on purpose**: the project has not
provisioned production release keys, and pinning placeholder keys would assert
a trust anchor that does not exist. With no pinned root, `vx6 update` reports
auto-updates **disabled** and installs nothing automatically — the correct
fail-closed default. Populate it with `vx6-release pin-root` when real offline
keys exist. Distribution/fetch over the DHT and the service-manager install
hooks are the remaining integration work tracked under #67.

## Tests

`internal/release` covers: valid release; below-threshold; duplicate signature;
wrong/non-root key; tampered hash; truncated and oversized artifact; expired
(frozen) metadata; rollback and freeze by sequence; wrong platform; key
rotation and revocation; wrong passphrase; that the private seed never appears
in the key file; and stage → activate → failed-health-check rollback with a
non-executable staging file.
