// Copyright (c) 2026 Suryansh Deshwal
// Licensed under the VX6 terms in LICENSE-COMMERCIAL.md.
// Sole inventor, maintainer, and rights holder: Suryansh Deshwal (https://github.com/ethical-buddy).

package release

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/vx6/vx6/internal/strictjson"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
)

// A release signing key is a secret. It is NOT pinned in the open-source binary
// (only PUBLIC root keys are). The private half lives off the network, on the
// maintainer's machine, inside an encrypted file.
//
// On "unreversible even when open source": a private key cannot be hidden
// inside a published binary. Anyone can read the source and extract an embedded
// secret; obfuscation only delays that and gives false assurance. The property
// that actually holds under a fully open-source client is this:
//
//   - PUBLIC root keys and the threshold are pinned in the binary. Everyone can
//     read them; that is fine, they verify, they do not sign.
//   - PRIVATE signing keys never ship. They are generated offline and stored
//     here encrypted with a passphrase (argon2id -> XChaCha20-Poly1305).
//   - Forging an update needs a THRESHOLD of those private keys. Reverse-
//     engineering the client reveals nothing that helps: the secrets are not in
//     it. This is the same model as TUF, Go module sumdb, and OS package repos.
//
// So the client is safe to open-source; the signing keys' secrecy rests on the
// passphrase and on keeping them offline, not on hiding anything in the binary.

const (
	keyFileMagic   = "vx6-release-signer-key-v1"
	argonTime      = 3
	argonMemoryKiB = 256 * 1024 // 256 MiB
	argonThreads   = 4
	saltLen        = 16
)

// EncryptedSignerKey is the on-disk, passphrase-protected private signing key.
type EncryptedSignerKey struct {
	Magic   string `json:"magic"`
	KeyID   string `json:"key_id"`     // of the PUBLIC key; safe to store in clear
	Public  string `json:"public_key"` // base64; safe to store in clear
	KDF     string `json:"kdf"`        // "argon2id"
	Time    uint32 `json:"kdf_time"`
	MemKiB  uint32 `json:"kdf_mem_kib"`
	Threads uint8  `json:"kdf_threads"`
	Salt    string `json:"salt"`   // base64
	Nonce   string `json:"nonce"`  // base64 (XChaCha20 24-byte)
	Cipher  string `json:"cipher"` // base64 AEAD ciphertext of the ed25519 seed
}

// GenerateSignerKey creates a fresh Ed25519 release key and encrypts its seed
// under passphrase. The passphrase is zeroed by the caller; this function never
// logs or returns it.
func GenerateSignerKey(passphrase []byte) (*EncryptedSignerKey, ed25519.PublicKey, error) {
	if len(passphrase) < 12 {
		return nil, nil, errors.New("passphrase must be at least 12 bytes")
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	defer zero(priv)
	seed := priv.Seed() // 32 bytes; the whole secret
	enc, err := sealSeed(seed, pub, passphrase)
	for i := range seed {
		seed[i] = 0
	}
	if err != nil {
		return nil, nil, err
	}
	return enc, pub, nil
}

func sealSeed(seed []byte, pub ed25519.PublicKey, passphrase []byte) (*EncryptedSignerKey, error) {
	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	key := argon2.IDKey(passphrase, salt, argonTime, argonMemoryKiB, argonThreads, chacha20poly1305.KeySize)
	defer zero(key)
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	// Bind the ciphertext to the public key so a swapped-public-key file fails
	// to open rather than silently signing with a mismatched identity.
	ct := aead.Seal(nil, nonce, seed, []byte(KeyID(pub)))
	return &EncryptedSignerKey{
		Magic: keyFileMagic, KeyID: KeyID(pub), Public: base64.StdEncoding.EncodeToString(pub),
		KDF: "argon2id", Time: argonTime, MemKiB: argonMemoryKiB, Threads: argonThreads,
		Salt: base64.StdEncoding.EncodeToString(salt), Nonce: base64.StdEncoding.EncodeToString(nonce),
		Cipher: base64.StdEncoding.EncodeToString(ct),
	}, nil
}

// Signer is an in-memory unlocked release key. Keep its lifetime short.
type Signer struct {
	priv ed25519.PrivateKey
	pub  ed25519.PublicKey
}

// Open decrypts the signer key with passphrase. The passphrase is the only
// secret; a wrong one fails AEAD authentication.
func (e *EncryptedSignerKey) Open(passphrase []byte) (*Signer, error) {
	if e.Magic != keyFileMagic {
		return nil, errors.New("not a vx6 release signer key file")
	}
	if e.KDF != "argon2id" {
		return nil, fmt.Errorf("unsupported kdf %q", e.KDF)
	}
	if e.Time != argonTime || e.MemKiB != argonMemoryKiB || e.Threads != argonThreads {
		return nil, errors.New("unsupported Argon2 parameters")
	}
	pubRaw, err := base64.StdEncoding.DecodeString(e.Public)
	if err != nil || len(pubRaw) != ed25519.PublicKeySize {
		return nil, errors.New("bad public key in key file")
	}
	pub := ed25519.PublicKey(pubRaw)
	if KeyID(pub) != e.KeyID {
		return nil, errors.New("key file public key does not match its key id")
	}
	salt, err := base64.StdEncoding.DecodeString(e.Salt)
	if err != nil || len(salt) != saltLen {
		return nil, errors.New("bad salt")
	}
	nonce, err := base64.StdEncoding.DecodeString(e.Nonce)
	if err != nil {
		return nil, errors.New("bad nonce")
	}
	ct, err := base64.StdEncoding.DecodeString(e.Cipher)
	if err != nil {
		return nil, errors.New("bad ciphertext")
	}
	key := argon2.IDKey(passphrase, salt, e.Time, e.MemKiB, e.Threads, chacha20poly1305.KeySize)
	defer zero(key)
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}
	if len(nonce) != aead.NonceSize() {
		return nil, errors.New("bad nonce length")
	}
	seed, err := aead.Open(nil, nonce, ct, []byte(e.KeyID))
	if err != nil {
		return nil, errors.New("cannot decrypt signer key: wrong passphrase or corrupted file")
	}
	defer zero(seed)
	if len(seed) != ed25519.SeedSize {
		return nil, errors.New("decrypted seed has wrong size")
	}
	priv := ed25519.NewKeyFromSeed(seed)
	// Cross-check: derived public key must equal the stored one.
	if subtle.ConstantTimeCompare(priv.Public().(ed25519.PublicKey), pub) != 1 {
		return nil, errors.New("decrypted key does not match stored public key")
	}
	return &Signer{priv: priv, pub: pub}, nil
}

// KeyID of the signer's public key.
func (s *Signer) KeyID() string { return KeyID(s.pub) }

// PublicKey returns the signer's public key.
func (s *Signer) PublicKey() ed25519.PublicKey { return s.pub }

// RootKey returns the signer's public half as a pinnable RootKey.
func (s *Signer) RootKey() RootKey {
	return RootKey{KeyID: KeyID(s.pub), PublicKey: base64.StdEncoding.EncodeToString(s.pub)}
}

// SignManifest produces this key's detached signature over the manifest.
func (s *Signer) SignManifest(m Manifest) Signature {
	return Signature{KeyID: KeyID(s.pub), Sig: base64.StdEncoding.EncodeToString(ed25519.Sign(s.priv, manifestSigningPayload(m)))}
}

// SignTrustRoot produces this key's detached signature over a trust-root
// statement (for rotation/revocation signed by the outgoing quorum).
func (s *Signer) SignTrustRoot(r TrustRoot) Signature {
	return Signature{KeyID: KeyID(s.pub), Sig: base64.StdEncoding.EncodeToString(ed25519.Sign(s.priv, trustRootSigningPayload(r)))}
}

// Close zeroes the in-memory private key.
func (s *Signer) Close() {
	if s.priv != nil {
		zero(s.priv)
		s.priv = nil
	}
}

// Marshal/Unmarshal the encrypted key file.
func (e *EncryptedSignerKey) Marshal() ([]byte, error) { return json.MarshalIndent(e, "", "  ") }

func LoadEncryptedSignerKey(r io.Reader) (*EncryptedSignerKey, error) {
	const maxKeyFileBytes = 1 << 16
	data, err := io.ReadAll(io.LimitReader(r, maxKeyFileBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxKeyFileBytes {
		return nil, errors.New("encrypted signer key file is too large")
	}
	var e EncryptedSignerKey
	if err := strictjson.Decode(data, &e); err != nil {
		return nil, err
	}
	return &e, nil
}

func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
