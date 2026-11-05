package dht

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/vx6/vx6/internal/identity"
)

func TestNodeNameKeyUsesCanonicalDomainSeparatedFullHash(t *testing.T) {
	upper := NodeNameKey("ALPHA-42")
	lower := NodeNameKey("alpha-42")
	if upper != lower {
		t.Fatalf("case variants produced different lookup keys: %q != %q", upper, lower)
	}
	if strings.Contains(upper, "ALPHA") {
		t.Fatalf("lookup key exposes the plaintext name: %q", upper)
	}

	want := sha256.Sum256([]byte("vx6/node-name/v1\x00ALPHA-42"))
	if upper != "node/name/"+hex.EncodeToString(want[:]) {
		t.Fatalf("lookup key = %q, want full SHA-256 name key", upper)
	}
	if NodeNameHash("alpha-42") != hex.EncodeToString(want[:]) {
		t.Fatalf("cached name hash = %q, want bare full SHA-256 digest", NodeNameHash("alpha-42"))
	}
	if got := routingIDBytes(upper); hex.EncodeToString(got) != hex.EncodeToString(want[:]) {
		t.Fatalf("routing target does not use the name digest: %x", got)
	}
}

func TestInvalidNodeNameDoesNotProduceLookupCoordinate(t *testing.T) {
	for _, name := range []string{"", "A", "not valid", "-BAD", "BAD-"} {
		if got := NodeNameHash(name); got != "" {
			t.Errorf("NodeNameHash(%q) = %q, want empty for invalid name", name, got)
		}
		if got := NodeNameKey(name); got != "node/name/" {
			t.Errorf("NodeNameKey(%q) = %q, want an invalid key rejected by request validation", name, got)
		}
	}
}

func TestPublicKeyLookupKeyMatchesFullNodeIDHashAndDiffersFromNameKey(t *testing.T) {
	id, err := identity.Generate()
	if err != nil {
		t.Fatal(err)
	}
	byKey, err := NodePublicKeyKey(id.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if byKey != NodeIDKey(id.NodeID) {
		t.Fatalf("public-key lookup key %q != NodeID lookup key %q", byKey, NodeIDKey(id.NodeID))
	}
	if byKey == NodeNameKey("ALPHA") {
		t.Fatal("identity and canonical-name lookup keys unexpectedly collide")
	}
	if _, err := NodePublicKeyKey(make([]byte, ed25519.PublicKeySize-1)); err == nil {
		t.Fatal("accepted a truncated public key")
	}
}
