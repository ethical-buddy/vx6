package dht

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
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
	if got := routingIDBytes(upper); hex.EncodeToString(got) != hex.EncodeToString(want[:]) {
		t.Fatalf("routing target does not use the name digest: %x", got)
	}
}
