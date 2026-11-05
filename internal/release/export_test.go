// Copyright (c) 2026 Suryansh Deshwal
// Licensed under the Apache License, Version 2.0

package release

import "testing"

// signerSeedForTest exposes the in-memory private seed so a test can assert it
// never appears in the serialized key file. Test-only.
func signerSeedForTest(t *testing.T, s *Signer) []byte {
	t.Helper()
	return s.priv.Seed()
}
