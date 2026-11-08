package cli

import (
	"strings"
	"testing"
)

func TestUpdateVerifyRequiresTrustedCurrentSequence(t *testing.T) {
	err := runUpdateVerify([]string{"--manifest", "manifest.json"})
	if err == nil || !strings.Contains(err.Error(), "--current-seq is required") {
		t.Fatalf("missing trusted sequence error = %v", err)
	}
}
