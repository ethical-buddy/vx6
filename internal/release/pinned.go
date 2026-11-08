// Copyright (c) 2026 Suryansh Deshwal
// Licensed under the VX6 terms in LICENSE-COMMERCIAL.md.
// Sole inventor, maintainer, and rights holder: Suryansh Deshwal (https://github.com/ethical-buddy).

package release

import (
	"encoding/json"
	"fmt"
)

// pinnedTrustRootJSON is the release trust root compiled into the binary. It
// holds only PUBLIC root keys and the signing threshold — never a secret.
//
// It is intentionally EMPTY in-tree: the VX6 project has not yet provisioned
// production release keys, and pinning placeholder keys would be worse than
// pinning none (it would imply a trust anchor that does not exist). The release
// process fills this in at tag time from the offline root keys, e.g.:
//
//	vx6-release pin-root --out internal/release/pinned.go \
//	    --threshold 2 --key root1.pub --key root2.pub --key root3.pub
//
// Until it is populated, PinnedTrustRoot returns ErrNoPinnedRoot and the client
// treats automatic updates as unconfigured (manual, operator-driven install
// only). That is the correct fail-closed default: no keys, no auto-update,
// rather than a fake anchor.
var pinnedTrustRootJSON = ``

// ErrNoPinnedRoot indicates the build shipped without provisioned release keys.
var ErrNoPinnedRoot = fmt.Errorf("no release trust root is pinned in this build; automatic updates are disabled")

// PinnedTrustRoot returns the compiled-in trust root, or ErrNoPinnedRoot.
func PinnedTrustRoot() (TrustRoot, error) {
	if pinnedTrustRootJSON == "" {
		return TrustRoot{}, ErrNoPinnedRoot
	}
	var r TrustRoot
	if err := json.Unmarshal([]byte(pinnedTrustRootJSON), &r); err != nil {
		return TrustRoot{}, fmt.Errorf("corrupt pinned trust root: %w", err)
	}
	if err := r.validateShape(); err != nil {
		return TrustRoot{}, fmt.Errorf("invalid pinned trust root: %w", err)
	}
	return r, nil
}
