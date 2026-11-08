package serviceproxy

import (
	"testing"
	"time"
)

func TestServiceAdmissionBoundsActiveSessionsAndRateState(t *testing.T) {
	tracker := NewSessionTracker()
	var releases []func()
	for i := 0; i < maxServiceSessionsPerPeer; i++ {
		release, err := tracker.admit("peer-a", time.Unix(1_800_000_000, 0))
		if err != nil {
			t.Fatalf("admitted session %d: %v", i+1, err)
		}
		releases = append(releases, release)
	}
	if _, err := tracker.admit("peer-a", time.Unix(1_800_000_000, 0)); err == nil {
		t.Fatal("accepted session above the per-peer concurrency limit")
	}
	if _, err := tracker.admit("peer-b", time.Unix(1_800_000_000, 0)); err != nil {
		t.Fatalf("peer-a limit affected peer-b: %v", err)
	}
	for _, release := range releases {
		release()
	}
	if _, err := tracker.admit("peer-a", time.Unix(1_800_000_000, 0)); err != nil {
		t.Fatalf("released slot was not reusable: %v", err)
	}
}
