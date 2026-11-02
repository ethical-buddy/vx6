package sdk

import (
	"context"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vx6/vx6/internal/runtimectl"
)

func TestObserveStatus(t *testing.T) {
	root := t.TempDir()
	cfgPath := filepath.Join(root, "config.json")
	client, err := New(cfgPath)
	if err != nil {
		t.Fatalf("new sdk client: %v", err)
	}
	controlPath, err := filepath.Abs(filepath.Join(root, "node.control.json"))
	if err != nil {
		t.Fatalf("abs control path: %v", err)
	}
	server, err := runtimectl.Start(controlPath, 1234, nil, func() runtimectl.Status {
		return runtimectl.Status{NodeName: "TEST", RegistryNodes: 3}
	})
	if err != nil {
		t.Fatalf("start runtime control: %v", err)
	}
	defer server.Close()

	var seen int32
	ctx, cancel := context.WithTimeout(context.Background(), 1200*time.Millisecond)
	defer cancel()
	err = client.ObserveStatus(ctx, StatusObserverOptions{
		Interval: 200 * time.Millisecond,
		OnStatus: func(s runtimectl.Status) {
			if s.NodeName == "TEST" {
				atomic.AddInt32(&seen, 1)
				cancel()
			}
		},
	})
	if err == nil {
		t.Fatal("expected context cancellation")
	}
	if atomic.LoadInt32(&seen) == 0 {
		t.Fatal("expected at least one status callback")
	}
}
