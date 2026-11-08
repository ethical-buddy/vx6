package runtimectl

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/vx6/vx6/internal/proto"
)

func TestServerStatusAndReload(t *testing.T) {
	t.Parallel()

	infoPath := filepath.Join(t.TempDir(), "node.control.json")
	reloads := 0
	server, err := Start(infoPath, 4242, func() error {
		reloads++
		return nil
	}, func() Status {
		return Status{
			NodeName:                        "alpha",
			EndpointPublish:                 "published",
			TransportConfig:                 "auto",
			TransportActive:                 "tcp",
			RelayMode:                       "on",
			RelayPercent:                    33,
			RegistryNodes:                   7,
			RegistryServices:                3,
			DHTTrackedKeys:                  5,
			DHTHealthyKeys:                  4,
			DHTDegradedKeys:                 1,
			HiddenDescriptorKeys:            2,
			HiddenDescriptorHealthy:         2,
			DHTRefreshIntervalSeconds:       10,
			HiddenDescriptorRotationSeconds: 3600,
			HiddenDescriptorOverlapKeys:     2,
		}
	})
	if err != nil {
		t.Fatalf("start runtime control: %v", err)
	}
	defer server.Close()

	status, err := RequestStatus(context.Background(), infoPath)
	if err != nil {
		t.Fatalf("request status: %v", err)
	}
	if status.NodeName != "alpha" {
		t.Fatalf("unexpected node name %q", status.NodeName)
	}
	if status.EndpointPublish != "published" {
		t.Fatalf("unexpected endpoint publish mode %q", status.EndpointPublish)
	}
	if status.RegistryNodes != 7 || status.RegistryServices != 3 {
		t.Fatalf("unexpected registry counters %+v", status)
	}
	if status.DHTTrackedKeys != 5 || status.HiddenDescriptorKeys != 2 {
		t.Fatalf("unexpected dht counters %+v", status)
	}

	if err := RequestReload(context.Background(), infoPath); err != nil {
		t.Fatalf("request reload: %v", err)
	}
	if reloads != 1 {
		t.Fatalf("expected one reload request, got %d", reloads)
	}
}

func TestPeerUseAndFriendActionsReachDaemonHandlers(t *testing.T) {
	infoPath := filepath.Join(t.TempDir(), "node.control.json")
	var useSeen, friendSeen, removeSeen bool
	peer := proto.NodeInfo{ID: "vx6_test", Name: "FRIEND", Addr: "[2001:db8::1]:4242"}
	server, err := StartWithPeerHandlers(infoPath, 99, nil, nil,
		func(got proto.NodeInfo) error { useSeen = got.ID == peer.ID; return nil },
		func(got proto.NodeInfo, friend bool) error {
			if friend {
				friendSeen = got.ID == peer.ID
			} else {
				removeSeen = got.ID == peer.ID
			}
			return nil
		})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	if err := RecordPeerUse(context.Background(), infoPath, peer); err != nil {
		t.Fatal(err)
	}
	if err := SetPeerFriend(context.Background(), infoPath, peer, true); err != nil {
		t.Fatal(err)
	}
	if err := RemovePeerFriend(context.Background(), infoPath, peer.ID); err != nil {
		t.Fatal(err)
	}
	if !useSeen || !friendSeen || !removeSeen {
		t.Fatalf("daemon handlers saw use=%v friend=%v remove=%v", useSeen, friendSeen, removeSeen)
	}
}

func TestRequestFailsWithBadToken(t *testing.T) {
	t.Parallel()

	infoPath := filepath.Join(t.TempDir(), "node.control.json")
	server, err := Start(infoPath, 1111, nil, func() Status { return Status{} })
	if err != nil {
		t.Fatalf("start runtime control: %v", err)
	}
	defer server.Close()

	info, err := LoadInfo(infoPath)
	if err != nil {
		t.Fatalf("load info: %v", err)
	}
	info.Token = "bad-token"
	if err := writeBadInfo(infoPath, info); err != nil {
		t.Fatalf("write bad info: %v", err)
	}

	if _, err := RequestStatus(context.Background(), infoPath); err == nil {
		t.Fatal("expected bad token to fail")
	}
}

func writeBadInfo(path string, info Info) error {
	data, err := json.Marshal(info)
	if err != nil {
		return err
	}
	data = append(data, '\n')
	return os.WriteFile(path, data, 0o600)
}
