package discovery

import (
	"encoding/json"
	"net"
	"testing"
	"time"

	"github.com/vx6/vx6/internal/identity"
	"github.com/vx6/vx6/internal/proto"
	"github.com/vx6/vx6/internal/record"
)

func TestRegistryPublishResolve(t *testing.T) {
	t.Parallel()

	id, err := identity.Generate()
	if err != nil {
		t.Fatalf("generate identity: %v", err)
	}
	reg, err := NewRegistry("")
	if err != nil {
		t.Fatalf("new registry: %v", err)
	}

	rec, err := record.NewEndpointRecord(id, "alpha", "[2001:db8::1]:4242", 10*time.Minute, time.Now())
	if err != nil {
		t.Fatalf("new endpoint record: %v", err)
	}

	server, client := net.Pipe()
	done := make(chan error, 2)

	go func() {
		kind, err := proto.ReadHeader(server)
		if err != nil {
			done <- err
			return
		}
		if kind != proto.KindDiscoveryReq {
			done <- testErr("unexpected request kind")
			return
		}
		done <- reg.HandleConn(server)
	}()
	go func() {
		_, err := roundTripWithConn(client, request{Action: "publish", Record: rec})
		done <- err
	}()

	for i := 0; i < 2; i++ {
		if err := <-done; err != nil {
			t.Fatalf("publish flow failed: %v", err)
		}
	}

	server2, client2 := net.Pipe()
	done = make(chan error, 2)

	go func() {
		kind, err := proto.ReadHeader(server2)
		if err != nil {
			done <- err
			return
		}
		if kind != proto.KindDiscoveryReq {
			done <- testErr("unexpected request kind")
			return
		}
		done <- reg.HandleConn(server2)
	}()
	go func() {
		resp, err := roundTripWithConn(client2, request{Action: "resolve", Name: "alpha"})
		if err != nil {
			done <- err
			return
		}
		if resp.Record.NodeID != rec.NodeID {
			done <- testErr("resolved wrong record")
			return
		}
		done <- nil
	}()

	for i := 0; i < 2; i++ {
		if err := <-done; err != nil {
			t.Fatalf("resolve flow failed: %v", err)
		}
	}
}

func TestRegistryPublishResolveService(t *testing.T) {
	t.Parallel()

	id, err := identity.Generate()
	if err != nil {
		t.Fatalf("generate identity: %v", err)
	}
	reg, err := NewRegistry("")
	if err != nil {
		t.Fatalf("new registry: %v", err)
	}

	rec, err := record.NewServiceRecord(id, "surya", "ssh", "[2001:db8::1]:4242", 10*time.Minute, time.Now())
	if err != nil {
		t.Fatalf("new service record: %v", err)
	}

	server, client := net.Pipe()
	done := make(chan error, 2)

	go func() {
		kind, err := proto.ReadHeader(server)
		if err != nil {
			done <- err
			return
		}
		if kind != proto.KindDiscoveryReq {
			done <- testErr("unexpected request kind")
			return
		}
		done <- reg.HandleConn(server)
	}()
	go func() {
		_, err := roundTripWithConn(client, request{Action: "publish_service", ServiceRecord: rec})
		done <- err
	}()

	for i := 0; i < 2; i++ {
		if err := <-done; err != nil {
			t.Fatalf("publish service flow failed: %v", err)
		}
	}

	server2, client2 := net.Pipe()
	done = make(chan error, 2)

	go func() {
		kind, err := proto.ReadHeader(server2)
		if err != nil {
			done <- err
			return
		}
		if kind != proto.KindDiscoveryReq {
			done <- testErr("unexpected request kind")
			return
		}
		done <- reg.HandleConn(server2)
	}()
	go func() {
		resp, err := roundTripWithConn(client2, request{Action: "resolve_service", Service: "surya.ssh"})
		if err != nil {
			done <- err
			return
		}
		if resp.ServiceRecord.ServiceName != "ssh" {
			done <- testErr("resolved wrong service")
			return
		}
		done <- nil
	}()

	for i := 0; i < 2; i++ {
		if err := <-done; err != nil {
			t.Fatalf("resolve service flow failed: %v", err)
		}
	}
}

func TestRegistryRejectsPrivateServicePublish(t *testing.T) {
	t.Parallel()

	id, err := identity.Generate()
	if err != nil {
		t.Fatalf("generate identity: %v", err)
	}
	reg, err := NewRegistry("")
	if err != nil {
		t.Fatalf("new registry: %v", err)
	}

	rec, err := record.NewServiceRecord(id, "surya", "admin", "[2001:db8::1]:4242", 10*time.Minute, time.Now())
	if err != nil {
		t.Fatalf("new service record: %v", err)
	}
	rec.IsPrivate = true
	if err := record.SignServiceRecord(id, &rec); err != nil {
		t.Fatalf("sign private service record: %v", err)
	}

	server, client := net.Pipe()
	done := make(chan error, 2)
	go func() {
		kind, err := proto.ReadHeader(server)
		if err != nil {
			done <- err
			return
		}
		if kind != proto.KindDiscoveryReq {
			done <- testErr("unexpected request kind")
			return
		}
		done <- reg.HandleConn(server)
	}()
	go func() {
		resp, err := roundTripWithConn(client, request{Action: "publish_service", ServiceRecord: rec})
		if err != nil {
			done <- err
			return
		}
		if resp.OK || resp.Error == "" {
			done <- testErr("expected private service publish to be rejected")
			return
		}
		done <- nil
	}()
	for i := 0; i < 2; i++ {
		if err := <-done; err != nil {
			t.Fatalf("private publish flow failed: %v", err)
		}
	}
}

func TestRegistryImportReplacesOlderEndpointAddress(t *testing.T) {
	t.Parallel()

	id, err := identity.Generate()
	if err != nil {
		t.Fatalf("generate identity: %v", err)
	}
	reg, err := NewRegistry("")
	if err != nil {
		t.Fatalf("new registry: %v", err)
	}

	now := time.Now()
	oldRec, err := record.NewEndpointRecord(id, "alpha", "[2001:db8::1]:4242", 10*time.Minute, now)
	if err != nil {
		t.Fatalf("new old endpoint record: %v", err)
	}
	newRec, err := record.NewEndpointRecord(id, "alpha", "[2001:db8::2]:4242", 10*time.Minute, now.Add(time.Second))
	if err != nil {
		t.Fatalf("new updated endpoint record: %v", err)
	}

	if err := reg.Import([]record.EndpointRecord{oldRec}, nil); err != nil {
		t.Fatalf("import old record: %v", err)
	}
	if err := reg.Import([]record.EndpointRecord{newRec}, nil); err != nil {
		t.Fatalf("import new record: %v", err)
	}

	got, err := reg.ResolveLocal("alpha", "")
	if err != nil {
		t.Fatalf("resolve local: %v", err)
	}
	if got.Address != "[2001:db8::2]:4242" {
		t.Fatalf("unexpected resolved address %q", got.Address)
	}

	nodes, _ := reg.Snapshot()
	if len(nodes) != 1 {
		t.Fatalf("unexpected node count %d", len(nodes))
	}
	if nodes[0].Address != "[2001:db8::2]:4242" {
		t.Fatalf("unexpected snapshot address %q", nodes[0].Address)
	}
}

func TestRegistryPublishNotifiesEndpointObserverAfterAcceptedUpdate(t *testing.T) {
	id, err := identity.Generate()
	if err != nil {
		t.Fatal(err)
	}
	reg, err := NewRegistry("")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	oldRec, err := record.NewEndpointRecordV2(id, "ALPHA", "[2001:db8:1::1]:4242", 1, time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}
	newRec, err := record.NewEndpointRecordV2(id, "ALPHA", "[2001:db8:2::1]:4242", 2, time.Hour, now.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if err := reg.Import([]record.EndpointRecord{oldRec}, nil); err != nil {
		t.Fatal(err)
	}
	observed := make(chan record.EndpointRecord, 1)
	reg.SetEndpointObserver(func(rec record.EndpointRecord) { observed <- rec })

	serverConn, clientConn := net.Pipe()
	defer clientConn.Close()
	serverDone := make(chan error, 1)
	go func() { serverDone <- reg.HandleConn(serverConn) }()
	payload, err := json.Marshal(request{Action: "publish", Record: newRec})
	if err != nil {
		t.Fatal(err)
	}
	if err := proto.WriteLengthPrefixed(clientConn, payload); err != nil {
		t.Fatal(err)
	}
	kind, err := proto.ReadHeader(clientConn)
	if err != nil || kind != proto.KindDiscoveryRes {
		t.Fatalf("unexpected discovery response kind %d: %v", kind, err)
	}
	if _, err := proto.ReadLengthPrefixed(clientConn, maxMessageSize); err != nil {
		t.Fatal(err)
	}
	if err := <-serverDone; err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-observed:
		if got.NodeID != id.NodeID || got.Address != newRec.Address || got.Sequence != newRec.Sequence {
			t.Fatalf("observer received %+v, want accepted new endpoint %+v", got, newRec)
		}
	case <-time.After(time.Second):
		t.Fatal("accepted endpoint publication did not notify the local observer")
	}
}

func TestRegistryKeepsThreeLocalHistoricalAddressesAndCurrentOnlyInSnapshot(t *testing.T) {
	id, err := identity.Generate()
	if err != nil {
		t.Fatal(err)
	}
	path := t.TempDir() + "/registry.json"
	reg, err := NewRegistry(path)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	for i := 1; i <= 5; i++ {
		address := "[2001:db8::" + string(rune('0'+i)) + "]:4242"
		rec, err := record.NewEndpointRecordV2(id, "alpha", address, uint64(i), 24*time.Hour, now.Add(time.Duration(i)*time.Second))
		if err != nil {
			t.Fatal(err)
		}
		if err := reg.Import([]record.EndpointRecord{rec}, nil); err != nil {
			t.Fatal(err)
		}
	}
	history := reg.HistoricalAddresses(id.NodeID, now.Add(6*time.Second))
	if len(history) != 3 {
		t.Fatalf("local address history has %d entries, want 3: %v", len(history), history)
	}
	if history[0] != "[2001:db8::4]:4242" || history[1] != "[2001:db8::3]:4242" || history[2] != "[2001:db8::2]:4242" {
		t.Fatalf("unexpected local history order/content: %v", history)
	}
	current, err := reg.ResolveLocal("alpha", id.NodeID)
	if err != nil || current.Address != "[2001:db8::5]:4242" {
		t.Fatalf("current record = %v, %v", current, err)
	}
	nodes, _ := reg.Snapshot()
	if len(nodes) != 1 || nodes[0].Address != current.Address {
		t.Fatalf("snapshot included stale addresses: %+v", nodes)
	}
	reloaded, err := NewRegistry(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := reloaded.HistoricalAddresses(id.NodeID, now.Add(6*time.Second)); len(got) != 3 {
		t.Fatalf("persisted local history lost entries: %v", got)
	}
	if got := reloaded.HistoricalAddresses(id.NodeID, now.Add(31*24*time.Hour)); len(got) != 0 {
		t.Fatalf("expired local hints remain: %v", got)
	}
}

func TestRegistryRetainsSameNameIdentitiesWithoutChoosingOne(t *testing.T) {
	firstID, err := identity.Generate()
	if err != nil {
		t.Fatal(err)
	}
	secondID, err := identity.Generate()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	first, err := record.NewEndpointRecordV2(firstID, "shared", "[2001:db8::1]:4242", 1, time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}
	second, err := record.NewEndpointRecordV2(secondID, "shared", "[2001:db8::2]:4242", 1, time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}
	reg, err := NewRegistry("")
	if err != nil {
		t.Fatal(err)
	}
	if err := reg.Import([]record.EndpointRecord{first, second}, nil); err != nil {
		t.Fatal(err)
	}
	nodes, _ := reg.Snapshot()
	if len(nodes) != 2 {
		t.Fatalf("same-name identities were collapsed: %+v", nodes)
	}
	if _, err := reg.ResolveLocal("shared", ""); err == nil {
		t.Fatal("name-only resolution silently chose one conflicting identity")
	}
	for _, candidate := range []record.EndpointRecord{first, second} {
		got, err := reg.ResolveLocal("", candidate.NodeID)
		if err != nil || got.NodeID != candidate.NodeID {
			t.Fatalf("identity lookup failed for %s: %v", candidate.NodeID, err)
		}
	}
}

func roundTripWithConn(conn net.Conn, req request) (response, error) {
	defer conn.Close()

	if err := proto.WriteHeader(conn, proto.KindDiscoveryReq); err != nil {
		return response{}, err
	}

	payload, err := json.Marshal(req)
	if err != nil {
		return response{}, err
	}
	if err := proto.WriteLengthPrefixed(conn, payload); err != nil {
		return response{}, err
	}

	kind, err := proto.ReadHeader(conn)
	if err != nil {
		return response{}, err
	}
	if kind != proto.KindDiscoveryRes {
		return response{}, testErr("unexpected response kind")
	}

	reply, err := proto.ReadLengthPrefixed(conn, maxMessageSize)
	if err != nil {
		return response{}, err
	}

	var resp response
	if err := json.Unmarshal(reply, &resp); err != nil {
		return response{}, err
	}

	return resp, nil
}

type testErr string

func (e testErr) Error() string { return string(e) }
