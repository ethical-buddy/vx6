package integration_test

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/vx6/vx6/internal/config"
	"github.com/vx6/vx6/internal/dht"
	"github.com/vx6/vx6/internal/discovery"
	"github.com/vx6/vx6/internal/hidden"
	"github.com/vx6/vx6/internal/identity"
	"github.com/vx6/vx6/internal/node"
	"github.com/vx6/vx6/internal/onion"
	"github.com/vx6/vx6/internal/proto"
	"github.com/vx6/vx6/internal/record"
	"github.com/vx6/vx6/internal/serviceproxy"
	vxtransport "github.com/vx6/vx6/internal/transport"
)

func testRootContext() (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancel(context.Background())
	return vxtransport.WithDialGuard(ctx, func(context.Context, string) error { return nil }), cancel
}

func newIntegrationDHT(nodeID string) *dht.Server {
	server := dht.NewServer(nodeID)
	server.SetDialGuard(func(context.Context, string) error { return nil })
	return server
}

func TestSixteenNodeSwarmServiceAndProxy(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping multi-node integration test in short mode")
	}

	rootCtx, rootCancel := testRootContext()
	defer rootCancel()

	baseDir := t.TempDir()
	bootstrap := startVX6Node(t, rootCtx, filepath.Join(baseDir, "bootstrap"), "bootstrap", nil, nil)

	echoAddr := reserveTCPAddr(t, "127.0.0.1:0")
	startEchoServer(t, rootCtx, echoAddr)

	owner := startVX6Node(
		t,
		rootCtx,
		filepath.Join(baseDir, "owner"),
		"owner",
		[]string{bootstrap.listenAddr},
		map[string]string{"echo": echoAddr},
	)
	client := startVX6Node(t, rootCtx, filepath.Join(baseDir, "client"), "client", []string{bootstrap.listenAddr}, nil)

	for i := 0; i < 13; i++ {
		startVX6Node(
			t,
			rootCtx,
			filepath.Join(baseDir, fmt.Sprintf("relay-%02d", i+1)),
			fmt.Sprintf("relay-%02d", i+1),
			[]string{bootstrap.listenAddr},
			nil,
		)
	}

	waitForCondition(t, 10*time.Second, func() bool {
		nodes, services := bootstrap.registry.Snapshot()
		return len(nodes) >= 16 && len(services) >= 1
	}, "bootstrap registry to converge with 16 nodes")

	records, services, err := discovery.Snapshot(rootCtx, bootstrap.listenAddr)
	if err != nil {
		t.Fatalf("snapshot bootstrap registry: %v", err)
	}
	if got := len(records); got < 16 {
		t.Fatalf("expected at least 16 discovered nodes, got %d", got)
	}
	if err := client.registry.Import(records, services); err != nil {
		t.Fatalf("import client registry: %v", err)
	}

	serviceName := record.FullServiceName(owner.name, "echo")
	serviceRec, err := client.registry.ResolveServiceLocal(serviceName)
	if err != nil {
		t.Fatalf("resolve service from client registry: %v", err)
	}

	dhtClient := newIntegrationDHT("observer")
	dhtClient.RT.AddNode(proto.NodeInfo{ID: "seed:" + bootstrap.listenAddr, Addr: bootstrap.listenAddr})

	waitForCondition(t, 5*time.Second, func() bool {
		value, err := dhtClient.RecursiveFindValue(rootCtx, dht.ServiceKey(serviceName))
		if err != nil || value == "" {
			return false
		}
		var got record.ServiceRecord
		return json.Unmarshal([]byte(value), &got) == nil && got.ServiceName == "echo" && got.NodeName == strings.ToUpper(owner.name)
	}, "service record in DHT")

	var endpointRec record.EndpointRecord
	waitForCondition(t, 5*time.Second, func() bool {
		endpointValue, err := dhtClient.RecursiveFindValue(rootCtx, dht.NodeNameKey(owner.name))
		if err != nil || endpointValue == "" {
			return false
		}
		if err := json.Unmarshal([]byte(endpointValue), &endpointRec); err != nil {
			return false
		}
		return endpointRec.NodeName == strings.ToUpper(owner.name) && endpointRec.Address == owner.listenAddr
	}, "endpoint record in DHT")

	directAddr := reserveTCPAddr(t, "127.0.0.1:0")
	directCtx, directCancel := context.WithCancel(rootCtx)
	directDone := make(chan error, 1)
	go func() {
		directDone <- serviceproxy.ServeLocalForward(directCtx, directAddr, serviceRec, client.id, func(ctx context.Context) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "tcp6", serviceRec.Address)
		})
	}()
	assertEchoEventually(t, directAddr, "direct service path")
	directCancel()
	waitForShutdown(t, directDone)

	onionPeers := filterPeers(records, func(rec record.EndpointRecord) bool {
		return rec.NodeID != owner.id.NodeID && rec.NodeID != client.id.NodeID
	})
	if len(onionPeers) < 5 {
		t.Fatalf("expected at least 5 relay candidates, got %d", len(onionPeers))
	}

	onionAddr := reserveTCPAddr(t, "127.0.0.1:0")
	onionCtx, onionCancel := context.WithCancel(rootCtx)
	onionDone := make(chan error, 1)
	go func() {
		onionDone <- serviceproxy.ServeLocalForward(onionCtx, onionAddr, serviceRec, client.id, func(ctx context.Context) (net.Conn, error) {
			return onion.BuildAutomatedCircuit(ctx, serviceRec, onionPeers)
		})
	}()
	assertEchoEventually(t, onionAddr, "five-hop proxy path")
	onionCancel()
	waitForShutdown(t, onionDone)
}

func TestPublicDirectIPv6ServiceDoesNotRequireOwnerDHTIdentity(t *testing.T) {
	rootCtx, rootCancel := testRootContext()
	defer rootCancel()

	baseDir := t.TempDir()
	echoAddr := reserveTCPAddr(t, "127.0.0.1:0")
	startEchoServer(t, rootCtx, echoAddr)

	owner := startVX6Node(t, rootCtx, filepath.Join(baseDir, "owner"), "owner", nil, map[string]string{"echo": echoAddr})
	client := startVX6Node(t, rootCtx, filepath.Join(baseDir, "client"), "client", nil, nil)

	directRec := record.ServiceRecord{
		NodeName:    "direct",
		ServiceName: "echo",
		Address:     owner.listenAddr,
	}

	directAddr := reserveTCPAddr(t, "127.0.0.1:0")
	directCtx, directCancel := context.WithCancel(rootCtx)
	directDone := make(chan error, 1)
	go func() {
		directDone <- serviceproxy.ServeLocalForward(directCtx, directAddr, directRec, client.id, func(ctx context.Context) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "tcp6", owner.listenAddr)
		})
	}()

	assertEchoEventually(t, directAddr, "public service caller absent from owner DHT")
	directCancel()
	waitForShutdown(t, directDone)
}

func TestConcurrentNamedServicesShareOnePeerListener(t *testing.T) {
	rootCtx, rootCancel := testRootContext()
	defer rootCancel()
	baseDir := t.TempDir()
	services := make(map[string]string)
	for _, name := range []string{"web", "ssh", "database"} {
		addr := reserveTCPAddr(t, "127.0.0.1:0")
		startTaggedEchoServer(t, rootCtx, addr, name)
		services[name] = addr
	}
	owner := startVX6Node(t, rootCtx, filepath.Join(baseDir, "owner"), "owner", nil, services)
	client := startVX6Node(t, rootCtx, filepath.Join(baseDir, "client"), "client", nil, nil)

	type forward struct {
		addr   string
		cancel context.CancelFunc
		done   chan error
	}
	forwards := make(map[string]forward, len(services))
	for name := range services {
		localAddr := reserveTCPAddr(t, "127.0.0.1:0")
		ctx, cancel := context.WithCancel(rootCtx)
		done := make(chan error, 1)
		rec := record.ServiceRecord{NodeName: owner.name, ServiceName: name, Address: owner.listenAddr}
		go func() {
			done <- serviceproxy.ServeLocalForward(ctx, localAddr, rec, client.id, func(ctx context.Context) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, "tcp6", owner.listenAddr)
			})
		}()
		forwards[name] = forward{addr: localAddr, cancel: cancel, done: done}
	}
	for name, item := range forwards {
		waitForTCPListener(t, item.addr, name)
	}
	defer func() {
		for _, item := range forwards {
			item.cancel()
			waitForShutdown(t, item.done)
		}
	}()

	var wg sync.WaitGroup
	errCh := make(chan error, len(services)*4)
	for name, item := range forwards {
		for i := 0; i < 4; i++ {
			name, item, i := name, item, i
			wg.Add(1)
			go func() {
				defer wg.Done()
				message := fmt.Sprintf("%s-stream-%d", name, i)
				conn, err := net.DialTimeout("tcp", item.addr, time.Second)
				if err != nil {
					errCh <- fmt.Errorf("dial %s: %w", name, err)
					return
				}
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
				marker := make([]byte, len(name)+1)
				if _, err := io.ReadFull(conn, marker); err != nil {
					errCh <- fmt.Errorf("read %s backend marker: %w", name, err)
					return
				}
				if string(marker) != name+":" {
					errCh <- fmt.Errorf("%s reached wrong backend %q", name, marker)
					return
				}
				if _, err := io.WriteString(conn, message); err != nil {
					errCh <- fmt.Errorf("write %s: %w", name, err)
					return
				}
				got := make([]byte, len(message))
				if _, err := io.ReadFull(conn, got); err != nil {
					errCh <- fmt.Errorf("read %s: %w", name, err)
					return
				}
				if string(got) != message {
					errCh <- fmt.Errorf("service cross-routing: %s returned %q", name, got)
				}
			}()
		}
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		if err != nil {
			t.Error(err)
		}
	}
}

func TestUDPServicePassesThroughPeerNode(t *testing.T) {
	rootCtx, rootCancel := testRootContext()
	defer rootCancel()
	baseDir := t.TempDir()
	backend, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer backend.Close()
	go func() {
		buffer := make([]byte, 2048)
		for {
			n, addr, err := backend.ReadFromUDP(buffer)
			if err != nil {
				return
			}
			_, _ = backend.WriteToUDP([]byte("udp:"+string(buffer[:n])), addr)
		}
	}()
	owner := startVX6NodeWithOptions(t, rootCtx, nodeOptions{
		dir: filepath.Join(baseDir, "owner"), name: "owner",
		services:         map[string]string{"media": backend.LocalAddr().String()},
		serviceProtocols: map[string]string{"media": record.ServiceProtocolUDP},
	})
	service := record.ServiceRecord{NodeName: owner.name, ServiceName: "media", Protocol: record.ServiceProtocolUDP, Address: owner.listenAddr}
	forwardCtx, forwardCancel := context.WithCancel(rootCtx)
	defer forwardCancel()
	ready := make(chan net.Addr, 1)
	forwardDone := make(chan error, 1)
	go func() {
		forwardDone <- serviceproxy.ServeLocalUDPForwardReady(forwardCtx, "127.0.0.1:0", service, func(ctx context.Context) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "tcp6", owner.listenAddr)
		}, ready)
	}()
	var localAddr net.Addr
	select {
	case localAddr = <-ready:
	case err := <-forwardDone:
		t.Fatalf("UDP forwarder exited: %v", err)
	case <-time.After(2 * time.Second):
		t.Fatal("UDP forwarder did not start")
	}

	var wg sync.WaitGroup
	errCh := make(chan error, 4)
	for i := 0; i < 4; i++ {
		message := fmt.Sprintf("packet-%d", i)
		wg.Add(1)
		go func() {
			defer wg.Done()
			conn, err := net.DialTimeout("udp", localAddr.String(), time.Second)
			if err != nil {
				errCh <- err
				return
			}
			defer conn.Close()
			_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
			if _, err := io.WriteString(conn, message); err != nil {
				errCh <- err
				return
			}
			buffer := make([]byte, 256)
			n, err := conn.Read(buffer)
			if err != nil {
				errCh <- err
				return
			}
			if got, want := string(buffer[:n]), "udp:"+message; got != want {
				errCh <- fmt.Errorf("UDP service response %q, want %q", got, want)
			}
		}()
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		if err != nil {
			t.Error(err)
		}
	}
	forwardCancel()
	waitForShutdown(t, forwardDone)
}

func TestSyncOnlyBootstrapClientCanOpenPublicServiceWithoutDHTIdentityLookup(t *testing.T) {
	rootCtx, rootCancel := testRootContext()
	defer rootCancel()

	baseDir := t.TempDir()
	bootstrap := startVX6Node(t, rootCtx, filepath.Join(baseDir, "bootstrap"), "bootstrap", nil, nil)

	echoAddr := reserveTCPAddr(t, "127.0.0.1:0")
	startEchoServer(t, rootCtx, echoAddr)

	owner := startVX6Node(
		t,
		rootCtx,
		filepath.Join(baseDir, "owner"),
		"owner",
		[]string{bootstrap.listenAddr},
		map[string]string{"echo": echoAddr},
	)
	client := startVX6NodeWithOptions(t, rootCtx, nodeOptions{
		dir:              filepath.Join(baseDir, "client"),
		name:             "client",
		bootstraps:       []string{bootstrap.listenAddr},
		disableAdvertise: true,
	})

	waitForCondition(t, 8*time.Second, func() bool {
		nodes, services := client.registry.Snapshot()
		seenOwner := false
		seenBootstrap := false
		for _, rec := range nodes {
			if rec.NodeName == strings.ToUpper(owner.name) {
				seenOwner = true
			}
			if rec.NodeName == strings.ToUpper(bootstrap.name) {
				seenBootstrap = true
			}
		}
		return seenOwner && seenBootstrap && len(services) >= 1
	}, "sync-only client registry convergence")

	serviceName := record.FullServiceName(owner.name, "echo")
	serviceRec, err := client.registry.ResolveServiceLocal(serviceName)
	if err != nil {
		t.Fatalf("resolve service from sync-only client registry: %v", err)
	}

	directAddr := reserveTCPAddr(t, "127.0.0.1:0")
	directCtx, directCancel := context.WithCancel(rootCtx)
	directDone := make(chan error, 1)
	go func() {
		directDone <- serviceproxy.ServeLocalForward(directCtx, directAddr, serviceRec, client.id, func(ctx context.Context) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "tcp6", serviceRec.Address)
		})
	}()
	assertEchoEventually(t, directAddr, "public service without owner-side DHT identity lookup")
	directCancel()
	waitForShutdown(t, directDone)

	nodes, _ := bootstrap.registry.Snapshot()
	for _, rec := range nodes {
		if rec.NodeName == client.name {
			t.Fatalf("sync-only client should not publish an endpoint record, but bootstrap learned %q", client.name)
		}
	}
}

func TestBootstrapLossStillAllowsRepublish(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping bootstrap-loss integration test in short mode")
	}

	rootCtx, rootCancel := testRootContext()
	defer rootCancel()

	baseDir := t.TempDir()
	bootstrap := startVX6Node(t, rootCtx, filepath.Join(baseDir, "bootstrap"), "bootstrap", nil, nil)

	echoAddr1 := reserveTCPAddr(t, "127.0.0.1:0")
	startEchoServer(t, rootCtx, echoAddr1)
	client := startVX6Node(t, rootCtx, filepath.Join(baseDir, "client"), "client", []string{bootstrap.listenAddr}, nil)
	for i := 0; i < 6; i++ {
		startVX6Node(t, rootCtx, filepath.Join(baseDir, fmt.Sprintf("mesh-%02d", i+1)), fmt.Sprintf("mesh-%02d", i+1), []string{bootstrap.listenAddr}, nil)
	}
	owner := startVX6Node(t, rootCtx, filepath.Join(baseDir, "owner"), "owner", []string{bootstrap.listenAddr}, map[string]string{"echo": echoAddr1})

	waitForCondition(t, 10*time.Second, func() bool {
		nodes, services := bootstrap.registry.Snapshot()
		return len(nodes) >= 9 && len(services) >= 1
	}, "bootstrap mesh convergence")

	records, services, err := discovery.Snapshot(rootCtx, bootstrap.listenAddr)
	if err != nil {
		t.Fatalf("initial snapshot: %v", err)
	}
	if err := client.registry.Import(records, services); err != nil {
		t.Fatalf("import client registry: %v", err)
	}

	bootstrap.cancel()
	time.Sleep(200 * time.Millisecond)

	echoAddr2 := reserveTCPAddr(t, "127.0.0.1:0")
	startEchoServer(t, rootCtx, echoAddr2)
	owner.cancel()
	time.Sleep(200 * time.Millisecond)

	ownerRestarted := startVX6NodeWithOptions(t, rootCtx, nodeOptions{
		dir:           filepath.Join(baseDir, "owner"),
		name:          "owner",
		bootstraps:    []string{bootstrap.listenAddr},
		services:      map[string]string{"echo": echoAddr2},
		identity:      owner.id,
		reuseIdentity: true,
	})

	waitForCondition(t, 10*time.Second, func() bool {
		nodes, _ := ownerRestarted.registry.Snapshot()
		return len(nodes) >= 2
	}, "owner restart peer cache")

	var cachedPeer record.EndpointRecord
	waitForCondition(t, 10*time.Second, func() bool {
		nodes, _ := ownerRestarted.registry.Snapshot()
		for _, node := range nodes {
			if node.NodeName != "OWNER" && node.NodeName != "BOOTSTRAP" && node.Address != "" {
				cachedPeer = node
				return true
			}
		}
		return false
	}, "owner restart cached peer after bootstrap shutdown")

	waitForCondition(t, 10*time.Second, func() bool {
		rec, err := discovery.Resolve(rootCtx, cachedPeer.Address, "owner", "")
		return err == nil && rec.Address == ownerRestarted.listenAddr
	}, "peer-to-peer owner record update after bootstrap loss")

	dhtClient := newIntegrationDHT("post-bootstrap-client")
	dhtClient.RT.AddNode(proto.NodeInfo{ID: "peer:" + cachedPeer.Address, Addr: cachedPeer.Address})
	waitForCondition(t, 10*time.Second, func() bool {
		value, err := dhtClient.RecursiveFindValue(rootCtx, dht.ServiceKey("owner.echo"))
		if err != nil || value == "" {
			return false
		}
		var rec record.ServiceRecord
		return json.Unmarshal([]byte(value), &rec) == nil && rec.Address == ownerRestarted.listenAddr
	}, "DHT service update after bootstrap loss")
}

func TestDeadBootstrapIsSkippedWhileHealthyBootstrapStillSyncs(t *testing.T) {
	rootCtx, rootCancel := testRootContext()
	defer rootCancel()

	baseDir := t.TempDir()
	bootstrap := startVX6Node(t, rootCtx, filepath.Join(baseDir, "bootstrap"), "bootstrap", nil, nil)
	deadBootstrap := startBlackholeServer(t, rootCtx)

	owner := startVX6Node(
		t,
		rootCtx,
		filepath.Join(baseDir, "owner"),
		"owner",
		[]string{deadBootstrap, bootstrap.listenAddr},
		nil,
	)

	waitForCondition(t, 5*time.Second, func() bool {
		rec, err := discovery.Resolve(rootCtx, bootstrap.listenAddr, owner.name, "")
		return err == nil && rec.Address == owner.listenAddr
	}, "owner sync through healthy bootstrap while dead bootstrap is skipped")
}

func TestHiddenServiceRendezvousPlainTCP(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping hidden-service integration test in short mode")
	}

	rootCtx, rootCancel := testRootContext()
	defer rootCancel()

	baseDir := t.TempDir()
	bootstrap := startVX6Node(t, rootCtx, filepath.Join(baseDir, "bootstrap"), "bootstrap", nil, nil)

	echoAddr := reserveTCPAddr(t, "127.0.0.1:0")
	startEchoServer(t, rootCtx, echoAddr)

	var (
		traceMu sync.Mutex
		traces  []onion.TraceEvent
	)
	restoreTrace := onion.SetTraceHook(func(ev onion.TraceEvent) {
		traceMu.Lock()
		traces = append(traces, ev)
		traceMu.Unlock()
	})
	defer restoreTrace()

	client := startVX6Node(t, rootCtx, filepath.Join(baseDir, "client"), "client", []string{bootstrap.listenAddr}, nil)
	for i := 0; i < 14; i++ {
		startVX6Node(t, rootCtx, filepath.Join(baseDir, fmt.Sprintf("relay-%02d", i+1)), fmt.Sprintf("relay-%02d", i+1), []string{bootstrap.listenAddr}, nil)
	}
	hiddenSecret := "ghost-invite-secret-2026"
	owner := startVX6NodeWithOptions(t, rootCtx, nodeOptions{
		dir:                 filepath.Join(baseDir, "hidden-owner"),
		name:                "hidden-owner",
		bootstraps:          []string{bootstrap.listenAddr},
		services:            map[string]string{"ghost": echoAddr},
		hiddenServices:      map[string]bool{"ghost": true},
		hiddenLookupSecrets: map[string]string{"ghost": hiddenSecret},
		hideEndpoint:        true,
	})

	waitForCondition(t, 10*time.Second, func() bool {
		nodes, _ := bootstrap.registry.Snapshot()
		return len(nodes) >= 16
	}, "hidden-service mesh convergence")

	records, services, err := discovery.Snapshot(rootCtx, bootstrap.listenAddr)
	if err != nil {
		t.Fatalf("snapshot hidden-service bootstrap registry: %v", err)
	}
	if err := client.registry.Import(records, services); err != nil {
		t.Fatalf("import client hidden registry: %v", err)
	}

	serviceAlias := "ghost"
	serviceInvite := dht.ComposeHiddenLookupInvite(serviceAlias, hiddenSecret)

	if _, err := client.registry.ResolveServiceLocal(serviceAlias); err == nil {
		t.Fatalf("hidden service should not be published through the shared registry")
	}
	if _, err := discovery.ResolveService(rootCtx, bootstrap.listenAddr, serviceAlias); err == nil {
		t.Fatalf("hidden service should not resolve through shared discovery service lookup")
	}

	if _, err := discovery.Resolve(rootCtx, bootstrap.listenAddr, owner.name, ""); err == nil {
		t.Fatalf("hidden owner endpoint should not be published publicly")
	}

	dhtClient := newIntegrationDHT("hidden-observer")
	dhtClient.RT.AddNode(proto.NodeInfo{ID: "seed:" + bootstrap.listenAddr, Addr: bootstrap.listenAddr})
	hiddenKey := dht.HiddenServiceKey(serviceInvite)
	var serviceRec record.ServiceRecord
	waitForCondition(t, 10*time.Second, func() bool {
		value, err := dhtClient.RecursiveFindValue(rootCtx, hiddenKey)
		if err != nil || value == "" {
			return false
		}
		rec, err := dht.DecodeHiddenServiceRecord(hiddenKey, value, serviceInvite, time.Now())
		if err != nil || !rec.IsHidden || len(rec.IntroPoints) != 3 || len(rec.StandbyIntroPoints) != 2 || rec.Address != "" {
			return false
		}
		serviceRec = rec
		return true
	}, "hidden service descriptor in DHT")

	hiddenValue, err := dhtClient.RecursiveFindValue(rootCtx, hiddenKey)
	if err != nil {
		t.Fatalf("resolve hidden descriptor from DHT: %v", err)
	}
	if strings.Contains(hiddenValue, "\"alias\"") || strings.Contains(hiddenValue, "\"intro_points\"") || strings.Contains(hiddenValue, "\"address\"") {
		t.Fatalf("hidden DHT descriptor leaked plaintext service metadata: %s", hiddenValue)
	}

	waitForCondition(t, 5*time.Second, func() bool {
		value, err := client.dht.RecursiveFindValue(rootCtx, hiddenKey)
		if err != nil || value == "" {
			return false
		}
		rec, err := dht.DecodeHiddenServiceRecord(hiddenKey, value, serviceInvite, time.Now())
		return err == nil && rec.IsHidden && rec.Alias == serviceAlias
	}, "anonymous hidden descriptor lookup through relay dht path")

	if _, err := dhtClient.RecursiveFindValue(rootCtx, dht.ServiceKey(record.FullServiceName(owner.name, serviceRec.ServiceName))); err == nil {
		t.Fatalf("hidden service should not be published under public service DHT key")
	}

	hiddenAddr := reserveTCPAddr(t, "127.0.0.1:0")
	hiddenCtx, hiddenCancel := context.WithCancel(rootCtx)
	hiddenDone := make(chan error, 1)
	go func() {
		hiddenDone <- serviceproxy.ServeLocalForward(hiddenCtx, hiddenAddr, serviceRec, client.id, func(ctx context.Context) (net.Conn, error) {
			return hidden.DialHiddenServiceWithOptions(ctx, serviceRec, client.registry, hidden.DialOptions{
				SelfAddr: client.listenAddr,
				Identity: client.id,
			})
		})
	}()
	// Each failed hidden dial attempt can wait a full rendezvousJoinTimeout
	// (8s) for a peer that never joins, for example while intro or guard
	// registrations are still settling right after startup, so allow several
	// attempts rather than the 5s used for direct paths. About one run in 30
	// needed three or four dials (76-94s) while registrations settled.
	assertEchoWithin(t, hiddenAddr, "hidden rendezvous path", 2*time.Minute)

	waitForCondition(t, 5*time.Second, func() bool {
		traceMu.Lock()
		defer traceMu.Unlock()
		return len(traces) >= 2
	}, "hidden-service circuit traces")

	hiddenCancel()
	waitForShutdown(t, hiddenDone)

	traceMu.Lock()
	gotTraces := append([]onion.TraceEvent(nil), traces...)
	traceMu.Unlock()
	// Traces are emitted before each circuit is dialed, and the client runs
	// several rendezvous attempts in parallel (each with its own rendezvous
	// ID), so traces also include losing and failed attempts. Only circuits of
	// the same rendezvous session are bound to be disjoint: the owner excludes
	// that session's client relays. Group by session and check every session
	// in which both sides built a circuit.
	type rendezvousSides struct {
		client []onion.TraceEvent
		owner  []onion.TraceEvent
	}
	sessions := map[string]*rendezvousSides{}
	rendezvousTraces := 0
	for _, trace := range gotTraces {
		if trace.Purpose != "hidden-rendezvous" {
			continue
		}
		rendezvousTraces++
		if trace.Session == "" {
			t.Fatalf("hidden rendezvous trace without a session: %+v", trace)
		}
		if len(trace.RelayAddrs) != 3 {
			t.Fatalf("expected 3 relays per hidden rendezvous circuit, got %+v", trace)
		}
		for _, addr := range trace.RelayAddrs {
			if addr == client.listenAddr {
				t.Fatalf("requester node should not be reused as a hidden-service relay: %+v", trace)
			}
		}
		sides := sessions[trace.Session]
		if sides == nil {
			sides = &rendezvousSides{}
			sessions[trace.Session] = sides
		}
		switch trace.Role {
		case "client":
			sides.client = append(sides.client, trace)
		case "owner":
			sides.owner = append(sides.owner, trace)
		default:
			t.Fatalf("hidden rendezvous trace with unknown role: %+v", trace)
		}
	}
	matched := 0
	for id, sides := range sessions {
		if len(sides.client) > 1 {
			t.Fatalf("rendezvous session %s has %d client circuits, want at most 1", id, len(sides.client))
		}
		// A losing attempt can be cancelled after its intro request went out
		// (owner side only) or before the owner answered (client side only).
		if len(sides.client) == 0 || len(sides.owner) == 0 {
			continue
		}
		matched++
		clientRelays := map[string]struct{}{}
		for _, addr := range sides.client[0].RelayAddrs {
			if _, ok := clientRelays[addr]; ok {
				t.Fatalf("client rendezvous circuit reuses relay %s: %+v", addr, sides.client[0])
			}
			clientRelays[addr] = struct{}{}
		}
		for _, owner := range sides.owner {
			ownerRelays := map[string]struct{}{}
			for _, addr := range owner.RelayAddrs {
				if _, ok := clientRelays[addr]; ok {
					t.Fatalf("expected disjoint hidden-service relay sets in session %s, duplicate %s detected (client %v, owner %v)",
						id, addr, sides.client[0].RelayAddrs, owner.RelayAddrs)
				}
				if _, ok := ownerRelays[addr]; ok {
					t.Fatalf("owner rendezvous circuit reuses relay %s: %+v", addr, owner)
				}
				ownerRelays[addr] = struct{}{}
			}
			if owner.TargetAddr == "" {
				t.Fatalf("owner rendezvous circuit has no target: %+v", owner)
			}
		}
	}
	if matched == 0 {
		t.Fatalf("expected at least one rendezvous session with client and owner circuits, got %d rendezvous traces in %d sessions", rendezvousTraces, len(sessions))
	}

	traceMu.Lock()
	allTraces := append([]onion.TraceEvent(nil), traces...)
	traceMu.Unlock()
	var sawDescriptorStore, sawDescriptorLookup bool
	for _, trace := range allTraces {
		switch trace.Purpose {
		case "dht-hidden-desc-store":
			sawDescriptorStore = true
		case "dht-hidden-desc-lookup":
			sawDescriptorLookup = true
		default:
			continue
		}
		if len(trace.RelayAddrs) != 3 {
			t.Fatalf("expected hidden descriptor privacy circuits to use 3 relays, got %d in %+v", len(trace.RelayAddrs), trace)
		}
		if trace.TargetAddr == "" {
			t.Fatalf("expected hidden descriptor privacy circuit to target a DHT holder: %+v", trace)
		}
	}
	if !sawDescriptorStore {
		t.Fatal("expected hidden descriptor publication to use anonymous relay DHT transport")
	}
	if !sawDescriptorLookup {
		t.Fatal("expected hidden descriptor lookup to use anonymous relay DHT transport")
	}
}

func TestHiddenServiceReconnectsAfterIntroLoss(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping hidden failover integration test in short mode")
	}
	if os.Getenv("VX6_RUN_HIDDEN_FAILOVER") == "" {
		t.Skip("set VX6_RUN_HIDDEN_FAILOVER=1 to run the relay-loss hidden failover scenario")
	}

	rootCtx, rootCancel := testRootContext()
	defer rootCancel()

	baseDir := t.TempDir()
	bootstrap := startVX6Node(t, rootCtx, filepath.Join(baseDir, "bootstrap"), "bootstrap", nil, nil)

	echoAddr := reserveTCPAddr(t, "127.0.0.1:0")
	startEchoServer(t, rootCtx, echoAddr)

	client := startVX6Node(t, rootCtx, filepath.Join(baseDir, "client"), "client", []string{bootstrap.listenAddr}, nil)
	relays := make([]runningNode, 0, 10)
	for i := 0; i < 10; i++ {
		relays = append(relays, startVX6Node(t, rootCtx, filepath.Join(baseDir, fmt.Sprintf("relay-%02d", i+1)), fmt.Sprintf("relay-%02d", i+1), []string{bootstrap.listenAddr}, nil))
	}
	introNodes := []string{relays[0].listenAddr, relays[1].listenAddr, relays[2].listenAddr, relays[3].listenAddr, relays[4].listenAddr}
	owner := startVX6NodeWithOptions(t, rootCtx, nodeOptions{
		dir:                 filepath.Join(baseDir, "hidden-owner"),
		name:                "hidden-owner",
		bootstraps:          []string{bootstrap.listenAddr},
		services:            map[string]string{"ghost": echoAddr},
		hiddenServices:      map[string]bool{"ghost": true},
		hiddenLookupSecrets: map[string]string{"ghost": "ghost-invite-secret-2026"},
		hiddenIntroNodes:    map[string][]string{"ghost": introNodes},
		hideEndpoint:        true,
	})

	waitForCondition(t, 10*time.Second, func() bool {
		nodes, _ := bootstrap.registry.Snapshot()
		return len(nodes) >= 12
	}, "hidden failover mesh convergence")

	records, services, err := discovery.Snapshot(rootCtx, bootstrap.listenAddr)
	if err != nil {
		t.Fatalf("snapshot hidden failover bootstrap registry: %v", err)
	}
	if err := client.registry.Import(records, services); err != nil {
		t.Fatalf("import hidden failover client registry: %v", err)
	}

	serviceInvite := dht.ComposeHiddenLookupInvite("ghost", "ghost-invite-secret-2026")
	hiddenKey := dht.HiddenServiceKey(serviceInvite)
	var serviceRec record.ServiceRecord
	waitForCondition(t, 10*time.Second, func() bool {
		value, err := client.dht.RecursiveFindValue(rootCtx, hiddenKey)
		if err != nil || value == "" {
			return false
		}
		rec, err := dht.DecodeHiddenServiceRecord(hiddenKey, value, serviceInvite, time.Now())
		if err != nil {
			return false
		}
		serviceRec = rec
		return len(serviceRec.IntroPoints) > 0 && len(serviceRec.StandbyIntroPoints) > 0
	}, "hidden failover descriptor lookup")

	candidatesByAddr := map[string]runningNode{}
	for _, relay := range relays {
		candidatesByAddr[relay.listenAddr] = relay
	}
	var (
		failedIntro runningNode
		found       bool
	)
	for _, addr := range append(append([]string(nil), serviceRec.IntroPoints...), serviceRec.StandbyIntroPoints...) {
		node, ok := candidatesByAddr[addr]
		if !ok {
			continue
		}
		failedIntro = node
		found = true
		break
	}
	if !found {
		t.Fatalf("expected manual relay intro selection, active=%v standby=%v", serviceRec.IntroPoints, serviceRec.StandbyIntroPoints)
	}
	failedIntro.cancel()
	time.Sleep(200 * time.Millisecond)

	hiddenAddr := reserveTCPAddr(t, "127.0.0.1:0")
	hiddenCtx, hiddenCancel := context.WithCancel(rootCtx)
	hiddenDone := make(chan error, 1)
	go func() {
		hiddenDone <- serviceproxy.ServeLocalForward(hiddenCtx, hiddenAddr, serviceRec, client.id, func(ctx context.Context) (net.Conn, error) {
			return hidden.DialHiddenServiceWithOptions(ctx, serviceRec, client.registry, hidden.DialOptions{
				SelfAddr: client.listenAddr,
				Identity: client.id,
			})
		})
	}()
	assertEchoEventually(t, hiddenAddr, "hidden rendezvous path after intro loss")
	hiddenCancel()
	waitForShutdown(t, hiddenDone)

	if _, err := discovery.Resolve(rootCtx, bootstrap.listenAddr, owner.name, ""); err == nil {
		t.Fatalf("hidden owner endpoint should remain unpublished during intro failover")
	}
}

func TestPrivateServiceCatalogLookup(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	root := t.TempDir()
	echoAddr := reserveTCPAddr(t, "127.0.0.1:0")
	startEchoServer(t, ctx, echoAddr)

	bootstrap := startVX6Node(t, ctx, filepath.Join(root, "bootstrap"), "bootstrap", nil, nil)
	owner := startVX6NodeWithOptions(t, ctx, nodeOptions{
		dir:             filepath.Join(root, "owner"),
		name:            "owner",
		bootstraps:      []string{bootstrap.listenAddr},
		services:        map[string]string{"web": echoAddr, "admin": echoAddr},
		privateServices: map[string]bool{"admin": true},
	})
	client := startVX6Node(t, ctx, filepath.Join(root, "client"), "client", []string{bootstrap.listenAddr}, nil)

	waitForCondition(t, 10*time.Second, func() bool {
		nodes, services := client.registry.Snapshot()
		if len(nodes) == 0 {
			return false
		}
		publicSeen := false
		privateSeen := false
		for _, svc := range services {
			switch record.FullServiceName(svc.NodeName, svc.ServiceName) {
			case "OWNER.web":
				publicSeen = true
			case "OWNER.admin":
				privateSeen = true
			}
		}
		return publicSeen && !privateSeen
	}, "public registry without private service leak")

	observer := newIntegrationDHT("observer")
	observer.RT.AddNode(proto.NodeInfo{ID: bootstrap.id.NodeID, Addr: bootstrap.listenAddr})
	nodes, _ := client.registry.Snapshot()
	for _, rec := range nodes {
		if rec.NodeID != "" && rec.Address != "" {
			observer.RT.AddNode(proto.NodeInfo{ID: rec.NodeID, Addr: rec.Address})
		}
	}

	var value string
	waitForCondition(t, 10*time.Second, func() bool {
		v, err := observer.RecursiveFindValue(ctx, dht.PrivateCatalogKey(owner.name))
		if err != nil || v == "" {
			return false
		}
		value = v
		return true
	}, "private catalog dht lookup")

	catalog, err := dht.DecodePrivateServiceCatalog(value, time.Now())
	if err != nil {
		t.Fatalf("decode private catalog: %v", err)
	}
	if len(catalog.Services) != 1 {
		t.Fatalf("expected one private service, got %+v", catalog)
	}
	if catalog.Services[0].ServiceName != "admin" || !catalog.Services[0].IsPrivate {
		t.Fatalf("unexpected private catalog service %+v", catalog.Services[0])
	}

	if _, err := observer.RecursiveFindValue(ctx, dht.ServiceKey("owner.admin")); err == nil {
		t.Fatal("expected private service to be absent from public service keyspace")
	}
}

func TestOnionRelayInspectVisibility(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping onion relay inspection integration test in short mode")
	}

	rootCtx, rootCancel := testRootContext()
	defer rootCancel()

	baseDir := t.TempDir()
	bootstrap := startVX6Node(t, rootCtx, filepath.Join(baseDir, "bootstrap"), "bootstrap", nil, nil)

	echoAddr := reserveTCPAddr(t, "127.0.0.1:0")
	startEchoServer(t, rootCtx, echoAddr)

	owner := startVX6Node(
		t,
		rootCtx,
		filepath.Join(baseDir, "owner"),
		"owner",
		[]string{bootstrap.listenAddr},
		map[string]string{"echo": echoAddr},
	)
	client := startVX6Node(t, rootCtx, filepath.Join(baseDir, "client"), "client", []string{bootstrap.listenAddr}, nil)

	for i := 0; i < 8; i++ {
		relayName := fmt.Sprintf("irelay%02d", i+1)
		startVX6Node(
			t,
			rootCtx,
			filepath.Join(baseDir, fmt.Sprintf("inspect-relay-%02d", i+1)),
			relayName,
			[]string{bootstrap.listenAddr},
			nil,
		)
	}

	waitForCondition(t, 10*time.Second, func() bool {
		nodes, services := bootstrap.registry.Snapshot()
		return len(nodes) >= 11 && len(services) >= 1
	}, "inspection mesh convergence")

	records, services, err := discovery.Snapshot(rootCtx, bootstrap.listenAddr)
	if err != nil {
		t.Fatalf("snapshot inspection registry: %v", err)
	}
	if err := client.registry.Import(records, services); err != nil {
		t.Fatalf("import inspection registry: %v", err)
	}

	serviceName := record.FullServiceName(owner.name, "echo")
	serviceRec, err := client.registry.ResolveServiceLocal(serviceName)
	if err != nil {
		t.Fatalf("resolve inspection service: %v", err)
	}

	onionPeers := filterPeers(records, func(rec record.EndpointRecord) bool {
		return rec.NodeID != owner.id.NodeID && rec.NodeID != client.id.NodeID
	})
	plan, err := onion.PlanAutomatedCircuit(serviceRec, onionPeers, 3, nil)
	if err != nil {
		t.Fatalf("plan inspection circuit: %v", err)
	}

	var (
		inspectMu sync.Mutex
		events    []onion.InspectEvent
	)
	restoreInspect := onion.SetInspectHook(func(ev onion.InspectEvent) {
		inspectMu.Lock()
		events = append(events, ev)
		inspectMu.Unlock()
	})
	defer restoreInspect()

	onionAddr := reserveTCPAddr(t, "127.0.0.1:0")
	onionCtx, onionCancel := context.WithCancel(rootCtx)
	onionDone := make(chan error, 1)
	go func() {
		onionDone <- serviceproxy.ServeLocalForward(onionCtx, onionAddr, serviceRec, client.id, func(ctx context.Context) (net.Conn, error) {
			return onion.DialPlannedCircuit(ctx, plan, onion.ClientOptions{Identity: client.id})
		})
	}()
	assertEchoEventually(t, onionAddr, "inspection path")
	onionCancel()
	waitForShutdown(t, onionDone)

	inspectMu.Lock()
	gotEvents := append([]onion.InspectEvent(nil), events...)
	inspectMu.Unlock()

	filtered := make([]onion.InspectEvent, 0, len(gotEvents))
	for _, ev := range gotEvents {
		if ev.CircuitID == plan.CircuitID {
			filtered = append(filtered, ev)
		}
	}
	if len(filtered) == 0 {
		t.Fatal("expected relay inspection events for planned circuit")
	}

	firstID := plan.Relays[0].NodeID
	secondID := plan.Relays[1].NodeID
	lastID := plan.Relays[2].NodeID

	assertRelayVisibility := func(nodeID string, forbiddenTarget string, wantExtend string, wantBegin bool) []onion.InspectEvent {
		t.Helper()
		nodeEvents := make([]onion.InspectEvent, 0)
		for _, ev := range filtered {
			if ev.NodeID == nodeID {
				nodeEvents = append(nodeEvents, ev)
			}
		}
		if len(nodeEvents) == 0 {
			t.Fatalf("expected inspection events for relay %s", nodeID)
		}
		for _, ev := range nodeEvents {
			if forbiddenTarget != "" && ev.TargetAddr == forbiddenTarget {
				t.Fatalf("relay %s should not have seen final target %s", nodeID, forbiddenTarget)
			}
		}
		if wantExtend != "" {
			found := false
			for _, ev := range nodeEvents {
				if ev.Command == "extend" && ev.NextHop == wantExtend {
					found = true
					break
				}
			}
			if !found {
				t.Fatalf("relay %s did not process expected extend to %s: %+v", nodeID, wantExtend, nodeEvents)
			}
		}
		foundBegin := false
		for _, ev := range nodeEvents {
			if ev.Command == "begin" {
				foundBegin = true
			}
		}
		if wantBegin != foundBegin {
			t.Fatalf("relay %s begin visibility mismatch: want=%v got=%v events=%+v", nodeID, wantBegin, foundBegin, nodeEvents)
		}
		return nodeEvents
	}

	firstEvents := assertRelayVisibility(firstID, owner.listenAddr, plan.Relays[1].Address, false)
	secondEvents := assertRelayVisibility(secondID, owner.listenAddr, plan.Relays[2].Address, false)
	lastEvents := assertRelayVisibility(lastID, "", "", true)

	for _, ev := range firstEvents {
		if ev.Command == "data" || ev.Command == "begin" {
			t.Fatalf("first hop should not process inner payload commands: %+v", firstEvents)
		}
	}
	for _, ev := range secondEvents {
		if ev.Command == "data" || ev.Command == "begin" {
			t.Fatalf("middle hop should not process exit commands: %+v", secondEvents)
		}
	}

	sawTarget := false
	sawData := false
	for _, ev := range lastEvents {
		if ev.Command == "begin" && ev.TargetAddr == owner.listenAddr {
			sawTarget = true
		}
		if ev.Command == "data" && ev.Bytes > 0 {
			sawData = true
		}
	}
	if !sawTarget {
		t.Fatalf("exit hop did not observe final target %s: %+v", owner.listenAddr, lastEvents)
	}
	if !sawData {
		t.Fatalf("exit hop did not observe application data: %+v", lastEvents)
	}
}

type runningNode struct {
	cancel     context.CancelFunc
	configPath string
	done       <-chan error
	id         identity.Identity
	dht        *dht.Server
	name       string
	listenAddr string
	registry   *discovery.Registry
}

type integrationIPsec struct{}

func (integrationIPsec) PreparePeer(_ context.Context, peer record.EndpointRecord) error {
	return record.VerifyEndpointRecord(peer, time.Now())
}

func (integrationIPsec) EnsurePeer(_ context.Context, peer record.EndpointRecord) error {
	return record.VerifyEndpointRecord(peer, time.Now())
}

func (integrationIPsec) RegisterProbePort(context.Context, string) error { return nil }

// The integration double models a successful IKE-authenticated transport;
// its empty peer record lets tests exercise public service access without a
// DHT identity known to the service owner.
func (integrationIPsec) AuthenticatePeer(_ context.Context, remoteAddress string) (record.EndpointRecord, bool) {
	host, _, err := net.SplitHostPort(remoteAddress)
	if err == nil {
		signedTestEndpoints.RLock()
		defer signedTestEndpoints.RUnlock()
		for address, peer := range signedTestEndpoints.byAddress {
			peerHost, _, splitErr := net.SplitHostPort(address)
			if splitErr == nil && peerHost == host {
				return peer, true
			}
		}
	}
	return record.EndpointRecord{}, true
}

var signedTestEndpoints = struct {
	sync.RWMutex
	byAddress map[string]record.EndpointRecord
}{byAddress: make(map[string]record.EndpointRecord)}

func startVX6Node(t *testing.T, parent context.Context, dir, name string, bootstraps []string, services map[string]string) runningNode {
	return startVX6NodeWithOptions(t, parent, nodeOptions{
		dir:        dir,
		name:       name,
		bootstraps: bootstraps,
		services:   services,
	})
}

type nodeOptions struct {
	dir                 string
	name                string
	bootstraps          []string
	services            map[string]string
	serviceProtocols    map[string]string
	advertiseAddr       string
	disableAdvertise    bool
	hiddenServices      map[string]bool
	hiddenLookupSecrets map[string]string
	hiddenIntroNodes    map[string][]string
	privateServices     map[string]bool
	hideEndpoint        bool
	identity            identity.Identity
	reuseIdentity       bool
}

func startVX6NodeWithOptions(t *testing.T, parent context.Context, opts nodeOptions) runningNode {
	t.Helper()

	id := opts.identity
	var err error
	if !opts.reuseIdentity {
		id, err = identity.Generate()
		if err != nil {
			t.Fatalf("generate identity for %s: %v", opts.name, err)
		}
	}

	dataDir := filepath.Join(opts.dir, "data")
	registry, err := discovery.NewRegistry(filepath.Join(dataDir, "registry.json"))
	if err != nil {
		t.Fatalf("new registry for %s: %v", opts.name, err)
	}

	listenAddr := reserveTCPAddr(t, "[::1]:0")
	advertiseAddr := opts.advertiseAddr
	if advertiseAddr == "" && !opts.disableAdvertise {
		advertiseAddr = listenAddr
	}
	for _, bootstrapAddr := range opts.bootstraps {
		signedTestEndpoints.RLock()
		bootstrap, ok := signedTestEndpoints.byAddress[bootstrapAddr]
		signedTestEndpoints.RUnlock()
		if ok {
			if err := registry.Import([]record.EndpointRecord{bootstrap}, nil); err != nil {
				t.Fatalf("seed signed bootstrap identity for %s: %v", opts.name, err)
			}
		}
	}
	var ownEndpoint record.EndpointRecord
	if advertiseAddr != "" {
		ownEndpoint, err = record.NewEndpointRecord(id, opts.name, advertiseAddr, 24*time.Hour, time.Now())
		if err != nil {
			t.Fatalf("create signed endpoint for %s: %v", opts.name, err)
		}
		signedTestEndpoints.Lock()
		signedTestEndpoints.byAddress[advertiseAddr] = ownEndpoint
		signedTestEndpoints.Unlock()
	}
	configPath := filepath.Join(opts.dir, "config.json")
	store, err := config.NewStore(configPath)
	if err != nil {
		t.Fatalf("new config store for %s: %v", opts.name, err)
	}
	cfgFile := config.File{
		Node: config.NodeConfig{
			Name:           opts.name,
			ListenAddr:     listenAddr,
			AdvertiseAddr:  advertiseAddr,
			HideEndpoint:   opts.hideEndpoint,
			DataDir:        dataDir,
			KnownPeerAddrs: append([]string(nil), opts.bootstraps...),
		},
		Peers:    map[string]config.PeerEntry{},
		Services: map[string]config.ServiceEntry{},
	}
	if previous, loadErr := store.Load(); loadErr == nil {
		cfgFile.Node.RecordSequence = previous.Node.RecordSequence
		cfgFile.Node.RecordName = previous.Node.RecordName
		cfgFile.Node.RecordAddress = previous.Node.RecordAddress
	}
	for serviceName, target := range opts.services {
		cfgFile.Services[serviceName] = config.ServiceEntry{
			Target:             target,
			Protocol:           opts.serviceProtocols[serviceName],
			IsHidden:           opts.hiddenServices[serviceName],
			HiddenLookupSecret: opts.hiddenLookupSecrets[serviceName],
			IntroNodes:         append([]string(nil), opts.hiddenIntroNodes[serviceName]...),
			IsPrivate:          opts.privateServices[serviceName],
		}
	}
	servicePolicies := make(map[string]serviceproxy.ServicePolicy, len(opts.services))
	for name, target := range opts.services {
		servicePolicies[name] = serviceproxy.ServicePolicy{Target: target, Protocol: opts.serviceProtocols[name], Private: opts.privateServices[name]}
	}
	if err := store.Save(cfgFile); err != nil {
		t.Fatalf("save config for %s: %v", opts.name, err)
	}

	nodeCtx, cancel := context.WithCancel(parent)
	cfg := node.Config{
		Name:            opts.name,
		NodeID:          id.NodeID,
		ListenAddr:      listenAddr,
		AdvertiseAddr:   advertiseAddr,
		HideEndpoint:    opts.hideEndpoint,
		DataDir:         dataDir,
		ConfigPath:      configPath,
		PeerAddrs:       append([]string(nil), opts.bootstraps...),
		Services:        cloneServices(opts.services),
		ServicePolicies: servicePolicies,
		DHT:             dht.NewServerWithIdentity(id),
		Identity:        id,
		Registry:        registry,
		IPsecTunnel:     integrationIPsec{},
		RefreshServices: func() map[string]string {
			c, err := store.Load()
			if err != nil {
				return cloneServices(opts.services)
			}
			out := make(map[string]string, len(c.Services))
			for name, svc := range c.Services {
				out[name] = svc.Target
			}
			return out
		},
		RefreshServicePolicies: func() map[string]serviceproxy.ServicePolicy {
			c, err := store.Load()
			if err != nil {
				return nil
			}
			out := make(map[string]serviceproxy.ServicePolicy, len(c.Services))
			for name, service := range c.Services {
				out[name] = serviceproxy.ServicePolicy{Target: service.Target, Protocol: service.Protocol, Private: service.IsPrivate, AllowedNodeIDs: append([]string(nil), service.AllowedNodeIDs...)}
			}
			return out
		},
	}

	done := make(chan error, 1)
	go func() {
		done <- node.Run(nodeCtx, io.Discard, cfg)
	}()

	listenerReady := false
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case err := <-done:
			done <- err
			t.Fatalf("node %s exited during startup: %v", opts.name, err)
		default:
		}
		conn, err := net.DialTimeout("tcp6", listenAddr, 50*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			listenerReady = true
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !listenerReady {
		select {
		case err := <-done:
			done <- err
			t.Fatalf("node %s failed to start: %v", opts.name, err)
		default:
			t.Fatalf("timed out waiting for %s listener", opts.name)
		}
	}

	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("node %s shutdown: %v", opts.name, err)
			}
		case <-time.After(10 * time.Second):
			t.Errorf("timed out waiting for node %s shutdown", opts.name)
		}
	})

	return runningNode{
		cancel:     cancel,
		configPath: configPath,
		done:       done,
		id:         id,
		dht:        cfg.DHT,
		name:       opts.name,
		listenAddr: listenAddr,
		registry:   registry,
	}
}

func waitForTCPListener(t *testing.T, addr, label string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, 50*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("local service listener %s (%s) did not start", label, addr)
}

func startEchoServer(t *testing.T, ctx context.Context, addr string) {
	t.Helper()

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatalf("listen echo server: %v", err)
	}

	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				_, _ = io.Copy(conn, conn)
			}(conn)
		}
	}()
}

func startTaggedEchoServer(t *testing.T, ctx context.Context, addr, tag string) {
	t.Helper()
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatalf("listen tagged echo server: %v", err)
	}
	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				_, _ = io.WriteString(conn, tag+":")
				_, _ = io.Copy(conn, conn)
			}(conn)
		}
	}()
}

func startBlackholeServer(t *testing.T, ctx context.Context) string {
	t.Helper()

	ln, err := net.Listen("tcp6", "[::1]:0")
	if err != nil {
		t.Fatalf("listen blackhole server: %v", err)
	}

	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				<-ctx.Done()
			}(conn)
		}
	}()

	return ln.Addr().String()
}

func reserveTCPAddr(t *testing.T, networkAddr string) string {
	t.Helper()

	network := "tcp"
	if networkAddr != "" && networkAddr[0] == '[' {
		network = "tcp6"
	}

	ln, err := net.Listen(network, networkAddr)
	if err != nil {
		t.Fatalf("reserve address %s: %v", networkAddr, err)
	}
	defer ln.Close()
	return ln.Addr().String()
}

func waitForCondition(t *testing.T, timeout time.Duration, fn func() bool, label string) {
	t.Helper()

	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if fn() {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", label)
}

func waitForShutdown(t *testing.T, done <-chan error) {
	t.Helper()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("forwarder shutdown: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for forwarder shutdown")
	}
}

func assertEchoRoundTrip(t *testing.T, addr, message string) {
	t.Helper()

	conn, err := net.DialTimeout("tcp", addr, time.Second)
	if err != nil {
		t.Fatalf("dial forwarder %s: %v", addr, err)
	}
	defer conn.Close()

	if _, err := io.WriteString(conn, message); err != nil {
		t.Fatalf("write echo payload: %v", err)
	}

	buf := make([]byte, len(message))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("read echo payload: %v", err)
	}
	if got := string(buf); got != message {
		t.Fatalf("unexpected echo payload %q, want %q", got, message)
	}
}

func assertEchoEventually(t *testing.T, addr, message string) {
	t.Helper()
	assertEchoWithin(t, addr, message, 5*time.Second)
}

func assertEchoWithin(t *testing.T, addr, message string, window time.Duration) {
	t.Helper()

	deadline := time.Now().Add(window)
	for time.Now().Before(deadline) {
		err := func() error {
			conn, err := net.DialTimeout("tcp", addr, 100*time.Millisecond)
			if err != nil {
				return err
			}
			defer conn.Close()

			if _, err := io.WriteString(conn, message); err != nil {
				return err
			}

			buf := make([]byte, len(message))
			if _, err := io.ReadFull(conn, buf); err != nil {
				return err
			}
			if got := string(buf); got != message {
				return fmt.Errorf("unexpected echo payload %q", got)
			}
			return nil
		}()
		if err == nil {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}

	assertEchoRoundTrip(t, addr, message)
}

func filterPeers(records []record.EndpointRecord, keep func(record.EndpointRecord) bool) []record.EndpointRecord {
	out := make([]record.EndpointRecord, 0, len(records))
	for _, rec := range records {
		if keep(rec) {
			out = append(out, rec)
		}
	}
	return out
}

func cloneServices(in map[string]string) map[string]string {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}
