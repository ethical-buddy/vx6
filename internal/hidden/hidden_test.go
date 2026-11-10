package hidden

import (
	"context"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/vx6/vx6/internal/record"
)

type testControlConn struct {
	net.Conn
	local string
	peer  string
}

func (c testControlConn) LocalNodeID() string {
	return c.local
}

func (c testControlConn) PeerNodeID() string {
	return c.peer
}

func TestSelectTopologyManualPrefersChosenIntros(t *testing.T) {
	t.Parallel()

	healthMu.Lock()
	for i := 0; i < 6; i++ {
		addr := "[2001:db8::" + string(rune('1'+i)) + "]:4242"
		healthCache[addr] = healthEntry{
			Healthy:     true,
			RTT:         time.Duration(i+1) * time.Millisecond,
			LastChecked: time.Now(),
		}
	}
	healthMu.Unlock()
	t.Cleanup(func() {
		healthMu.Lock()
		defer healthMu.Unlock()
		for i := 0; i < 6; i++ {
			delete(healthCache, "[2001:db8::"+string(rune('1'+i))+"]:4242")
		}
	})

	var nodes []record.EndpointRecord
	for i := 0; i < 6; i++ {
		addr := "[2001:db8::" + string(rune('1'+i)) + "]:4242"
		nodes = append(nodes, record.EndpointRecord{
			NodeName:  "relay-" + string(rune('a'+i)),
			Address:   addr,
			NodeID:    "relay-id",
			PublicKey: "unused",
		})
	}

	topology := SelectTopology(
		context.Background(),
		"",
		nodes,
		[]string{"relay-c", "relay-a", "relay-b"},
		IntroModeManual,
		"fast",
	)

	if len(topology.ActiveIntros) != 3 {
		t.Fatalf("expected 3 active intros, got %d", len(topology.ActiveIntros))
	}
	if topology.ActiveIntros[0] != nodes[2].Address || topology.ActiveIntros[1] != nodes[0].Address || topology.ActiveIntros[2] != nodes[1].Address {
		t.Fatalf("manual intro selection was not preserved: %#v", topology.ActiveIntros)
	}
	if len(topology.StandbyIntros) != 1 {
		t.Fatalf("expected 1 standby intro after reserving guard capacity, got %d", len(topology.StandbyIntros))
	}
	if len(topology.Guards) != 2 {
		t.Fatalf("expected 2 guards to be reserved first, got %d", len(topology.Guards))
	}
}

func TestSelectTopologyKeepsGuardSetStable(t *testing.T) {
	t.Parallel()

	healthMu.Lock()
	for i := 0; i < 8; i++ {
		addr := "[2001:db8::" + string(rune('1'+i)) + "]:4242"
		healthCache[addr] = healthEntry{
			Healthy:     true,
			RTT:         time.Duration(i+1) * time.Millisecond,
			LastChecked: time.Now(),
		}
	}
	healthMu.Unlock()
	t.Cleanup(func() {
		healthMu.Lock()
		defer healthMu.Unlock()
		for i := 0; i < 8; i++ {
			delete(healthCache, "[2001:db8::"+string(rune('1'+i))+"]:4242")
		}
	})

	nodes := make([]record.EndpointRecord, 0, 8)
	for i := 0; i < 8; i++ {
		nodes = append(nodes, record.EndpointRecord{
			NodeName: "relay-" + string(rune('a'+i)),
			Address:  "[2001:db8::" + string(rune('1'+i)) + "]:4242",
		})
	}

	first := SelectTopology(context.Background(), "[2001:db8::ffff]:4242", nodes, nil, IntroModeRandom, "fast")
	second := SelectTopology(context.Background(), "[2001:db8::ffff]:4242", nodes, nil, IntroModeRandom, "fast")
	if len(first.Guards) == 0 {
		t.Fatal("expected guard set to be populated")
	}
	if len(first.Guards) != len(second.Guards) {
		t.Fatalf("expected stable guard count, got %d and %d", len(first.Guards), len(second.Guards))
	}
	for i := range first.Guards {
		if first.Guards[i] != second.Guards[i] {
			t.Fatalf("expected stable guard selection, got %#v and %#v", first.Guards, second.Guards)
		}
	}
}

func TestGuardCallbackRegistrationAndForwarding(t *testing.T) {
	guardMu.Lock()
	original := guardServices
	guardServices = map[string]*guardRegistration{}
	guardMu.Unlock()
	defer func() {
		guardMu.Lock()
		guardServices = original
		guardMu.Unlock()
	}()

	serverConn, clientConn := net.Pipe()
	defer clientConn.Close()

	scope := nodeScopedService("guard-a", "ghost")
	done := make(chan error, 1)
	go func() {
		done <- holdGuardRegistration(serverConn, scope, "cb-1")
	}()

	waitForGuardRegistration(t, scope)

	msgCh := make(chan Message, 1)
	errCh := make(chan error, 1)
	go func() {
		msg, err := readControl(clientConn)
		if err != nil {
			errCh <- err
			return
		}
		msgCh <- msg
	}()

	if err := sendGuardCallback(scope, Message{
		Action:       "intro_notify",
		Service:      "ghost",
		RendezvousID: "rv-1",
	}); err != nil {
		t.Fatalf("send guard callback: %v", err)
	}

	select {
	case err := <-errCh:
		t.Fatalf("read callback message: %v", err)
	case msg := <-msgCh:
		if msg.Action != "intro_notify" || msg.RendezvousID != "rv-1" || msg.Service != "ghost" {
			t.Fatalf("unexpected callback message: %+v", msg)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for callback message")
	}

	_ = clientConn.Close()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("guard registration did not shut down after connection close")
	}
}

func TestGuardCallbackScopesAreIsolatedPerNode(t *testing.T) {
	guardMu.Lock()
	original := guardServices
	guardServices = map[string]*guardRegistration{}
	guardMu.Unlock()
	defer func() {
		guardMu.Lock()
		guardServices = original
		guardMu.Unlock()
	}()

	scopeA := nodeScopedService("guard-a", "ghost")
	scopeB := nodeScopedService("guard-b", "ghost")
	leftA, rightA := net.Pipe()
	defer leftA.Close()
	defer rightA.Close()

	guardMu.Lock()
	guardServices[scopeA] = &guardRegistration{CallbackID: "cb-a", Conn: leftA}
	guardMu.Unlock()

	msgCh := make(chan Message, 1)
	go func() {
		msg, err := readControl(rightA)
		if err == nil {
			msgCh <- msg
		}
	}()

	if err := sendGuardCallback(scopeA, Message{Action: "intro_notify", Service: "ghost", RendezvousID: "rv-a"}); err != nil {
		t.Fatalf("send scoped callback: %v", err)
	}

	select {
	case msg := <-msgCh:
		if msg.RendezvousID != "rv-a" {
			t.Fatalf("unexpected scoped callback message: %+v", msg)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for scoped callback message")
	}

	if err := sendGuardCallback(scopeB, Message{Action: "intro_notify", Service: "ghost"}); err == nil {
		t.Fatal("expected callback on missing guard scope to fail")
	}
}

func TestControlEnvelopeValidationRejectsReplayAndWrongPeer(t *testing.T) {
	controlReplayMu.Lock()
	originalReplays := controlReplays
	controlReplays = map[string]time.Time{}
	controlReplayMu.Unlock()
	t.Cleanup(func() {
		controlReplayMu.Lock()
		controlReplays = originalReplays
		controlReplayMu.Unlock()
	})

	sender := testControlConn{local: "node-a"}
	receiver := testControlConn{peer: "node-a"}

	msg, err := stampControlMessage(sender, Message{Action: "intro_request", Service: "ghost"})
	if err != nil {
		t.Fatalf("stamp control message: %v", err)
	}
	if msg.SenderNodeID != "node-a" || msg.Nonce == "" || msg.Epoch == 0 {
		t.Fatalf("unexpected stamped control envelope: %+v", msg)
	}
	if err := validateControlMessage(receiver, msg); err != nil {
		t.Fatalf("validate control message: %v", err)
	}
	if err := validateControlMessage(receiver, msg); err == nil || !strings.Contains(err.Error(), "replay") {
		t.Fatalf("expected replay detection, got %v", err)
	}

	msg, err = stampControlMessage(sender, Message{Action: "intro_request", Service: "ghost"})
	if err != nil {
		t.Fatalf("restamp control message: %v", err)
	}
	if err := validateControlMessage(testControlConn{peer: "node-b"}, msg); err == nil || !strings.Contains(err.Error(), "sender mismatch") {
		t.Fatalf("expected sender mismatch, got %v", err)
	}

	expired := Message{
		Action:       "intro_request",
		Service:      "ghost",
		SenderNodeID: "node-a",
		Epoch:        controlEpoch(time.Now().Add(-2 * hiddenControlEpochDuration)),
		Nonce:        "expired-nonce",
	}
	if err := validateControlMessage(receiver, expired); err == nil || !strings.Contains(err.Error(), "epoch") {
		t.Fatalf("expected expired epoch rejection, got %v", err)
	}
}

func TestIntroRegistrationReplacesNotifyTargets(t *testing.T) {
	introMu.Lock()
	original := introServices
	introServices = map[string]introRegistration{}
	introMu.Unlock()
	defer func() {
		introMu.Lock()
		introServices = original
		introMu.Unlock()
	}()

	scope := nodeScopedService("intro-a", "ghost")
	serverA, clientA := net.Pipe()
	defer clientA.Close()
	doneA := make(chan error, 1)
	go func() {
		doneA <- holdIntroRegistration(serverA, scope, []string{"guard-a"})
	}()

	waitForIntroRegistration(t, scope)
	introMu.RLock()
	first := introServices[scope]
	introMu.RUnlock()
	if len(first.NotifyAddrs) != 1 || first.NotifyAddrs[0] != "guard-a" {
		t.Fatalf("unexpected first intro registration: %+v", first)
	}

	serverB, clientB := net.Pipe()
	defer clientB.Close()
	doneB := make(chan error, 1)
	go func() {
		doneB <- holdIntroRegistration(serverB, scope, []string{"guard-b", "guard-c"})
	}()

	waitForIntroNotifyAddrs(t, scope, []string{"guard-b", "guard-c"})

	select {
	case <-doneA:
	case <-time.After(time.Second):
		t.Fatal("old intro registration did not shut down after replacement")
	}

	introMu.RLock()
	second := introServices[scope]
	introMu.RUnlock()
	if len(second.NotifyAddrs) != 2 || second.NotifyAddrs[0] != "guard-b" || second.NotifyAddrs[1] != "guard-c" {
		t.Fatalf("unexpected replacement intro registration: %+v", second)
	}

	_ = clientB.Close()
	select {
	case <-doneB:
	case <-time.After(time.Second):
		t.Fatal("replacement intro registration did not shut down after connection close")
	}
}

func TestHoldGuardRegistrationRespondsToControlPing(t *testing.T) {
	guardMu.Lock()
	original := guardServices
	guardServices = map[string]*guardRegistration{}
	guardMu.Unlock()
	defer func() {
		guardMu.Lock()
		guardServices = original
		guardMu.Unlock()
	}()

	serverConn, clientConn := net.Pipe()
	defer clientConn.Close()

	scope := nodeScopedService("guard-a", "ghost")
	done := make(chan error, 1)
	go func() {
		done <- holdGuardRegistration(serverConn, scope, "cb-1")
	}()

	waitForGuardRegistration(t, scope)

	if err := writeControl(clientConn, Message{Action: "control_ping"}); err != nil {
		t.Fatalf("write guard ping: %v", err)
	}
	msg, err := readControl(clientConn)
	if err != nil {
		t.Fatalf("read guard pong: %v", err)
	}
	if msg.Action != "control_pong" {
		t.Fatalf("expected control_pong, got %+v", msg)
	}

	_ = clientConn.Close()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("guard registration did not shut down after ping test")
	}
}

func TestHoldIntroRegistrationRespondsToControlPing(t *testing.T) {
	introMu.Lock()
	original := introServices
	introServices = map[string]introRegistration{}
	introMu.Unlock()
	defer func() {
		introMu.Lock()
		introServices = original
		introMu.Unlock()
	}()

	serverConn, clientConn := net.Pipe()
	defer clientConn.Close()

	scope := nodeScopedService("intro-a", "ghost")
	done := make(chan error, 1)
	go func() {
		done <- holdIntroRegistration(serverConn, scope, []string{"guard-a"})
	}()

	waitForIntroRegistration(t, scope)

	if err := writeControl(clientConn, Message{Action: "control_ping"}); err != nil {
		t.Fatalf("write intro ping: %v", err)
	}
	msg, err := readControl(clientConn)
	if err != nil {
		t.Fatalf("read intro pong: %v", err)
	}
	if msg.Action != "control_pong" {
		t.Fatalf("expected control_pong, got %+v", msg)
	}

	_ = clientConn.Close()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("intro registration did not shut down after ping test")
	}
}

func TestPruneOwnerRegistrationsCancelsStaleLeases(t *testing.T) {
	introClientMu.Lock()
	origIntro := introClients
	introClients = map[string]registrationLease{}
	introClientMu.Unlock()
	defer func() {
		introClientMu.Lock()
		introClients = origIntro
		introClientMu.Unlock()
	}()

	guardClientMu.Lock()
	origGuard := guardClients
	guardClients = map[string]registrationLease{}
	guardClientMu.Unlock()
	defer func() {
		guardClientMu.Lock()
		guardClients = origGuard
		guardClientMu.Unlock()
	}()

	introCanceled := make(chan string, 2)
	guardCanceled := make(chan string, 2)
	introKeep := introClientKey("owner-a", "[::1]:4001", "ghost")
	introDrop := introClientKey("owner-a", "[::1]:4002", "ghost")
	guardKeep := guardClientKey("owner-a", "[::1]:5001", "ghost")
	guardDrop := guardClientKey("owner-a", "[::1]:5002", "ghost")

	introClientMu.Lock()
	introClients[introKeep] = registrationLease{Cancel: func() { introCanceled <- introKeep }}
	introClients[introDrop] = registrationLease{Cancel: func() { introCanceled <- introDrop }}
	introClientMu.Unlock()

	guardClientMu.Lock()
	guardClients[guardKeep] = registrationLease{Cancel: func() { guardCanceled <- guardKeep }}
	guardClients[guardDrop] = registrationLease{Cancel: func() { guardCanceled <- guardDrop }}
	guardClientMu.Unlock()

	PruneOwnerRegistrations("owner-a", []OwnerRegistrationTarget{{
		LookupKey:  "ghost",
		IntroAddrs: []string{"[::1]:4001"},
		GuardAddrs: []string{"[::1]:5001"},
	}})

	select {
	case got := <-introCanceled:
		if got != introDrop {
			t.Fatalf("unexpected intro lease canceled: %s", got)
		}
	case <-time.After(time.Second):
		t.Fatal("expected stale intro lease to be canceled")
	}
	select {
	case got := <-guardCanceled:
		if got != guardDrop {
			t.Fatalf("unexpected guard lease canceled: %s", got)
		}
	case <-time.After(time.Second):
		t.Fatal("expected stale guard lease to be canceled")
	}

	introClientMu.Lock()
	if _, ok := introClients[introKeep]; !ok {
		t.Fatal("expected desired intro lease to remain")
	}
	if _, ok := introClients[introDrop]; ok {
		t.Fatal("expected stale intro lease to be pruned")
	}
	introClientMu.Unlock()

	guardClientMu.Lock()
	if _, ok := guardClients[guardKeep]; !ok {
		t.Fatal("expected desired guard lease to remain")
	}
	if _, ok := guardClients[guardDrop]; ok {
		t.Fatal("expected stale guard lease to be pruned")
	}
	guardClientMu.Unlock()
}

func TestAllowHiddenActionRateLimit(t *testing.T) {
	hiddenRateMu.Lock()
	original := hiddenRateCounters
	hiddenRateCounters = map[string]windowCounter{}
	hiddenRateMu.Unlock()
	defer func() {
		hiddenRateMu.Lock()
		hiddenRateCounters = original
		hiddenRateMu.Unlock()
	}()

	now := time.Now()
	for i := 0; i < 3; i++ {
		if !allowHiddenAction("node:alice", "intro_request", time.Second, 3, now) {
			t.Fatalf("unexpected rate-limit before limit at attempt %d", i+1)
		}
	}
	if allowHiddenAction("node:alice", "intro_request", time.Second, 3, now) {
		t.Fatal("expected rate-limit after limit is reached")
	}
	if !allowHiddenAction("node:alice", "intro_request", time.Second, 3, now.Add(1100*time.Millisecond)) {
		t.Fatal("expected window reset after rate-limit window elapsed")
	}
}

func TestHiddenPathFailureAppliesCooldown(t *testing.T) {
	healthMu.Lock()
	original := healthCache
	healthCache = map[string]healthEntry{}
	healthMu.Unlock()
	defer func() {
		healthMu.Lock()
		healthCache = original
		healthMu.Unlock()
	}()

	addr := "[::1]:65530"
	noteHiddenPathFailure([]string{addr})

	healthy, _, failures := measureHealth(context.Background(), addr)
	if healthy {
		t.Fatal("expected cooled-down relay to be considered unhealthy")
	}
	if failures == 0 {
		t.Fatal("expected cooled-down relay to retain a failure count")
	}
}

func TestJoinRendezvousRejectsWhenCapacityReached(t *testing.T) {
	rendezvousMu.Lock()
	original := rendezvouses
	rendezvouses = map[string]*rendezvousWait{}
	for i := 0; i < maxActiveRendezvous; i++ {
		rendezvouses[fmt.Sprintf("rv-%d", i)] = &rendezvousWait{
			peerCh:    make(chan net.Conn, 1),
			doneCh:    make(chan struct{}),
			createdAt: time.Now(),
			expiresAt: time.Now().Add(time.Minute),
		}
	}
	rendezvousMu.Unlock()
	defer func() {
		rendezvousMu.Lock()
		rendezvouses = original
		rendezvousMu.Unlock()
	}()

	left, right := net.Pipe()
	defer left.Close()
	defer right.Close()

	if err := joinRendezvous(left, "overflow"); err == nil || !strings.Contains(err.Error(), "capacity") {
		t.Fatalf("expected rendezvous capacity rejection, got %v", err)
	}
}

func waitForGuardRegistration(t *testing.T, scope string) {
	t.Helper()

	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		guardMu.RLock()
		_, ok := guardServices[scope]
		guardMu.RUnlock()
		if ok {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for guard registration %q", scope)
}

func waitForIntroRegistration(t *testing.T, scope string) {
	t.Helper()

	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		introMu.RLock()
		_, ok := introServices[scope]
		introMu.RUnlock()
		if ok {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for intro registration %q", scope)
}

func waitForIntroNotifyAddrs(t *testing.T, scope string, want []string) {
	t.Helper()

	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		introMu.RLock()
		reg, ok := introServices[scope]
		introMu.RUnlock()
		if ok && len(reg.NotifyAddrs) == len(want) {
			match := true
			for i := range want {
				if reg.NotifyAddrs[i] != want[i] {
					match = false
					break
				}
			}
			if match {
				return
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for intro notify addrs %q", scope)
}

func TestJoinedRendezvousOutlivesJoinTimeout(t *testing.T) {
	original := rendezvousJoinTimeout
	rendezvousJoinTimeout = 200 * time.Millisecond
	defer func() { rendezvousJoinTimeout = original }()

	firstRelay, firstPeer := net.Pipe()
	secondRelay, secondPeer := net.Pipe()
	defer firstPeer.Close()
	defer secondPeer.Close()

	firstDone := make(chan error, 1)
	go func() {
		firstDone <- joinRendezvous(testControlConn{Conn: firstRelay, local: "relay", peer: "first"}, "rv-long")
	}()
	waitForRendezvous(t, "rv-long")

	secondDone := make(chan error, 1)
	go func() {
		secondDone <- joinRendezvous(testControlConn{Conn: secondRelay, local: "relay", peer: "second"}, "rv-long")
	}()
	for _, peer := range []net.Conn{firstPeer, secondPeer} {
		msg, err := readControl(peer)
		if err != nil || msg.Action != "rv_ready" {
			t.Fatalf("expected rv_ready, got %+v, %v", msg, err)
		}
	}

	// Keep the session idle for several join timeouts; the second joiner
	// must not return (its caller would close the connection mid-session).
	time.Sleep(4 * rendezvousJoinTimeout)
	select {
	case err := <-secondDone:
		t.Fatalf("second joiner returned while the session was live: %v", err)
	default:
	}

	payload := []byte("still connected")
	go func() { _, _ = firstPeer.Write(payload) }()
	buf := make([]byte, len(payload))
	if _, err := io.ReadFull(secondPeer, buf); err != nil || string(buf) != string(payload) {
		t.Fatalf("session data after join timeout: %q, %v", buf, err)
	}

	_ = firstPeer.Close()
	for name, done := range map[string]chan error{"first": firstDone, "second": secondDone} {
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Fatalf("%s joiner did not return after the session closed", name)
		}
	}
}

func waitForRendezvous(t *testing.T, id string) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		rendezvousMu.Lock()
		_, ok := rendezvouses[id]
		rendezvousMu.Unlock()
		if ok {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("rendezvous %q was not registered", id)
}
