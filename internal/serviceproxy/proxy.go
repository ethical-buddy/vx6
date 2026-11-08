// Copyright (c) 2026 Suryansh Deshwal
// Licensed under the VX6 terms in LICENSE-COMMERCIAL.md.
// Sole inventor, maintainer, and rights holder: Suryansh Deshwal (https://github.com/ethical-buddy).

package serviceproxy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/vx6/vx6/internal/identity"
	"github.com/vx6/vx6/internal/proto"
	"github.com/vx6/vx6/internal/record"
	"github.com/vx6/vx6/internal/secure"
	"github.com/vx6/vx6/internal/strictjson"
)

const maxRequestSize = 4 * 1024

type ConnectRequest struct {
	Version     uint8  `json:"version"`
	Action      string `json:"action"`
	ServiceName string `json:"service_name"`
}

func (r ConnectRequest) Validate() error {
	if r.Version != 1 || r.Action != "open" {
		return errors.New("unsupported service request version or action")
	}
	return record.ValidateServiceName(r.ServiceName)
}

type ServicePolicy struct {
	Target         string
	Protocol       string
	Private        bool
	AllowedNodeIDs []string
}

// SessionTracker enforces per-peer stream admission and closes active streams
// when their live service policy no longer permits them.
type SessionTracker struct {
	mu          sync.Mutex
	sessions    map[*serviceSession]struct{}
	active      map[string]int
	openWindows map[string]openWindow
}

type openWindow struct {
	start time.Time
	count int
}

const (
	maxServiceSessionsPerPeer = 128
	serviceOpenWindow         = 10 * time.Second
	serviceOpenBurst          = 600
	maxServiceQuotaPeers      = 4096
)

type serviceSession struct {
	service string
	peerID  string
	conn    net.Conn
	release func()
	once    sync.Once
}

func NewSessionTracker() *SessionTracker {
	return &SessionTracker{sessions: make(map[*serviceSession]struct{}), active: make(map[string]int), openWindows: make(map[string]openWindow)}
}

func (t *SessionTracker) admit(peerID string, now time.Time) (func(), error) {
	if t == nil {
		return func() {}, nil
	}
	if peerID == "" {
		return nil, errors.New("service request has no authenticated peer identity")
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.openWindows == nil {
		t.openWindows = make(map[string]openWindow)
	}
	if t.active == nil {
		t.active = make(map[string]int)
	}
	window, exists := t.openWindows[peerID]
	if !exists {
		if len(t.openWindows) >= maxServiceQuotaPeers {
			for key, old := range t.openWindows {
				if t.active[key] == 0 && now.Sub(old.start) >= serviceOpenWindow {
					delete(t.openWindows, key)
				}
			}
			if len(t.openWindows) >= maxServiceQuotaPeers {
				return nil, errors.New("service admission capacity is full")
			}
		}
		window = openWindow{start: now}
	} else if now.Sub(window.start) >= serviceOpenWindow {
		window = openWindow{start: now}
	}
	if window.count >= serviceOpenBurst || t.active[peerID] >= maxServiceSessionsPerPeer {
		return nil, errors.New("service request rate or concurrency limit exceeded")
	}
	window.count++
	t.openWindows[peerID] = window
	t.active[peerID]++
	var once sync.Once
	return func() {
		once.Do(func() {
			t.mu.Lock()
			if t.active[peerID] <= 1 {
				delete(t.active, peerID)
			} else {
				t.active[peerID]--
			}
			t.mu.Unlock()
		})
	}, nil
}

func (t *SessionTracker) track(service, peerID string, conn net.Conn, release func()) func() {
	if t == nil {
		return func() {}
	}
	session := &serviceSession{service: service, peerID: peerID, conn: conn, release: release}
	t.mu.Lock()
	if t.sessions == nil {
		t.sessions = make(map[*serviceSession]struct{})
	}
	t.sessions[session] = struct{}{}
	t.mu.Unlock()
	return func() {
		session.once.Do(func() {
			t.mu.Lock()
			delete(t.sessions, session)
			t.mu.Unlock()
			session.release()
		})
	}
}

func (t *SessionTracker) Reconcile(policies map[string]ServicePolicy) {
	if t == nil {
		return
	}
	var revoke []*serviceSession
	t.mu.Lock()
	for session := range t.sessions {
		policy, exists := policies[session.service]
		if !exists || policy.Target == "" || (policy.Private && !policy.Allows(session.peerID)) {
			revoke = append(revoke, session)
			delete(t.sessions, session)
		}
	}
	t.mu.Unlock()
	for _, session := range revoke {
		session.once.Do(session.release)
		_ = session.conn.Close()
	}
}

func (p ServicePolicy) Allows(nodeID string) bool {
	return !p.Private || (nodeID != "" && slices.Contains(p.AllowedNodeIDs, nodeID))
}

func HandleInbound(conn net.Conn, id identity.Identity, services map[string]string) error {
	fmt.Printf("[PROXY] Incoming request from %s\n", conn.RemoteAddr())

	secureConn, err := secure.Server(conn, proto.KindServiceConn, id)
	if err != nil {
		fmt.Printf("[PROXY] Secure handshake failed: %v\n", err)
		return err
	}

	reqPayload, err := proto.ReadLengthPrefixed(secureConn, maxRequestSize)
	if err != nil {
		fmt.Printf("[PROXY] Failed to read request: %v\n", err)
		return err
	}

	var req ConnectRequest
	if err := strictjson.Decode(reqPayload, &req); err != nil {
		return fmt.Errorf("decode service request: %w", err)
	}
	if err := req.Validate(); err != nil {
		return fmt.Errorf("invalid service request: %w", err)
	}

	target, ok := services[req.ServiceName]
	if !ok {
		fmt.Printf("[PROXY] Reject: Service %q not found in local config\n", req.ServiceName)
		return fmt.Errorf("service %q not found", req.ServiceName)
	}

	// Ensure we dial explicitly on the local interface
	targetConn, err := net.Dial("tcp", target)
	if err != nil {
		fmt.Printf("[PROXY] Reject: Could not connect to local target %s: %v\n", target, err)
		return err
	}
	defer targetConn.Close()

	fmt.Printf("[PROXY] Linked %s <-> %s (%s)\n", conn.RemoteAddr(), target, req.ServiceName)
	return proxyDuplex(secureConn, targetConn)
}

// HandleInboundWithPolicy relies on the listener's authenticated IKE peer
// record. Service data is not wrapped in a second application crypto session.
func HandleInboundWithPolicy(conn net.Conn, services map[string]ServicePolicy, ikePeer record.EndpointRecord) error {
	return HandleInboundWithPolicyAndTracker(conn, services, ikePeer, nil)
}

func HandleInboundWithPolicyAndTracker(conn net.Conn, services map[string]ServicePolicy, ikePeer record.EndpointRecord, tracker *SessionTracker) error {
	payload, err := proto.ReadLengthPrefixed(conn, maxRequestSize)
	if err != nil {
		return err
	}
	var req ConnectRequest
	if err := strictjson.Decode(payload, &req); err != nil {
		return fmt.Errorf("decode service request: %w", err)
	}
	if err := req.Validate(); err != nil {
		return fmt.Errorf("invalid service request name: %w", err)
	}
	policy, ok := services[req.ServiceName]
	if !ok || policy.Target == "" || policy.Protocol == record.ServiceProtocolUDP {
		return errors.New("service unavailable")
	}
	peerID := conn.RemoteAddr().String()
	verifiedPeer, verifyErr := record.VerifyEndpoint(ikePeer, time.Now())
	if verifyErr == nil {
		peerID = verifiedPeer.Endpoint().NodeID
	}
	if policy.Private {
		if verifyErr != nil {
			return errors.New("service unavailable")
		}
		if !policy.Allows(peerID) {
			return errors.New("service unavailable")
		}
	}
	releaseAdmission, err := tracker.admit(peerID, time.Now())
	if err != nil {
		return err
	}
	tracked := false
	defer func() {
		if !tracked {
			releaseAdmission()
		}
	}()
	targetConn, err := net.Dial("tcp", policy.Target)
	if err != nil {
		return fmt.Errorf("connect local service target: %w", err)
	}
	defer targetConn.Close()
	done := tracker.track(req.ServiceName, peerID, conn, releaseAdmission)
	tracked = true
	defer done()
	return proxyDuplex(conn, targetConn)
}

func ServeLocalForward(ctx context.Context, localListen string, service record.ServiceRecord, id identity.Identity, dialer func(context.Context) (net.Conn, error)) error {
	return ServeLocalForwardWithUseObserver(ctx, localListen, service, id, dialer, nil)
}

// ServeLocalForwardWithUseObserver reports use after application bytes pass
// through the established VX6 channel. This is local bookkeeping only.
func ServeLocalForwardWithUseObserver(ctx context.Context, localListen string, service record.ServiceRecord, id identity.Identity, dialer func(context.Context) (net.Conn, error), onUse func()) error {
	listener, err := net.Listen("tcp", localListen)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", localListen, err)
	}
	defer listener.Close()

	go func() {
		<-ctx.Done()
		_ = listener.Close()
	}()

	fmt.Printf("local_forwarder\t%s\t%s\n", localListen, service.ServiceName)

	for {
		localConn, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			continue
		}

		go func() {
			defer localConn.Close()

			fmt.Printf("[TUNNEL] Dialing remote node for %s...\n", service.ServiceName)
			remoteConn, err := dialer(ctx)
			if err != nil {
				fmt.Printf("[TUNNEL] Connection failed: %v\n", err)
				return
			}
			defer remoteConn.Close()

			if err := proto.WriteHeader(remoteConn, proto.KindServiceConn); err != nil {
				return
			}
			var serviceConn io.ReadWriter = remoteConn
			if !service.IsHidden {
				// Normal services rely on the IKE-authenticated ESP tunnel.
			} else {
				secureConn, handshakeErr := secure.Client(remoteConn, proto.KindServiceConn, id)
				if handshakeErr != nil {
					fmt.Printf("[TUNNEL] Handshake failed: %v\n", handshakeErr)
					return
				}
				serviceConn = secureConn
			}

			payload, _ := json.Marshal(ConnectRequest{Version: 1, Action: "open", ServiceName: service.ServiceName})
			if err := proto.WriteLengthPrefixed(serviceConn, payload); err != nil {
				return
			}

			fmt.Printf("[TUNNEL] Active: Local:%s <-> Remote:%s\n", localListen, service.NodeName)
			_ = proxyDuplexObserved(localConn, serviceConn, onUse)
		}()
	}
}

func proxyDuplex(a, b io.ReadWriter) error {
	return proxyDuplexObserved(a, b, nil)
}

func proxyDuplexObserved(a, b io.ReadWriter, onActivity func()) error {
	var wg sync.WaitGroup
	var activityOnce sync.Once
	errCh := make(chan error, 2)
	observed := func(dst io.Writer) io.Writer {
		if onActivity == nil {
			return dst
		}
		return activityWriter{dst: dst, once: &activityOnce, onActivity: onActivity}
	}

	copyPipe := func(dst io.Writer, src io.Reader) {
		defer wg.Done()
		_, err := io.Copy(observed(dst), src)
		if closer, ok := dst.(io.Closer); ok {
			_ = closer.Close()
		}
		if closer, ok := src.(io.Closer); ok {
			_ = closer.Close()
		}
		errCh <- err
	}

	wg.Add(2)
	go copyPipe(a, b)
	go copyPipe(b, a)
	wg.Wait()
	close(errCh)

	for err := range errCh {
		if err != nil && !isProxyCloseError(err) {
			return err
		}
	}
	return nil
}

type activityWriter struct {
	dst        io.Writer
	once       *sync.Once
	onActivity func()
}

func (w activityWriter) Write(p []byte) (int, error) {
	n, err := w.dst.Write(p)
	if n > 0 {
		w.once.Do(w.onActivity)
	}
	return n, err
}

func isProxyCloseError(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) {
		return true
	}
	return strings.Contains(err.Error(), "use of closed network connection") || strings.Contains(err.Error(), "closed pipe")
}
